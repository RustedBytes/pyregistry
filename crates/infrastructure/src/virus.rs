use crate::supplied_assets::bundled_yara_rule_files;
use log::{debug, info, warn};
use pyregistry_application::{
    ApplicationError, WheelArchiveSnapshot, WheelAuditFinding, WheelAuditFindingKind,
    WheelVirusScanResult, WheelVirusScanner,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use yara_x::{Compiler, MetaValue, Scanner, SourceCode};

const YARA_EVIDENCE_LIMIT: usize = 8;

pub struct YaraWheelVirusScanner {
    rules_source: String,
    rules: Option<Arc<yara_x::Rules>>,
    signature_rule_count: usize,
    skipped_rule_count: usize,
    load_error: Option<String>,
}

impl YaraWheelVirusScanner {
    #[must_use]
    pub fn from_rules_dir(rules_path: impl Into<PathBuf>) -> Self {
        let rules_path = rules_path.into();
        match compile_rules_dir(&rules_path) {
            Ok(compiled) => {
                info!(
                    "loaded {} YARA virus signature rule(s) from {} (skipped {} incompatible file(s))",
                    compiled.signature_rule_count,
                    rules_path.display(),
                    compiled.skipped_rule_count
                );
                Self {
                    rules_source: rules_path.display().to_string(),
                    rules: Some(Arc::new(compiled.rules)),
                    signature_rule_count: compiled.signature_rule_count,
                    skipped_rule_count: compiled.skipped_rule_count,
                    load_error: None,
                }
            }
            Err(error) => {
                warn!(
                    "YARA virus signature rules are unavailable from {}: {}; falling back to bundled supplied rules",
                    rules_path.display(),
                    error
                );
                match compile_bundled_rules_for_fallback(&rules_path) {
                    Ok(compiled) => {
                        info!(
                            "loaded {} bundled YARA virus signature rule(s) from supplied/signature-base (skipped {} incompatible file(s))",
                            compiled.signature_rule_count, compiled.skipped_rule_count
                        );
                        Self {
                            rules_source: "bundled supplied/signature-base".into(),
                            rules: Some(Arc::new(compiled.rules)),
                            signature_rule_count: compiled.signature_rule_count,
                            skipped_rule_count: compiled.skipped_rule_count,
                            load_error: None,
                        }
                    }
                    Err(bundled_error) => {
                        warn!(
                            "YARA virus scanning is unavailable: configured rules failed ({error}); bundled rules failed ({bundled_error})"
                        );
                        Self {
                            rules_source: rules_path.display().to_string(),
                            rules: None,
                            signature_rule_count: 0,
                            skipped_rule_count: 0,
                            load_error: Some(format!(
                                "configured rules failed: {error}; bundled rules failed: {bundled_error}"
                            )),
                        }
                    }
                }
            }
        }
    }
}

impl WheelVirusScanner for YaraWheelVirusScanner {
    fn scan_archive(
        &self,
        archive: &WheelArchiveSnapshot,
    ) -> Result<WheelVirusScanResult, ApplicationError> {
        let rules = self.rules.as_ref().ok_or_else(|| {
            ApplicationError::External(format!(
                "YARA rules are not loaded from {}: {}",
                self.rules_source,
                self.load_error
                    .as_deref()
                    .unwrap_or("no compatible rules were compiled")
            ))
        })?;

        debug!(
            "running YARA virus scan over {} wheel entrie(s) from `{}` with {} signature rule(s) from {}",
            archive.entries.len(),
            archive.wheel_filename,
            self.signature_rule_count,
            self.rules_source
        );

        let mut scanner = Scanner::new(rules);
        let mut findings = Vec::new();
        for entry in &archive.entries {
            set_entry_globals(&mut scanner, &entry.path)?;
            let results = scanner.scan(&entry.contents).map_err(|error| {
                ApplicationError::External(format!(
                    "YARA scan failed for `{}` in `{}`: {error}",
                    entry.path, archive.wheel_filename
                ))
            })?;

            for matching_rule in results.matching_rules() {
                let rule_name = matching_rule.identifier().to_string();
                let namespace = matching_rule.namespace().to_string();
                let tags = matching_rule
                    .tags()
                    .map(|tag| tag.identifier().to_string())
                    .collect::<Vec<_>>();
                let mut evidence = vec![
                    format!("rule={rule_name}"),
                    format!("namespace={namespace}"),
                ];
                if !tags.is_empty() {
                    evidence.push(format!("tags={}", tags.join(",")));
                }
                evidence.extend(
                    matching_rule
                        .metadata()
                        .take(YARA_EVIDENCE_LIMIT.saturating_sub(evidence.len()))
                        .map(|(key, value)| format!("meta.{key}={}", format_meta_value(value))),
                );

                findings.push(WheelAuditFinding {
                    kind: WheelAuditFindingKind::VirusSignatureMatch,
                    path: Some(entry.path.clone()),
                    summary: format!("YARA virus signature `{rule_name}` matched"),
                    evidence,
                });
            }
        }

        Ok(WheelVirusScanResult {
            scanned_file_count: archive.entries.len(),
            signature_rule_count: self.signature_rule_count,
            skipped_rule_count: self.skipped_rule_count,
            findings,
        })
    }
}

struct CompiledYaraRules {
    rules: yara_x::Rules,
    signature_rule_count: usize,
    skipped_rule_count: usize,
}

fn compile_rules_dir(path: &Path) -> Result<CompiledYaraRules, String> {
    if !path.exists() {
        return Err("rules directory does not exist".into());
    }
    if !path.is_dir() {
        return Err("rules path is not a directory".into());
    }

    let mut rule_files = Vec::new();
    let mut include_dirs = Vec::new();
    collect_yara_material(path, &mut rule_files, &mut include_dirs)?;
    rule_files.sort();
    include_dirs.sort();
    include_dirs.dedup();

    if rule_files.is_empty() {
        return Err("rules directory does not contain .yar or .yara files".into());
    }

    let mut compiler = Compiler::new();
    define_loki_style_globals(&mut compiler)?;
    for dir in include_dirs {
        compiler.add_include_dir(dir);
    }

    let mut skipped_rule_count = 0usize;
    for file in &rule_files {
        let source = match fs::read(file) {
            Ok(source) => source,
            Err(error) => {
                skipped_rule_count += 1;
                warn!(
                    "skipping unreadable YARA rule file {}: {}",
                    file.display(),
                    error
                );
                continue;
            }
        };
        compiler.new_namespace(&namespace_for(path, file));
        if let Err(error) = compiler
            .add_source(SourceCode::from(source.as_slice()).with_origin(file.display().to_string()))
        {
            skipped_rule_count += 1;
            warn!(
                "skipping incompatible YARA rule file {}: {}",
                file.display(),
                error
            );
        }
    }

    finish_compiler(compiler, rule_files.len(), skipped_rule_count)
}

fn compile_bundled_rules() -> Result<CompiledYaraRules, String> {
    let mut rule_files = bundled_yara_rule_files();
    rule_files.sort_by(|left, right| left.relative_path.cmp(right.relative_path));

    if rule_files.is_empty() {
        return Err("bundled supplied/signature-base does not contain YARA rule files".into());
    }

    let mut compiler = Compiler::new();
    define_loki_style_globals(&mut compiler)?;

    let mut skipped_rule_count = 0usize;
    for file in &rule_files {
        compiler.new_namespace(&namespace_for_relative(file.relative_path));
        if let Err(error) = compiler.add_source(
            SourceCode::from(file.contents)
                .with_origin(format!("bundled:{}", file.relative_path.display())),
        ) {
            skipped_rule_count += 1;
            warn!(
                "skipping incompatible bundled YARA rule file {}: {}",
                file.relative_path.display(),
                error
            );
        }
    }

    finish_compiler(compiler, rule_files.len(), skipped_rule_count)
}

#[cfg(test)]
fn compile_bundled_rules_for_fallback(rules_path: &Path) -> Result<CompiledYaraRules, String> {
    if rules_path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "__force-bundled-yara-failure__")
    {
        return Err("forced bundled rule failure".into());
    }

    compile_bundled_rules()
}

#[cfg(not(test))]
fn compile_bundled_rules_for_fallback(_rules_path: &Path) -> Result<CompiledYaraRules, String> {
    compile_bundled_rules()
}

fn finish_compiler(
    compiler: Compiler<'_>,
    source_file_count: usize,
    skipped_rule_count: usize,
) -> Result<CompiledYaraRules, String> {
    let rules = compiler.build();
    let signature_rule_count = rules.iter().len();
    if signature_rule_count == 0 {
        return Err(format!(
            "no compatible YARA rules compiled from {} file(s)",
            source_file_count
        ));
    }
    if !rules.warnings().is_empty() {
        warn!(
            "compiled YARA rule set with {} warning(s)",
            rules.warnings().len()
        );
    }

    Ok(CompiledYaraRules {
        rules,
        signature_rule_count,
        skipped_rule_count,
    })
}

fn collect_yara_material(
    dir: &Path,
    rule_files: &mut Vec<PathBuf>,
    include_dirs: &mut Vec<PathBuf>,
) -> Result<(), String> {
    include_dirs.push(dir.to_path_buf());
    let entries = fs::read_dir(dir)
        .map_err(|error| format!("could not read rules directory {}: {error}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "could not read an entry below rules directory {}: {error}",
                dir.display()
            )
        })?;
        let path = entry.path();
        if path.is_dir() {
            collect_yara_material(&path, rule_files, include_dirs)?;
        } else if is_yara_rule_file(&path) {
            rule_files.push(path);
        }
    }
    Ok(())
}

fn is_yara_rule_file(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| extension.to_ascii_lowercase())
            .as_deref(),
        Some("yar" | "yara")
    )
}

fn define_loki_style_globals(compiler: &mut Compiler<'_>) -> Result<(), String> {
    for name in [
        "filename",
        "filepath",
        "extension",
        "filetype",
        "md5",
        "sha1",
        "sha256",
        "owner",
    ] {
        compiler
            .define_global(name, "")
            .map_err(|error| format!("could not define YARA global `{name}`: {error}"))?;
    }
    Ok(())
}

fn set_entry_globals(scanner: &mut Scanner<'_>, path: &str) -> Result<(), ApplicationError> {
    let filename = path.rsplit('/').next().unwrap_or(path);
    let extension = filename
        .rsplit_once('.')
        .map_or("", |(_, extension)| extension);
    for (name, value) in [
        ("filename", filename),
        ("filepath", path),
        ("extension", extension),
        ("filetype", extension),
    ] {
        scanner.set_global(name, value).map_err(|error| {
            ApplicationError::External(format!("could not set YARA global `{name}`: {error}"))
        })?;
    }
    Ok(())
}

fn namespace_for(root: &Path, file: &Path) -> String {
    let relative = file.strip_prefix(root).unwrap_or(file);
    namespace_for_relative(relative)
}

fn namespace_for_relative(relative: &Path) -> String {
    let mut namespace = String::from("sig");
    for ch in relative.to_string_lossy().chars() {
        if ch.is_ascii_alphanumeric() {
            namespace.push(ch);
        } else {
            namespace.push('_');
        }
    }
    namespace
}

fn format_meta_value(value: MetaValue<'_>) -> String {
    match value {
        MetaValue::Integer(value) => value.to_string(),
        MetaValue::Float(value) => value.to_string(),
        MetaValue::Bool(value) => value.to_string(),
        MetaValue::String(value) => value.to_string(),
        MetaValue::Bytes(value) => format!("{value:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bstr::BStr;
    use log::Log;
    use pyregistry_application::WheelArchiveEntry;
    use std::sync::Once;
    use uuid::Uuid;

    #[test]
    fn builds_stable_namespace_from_relative_path() {
        init_test_logger();
        let namespace = namespace_for(
            Path::new("supplied/signature-base/yara"),
            Path::new("supplied/signature-base/yara/malware/demo-rule.yar"),
        );

        assert_eq!(namespace, "sigmalware_demo_rule_yar");
    }

    #[test]
    fn formats_byte_metadata_values_and_test_logger_is_noop() {
        let metadata = log::Metadata::builder()
            .level(log::Level::Info)
            .target("pyregistry-test")
            .build();
        assert!(TEST_LOGGER.enabled(&metadata));

        let record = log::Record::builder()
            .metadata(metadata)
            .args(format_args!("hello {}", "coverage"))
            .build();
        TEST_LOGGER.log(&record);
        TEST_LOGGER.flush();

        let bytes = BStr::new(b"\xffdemo");
        assert_eq!(
            format_meta_value(MetaValue::Bytes(bytes)),
            format!("{bytes:?}")
        );
    }

    #[test]
    fn matches_compiled_rule_against_wheel_entry() {
        init_test_logger();
        let rules_dir = std::env::temp_dir().join(format!("pyregistry-yara-{}", Uuid::new_v4()));
        fs::create_dir_all(&rules_dir).expect("create rules dir");
        fs::write(
            rules_dir.join("eicar.yar"),
            r#"
rule Pyregistry_Eicar_Test {
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}
"#,
        )
        .expect("write rule");

        let scanner = YaraWheelVirusScanner::from_rules_dir(&rules_dir);
        let result = scanner
            .scan_archive(&WheelArchiveSnapshot {
                wheel_filename: "demo-0.1.0-py3-none-any.whl".into(),
                entries: vec![WheelArchiveEntry {
                    path: "demo/payload.bin".into(),
                    contents: b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE".to_vec(),
                }],
            })
            .expect("scan archive");

        assert_eq!(result.signature_rule_count, 1);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(
            result.findings[0].kind,
            WheelAuditFindingKind::VirusSignatureMatch
        );

        let _ = fs::remove_dir_all(rules_dir);
    }

    #[test]
    fn includes_tags_and_metadata_in_yara_evidence() {
        init_test_logger();
        let rules_dir =
            std::env::temp_dir().join(format!("pyregistry-yara-meta-{}", Uuid::new_v4()));
        fs::create_dir_all(&rules_dir).expect("create rules dir");
        fs::write(
            rules_dir.join("meta.yara"),
            r#"
rule Pyregistry_Meta_Test : malware test {
    meta:
        score = 10
        ratio = 1.5
        enabled = true
        description = "demo rule"
    strings:
        $payload = "PYREGISTRY-META-MATCH"
    condition:
        $payload
}
"#,
        )
        .expect("write rule");

        let scanner = YaraWheelVirusScanner::from_rules_dir(&rules_dir);
        let result = scanner
            .scan_archive(&WheelArchiveSnapshot {
                wheel_filename: "demo-0.1.0-py3-none-any.whl".into(),
                entries: vec![WheelArchiveEntry {
                    path: "demo/payload.bin".into(),
                    contents: b"PYREGISTRY-META-MATCH".to_vec(),
                }],
            })
            .expect("scan archive");

        let evidence = result.findings[0].evidence.join("\n");
        assert!(evidence.contains("tags=malware,test"));
        assert!(evidence.contains("meta.score=10"));
        assert!(evidence.contains("meta.ratio=1.5"));
        assert!(evidence.contains("meta.enabled=true"));
        assert!(evidence.contains("meta.description=demo rule"));

        let _ = fs::remove_dir_all(rules_dir);
    }

    #[test]
    fn falls_back_to_bundled_rules_when_configured_dir_is_missing() {
        init_test_logger();
        let missing_rules_dir =
            std::env::temp_dir().join(format!("pyregistry-missing-yara-{}", Uuid::new_v4()));
        let scanner = YaraWheelVirusScanner::from_rules_dir(&missing_rules_dir);

        assert_eq!(scanner.rules_source, "bundled supplied/signature-base");
        assert!(scanner.rules.is_some());
        assert!(scanner.signature_rule_count > 0);
    }

    #[test]
    fn reports_unavailable_when_configured_and_bundled_rules_fail() {
        init_test_logger();
        let missing_rules_dir = std::env::temp_dir().join("__force-bundled-yara-failure__");

        let scanner = YaraWheelVirusScanner::from_rules_dir(&missing_rules_dir);

        assert_eq!(
            scanner.rules_source,
            missing_rules_dir.display().to_string()
        );
        assert!(scanner.rules.is_none());
        assert_eq!(scanner.signature_rule_count, 0);
        assert_eq!(scanner.skipped_rule_count, 0);
        assert!(
            scanner
                .load_error
                .as_deref()
                .is_some_and(|error| error.contains("forced bundled rule failure"))
        );
    }

    #[test]
    fn unloaded_scanner_reports_clear_error() {
        init_test_logger();
        let scanner = YaraWheelVirusScanner {
            rules_source: "test rules".into(),
            rules: None,
            signature_rule_count: 0,
            skipped_rule_count: 0,
            load_error: Some("boom".into()),
        };

        let error = scanner
            .scan_archive(&WheelArchiveSnapshot {
                wheel_filename: "demo.whl".into(),
                entries: Vec::new(),
            })
            .expect_err("missing rules should fail");

        assert!(error.to_string().contains("YARA rules are not loaded"));
        assert!(error.to_string().contains("boom"));
    }

    #[test]
    fn rule_directory_validation_and_collection_handles_edge_cases() {
        init_test_logger();
        let root = std::env::temp_dir().join(format!("pyregistry-yara-tree-{}", Uuid::new_v4()));
        let missing = root.join("missing");
        let missing_error = compile_rules_dir(&missing)
            .err()
            .expect("missing dir should fail");
        assert!(missing_error.contains("does not exist"));

        fs::create_dir_all(&root).expect("create root");
        let file_path = root.join("not-a-dir.yar");
        fs::write(&file_path, "rule FileRule { condition: true }").expect("write file");
        let file_error = compile_rules_dir(&file_path)
            .err()
            .expect("file path should fail");
        assert!(file_error.contains("not a directory"));

        let empty = root.join("empty");
        fs::create_dir_all(&empty).expect("create empty dir");
        let empty_error = compile_rules_dir(&empty)
            .err()
            .expect("empty dir should fail");
        assert!(empty_error.contains("does not contain"));

        let nested = root.join("nested");
        fs::create_dir_all(nested.join("child")).expect("create nested dir");
        fs::write(
            nested.join("child").join("one.yar"),
            "rule One { condition: true }",
        )
        .expect("write yar");
        fs::write(nested.join("two.yara"), "rule Two { condition: true }").expect("write yara");
        fs::write(nested.join("notes.txt"), "ignored").expect("write ignored");
        let mut rule_files = Vec::new();
        let mut include_dirs = Vec::new();
        collect_yara_material(&nested, &mut rule_files, &mut include_dirs)
            .expect("collect yara material");
        rule_files.sort();

        assert_eq!(rule_files.len(), 2);
        assert!(include_dirs.contains(&nested));
        assert!(include_dirs.contains(&nested.join("child")));
        assert!(is_yara_rule_file(&nested.join("two.YARA")));
        assert!(!is_yara_rule_file(&nested.join("notes.txt")));

        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_rule_files_are_skipped_and_zero_compatible_rules_fail() {
        init_test_logger();
        let rules_dir =
            std::env::temp_dir().join(format!("pyregistry-yara-unreadable-{}", Uuid::new_v4()));
        fs::create_dir_all(&rules_dir).expect("create rules dir");
        std::os::unix::fs::symlink(
            rules_dir.join("missing-target"),
            rules_dir.join("broken.yar"),
        )
        .expect("create broken rule symlink");

        let error = match compile_rules_dir(&rules_dir) {
            Ok(_) => panic!("broken rule should not compile"),
            Err(error) => error,
        };

        assert!(error.contains("no compatible YARA rules compiled"));
        let _ = fs::remove_dir_all(rules_dir);
    }

    #[test]
    fn incompatible_rule_files_are_skipped_when_others_compile() {
        init_test_logger();
        let rules_dir =
            std::env::temp_dir().join(format!("pyregistry-yara-skip-{}", Uuid::new_v4()));
        fs::create_dir_all(&rules_dir).expect("create rules dir");
        fs::write(
            rules_dir.join("valid.yar"),
            "rule ValidRule { condition: true }",
        )
        .expect("write valid rule");
        fs::write(rules_dir.join("broken.yar"), "rule Broken { condition:").expect("write broken");

        let compiled = compile_rules_dir(&rules_dir).expect("compile with skipped rule");

        assert_eq!(compiled.signature_rule_count, 1);
        assert_eq!(compiled.skipped_rule_count, 1);

        let _ = fs::remove_dir_all(rules_dir);
    }

    static TEST_LOGGER: TestLogger = TestLogger;
    static INIT_TEST_LOGGER: Once = Once::new();

    struct TestLogger;

    impl log::Log for TestLogger {
        fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
            true
        }

        fn log(&self, record: &log::Record<'_>) {
            let _ = format!("{}", record.args());
        }

        fn flush(&self) {}
    }

    fn init_test_logger() {
        INIT_TEST_LOGGER.call_once(|| {
            let _ = log::set_logger(&TEST_LOGGER);
            log::set_max_level(log::LevelFilter::Trace);
        });
    }
}
