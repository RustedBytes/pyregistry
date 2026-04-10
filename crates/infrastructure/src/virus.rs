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
    rules_path: PathBuf,
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
                    rules_path,
                    rules: Some(Arc::new(compiled.rules)),
                    signature_rule_count: compiled.signature_rule_count,
                    skipped_rule_count: compiled.skipped_rule_count,
                    load_error: None,
                }
            }
            Err(error) => {
                warn!(
                    "YARA virus scanning is unavailable from {}: {}",
                    rules_path.display(),
                    error
                );
                Self {
                    rules_path,
                    rules: None,
                    signature_rule_count: 0,
                    skipped_rule_count: 0,
                    load_error: Some(error),
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
                self.rules_path.display(),
                self.load_error
                    .as_deref()
                    .unwrap_or("no compatible rules were compiled")
            ))
        })?;

        debug!(
            "running YARA virus scan over {} wheel entrie(s) from `{}` with {} signature rule(s)",
            archive.entries.len(),
            archive.wheel_filename,
            self.signature_rule_count
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

    let rules = compiler.build();
    let signature_rule_count = rules.iter().len();
    if signature_rule_count == 0 {
        return Err(format!(
            "no compatible YARA rules compiled from {} file(s)",
            rule_files.len()
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
    use pyregistry_application::WheelArchiveEntry;
    use uuid::Uuid;

    #[test]
    fn builds_stable_namespace_from_relative_path() {
        let namespace = namespace_for(
            Path::new("supplied/signature-base/yara"),
            Path::new("supplied/signature-base/yara/malware/demo-rule.yar"),
        );

        assert_eq!(namespace, "sigmalware_demo_rule_yar");
    }

    #[test]
    fn matches_compiled_rule_against_wheel_entry() {
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
}
