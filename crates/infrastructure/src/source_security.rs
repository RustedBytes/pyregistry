use crate::ignored_findings::IgnoredFindings;
use foxguard::{Finding, engine, rules::RuleRegistry, secrets};
use log::{debug, info, warn};
use pyregistry_application::{
    ApplicationError, WheelArchiveSnapshot, WheelAuditFinding, WheelAuditFindingKind,
    WheelSourceSecurityScanResult, WheelSourceSecurityScanner,
};
use std::fs;
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

const MAX_SNIPPET_LEN: usize = 240;
const MAX_FOXGUARD_FILE_SIZE_BYTES: u64 = 1_048_576;

pub struct FoxGuardWheelSourceSecurityScanner {
    registry: RuleRegistry,
    ignored_rule_ids: IgnoredFindings,
}

impl Default for FoxGuardWheelSourceSecurityScanner {
    fn default() -> Self {
        Self::with_ignored_rules(Vec::<String>::new())
    }
}

impl WheelSourceSecurityScanner for FoxGuardWheelSourceSecurityScanner {
    fn scan_archive(
        &self,
        archive: &WheelArchiveSnapshot,
    ) -> Result<WheelSourceSecurityScanResult, ApplicationError> {
        let root = std::env::temp_dir().join(format!("pyregistry-foxguard-{}", Uuid::new_v4()));
        let scan_result = self.scan_archive_in_temp_dir(archive, &root);

        if let Err(error) = fs::remove_dir_all(&root)
            && root.exists()
        {
            warn!(
                "failed to clean FoxGuard temporary directory {}: {}",
                root.display(),
                error
            );
        }

        scan_result
    }
}

impl FoxGuardWheelSourceSecurityScanner {
    #[must_use]
    pub fn with_ignored_rules(ignored_rule_ids: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        Self {
            registry: RuleRegistry::new(),
            ignored_rule_ids: IgnoredFindings::new(ignored_rule_ids),
        }
    }

    fn scan_archive_in_temp_dir(
        &self,
        archive: &WheelArchiveSnapshot,
        root: &Path,
    ) -> Result<WheelSourceSecurityScanResult, ApplicationError> {
        fs::create_dir_all(root).map_err(|error| {
            ApplicationError::External(format!(
                "FoxGuard temp directory creation failed at {}: {error}",
                root.display()
            ))
        })?;

        let paths = materialize_archive_entries(archive, root)?;
        info!(
            "running FoxGuard source security scan for `{}` across {} archive file(s)",
            archive.wheel_filename,
            paths.len()
        );

        let source_scan = engine::scan_paths_with_root(
            root,
            &paths,
            &self.registry,
            MAX_FOXGUARD_FILE_SIZE_BYTES,
        );
        debug!(
            "FoxGuard source rules scanned {} language file(s) in {:?}",
            source_scan.files_scanned, source_scan.duration
        );

        let mut findings = Vec::new();
        findings.extend(source_scan.findings.into_iter().filter_map(|finding| {
            (!self.ignored_rule_ids.matches(&finding.rule_id))
                .then(|| map_foxguard_finding("source-rule", root, finding))
        }));
        findings.extend(
            secrets::scan_paths_with_config(
                root,
                &paths,
                &secrets::SecretScanConfig::default(),
                MAX_FOXGUARD_FILE_SIZE_BYTES,
            )
            .into_iter()
            .filter_map(|finding| {
                (!self.ignored_rule_ids.matches(&finding.rule_id))
                    .then(|| map_foxguard_finding("secret", root, finding))
            }),
        );

        Ok(WheelSourceSecurityScanResult {
            scanned_file_count: paths.len(),
            findings,
        })
    }
}

fn materialize_archive_entries(
    archive: &WheelArchiveSnapshot,
    root: &Path,
) -> Result<Vec<PathBuf>, ApplicationError> {
    let mut paths = Vec::with_capacity(archive.entries.len());

    for entry in &archive.entries {
        let Some(path) = safe_archive_path(root, &entry.path) else {
            warn!(
                "skipping unsafe wheel entry `{}` during FoxGuard scan of `{}`",
                entry.path, archive.wheel_filename
            );
            continue;
        };

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                ApplicationError::External(format!(
                    "FoxGuard temp directory creation failed at {}: {error}",
                    parent.display()
                ))
            })?;
        }
        fs::write(&path, &entry.contents).map_err(|error| {
            ApplicationError::External(format!(
                "FoxGuard temp file write failed at {}: {error}",
                path.display()
            ))
        })?;
        paths.push(path);
    }

    Ok(paths)
}

fn safe_archive_path(root: &Path, archive_path: &str) -> Option<PathBuf> {
    let mut safe_path = root.to_path_buf();
    let mut has_normal_component = false;

    for component in Path::new(archive_path).components() {
        match component {
            Component::Normal(part) => {
                safe_path.push(part);
                has_normal_component = true;
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }

    has_normal_component.then_some(safe_path)
}

fn map_foxguard_finding(source: &str, root: &Path, finding: Finding) -> WheelAuditFinding {
    let severity = finding.severity.to_string().to_ascii_uppercase();
    let mut evidence = vec![
        format!("scanner=FoxGuard {source}"),
        format!("rule={}", finding.rule_id),
        format!("severity={severity}"),
        format!("location=line {}, column {}", finding.line, finding.column),
    ];

    if let Some(cwe) = &finding.cwe {
        evidence.push(format!("cwe={cwe}"));
    }

    let snippet = finding.snippet.trim();
    if !snippet.is_empty() {
        evidence.push(format!("snippet={}", truncate(snippet, MAX_SNIPPET_LEN)));
    }

    WheelAuditFinding {
        kind: WheelAuditFindingKind::SourceSecurityFinding,
        path: relative_finding_path(root, &finding.file),
        summary: format!("FoxGuard {severity} finding: {}", finding.description),
        evidence,
    }
}

fn relative_finding_path(root: &Path, finding_file: &str) -> Option<String> {
    let path = Path::new(finding_file);
    path.strip_prefix(root)
        .ok()
        .or_else(|| path.strip_prefix(".").ok())
        .unwrap_or(path)
        .to_str()
        .map(|value| value.replace('\\', "/"))
        .filter(|value| !value.is_empty())
}

fn truncate(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        return value.to_string();
    }

    let mut truncated = value
        .chars()
        .scan(0usize, |used, ch| {
            let next = *used + ch.len_utf8();
            if next > max_len {
                None
            } else {
                *used = next;
                Some(ch)
            }
        })
        .collect::<String>();
    truncated.push_str("...");
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyregistry_application::WheelArchiveEntry;

    #[test]
    fn rejects_archive_paths_that_escape_temp_root() {
        let root = Path::new("/tmp/pyregistry-foxguard-test");

        assert!(safe_archive_path(root, "../escape.py").is_none());
        assert!(safe_archive_path(root, "/absolute.py").is_none());
        assert!(safe_archive_path(root, "./pkg/./module.py").is_some());
        assert!(safe_archive_path(root, "pkg/module.py").is_some());
    }

    #[test]
    fn reports_foxguard_secret_findings_from_archive_contents() {
        let scanner = FoxGuardWheelSourceSecurityScanner::default();
        let archive = WheelArchiveSnapshot {
            wheel_filename: "demo-0.1.0-py3-none-any.whl".into(),
            entries: vec![WheelArchiveEntry {
                path: "demo/secrets.py".into(),
                contents: b"AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'".to_vec(),
            }],
        };

        let result = scanner.scan_archive(&archive).expect("FoxGuard scan");

        assert_eq!(result.scanned_file_count, 1);
        assert!(result.findings.iter().any(|finding| {
            finding.kind == WheelAuditFindingKind::SourceSecurityFinding
                && finding
                    .evidence
                    .iter()
                    .any(|value| value.contains("secret/aws-access-key-id"))
        }));
    }

    #[test]
    fn configured_foxguard_rule_ignores_suppress_findings() {
        let scanner =
            FoxGuardWheelSourceSecurityScanner::with_ignored_rules(["secret/aws-access-key-id"]);
        let archive = WheelArchiveSnapshot {
            wheel_filename: "demo-0.1.0-py3-none-any.whl".into(),
            entries: vec![WheelArchiveEntry {
                path: "demo/secrets.py".into(),
                contents: b"AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'".to_vec(),
            }],
        };

        let result = scanner.scan_archive(&archive).expect("FoxGuard scan");

        assert_eq!(result.scanned_file_count, 1);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn materializes_only_safe_archive_entries() {
        let root =
            std::env::temp_dir().join(format!("pyregistry-foxguard-test-{}", Uuid::new_v4()));
        let archive = WheelArchiveSnapshot {
            wheel_filename: "demo.whl".into(),
            entries: vec![
                WheelArchiveEntry {
                    path: "pkg/module.py".into(),
                    contents: b"print('ok')".to_vec(),
                },
                WheelArchiveEntry {
                    path: "../escape.py".into(),
                    contents: b"bad".to_vec(),
                },
                WheelArchiveEntry {
                    path: ".".into(),
                    contents: b"skip".to_vec(),
                },
            ],
        };

        let paths = materialize_archive_entries(&archive, &root).expect("materialize");

        assert_eq!(paths.len(), 1);
        assert!(paths[0].ends_with("pkg/module.py"));
        assert_eq!(fs::read(&paths[0]).expect("contents"), b"print('ok')");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn relative_paths_and_snippets_are_sanitized_for_findings() {
        let root = Path::new("/tmp/pyregistry-foxguard-test");

        assert_eq!(
            relative_finding_path(root, "/tmp/pyregistry-foxguard-test/pkg/module.py").as_deref(),
            Some("pkg/module.py")
        );
        assert_eq!(
            relative_finding_path(root, "./pkg\\module.py").as_deref(),
            Some("pkg/module.py")
        );
        assert_eq!(truncate("short", MAX_SNIPPET_LEN), "short");
        assert!(truncate(&"a".repeat(MAX_SNIPPET_LEN + 10), MAX_SNIPPET_LEN).ends_with("..."));
    }

    #[test]
    fn scan_archive_in_temp_dir_reports_creation_failure() {
        let scanner = FoxGuardWheelSourceSecurityScanner::default();
        let root =
            std::env::temp_dir().join(format!("pyregistry-foxguard-file-root-{}", Uuid::new_v4()));
        fs::write(&root, b"not a directory").expect("write file root");
        let archive = WheelArchiveSnapshot {
            wheel_filename: "demo.whl".into(),
            entries: vec![WheelArchiveEntry {
                path: "pkg/module.py".into(),
                contents: b"print('ok')".to_vec(),
            }],
        };

        let error = scanner
            .scan_archive_in_temp_dir(&archive, &root)
            .expect_err("file root should fail");

        assert!(error.to_string().contains("temp directory creation failed"));
        let _ = fs::remove_file(root);
    }

    #[test]
    fn materialize_reports_parent_creation_and_file_write_failures() {
        let parent_root =
            std::env::temp_dir().join(format!("pyregistry-foxguard-parent-{}", Uuid::new_v4()));
        fs::create_dir(&parent_root).expect("create parent root");
        fs::write(parent_root.join("pkg"), b"not a directory").expect("create blocking file");
        let archive = WheelArchiveSnapshot {
            wheel_filename: "demo.whl".into(),
            entries: vec![WheelArchiveEntry {
                path: "pkg/module.py".into(),
                contents: b"print('ok')".to_vec(),
            }],
        };

        let error =
            materialize_archive_entries(&archive, &parent_root).expect_err("parent should fail");
        assert!(error.to_string().contains("temp directory creation failed"));
        let _ = fs::remove_dir_all(parent_root);

        let write_root =
            std::env::temp_dir().join(format!("pyregistry-foxguard-write-{}", Uuid::new_v4()));
        fs::create_dir(&write_root).expect("create write root");
        fs::create_dir(write_root.join("pkg")).expect("create directory target");
        let archive = WheelArchiveSnapshot {
            wheel_filename: "demo.whl".into(),
            entries: vec![WheelArchiveEntry {
                path: "pkg".into(),
                contents: b"cannot overwrite directory".to_vec(),
            }],
        };

        let error =
            materialize_archive_entries(&archive, &write_root).expect_err("write should fail");
        assert!(error.to_string().contains("temp file write failed"));
        let _ = fs::remove_dir_all(write_root);
    }

    #[test]
    fn maps_foxguard_finding_with_cwe_and_truncated_snippet() {
        let root = Path::new("/tmp/pyregistry-foxguard-test");
        let finding = Finding {
            rule_id: "python/dangerous-eval".into(),
            severity: foxguard::Severity::High,
            cwe: Some("CWE-95".into()),
            description: "dynamic code execution".into(),
            file: "/tmp/pyregistry-foxguard-test/pkg/module.py".into(),
            line: 7,
            column: 11,
            end_line: 7,
            end_column: 20,
            snippet: "x".repeat(MAX_SNIPPET_LEN + 20),
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
        };

        let mapped = map_foxguard_finding("source-rule", root, finding);

        assert_eq!(mapped.kind, WheelAuditFindingKind::SourceSecurityFinding);
        assert_eq!(mapped.path.as_deref(), Some("pkg/module.py"));
        assert!(mapped.summary.contains("HIGH"));
        assert!(mapped.evidence.iter().any(|value| value == "cwe=CWE-95"));
        assert!(
            mapped
                .evidence
                .iter()
                .any(|value| { value.starts_with("snippet=") && value.ends_with("...") })
        );
        assert_eq!(relative_finding_path(root, "").as_deref(), None);
    }
}
