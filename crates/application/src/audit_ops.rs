use crate::{
    ApplicationError, AuditStoredWheelCommand, AuditWheelCommand, WheelArchiveEntry,
    WheelArchiveReader, WheelAuditFinding, WheelAuditFindingKind, WheelAuditReport,
    WheelVirusScanSummary, WheelVirusScanner,
};
use log::{debug, info, warn};
use pyregistry_domain::ProjectName;
use std::sync::Arc;

pub struct WheelAuditUseCase {
    archive_reader: Arc<dyn WheelArchiveReader>,
    virus_scanner: Arc<dyn WheelVirusScanner>,
}

impl WheelAuditUseCase {
    #[must_use]
    pub fn new(
        archive_reader: Arc<dyn WheelArchiveReader>,
        virus_scanner: Arc<dyn WheelVirusScanner>,
    ) -> Self {
        Self {
            archive_reader,
            virus_scanner,
        }
    }

    pub fn audit(&self, command: AuditWheelCommand) -> Result<WheelAuditReport, ApplicationError> {
        info!(
            "auditing wheel `{}` for project `{}`",
            command.wheel_path.display(),
            command.project_name
        );
        let archive = self.archive_reader.read_wheel(&command.wheel_path)?;
        self.audit_archive(command.project_name, archive)
    }

    pub(crate) fn audit_archive(
        &self,
        project_name: String,
        archive: crate::WheelArchiveSnapshot,
    ) -> Result<WheelAuditReport, ApplicationError> {
        let expected_project = ProjectName::new(project_name.clone())?;
        debug!(
            "loaded wheel archive `{}` with {} file(s)",
            archive.wheel_filename,
            archive.entries.len()
        );

        let mut findings = Vec::new();
        findings.extend(unexpected_executable_findings(&archive.entries));
        findings.extend(network_string_findings(&archive.entries));
        findings.extend(post_install_findings(&archive.entries));
        findings.extend(suspicious_dependency_findings(
            &archive.entries,
            expected_project.normalized(),
        ));
        let virus_scan = match self.virus_scanner.scan_archive(&archive) {
            Ok(result) => {
                if result.findings.is_empty() {
                    info!(
                        "YARA virus scan completed for `{}` with no signature matches (rules={}, skipped={})",
                        archive.wheel_filename,
                        result.signature_rule_count,
                        result.skipped_rule_count
                    );
                } else {
                    warn!(
                        "YARA virus scan matched {} signature(s) in `{}`",
                        result.findings.len(),
                        archive.wheel_filename
                    );
                }
                let summary = WheelVirusScanSummary::from_result(&result);
                findings.extend(result.findings);
                summary
            }
            Err(error) => {
                warn!(
                    "YARA virus scan did not complete for `{}`: {}",
                    archive.wheel_filename, error
                );
                WheelVirusScanSummary::failed(error.to_string())
            }
        };

        if findings.is_empty() {
            info!(
                "wheel audit completed for `{}` with no suspicious findings",
                archive.wheel_filename
            );
        } else {
            warn!(
                "wheel audit completed for `{}` with {} finding(s)",
                archive.wheel_filename,
                findings.len()
            );
        }

        Ok(WheelAuditReport {
            project_name,
            wheel_filename: archive.wheel_filename,
            scanned_file_count: archive.entries.len(),
            virus_scan,
            findings,
        })
    }
}

impl crate::PyregistryApp {
    pub async fn audit_stored_wheel(
        &self,
        command: AuditStoredWheelCommand,
    ) -> Result<WheelAuditReport, ApplicationError> {
        info!(
            "auditing stored artifact `{}` for tenant `{}` project `{}` version `{}`",
            command.filename, command.tenant_slug, command.project_name, command.version
        );
        if !command.filename.ends_with(".whl") {
            return Err(ApplicationError::Conflict(format!(
                "artifact `{}` is not a wheel file",
                command.filename
            )));
        }

        let artifact = self
            .find_artifact(
                &command.tenant_slug,
                &command.project_name,
                &command.version,
                &command.filename,
            )
            .await?;
        let bytes = self
            .download_artifact(
                &command.tenant_slug,
                &command.project_name,
                &command.version,
                &command.filename,
            )
            .await?;

        let archive = self
            .wheel_archive_reader
            .read_wheel_bytes(&artifact.filename, &bytes)?;
        WheelAuditUseCase::new(
            self.wheel_archive_reader.clone(),
            self.wheel_virus_scanner.clone(),
        )
        .audit_archive(command.project_name, archive)
    }
}

fn unexpected_executable_findings(entries: &[WheelArchiveEntry]) -> Vec<WheelAuditFinding> {
    let mut findings = Vec::new();

    for entry in entries {
        let path = entry.path.to_ascii_lowercase();
        let mut evidence = Vec::new();

        if is_script_path(&path) {
            evidence.push("script-like filename".into());
        }
        if path.contains(".data/scripts/") {
            evidence.push("installed script payload".into());
        }
        if has_shebang(&entry.contents) {
            evidence.push("shebang header".into());
        }
        if looks_like_executable_binary(&entry.contents) && !is_known_extension_module(&path) {
            evidence.push("native executable header".into());
        }

        if !evidence.is_empty() {
            findings.push(WheelAuditFinding {
                kind: WheelAuditFindingKind::UnexpectedExecutable,
                path: Some(entry.path.clone()),
                summary: "unexpected executable or shell-oriented payload found".into(),
                evidence,
            });
        }
    }

    findings
}

fn network_string_findings(entries: &[WheelArchiveEntry]) -> Vec<WheelAuditFinding> {
    let mut findings = Vec::new();

    for entry in entries {
        if !is_binary_content(&entry.contents) {
            continue;
        }

        let matches = find_patterns(
            &ascii_strings(&entry.contents),
            &[
                "http://",
                "https://",
                "socket",
                "connect(",
                "connect ",
                "webhook",
                "curl",
                "wget",
                "invoke-webrequest",
                "powershell",
                "ws://",
                "wss://",
                "urllib",
                "requests",
                "tcp",
                "udp",
            ],
            4,
        );

        if !matches.is_empty() {
            findings.push(WheelAuditFinding {
                kind: WheelAuditFindingKind::NetworkString,
                path: Some(entry.path.clone()),
                summary: "binary payload contains network-related strings".into(),
                evidence: matches,
            });
        }
    }

    findings
}

fn post_install_findings(entries: &[WheelArchiveEntry]) -> Vec<WheelAuditFinding> {
    let mut findings = Vec::new();

    for entry in entries {
        let path = entry.path.to_ascii_lowercase();
        let content_text = String::from_utf8_lossy(&entry.contents);
        let mut evidence = Vec::new();

        if path.ends_with(".pth") {
            evidence.push("`.pth` file executes import-time code".into());
        }
        if path.ends_with("sitecustomize.py") || path.ends_with("usercustomize.py") {
            evidence.push("Python startup hook".into());
        }
        if path.ends_with("entry_points.txt") {
            evidence.push("entry point definitions present".into());
        }
        if path.contains(".data/scripts/") {
            evidence.push("script installed into environment".into());
        }

        let text_matches = find_patterns(
            &content_text,
            &[
                "subprocess",
                "os.system",
                "pip._internal",
                "sitecustomize",
                "usercustomize",
                "atexit",
                "exec(",
                "eval(",
            ],
            4,
        );
        evidence.extend(text_matches);

        if !evidence.is_empty() {
            findings.push(WheelAuditFinding {
                kind: WheelAuditFindingKind::PostInstallClue,
                path: Some(entry.path.clone()),
                summary: "package contents include post-install or startup behavior clues".into(),
                evidence,
            });
        }
    }

    findings
}

fn suspicious_dependency_findings(
    entries: &[WheelArchiveEntry],
    expected_project_normalized: &str,
) -> Vec<WheelAuditFinding> {
    let mut findings = Vec::new();

    for entry in entries {
        if !entry.path.ends_with("METADATA") {
            continue;
        }

        let metadata = String::from_utf8_lossy(&entry.contents);
        let mut evidence = Vec::new();

        if let Some(name) = metadata_field(&metadata, "Name") {
            if let Ok(metadata_project) = ProjectName::new(name.to_string()) {
                if metadata_project.normalized() != expected_project_normalized {
                    evidence.push(format!(
                        "metadata project name `{}` does not match requested project `{}`",
                        metadata_project.original(),
                        expected_project_normalized
                    ));
                }
            }
        }

        for dependency in metadata
            .lines()
            .filter_map(|line| line.strip_prefix("Requires-Dist:"))
            .map(str::trim)
        {
            let dependency_lower = dependency.to_ascii_lowercase();
            if dependency_lower.contains(" @ ")
                || dependency_lower.contains("://")
                || dependency_lower.contains("git+")
                || dependency_lower.contains("file:")
            {
                evidence.push(format!("direct URL or file dependency: {dependency}"));
                continue;
            }

            let suspicious_name = dependency_name(dependency);
            if matches!(
                suspicious_name.as_deref(),
                Some(
                    "pip"
                        | "setuptools"
                        | "wheel"
                        | "virtualenv"
                        | "poetry"
                        | "poetry-core"
                        | "twine"
                        | "build"
                        | "installer"
                        | "pip-tools"
                        | "pytest"
                        | "tox"
                        | "nox"
                )
            ) {
                evidence.push(format!("unusual runtime dependency: {dependency}"));
            }
        }

        if !evidence.is_empty() {
            findings.push(WheelAuditFinding {
                kind: WheelAuditFindingKind::SuspiciousDependency,
                path: Some(entry.path.clone()),
                summary: "METADATA contains suspicious dependency signals".into(),
                evidence,
            });
        }
    }

    findings
}

fn is_script_path(path: &str) -> bool {
    matches!(
        path.rsplit('.').next(),
        Some("sh" | "bash" | "command" | "ps1" | "bat" | "cmd")
    )
}

fn is_known_extension_module(path: &str) -> bool {
    matches!(
        path.rsplit('.').next(),
        Some("so" | "pyd" | "dll" | "dylib")
    )
}

fn has_shebang(contents: &[u8]) -> bool {
    contents.starts_with(b"#!")
}

fn looks_like_executable_binary(contents: &[u8]) -> bool {
    contents.starts_with(b"\x7fELF")
        || contents.starts_with(b"MZ")
        || contents.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || contents.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || contents.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || contents.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
}

fn is_binary_content(contents: &[u8]) -> bool {
    if contents.is_empty() {
        return false;
    }
    if contents.contains(&0) {
        return true;
    }

    let suspicious = contents
        .iter()
        .filter(|byte| !(byte.is_ascii_graphic() || byte.is_ascii_whitespace()))
        .count();
    suspicious * 5 > contents.len()
}

fn ascii_strings(contents: &[u8]) -> String {
    let mut out = String::new();
    let mut current = String::new();

    for byte in contents {
        let ch = *byte as char;
        if ch.is_ascii_graphic() || ch == ' ' {
            current.push(ch);
        } else {
            if current.len() >= 4 {
                if !out.is_empty() {
                    out.push('\n');
                }
                out.push_str(&current);
            }
            current.clear();
        }
    }

    if current.len() >= 4 {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&current);
    }

    out
}

fn find_patterns(haystack: &str, patterns: &[&str], limit: usize) -> Vec<String> {
    let lower = haystack.to_ascii_lowercase();
    let mut hits = Vec::new();

    for pattern in patterns {
        if lower.contains(pattern) {
            hits.push((*pattern).to_string());
        }
        if hits.len() >= limit {
            break;
        }
    }

    hits
}

fn metadata_field<'a>(metadata: &'a str, field: &str) -> Option<&'a str> {
    metadata
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{field}:")))
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn dependency_name(requirement: &str) -> Option<String> {
    requirement
        .split([' ', ';', '[', '(', '<', '>', '=', '!'])
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| name.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{WheelArchiveSnapshot, WheelAuditFindingKind, WheelVirusScanResult};
    use std::path::Path;

    struct FakeReader {
        archive: WheelArchiveSnapshot,
    }

    impl crate::WheelArchiveReader for FakeReader {
        fn read_wheel(&self, _path: &Path) -> Result<WheelArchiveSnapshot, ApplicationError> {
            Ok(self.archive.clone())
        }

        fn read_wheel_bytes(
            &self,
            _wheel_filename: &str,
            _bytes: &[u8],
        ) -> Result<WheelArchiveSnapshot, ApplicationError> {
            Ok(self.archive.clone())
        }
    }

    struct FakeVirusScanner;

    impl crate::WheelVirusScanner for FakeVirusScanner {
        fn scan_archive(
            &self,
            archive: &WheelArchiveSnapshot,
        ) -> Result<WheelVirusScanResult, ApplicationError> {
            let findings = archive
                .entries
                .iter()
                .filter(|entry| entry.contents.windows(5).any(|window| window == b"EICAR"))
                .map(|entry| WheelAuditFinding {
                    kind: WheelAuditFindingKind::VirusSignatureMatch,
                    path: Some(entry.path.clone()),
                    summary: "YARA virus signature matched wheel entry".into(),
                    evidence: vec!["rule=Test_EICAR".into()],
                })
                .collect();

            Ok(WheelVirusScanResult {
                scanned_file_count: archive.entries.len(),
                signature_rule_count: 1,
                skipped_rule_count: 0,
                findings,
            })
        }
    }

    #[test]
    fn reports_requested_audit_signals() {
        let reader = Arc::new(FakeReader {
            archive: WheelArchiveSnapshot {
                wheel_filename: "demo_pkg-0.1.0-py3-none-any.whl".into(),
                entries: vec![
                    WheelArchiveEntry {
                        path: "demo_pkg/data/install.sh".into(),
                        contents: b"#!/bin/sh\ncurl https://example.com".to_vec(),
                    },
                    WheelArchiveEntry {
                        path: "demo_pkg/native.bin".into(),
                        contents: b"\x7fELF\0https://evil.example/socket".to_vec(),
                    },
                    WheelArchiveEntry {
                        path: "demo_pkg/startup.pth".into(),
                        contents: b"import sitecustomize".to_vec(),
                    },
                    WheelArchiveEntry {
                        path: "demo_pkg-0.1.0.dist-info/METADATA".into(),
                        contents: br#"Name: demo-pkg
Requires-Dist: pip>=24
Requires-Dist: helper @ https://example.com/helper.whl
"#
                        .to_vec(),
                    },
                    WheelArchiveEntry {
                        path: "demo_pkg/payload.dat".into(),
                        contents: b"EICAR test payload".to_vec(),
                    },
                ],
            },
        });
        let use_case = WheelAuditUseCase::new(reader, Arc::new(FakeVirusScanner));

        let report = use_case
            .audit(AuditWheelCommand {
                project_name: "demo-pkg".into(),
                wheel_path: "demo_pkg-0.1.0-py3-none-any.whl".into(),
            })
            .expect("audit report");

        assert_eq!(report.scanned_file_count, 5);
        assert_eq!(report.virus_scan.signature_rule_count, 1);
        assert_eq!(report.virus_scan.match_count, 1);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.kind == WheelAuditFindingKind::UnexpectedExecutable)
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.kind == WheelAuditFindingKind::NetworkString)
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.kind == WheelAuditFindingKind::PostInstallClue)
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.kind == WheelAuditFindingKind::SuspiciousDependency)
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.kind == WheelAuditFindingKind::VirusSignatureMatch)
        );
    }
}
