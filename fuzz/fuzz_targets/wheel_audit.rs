#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use pyregistry_application::{
    ApplicationError, AuditWheelCommand, WheelArchiveEntry, WheelArchiveReader,
    WheelArchiveSnapshot, WheelAuditUseCase, WheelSourceSecurityScanResult,
    WheelSourceSecurityScanner, WheelVirusScanResult, WheelVirusScanner,
};
use pyregistry_domain::ProjectName;
use std::path::Path;
use std::sync::Arc;

const MAX_AUDIT_ENTRIES: usize = 64;
const MAX_ENTRY_BYTES: usize = 16 * 1024;

#[derive(Debug, Arbitrary)]
struct AuditInput {
    project_name: String,
    wheel_filename: String,
    entries: Vec<AuditEntryInput>,
}

#[derive(Debug, Arbitrary)]
struct AuditEntryInput {
    path: String,
    contents: Vec<u8>,
}

#[derive(Clone)]
struct FuzzArchiveReader {
    archive: WheelArchiveSnapshot,
}

impl WheelArchiveReader for FuzzArchiveReader {
    fn read_wheel(&self, _path: &Path) -> Result<WheelArchiveSnapshot, ApplicationError> {
        Ok(self.archive.clone())
    }

    fn read_wheel_bytes(
        &self,
        wheel_filename: &str,
        bytes: &[u8],
    ) -> Result<WheelArchiveSnapshot, ApplicationError> {
        Ok(WheelArchiveSnapshot {
            wheel_filename: wheel_filename.to_string(),
            entries: vec![WheelArchiveEntry {
                path: "fuzz.py".into(),
                contents: bytes.to_vec(),
            }],
        })
    }
}

struct NoopVirusScanner;

impl WheelVirusScanner for NoopVirusScanner {
    fn scan_archive(
        &self,
        archive: &WheelArchiveSnapshot,
    ) -> Result<WheelVirusScanResult, ApplicationError> {
        Ok(WheelVirusScanResult {
            scanned_file_count: archive.entries.len(),
            signature_rule_count: 0,
            skipped_rule_count: 0,
            findings: Vec::new(),
        })
    }
}

struct NoopSourceSecurityScanner;

impl WheelSourceSecurityScanner for NoopSourceSecurityScanner {
    fn scan_archive(
        &self,
        archive: &WheelArchiveSnapshot,
    ) -> Result<WheelSourceSecurityScanResult, ApplicationError> {
        Ok(WheelSourceSecurityScanResult {
            scanned_file_count: archive.entries.len(),
            findings: Vec::new(),
        })
    }
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = AuditInput::arbitrary(&mut unstructured) else {
        return;
    };

    let project_name = ProjectName::new(input.project_name.as_str())
        .map(|name| name.original().to_string())
        .unwrap_or_else(|_| "fuzz-project".into());
    let wheel_filename = if input.wheel_filename.trim().is_empty() {
        "fuzz_project-0.1.0-py3-none-any.whl".into()
    } else {
        input.wheel_filename
    };
    let entries = input
        .entries
        .into_iter()
        .take(MAX_AUDIT_ENTRIES)
        .map(|entry| WheelArchiveEntry {
            path: if entry.path.is_empty() {
                "fuzz.py".into()
            } else {
                entry.path
            },
            contents: entry.contents.into_iter().take(MAX_ENTRY_BYTES).collect(),
        })
        .collect();

    let use_case = WheelAuditUseCase::new(
        Arc::new(FuzzArchiveReader {
            archive: WheelArchiveSnapshot {
                wheel_filename,
                entries,
            },
        }),
        Arc::new(NoopVirusScanner),
        Arc::new(NoopSourceSecurityScanner),
    );

    let report = use_case.audit(AuditWheelCommand {
        project_name: project_name.clone(),
        wheel_path: "fuzz.whl".into(),
    });

    if let Ok(report) = report {
        assert_eq!(report.project_name, project_name);
        assert_eq!(report.scanned_file_count, report.source_security_scan.scanned_file_count);
        assert_eq!(report.scanned_file_count, report.virus_scan.scanned_file_count);
        assert_eq!(report.source_security_scan.finding_count, 0);
        assert_eq!(report.virus_scan.match_count, 0);
        assert!(report
            .findings
            .iter()
            .all(|finding| !finding.summary.trim().is_empty()));
    }
});
