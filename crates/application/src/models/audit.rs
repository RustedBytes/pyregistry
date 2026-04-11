use serde::{Deserialize, Serialize};

pub struct WheelAuditReport {
    pub project_name: String,
    pub wheel_filename: String,
    pub scanned_file_count: usize,
    pub source_security_scan: WheelSourceSecurityScanSummary,
    pub virus_scan: WheelVirusScanSummary,
    pub findings: Vec<WheelAuditFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WheelAuditFindingKind {
    UnexpectedExecutable,
    NetworkString,
    PostInstallClue,
    PythonAstSuspiciousBehavior,
    SuspiciousDependency,
    VirusSignatureMatch,
    SourceSecurityFinding,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WheelSourceSecurityScanSummary {
    pub enabled: bool,
    pub scanned_file_count: usize,
    pub finding_count: usize,
    pub scan_error: Option<String>,
}

impl WheelSourceSecurityScanSummary {
    #[must_use]
    pub fn from_result(result: &WheelSourceSecurityScanResult) -> Self {
        Self {
            enabled: true,
            scanned_file_count: result.scanned_file_count,
            finding_count: result.findings.len(),
            scan_error: None,
        }
    }

    #[must_use]
    pub fn failed(error: impl Into<String>) -> Self {
        Self {
            enabled: false,
            scanned_file_count: 0,
            finding_count: 0,
            scan_error: Some(error.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WheelVirusScanSummary {
    pub enabled: bool,
    pub scanned_file_count: usize,
    pub signature_rule_count: usize,
    pub skipped_rule_count: usize,
    pub match_count: usize,
    pub scan_error: Option<String>,
}

impl WheelVirusScanSummary {
    #[must_use]
    pub fn from_result(result: &WheelVirusScanResult) -> Self {
        Self {
            enabled: result.signature_rule_count > 0,
            scanned_file_count: result.scanned_file_count,
            signature_rule_count: result.signature_rule_count,
            skipped_rule_count: result.skipped_rule_count,
            match_count: result.findings.len(),
            scan_error: None,
        }
    }

    #[must_use]
    pub fn failed(error: impl Into<String>) -> Self {
        Self {
            enabled: false,
            scanned_file_count: 0,
            signature_rule_count: 0,
            skipped_rule_count: 0,
            match_count: 0,
            scan_error: Some(error.into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct WheelVirusScanResult {
    pub scanned_file_count: usize,
    pub signature_rule_count: usize,
    pub skipped_rule_count: usize,
    pub findings: Vec<WheelAuditFinding>,
}

#[derive(Debug, Clone)]
pub struct WheelSourceSecurityScanResult {
    pub scanned_file_count: usize,
    pub findings: Vec<WheelAuditFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WheelAuditFinding {
    pub kind: WheelAuditFindingKind,
    pub path: Option<String>,
    pub summary: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct WheelArchiveSnapshot {
    pub wheel_filename: String,
    pub entries: Vec<WheelArchiveEntry>,
}

#[derive(Debug, Clone)]
pub struct WheelArchiveEntry {
    pub path: String,
    pub contents: Vec<u8>,
}
