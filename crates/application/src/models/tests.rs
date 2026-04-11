use super::*;
use std::path::PathBuf;

#[test]
fn artifact_security_uses_highest_vulnerability_severity() {
    let security = ArtifactSecurityDetails::scanned(vec![
        PackageVulnerability {
            id: "LOW-1".into(),
            summary: "low issue".into(),
            severity: "LOW".into(),
            fixed_versions: Vec::new(),
            references: Vec::new(),
            source: None,
            cvss_score: None,
        },
        PackageVulnerability {
            id: "CRITICAL-1".into(),
            summary: "critical issue".into(),
            severity: "CRITICAL".into(),
            fixed_versions: Vec::new(),
            references: Vec::new(),
            source: None,
            cvss_score: None,
        },
    ]);

    assert!(security.scanned);
    assert_eq!(security.vulnerability_count, 2);
    assert_eq!(security.highest_severity.as_deref(), Some("CRITICAL"));
}

#[test]
fn artifact_security_pending_and_failed_states_are_explicit() {
    let pending = ArtifactSecurityDetails::pending();
    assert!(!pending.scanned);
    assert_eq!(pending.vulnerability_count, 0);
    assert!(pending.scan_error.is_none());

    let failed = ArtifactSecurityDetails::failed("scanner unavailable");
    assert!(!failed.scanned);
    assert_eq!(failed.scan_error.as_deref(), Some("scanner unavailable"));
}

#[test]
fn distribution_labels_and_validation_statuses_are_human_readable() {
    assert_eq!(DistributionKind::Wheel.label(), "wheel");
    assert_eq!(DistributionKind::SourceTarGz.label(), "source tar.gz");
    assert_eq!(DistributionKind::SourceZip.label(), "source zip");

    assert_eq!(RegistryDistributionValidationStatus::Valid.label(), "valid");
    assert_eq!(
        RegistryDistributionValidationStatus::MissingBlob.label(),
        "missing blob"
    );
    assert_eq!(
        RegistryDistributionValidationStatus::ChecksumMismatch.label(),
        "checksum mismatch"
    );
    assert_eq!(
        RegistryDistributionValidationStatus::InvalidArchive.label(),
        "invalid archive"
    );
    assert_eq!(
        RegistryDistributionValidationStatus::UnsupportedDistribution.label(),
        "unsupported distribution"
    );
    assert_eq!(
        RegistryDistributionValidationStatus::StorageError.label(),
        "storage error"
    );
}

#[test]
fn distribution_validation_report_validity_tracks_checksum_status() {
    let base = DistributionInspection {
        kind: DistributionKind::Wheel,
        size_bytes: 1,
        sha256: "a".repeat(64),
        archive_entry_count: 1,
    };

    assert!(
        DistributionValidationReport {
            file_path: PathBuf::from("demo.whl"),
            inspection: base.clone(),
            checksum: DistributionChecksumStatus::NotProvided,
        }
        .is_valid()
    );
    assert!(
        DistributionValidationReport {
            file_path: PathBuf::from("demo.whl"),
            inspection: base.clone(),
            checksum: DistributionChecksumStatus::Matched {
                expected: "a".repeat(64)
            },
        }
        .is_valid()
    );
    assert!(
        !DistributionValidationReport {
            file_path: PathBuf::from("demo.whl"),
            inspection: base,
            checksum: DistributionChecksumStatus::Mismatched {
                expected: "a".repeat(64),
                actual: "b".repeat(64)
            },
        }
        .is_valid()
    );
}

#[test]
fn registry_distribution_report_counts_each_invalid_status() {
    let mut report = RegistryDistributionValidationReport::default();
    for status in [
        RegistryDistributionValidationStatus::Valid,
        RegistryDistributionValidationStatus::MissingBlob,
        RegistryDistributionValidationStatus::ChecksumMismatch,
        RegistryDistributionValidationStatus::InvalidArchive,
        RegistryDistributionValidationStatus::UnsupportedDistribution,
        RegistryDistributionValidationStatus::StorageError,
    ] {
        report.push_item(RegistryDistributionValidationItem {
            tenant_slug: "acme".into(),
            project_name: "demo".into(),
            version: "1.0.0".into(),
            filename: "demo.whl".into(),
            object_key: "objects/demo.whl".into(),
            expected_sha256: "a".repeat(64),
            actual_sha256: None,
            recorded_size_bytes: 1,
            actual_size_bytes: None,
            kind: Some(DistributionKind::Wheel),
            archive_entry_count: None,
            status,
            error: None,
        });
    }

    assert_eq!(report.artifact_count, 6);
    assert_eq!(report.valid_count, 1);
    assert_eq!(report.invalid_count, 5);
    assert_eq!(report.missing_blob_count, 1);
    assert_eq!(report.checksum_mismatch_count, 1);
    assert_eq!(report.invalid_archive_count, 1);
    assert_eq!(report.unsupported_distribution_count, 1);
    assert_eq!(report.storage_error_count, 1);
    assert!(!report.is_valid());
}

#[test]
fn wheel_scan_summaries_can_be_created_from_results_or_errors() {
    let finding = PackageVulnerability {
        id: "demo".into(),
        summary: "demo".into(),
        severity: "UNKNOWN".into(),
        fixed_versions: Vec::new(),
        references: Vec::new(),
        source: None,
        cvss_score: None,
    };
    let audit_finding = WheelAuditFinding {
        kind: WheelAuditFindingKind::VirusSignatureMatch,
        path: Some("demo.py".into()),
        summary: finding.summary,
        evidence: vec!["rule=demo".into()],
    };

    let source = WheelSourceSecurityScanSummary::from_result(&WheelSourceSecurityScanResult {
        scanned_file_count: 3,
        findings: vec![audit_finding.clone()],
    });
    assert!(source.enabled);
    assert_eq!(source.scanned_file_count, 3);
    assert_eq!(source.finding_count, 1);
    assert_eq!(
        WheelSourceSecurityScanSummary::failed("foxguard failed")
            .scan_error
            .as_deref(),
        Some("foxguard failed")
    );

    let virus = WheelVirusScanSummary::from_result(&WheelVirusScanResult {
        scanned_file_count: 4,
        signature_rule_count: 2,
        skipped_rule_count: 1,
        findings: vec![audit_finding],
    });
    assert!(virus.enabled);
    assert_eq!(virus.match_count, 1);
    assert_eq!(
        WheelVirusScanSummary::failed("yara failed")
            .scan_error
            .as_deref(),
        Some("yara failed")
    );
}

#[test]
fn severity_rank_orders_known_values() {
    assert!(severity_rank("critical") > severity_rank("high"));
    assert!(severity_rank("high") > severity_rank("medium"));
    assert!(severity_rank("medium") > severity_rank("low"));
    assert!(severity_rank("low") > severity_rank("unknown"));
    assert_eq!(severity_rank("custom"), 0);
}
