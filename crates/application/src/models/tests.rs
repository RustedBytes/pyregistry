use super::*;
use crate::models::ports::{
    CancellationSignal, NoopPackagePublishNotifier, NoopVulnerabilityNotifier,
    NoopWheelAuditNotifier, PackagePublishNotifier, VulnerabilityNotifier, WheelAuditNotifier,
};
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
fn package_and_dependency_vulnerability_reports_preserve_query_identity() {
    let package_query = PackageVulnerabilityQuery {
        package_name: "demo".into(),
        version: "1.2.3".into(),
    };
    let clean_package = PackageVulnerabilityReport::clean(&package_query);
    assert_eq!(clean_package.package_name, "demo");
    assert_eq!(clean_package.version, "1.2.3");
    assert!(clean_package.vulnerabilities.is_empty());
    assert!(clean_package.scan_error.is_none());

    let failed_package = PackageVulnerabilityReport::failed(&package_query, "osv unavailable");
    assert_eq!(failed_package.package_name, "demo");
    assert_eq!(failed_package.version, "1.2.3");
    assert_eq!(
        failed_package.scan_error.as_deref(),
        Some("osv unavailable")
    );

    let dependency_query = DependencyVulnerabilityQuery {
        package_name: "dep".into(),
        version: "4.5.6".into(),
    };
    let clean_dependency = DependencyVulnerabilityReport::clean(&dependency_query);
    assert_eq!(clean_dependency.package_name, "dep");
    assert_eq!(clean_dependency.version, "4.5.6");
    assert!(clean_dependency.vulnerabilities.is_empty());
    assert!(clean_dependency.scan_error.is_none());

    let failed_dependency =
        DependencyVulnerabilityReport::failed(&dependency_query, "dependency scanner failed");
    assert_eq!(failed_dependency.package_name, "dep");
    assert_eq!(failed_dependency.version, "4.5.6");
    assert_eq!(
        failed_dependency.scan_error.as_deref(),
        Some("dependency scanner failed")
    );
}

#[test]
fn dependency_details_and_security_summary_count_dependency_risk() {
    let report = DependencyVulnerabilityReport {
        package_name: "dep".into(),
        version: "4.5.6".into(),
        vulnerabilities: vec![
            PackageVulnerability {
                id: "LOW-1".into(),
                summary: "low".into(),
                severity: "LOW".into(),
                fixed_versions: vec!["4.5.7".into()],
                references: vec!["https://example.test/low".into()],
                source: Some("test".into()),
                cvss_score: Some(2.0),
            },
            PackageVulnerability {
                id: "HIGH-1".into(),
                summary: "high".into(),
                severity: "HIGH".into(),
                fixed_versions: vec!["5.0.0".into()],
                references: vec!["https://example.test/high".into()],
                source: Some("test".into()),
                cvss_score: Some(8.0),
            },
        ],
        scan_error: None,
    };

    let vulnerable = DependencyVulnerabilityDetails::from_report("dep>=4".into(), report);
    assert_eq!(vulnerable.requirement, "dep>=4");
    assert_eq!(vulnerable.vulnerability_count, 2);
    assert_eq!(vulnerable.highest_severity.as_deref(), Some("HIGH"));

    let clean = DependencyVulnerabilityDetails::from_report(
        "clean==1".into(),
        DependencyVulnerabilityReport {
            package_name: "clean".into(),
            version: "1.0.0".into(),
            vulnerabilities: Vec::new(),
            scan_error: None,
        },
    );
    let security =
        ArtifactSecurityDetails::pending().with_dependencies(vec![vulnerable, clean], None);

    assert_eq!(security.dependency_count, 2);
    assert_eq!(security.vulnerable_dependency_count, 1);
    assert_eq!(security.dependency_vulnerability_count, 2);
    assert!(security.dependency_scan_error.is_none());
}

#[test]
fn notification_models_are_derived_from_application_reports() {
    let package = RegistryPackageSecurityReport {
        tenant_slug: "acme".into(),
        project_name: "demo".into(),
        normalized_name: "demo".into(),
        security: PackageSecuritySummary {
            scanned_file_count: 3,
            vulnerable_file_count: 2,
            vulnerability_count: 4,
            highest_severity: Some("CRITICAL".into()),
            ..PackageSecuritySummary::default()
        },
    };
    let vulnerable = VulnerablePackageNotification::from_registry_package(&package);
    assert_eq!(vulnerable.tenant_slug, "acme");
    assert_eq!(vulnerable.project_name, "demo");
    assert_eq!(vulnerable.scanned_file_count, 3);
    assert_eq!(vulnerable.vulnerable_file_count, 2);
    assert_eq!(vulnerable.vulnerability_count, 4);
    assert_eq!(vulnerable.highest_severity.as_deref(), Some("CRITICAL"));

    let finding = WheelAuditFinding {
        kind: WheelAuditFindingKind::NetworkString,
        path: Some("demo/__init__.py".into()),
        summary: "opens a network connection".into(),
        evidence: vec!["socket".into()],
    };
    let audit = WheelAuditReport {
        project_name: "demo".into(),
        wheel_filename: "demo-1.0.0-py3-none-any.whl".into(),
        scanned_file_count: 8,
        source_security_scan: WheelSourceSecurityScanSummary::failed("foxguard failed"),
        virus_scan: WheelVirusScanSummary::failed("yara failed"),
        findings: vec![finding],
    };
    let notification = WheelAuditFindingNotification::from_audit_report("acme", "1.0.0", &audit);
    assert_eq!(notification.tenant_slug, "acme");
    assert_eq!(notification.project_name, "demo");
    assert_eq!(notification.version, "1.0.0");
    assert_eq!(notification.wheel_filename, audit.wheel_filename);
    assert_eq!(notification.scanned_file_count, 8);
    assert_eq!(
        notification.source_security_scan_error.as_deref(),
        Some("foxguard failed")
    );
    assert_eq!(
        notification.virus_scan_error.as_deref(),
        Some("yara failed")
    );
    assert_eq!(notification.findings.len(), 1);
}

#[tokio::test]
async fn noop_notifiers_and_never_cancelled_are_boundary_defaults() {
    let vulnerable = VulnerablePackageNotification {
        tenant_slug: "acme".into(),
        project_name: "demo".into(),
        normalized_name: "demo".into(),
        scanned_file_count: 1,
        vulnerable_file_count: 1,
        vulnerability_count: 1,
        highest_severity: Some("HIGH".into()),
    };
    NoopVulnerabilityNotifier
        .notify_vulnerable_package(&vulnerable)
        .await
        .expect("noop vulnerable package notifier");

    NoopPackagePublishNotifier
        .notify_package_publish(&PackagePublishNotification {
            kind: PackagePublishEventKind::NewPackage,
            tenant_slug: "acme".into(),
            project_name: "demo".into(),
            normalized_name: "demo".into(),
            version: "1.0.0".into(),
            filename: "demo-1.0.0.tar.gz".into(),
            size_bytes: 10,
            sha256: "a".repeat(64),
        })
        .await
        .expect("noop publish notifier");

    NoopWheelAuditNotifier
        .notify_wheel_audit_findings(&WheelAuditFindingNotification {
            tenant_slug: "acme".into(),
            project_name: "demo".into(),
            version: "1.0.0".into(),
            wheel_filename: "demo.whl".into(),
            scanned_file_count: 1,
            source_security_scan_error: None,
            virus_scan_error: None,
            findings: Vec::new(),
        })
        .await
        .expect("noop audit notifier");

    let cancellation = NeverCancelled;
    assert!(!cancellation.is_cancelled());
    let pending = tokio::time::timeout(
        std::time::Duration::from_millis(1),
        cancellation.cancelled(),
    )
    .await;
    assert!(pending.is_err());
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
        RegistryDistributionValidationStatus::ExtensionMismatch.label(),
        "extension mismatch"
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
        file_type: FileTypeInspection::unknown_for_extension(
            Some("whl".into()),
            vec!["whl".into()],
        ),
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
        RegistryDistributionValidationStatus::ExtensionMismatch,
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
            detected_file_type: Some("zip".into()),
            detected_mime_type: Some("application/zip".into()),
            extension_matches: Some(true),
            archive_entry_count: None,
            status,
            error: None,
        });
    }

    assert_eq!(report.artifact_count, 7);
    assert_eq!(report.valid_count, 1);
    assert_eq!(report.invalid_count, 6);
    assert_eq!(report.missing_blob_count, 1);
    assert_eq!(report.checksum_mismatch_count, 1);
    assert_eq!(report.extension_mismatch_count, 1);
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
