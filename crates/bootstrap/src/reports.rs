use pyregistry_application::{
    DistributionChecksumStatus, DistributionValidationReport, RegistryDistributionValidationItem,
    RegistryDistributionValidationReport, RegistryDistributionValidationStatus,
    RegistrySecurityReport, WheelAuditFinding, WheelAuditFindingKind, WheelAuditReport,
};
pub(crate) fn print_distribution_validation_report(report: &DistributionValidationReport) {
    println!("Distribution validation: {}", report.file_path.display());
    println!("Kind: {}", report.inspection.kind.label());
    println!("Size: {} bytes", report.inspection.size_bytes);
    println!("SHA256: {}", report.inspection.sha256);
    if report.inspection.file_type.matches_extension {
        println!(
            "Archive: valid ({} file entries read)",
            report.inspection.archive_entry_count
        );
    } else {
        println!("Archive: not inspected because the extension does not match the content");
    }
    println!(
        "Detected type: {} ({}, score {:.3})",
        report.inspection.file_type.label,
        report.inspection.file_type.mime_type,
        report.inspection.file_type.score
    );
    if report.inspection.file_type.matches_extension {
        println!("Extension: matches detected content");
    } else {
        let actual = report
            .inspection
            .file_type
            .actual_extension
            .as_deref()
            .unwrap_or("<none>");
        println!(
            "Extension: mismatch (actual {actual}, expected one of {})",
            report.inspection.file_type.expected_extensions.join(", ")
        );
    }

    match &report.checksum {
        DistributionChecksumStatus::NotProvided => {
            println!("Checksum: not provided");
        }
        DistributionChecksumStatus::Matched { expected } => {
            println!("Checksum: matched ({expected})");
        }
        DistributionChecksumStatus::Mismatched { expected, actual } => {
            println!("Checksum: mismatch");
            println!("Expected: {expected}");
            println!("Actual:   {actual}");
        }
    }
}

pub(crate) fn print_registry_distribution_validation_report(
    report: &RegistryDistributionValidationReport,
) {
    println!("Registry distribution validation");
    println!("Tenants checked: {}", report.tenant_count);
    println!("Projects checked: {}", report.project_count);
    println!("Releases checked: {}", report.release_count);
    println!("Files checked: {}", report.artifact_count);
    println!("Valid files: {}", report.valid_count);
    println!("Invalid files: {}", report.invalid_count);
    println!("Missing blobs: {}", report.missing_blob_count);
    println!("Checksum mismatches: {}", report.checksum_mismatch_count);
    println!("Extension mismatches: {}", report.extension_mismatch_count);
    println!("Invalid archives: {}", report.invalid_archive_count);
    println!(
        "Unsupported distributions: {}",
        report.unsupported_distribution_count
    );
    println!("Storage errors: {}", report.storage_error_count);

    if report.items.is_empty() {
        println!();
        println!("No distribution files were found for the selected scope.");
        return;
    }

    let invalid_items = report
        .items
        .iter()
        .filter(|item| item.status != RegistryDistributionValidationStatus::Valid)
        .collect::<Vec<_>>();
    if invalid_items.is_empty() {
        println!();
        println!("All stored distribution files are valid.");
        return;
    }

    println!();
    println!("Invalid files");
    for item in invalid_items {
        print_registry_distribution_validation_item(item);
    }
}

fn print_registry_distribution_validation_item(item: &RegistryDistributionValidationItem) {
    println!(
        "- {}/{}/{} {}: {}",
        item.tenant_slug,
        item.project_name,
        item.version,
        item.filename,
        item.status.label()
    );
    if let Some(actual_sha256) = &item.actual_sha256 {
        println!("  expected sha256: {}", item.expected_sha256);
        println!("  actual sha256:   {actual_sha256}");
    }
    if let Some(actual_size_bytes) = item.actual_size_bytes {
        println!(
            "  size: recorded={} bytes actual={} bytes",
            item.recorded_size_bytes, actual_size_bytes
        );
    }
    if let Some(entry_count) = item.archive_entry_count {
        println!("  archive entries read: {entry_count}");
    }
    if let Some(detected_file_type) = &item.detected_file_type {
        let mime_type = item.detected_mime_type.as_deref().unwrap_or("unknown");
        println!("  detected type: {detected_file_type} ({mime_type})");
    }
    if item.extension_matches == Some(false) {
        println!("  extension does not match detected file type");
    }
    if let Some(error) = &item.error {
        println!("  error: {error}");
    }
}

pub(crate) fn print_wheel_audit_report(report: &WheelAuditReport) {
    println!("Wheel audit: {}", report.wheel_filename);
    println!("Project: {}", report.project_name);
    println!("Scanned files: {}", report.scanned_file_count);
    print_source_security_scan_summary(report);
    print_virus_scan_summary(report);

    if report.findings.is_empty() {
        println!();
        println!(
            "No suspicious heuristic signals, FoxGuard findings, or YARA virus signatures were detected."
        );
        return;
    }

    for kind in [
        WheelAuditFindingKind::UnexpectedExecutable,
        WheelAuditFindingKind::NetworkString,
        WheelAuditFindingKind::PostInstallClue,
        WheelAuditFindingKind::PythonAstSuspiciousBehavior,
        WheelAuditFindingKind::SuspiciousDependency,
        WheelAuditFindingKind::SourceSecurityFinding,
        WheelAuditFindingKind::VirusSignatureMatch,
    ] {
        let findings: Vec<_> = report
            .findings
            .iter()
            .filter(|finding| finding.kind == kind)
            .collect();
        if findings.is_empty() {
            continue;
        }

        println!();
        println!("{} ({})", audit_heading(kind), findings.len());
        for finding in findings {
            print_wheel_finding(finding);
        }
    }
}

fn print_wheel_finding(finding: &WheelAuditFinding) {
    match &finding.path {
        Some(path) => println!("- {} [{}]", finding.summary, path),
        None => println!("- {}", finding.summary),
    }
    for evidence in &finding.evidence {
        println!("  evidence: {}", evidence);
    }
}

fn print_source_security_scan_summary(report: &WheelAuditReport) {
    println!(
        "FoxGuard source scan: {}",
        if report.source_security_scan.enabled {
            "enabled"
        } else {
            "unavailable"
        }
    );
    println!(
        "FoxGuard files inspected: {}, findings: {}",
        report.source_security_scan.scanned_file_count, report.source_security_scan.finding_count
    );
    if let Some(error) = &report.source_security_scan.scan_error {
        println!("FoxGuard scan warning: {error}");
    }
}

fn print_virus_scan_summary(report: &WheelAuditReport) {
    println!(
        "YARA virus scan: {}",
        if report.virus_scan.enabled {
            "enabled"
        } else {
            "unavailable"
        }
    );
    println!(
        "YARA rules loaded: {} (skipped {})",
        report.virus_scan.signature_rule_count, report.virus_scan.skipped_rule_count
    );
    println!(
        "YARA files scanned: {}, signature matches: {}",
        report.virus_scan.scanned_file_count, report.virus_scan.match_count
    );
    if let Some(error) = &report.virus_scan.scan_error {
        println!("YARA scan warning: {error}");
    }
}

pub(crate) fn audit_heading(kind: WheelAuditFindingKind) -> &'static str {
    match kind {
        WheelAuditFindingKind::UnexpectedExecutable => "Unexpected executables or shell scripts",
        WheelAuditFindingKind::NetworkString => "Network-related strings inside binaries",
        WheelAuditFindingKind::PostInstallClue => "Post-install behavior clues",
        WheelAuditFindingKind::PythonAstSuspiciousBehavior => "Python AST suspicious behavior",
        WheelAuditFindingKind::SuspiciousDependency => "Suspicious dependencies in METADATA",
        WheelAuditFindingKind::SourceSecurityFinding => "FoxGuard source security findings",
        WheelAuditFindingKind::VirusSignatureMatch => "YARA virus signature matches",
    }
}

pub(crate) fn print_registry_security_report(report: &RegistrySecurityReport) {
    println!("Registry security check");
    println!("Packages checked: {}", report.package_count);
    println!("Release files scanned: {}", report.file_count);
    println!("Vulnerable files: {}", report.vulnerable_file_count);
    println!("Advisory matches: {}", report.vulnerability_count);
    if let Some(severity) = &report.highest_severity {
        println!("Highest severity: {severity}");
    }

    if report.packages.is_empty() {
        println!();
        println!("No packages were found for the selected scope.");
        return;
    }

    for package in &report.packages {
        println!();
        println!(
            "{} / {} ({})",
            package.tenant_slug, package.project_name, package.normalized_name
        );
        if let Some(error) = &package.security.scan_error {
            println!("  Scan warning: {error}");
        }
        println!(
            "  Files scanned: {}, vulnerable files: {}, advisory matches: {}",
            package.security.scanned_file_count,
            package.security.vulnerable_file_count,
            package.security.vulnerability_count
        );
        if let Some(severity) = &package.security.highest_severity {
            println!("  Highest severity: {severity}");
        }
    }
}
