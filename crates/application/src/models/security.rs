use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PackageSecuritySummary {
    pub scanned_file_count: usize,
    pub vulnerable_file_count: usize,
    pub vulnerability_count: usize,
    pub highest_severity: Option<String>,
    pub scan_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactSecurityDetails {
    pub scanned: bool,
    pub vulnerability_count: usize,
    pub highest_severity: Option<String>,
    pub vulnerabilities: Vec<PackageVulnerability>,
    pub scan_error: Option<String>,
}

impl ArtifactSecurityDetails {
    #[must_use]
    pub fn pending() -> Self {
        Self {
            scanned: false,
            vulnerability_count: 0,
            highest_severity: None,
            vulnerabilities: Vec::new(),
            scan_error: None,
        }
    }

    #[must_use]
    pub fn failed(error: impl Into<String>) -> Self {
        Self {
            scanned: false,
            vulnerability_count: 0,
            highest_severity: None,
            vulnerabilities: Vec::new(),
            scan_error: Some(error.into()),
        }
    }

    #[must_use]
    pub fn scanned(vulnerabilities: Vec<PackageVulnerability>) -> Self {
        let highest_severity = vulnerabilities
            .iter()
            .map(|vulnerability| vulnerability.severity.as_str())
            .max_by_key(|severity| severity_rank(severity))
            .map(ToOwned::to_owned);

        Self {
            scanned: true,
            vulnerability_count: vulnerabilities.len(),
            highest_severity,
            vulnerabilities,
            scan_error: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageVulnerabilityQuery {
    pub package_name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageVulnerabilityReport {
    pub package_name: String,
    pub version: String,
    pub vulnerabilities: Vec<PackageVulnerability>,
    pub scan_error: Option<String>,
}

impl PackageVulnerabilityReport {
    #[must_use]
    pub fn clean(query: &PackageVulnerabilityQuery) -> Self {
        Self {
            package_name: query.package_name.clone(),
            version: query.version.clone(),
            vulnerabilities: Vec::new(),
            scan_error: None,
        }
    }

    #[must_use]
    pub fn failed(query: &PackageVulnerabilityQuery, error: impl Into<String>) -> Self {
        Self {
            package_name: query.package_name.clone(),
            version: query.version.clone(),
            vulnerabilities: Vec::new(),
            scan_error: Some(error.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageVulnerability {
    pub id: String,
    pub summary: String,
    pub severity: String,
    pub fixed_versions: Vec<String>,
    pub references: Vec<String>,
    pub source: Option<String>,
    pub cvss_score: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrySecurityReport {
    pub package_count: usize,
    pub file_count: usize,
    pub vulnerable_file_count: usize,
    pub vulnerability_count: usize,
    pub highest_severity: Option<String>,
    pub packages: Vec<RegistryPackageSecurityReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryPackageSecurityReport {
    pub tenant_slug: String,
    pub project_name: String,
    pub normalized_name: String,
    pub security: PackageSecuritySummary,
}

#[derive(Debug, Clone)]
pub struct VulnerablePackageNotification {
    pub tenant_slug: String,
    pub project_name: String,
    pub normalized_name: String,
    pub scanned_file_count: usize,
    pub vulnerable_file_count: usize,
    pub vulnerability_count: usize,
    pub highest_severity: Option<String>,
}

impl VulnerablePackageNotification {
    #[must_use]
    pub fn from_registry_package(report: &RegistryPackageSecurityReport) -> Self {
        Self {
            tenant_slug: report.tenant_slug.clone(),
            project_name: report.project_name.clone(),
            normalized_name: report.normalized_name.clone(),
            scanned_file_count: report.security.scanned_file_count,
            vulnerable_file_count: report.security.vulnerable_file_count,
            vulnerability_count: report.security.vulnerability_count,
            highest_severity: report.security.highest_severity.clone(),
        }
    }
}

#[must_use]
pub fn severity_rank(severity: &str) -> u8 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "unknown" => 1,
        _ => 0,
    }
}
