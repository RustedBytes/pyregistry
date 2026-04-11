use crate::ApplicationError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pyregistry_domain::{
    AdminUser, ApiToken, Artifact, ArtifactId, AttestationBundle, AuditEvent, DeletionMode,
    Project, ProjectId, PublishIdentity, Release, ReleaseId, ReleaseVersion, Tenant, TenantId,
    TokenId, TokenScope, TrustedPublisher, TrustedPublisherProvider,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryOverview {
    pub tenant_count: usize,
    pub project_count: usize,
    pub release_count: usize,
    pub artifact_count: usize,
    pub total_storage_bytes: u64,
    pub mirrored_project_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub tenant_slug: String,
    pub project_name: String,
    pub normalized_name: String,
    pub summary: String,
    pub source: String,
    pub latest_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentActivity {
    pub project_name: String,
    pub tenant_slug: String,
    pub source: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MirrorRefreshReport {
    pub tenant_count: usize,
    pub mirrored_project_count: usize,
    pub refreshed_project_count: usize,
    pub failed_project_count: usize,
    pub failures: Vec<MirrorRefreshFailure>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorRefreshFailure {
    pub tenant_slug: String,
    pub project_name: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardMetrics {
    pub tenant_slug: String,
    pub project_count: usize,
    pub release_count: usize,
    pub artifact_count: usize,
    pub token_count: usize,
    pub trusted_publisher_count: usize,
    pub recent_activity: Vec<RecentActivity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleProject {
    pub name: String,
    pub normalized_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleArtifactLink {
    pub filename: String,
    pub version: String,
    pub sha256: String,
    pub url: String,
    pub provenance_url: Option<String>,
    pub yanked_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleProjectPage {
    pub tenant_slug: String,
    pub project_name: String,
    pub artifacts: Vec<SimpleArtifactLink>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceDescriptor {
    pub filename: String,
    pub media_type: String,
    pub payload: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageArtifactDetails {
    pub filename: String,
    pub version: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub yanked_reason: Option<String>,
    pub security: ArtifactSecurityDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageReleaseDetails {
    pub version: String,
    pub yanked_reason: Option<String>,
    pub artifacts: Vec<PackageArtifactDetails>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedPublisherDescriptor {
    pub provider: String,
    pub issuer: String,
    pub audience: String,
    pub project_name: String,
    pub claim_rules: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageDetails {
    pub tenant_slug: String,
    pub project_name: String,
    pub normalized_name: String,
    pub summary: String,
    pub description: String,
    pub source: String,
    pub security: PackageSecuritySummary,
    pub releases: Vec<PackageReleaseDetails>,
    pub trusted_publishers: Vec<TrustedPublisherDescriptor>,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishTokenGrant {
    pub tenant_slug: String,
    pub project_name: String,
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedAccess {
    pub tenant: Tenant,
    pub token: ApiToken,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminSession {
    pub email: String,
    pub tenant_slug: Option<String>,
    pub is_superadmin: bool,
}

#[derive(Debug, Clone)]
pub struct RecordAuditEventCommand {
    pub actor: String,
    pub action: String,
    pub tenant_slug: Option<String>,
    pub target: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTrailEntry {
    pub occurred_at: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub tenant_slug: Option<String>,
    pub target: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct CreateTenantCommand {
    pub slug: String,
    pub display_name: String,
    pub mirroring_enabled: bool,
    pub admin_email: String,
    pub admin_password: String,
}

#[derive(Debug, Clone)]
pub struct IssueApiTokenCommand {
    pub tenant_slug: String,
    pub label: String,
    pub scopes: Vec<TokenScope>,
    pub ttl_hours: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct IssuedApiToken {
    pub label: String,
    pub secret: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct UploadArtifactCommand {
    pub tenant_slug: String,
    pub project_name: String,
    pub version: String,
    pub filename: String,
    pub summary: String,
    pub description: String,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RegisterTrustedPublisherCommand {
    pub tenant_slug: String,
    pub project_name: String,
    pub provider: TrustedPublisherProvider,
    pub issuer: String,
    pub audience: String,
    pub claim_rules: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct MintOidcPublishTokenCommand {
    pub tenant_slug: String,
    pub project_name: String,
    pub oidc_token: String,
}

#[derive(Debug, Clone)]
pub struct DeletionCommand {
    pub tenant_slug: String,
    pub project_name: String,
    pub version: Option<String>,
    pub filename: Option<String>,
    pub reason: Option<String>,
    pub mode: DeletionMode,
}

#[derive(Debug, Clone)]
pub struct MirroredArtifactSnapshot {
    pub filename: String,
    pub version: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub blake2b_256: Option<String>,
    pub download_url: String,
    pub provenance_payload: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MirroredProjectSnapshot {
    pub canonical_name: String,
    pub summary: String,
    pub description: String,
    pub artifacts: Vec<MirroredArtifactSnapshot>,
}

#[derive(Debug, Clone)]
pub struct AuditWheelCommand {
    pub project_name: String,
    pub wheel_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct AuditStoredWheelCommand {
    pub tenant_slug: String,
    pub project_name: String,
    pub version: String,
    pub filename: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WheelAuditReport {
    pub project_name: String,
    pub wheel_filename: String,
    pub scanned_file_count: usize,
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

#[async_trait]
pub trait RegistryStore: Send + Sync {
    async fn registry_overview(&self) -> Result<RegistryOverview, ApplicationError>;
    async fn save_tenant(&self, tenant: Tenant) -> Result<(), ApplicationError>;
    async fn list_tenants(&self) -> Result<Vec<Tenant>, ApplicationError>;
    async fn get_tenant_by_slug(&self, slug: &str) -> Result<Option<Tenant>, ApplicationError>;

    async fn save_admin_user(&self, user: AdminUser) -> Result<(), ApplicationError>;
    async fn get_admin_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<AdminUser>, ApplicationError>;

    async fn save_api_token(&self, token: ApiToken) -> Result<(), ApplicationError>;
    async fn list_api_tokens(&self, tenant_id: TenantId)
    -> Result<Vec<ApiToken>, ApplicationError>;
    async fn revoke_api_token(
        &self,
        tenant_id: TenantId,
        token_id: TokenId,
    ) -> Result<(), ApplicationError>;

    async fn save_project(&self, project: Project) -> Result<(), ApplicationError>;
    async fn list_projects(&self, tenant_id: TenantId) -> Result<Vec<Project>, ApplicationError>;
    async fn search_projects(
        &self,
        tenant_id: TenantId,
        query: &str,
    ) -> Result<Vec<SearchHit>, ApplicationError>;
    async fn get_project_by_normalized_name(
        &self,
        tenant_id: TenantId,
        normalized_name: &str,
    ) -> Result<Option<Project>, ApplicationError>;

    async fn save_release(&self, release: Release) -> Result<(), ApplicationError>;
    async fn list_releases(&self, project_id: ProjectId) -> Result<Vec<Release>, ApplicationError>;
    async fn get_release_by_version(
        &self,
        project_id: ProjectId,
        version: &ReleaseVersion,
    ) -> Result<Option<Release>, ApplicationError>;
    async fn delete_release(&self, release_id: ReleaseId) -> Result<(), ApplicationError>;

    async fn save_artifact(&self, artifact: Artifact) -> Result<(), ApplicationError>;
    async fn list_artifacts(
        &self,
        release_id: ReleaseId,
    ) -> Result<Vec<Artifact>, ApplicationError>;
    async fn get_artifact_by_filename(
        &self,
        release_id: ReleaseId,
        filename: &str,
    ) -> Result<Option<Artifact>, ApplicationError>;
    async fn delete_artifact(&self, artifact_id: ArtifactId) -> Result<(), ApplicationError>;

    async fn save_attestation(
        &self,
        attestation: AttestationBundle,
    ) -> Result<(), ApplicationError>;
    async fn get_attestation_by_artifact(
        &self,
        artifact_id: ArtifactId,
    ) -> Result<Option<AttestationBundle>, ApplicationError>;

    async fn save_trusted_publisher(
        &self,
        publisher: TrustedPublisher,
    ) -> Result<(), ApplicationError>;
    async fn list_trusted_publishers(
        &self,
        tenant_id: TenantId,
        normalized_project_name: &str,
    ) -> Result<Vec<TrustedPublisher>, ApplicationError>;
    async fn delete_project(&self, project_id: ProjectId) -> Result<(), ApplicationError>;

    async fn save_audit_event(&self, event: AuditEvent) -> Result<(), ApplicationError>;
    async fn list_audit_events(
        &self,
        tenant_slug: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AuditEvent>, ApplicationError>;
}

pub trait WheelArchiveReader: Send + Sync {
    fn read_wheel(&self, path: &Path) -> Result<WheelArchiveSnapshot, ApplicationError>;
    fn read_wheel_bytes(
        &self,
        wheel_filename: &str,
        bytes: &[u8],
    ) -> Result<WheelArchiveSnapshot, ApplicationError>;
}

pub trait WheelVirusScanner: Send + Sync {
    fn scan_archive(
        &self,
        archive: &WheelArchiveSnapshot,
    ) -> Result<WheelVirusScanResult, ApplicationError>;
}

#[async_trait]
pub trait ObjectStorage: Send + Sync {
    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), ApplicationError>;
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, ApplicationError>;
    async fn delete(&self, key: &str) -> Result<(), ApplicationError>;
}

#[async_trait]
pub trait MirrorClient: Send + Sync {
    async fn fetch_project(
        &self,
        project_name: &str,
    ) -> Result<Option<MirroredProjectSnapshot>, ApplicationError>;
    async fn fetch_artifact_bytes(&self, download_url: &str) -> Result<Vec<u8>, ApplicationError>;
}

#[async_trait]
pub trait OidcVerifier: Send + Sync {
    async fn verify(
        &self,
        token: &str,
        audience: &str,
    ) -> Result<PublishIdentity, ApplicationError>;
}

#[async_trait]
pub trait AttestationSigner: Send + Sync {
    async fn build_attestation(
        &self,
        project_name: &pyregistry_domain::ProjectName,
        version: &pyregistry_domain::ReleaseVersion,
        artifact: &Artifact,
        identity: &PublishIdentity,
    ) -> Result<String, ApplicationError>;
}

pub trait PasswordHasher: Send + Sync {
    fn hash(&self, password: &str) -> Result<String, ApplicationError>;
    fn verify(&self, password: &str, hash: &str) -> Result<bool, ApplicationError>;
}

pub trait TokenHasher: Send + Sync {
    fn hash(&self, secret: &str) -> Result<String, ApplicationError>;
}

#[async_trait]
pub trait VulnerabilityScanner: Send + Sync {
    async fn scan_package_versions(
        &self,
        packages: &[PackageVulnerabilityQuery],
    ) -> Result<Vec<PackageVulnerabilityReport>, ApplicationError>;
}

pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

pub trait IdGenerator: Send + Sync {
    fn next(&self) -> Uuid;
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

#[cfg(test)]
mod tests {
    use super::{ArtifactSecurityDetails, PackageVulnerability};

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
}
