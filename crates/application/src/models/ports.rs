use super::{
    DependencyVulnerabilityQuery, DependencyVulnerabilityReport, DistributionInspection,
    MirroredProjectSnapshot, PackagePublishNotification, PackageVulnerabilityQuery,
    PackageVulnerabilityReport, RecentActivity, RegistryOverview, ReleaseArtifacts, SearchHit,
    TenantDashboardStats, VulnerablePackageNotification, WheelArchiveSnapshot,
    WheelAuditFindingNotification, WheelSourceSecurityScanResult, WheelVirusScanResult,
};
use crate::ApplicationError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pyregistry_domain::{
    AdminUser, ApiToken, Artifact, ArtifactId, AttestationBundle, AuditEvent, Project, ProjectId,
    PublishIdentity, Release, ReleaseId, ReleaseVersion, Tenant, TenantId, TokenId,
    TrustedPublisher,
};
use std::future;
use std::path::Path;
use uuid::Uuid;

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

    async fn list_release_artifacts(
        &self,
        project_id: ProjectId,
    ) -> Result<Vec<ReleaseArtifacts>, ApplicationError> {
        let releases = self.list_releases(project_id).await?;
        let mut grouped = Vec::with_capacity(releases.len());
        for release in releases {
            grouped.push(ReleaseArtifacts {
                artifacts: self.list_artifacts(release.id).await?,
                release,
            });
        }
        Ok(grouped)
    }

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

    async fn tenant_dashboard_stats(
        &self,
        tenant: &Tenant,
    ) -> Result<TenantDashboardStats, ApplicationError> {
        let projects = self.list_projects(tenant.id).await?;
        let mut release_count = 0usize;
        let mut artifact_count = 0usize;
        let mut recent_activity = Vec::new();

        for project in &projects {
            let releases = self.list_releases(project.id).await?;
            release_count += releases.len();
            for release in releases {
                artifact_count += self.list_artifacts(release.id).await?.len();
            }
            recent_activity.push(RecentActivity {
                project_name: project.name.original().to_string(),
                tenant_slug: tenant.slug.as_str().to_string(),
                source: format!("{:?}", project.source).to_ascii_lowercase(),
                updated_at: project.updated_at,
            });
        }
        recent_activity.sort_by(|left, right| right.updated_at.cmp(&left.updated_at));

        Ok(TenantDashboardStats {
            project_count: projects.len(),
            release_count,
            artifact_count,
            token_count: self.list_api_tokens(tenant.id).await?.len(),
            trusted_publisher_count: self.list_trusted_publishers(tenant.id, "").await?.len(),
            recent_activity: recent_activity.into_iter().take(6).collect(),
        })
    }

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

pub trait WheelSourceSecurityScanner: Send + Sync {
    fn scan_archive(
        &self,
        archive: &WheelArchiveSnapshot,
    ) -> Result<WheelSourceSecurityScanResult, ApplicationError>;
}

pub trait DistributionFileInspector: Send + Sync {
    fn inspect_distribution(&self, path: &Path)
    -> Result<DistributionInspection, ApplicationError>;

    fn inspect_distribution_bytes(
        &self,
        filename: &str,
        bytes: &[u8],
    ) -> Result<DistributionInspection, ApplicationError>;
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

    async fn scan_dependency_versions(
        &self,
        dependencies: &[DependencyVulnerabilityQuery],
    ) -> Result<Vec<DependencyVulnerabilityReport>, ApplicationError>;
}

#[async_trait]
pub trait VulnerabilityNotifier: Send + Sync {
    async fn notify_vulnerable_package(
        &self,
        notification: &VulnerablePackageNotification,
    ) -> Result<(), ApplicationError>;
}

pub struct NoopVulnerabilityNotifier;

#[async_trait]
impl VulnerabilityNotifier for NoopVulnerabilityNotifier {
    async fn notify_vulnerable_package(
        &self,
        _notification: &VulnerablePackageNotification,
    ) -> Result<(), ApplicationError> {
        Ok(())
    }
}

#[async_trait]
pub trait PackagePublishNotifier: Send + Sync {
    async fn notify_package_publish(
        &self,
        notification: &PackagePublishNotification,
    ) -> Result<(), ApplicationError>;
}

pub struct NoopPackagePublishNotifier;

#[async_trait]
impl PackagePublishNotifier for NoopPackagePublishNotifier {
    async fn notify_package_publish(
        &self,
        _notification: &PackagePublishNotification,
    ) -> Result<(), ApplicationError> {
        Ok(())
    }
}

#[async_trait]
pub trait WheelAuditNotifier: Send + Sync {
    async fn notify_wheel_audit_findings(
        &self,
        notification: &WheelAuditFindingNotification,
    ) -> Result<(), ApplicationError>;
}

pub struct NoopWheelAuditNotifier;

#[async_trait]
impl WheelAuditNotifier for NoopWheelAuditNotifier {
    async fn notify_wheel_audit_findings(
        &self,
        _notification: &WheelAuditFindingNotification,
    ) -> Result<(), ApplicationError> {
        Ok(())
    }
}

pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

pub trait IdGenerator: Send + Sync {
    fn next(&self) -> Uuid;
}

#[async_trait]
pub trait CancellationSignal: Send + Sync {
    fn is_cancelled(&self) -> bool;
    async fn cancelled(&self);
}

pub struct NeverCancelled;

#[async_trait]
impl CancellationSignal for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }

    async fn cancelled(&self) {
        future::pending::<()>().await;
    }
}
