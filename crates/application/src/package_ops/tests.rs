use super::*;
use crate::{
    AttestationSigner, CancellationSignal, Clock, IdGenerator, MirrorClient,
    MirroredArtifactSnapshot, ObjectStorage, OidcVerifier, PackageVulnerabilityQuery,
    PackageVulnerabilityReport, PasswordHasher, RegistryOverview, RegistryStore, SearchHit,
    TokenHasher, VulnerabilityScanner, WheelArchiveReader, WheelArchiveSnapshot,
    WheelVirusScanResult, WheelVirusScanner,
};
use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use pyregistry_domain::{
    AdminUser, ApiToken, Artifact, ArtifactId, AttestationBundle, AuditEvent, MirrorRule, Project,
    ProjectId, ProjectName, ProjectSource, PublishIdentity, Release, ReleaseId, ReleaseVersion,
    Tenant, TenantId, TenantSlug, TokenId, TrustedPublisher,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use uuid::Uuid;

#[tokio::test]
async fn mirrored_project_caches_artifacts_with_bounded_parallelism() {
    let store = Arc::new(FakeRegistryStore::with_mirrored_tenant());
    let storage = Arc::new(FakeObjectStorage::default());
    let mirror = Arc::new(FakeMirrorClient::with_artifact_count(6));
    let app = test_app(store.clone(), storage.clone(), mirror.clone(), 2);

    let project = app
        .resolve_project_from_mirror("acme", "demo")
        .await
        .expect("mirror result")
        .expect("mirrored project");

    assert_eq!(project.name.normalized(), "demo");
    assert_eq!(mirror.fetch_count(), 6);
    assert_eq!(mirror.max_active_fetches(), 2);
    assert_eq!(storage.object_count(), 6);
    assert_eq!(
        store.artifact_count(),
        6,
        "all artifact records should be saved before/while payload caching runs"
    );
}

#[tokio::test]
async fn refresh_mirrored_projects_updates_existing_mirrors_only() {
    let store = Arc::new(FakeRegistryStore::with_mirrored_and_local_projects(true));
    let storage = Arc::new(FakeObjectStorage::default());
    let mirror = Arc::new(FakeMirrorClient::with_artifact_count(3));
    let app = test_app(store.clone(), storage.clone(), mirror.clone(), 2);

    let report = app
        .refresh_mirrored_projects()
        .await
        .expect("refresh mirrored projects");

    assert_eq!(report.tenant_count, 1);
    assert_eq!(report.mirrored_project_count, 1);
    assert_eq!(report.refreshed_project_count, 1);
    assert_eq!(report.failed_project_count, 0);
    assert_eq!(mirror.project_fetch_count(), 1);
    assert_eq!(
        mirror.fetch_count(),
        3,
        "only the mirrored project should fetch artifact payloads"
    );
    assert_eq!(storage.object_count(), 3);
    assert_eq!(store.artifact_count(), 3);
}

#[tokio::test]
async fn refresh_mirrored_projects_skips_disabled_tenants() {
    let store = Arc::new(FakeRegistryStore::with_mirrored_and_local_projects(false));
    let storage = Arc::new(FakeObjectStorage::default());
    let mirror = Arc::new(FakeMirrorClient::with_artifact_count(3));
    let app = test_app(store, storage, mirror.clone(), 2);

    let report = app
        .refresh_mirrored_projects()
        .await
        .expect("refresh mirrored projects");

    assert_eq!(report.tenant_count, 0);
    assert_eq!(report.mirrored_project_count, 0);
    assert_eq!(report.refreshed_project_count, 0);
    assert_eq!(mirror.project_fetch_count(), 0);
    assert_eq!(mirror.fetch_count(), 0);
}

#[tokio::test]
async fn refresh_mirrored_projects_stops_before_work_when_cancelled() {
    let store = Arc::new(FakeRegistryStore::with_mirrored_and_local_projects(true));
    let storage = Arc::new(FakeObjectStorage::default());
    let mirror = Arc::new(FakeMirrorClient::with_artifact_count(3));
    let app = test_app(store, storage, mirror.clone(), 2);

    let error = app
        .refresh_mirrored_projects_with_cancellation(&AlwaysCancelled)
        .await
        .expect_err("refresh should be cancelled");

    assert!(matches!(error, ApplicationError::Cancelled(_)));
    assert_eq!(mirror.project_fetch_count(), 0);
    assert_eq!(mirror.fetch_count(), 0);
}

fn test_app(
    store: Arc<FakeRegistryStore>,
    storage: Arc<FakeObjectStorage>,
    mirror: Arc<FakeMirrorClient>,
    mirror_download_concurrency: usize,
) -> PyregistryApp {
    PyregistryApp::new(
        store,
        storage,
        mirror,
        Arc::new(UnusedOidcVerifier),
        Arc::new(UnusedAttestationSigner),
        Arc::new(UnusedPasswordHasher),
        Arc::new(UnusedTokenHasher),
        Arc::new(UnusedVulnerabilityScanner),
        Arc::new(UnusedWheelArchiveReader),
        Arc::new(UnusedWheelVirusScanner),
        Arc::new(FixedClock),
        Arc::new(SequentialIds::default()),
        mirror_download_concurrency,
    )
}

#[derive(Default)]
struct FakeRegistryStore {
    state: Mutex<FakeRegistryState>,
}

#[derive(Default)]
struct FakeRegistryState {
    tenants: HashMap<Uuid, Tenant>,
    projects: HashMap<Uuid, Project>,
    releases: HashMap<Uuid, Release>,
    artifacts: HashMap<Uuid, Artifact>,
    attestations: HashMap<Uuid, AttestationBundle>,
}

impl FakeRegistryStore {
    fn with_mirrored_tenant() -> Self {
        Self::with_tenant(false, true)
    }

    fn with_mirrored_and_local_projects(mirroring_enabled: bool) -> Self {
        Self::with_tenant(true, mirroring_enabled)
    }

    fn with_tenant(include_projects: bool, mirroring_enabled: bool) -> Self {
        let tenant = Tenant::new(
            TenantId::default(),
            TenantSlug::new("acme").expect("tenant slug"),
            "Acme",
            MirrorRule {
                enabled: mirroring_enabled,
            },
            fixed_now(),
        )
        .expect("tenant");
        let mut state = FakeRegistryState::default();
        if include_projects {
            let mirrored_project = Project::new(
                ProjectId::new(Uuid::from_u128(100)),
                tenant.id,
                ProjectName::new("demo").expect("project name"),
                ProjectSource::Mirrored,
                "Demo package",
                "Demo package",
                fixed_now(),
            );
            let local_project = Project::new(
                ProjectId::new(Uuid::from_u128(101)),
                tenant.id,
                ProjectName::new("internal").expect("project name"),
                ProjectSource::Local,
                "Internal package",
                "Internal package",
                fixed_now(),
            );
            state
                .projects
                .insert(mirrored_project.id.into_inner(), mirrored_project);
            state
                .projects
                .insert(local_project.id.into_inner(), local_project);
        }
        state.tenants.insert(tenant.id.into_inner(), tenant);
        Self {
            state: Mutex::new(state),
        }
    }

    fn artifact_count(&self) -> usize {
        self.state.lock().expect("store state").artifacts.len()
    }
}

#[async_trait]
impl RegistryStore for FakeRegistryStore {
    async fn registry_overview(&self) -> Result<RegistryOverview, ApplicationError> {
        Ok(RegistryOverview {
            tenant_count: 0,
            project_count: 0,
            release_count: 0,
            artifact_count: 0,
            total_storage_bytes: 0,
            mirrored_project_count: 0,
        })
    }

    async fn save_tenant(&self, tenant: Tenant) -> Result<(), ApplicationError> {
        self.state
            .lock()
            .expect("store state")
            .tenants
            .insert(tenant.id.into_inner(), tenant);
        Ok(())
    }

    async fn list_tenants(&self) -> Result<Vec<Tenant>, ApplicationError> {
        Ok(self
            .state
            .lock()
            .expect("store state")
            .tenants
            .values()
            .cloned()
            .collect())
    }

    async fn get_tenant_by_slug(&self, slug: &str) -> Result<Option<Tenant>, ApplicationError> {
        Ok(self
            .state
            .lock()
            .expect("store state")
            .tenants
            .values()
            .find(|tenant| tenant.slug.as_str() == slug)
            .cloned())
    }

    async fn save_admin_user(&self, _user: AdminUser) -> Result<(), ApplicationError> {
        Ok(())
    }

    async fn get_admin_user_by_email(
        &self,
        _email: &str,
    ) -> Result<Option<AdminUser>, ApplicationError> {
        Ok(None)
    }

    async fn save_api_token(&self, _token: ApiToken) -> Result<(), ApplicationError> {
        Ok(())
    }

    async fn list_api_tokens(
        &self,
        _tenant_id: TenantId,
    ) -> Result<Vec<ApiToken>, ApplicationError> {
        Ok(Vec::new())
    }

    async fn revoke_api_token(
        &self,
        _tenant_id: TenantId,
        _token_id: TokenId,
    ) -> Result<(), ApplicationError> {
        Ok(())
    }

    async fn save_project(&self, project: Project) -> Result<(), ApplicationError> {
        self.state
            .lock()
            .expect("store state")
            .projects
            .insert(project.id.into_inner(), project);
        Ok(())
    }

    async fn list_projects(&self, tenant_id: TenantId) -> Result<Vec<Project>, ApplicationError> {
        Ok(self
            .state
            .lock()
            .expect("store state")
            .projects
            .values()
            .filter(|project| project.tenant_id == tenant_id)
            .cloned()
            .collect())
    }

    async fn search_projects(
        &self,
        _tenant_id: TenantId,
        _query: &str,
    ) -> Result<Vec<SearchHit>, ApplicationError> {
        Ok(Vec::new())
    }

    async fn get_project_by_normalized_name(
        &self,
        tenant_id: TenantId,
        normalized_name: &str,
    ) -> Result<Option<Project>, ApplicationError> {
        Ok(self
            .state
            .lock()
            .expect("store state")
            .projects
            .values()
            .find(|project| {
                project.tenant_id == tenant_id && project.name.normalized() == normalized_name
            })
            .cloned())
    }

    async fn save_release(&self, release: Release) -> Result<(), ApplicationError> {
        self.state
            .lock()
            .expect("store state")
            .releases
            .insert(release.id.into_inner(), release);
        Ok(())
    }

    async fn list_releases(&self, project_id: ProjectId) -> Result<Vec<Release>, ApplicationError> {
        Ok(self
            .state
            .lock()
            .expect("store state")
            .releases
            .values()
            .filter(|release| release.project_id == project_id)
            .cloned()
            .collect())
    }

    async fn get_release_by_version(
        &self,
        project_id: ProjectId,
        version: &ReleaseVersion,
    ) -> Result<Option<Release>, ApplicationError> {
        Ok(self
            .state
            .lock()
            .expect("store state")
            .releases
            .values()
            .find(|release| release.project_id == project_id && release.version == *version)
            .cloned())
    }

    async fn delete_release(&self, release_id: ReleaseId) -> Result<(), ApplicationError> {
        self.state
            .lock()
            .expect("store state")
            .releases
            .remove(&release_id.into_inner());
        Ok(())
    }

    async fn save_artifact(&self, artifact: Artifact) -> Result<(), ApplicationError> {
        self.state
            .lock()
            .expect("store state")
            .artifacts
            .insert(artifact.id.into_inner(), artifact);
        Ok(())
    }

    async fn list_artifacts(
        &self,
        release_id: ReleaseId,
    ) -> Result<Vec<Artifact>, ApplicationError> {
        Ok(self
            .state
            .lock()
            .expect("store state")
            .artifacts
            .values()
            .filter(|artifact| artifact.release_id == release_id)
            .cloned()
            .collect())
    }

    async fn get_artifact_by_filename(
        &self,
        release_id: ReleaseId,
        filename: &str,
    ) -> Result<Option<Artifact>, ApplicationError> {
        Ok(self
            .state
            .lock()
            .expect("store state")
            .artifacts
            .values()
            .find(|artifact| artifact.release_id == release_id && artifact.filename == filename)
            .cloned())
    }

    async fn delete_artifact(&self, artifact_id: ArtifactId) -> Result<(), ApplicationError> {
        self.state
            .lock()
            .expect("store state")
            .artifacts
            .remove(&artifact_id.into_inner());
        Ok(())
    }

    async fn save_attestation(
        &self,
        attestation: AttestationBundle,
    ) -> Result<(), ApplicationError> {
        self.state
            .lock()
            .expect("store state")
            .attestations
            .insert(attestation.artifact_id.into_inner(), attestation);
        Ok(())
    }

    async fn get_attestation_by_artifact(
        &self,
        artifact_id: ArtifactId,
    ) -> Result<Option<AttestationBundle>, ApplicationError> {
        Ok(self
            .state
            .lock()
            .expect("store state")
            .attestations
            .get(&artifact_id.into_inner())
            .cloned())
    }

    async fn save_trusted_publisher(
        &self,
        _publisher: TrustedPublisher,
    ) -> Result<(), ApplicationError> {
        Ok(())
    }

    async fn list_trusted_publishers(
        &self,
        _tenant_id: TenantId,
        _normalized_project_name: &str,
    ) -> Result<Vec<TrustedPublisher>, ApplicationError> {
        Ok(Vec::new())
    }

    async fn delete_project(&self, project_id: ProjectId) -> Result<(), ApplicationError> {
        self.state
            .lock()
            .expect("store state")
            .projects
            .remove(&project_id.into_inner());
        Ok(())
    }

    async fn save_audit_event(&self, _event: AuditEvent) -> Result<(), ApplicationError> {
        Ok(())
    }

    async fn list_audit_events(
        &self,
        _tenant_slug: Option<&str>,
        _limit: usize,
    ) -> Result<Vec<AuditEvent>, ApplicationError> {
        Ok(Vec::new())
    }
}

#[derive(Default)]
struct FakeObjectStorage {
    objects: Mutex<HashMap<String, Vec<u8>>>,
}

impl FakeObjectStorage {
    fn object_count(&self) -> usize {
        self.objects.lock().expect("object storage").len()
    }
}

#[async_trait]
impl ObjectStorage for FakeObjectStorage {
    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), ApplicationError> {
        self.objects
            .lock()
            .expect("object storage")
            .insert(key.to_string(), bytes);
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, ApplicationError> {
        Ok(self
            .objects
            .lock()
            .expect("object storage")
            .get(key)
            .cloned())
    }

    async fn delete(&self, key: &str) -> Result<(), ApplicationError> {
        self.objects.lock().expect("object storage").remove(key);
        Ok(())
    }
}

struct FakeMirrorClient {
    snapshot: MirroredProjectSnapshot,
    bytes_by_url: HashMap<String, Vec<u8>>,
    counters: Mutex<MirrorCounters>,
}

#[derive(Default)]
struct MirrorCounters {
    project_fetch_count: usize,
    active_fetches: usize,
    max_active_fetches: usize,
    fetch_count: usize,
}

impl FakeMirrorClient {
    fn with_artifact_count(count: usize) -> Self {
        let mut artifacts = Vec::new();
        let mut bytes_by_url = HashMap::new();
        for index in 0..count {
            let filename = format!("demo-1.0.{index}-py3-none-any.whl");
            let download_url = format!("https://files.example.test/{filename}");
            let bytes = format!("artifact-{index}").into_bytes();
            let sha256 = hex::encode(Sha256::digest(&bytes));
            artifacts.push(MirroredArtifactSnapshot {
                filename,
                version: format!("1.0.{index}"),
                size_bytes: bytes.len() as u64,
                sha256,
                blake2b_256: None,
                download_url: download_url.clone(),
                provenance_payload: None,
            });
            bytes_by_url.insert(download_url, bytes);
        }

        Self {
            snapshot: MirroredProjectSnapshot {
                canonical_name: "demo".into(),
                summary: "Demo package".into(),
                description: "Demo package".into(),
                artifacts,
            },
            bytes_by_url,
            counters: Mutex::new(MirrorCounters::default()),
        }
    }

    fn fetch_count(&self) -> usize {
        self.counters.lock().expect("mirror counters").fetch_count
    }

    fn project_fetch_count(&self) -> usize {
        self.counters
            .lock()
            .expect("mirror counters")
            .project_fetch_count
    }

    fn max_active_fetches(&self) -> usize {
        self.counters
            .lock()
            .expect("mirror counters")
            .max_active_fetches
    }
}

#[async_trait]
impl MirrorClient for FakeMirrorClient {
    async fn fetch_project(
        &self,
        _project_name: &str,
    ) -> Result<Option<MirroredProjectSnapshot>, ApplicationError> {
        self.counters
            .lock()
            .expect("mirror counters")
            .project_fetch_count += 1;
        Ok(Some(self.snapshot.clone()))
    }

    async fn fetch_artifact_bytes(&self, download_url: &str) -> Result<Vec<u8>, ApplicationError> {
        {
            let mut counters = self.counters.lock().expect("mirror counters");
            counters.active_fetches += 1;
            counters.fetch_count += 1;
            counters.max_active_fetches = counters.max_active_fetches.max(counters.active_fetches);
        }

        tokio::time::sleep(Duration::from_millis(25)).await;

        let bytes = self
            .bytes_by_url
            .get(download_url)
            .cloned()
            .ok_or_else(|| ApplicationError::NotFound(download_url.to_string()));

        let mut counters = self.counters.lock().expect("mirror counters");
        counters.active_fetches -= 1;
        bytes
    }
}

struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> chrono::DateTime<Utc> {
        fixed_now()
    }
}

fn fixed_now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 4, 11, 12, 0, 0)
        .single()
        .expect("fixed timestamp")
}

#[derive(Default)]
struct SequentialIds {
    next: Mutex<u128>,
}

impl IdGenerator for SequentialIds {
    fn next(&self) -> Uuid {
        let mut next = self.next.lock().expect("id generator");
        *next += 1;
        Uuid::from_u128(*next)
    }
}

struct UnusedOidcVerifier;

#[async_trait]
impl OidcVerifier for UnusedOidcVerifier {
    async fn verify(
        &self,
        _token: &str,
        _audience: &str,
    ) -> Result<PublishIdentity, ApplicationError> {
        Err(ApplicationError::External("unused OIDC verifier".into()))
    }
}

struct UnusedAttestationSigner;

#[async_trait]
impl AttestationSigner for UnusedAttestationSigner {
    async fn build_attestation(
        &self,
        _project_name: &ProjectName,
        _version: &ReleaseVersion,
        _artifact: &Artifact,
        _identity: &PublishIdentity,
    ) -> Result<String, ApplicationError> {
        Ok("{}".into())
    }
}

struct UnusedPasswordHasher;

impl PasswordHasher for UnusedPasswordHasher {
    fn hash(&self, _password: &str) -> Result<String, ApplicationError> {
        Ok("hash".into())
    }

    fn verify(&self, _password: &str, _hash: &str) -> Result<bool, ApplicationError> {
        Ok(false)
    }
}

struct UnusedTokenHasher;

impl TokenHasher for UnusedTokenHasher {
    fn hash(&self, secret: &str) -> Result<String, ApplicationError> {
        Ok(secret.to_string())
    }
}

struct UnusedVulnerabilityScanner;

#[async_trait]
impl VulnerabilityScanner for UnusedVulnerabilityScanner {
    async fn scan_package_versions(
        &self,
        packages: &[PackageVulnerabilityQuery],
    ) -> Result<Vec<PackageVulnerabilityReport>, ApplicationError> {
        Ok(packages
            .iter()
            .map(PackageVulnerabilityReport::clean)
            .collect())
    }
}

struct AlwaysCancelled;

#[async_trait]
impl CancellationSignal for AlwaysCancelled {
    fn is_cancelled(&self) -> bool {
        true
    }

    async fn cancelled(&self) {}
}

struct UnusedWheelArchiveReader;

impl WheelArchiveReader for UnusedWheelArchiveReader {
    fn read_wheel(&self, _path: &Path) -> Result<WheelArchiveSnapshot, ApplicationError> {
        Err(ApplicationError::External("unused wheel reader".into()))
    }

    fn read_wheel_bytes(
        &self,
        _wheel_filename: &str,
        _bytes: &[u8],
    ) -> Result<WheelArchiveSnapshot, ApplicationError> {
        Err(ApplicationError::External("unused wheel reader".into()))
    }
}

struct UnusedWheelVirusScanner;

impl WheelVirusScanner for UnusedWheelVirusScanner {
    fn scan_archive(
        &self,
        _archive: &WheelArchiveSnapshot,
    ) -> Result<WheelVirusScanResult, ApplicationError> {
        Ok(WheelVirusScanResult {
            scanned_file_count: 0,
            signature_rule_count: 0,
            skipped_rule_count: 0,
            findings: Vec::new(),
        })
    }
}
