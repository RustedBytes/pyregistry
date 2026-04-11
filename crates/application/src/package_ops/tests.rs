use super::*;
use crate::{
    AttestationSigner, CancellationSignal, Clock, CreateTenantCommand, DeletionCommand,
    DistributionFileInspector, DistributionInspection, DistributionKind, IdGenerator,
    IssueApiTokenCommand, MintOidcPublishTokenCommand, MirrorClient, MirroredArtifactSnapshot,
    ObjectStorage, OidcVerifier, PackageVulnerabilityQuery, PackageVulnerabilityReport,
    PasswordHasher, RecordAuditEventCommand, RegisterTrustedPublisherCommand,
    RegistryDistributionValidationStatus, RegistryOverview, RegistryStore, SearchHit, TokenHasher,
    UploadArtifactCommand, ValidateRegistryDistributionsCommand, VulnerabilityScanner,
    WheelArchiveReader, WheelArchiveSnapshot, WheelSourceSecurityScanResult,
    WheelSourceSecurityScanner, WheelVirusScanResult, WheelVirusScanner,
};
use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use pyregistry_domain::{
    AdminUser, ApiToken, Artifact, ArtifactId, AttestationBundle, AuditEvent, DeletionMode,
    DigestSet, MirrorRule, Project, ProjectId, ProjectName, ProjectSource, PublishIdentity,
    Release, ReleaseId, ReleaseVersion, Tenant, TenantId, TenantSlug, TokenId, TokenScope,
    TrustedPublisher, TrustedPublisherProvider,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
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

#[tokio::test]
async fn validate_registry_distributions_reports_checksum_and_missing_blob_failures() {
    let store = Arc::new(FakeRegistryStore::with_mirrored_and_local_projects(true));
    let storage = Arc::new(FakeObjectStorage::default());
    let mirror = Arc::new(FakeMirrorClient::with_artifact_count(0));
    let app = test_app(store.clone(), storage.clone(), mirror, 2);
    let release = Release {
        id: ReleaseId::new(Uuid::from_u128(200)),
        project_id: ProjectId::new(Uuid::from_u128(101)),
        version: ReleaseVersion::new("1.0.0").expect("version"),
        yanked: None,
        created_at: fixed_now(),
    };
    store.save_release(release).await.expect("save release");

    let valid_bytes = b"valid wheel bytes".to_vec();
    let zip_bytes = b"valid source zip bytes".to_vec();
    let mismatch_bytes = b"changed wheel bytes".to_vec();
    let valid_sha256 = hex::encode(Sha256::digest(&valid_bytes));
    let zip_sha256 = hex::encode(Sha256::digest(&zip_bytes));
    store
        .save_artifact(
            Artifact::new(
                ArtifactId::new(Uuid::from_u128(300)),
                ReleaseId::new(Uuid::from_u128(200)),
                "internal-1.0.0-py3-none-any.whl",
                valid_bytes.len() as u64,
                DigestSet::new(valid_sha256, None).expect("digest"),
                "objects/valid.whl",
                fixed_now(),
            )
            .expect("valid artifact"),
        )
        .await
        .expect("save valid artifact");
    store
        .save_artifact(
            Artifact::new(
                ArtifactId::new(Uuid::from_u128(301)),
                ReleaseId::new(Uuid::from_u128(200)),
                "internal-1.0.0.zip",
                zip_bytes.len() as u64,
                DigestSet::new(zip_sha256, None).expect("digest"),
                "objects/source.zip",
                fixed_now(),
            )
            .expect("zip artifact"),
        )
        .await
        .expect("save zip artifact");
    store
        .save_artifact(
            Artifact::new(
                ArtifactId::new(Uuid::from_u128(302)),
                ReleaseId::new(Uuid::from_u128(200)),
                "internal-1.0.0-cp314-cp314-linux_x86_64.whl",
                mismatch_bytes.len() as u64,
                DigestSet::new("a".repeat(64), None).expect("digest"),
                "objects/mismatch.whl",
                fixed_now(),
            )
            .expect("mismatch artifact"),
        )
        .await
        .expect("save mismatch artifact");
    store
        .save_artifact(
            Artifact::new(
                ArtifactId::new(Uuid::from_u128(303)),
                ReleaseId::new(Uuid::from_u128(200)),
                "internal-1.0.0.tar.gz",
                42,
                DigestSet::new("b".repeat(64), None).expect("digest"),
                "objects/missing.tar.gz",
                fixed_now(),
            )
            .expect("missing artifact"),
        )
        .await
        .expect("save missing artifact");
    storage
        .put("objects/valid.whl", valid_bytes)
        .await
        .expect("put valid bytes");
    storage
        .put("objects/mismatch.whl", mismatch_bytes)
        .await
        .expect("put mismatch bytes");
    storage
        .put("objects/source.zip", zip_bytes)
        .await
        .expect("put source zip bytes");

    let report = app
        .validate_registry_distributions(
            Arc::new(FakeDistributionInspector),
            ValidateRegistryDistributionsCommand {
                tenant_slug: Some("acme".into()),
                project_name: Some("internal".into()),
                parallelism: 2,
            },
        )
        .await
        .expect("registry distribution validation");

    assert!(!report.is_valid());
    assert_eq!(report.tenant_count, 1);
    assert_eq!(report.project_count, 1);
    assert_eq!(report.release_count, 1);
    assert_eq!(report.artifact_count, 4);
    assert_eq!(report.valid_count, 2);
    assert_eq!(report.invalid_count, 2);
    assert_eq!(report.checksum_mismatch_count, 1);
    assert_eq!(report.missing_blob_count, 1);
    assert!(report.items.iter().any(|item| {
        item.filename == "internal-1.0.0-cp314-cp314-linux_x86_64.whl"
            && item.status == RegistryDistributionValidationStatus::ChecksumMismatch
            && item.actual_sha256 == Some(hex::encode(Sha256::digest(b"changed wheel bytes")))
    }));
    assert!(report.items.iter().any(|item| {
        item.filename == "internal-1.0.0.tar.gz"
            && item.status == RegistryDistributionValidationStatus::MissingBlob
    }));
    assert!(report.items.iter().any(|item| {
        item.filename == "internal-1.0.0.zip"
            && item.status == RegistryDistributionValidationStatus::Valid
            && item.kind == Some(DistributionKind::SourceZip)
    }));
}

#[tokio::test]
async fn validate_registry_distributions_inspects_files_in_parallel() {
    let store = Arc::new(FakeRegistryStore::with_mirrored_and_local_projects(true));
    let storage = Arc::new(FakeObjectStorage::default());
    let mirror = Arc::new(FakeMirrorClient::with_artifact_count(0));
    let app = test_app(store.clone(), storage.clone(), mirror, 2);
    let release = Release {
        id: ReleaseId::new(Uuid::from_u128(210)),
        project_id: ProjectId::new(Uuid::from_u128(101)),
        version: ReleaseVersion::new("2.0.0").expect("version"),
        yanked: None,
        created_at: fixed_now(),
    };
    store.save_release(release).await.expect("save release");

    for index in 0..4 {
        let bytes = format!("valid wheel bytes {index}").into_bytes();
        let sha256 = hex::encode(Sha256::digest(&bytes));
        let filename = format!("internal-2.0.0-{index}.whl");
        let object_key = format!("objects/parallel-{index}.whl");
        store
            .save_artifact(
                Artifact::new(
                    ArtifactId::new(Uuid::from_u128(400 + index)),
                    ReleaseId::new(Uuid::from_u128(210)),
                    filename,
                    bytes.len() as u64,
                    DigestSet::new(sha256, None).expect("digest"),
                    object_key.clone(),
                    fixed_now(),
                )
                .expect("parallel artifact"),
            )
            .await
            .expect("save parallel artifact");
        storage
            .put(&object_key, bytes)
            .await
            .expect("put parallel bytes");
    }

    let inspector = Arc::new(ConcurrentDistributionInspector::default());
    let inspector_port: Arc<dyn DistributionFileInspector> = inspector.clone();
    let report = app
        .validate_registry_distributions(
            inspector_port,
            ValidateRegistryDistributionsCommand {
                tenant_slug: Some("acme".into()),
                project_name: Some("internal".into()),
                parallelism: 2,
            },
        )
        .await
        .expect("registry distribution validation");

    assert!(report.is_valid());
    assert_eq!(report.artifact_count, 4);
    assert_eq!(report.valid_count, 4);
    assert!(
        inspector.max_active() > 1,
        "validation should run more than one CPU inspection at once"
    );
    assert!(
        inspector.max_active() <= 2,
        "validation should respect the configured worker bound"
    );
}

#[tokio::test]
async fn admin_publish_governance_and_audit_use_cases_share_a_consistent_registry_state() {
    let store = Arc::new(FakeRegistryStore::default());
    let storage = Arc::new(FakeObjectStorage::default());
    let mirror = Arc::new(FakeMirrorClient::with_artifact_count(0));
    let app = test_app(store.clone(), storage.clone(), mirror, 2);

    app.bootstrap_superadmin(" ROOT@Example.COM ", "root-secret")
        .await
        .expect("bootstrap superadmin");
    app.bootstrap_superadmin("root@example.com", "ignored")
        .await
        .expect("bootstrap is idempotent");
    let root_session = app
        .login_admin("root@example.com", "root-secret")
        .await
        .expect("root login");
    assert!(root_session.is_superadmin);

    let tenant = app
        .create_tenant(CreateTenantCommand {
            slug: "Acme".into(),
            display_name: "Acme Corp".into(),
            mirroring_enabled: true,
            admin_email: "Admin@Acme.test".into(),
            admin_password: "tenant-secret".into(),
        })
        .await
        .expect("tenant creation");
    assert_eq!(tenant.slug.as_str(), "acme");
    assert!(matches!(
        app.create_tenant(CreateTenantCommand {
            slug: "acme".into(),
            display_name: "Acme Again".into(),
            mirroring_enabled: false,
            admin_email: "other@acme.test".into(),
            admin_password: "tenant-secret".into(),
        })
        .await,
        Err(ApplicationError::Conflict(_))
    ));

    let tenant_session = app
        .login_admin("admin@acme.test", "tenant-secret")
        .await
        .expect("tenant admin login");
    assert_eq!(tenant_session.tenant_slug.as_deref(), Some("acme"));
    assert!(matches!(
        app.login_admin("admin@acme.test", "wrong").await,
        Err(ApplicationError::Unauthorized(_))
    ));

    let read_token = app
        .issue_api_token(IssueApiTokenCommand {
            tenant_slug: "acme".into(),
            label: "read-only".into(),
            scopes: vec![TokenScope::Read],
            ttl_hours: Some(1),
        })
        .await
        .expect("read token");
    assert_eq!(read_token.label, "read-only");
    assert!(read_token.secret.starts_with("pyr_"));
    app.authenticate_tenant_token("acme", &read_token.secret, TokenScope::Read)
        .await
        .expect("read token authenticates");
    assert!(matches!(
        app.authenticate_tenant_token("acme", &read_token.secret, TokenScope::Publish)
            .await,
        Err(ApplicationError::Unauthorized(_))
    ));
    app.revoke_api_token("acme", "read-only")
        .await
        .expect("token revocation");
    assert!(matches!(
        app.authenticate_tenant_token("acme", &read_token.secret, TokenScope::Read)
            .await,
        Err(ApplicationError::Unauthorized(_))
    ));

    let publish_token = app
        .issue_api_token(IssueApiTokenCommand {
            tenant_slug: "acme".into(),
            label: "publisher".into(),
            scopes: vec![TokenScope::Publish, TokenScope::Admin],
            ttl_hours: None,
        })
        .await
        .expect("publish token");
    let publish_access = app
        .authenticate_tenant_token("acme", &publish_token.secret, TokenScope::Publish)
        .await
        .expect("publish token authenticates");

    app.upload_artifact(
        &publish_access,
        UploadArtifactCommand {
            tenant_slug: "acme".into(),
            project_name: "Demo_Pkg".into(),
            version: "1.0.0".into(),
            filename: "demo-pkg-1.0.0-py3-none-any.whl".into(),
            summary: "Demo package".into(),
            description: "A package used by the coverage flow".into(),
            content: b"first wheel".to_vec(),
        },
    )
    .await
    .expect("upload artifact");
    assert!(matches!(
        app.upload_artifact(
            &publish_access,
            UploadArtifactCommand {
                tenant_slug: "other".into(),
                project_name: "Demo_Pkg".into(),
                version: "1.0.0".into(),
                filename: "demo-pkg-1.0.0-py3-none-any.whl".into(),
                summary: "Demo package".into(),
                description: "Tenant mismatch".into(),
                content: b"tenant mismatch".to_vec(),
            },
        )
        .await,
        Err(ApplicationError::Unauthorized(_))
    ));
    assert!(matches!(
        app.upload_artifact(
            &publish_access,
            UploadArtifactCommand {
                tenant_slug: "acme".into(),
                project_name: "Demo_Pkg".into(),
                version: "1.0.0".into(),
                filename: "demo-pkg-1.0.0-py3-none-any.whl".into(),
                summary: "Demo package".into(),
                description: "Duplicate".into(),
                content: b"duplicate".to_vec(),
            },
        )
        .await,
        Err(ApplicationError::Conflict(_))
    ));

    let mut claim_rules = BTreeMap::new();
    claim_rules.insert("repository".into(), "acme/demo-pkg".into());
    let publisher = app
        .register_trusted_publisher(RegisterTrustedPublisherCommand {
            tenant_slug: "acme".into(),
            project_name: "Demo_Pkg".into(),
            provider: TrustedPublisherProvider::GitHubActions,
            issuer: "https://token.actions.githubusercontent.com".into(),
            audience: "pyregistry".into(),
            claim_rules,
        })
        .await
        .expect("trusted publisher");
    assert_eq!(publisher.project_name, "Demo_Pkg");

    let oidc_grant = app
        .mint_oidc_publish_token(MintOidcPublishTokenCommand {
            tenant_slug: "acme".into(),
            project_name: "Demo_Pkg".into(),
            oidc_token: "fixture.jwt".into(),
        })
        .await
        .expect("OIDC publish token");
    assert!(oidc_grant.token.starts_with("oidc_"));
    let trusted_access = app
        .authenticate_tenant_token("acme", &oidc_grant.token, TokenScope::Publish)
        .await
        .expect("OIDC token authenticates");
    app.upload_artifact(
        &trusted_access,
        UploadArtifactCommand {
            tenant_slug: "acme".into(),
            project_name: "Demo_Pkg".into(),
            version: "1.1.0".into(),
            filename: "demo-pkg-1.1.0-py3-none-any.whl".into(),
            summary: "Demo package".into(),
            description: "Trusted publish".into(),
            content: b"trusted wheel".to_vec(),
        },
    )
    .await
    .expect("trusted upload");

    let overview = app.get_registry_overview().await.expect("overview");
    assert_eq!(overview.tenant_count, 1);
    assert_eq!(overview.project_count, 1);
    assert_eq!(overview.release_count, 2);
    assert_eq!(overview.artifact_count, 2);
    assert_eq!(overview.total_storage_bytes, 24);

    let dashboard = app
        .get_tenant_dashboard("acme")
        .await
        .expect("tenant dashboard");
    assert_eq!(dashboard.project_count, 1);
    assert_eq!(dashboard.release_count, 2);
    assert_eq!(dashboard.artifact_count, 2);
    assert_eq!(dashboard.token_count, 2);
    assert_eq!(dashboard.trusted_publisher_count, 1);

    let hits = app
        .search_packages("acme", "demo")
        .await
        .expect("package search");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].normalized_name, "demo-pkg");
    assert_eq!(hits[0].latest_version.as_deref(), Some("1.1.0"));

    let details = app
        .get_package_details("acme", "demo-pkg")
        .await
        .expect("package details");
    assert_eq!(details.releases[0].version, "1.1.0");
    assert_eq!(details.trusted_publishers.len(), 1);
    assert_eq!(details.security.scanned_file_count, 2);

    let simple_projects = app
        .list_simple_projects("acme")
        .await
        .expect("simple project listing");
    assert_eq!(simple_projects[0].normalized_name, "demo-pkg");
    let simple_page = app
        .get_simple_project_index("acme", "demo-pkg")
        .await
        .expect("simple project page");
    assert_eq!(simple_page.artifacts.len(), 2);
    assert_eq!(simple_page.artifacts[0].version, "1.1.0");
    assert!(simple_page.artifacts[0].provenance_url.is_some());
    let downloaded = app
        .download_artifact(
            "acme",
            "demo-pkg",
            "1.0.0",
            "demo-pkg-1.0.0-py3-none-any.whl",
        )
        .await
        .expect("download local artifact");
    assert_eq!(downloaded, b"first wheel");
    let provenance = app
        .get_provenance(
            "acme",
            "demo-pkg",
            "1.1.0",
            "demo-pkg-1.1.0-py3-none-any.whl",
        )
        .await
        .expect("trusted publish provenance");
    assert_eq!(provenance.source, "trustedpublish");
    assert!(matches!(
        app.get_provenance(
            "acme",
            "demo-pkg",
            "1.0.0",
            "demo-pkg-1.0.0-py3-none-any.whl",
        )
        .await,
        Err(ApplicationError::NotFound(_))
    ));

    let security = app
        .check_registry_security(Some("acme"), Some("demo-pkg"))
        .await
        .expect("registry security report");
    assert_eq!(security.package_count, 1);
    assert_eq!(security.file_count, 2);
    assert_eq!(security.vulnerability_count, 0);

    app.yank_artifact(DeletionCommand {
        tenant_slug: "acme".into(),
        project_name: "demo-pkg".into(),
        version: Some("1.0.0".into()),
        filename: Some("demo-pkg-1.0.0-py3-none-any.whl".into()),
        reason: Some("bad wheel".into()),
        mode: DeletionMode::Yank,
    })
    .await
    .expect("yank artifact");
    let details = app
        .get_package_details("acme", "demo-pkg")
        .await
        .expect("details after artifact yank");
    assert_eq!(
        details.releases[1].artifacts[0].yanked_reason.as_deref(),
        Some("bad wheel")
    );
    app.unyank_artifact(
        "acme",
        "demo-pkg",
        "1.0.0",
        "demo-pkg-1.0.0-py3-none-any.whl",
    )
    .await
    .expect("unyank artifact");

    app.yank_release(DeletionCommand {
        tenant_slug: "acme".into(),
        project_name: "demo-pkg".into(),
        version: Some("1.0.0".into()),
        filename: None,
        reason: Some("release hold".into()),
        mode: DeletionMode::Yank,
    })
    .await
    .expect("yank release");
    let details = app
        .get_package_details("acme", "demo-pkg")
        .await
        .expect("details after release yank");
    assert_eq!(
        details.releases[1].yanked_reason.as_deref(),
        Some("release hold")
    );
    app.unyank_release("acme", "demo-pkg", "1.0.0")
        .await
        .expect("unyank release");

    app.record_audit_event(RecordAuditEventCommand {
        actor: " admin@acme.test ".into(),
        action: " package.scan ".into(),
        tenant_slug: Some(" acme ".into()),
        target: Some(" demo-pkg ".into()),
        metadata: BTreeMap::from([
            (" findings ".into(), " 0 ".into()),
            ("empty".into(), "   ".into()),
        ]),
    })
    .await
    .expect("record audit event");
    let audit_trail = app
        .list_audit_trail(Some("acme"), 0)
        .await
        .expect("audit trail");
    assert_eq!(audit_trail.len(), 1);
    assert_eq!(audit_trail[0].actor, "admin@acme.test");
    assert_eq!(
        audit_trail[0].metadata.get("findings"),
        Some(&"0".to_string())
    );
    assert!(!audit_trail[0].metadata.contains_key("empty"));

    app.purge_artifact(
        "acme",
        "demo-pkg",
        "1.0.0",
        "demo-pkg-1.0.0-py3-none-any.whl",
    )
    .await
    .expect("purge artifact");
    assert_eq!(store.artifact_count(), 1);
    assert_eq!(storage.object_count(), 2);

    app.purge_release("acme", "demo-pkg", "1.1.0")
        .await
        .expect("purge release");
    assert_eq!(store.artifact_count(), 0);
    assert_eq!(storage.object_count(), 0);

    app.upload_artifact(
        &publish_access,
        UploadArtifactCommand {
            tenant_slug: "acme".into(),
            project_name: "Demo_Pkg".into(),
            version: "2.0.0".into(),
            filename: "demo-pkg-2.0.0-py3-none-any.whl".into(),
            summary: "Demo package".into(),
            description: "Project purge target".into(),
            content: b"final wheel".to_vec(),
        },
    )
    .await
    .expect("upload before project purge");
    app.purge_project("acme", "demo-pkg")
        .await
        .expect("purge project");
    assert_eq!(store.artifact_count(), 0);
    assert_eq!(storage.object_count(), 0);
    assert!(
        store
            .get_project_by_normalized_name(tenant.id, "demo-pkg")
            .await
            .expect("project lookup")
            .is_none()
    );
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
        Arc::new(UnusedWheelSourceSecurityScanner),
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
    admins: HashMap<String, AdminUser>,
    tokens: HashMap<Uuid, ApiToken>,
    projects: HashMap<Uuid, Project>,
    releases: HashMap<Uuid, Release>,
    artifacts: HashMap<Uuid, Artifact>,
    attestations: HashMap<Uuid, AttestationBundle>,
    trusted_publishers: HashMap<Uuid, TrustedPublisher>,
    audit_events: Vec<AuditEvent>,
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

    fn latest_version_for_project(
        state: &FakeRegistryState,
        project_id: ProjectId,
    ) -> Option<String> {
        state
            .releases
            .values()
            .filter(|release| release.project_id == project_id)
            .map(|release| release.version.clone())
            .max()
            .map(|version| version.as_str().to_string())
    }
}

#[async_trait]
impl RegistryStore for FakeRegistryStore {
    async fn registry_overview(&self) -> Result<RegistryOverview, ApplicationError> {
        let state = self.state.lock().expect("store state");
        Ok(RegistryOverview {
            tenant_count: state.tenants.len(),
            project_count: state.projects.len(),
            release_count: state.releases.len(),
            artifact_count: state.artifacts.len(),
            total_storage_bytes: state
                .artifacts
                .values()
                .map(|artifact| artifact.size_bytes)
                .sum(),
            mirrored_project_count: state
                .projects
                .values()
                .filter(|project| matches!(project.source, ProjectSource::Mirrored))
                .count(),
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

    async fn save_admin_user(&self, user: AdminUser) -> Result<(), ApplicationError> {
        self.state
            .lock()
            .expect("store state")
            .admins
            .insert(user.email.clone(), user);
        Ok(())
    }

    async fn get_admin_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<AdminUser>, ApplicationError> {
        Ok(self
            .state
            .lock()
            .expect("store state")
            .admins
            .get(email)
            .cloned())
    }

    async fn save_api_token(&self, token: ApiToken) -> Result<(), ApplicationError> {
        self.state
            .lock()
            .expect("store state")
            .tokens
            .insert(token.id.into_inner(), token);
        Ok(())
    }

    async fn list_api_tokens(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<ApiToken>, ApplicationError> {
        Ok(self
            .state
            .lock()
            .expect("store state")
            .tokens
            .values()
            .filter(|token| token.tenant_id == tenant_id)
            .cloned()
            .collect())
    }

    async fn revoke_api_token(
        &self,
        _tenant_id: TenantId,
        token_id: TokenId,
    ) -> Result<(), ApplicationError> {
        self.state
            .lock()
            .expect("store state")
            .tokens
            .remove(&token_id.into_inner());
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
        tenant_id: TenantId,
        query: &str,
    ) -> Result<Vec<SearchHit>, ApplicationError> {
        let query = query.trim().to_ascii_lowercase();
        let state = self.state.lock().expect("store state");
        Ok(state
            .projects
            .values()
            .filter(|project| project.tenant_id == tenant_id)
            .filter(|project| {
                query.is_empty()
                    || project.name.normalized().contains(&query)
                    || project.summary.to_ascii_lowercase().contains(&query)
            })
            .map(|project| SearchHit {
                tenant_slug: state
                    .tenants
                    .get(&tenant_id.into_inner())
                    .map(|tenant| tenant.slug.as_str().to_string())
                    .unwrap_or_default(),
                project_name: project.name.original().to_string(),
                normalized_name: project.name.normalized().to_string(),
                summary: project.summary.clone(),
                source: format!("{:?}", project.source).to_ascii_lowercase(),
                latest_version: Self::latest_version_for_project(&state, project.id),
            })
            .collect())
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
        publisher: TrustedPublisher,
    ) -> Result<(), ApplicationError> {
        self.state
            .lock()
            .expect("store state")
            .trusted_publishers
            .insert(publisher.id.into_inner(), publisher);
        Ok(())
    }

    async fn list_trusted_publishers(
        &self,
        tenant_id: TenantId,
        normalized_project_name: &str,
    ) -> Result<Vec<TrustedPublisher>, ApplicationError> {
        Ok(self
            .state
            .lock()
            .expect("store state")
            .trusted_publishers
            .values()
            .filter(|publisher| publisher.tenant_id == tenant_id)
            .filter(|publisher| {
                normalized_project_name.is_empty()
                    || publisher.project_name.normalized() == normalized_project_name
            })
            .cloned()
            .collect())
    }

    async fn delete_project(&self, project_id: ProjectId) -> Result<(), ApplicationError> {
        self.state
            .lock()
            .expect("store state")
            .projects
            .remove(&project_id.into_inner());
        Ok(())
    }

    async fn save_audit_event(&self, event: AuditEvent) -> Result<(), ApplicationError> {
        self.state
            .lock()
            .expect("store state")
            .audit_events
            .push(event);
        Ok(())
    }

    async fn list_audit_events(
        &self,
        tenant_slug: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AuditEvent>, ApplicationError> {
        let mut events = self
            .state
            .lock()
            .expect("store state")
            .audit_events
            .iter()
            .filter(|event| {
                tenant_slug
                    .map(|tenant_slug| event.tenant_slug.as_deref() == Some(tenant_slug))
                    .unwrap_or(true)
            })
            .cloned()
            .collect::<Vec<_>>();
        events.sort_by(|left, right| right.occurred_at.cmp(&left.occurred_at));
        events.truncate(limit);
        Ok(events)
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
        audience: &str,
    ) -> Result<PublishIdentity, ApplicationError> {
        Ok(PublishIdentity {
            issuer: "https://token.actions.githubusercontent.com".into(),
            subject: "repo:acme/demo-pkg:ref:refs/heads/main".into(),
            audience: audience.to_string(),
            provider: TrustedPublisherProvider::GitHubActions,
            claims: BTreeMap::from([
                ("repository".into(), "acme/demo-pkg".into()),
                ("ref".into(), "refs/heads/main".into()),
            ]),
        })
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
    fn hash(&self, password: &str) -> Result<String, ApplicationError> {
        Ok(format!("hashed:{password}"))
    }

    fn verify(&self, password: &str, hash: &str) -> Result<bool, ApplicationError> {
        Ok(hash == format!("hashed:{password}"))
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

struct UnusedWheelSourceSecurityScanner;

impl WheelSourceSecurityScanner for UnusedWheelSourceSecurityScanner {
    fn scan_archive(
        &self,
        _archive: &WheelArchiveSnapshot,
    ) -> Result<WheelSourceSecurityScanResult, ApplicationError> {
        Ok(WheelSourceSecurityScanResult {
            scanned_file_count: 0,
            findings: Vec::new(),
        })
    }
}

struct FakeDistributionInspector;

impl DistributionFileInspector for FakeDistributionInspector {
    fn inspect_distribution(
        &self,
        _path: &Path,
    ) -> Result<DistributionInspection, ApplicationError> {
        Err(ApplicationError::External(
            "path distribution inspection is unused".into(),
        ))
    }

    fn inspect_distribution_bytes(
        &self,
        filename: &str,
        bytes: &[u8],
    ) -> Result<DistributionInspection, ApplicationError> {
        Ok(DistributionInspection {
            kind: if filename.ends_with(".whl") {
                DistributionKind::Wheel
            } else if filename.ends_with(".zip") {
                DistributionKind::SourceZip
            } else {
                DistributionKind::SourceTarGz
            },
            size_bytes: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
            archive_entry_count: 1,
        })
    }
}

#[derive(Default)]
struct ConcurrentDistributionInspector {
    active: AtomicUsize,
    max_active: AtomicUsize,
}

impl ConcurrentDistributionInspector {
    fn max_active(&self) -> usize {
        self.max_active.load(Ordering::SeqCst)
    }

    fn mark_active(&self) {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        let mut observed = self.max_active.load(Ordering::SeqCst);
        while active > observed {
            match self.max_active.compare_exchange(
                observed,
                active,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(next) => observed = next,
            }
        }
    }
}

impl DistributionFileInspector for ConcurrentDistributionInspector {
    fn inspect_distribution(
        &self,
        _path: &Path,
    ) -> Result<DistributionInspection, ApplicationError> {
        Err(ApplicationError::External(
            "path distribution inspection is unused".into(),
        ))
    }

    fn inspect_distribution_bytes(
        &self,
        filename: &str,
        bytes: &[u8],
    ) -> Result<DistributionInspection, ApplicationError> {
        self.mark_active();
        std::thread::sleep(Duration::from_millis(50));
        self.active.fetch_sub(1, Ordering::SeqCst);

        Ok(DistributionInspection {
            kind: if filename.ends_with(".whl") {
                DistributionKind::Wheel
            } else if filename.ends_with(".zip") {
                DistributionKind::SourceZip
            } else {
                DistributionKind::SourceTarGz
            },
            size_bytes: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
            archive_entry_count: 1,
        })
    }
}
