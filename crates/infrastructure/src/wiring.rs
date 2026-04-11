use crate::{
    ArgonPasswordHasher, ArtifactDownloadRetryPolicy, ArtifactStorageBackend, DatabaseStoreKind,
    FileSystemObjectStorage, FoxGuardWheelSourceSecurityScanner, InMemoryRegistryStore,
    JsonAttestationSigner, OpenDalObjectStorage, PostgresRegistryStore,
    PySentryVulnerabilityScanner, PypiMirrorClient, Settings, Sha256TokenHasher,
    SimpleJwksOidcVerifier, SqliteRegistryStore, YaraWheelVirusScanner, ZipWheelArchiveReader,
};
use log::{info, warn};
use pyregistry_application::{
    ApplicationError, ObjectStorage, PyregistryApp, RegistryStore, SystemClock, UuidGenerator,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

pub async fn build_application(
    settings: &Settings,
) -> Result<Arc<PyregistryApp>, InfrastructureError> {
    let registry_store = build_registry_store(settings).await?;
    info!(
        "using PyPI-compatible upstream base URL {} with mirror download concurrency {}, artifact download attempts {}, initial backoff {} ms",
        settings.pypi.base_url,
        settings.pypi.mirror_download_concurrency,
        settings.pypi.artifact_download_max_attempts,
        settings.pypi.artifact_download_initial_backoff_millis
    );
    let object_storage = build_object_storage(settings)?;
    let retry_policy = ArtifactDownloadRetryPolicy::new(
        settings.pypi.artifact_download_max_attempts,
        Duration::from_millis(settings.pypi.artifact_download_initial_backoff_millis),
    );
    let mirror_client = match PypiMirrorClient::with_retry_policy(
        &settings.pypi.base_url,
        retry_policy,
    ) {
        Ok(client) => Arc::new(client),
        Err(error) => {
            warn!(
                "configured PyPI base URL `{}` is invalid ({}); falling back to https://pypi.org",
                settings.pypi.base_url, error
            );
            Arc::new(
                PypiMirrorClient::with_retry_policy("https://pypi.org", retry_policy)
                    .expect("fallback PyPI URL is valid"),
            )
        }
    };
    Ok(Arc::new(PyregistryApp::new(
        registry_store,
        object_storage,
        mirror_client,
        Arc::new(SimpleJwksOidcVerifier::new(settings.oidc_issuers.clone())),
        Arc::new(JsonAttestationSigner),
        Arc::new(ArgonPasswordHasher),
        Arc::new(Sha256TokenHasher),
        Arc::new(PySentryVulnerabilityScanner::new(pysentry_cache_dir(
            settings,
        ))),
        Arc::new(ZipWheelArchiveReader),
        Arc::new(YaraWheelVirusScanner::from_rules_dir(
            settings.security.yara_rules_path.clone(),
        )),
        Arc::new(FoxGuardWheelSourceSecurityScanner::default()),
        Arc::new(SystemClock),
        Arc::new(UuidGenerator),
        settings.pypi.mirror_download_concurrency,
    )))
}

async fn build_registry_store(
    settings: &Settings,
) -> Result<Arc<dyn RegistryStore>, InfrastructureError> {
    match settings.database_store {
        DatabaseStoreKind::InMemory => {
            warn!(
                "building application with in-memory metadata store; registry state will be lost when the process exits"
            );
            if let Some(postgres) = &settings.postgres {
                warn!(
                    "postgres config is present ({}) but database_store is `in-memory`, so postgres metadata storage will not be used",
                    postgres.log_safe_summary()
                );
            }
            Ok(Arc::new(InMemoryRegistryStore::default()))
        }
        DatabaseStoreKind::Sqlite => {
            let sqlite = settings
                .sqlite
                .as_ref()
                .ok_or(InfrastructureError::SqliteConfigurationRequired)?;
            info!(
                "building application with SQLite metadata store at {}",
                sqlite.path.display()
            );
            SqliteRegistryStore::open(&sqlite.path)
                .map(|store| Arc::new(store) as Arc<dyn RegistryStore>)
                .map_err(|error| InfrastructureError::MetadataStoreConfiguration(error.to_string()))
        }
        DatabaseStoreKind::Pgsql => {
            let postgres = settings
                .postgres
                .as_ref()
                .ok_or(InfrastructureError::PostgresConfigurationRequired)?;
            info!(
                "building application with PostgreSQL metadata store: {}",
                postgres.log_safe_summary()
            );
            PostgresRegistryStore::connect(postgres)
                .await
                .map(|store| Arc::new(store) as Arc<dyn RegistryStore>)
                .map_err(|error| InfrastructureError::MetadataStoreConfiguration(error.to_string()))
        }
    }
}

fn pysentry_cache_dir(settings: &Settings) -> PathBuf {
    settings
        .blob_root
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new(".pyregistry"))
        .join("pysentry-cache")
}

fn build_object_storage(
    settings: &Settings,
) -> Result<Arc<dyn ObjectStorage>, InfrastructureError> {
    match settings.artifact_storage.backend {
        ArtifactStorageBackend::FileSystem => {
            warn!(
                "using legacy filesystem artifact storage rooted at {}; prefer artifact_storage.backend=`opendal` for new deployments",
                settings.blob_root.display()
            );
            Ok(Arc::new(FileSystemObjectStorage::new(
                settings.blob_root.clone(),
            )))
        }
        ArtifactStorageBackend::OpenDal => {
            info!(
                "building OpenDAL artifact storage: {}",
                settings.artifact_storage.opendal.log_safe_summary()
            );
            let storage = OpenDalObjectStorage::from_config(&settings.artifact_storage.opendal)
                .map_err(InfrastructureError::ObjectStorageConfiguration)?;
            Ok(Arc::new(storage))
        }
    }
}

pub async fn seed_application(
    app: &Arc<PyregistryApp>,
    settings: &Settings,
) -> Result<(), ApplicationError> {
    info!(
        "seeding bootstrap superadmin `{}`",
        settings.superadmin_email
    );
    app.bootstrap_superadmin(&settings.superadmin_email, &settings.superadmin_password)
        .await?;

    if app.list_tenants().await?.is_empty() {
        info!("no tenants found; creating bootstrap tenant `acme`");
        let _tenant = app
            .create_tenant(pyregistry_application::CreateTenantCommand {
                slug: "acme".into(),
                display_name: "Acme Corp".into(),
                mirroring_enabled: true,
                admin_email: "tenant-admin@acme.local".into(),
                admin_password: "change-me-now".into(),
            })
            .await?;
        let _ = app
            .issue_api_token(pyregistry_application::IssueApiTokenCommand {
                tenant_slug: "acme".into(),
                label: "bootstrap-readwrite".into(),
                scopes: vec![
                    pyregistry_domain::TokenScope::Read,
                    pyregistry_domain::TokenScope::Publish,
                    pyregistry_domain::TokenScope::Admin,
                ],
                ttl_hours: None,
            })
            .await?;
        info!("bootstrap tenant `acme` seeded with an initial API token");
    } else {
        info!("tenant store already populated; skipping bootstrap tenant creation");
    }

    Ok(())
}

#[derive(Debug, Error)]
pub enum InfrastructureError {
    #[error("database_store `sqlite` requires sqlite metadata settings")]
    SqliteConfigurationRequired,
    #[error("database_store `pgsql` requires postgres connection settings")]
    PostgresConfigurationRequired,
    #[error("metadata store is not configured correctly: {0}")]
    MetadataStoreConfiguration(String),
    #[error("artifact object storage is not configured correctly: {0}")]
    ObjectStorageConfiguration(String),
}
