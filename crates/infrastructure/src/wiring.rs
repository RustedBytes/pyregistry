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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OpenDalStorageConfig, PostgresConfig, SqliteConfig};
    use std::collections::BTreeMap;
    use uuid::Uuid;

    fn in_memory_settings() -> Settings {
        let mut settings = Settings::new_local_template();
        settings.database_store = DatabaseStoreKind::InMemory;
        settings.blob_root =
            std::env::temp_dir().join(format!("pyregistry-wiring-{}", Uuid::new_v4()));
        settings
    }

    #[tokio::test]
    async fn builds_application_with_in_memory_store_and_filesystem_storage() {
        let settings = in_memory_settings();

        let app = build_application(&settings).await.expect("application");

        assert_eq!(app.list_tenants().await.expect("tenants"), Vec::new());
        assert_eq!(
            app.get_registry_overview()
                .await
                .expect("overview")
                .tenant_count,
            0
        );

        let _ = std::fs::remove_dir_all(settings.blob_root);
    }

    #[tokio::test]
    async fn seed_application_creates_superadmin_and_bootstrap_tenant_once() {
        let settings = in_memory_settings();
        let app = build_application(&settings).await.expect("application");

        seed_application(&app, &settings).await.expect("first seed");
        seed_application(&app, &settings)
            .await
            .expect("second seed");

        assert_eq!(app.list_tenants().await.expect("tenants").len(), 1);
        assert!(
            app.login_admin(&settings.superadmin_email, &settings.superadmin_password)
                .await
                .is_ok()
        );

        let _ = std::fs::remove_dir_all(settings.blob_root);
    }

    #[tokio::test]
    async fn build_registry_store_requires_selected_database_configuration() {
        let mut sqlite_settings = in_memory_settings();
        sqlite_settings.database_store = DatabaseStoreKind::Sqlite;
        sqlite_settings.sqlite = None;
        assert!(matches!(
            build_registry_store(&sqlite_settings).await,
            Err(InfrastructureError::SqliteConfigurationRequired)
        ));

        let mut postgres_settings = in_memory_settings();
        postgres_settings.database_store = DatabaseStoreKind::Pgsql;
        postgres_settings.postgres = None;
        assert!(matches!(
            build_registry_store(&postgres_settings).await,
            Err(InfrastructureError::PostgresConfigurationRequired)
        ));
    }

    #[tokio::test]
    async fn build_registry_store_opens_sqlite_metadata_store() {
        let path =
            std::env::temp_dir().join(format!("pyregistry-wiring-{}.sqlite", Uuid::new_v4()));
        let mut settings = in_memory_settings();
        settings.database_store = DatabaseStoreKind::Sqlite;
        settings.sqlite = Some(SqliteConfig { path: path.clone() });

        let store = build_registry_store(&settings)
            .await
            .expect("sqlite registry store");

        assert_eq!(
            store
                .registry_overview()
                .await
                .expect("overview")
                .tenant_count,
            0
        );
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn build_registry_store_reports_postgres_connection_errors() {
        let mut settings = in_memory_settings();
        settings.database_store = DatabaseStoreKind::Pgsql;
        settings.postgres = Some(PostgresConfig {
            connection_url: "postgres://invalid:invalid@127.0.0.1:1/pyregistry".into(),
            max_connections: 1,
            min_connections: 0,
            acquire_timeout_seconds: 1,
        });

        assert!(matches!(
            build_registry_store(&settings).await,
            Err(InfrastructureError::MetadataStoreConfiguration(_))
        ));
    }

    #[test]
    fn build_object_storage_uses_filesystem_or_reports_opendal_config_errors() {
        let settings = in_memory_settings();
        let storage = build_object_storage(&settings).expect("filesystem storage");
        assert!(Arc::strong_count(&storage) >= 1);

        let mut broken = settings.clone();
        broken.artifact_storage.backend = ArtifactStorageBackend::OpenDal;
        broken.artifact_storage.opendal = OpenDalStorageConfig {
            scheme: "fs".into(),
            options: BTreeMap::new(),
        };

        assert!(matches!(
            build_object_storage(&broken),
            Err(InfrastructureError::ObjectStorageConfiguration(_))
        ));
    }

    #[test]
    fn pysentry_cache_dir_is_sibling_to_blob_root_parent() {
        let mut settings = in_memory_settings();
        settings.blob_root = PathBuf::from("/tmp/pyregistry/blobs");

        assert_eq!(
            pysentry_cache_dir(&settings),
            PathBuf::from("/tmp/pyregistry/pysentry-cache")
        );
    }
}
