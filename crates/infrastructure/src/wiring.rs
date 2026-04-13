use crate::{
    ArgonPasswordHasher, ArtifactDownloadRetryPolicy, ArtifactStorageBackend, DatabaseStoreKind,
    DiscordWebhookVulnerabilityNotifier, FileSystemObjectStorage,
    FoxGuardWheelSourceSecurityScanner, InMemoryRegistryStore, JsonAttestationSigner,
    OpenDalObjectStorage, PostgresRegistryStore, PySentryVulnerabilityScanner, PypiMirrorClient,
    Settings, Sha256TokenHasher, SimpleJwksOidcVerifier, SqliteRegistryStore,
    YaraWheelVirusScanner, ZipWheelArchiveReader,
};
use log::{info, warn};
use pyregistry_application::{
    ApplicationError, NoopVulnerabilityNotifier, ObjectStorage, PyregistryApp, RegistryStore,
    SystemClock, UuidGenerator, VulnerabilityNotifier, WheelAuditNotifier,
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
    let vulnerability_notifier = build_vulnerability_notifier(settings)?;
    let wheel_audit_notifier = build_wheel_audit_notifier(settings)?;

    Ok(Arc::new(PyregistryApp::new(
        registry_store,
        object_storage,
        mirror_client,
        Arc::new(SimpleJwksOidcVerifier::new(settings.oidc_issuers.clone())),
        Arc::new(JsonAttestationSigner),
        Arc::new(ArgonPasswordHasher),
        Arc::new(Sha256TokenHasher),
        Arc::new(
            PySentryVulnerabilityScanner::with_ignored_vulnerability_ids(
                pysentry_cache_dir(settings),
                settings
                    .security
                    .scanner_ignores
                    .pysentry_vulnerability_ids
                    .clone(),
            ),
        ),
        vulnerability_notifier,
        wheel_audit_notifier,
        Arc::new(ZipWheelArchiveReader),
        Arc::new(YaraWheelVirusScanner::from_rules_dir_with_ignored_rules(
            settings.security.yara_rules_path.clone(),
            settings.security.scanner_ignores.yara_rule_ids.clone(),
        )),
        Arc::new(FoxGuardWheelSourceSecurityScanner::with_ignored_rules(
            settings.security.scanner_ignores.foxguard_rule_ids.clone(),
        )),
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
                .await
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

fn build_vulnerability_notifier(
    settings: &Settings,
) -> Result<Arc<dyn VulnerabilityNotifier>, InfrastructureError> {
    let config = &settings.security.vulnerability_webhook;
    let Some(url) = &config.url else {
        info!("vulnerable package webhook notifications are disabled");
        return Ok(Arc::new(NoopVulnerabilityNotifier));
    };

    info!(
        "vulnerable package webhook notifications are enabled: {}",
        config.log_safe_summary()
    );
    DiscordWebhookVulnerabilityNotifier::new(url, config.username.clone(), config.timeout_seconds)
        .map(|notifier| Arc::new(notifier) as Arc<dyn VulnerabilityNotifier>)
        .map_err(|error| InfrastructureError::WebhookConfiguration(error.to_string()))
}

fn build_wheel_audit_notifier(
    settings: &Settings,
) -> Result<Arc<dyn WheelAuditNotifier>, InfrastructureError> {
    let config = &settings.security.vulnerability_webhook;
    let Some(url) = &config.url else {
        info!("wheel audit webhook notifications are disabled");
        return Ok(Arc::new(pyregistry_application::NoopWheelAuditNotifier));
    };

    info!(
        "wheel audit webhook notifications are enabled: {}",
        config.log_safe_summary()
    );
    DiscordWebhookVulnerabilityNotifier::new(url, config.username.clone(), config.timeout_seconds)
        .map(|notifier| Arc::new(notifier) as Arc<dyn WheelAuditNotifier>)
        .map_err(|error| InfrastructureError::WebhookConfiguration(error.to_string()))
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
    #[error("vulnerability webhook is not configured correctly: {0}")]
    WebhookConfiguration(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OpenDalStorageConfig, PostgresConfig, SqliteConfig};
    use std::collections::BTreeMap;
    use std::sync::Once;
    use uuid::Uuid;

    fn in_memory_settings() -> Settings {
        let mut settings = Settings::new_local_template();
        settings.database_store = DatabaseStoreKind::InMemory;
        settings.blob_root =
            std::env::temp_dir().join(format!("pyregistry-wiring-{}", Uuid::new_v4()));
        let yara_rules_path = settings.blob_root.join("yara-rules");
        std::fs::create_dir_all(&yara_rules_path).expect("create test YARA rules dir");
        std::fs::write(
            yara_rules_path.join("pyregistry-test.yar"),
            "rule PyregistryWiringTest { condition: false }",
        )
        .expect("write test YARA rule");
        settings.security.yara_rules_path = yara_rules_path;
        settings
    }

    #[tokio::test]
    async fn builds_application_with_in_memory_store_and_filesystem_storage() {
        init_test_logger();
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
    async fn build_application_falls_back_when_pypi_base_url_is_invalid() {
        init_test_logger();
        let mut settings = in_memory_settings();
        settings.pypi.base_url = "not a URL".into();

        let app = build_application(&settings)
            .await
            .expect("application with fallback PyPI client");

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
        init_test_logger();
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
        init_test_logger();
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
        init_test_logger();
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
        init_test_logger();
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
        init_test_logger();
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
        init_test_logger();
        let mut settings = in_memory_settings();
        settings.blob_root = PathBuf::from("/tmp/pyregistry/blobs");

        assert_eq!(
            pysentry_cache_dir(&settings),
            PathBuf::from("/tmp/pyregistry/pysentry-cache")
        );
    }

    static TEST_LOGGER: TestLogger = TestLogger;
    static INIT_TEST_LOGGER: Once = Once::new();

    struct TestLogger;

    impl log::Log for TestLogger {
        fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
            true
        }

        fn log(&self, record: &log::Record<'_>) {
            let _ = format!("{}", record.args());
        }

        fn flush(&self) {}
    }

    fn init_test_logger() {
        INIT_TEST_LOGGER.call_once(|| {
            let _ = log::set_logger(&TEST_LOGGER);
            log::set_max_level(log::LevelFilter::Trace);
        });
    }
}
