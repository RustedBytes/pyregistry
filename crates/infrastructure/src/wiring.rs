use crate::{
    ArgonPasswordHasher, ArtifactStorageBackend, DatabaseStoreKind, FileSystemObjectStorage,
    InMemoryRegistryStore, JsonAttestationSigner, OpenDalObjectStorage,
    PySentryVulnerabilityScanner, PypiMirrorClient, Settings, Sha256TokenHasher,
    SimpleJwksOidcVerifier, YaraWheelVirusScanner, ZipWheelArchiveReader,
};
use log::{info, warn};
use pyregistry_application::{
    ApplicationError, ObjectStorage, PyregistryApp, SystemClock, UuidGenerator,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;

pub fn build_application(settings: &Settings) -> Result<Arc<PyregistryApp>, InfrastructureError> {
    match settings.database_store {
        DatabaseStoreKind::InMemory => {
            info!(
                "building application with in-memory registry store and filesystem blobs rooted at {}",
                settings.blob_root.display()
            );
            if let Some(postgres) = &settings.postgres {
                warn!(
                    "postgres config is present ({}) but database_store is `in-memory`, so postgres metadata storage will not be used",
                    postgres.log_safe_summary()
                );
            }
        }
        DatabaseStoreKind::Pgsql => {
            let postgres = settings
                .postgres
                .as_ref()
                .ok_or(InfrastructureError::PostgresConfigurationRequired)?;
            return Err(InfrastructureError::PostgresStoreNotImplemented(
                postgres.log_safe_summary(),
            ));
        }
    }
    info!(
        "using PyPI-compatible upstream base URL {}",
        settings.pypi.base_url
    );
    warn!(
        "pyregistry is running with development metadata store adapters until postgres support lands"
    );
    let object_storage = build_object_storage(settings)?;
    let mirror_client = match PypiMirrorClient::new(&settings.pypi.base_url) {
        Ok(client) => Arc::new(client),
        Err(error) => {
            warn!(
                "configured PyPI base URL `{}` is invalid ({}); falling back to https://pypi.org",
                settings.pypi.base_url, error
            );
            Arc::new(PypiMirrorClient::default())
        }
    };
    Ok(Arc::new(PyregistryApp::new(
        Arc::new(InMemoryRegistryStore::default()),
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
        Arc::new(SystemClock),
        Arc::new(UuidGenerator),
    )))
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
    #[error("database_store `pgsql` requires postgres connection settings")]
    PostgresConfigurationRequired,
    #[error(
        "database_store `pgsql` is configured, but the postgres metadata adapter is not implemented yet ({0})"
    )]
    PostgresStoreNotImplemented(String),
    #[error("artifact object storage is not configured correctly: {0}")]
    ObjectStorageConfiguration(String),
}
