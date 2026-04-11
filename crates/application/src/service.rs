use crate::{
    ApplicationError, AttestationSigner, Clock, IdGenerator, MirrorClient, ObjectStorage,
    OidcVerifier, PasswordHasher, RegistryStore, TokenHasher, VulnerabilityNotifier,
    VulnerabilityScanner, WheelArchiveReader, WheelSourceSecurityScanner, WheelVirusScanner,
};
use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use pyregistry_domain::{Artifact, Project, ProjectName, Release, ReleaseVersion, Tenant};
use std::sync::Arc;
use uuid::Uuid;

pub struct PyregistryApp {
    pub(crate) store: Arc<dyn RegistryStore>,
    pub(crate) object_storage: Arc<dyn ObjectStorage>,
    pub(crate) mirror_client: Arc<dyn MirrorClient>,
    pub(crate) oidc_verifier: Arc<dyn OidcVerifier>,
    pub(crate) attestation_signer: Arc<dyn AttestationSigner>,
    pub(crate) password_hasher: Arc<dyn PasswordHasher>,
    pub(crate) token_hasher: Arc<dyn TokenHasher>,
    pub(crate) vulnerability_scanner: Arc<dyn VulnerabilityScanner>,
    pub(crate) vulnerability_notifier: Arc<dyn VulnerabilityNotifier>,
    pub(crate) wheel_archive_reader: Arc<dyn WheelArchiveReader>,
    pub(crate) wheel_virus_scanner: Arc<dyn WheelVirusScanner>,
    pub(crate) wheel_source_security_scanner: Arc<dyn WheelSourceSecurityScanner>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) ids: Arc<dyn IdGenerator>,
    pub(crate) mirror_download_concurrency: usize,
}

impl PyregistryApp {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        store: Arc<dyn RegistryStore>,
        object_storage: Arc<dyn ObjectStorage>,
        mirror_client: Arc<dyn MirrorClient>,
        oidc_verifier: Arc<dyn OidcVerifier>,
        attestation_signer: Arc<dyn AttestationSigner>,
        password_hasher: Arc<dyn PasswordHasher>,
        token_hasher: Arc<dyn TokenHasher>,
        vulnerability_scanner: Arc<dyn VulnerabilityScanner>,
        vulnerability_notifier: Arc<dyn VulnerabilityNotifier>,
        wheel_archive_reader: Arc<dyn WheelArchiveReader>,
        wheel_virus_scanner: Arc<dyn WheelVirusScanner>,
        wheel_source_security_scanner: Arc<dyn WheelSourceSecurityScanner>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
        mirror_download_concurrency: usize,
    ) -> Self {
        Self {
            store,
            object_storage,
            mirror_client,
            oidc_verifier,
            attestation_signer,
            password_hasher,
            token_hasher,
            vulnerability_scanner,
            vulnerability_notifier,
            wheel_archive_reader,
            wheel_virus_scanner,
            wheel_source_security_scanner,
            clock,
            ids,
            mirror_download_concurrency: mirror_download_concurrency.max(1),
        }
    }

    pub(crate) async fn purge_project_internal(
        &self,
        project: &Project,
    ) -> Result<(), ApplicationError> {
        let mut release_count = 0usize;
        let mut artifact_count = 0usize;
        for release in self.store.list_releases(project.id).await? {
            release_count += 1;
            for artifact in self.store.list_artifacts(release.id).await? {
                artifact_count += 1;
                self.object_storage.delete(&artifact.object_key).await?;
                if let Some(key) = artifact.provenance_key {
                    self.object_storage.delete(&key).await?;
                }
                self.store.delete_artifact(artifact.id).await?;
            }
            self.store.delete_release(release.id).await?;
        }
        self.store.delete_project(project.id).await?;
        info!(
            "purged project `{}` removing {} release(s) and {} artifact(s)",
            project.name.original(),
            release_count,
            artifact_count
        );
        Ok(())
    }

    pub(crate) async fn ensure_project_available(
        &self,
        tenant_slug: &str,
        project_name: &str,
    ) -> Result<Project, ApplicationError> {
        let tenant = self.require_tenant(tenant_slug).await?;
        let project_name = ProjectName::new(project_name)?;
        if let Some(project) = self
            .store
            .get_project_by_normalized_name(tenant.id, project_name.normalized())
            .await?
        {
            debug!(
                "resolved tenant `{tenant_slug}` project `{}` from the registry store",
                project.name.original()
            );
            return Ok(project);
        }

        debug!(
            "project `{}` missing locally for tenant `{tenant_slug}`; attempting mirror resolution",
            project_name.original()
        );
        self.resolve_project_from_mirror(tenant_slug, project_name.original())
            .await?
            .ok_or_else(|| ApplicationError::NotFound("package".into()))
    }

    pub(crate) async fn find_release(
        &self,
        tenant_slug: &str,
        project_name: &str,
        version: &str,
    ) -> Result<Release, ApplicationError> {
        let project = self
            .ensure_project_available(tenant_slug, project_name)
            .await?;
        let version = ReleaseVersion::new(version)?;
        self.store
            .get_release_by_version(project.id, &version)
            .await?
            .ok_or_else(|| ApplicationError::NotFound("release".into()))
    }

    pub(crate) async fn find_artifact(
        &self,
        tenant_slug: &str,
        project_name: &str,
        version: &str,
        filename: &str,
    ) -> Result<Artifact, ApplicationError> {
        let release = self
            .find_release(tenant_slug, project_name, version)
            .await?;
        self.store
            .get_artifact_by_filename(release.id, filename)
            .await?
            .ok_or_else(|| ApplicationError::NotFound("artifact".into()))
    }

    pub(crate) async fn require_tenant(
        &self,
        tenant_slug: &str,
    ) -> Result<Tenant, ApplicationError> {
        let tenant = self
            .store
            .get_tenant_by_slug(tenant_slug)
            .await?
            .ok_or_else(|| {
                warn!("requested tenant `{tenant_slug}` was not found");
                ApplicationError::NotFound(format!("tenant `{tenant_slug}`"))
            })?;
        debug!("resolved tenant `{tenant_slug}`");
        Ok(tenant)
    }
}

pub struct SystemClock;

impl crate::Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

pub struct UuidGenerator;

impl crate::IdGenerator for UuidGenerator {
    fn next(&self) -> Uuid {
        Uuid::new_v4()
    }
}
