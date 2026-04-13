use crate::{ApplicationError, DeletionCommand, PyregistryApp};
use log::info;
use pyregistry_domain::{ProjectName, ProjectSource, ensure_purge_allowed};

impl PyregistryApp {
    pub async fn yank_artifact(&self, command: DeletionCommand) -> Result<(), ApplicationError> {
        info!(
            "yanking artifact for tenant `{}` project `{}` version `{:?}` filename `{:?}` mode={:?}",
            command.tenant_slug,
            command.project_name,
            command.version,
            command.filename,
            command.mode
        );
        let artifact = self
            .find_artifact(
                &command.tenant_slug,
                &command.project_name,
                command
                    .version
                    .as_deref()
                    .ok_or_else(|| ApplicationError::NotFound("release version".into()))?,
                command
                    .filename
                    .as_deref()
                    .ok_or_else(|| ApplicationError::NotFound("artifact filename".into()))?,
            )
            .await?;
        let mut artifact = artifact;
        artifact.yank(command.reason, self.clock.now());
        self.store.save_artifact(artifact).await?;
        info!("artifact yank completed");
        Ok(())
    }

    pub async fn unyank_artifact(
        &self,
        tenant_slug: &str,
        project_name: &str,
        version: &str,
        filename: &str,
    ) -> Result<(), ApplicationError> {
        info!(
            "unyanking artifact for tenant `{tenant_slug}` project `{project_name}` version `{version}` filename `{filename}`"
        );
        let mut artifact = self
            .find_artifact(tenant_slug, project_name, version, filename)
            .await?;
        artifact.unyank();
        self.store.save_artifact(artifact).await?;
        info!("artifact unyank completed");
        Ok(())
    }

    pub async fn yank_release(&self, command: DeletionCommand) -> Result<(), ApplicationError> {
        info!(
            "yanking release for tenant `{}` project `{}` version `{:?}` mode={:?}",
            command.tenant_slug, command.project_name, command.version, command.mode
        );
        let release = self
            .find_release(
                &command.tenant_slug,
                &command.project_name,
                command
                    .version
                    .as_deref()
                    .ok_or_else(|| ApplicationError::NotFound("release version".into()))?,
            )
            .await?;
        let mut release = release;
        release.yank(command.reason, self.clock.now());
        self.store.save_release(release).await?;
        info!("release yank completed");
        Ok(())
    }

    pub async fn unyank_release(
        &self,
        tenant_slug: &str,
        project_name: &str,
        version: &str,
    ) -> Result<(), ApplicationError> {
        info!(
            "unyanking release for tenant `{tenant_slug}` project `{project_name}` version `{version}`"
        );
        let mut release = self
            .find_release(tenant_slug, project_name, version)
            .await?;
        release.unyank();
        self.store.save_release(release).await?;
        info!("release unyank completed");
        Ok(())
    }

    pub async fn purge_artifact(
        &self,
        tenant_slug: &str,
        project_name: &str,
        version: &str,
        filename: &str,
    ) -> Result<(), ApplicationError> {
        info!(
            "purging artifact for tenant `{tenant_slug}` project `{project_name}` version `{version}` filename `{filename}`"
        );
        let project = self
            .ensure_project_available(tenant_slug, project_name)
            .await?;
        ensure_purge_allowed(&project.source)?;
        let artifact = self
            .find_artifact(tenant_slug, project_name, version, filename)
            .await?;
        self.object_storage.delete(&artifact.object_key).await?;
        if let Some(key) = artifact.provenance_key {
            self.object_storage.delete(&key).await?;
        }
        self.store.delete_artifact(artifact.id).await?;
        info!("artifact purge completed");
        Ok(())
    }

    pub async fn purge_release(
        &self,
        tenant_slug: &str,
        project_name: &str,
        version: &str,
    ) -> Result<(), ApplicationError> {
        info!(
            "purging release for tenant `{tenant_slug}` project `{project_name}` version `{version}`"
        );
        let project = self
            .ensure_project_available(tenant_slug, project_name)
            .await?;
        ensure_purge_allowed(&project.source)?;
        let release = self
            .find_release(tenant_slug, project_name, version)
            .await?;
        for artifact in self.store.list_artifacts(release.id).await? {
            self.object_storage.delete(&artifact.object_key).await?;
            if let Some(key) = artifact.provenance_key {
                self.object_storage.delete(&key).await?;
            }
            self.store.delete_artifact(artifact.id).await?;
        }
        self.store.delete_release(release.id).await?;
        info!("release purge completed");
        Ok(())
    }

    pub async fn purge_project(
        &self,
        tenant_slug: &str,
        project_name: &str,
    ) -> Result<(), ApplicationError> {
        info!("purging project for tenant `{tenant_slug}` project `{project_name}`");
        let project = self
            .ensure_project_available(tenant_slug, project_name)
            .await?;
        ensure_purge_allowed(&project.source)?;
        self.purge_project_internal(&project).await?;
        info!("project purge completed");
        Ok(())
    }

    pub async fn remove_package(
        &self,
        tenant_slug: &str,
        project_name: &str,
    ) -> Result<(), ApplicationError> {
        info!("removing package for tenant `{tenant_slug}` project `{project_name}`");
        let tenant = self.require_tenant(tenant_slug).await?;
        let project_name = ProjectName::new(project_name)?;
        let project = self
            .store
            .get_project_by_normalized_name(tenant.id, project_name.normalized())
            .await?
            .ok_or_else(|| ApplicationError::NotFound("package".into()))?;

        if matches!(project.source, ProjectSource::Local) {
            ensure_purge_allowed(&project.source)?;
        }

        self.purge_project_internal(&project).await?;
        info!("package removal completed");
        Ok(())
    }
}
