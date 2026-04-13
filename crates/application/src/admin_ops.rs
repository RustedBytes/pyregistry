use crate::{
    AdminSession, ApplicationError, CreateTenantCommand, DashboardMetrics, PackageArtifactDetails,
    PackageDetails, PackageReleaseDetails, PyregistryApp, RegistryOverview, SearchHit,
    TrustedPublisherDescriptor,
};
use log::{debug, info, warn};
use pyregistry_domain::{AdminUser, AdminUserId, MirrorRule, Tenant, TenantId, TenantSlug};

impl PyregistryApp {
    pub async fn bootstrap_superadmin(
        &self,
        email: &str,
        password: &str,
    ) -> Result<(), ApplicationError> {
        let email = email.trim().to_ascii_lowercase();
        if self.store.get_admin_user_by_email(&email).await?.is_some() {
            info!("bootstrap skipped because superadmin `{email}` already exists");
            return Ok(());
        }

        let user = AdminUser {
            id: AdminUserId::new(self.ids.next()),
            tenant_id: None,
            email: email.clone(),
            password_hash: self.password_hasher.hash(password)?,
            is_superadmin: true,
            created_at: self.clock.now(),
        };

        self.store.save_admin_user(user).await?;
        info!("bootstrapped superadmin account `{email}`");
        Ok(())
    }

    pub async fn get_registry_overview(&self) -> Result<RegistryOverview, ApplicationError> {
        let overview = self.store.registry_overview().await?;
        debug!(
            "loaded registry overview: tenants={}, projects={}, releases={}, artifacts={}, mirrored_projects={}, total_storage_bytes={}",
            overview.tenant_count,
            overview.project_count,
            overview.release_count,
            overview.artifact_count,
            overview.mirrored_project_count,
            overview.total_storage_bytes
        );
        Ok(overview)
    }

    pub async fn list_tenants(&self) -> Result<Vec<Tenant>, ApplicationError> {
        let tenants = self.store.list_tenants().await?;
        debug!("listed {} tenant(s)", tenants.len());
        Ok(tenants)
    }

    pub async fn create_tenant(
        &self,
        command: CreateTenantCommand,
    ) -> Result<Tenant, ApplicationError> {
        info!(
            "creating tenant slug=`{}` display_name=`{}` mirroring_enabled={}",
            command.slug, command.display_name, command.mirroring_enabled
        );
        let slug = TenantSlug::new(command.slug)?;
        if self
            .store
            .get_tenant_by_slug(slug.as_str())
            .await?
            .is_some()
        {
            warn!(
                "tenant creation rejected because `{}` already exists",
                slug.as_str()
            );
            return Err(ApplicationError::Conflict(format!(
                "tenant `{}` already exists",
                slug.as_str()
            )));
        }

        let tenant = Tenant::new(
            TenantId::new(self.ids.next()),
            slug,
            command.display_name,
            MirrorRule {
                enabled: command.mirroring_enabled,
            },
            self.clock.now(),
        )?;
        self.store.save_tenant(tenant.clone()).await?;

        let admin = AdminUser {
            id: AdminUserId::new(self.ids.next()),
            tenant_id: Some(tenant.id),
            email: command.admin_email.trim().to_ascii_lowercase(),
            password_hash: self.password_hasher.hash(&command.admin_password)?,
            is_superadmin: false,
            created_at: self.clock.now(),
        };
        self.store.save_admin_user(admin).await?;

        info!(
            "created tenant `{}` with admin `{}`",
            tenant.slug.as_str(),
            command.admin_email.trim().to_ascii_lowercase()
        );
        Ok(tenant)
    }

    pub async fn login_admin(
        &self,
        email: &str,
        password: &str,
    ) -> Result<AdminSession, ApplicationError> {
        let email = email.trim().to_ascii_lowercase();
        debug!("admin login requested for `{email}`");
        let user = self
            .store
            .get_admin_user_by_email(&email)
            .await?
            .ok_or_else(|| {
                warn!("admin login rejected because `{email}` is unknown");
                ApplicationError::Unauthorized("unknown admin".into())
            })?;

        if !self.password_hasher.verify(password, &user.password_hash)? {
            warn!(
                "admin login rejected because `{}` provided an invalid password",
                user.email
            );
            return Err(ApplicationError::Unauthorized("invalid credentials".into()));
        }

        let tenant_slug = if let Some(tenant_id) = user.tenant_id {
            self.store
                .list_tenants()
                .await?
                .into_iter()
                .find(|tenant| tenant.id == tenant_id)
                .map(|tenant| tenant.slug.as_str().to_string())
        } else {
            None
        };

        let session = AdminSession {
            email: user.email,
            tenant_slug,
            is_superadmin: user.is_superadmin,
        };
        info!(
            "admin login succeeded for `{}` (superadmin={}, tenant={:?})",
            session.email, session.is_superadmin, session.tenant_slug
        );
        Ok(session)
    }

    pub async fn get_tenant_dashboard(
        &self,
        tenant_slug: &str,
    ) -> Result<DashboardMetrics, ApplicationError> {
        debug!("loading tenant dashboard for `{tenant_slug}`");
        let tenant = self.require_tenant(tenant_slug).await?;
        let stats = self.store.tenant_dashboard_stats(&tenant).await?;

        let metrics = DashboardMetrics {
            tenant_slug: tenant.slug.as_str().to_string(),
            project_count: stats.project_count,
            release_count: stats.release_count,
            artifact_count: stats.artifact_count,
            token_count: stats.token_count,
            trusted_publisher_count: stats.trusted_publisher_count,
            recent_activity: stats.recent_activity,
        };
        debug!(
            "tenant dashboard ready for `{}`: projects={}, releases={}, artifacts={}, tokens={}, trusted_publishers={}",
            metrics.tenant_slug,
            metrics.project_count,
            metrics.release_count,
            metrics.artifact_count,
            metrics.token_count,
            metrics.trusted_publisher_count
        );
        Ok(metrics)
    }

    pub async fn search_packages(
        &self,
        tenant_slug: &str,
        query: &str,
    ) -> Result<Vec<SearchHit>, ApplicationError> {
        let tenant = self.require_tenant(tenant_slug).await?;
        let hits = self.store.search_projects(tenant.id, query).await?;
        debug!(
            "package search for tenant `{tenant_slug}` query=`{}` returned {} hit(s)",
            query.trim(),
            hits.len()
        );
        Ok(hits)
    }

    pub async fn list_tenant_packages(
        &self,
        tenant_slug: &str,
    ) -> Result<Vec<SearchHit>, ApplicationError> {
        self.search_packages(tenant_slug, "").await
    }

    pub async fn get_package_details(
        &self,
        tenant_slug: &str,
        project_name: &str,
    ) -> Result<PackageDetails, ApplicationError> {
        debug!("loading package details for tenant `{tenant_slug}` project `{project_name}`");
        let project = self
            .ensure_project_available(tenant_slug, project_name)
            .await?;
        let tenant = self.require_tenant(tenant_slug).await?;
        let mut release_artifact_groups = self.store.list_release_artifacts(project.id).await?;
        release_artifact_groups
            .sort_by(|left, right| right.release.version.cmp(&left.release.version));

        let mut release_details = Vec::new();
        for group in release_artifact_groups {
            let mut artifacts = group.artifacts;
            artifacts.sort_by(|left, right| left.filename.cmp(&right.filename));
            let artifacts = artifacts
                .into_iter()
                .map(|artifact| PackageArtifactDetails {
                    filename: artifact.filename,
                    version: group.release.version.as_str().to_string(),
                    size_bytes: artifact.size_bytes,
                    sha256: artifact.digests.sha256,
                    object_key: artifact.object_key,
                    yanked_reason: artifact.yanked.and_then(|state| state.reason),
                    security: crate::ArtifactSecurityDetails::pending(),
                })
                .collect();

            release_details.push(PackageReleaseDetails {
                version: group.release.version.as_str().to_string(),
                yanked_reason: group.release.yanked.and_then(|state| state.reason),
                artifacts,
            });
        }

        let security = self
            .attach_package_security(
                project.name.original(),
                project.name.normalized(),
                &mut release_details,
            )
            .await;

        let trusted_publishers = self
            .store
            .list_trusted_publishers(tenant.id, project.name.normalized())
            .await?
            .into_iter()
            .map(|publisher| TrustedPublisherDescriptor {
                provider: format!("{:?}", publisher.provider),
                issuer: publisher.issuer,
                audience: publisher.audience,
                project_name: publisher.project_name.original().to_string(),
                claim_rules: publisher.claim_rules,
            })
            .collect();

        let details = PackageDetails {
            tenant_slug: tenant.slug.as_str().to_string(),
            project_name: project.name.original().to_string(),
            normalized_name: project.name.normalized().to_string(),
            summary: project.summary,
            description: project.description,
            source: format!("{:?}", project.source).to_ascii_lowercase(),
            security,
            releases: release_details,
            trusted_publishers,
        };
        debug!(
            "package details ready for tenant `{}` project `{}`: source={}, releases={}, trusted_publishers={}",
            details.tenant_slug,
            details.project_name,
            details.source,
            details.releases.len(),
            details.trusted_publishers.len()
        );
        Ok(details)
    }
}
