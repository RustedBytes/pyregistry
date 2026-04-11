use async_trait::async_trait;
use pyregistry_application::{ApplicationError, RegistryOverview, RegistryStore, SearchHit};
use pyregistry_domain::{
    AdminUser, ApiToken, Artifact, ArtifactId, AttestationBundle, AuditEvent, Project, ProjectId,
    ProjectSource, Release, ReleaseId, ReleaseVersion, Tenant, TenantId, TokenId, TrustedPublisher,
};
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Default)]
struct InMemoryData {
    tenants: HashMap<Uuid, Tenant>,
    admins: HashMap<String, AdminUser>,
    tokens: HashMap<Uuid, ApiToken>,
    projects: HashMap<Uuid, Project>,
    releases: HashMap<Uuid, Release>,
    artifacts: HashMap<Uuid, Artifact>,
    attestations: HashMap<Uuid, AttestationBundle>,
    trusted_publishers: HashMap<Uuid, TrustedPublisher>,
    audit_events: HashMap<Uuid, AuditEvent>,
}

#[derive(Default)]
pub struct InMemoryRegistryStore {
    data: RwLock<InMemoryData>,
}

#[async_trait]
impl RegistryStore for InMemoryRegistryStore {
    async fn registry_overview(&self) -> Result<RegistryOverview, ApplicationError> {
        let data = self.data.read().await;
        Ok(RegistryOverview {
            tenant_count: data.tenants.len(),
            project_count: data.projects.len(),
            release_count: data.releases.len(),
            artifact_count: data.artifacts.len(),
            total_storage_bytes: data
                .artifacts
                .values()
                .map(|artifact| artifact.size_bytes)
                .sum(),
            mirrored_project_count: data
                .projects
                .values()
                .filter(|project| matches!(project.source, ProjectSource::Mirrored))
                .count(),
        })
    }

    async fn save_tenant(&self, tenant: Tenant) -> Result<(), ApplicationError> {
        self.data
            .write()
            .await
            .tenants
            .insert(tenant.id.into_inner(), tenant);
        Ok(())
    }

    async fn list_tenants(&self) -> Result<Vec<Tenant>, ApplicationError> {
        let data = self.data.read().await;
        let mut tenants: Vec<_> = data.tenants.values().cloned().collect();
        tenants.sort_by(|left, right| left.slug.as_str().cmp(right.slug.as_str()));
        Ok(tenants)
    }

    async fn get_tenant_by_slug(&self, slug: &str) -> Result<Option<Tenant>, ApplicationError> {
        let data = self.data.read().await;
        Ok(data
            .tenants
            .values()
            .find(|tenant| tenant.slug.as_str() == slug)
            .cloned())
    }

    async fn save_admin_user(&self, user: AdminUser) -> Result<(), ApplicationError> {
        self.data
            .write()
            .await
            .admins
            .insert(user.email.clone(), user);
        Ok(())
    }

    async fn get_admin_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<AdminUser>, ApplicationError> {
        Ok(self.data.read().await.admins.get(email).cloned())
    }

    async fn save_api_token(&self, token: ApiToken) -> Result<(), ApplicationError> {
        self.data
            .write()
            .await
            .tokens
            .insert(token.id.into_inner(), token);
        Ok(())
    }

    async fn list_api_tokens(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<ApiToken>, ApplicationError> {
        let data = self.data.read().await;
        Ok(data
            .tokens
            .values()
            .filter(|token| token.tenant_id == tenant_id)
            .cloned()
            .collect())
    }

    async fn revoke_api_token(
        &self,
        tenant_id: TenantId,
        token_id: TokenId,
    ) -> Result<(), ApplicationError> {
        let mut data = self.data.write().await;
        if matches!(data.tokens.get(&token_id.into_inner()), Some(token) if token.tenant_id == tenant_id)
        {
            data.tokens.remove(&token_id.into_inner());
        }
        Ok(())
    }

    async fn save_project(&self, project: Project) -> Result<(), ApplicationError> {
        self.data
            .write()
            .await
            .projects
            .insert(project.id.into_inner(), project);
        Ok(())
    }

    async fn list_projects(&self, tenant_id: TenantId) -> Result<Vec<Project>, ApplicationError> {
        let data = self.data.read().await;
        Ok(data
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
        let data = self.data.read().await;
        let query = query.trim().to_ascii_lowercase();
        let tenant_slug = data
            .tenants
            .values()
            .find(|tenant| tenant.id == tenant_id)
            .map(|tenant| tenant.slug.as_str().to_string())
            .unwrap_or_default();

        let mut hits = Vec::new();
        for project in data
            .projects
            .values()
            .filter(|project| project.tenant_id == tenant_id)
        {
            let haystack = format!(
                "{} {}",
                project.name.normalized(),
                project.summary.to_ascii_lowercase()
            );
            if !query.is_empty() && !haystack.contains(&query) {
                continue;
            }

            hits.push(SearchHit {
                tenant_slug: tenant_slug.clone(),
                project_name: project.name.original().to_string(),
                normalized_name: project.name.normalized().to_string(),
                summary: project.summary.clone(),
                source: format!("{:?}", project.source).to_ascii_lowercase(),
                latest_version: data
                    .releases
                    .values()
                    .filter(|release| release.project_id == project.id)
                    .map(|release| release.version.clone())
                    .max()
                    .map(|version| version.as_str().to_string()),
            });
        }
        hits.sort_by(|left, right| left.project_name.cmp(&right.project_name));
        Ok(hits)
    }

    async fn get_project_by_normalized_name(
        &self,
        tenant_id: TenantId,
        normalized_name: &str,
    ) -> Result<Option<Project>, ApplicationError> {
        let data = self.data.read().await;
        Ok(data
            .projects
            .values()
            .find(|project| {
                project.tenant_id == tenant_id && project.name.normalized() == normalized_name
            })
            .cloned())
    }

    async fn save_release(&self, release: Release) -> Result<(), ApplicationError> {
        self.data
            .write()
            .await
            .releases
            .insert(release.id.into_inner(), release);
        Ok(())
    }

    async fn list_releases(&self, project_id: ProjectId) -> Result<Vec<Release>, ApplicationError> {
        let data = self.data.read().await;
        Ok(data
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
        let data = self.data.read().await;
        Ok(data
            .releases
            .values()
            .find(|release| release.project_id == project_id && release.version == *version)
            .cloned())
    }

    async fn delete_release(&self, release_id: ReleaseId) -> Result<(), ApplicationError> {
        self.data
            .write()
            .await
            .releases
            .remove(&release_id.into_inner());
        Ok(())
    }

    async fn save_artifact(&self, artifact: Artifact) -> Result<(), ApplicationError> {
        self.data
            .write()
            .await
            .artifacts
            .insert(artifact.id.into_inner(), artifact);
        Ok(())
    }

    async fn list_artifacts(
        &self,
        release_id: ReleaseId,
    ) -> Result<Vec<Artifact>, ApplicationError> {
        let data = self.data.read().await;
        Ok(data
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
        let data = self.data.read().await;
        Ok(data
            .artifacts
            .values()
            .find(|artifact| artifact.release_id == release_id && artifact.filename == filename)
            .cloned())
    }

    async fn delete_artifact(&self, artifact_id: ArtifactId) -> Result<(), ApplicationError> {
        let mut data = self.data.write().await;
        data.artifacts.remove(&artifact_id.into_inner());
        data.attestations.remove(&artifact_id.into_inner());
        Ok(())
    }

    async fn save_attestation(
        &self,
        attestation: AttestationBundle,
    ) -> Result<(), ApplicationError> {
        self.data
            .write()
            .await
            .attestations
            .insert(attestation.artifact_id.into_inner(), attestation);
        Ok(())
    }

    async fn get_attestation_by_artifact(
        &self,
        artifact_id: ArtifactId,
    ) -> Result<Option<AttestationBundle>, ApplicationError> {
        Ok(self
            .data
            .read()
            .await
            .attestations
            .get(&artifact_id.into_inner())
            .cloned())
    }

    async fn save_trusted_publisher(
        &self,
        publisher: TrustedPublisher,
    ) -> Result<(), ApplicationError> {
        self.data
            .write()
            .await
            .trusted_publishers
            .insert(publisher.id.into_inner(), publisher);
        Ok(())
    }

    async fn list_trusted_publishers(
        &self,
        tenant_id: TenantId,
        normalized_project_name: &str,
    ) -> Result<Vec<TrustedPublisher>, ApplicationError> {
        let data = self.data.read().await;
        Ok(data
            .trusted_publishers
            .values()
            .filter(|publisher| {
                publisher.tenant_id == tenant_id
                    && (normalized_project_name.is_empty()
                        || publisher.project_name.normalized() == normalized_project_name)
            })
            .cloned()
            .collect())
    }

    async fn delete_project(&self, project_id: ProjectId) -> Result<(), ApplicationError> {
        self.data
            .write()
            .await
            .projects
            .remove(&project_id.into_inner());
        Ok(())
    }

    async fn save_audit_event(&self, event: AuditEvent) -> Result<(), ApplicationError> {
        self.data
            .write()
            .await
            .audit_events
            .insert(event.id.into_inner(), event);
        Ok(())
    }

    async fn list_audit_events(
        &self,
        tenant_slug: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AuditEvent>, ApplicationError> {
        let data = self.data.read().await;
        let mut events = data
            .audit_events
            .values()
            .filter(|event| {
                tenant_slug
                    .map(|tenant_slug| event.tenant_slug.as_deref() == Some(tenant_slug))
                    .unwrap_or(true)
            })
            .cloned()
            .collect::<Vec<_>>();
        events.sort_by(|left, right| {
            right
                .occurred_at
                .cmp(&left.occurred_at)
                .then(right.id.cmp(&left.id))
        });
        events.truncate(limit);
        Ok(events)
    }
}
