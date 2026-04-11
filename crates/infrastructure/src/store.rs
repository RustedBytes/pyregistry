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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use pyregistry_application::RegistryStore;
    use pyregistry_domain::{
        AdminUserId, AttestationSource, AuditEventId, DigestSet, MirrorRule, ProjectName,
        TenantSlug, TokenScope, TrustedPublisherId, TrustedPublisherProvider,
    };
    use std::collections::BTreeMap;

    fn now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 4, 11, 12, 0, 0)
            .single()
            .expect("timestamp")
    }

    #[tokio::test]
    async fn in_memory_store_round_trips_registry_state() {
        let store = InMemoryRegistryStore::default();
        let tenant = Tenant::new(
            TenantId::new(Uuid::from_u128(1)),
            TenantSlug::new("acme").expect("slug"),
            "Acme",
            MirrorRule { enabled: true },
            now(),
        )
        .expect("tenant");
        store.save_tenant(tenant.clone()).await.expect("tenant");

        let admin = AdminUser {
            id: AdminUserId::new(Uuid::from_u128(2)),
            tenant_id: Some(tenant.id),
            email: "admin@acme.test".into(),
            password_hash: "hash".into(),
            is_superadmin: false,
            created_at: now(),
        };
        store.save_admin_user(admin.clone()).await.expect("admin");

        let token = ApiToken {
            id: TokenId::new(Uuid::from_u128(3)),
            tenant_id: tenant.id,
            label: "read".into(),
            secret_hash: "secret-hash".into(),
            scopes: vec![TokenScope::Read],
            publish_identity: None,
            created_at: now(),
            expires_at: None,
        };
        store.save_api_token(token.clone()).await.expect("token");

        let project = Project::new(
            ProjectId::new(Uuid::from_u128(4)),
            tenant.id,
            ProjectName::new("Demo_Pkg").expect("project"),
            ProjectSource::Local,
            "Demo summary",
            "Demo description",
            now(),
        );
        store.save_project(project.clone()).await.expect("project");
        let release = Release {
            id: ReleaseId::new(Uuid::from_u128(5)),
            project_id: project.id,
            version: ReleaseVersion::new("1.0.0").expect("version"),
            yanked: None,
            created_at: now(),
        };
        store.save_release(release.clone()).await.expect("release");
        let artifact = Artifact::new(
            ArtifactId::new(Uuid::from_u128(6)),
            release.id,
            "demo-pkg-1.0.0-py3-none-any.whl",
            11,
            DigestSet::new("a".repeat(64), None).expect("digest"),
            "objects/demo.whl",
            now(),
        )
        .expect("artifact");
        store
            .save_artifact(artifact.clone())
            .await
            .expect("artifact");
        let attestation = AttestationBundle {
            artifact_id: artifact.id,
            media_type: "application/json".into(),
            payload: "{}".into(),
            source: AttestationSource::TrustedPublish,
            recorded_at: now(),
        };
        store
            .save_attestation(attestation.clone())
            .await
            .expect("attestation");
        let publisher = TrustedPublisher {
            id: TrustedPublisherId::new(Uuid::from_u128(7)),
            tenant_id: tenant.id,
            project_name: project.name.clone(),
            provider: TrustedPublisherProvider::GitHubActions,
            issuer: "https://issuer.example".into(),
            audience: "pyregistry".into(),
            claim_rules: BTreeMap::from([("repository".into(), "acme/demo".into())]),
            created_at: now(),
        };
        store
            .save_trusted_publisher(publisher.clone())
            .await
            .expect("publisher");
        let event = AuditEvent::new(
            AuditEventId::new(Uuid::from_u128(8)),
            now(),
            "admin@acme.test",
            "artifact.upload",
            Some("acme".into()),
            Some("demo-pkg".into()),
            BTreeMap::from([("filename".into(), artifact.filename.clone())]),
        )
        .expect("event");
        store.save_audit_event(event.clone()).await.expect("event");

        assert_eq!(
            store
                .registry_overview()
                .await
                .expect("overview")
                .artifact_count,
            1
        );
        assert_eq!(
            store.list_tenants().await.expect("tenants"),
            vec![tenant.clone()]
        );
        assert_eq!(
            store
                .get_tenant_by_slug("acme")
                .await
                .expect("tenant lookup"),
            Some(tenant.clone())
        );
        assert_eq!(
            store
                .get_admin_user_by_email("admin@acme.test")
                .await
                .expect("admin lookup"),
            Some(admin)
        );
        assert_eq!(
            store.list_api_tokens(tenant.id).await.expect("tokens"),
            vec![token.clone()]
        );
        assert_eq!(
            store
                .get_project_by_normalized_name(tenant.id, "demo-pkg")
                .await
                .expect("project lookup"),
            Some(project.clone())
        );
        assert_eq!(
            store
                .search_projects(tenant.id, "summary")
                .await
                .expect("search")[0]
                .latest_version,
            Some("1.0.0".into())
        );
        assert_eq!(
            store
                .list_release_artifacts(project.id)
                .await
                .expect("groups")[0]
                .artifacts[0]
                .filename,
            artifact.filename
        );
        assert_eq!(
            store
                .get_attestation_by_artifact(artifact.id)
                .await
                .expect("attestation lookup"),
            Some(attestation)
        );
        assert_eq!(
            store
                .list_trusted_publishers(tenant.id, "demo-pkg")
                .await
                .expect("publishers"),
            vec![publisher]
        );
        assert_eq!(
            store
                .list_audit_events(Some("acme"), 10)
                .await
                .expect("events"),
            vec![event]
        );

        store
            .revoke_api_token(tenant.id, token.id)
            .await
            .expect("revoke");
        assert!(
            store
                .list_api_tokens(tenant.id)
                .await
                .expect("tokens")
                .is_empty()
        );
        store
            .delete_artifact(artifact.id)
            .await
            .expect("delete artifact");
        assert!(
            store
                .get_attestation_by_artifact(artifact.id)
                .await
                .expect("attestation lookup")
                .is_none()
        );
        store
            .delete_release(release.id)
            .await
            .expect("delete release");
        store
            .delete_project(project.id)
            .await
            .expect("delete project");
        assert!(
            store
                .list_projects(tenant.id)
                .await
                .expect("projects")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn in_memory_store_sorts_filters_and_keeps_unmatched_tokens() {
        let store = InMemoryRegistryStore::default();
        let acme = Tenant::new(
            TenantId::new(Uuid::from_u128(11)),
            TenantSlug::new("acme").expect("slug"),
            "Acme",
            MirrorRule { enabled: true },
            now(),
        )
        .expect("tenant");
        let beta = Tenant::new(
            TenantId::new(Uuid::from_u128(12)),
            TenantSlug::new("beta").expect("slug"),
            "Beta",
            MirrorRule { enabled: false },
            now(),
        )
        .expect("tenant");
        store.save_tenant(beta.clone()).await.expect("beta");
        store.save_tenant(acme.clone()).await.expect("acme");

        assert_eq!(
            store
                .list_tenants()
                .await
                .expect("tenants")
                .into_iter()
                .map(|tenant| tenant.slug.as_str().to_string())
                .collect::<Vec<_>>(),
            vec!["acme", "beta"]
        );

        let token = ApiToken {
            id: TokenId::new(Uuid::from_u128(13)),
            tenant_id: acme.id,
            label: "read".into(),
            secret_hash: "hash".into(),
            scopes: vec![TokenScope::Read],
            publish_identity: None,
            created_at: now(),
            expires_at: None,
        };
        store.save_api_token(token.clone()).await.expect("token");
        store
            .revoke_api_token(beta.id, token.id)
            .await
            .expect("wrong tenant revoke");
        assert_eq!(
            store.list_api_tokens(acme.id).await.expect("tokens"),
            vec![token]
        );

        let mirrored_project = Project::new(
            ProjectId::new(Uuid::from_u128(14)),
            acme.id,
            ProjectName::new("Alpha").expect("project"),
            ProjectSource::Mirrored,
            "shared summary",
            "",
            now(),
        );
        let local_project = Project::new(
            ProjectId::new(Uuid::from_u128(15)),
            acme.id,
            ProjectName::new("Zulu").expect("project"),
            ProjectSource::Local,
            "other summary",
            "",
            now(),
        );
        let other_tenant_project = Project::new(
            ProjectId::new(Uuid::from_u128(16)),
            beta.id,
            ProjectName::new("Hidden").expect("project"),
            ProjectSource::Local,
            "shared summary",
            "",
            now(),
        );
        store
            .save_project(local_project.clone())
            .await
            .expect("local");
        store
            .save_project(mirrored_project.clone())
            .await
            .expect("mirrored");
        store
            .save_project(other_tenant_project)
            .await
            .expect("other");

        assert_eq!(
            store
                .registry_overview()
                .await
                .expect("overview")
                .mirrored_project_count,
            1
        );
        assert_eq!(
            store.list_projects(acme.id).await.expect("projects").len(),
            2
        );

        let release_019 = Release {
            id: ReleaseId::new(Uuid::from_u128(17)),
            project_id: mirrored_project.id,
            version: ReleaseVersion::new("0.1.9").expect("version"),
            yanked: None,
            created_at: now(),
        };
        let release_0114 = Release {
            id: ReleaseId::new(Uuid::from_u128(18)),
            project_id: mirrored_project.id,
            version: ReleaseVersion::new("0.1.14").expect("version"),
            yanked: None,
            created_at: now(),
        };
        store.save_release(release_019).await.expect("old release");
        store.save_release(release_0114).await.expect("new release");

        let hits = store
            .search_projects(acme.id, "")
            .await
            .expect("all search hits");
        assert_eq!(
            hits.iter()
                .map(|hit| hit.project_name.as_str())
                .collect::<Vec<_>>(),
            vec!["Alpha", "Zulu"]
        );
        assert_eq!(hits[0].latest_version.as_deref(), Some("0.1.14"));
        assert!(
            store
                .search_projects(acme.id, "missing")
                .await
                .expect("empty search")
                .is_empty()
        );

        let first_event = AuditEvent::new(
            AuditEventId::new(Uuid::from_u128(19)),
            now(),
            "admin@example.test",
            "first",
            Some("acme".into()),
            None,
            BTreeMap::new(),
        )
        .expect("event");
        let second_event = AuditEvent::new(
            AuditEventId::new(Uuid::from_u128(20)),
            now(),
            "admin@example.test",
            "second",
            Some("acme".into()),
            None,
            BTreeMap::new(),
        )
        .expect("event");
        store
            .save_audit_event(first_event)
            .await
            .expect("first event");
        store
            .save_audit_event(second_event)
            .await
            .expect("second event");

        let events = store
            .list_audit_events(None, 1)
            .await
            .expect("limited events");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "second");
    }
}
