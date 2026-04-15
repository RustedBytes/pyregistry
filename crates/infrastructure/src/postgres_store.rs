use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pyregistry_application::{
    ApplicationError, RecentActivity, RegistryOverview, RegistryStore, ReleaseArtifacts, SearchHit,
    TenantDashboardStats,
};
use pyregistry_domain::{
    AdminUser, AdminUserId, ApiToken, Artifact, ArtifactId, ArtifactKind, AttestationBundle,
    AttestationSource, AuditEvent, AuditEventId, DigestSet, MirrorRule, Project, ProjectId,
    ProjectName, ProjectSource, PublishIdentity, Release, ReleaseId, ReleaseVersion, Tenant,
    TenantId, TenantSlug, TokenId, TokenScope, TrustedPublisher, TrustedPublisherId,
    TrustedPublisherProvider, YankState,
};
use std::collections::BTreeMap;
use std::time::Duration;
use tokio_postgres::{Client, NoTls, Row};
use uuid::Uuid;

use crate::PostgresConfig;

const POSTGRES_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    mirroring_enabled BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_users (
    id UUID PRIMARY KEY,
    tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_superadmin BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    label TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    scopes_json TEXT NOT NULL,
    identity_issuer TEXT,
    identity_subject TEXT,
    identity_audience TEXT,
    identity_provider TEXT,
    identity_claims_json TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS projects (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    original_name TEXT NOT NULL,
    normalized_name TEXT NOT NULL,
    source TEXT NOT NULL,
    summary TEXT NOT NULL,
    description TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE(tenant_id, normalized_name)
);

CREATE TABLE IF NOT EXISTS releases (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    version TEXT NOT NULL,
    yanked_reason TEXT,
    yanked_changed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE(project_id, version)
);

CREATE TABLE IF NOT EXISTS artifacts (
    id UUID PRIMARY KEY,
    release_id UUID NOT NULL REFERENCES releases(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    kind TEXT NOT NULL,
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    sha256 TEXT NOT NULL,
    blake2b_256 TEXT,
    object_key TEXT NOT NULL,
    upstream_url TEXT,
    provenance_key TEXT,
    yanked_reason TEXT,
    yanked_changed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE(release_id, filename)
);

CREATE TABLE IF NOT EXISTS attestations (
    artifact_id UUID PRIMARY KEY REFERENCES artifacts(id) ON DELETE CASCADE,
    media_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    source TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS trusted_publishers (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_original_name TEXT NOT NULL,
    project_normalized_name TEXT NOT NULL,
    provider TEXT NOT NULL,
    issuer TEXT NOT NULL,
    audience TEXT NOT NULL,
    claim_rules_json TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    tenant_slug TEXT,
    target TEXT,
    metadata_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_api_tokens_tenant ON api_tokens(tenant_id);
CREATE INDEX IF NOT EXISTS idx_api_tokens_tenant_created
    ON api_tokens(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_projects_tenant ON projects(tenant_id);
CREATE INDEX IF NOT EXISTS idx_projects_tenant_search ON projects(tenant_id, normalized_name);
CREATE INDEX IF NOT EXISTS idx_projects_tenant_normalized_prefix
    ON projects(tenant_id, normalized_name text_pattern_ops);
CREATE INDEX IF NOT EXISTS idx_projects_tenant_updated
    ON projects(tenant_id, updated_at DESC, normalized_name);
CREATE INDEX IF NOT EXISTS idx_releases_project ON releases(project_id);
CREATE INDEX IF NOT EXISTS idx_releases_project_created
    ON releases(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_artifacts_release ON artifacts(release_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_release_filename
    ON artifacts(release_id, filename);
CREATE INDEX IF NOT EXISTS idx_trusted_publishers_tenant_project
    ON trusted_publishers(tenant_id, project_normalized_name);
CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_time
    ON audit_events(tenant_slug, occurred_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_time
    ON audit_events(occurred_at);
"#;

pub struct PostgresRegistryStore {
    client: Client,
}

impl PostgresRegistryStore {
    pub async fn connect(config: &PostgresConfig) -> Result<Self, ApplicationError> {
        let connect = tokio_postgres::connect(&config.connection_url, NoTls);
        let (client, connection) =
            tokio::time::timeout(Duration::from_secs(config.acquire_timeout_seconds), connect)
                .await
                .map_err(|_| {
                    ApplicationError::External(format!(
                        "postgres metadata store connection timed out after {}s",
                        config.acquire_timeout_seconds
                    ))
                })?
                .map_err(postgres_error)?;
        if config.max_connections > 1 || config.min_connections > 1 {
            log::debug!(
                "postgres metadata adapter uses tokio-postgres connection pipelining; configured pool bounds are min={}, max={}",
                config.min_connections,
                config.max_connections
            );
        }
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                log::error!("postgres metadata connection task failed: {error}");
            }
        });
        migrate(&client).await?;
        Ok(Self { client })
    }
}

#[async_trait]
impl RegistryStore for PostgresRegistryStore {
    async fn registry_overview(&self) -> Result<RegistryOverview, ApplicationError> {
        let row = self
            .client
            .query_one(
                r#"
                SELECT
                    (SELECT COUNT(*)::BIGINT FROM tenants) AS tenant_count,
                    (SELECT COUNT(*)::BIGINT FROM projects) AS project_count,
                    (SELECT COUNT(*)::BIGINT FROM releases) AS release_count,
                    (SELECT COUNT(*)::BIGINT FROM artifacts) AS artifact_count,
                    (SELECT COALESCE(SUM(size_bytes), 0)::BIGINT FROM artifacts) AS total_storage_bytes,
                    (SELECT COUNT(*)::BIGINT FROM projects WHERE source = 'mirrored') AS mirrored_project_count
                "#,
                &[],
            )
            .await
            .map_err(postgres_error)?;
        Ok(RegistryOverview {
            tenant_count: row
                .try_get::<_, i64>("tenant_count")
                .map_err(postgres_error)? as usize,
            project_count: row
                .try_get::<_, i64>("project_count")
                .map_err(postgres_error)? as usize,
            release_count: row
                .try_get::<_, i64>("release_count")
                .map_err(postgres_error)? as usize,
            artifact_count: row
                .try_get::<_, i64>("artifact_count")
                .map_err(postgres_error)? as usize,
            total_storage_bytes: row
                .try_get::<_, i64>("total_storage_bytes")
                .map_err(postgres_error)? as u64,
            mirrored_project_count: row
                .try_get::<_, i64>("mirrored_project_count")
                .map_err(postgres_error)? as usize,
        })
    }

    async fn save_tenant(&self, tenant: Tenant) -> Result<(), ApplicationError> {
        let id = tenant.id.into_inner();
        let slug = tenant.slug.as_str().to_string();
        self.client
            .execute(
                r#"
                INSERT INTO tenants (id, slug, display_name, mirroring_enabled, created_at)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (id) DO UPDATE SET
                    slug = excluded.slug,
                    display_name = excluded.display_name,
                    mirroring_enabled = excluded.mirroring_enabled,
                    created_at = excluded.created_at
                "#,
                &[
                    &id,
                    &slug,
                    &tenant.display_name,
                    &tenant.mirror_rule.enabled,
                    &tenant.created_at,
                ],
            )
            .await
            .map_err(postgres_error)?;
        Ok(())
    }

    async fn list_tenants(&self) -> Result<Vec<Tenant>, ApplicationError> {
        let rows = self
            .client
            .query(
                "SELECT id, slug, display_name, mirroring_enabled, created_at FROM tenants ORDER BY slug",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        rows.iter().map(map_tenant).collect()
    }

    async fn get_tenant_by_slug(&self, slug: &str) -> Result<Option<Tenant>, ApplicationError> {
        let row = self
            .client
            .query_opt(
                "SELECT id, slug, display_name, mirroring_enabled, created_at FROM tenants WHERE slug = $1",
                &[&slug],
            )
            .await
            .map_err(postgres_error)?;
        row.as_ref().map(map_tenant).transpose()
    }

    async fn tenant_dashboard_stats(
        &self,
        tenant: &Tenant,
    ) -> Result<TenantDashboardStats, ApplicationError> {
        let tenant_id = tenant.id.into_inner();
        let counts = self
            .client
            .query_one(
                r#"
                SELECT
                    (SELECT COUNT(*)::BIGINT FROM projects WHERE tenant_id = $1) AS project_count,
                    (
                        SELECT COUNT(*)::BIGINT
                        FROM releases r
                        INNER JOIN projects p ON p.id = r.project_id
                        WHERE p.tenant_id = $1
                    ) AS release_count,
                    (
                        SELECT COUNT(*)::BIGINT
                        FROM artifacts a
                        INNER JOIN releases r ON r.id = a.release_id
                        INNER JOIN projects p ON p.id = r.project_id
                        WHERE p.tenant_id = $1
                    ) AS artifact_count,
                    (SELECT COUNT(*)::BIGINT FROM api_tokens WHERE tenant_id = $1) AS token_count,
                    (SELECT COUNT(*)::BIGINT FROM trusted_publishers WHERE tenant_id = $1) AS trusted_publisher_count
                "#,
                &[&tenant_id],
            )
            .await
            .map_err(postgres_error)?;

        let rows = self
            .client
            .query(
                r#"
                SELECT original_name, source, updated_at
                FROM projects
                WHERE tenant_id = $1
                ORDER BY updated_at DESC, normalized_name
                LIMIT 6
                "#,
                &[&tenant_id],
            )
            .await
            .map_err(postgres_error)?;
        let mut recent_activity = Vec::with_capacity(rows.len());
        for row in rows {
            recent_activity.push(RecentActivity {
                project_name: row
                    .try_get::<_, String>("original_name")
                    .map_err(postgres_error)?,
                tenant_slug: tenant.slug.as_str().to_string(),
                source: row.try_get::<_, String>("source").map_err(postgres_error)?,
                updated_at: row
                    .try_get::<_, DateTime<Utc>>("updated_at")
                    .map_err(postgres_error)?,
            });
        }

        Ok(TenantDashboardStats {
            project_count: counts
                .try_get::<_, i64>("project_count")
                .map_err(postgres_error)? as usize,
            release_count: counts
                .try_get::<_, i64>("release_count")
                .map_err(postgres_error)? as usize,
            artifact_count: counts
                .try_get::<_, i64>("artifact_count")
                .map_err(postgres_error)? as usize,
            token_count: counts
                .try_get::<_, i64>("token_count")
                .map_err(postgres_error)? as usize,
            trusted_publisher_count: counts
                .try_get::<_, i64>("trusted_publisher_count")
                .map_err(postgres_error)? as usize,
            recent_activity,
        })
    }

    async fn save_admin_user(&self, user: AdminUser) -> Result<(), ApplicationError> {
        let id = user.id.into_inner();
        let tenant_id = user.tenant_id.map(|id| id.into_inner());
        self.client
            .execute(
                r#"
                INSERT INTO admin_users (id, tenant_id, email, password_hash, is_superadmin, created_at)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (email) DO UPDATE SET
                    id = excluded.id,
                    tenant_id = excluded.tenant_id,
                    password_hash = excluded.password_hash,
                    is_superadmin = excluded.is_superadmin,
                    created_at = excluded.created_at
                "#,
                &[
                    &id,
                    &tenant_id,
                    &user.email,
                    &user.password_hash,
                    &user.is_superadmin,
                    &user.created_at,
                ],
            )
            .await
            .map_err(postgres_error)?;
        Ok(())
    }

    async fn get_admin_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<AdminUser>, ApplicationError> {
        let row = self
            .client
            .query_opt(
                r#"
                SELECT id, tenant_id, email, password_hash, is_superadmin, created_at
                FROM admin_users
                WHERE email = $1
                "#,
                &[&email],
            )
            .await
            .map_err(postgres_error)?;
        row.as_ref().map(map_admin_user).transpose()
    }

    async fn save_api_token(&self, token: ApiToken) -> Result<(), ApplicationError> {
        let scopes_json = serde_json::to_string(
            &token
                .scopes
                .iter()
                .map(|scope| token_scope_str(scope).to_string())
                .collect::<Vec<_>>(),
        )
        .map_err(json_error)?;
        let (identity_issuer, identity_subject, identity_audience, identity_provider, claims_json) =
            match token.publish_identity {
                Some(identity) => (
                    Some(identity.issuer),
                    Some(identity.subject),
                    Some(identity.audience),
                    Some(provider_str(&identity.provider).to_string()),
                    Some(serde_json::to_string(&identity.claims).map_err(json_error)?),
                ),
                None => (None, None, None, None, None),
            };
        let id = token.id.into_inner();
        let tenant_id = token.tenant_id.into_inner();
        self.client
            .execute(
                r#"
                INSERT INTO api_tokens (
                    id, tenant_id, label, secret_hash, scopes_json,
                    identity_issuer, identity_subject, identity_audience, identity_provider,
                    identity_claims_json, created_at, expires_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                ON CONFLICT (id) DO UPDATE SET
                    tenant_id = excluded.tenant_id,
                    label = excluded.label,
                    secret_hash = excluded.secret_hash,
                    scopes_json = excluded.scopes_json,
                    identity_issuer = excluded.identity_issuer,
                    identity_subject = excluded.identity_subject,
                    identity_audience = excluded.identity_audience,
                    identity_provider = excluded.identity_provider,
                    identity_claims_json = excluded.identity_claims_json,
                    created_at = excluded.created_at,
                    expires_at = excluded.expires_at
                "#,
                &[
                    &id,
                    &tenant_id,
                    &token.label,
                    &token.secret_hash,
                    &scopes_json,
                    &identity_issuer,
                    &identity_subject,
                    &identity_audience,
                    &identity_provider,
                    &claims_json,
                    &token.created_at,
                    &token.expires_at,
                ],
            )
            .await
            .map_err(postgres_error)?;
        Ok(())
    }

    async fn list_api_tokens(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<ApiToken>, ApplicationError> {
        let tenant_id = tenant_id.into_inner();
        let rows = self
            .client
            .query(
                r#"
                SELECT id, tenant_id, label, secret_hash, scopes_json,
                       identity_issuer, identity_subject, identity_audience, identity_provider,
                       identity_claims_json, created_at, expires_at
                FROM api_tokens
                WHERE tenant_id = $1
                ORDER BY created_at DESC, label
                "#,
                &[&tenant_id],
            )
            .await
            .map_err(postgres_error)?;
        rows.iter().map(map_api_token).collect()
    }

    async fn revoke_api_token(
        &self,
        tenant_id: TenantId,
        token_id: TokenId,
    ) -> Result<(), ApplicationError> {
        let tenant_id = tenant_id.into_inner();
        let token_id = token_id.into_inner();
        self.client
            .execute(
                "DELETE FROM api_tokens WHERE id = $1 AND tenant_id = $2",
                &[&token_id, &tenant_id],
            )
            .await
            .map_err(postgres_error)?;
        Ok(())
    }

    async fn save_project(&self, project: Project) -> Result<(), ApplicationError> {
        let id = project.id.into_inner();
        let tenant_id = project.tenant_id.into_inner();
        let original_name = project.name.original().to_string();
        let normalized_name = project.name.normalized().to_string();
        let source = project_source_str(&project.source);
        self.client
            .execute(
                r#"
                INSERT INTO projects (
                    id, tenant_id, original_name, normalized_name, source,
                    summary, description, created_at, updated_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (id) DO UPDATE SET
                    tenant_id = excluded.tenant_id,
                    original_name = excluded.original_name,
                    normalized_name = excluded.normalized_name,
                    source = excluded.source,
                    summary = excluded.summary,
                    description = excluded.description,
                    created_at = excluded.created_at,
                    updated_at = excluded.updated_at
                "#,
                &[
                    &id,
                    &tenant_id,
                    &original_name,
                    &normalized_name,
                    &source,
                    &project.summary,
                    &project.description,
                    &project.created_at,
                    &project.updated_at,
                ],
            )
            .await
            .map_err(postgres_error)?;
        Ok(())
    }

    async fn list_projects(&self, tenant_id: TenantId) -> Result<Vec<Project>, ApplicationError> {
        let tenant_id = tenant_id.into_inner();
        let rows = self
            .client
            .query(
                r#"
                SELECT id, tenant_id, original_name, source, summary, description, created_at, updated_at
                FROM projects
                WHERE tenant_id = $1
                ORDER BY normalized_name
                "#,
                &[&tenant_id],
            )
            .await
            .map_err(postgres_error)?;
        rows.iter().map(map_project).collect()
    }

    async fn search_projects(
        &self,
        tenant_id: TenantId,
        query: &str,
    ) -> Result<Vec<SearchHit>, ApplicationError> {
        let tenant_id = tenant_id.into_inner();
        let query = query.trim().to_ascii_lowercase();
        let contains_pattern = format!("%{}%", escape_like_pattern(&query));
        let prefix_pattern = format!("{}%", escape_like_pattern(&query));

        let rows = self
            .client
            .query(
                r#"
                SELECT t.slug AS tenant_slug, p.original_name, p.normalized_name, p.source, p.summary,
                       COALESCE(
                           ARRAY_AGG(r.version) FILTER (WHERE r.version IS NOT NULL),
                           ARRAY[]::TEXT[]
                       ) AS release_versions
                FROM projects p
                INNER JOIN tenants t ON t.id = p.tenant_id
                LEFT JOIN releases r ON r.project_id = p.id
                WHERE p.tenant_id = $1
                  AND (
                      $2 = ''
                      OR p.normalized_name LIKE $3 ESCAPE '\'
                      OR lower(p.summary) LIKE $3 ESCAPE '\'
                  )
                GROUP BY t.slug, p.id, p.original_name, p.normalized_name, p.source, p.summary
                ORDER BY
                    CASE
                        WHEN p.normalized_name = $2 THEN 0
                        WHEN p.normalized_name LIKE $4 ESCAPE '\' THEN 1
                        WHEN lower(p.summary) LIKE $4 ESCAPE '\' THEN 2
                        ELSE 3
                    END,
                    p.normalized_name
                "#,
                &[&tenant_id, &query, &contains_pattern, &prefix_pattern],
            )
            .await
            .map_err(postgres_error)?;

        let mut hits = Vec::new();
        for row in rows {
            let release_versions = row
                .try_get::<_, Vec<String>>("release_versions")
                .map_err(postgres_error)?;
            hits.push(SearchHit {
                tenant_slug: row
                    .try_get::<_, String>("tenant_slug")
                    .map_err(postgres_error)?,
                project_name: row
                    .try_get::<_, String>("original_name")
                    .map_err(postgres_error)?,
                normalized_name: row
                    .try_get::<_, String>("normalized_name")
                    .map_err(postgres_error)?,
                source: row.try_get::<_, String>("source").map_err(postgres_error)?,
                summary: row
                    .try_get::<_, String>("summary")
                    .map_err(postgres_error)?,
                latest_version: latest_release_version_from_values(release_versions)?,
            });
        }
        Ok(hits)
    }

    async fn get_project_by_normalized_name(
        &self,
        tenant_id: TenantId,
        normalized_name: &str,
    ) -> Result<Option<Project>, ApplicationError> {
        let tenant_id = tenant_id.into_inner();
        let row = self
            .client
            .query_opt(
                r#"
                SELECT id, tenant_id, original_name, source, summary, description, created_at, updated_at
                FROM projects
                WHERE tenant_id = $1 AND normalized_name = $2
                "#,
                &[&tenant_id, &normalized_name],
            )
            .await
            .map_err(postgres_error)?;
        row.as_ref().map(map_project).transpose()
    }

    async fn save_release(&self, release: Release) -> Result<(), ApplicationError> {
        let (reason, changed_at) = yank_columns(&release.yanked);
        let id = release.id.into_inner();
        let project_id = release.project_id.into_inner();
        let version = release.version.as_str().to_string();
        self.client
            .execute(
                r#"
                INSERT INTO releases (id, project_id, version, yanked_reason, yanked_changed_at, created_at)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (id) DO UPDATE SET
                    project_id = excluded.project_id,
                    version = excluded.version,
                    yanked_reason = excluded.yanked_reason,
                    yanked_changed_at = excluded.yanked_changed_at,
                    created_at = excluded.created_at
                "#,
                &[
                    &id,
                    &project_id,
                    &version,
                    &reason,
                    &changed_at,
                    &release.created_at,
                ],
            )
            .await
            .map_err(postgres_error)?;
        Ok(())
    }

    async fn list_releases(&self, project_id: ProjectId) -> Result<Vec<Release>, ApplicationError> {
        let project_id = project_id.into_inner();
        let rows = self
            .client
            .query(
                r#"
                SELECT id, project_id, version, yanked_reason, yanked_changed_at, created_at
                FROM releases
                WHERE project_id = $1
                ORDER BY created_at DESC, version DESC
                "#,
                &[&project_id],
            )
            .await
            .map_err(postgres_error)?;
        rows.iter().map(map_release).collect()
    }

    async fn get_release_by_version(
        &self,
        project_id: ProjectId,
        version: &ReleaseVersion,
    ) -> Result<Option<Release>, ApplicationError> {
        let project_id = project_id.into_inner();
        let version = version.as_str().to_string();
        let row = self
            .client
            .query_opt(
                r#"
                SELECT id, project_id, version, yanked_reason, yanked_changed_at, created_at
                FROM releases
                WHERE project_id = $1 AND version = $2
                "#,
                &[&project_id, &version],
            )
            .await
            .map_err(postgres_error)?;
        row.as_ref().map(map_release).transpose()
    }

    async fn delete_release(&self, release_id: ReleaseId) -> Result<(), ApplicationError> {
        let release_id = release_id.into_inner();
        self.client
            .execute("DELETE FROM releases WHERE id = $1", &[&release_id])
            .await
            .map_err(postgres_error)?;
        Ok(())
    }

    async fn save_artifact(&self, artifact: Artifact) -> Result<(), ApplicationError> {
        let size_bytes = i64::try_from(artifact.size_bytes).map_err(|error| {
            ApplicationError::External(format!(
                "artifact `{}` is too large to store in postgres metadata: {error}",
                artifact.filename
            ))
        })?;
        let (reason, changed_at) = yank_columns(&artifact.yanked);
        let id = artifact.id.into_inner();
        let release_id = artifact.release_id.into_inner();
        let kind = artifact_kind_str(&artifact.kind);
        self.client
            .execute(
                r#"
                INSERT INTO artifacts (
                    id, release_id, filename, kind, size_bytes, sha256, blake2b_256,
                    object_key, upstream_url, provenance_key, yanked_reason, yanked_changed_at,
                    created_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                ON CONFLICT (id) DO UPDATE SET
                    release_id = excluded.release_id,
                    filename = excluded.filename,
                    kind = excluded.kind,
                    size_bytes = excluded.size_bytes,
                    sha256 = excluded.sha256,
                    blake2b_256 = excluded.blake2b_256,
                    object_key = excluded.object_key,
                    upstream_url = excluded.upstream_url,
                    provenance_key = excluded.provenance_key,
                    yanked_reason = excluded.yanked_reason,
                    yanked_changed_at = excluded.yanked_changed_at,
                    created_at = excluded.created_at
                "#,
                &[
                    &id,
                    &release_id,
                    &artifact.filename,
                    &kind,
                    &size_bytes,
                    &artifact.digests.sha256,
                    &artifact.digests.blake2b_256,
                    &artifact.object_key,
                    &artifact.upstream_url,
                    &artifact.provenance_key,
                    &reason,
                    &changed_at,
                    &artifact.created_at,
                ],
            )
            .await
            .map_err(postgres_error)?;
        Ok(())
    }

    async fn list_artifacts(
        &self,
        release_id: ReleaseId,
    ) -> Result<Vec<Artifact>, ApplicationError> {
        let release_id = release_id.into_inner();
        let rows = self
            .client
            .query(
                r#"
                SELECT id, release_id, filename, kind, size_bytes, sha256, blake2b_256,
                       object_key, upstream_url, provenance_key, yanked_reason, yanked_changed_at,
                       created_at
                FROM artifacts
                WHERE release_id = $1
                ORDER BY filename
                "#,
                &[&release_id],
            )
            .await
            .map_err(postgres_error)?;
        rows.iter().map(map_artifact).collect()
    }

    async fn list_release_artifacts(
        &self,
        project_id: ProjectId,
    ) -> Result<Vec<ReleaseArtifacts>, ApplicationError> {
        let project_id = project_id.into_inner();
        let rows = self
            .client
            .query(
                r#"
                SELECT r.id AS release_id, r.project_id AS release_project_id,
                       r.version AS release_version, r.yanked_reason AS release_yanked_reason,
                       r.yanked_changed_at AS release_yanked_changed_at,
                       r.created_at AS release_created_at,
                       a.id AS artifact_id, a.release_id AS artifact_release_id,
                       a.filename AS artifact_filename, a.kind AS artifact_kind,
                       a.size_bytes AS artifact_size_bytes, a.sha256 AS artifact_sha256,
                       a.blake2b_256 AS artifact_blake2b_256,
                       a.object_key AS artifact_object_key,
                       a.upstream_url AS artifact_upstream_url,
                       a.provenance_key AS artifact_provenance_key,
                       a.yanked_reason AS artifact_yanked_reason,
                       a.yanked_changed_at AS artifact_yanked_changed_at,
                       a.created_at AS artifact_created_at
                FROM releases r
                LEFT JOIN artifacts a ON a.release_id = r.id
                WHERE r.project_id = $1
                ORDER BY r.created_at DESC, r.version DESC, a.filename
                "#,
                &[&project_id],
            )
            .await
            .map_err(postgres_error)?;

        let mut grouped = Vec::<ReleaseArtifacts>::new();
        let mut release_positions = BTreeMap::<Uuid, usize>::new();
        for row in rows {
            let release = map_release_alias(&row)?;
            let release_id = release.id.into_inner();
            let artifact_id = row
                .try_get::<_, Option<Uuid>>("artifact_id")
                .map_err(postgres_error)?;
            let artifact = if artifact_id.is_some() {
                Some(map_artifact_alias(&row)?)
            } else {
                None
            };

            let index = match release_positions.get(&release_id) {
                Some(index) => *index,
                None => {
                    grouped.push(ReleaseArtifacts {
                        release,
                        artifacts: Vec::new(),
                    });
                    let index = grouped.len() - 1;
                    release_positions.insert(release_id, index);
                    index
                }
            };
            if let Some(artifact) = artifact {
                grouped[index].artifacts.push(artifact);
            }
        }

        Ok(grouped)
    }

    async fn get_artifact_by_filename(
        &self,
        release_id: ReleaseId,
        filename: &str,
    ) -> Result<Option<Artifact>, ApplicationError> {
        let release_id = release_id.into_inner();
        let row = self
            .client
            .query_opt(
                r#"
                SELECT id, release_id, filename, kind, size_bytes, sha256, blake2b_256,
                       object_key, upstream_url, provenance_key, yanked_reason, yanked_changed_at,
                       created_at
                FROM artifacts
                WHERE release_id = $1 AND filename = $2
                "#,
                &[&release_id, &filename],
            )
            .await
            .map_err(postgres_error)?;
        row.as_ref().map(map_artifact).transpose()
    }

    async fn delete_artifact(&self, artifact_id: ArtifactId) -> Result<(), ApplicationError> {
        let artifact_id = artifact_id.into_inner();
        self.client
            .execute("DELETE FROM artifacts WHERE id = $1", &[&artifact_id])
            .await
            .map_err(postgres_error)?;
        Ok(())
    }

    async fn save_attestation(
        &self,
        attestation: AttestationBundle,
    ) -> Result<(), ApplicationError> {
        let artifact_id = attestation.artifact_id.into_inner();
        let source = attestation_source_str(&attestation.source);
        self.client
            .execute(
                r#"
                INSERT INTO attestations (artifact_id, media_type, payload, source, recorded_at)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (artifact_id) DO UPDATE SET
                    media_type = excluded.media_type,
                    payload = excluded.payload,
                    source = excluded.source,
                    recorded_at = excluded.recorded_at
                "#,
                &[
                    &artifact_id,
                    &attestation.media_type,
                    &attestation.payload,
                    &source,
                    &attestation.recorded_at,
                ],
            )
            .await
            .map_err(postgres_error)?;
        Ok(())
    }

    async fn get_attestation_by_artifact(
        &self,
        artifact_id: ArtifactId,
    ) -> Result<Option<AttestationBundle>, ApplicationError> {
        let artifact_id = artifact_id.into_inner();
        let row = self
            .client
            .query_opt(
                r#"
                SELECT artifact_id, media_type, payload, source, recorded_at
                FROM attestations
                WHERE artifact_id = $1
                "#,
                &[&artifact_id],
            )
            .await
            .map_err(postgres_error)?;
        row.as_ref().map(map_attestation).transpose()
    }

    async fn save_trusted_publisher(
        &self,
        publisher: TrustedPublisher,
    ) -> Result<(), ApplicationError> {
        let claim_rules_json = serde_json::to_string(&publisher.claim_rules).map_err(json_error)?;
        let id = publisher.id.into_inner();
        let tenant_id = publisher.tenant_id.into_inner();
        let original_name = publisher.project_name.original().to_string();
        let normalized_name = publisher.project_name.normalized().to_string();
        let provider = provider_str(&publisher.provider);
        self.client
            .execute(
                r#"
                INSERT INTO trusted_publishers (
                    id, tenant_id, project_original_name, project_normalized_name,
                    provider, issuer, audience, claim_rules_json, created_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (id) DO UPDATE SET
                    tenant_id = excluded.tenant_id,
                    project_original_name = excluded.project_original_name,
                    project_normalized_name = excluded.project_normalized_name,
                    provider = excluded.provider,
                    issuer = excluded.issuer,
                    audience = excluded.audience,
                    claim_rules_json = excluded.claim_rules_json,
                    created_at = excluded.created_at
                "#,
                &[
                    &id,
                    &tenant_id,
                    &original_name,
                    &normalized_name,
                    &provider,
                    &publisher.issuer,
                    &publisher.audience,
                    &claim_rules_json,
                    &publisher.created_at,
                ],
            )
            .await
            .map_err(postgres_error)?;
        Ok(())
    }

    async fn list_trusted_publishers(
        &self,
        tenant_id: TenantId,
        normalized_project_name: &str,
    ) -> Result<Vec<TrustedPublisher>, ApplicationError> {
        let tenant_id = tenant_id.into_inner();
        let rows = self
            .client
            .query(
                r#"
                SELECT id, tenant_id, project_original_name, provider, issuer, audience,
                       claim_rules_json, created_at
                FROM trusted_publishers
                WHERE tenant_id = $1
                  AND ($2 = '' OR project_normalized_name = $2)
                ORDER BY created_at DESC
                "#,
                &[&tenant_id, &normalized_project_name],
            )
            .await
            .map_err(postgres_error)?;
        rows.iter().map(map_trusted_publisher).collect()
    }

    async fn delete_project(&self, project_id: ProjectId) -> Result<(), ApplicationError> {
        let project_id = project_id.into_inner();
        self.client
            .execute("DELETE FROM projects WHERE id = $1", &[&project_id])
            .await
            .map_err(postgres_error)?;
        Ok(())
    }

    async fn save_audit_event(&self, event: AuditEvent) -> Result<(), ApplicationError> {
        let metadata_json = serde_json::to_string(&event.metadata).map_err(json_error)?;
        let id = event.id.into_inner();
        self.client
            .execute(
                r#"
                INSERT INTO audit_events
                    (id, occurred_at, actor, action, tenant_slug, target, metadata_json)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                "#,
                &[
                    &id,
                    &event.occurred_at,
                    &event.actor,
                    &event.action,
                    &event.tenant_slug,
                    &event.target,
                    &metadata_json,
                ],
            )
            .await
            .map_err(postgres_error)?;
        Ok(())
    }

    async fn list_audit_events(
        &self,
        tenant_slug: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AuditEvent>, ApplicationError> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let rows = if let Some(tenant_slug) = tenant_slug {
            self.client
                .query(
                    r#"
                    SELECT id, occurred_at, actor, action, tenant_slug, target, metadata_json
                    FROM audit_events
                    WHERE tenant_slug = $1
                    ORDER BY occurred_at DESC, id DESC
                    LIMIT $2
                    "#,
                    &[&tenant_slug, &limit],
                )
                .await
                .map_err(postgres_error)?
        } else {
            self.client
                .query(
                    r#"
                    SELECT id, occurred_at, actor, action, tenant_slug, target, metadata_json
                    FROM audit_events
                    ORDER BY occurred_at DESC, id DESC
                    LIMIT $1
                    "#,
                    &[&limit],
                )
                .await
                .map_err(postgres_error)?
        };
        rows.iter().map(map_audit_event).collect()
    }
}

async fn migrate(client: &Client) -> Result<(), ApplicationError> {
    client
        .batch_execute(POSTGRES_SCHEMA)
        .await
        .map_err(postgres_error)
}

fn latest_release_version_from_values(
    release_versions: Vec<String>,
) -> Result<Option<String>, ApplicationError> {
    let versions = release_versions
        .into_iter()
        .map(ReleaseVersion::new)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(versions
        .into_iter()
        .max()
        .map(|version| version.as_str().to_string()))
}

fn escape_like_pattern(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' | '%' | '_' => {
                escaped.push('\\');
                escaped.push(character);
            }
            _ => escaped.push(character),
        }
    }
    escaped
}

fn map_tenant(row: &Row) -> Result<Tenant, ApplicationError> {
    Tenant::new(
        TenantId::new(row.try_get::<_, Uuid>("id").map_err(postgres_error)?),
        TenantSlug::new(row.try_get::<_, String>("slug").map_err(postgres_error)?)?,
        row.try_get::<_, String>("display_name")
            .map_err(postgres_error)?,
        MirrorRule {
            enabled: row
                .try_get::<_, bool>("mirroring_enabled")
                .map_err(postgres_error)?,
        },
        row.try_get::<_, DateTime<Utc>>("created_at")
            .map_err(postgres_error)?,
    )
    .map_err(ApplicationError::Domain)
}

fn map_admin_user(row: &Row) -> Result<AdminUser, ApplicationError> {
    Ok(AdminUser {
        id: AdminUserId::new(row.try_get::<_, Uuid>("id").map_err(postgres_error)?),
        tenant_id: row
            .try_get::<_, Option<Uuid>>("tenant_id")
            .map_err(postgres_error)?
            .map(TenantId::new),
        email: row.try_get::<_, String>("email").map_err(postgres_error)?,
        password_hash: row
            .try_get::<_, String>("password_hash")
            .map_err(postgres_error)?,
        is_superadmin: row
            .try_get::<_, bool>("is_superadmin")
            .map_err(postgres_error)?,
        created_at: row
            .try_get::<_, DateTime<Utc>>("created_at")
            .map_err(postgres_error)?,
    })
}

fn map_api_token(row: &Row) -> Result<ApiToken, ApplicationError> {
    Ok(ApiToken {
        id: TokenId::new(row.try_get::<_, Uuid>("id").map_err(postgres_error)?),
        tenant_id: TenantId::new(
            row.try_get::<_, Uuid>("tenant_id")
                .map_err(postgres_error)?,
        ),
        label: row.try_get::<_, String>("label").map_err(postgres_error)?,
        secret_hash: row
            .try_get::<_, String>("secret_hash")
            .map_err(postgres_error)?,
        scopes: parse_scopes_json(
            row.try_get::<_, String>("scopes_json")
                .map_err(postgres_error)?,
        )?,
        publish_identity: parse_publish_identity(
            row.try_get::<_, Option<String>>("identity_issuer")
                .map_err(postgres_error)?,
            row.try_get::<_, Option<String>>("identity_subject")
                .map_err(postgres_error)?,
            row.try_get::<_, Option<String>>("identity_audience")
                .map_err(postgres_error)?,
            row.try_get::<_, Option<String>>("identity_provider")
                .map_err(postgres_error)?,
            row.try_get::<_, Option<String>>("identity_claims_json")
                .map_err(postgres_error)?,
        )?,
        created_at: row
            .try_get::<_, DateTime<Utc>>("created_at")
            .map_err(postgres_error)?,
        expires_at: row
            .try_get::<_, Option<DateTime<Utc>>>("expires_at")
            .map_err(postgres_error)?,
    })
}

fn map_project(row: &Row) -> Result<Project, ApplicationError> {
    Ok(Project {
        id: ProjectId::new(row.try_get::<_, Uuid>("id").map_err(postgres_error)?),
        tenant_id: TenantId::new(
            row.try_get::<_, Uuid>("tenant_id")
                .map_err(postgres_error)?,
        ),
        name: ProjectName::new(
            row.try_get::<_, String>("original_name")
                .map_err(postgres_error)?,
        )?,
        source: parse_project_source(row.try_get::<_, String>("source").map_err(postgres_error)?)?,
        summary: row
            .try_get::<_, String>("summary")
            .map_err(postgres_error)?,
        description: row
            .try_get::<_, String>("description")
            .map_err(postgres_error)?,
        created_at: row
            .try_get::<_, DateTime<Utc>>("created_at")
            .map_err(postgres_error)?,
        updated_at: row
            .try_get::<_, DateTime<Utc>>("updated_at")
            .map_err(postgres_error)?,
    })
}

fn map_release(row: &Row) -> Result<Release, ApplicationError> {
    Ok(Release {
        id: ReleaseId::new(row.try_get::<_, Uuid>("id").map_err(postgres_error)?),
        project_id: ProjectId::new(
            row.try_get::<_, Uuid>("project_id")
                .map_err(postgres_error)?,
        ),
        version: ReleaseVersion::new(
            row.try_get::<_, String>("version")
                .map_err(postgres_error)?,
        )?,
        yanked: parse_yank(
            row.try_get::<_, Option<String>>("yanked_reason")
                .map_err(postgres_error)?,
            row.try_get::<_, Option<DateTime<Utc>>>("yanked_changed_at")
                .map_err(postgres_error)?,
        ),
        created_at: row
            .try_get::<_, DateTime<Utc>>("created_at")
            .map_err(postgres_error)?,
    })
}

fn map_release_alias(row: &Row) -> Result<Release, ApplicationError> {
    Ok(Release {
        id: ReleaseId::new(
            row.try_get::<_, Uuid>("release_id")
                .map_err(postgres_error)?,
        ),
        project_id: ProjectId::new(
            row.try_get::<_, Uuid>("release_project_id")
                .map_err(postgres_error)?,
        ),
        version: ReleaseVersion::new(
            row.try_get::<_, String>("release_version")
                .map_err(postgres_error)?,
        )?,
        yanked: parse_yank(
            row.try_get::<_, Option<String>>("release_yanked_reason")
                .map_err(postgres_error)?,
            row.try_get::<_, Option<DateTime<Utc>>>("release_yanked_changed_at")
                .map_err(postgres_error)?,
        ),
        created_at: row
            .try_get::<_, DateTime<Utc>>("release_created_at")
            .map_err(postgres_error)?,
    })
}

fn map_artifact(row: &Row) -> Result<Artifact, ApplicationError> {
    let size_bytes = row
        .try_get::<_, i64>("size_bytes")
        .map_err(postgres_error)?;
    if size_bytes < 0 {
        return Err(ApplicationError::External(
            "artifact size cannot be negative".into(),
        ));
    }

    Ok(Artifact {
        id: ArtifactId::new(row.try_get::<_, Uuid>("id").map_err(postgres_error)?),
        release_id: ReleaseId::new(
            row.try_get::<_, Uuid>("release_id")
                .map_err(postgres_error)?,
        ),
        filename: row
            .try_get::<_, String>("filename")
            .map_err(postgres_error)?,
        kind: parse_artifact_kind(row.try_get::<_, String>("kind").map_err(postgres_error)?)?,
        size_bytes: size_bytes as u64,
        digests: DigestSet::new(
            row.try_get::<_, String>("sha256").map_err(postgres_error)?,
            row.try_get::<_, Option<String>>("blake2b_256")
                .map_err(postgres_error)?,
        )?,
        object_key: row
            .try_get::<_, String>("object_key")
            .map_err(postgres_error)?,
        upstream_url: row
            .try_get::<_, Option<String>>("upstream_url")
            .map_err(postgres_error)?,
        provenance_key: row
            .try_get::<_, Option<String>>("provenance_key")
            .map_err(postgres_error)?,
        yanked: parse_yank(
            row.try_get::<_, Option<String>>("yanked_reason")
                .map_err(postgres_error)?,
            row.try_get::<_, Option<DateTime<Utc>>>("yanked_changed_at")
                .map_err(postgres_error)?,
        ),
        created_at: row
            .try_get::<_, DateTime<Utc>>("created_at")
            .map_err(postgres_error)?,
    })
}

fn map_artifact_alias(row: &Row) -> Result<Artifact, ApplicationError> {
    let size_bytes = row
        .try_get::<_, i64>("artifact_size_bytes")
        .map_err(postgres_error)?;
    if size_bytes < 0 {
        return Err(ApplicationError::External(
            "artifact size cannot be negative".into(),
        ));
    }

    Ok(Artifact {
        id: ArtifactId::new(
            row.try_get::<_, Uuid>("artifact_id")
                .map_err(postgres_error)?,
        ),
        release_id: ReleaseId::new(
            row.try_get::<_, Uuid>("artifact_release_id")
                .map_err(postgres_error)?,
        ),
        filename: row
            .try_get::<_, String>("artifact_filename")
            .map_err(postgres_error)?,
        kind: parse_artifact_kind(
            row.try_get::<_, String>("artifact_kind")
                .map_err(postgres_error)?,
        )?,
        size_bytes: size_bytes as u64,
        digests: DigestSet::new(
            row.try_get::<_, String>("artifact_sha256")
                .map_err(postgres_error)?,
            row.try_get::<_, Option<String>>("artifact_blake2b_256")
                .map_err(postgres_error)?,
        )?,
        object_key: row
            .try_get::<_, String>("artifact_object_key")
            .map_err(postgres_error)?,
        upstream_url: row
            .try_get::<_, Option<String>>("artifact_upstream_url")
            .map_err(postgres_error)?,
        provenance_key: row
            .try_get::<_, Option<String>>("artifact_provenance_key")
            .map_err(postgres_error)?,
        yanked: parse_yank(
            row.try_get::<_, Option<String>>("artifact_yanked_reason")
                .map_err(postgres_error)?,
            row.try_get::<_, Option<DateTime<Utc>>>("artifact_yanked_changed_at")
                .map_err(postgres_error)?,
        ),
        created_at: row
            .try_get::<_, DateTime<Utc>>("artifact_created_at")
            .map_err(postgres_error)?,
    })
}

fn map_attestation(row: &Row) -> Result<AttestationBundle, ApplicationError> {
    Ok(AttestationBundle {
        artifact_id: ArtifactId::new(
            row.try_get::<_, Uuid>("artifact_id")
                .map_err(postgres_error)?,
        ),
        media_type: row
            .try_get::<_, String>("media_type")
            .map_err(postgres_error)?,
        payload: row
            .try_get::<_, String>("payload")
            .map_err(postgres_error)?,
        source: parse_attestation_source(
            row.try_get::<_, String>("source").map_err(postgres_error)?,
        )?,
        recorded_at: row
            .try_get::<_, DateTime<Utc>>("recorded_at")
            .map_err(postgres_error)?,
    })
}

fn map_trusted_publisher(row: &Row) -> Result<TrustedPublisher, ApplicationError> {
    Ok(TrustedPublisher {
        id: TrustedPublisherId::new(row.try_get::<_, Uuid>("id").map_err(postgres_error)?),
        tenant_id: TenantId::new(
            row.try_get::<_, Uuid>("tenant_id")
                .map_err(postgres_error)?,
        ),
        project_name: ProjectName::new(
            row.try_get::<_, String>("project_original_name")
                .map_err(postgres_error)?,
        )?,
        provider: parse_provider(
            row.try_get::<_, String>("provider")
                .map_err(postgres_error)?,
        )?,
        issuer: row.try_get::<_, String>("issuer").map_err(postgres_error)?,
        audience: row
            .try_get::<_, String>("audience")
            .map_err(postgres_error)?,
        claim_rules: parse_claims_json(
            row.try_get::<_, String>("claim_rules_json")
                .map_err(postgres_error)?,
        )?,
        created_at: row
            .try_get::<_, DateTime<Utc>>("created_at")
            .map_err(postgres_error)?,
    })
}

fn map_audit_event(row: &Row) -> Result<AuditEvent, ApplicationError> {
    AuditEvent::new(
        AuditEventId::new(row.try_get::<_, Uuid>("id").map_err(postgres_error)?),
        row.try_get::<_, DateTime<Utc>>("occurred_at")
            .map_err(postgres_error)?,
        row.try_get::<_, String>("actor").map_err(postgres_error)?,
        row.try_get::<_, String>("action").map_err(postgres_error)?,
        row.try_get::<_, Option<String>>("tenant_slug")
            .map_err(postgres_error)?,
        row.try_get::<_, Option<String>>("target")
            .map_err(postgres_error)?,
        parse_claims_json(
            row.try_get::<_, String>("metadata_json")
                .map_err(postgres_error)?,
        )?,
    )
    .map_err(ApplicationError::Domain)
}

fn parse_publish_identity(
    issuer: Option<String>,
    subject: Option<String>,
    audience: Option<String>,
    provider: Option<String>,
    claims_json: Option<String>,
) -> Result<Option<PublishIdentity>, ApplicationError> {
    match (issuer, subject, audience, provider) {
        (Some(issuer), Some(subject), Some(audience), Some(provider)) => {
            Ok(Some(PublishIdentity {
                issuer,
                subject,
                audience,
                provider: parse_provider(provider)?,
                claims: parse_claims_json(claims_json.unwrap_or_else(|| "{}".into()))?,
            }))
        }
        (None, None, None, None) => Ok(None),
        _ => Err(ApplicationError::External(
            "postgres metadata row has incomplete publish identity columns".into(),
        )),
    }
}

fn parse_scopes_json(value: String) -> Result<Vec<TokenScope>, ApplicationError> {
    let scopes: Vec<String> = parse_json(value)?;
    scopes.into_iter().map(parse_token_scope).collect()
}

#[inline]
fn parse_claims_json(value: String) -> Result<BTreeMap<String, String>, ApplicationError> {
    parse_json(value)
}

fn parse_json<T: serde::de::DeserializeOwned>(value: String) -> Result<T, ApplicationError> {
    serde_json::from_str(&value).map_err(|error| {
        ApplicationError::External(format!(
            "could not deserialize postgres metadata JSON: {error}"
        ))
    })
}

fn parse_yank(reason: Option<String>, changed_at: Option<DateTime<Utc>>) -> Option<YankState> {
    match (reason, changed_at) {
        (None, None) => None,
        (reason, Some(changed_at)) => Some(YankState { reason, changed_at }),
        (Some(reason), None) => Some(YankState {
            reason: Some(reason),
            changed_at: Utc::now(),
        }),
    }
}

fn parse_project_source(value: String) -> Result<ProjectSource, ApplicationError> {
    match value.as_str() {
        "local" => Ok(ProjectSource::Local),
        "mirrored" => Ok(ProjectSource::Mirrored),
        _ => Err(invalid_enum("project source", value)),
    }
}

fn parse_artifact_kind(value: String) -> Result<ArtifactKind, ApplicationError> {
    match value.as_str() {
        "wheel" => Ok(ArtifactKind::Wheel),
        "sdist" => Ok(ArtifactKind::SourceDistribution),
        _ => Err(invalid_enum("artifact kind", value)),
    }
}

fn parse_token_scope(value: String) -> Result<TokenScope, ApplicationError> {
    match value.as_str() {
        "read" => Ok(TokenScope::Read),
        "publish" => Ok(TokenScope::Publish),
        "admin" => Ok(TokenScope::Admin),
        _ => Err(invalid_enum("token scope", value)),
    }
}

fn parse_provider(value: String) -> Result<TrustedPublisherProvider, ApplicationError> {
    match value.as_str() {
        "github-actions" => Ok(TrustedPublisherProvider::GitHubActions),
        "gitlab" => Ok(TrustedPublisherProvider::GitLab),
        _ => Err(invalid_enum("trusted publisher provider", value)),
    }
}

fn parse_attestation_source(value: String) -> Result<AttestationSource, ApplicationError> {
    match value.as_str() {
        "mirrored" => Ok(AttestationSource::Mirrored),
        "trusted-publish" => Ok(AttestationSource::TrustedPublish),
        _ => Err(invalid_enum("attestation source", value)),
    }
}

fn invalid_enum(label: &'static str, value: String) -> ApplicationError {
    ApplicationError::External(format!(
        "unknown {label} `{value}` in postgres metadata row"
    ))
}

fn yank_columns(yanked: &Option<YankState>) -> (Option<String>, Option<DateTime<Utc>>) {
    yanked
        .as_ref()
        .map(|state| (state.reason.clone(), Some(state.changed_at)))
        .unwrap_or((None, None))
}

fn project_source_str(source: &ProjectSource) -> &'static str {
    match source {
        ProjectSource::Local => "local",
        ProjectSource::Mirrored => "mirrored",
    }
}

fn artifact_kind_str(kind: &ArtifactKind) -> &'static str {
    match kind {
        ArtifactKind::Wheel => "wheel",
        ArtifactKind::SourceDistribution => "sdist",
    }
}

fn token_scope_str(scope: &TokenScope) -> &'static str {
    match scope {
        TokenScope::Read => "read",
        TokenScope::Publish => "publish",
        TokenScope::Admin => "admin",
    }
}

fn provider_str(provider: &TrustedPublisherProvider) -> &'static str {
    match provider {
        TrustedPublisherProvider::GitHubActions => "github-actions",
        TrustedPublisherProvider::GitLab => "gitlab",
    }
}

fn attestation_source_str(source: &AttestationSource) -> &'static str {
    match source {
        AttestationSource::Mirrored => "mirrored",
        AttestationSource::TrustedPublish => "trusted-publish",
    }
}

fn postgres_error(error: tokio_postgres::Error) -> ApplicationError {
    ApplicationError::External(format!("postgres metadata store failure: {error}"))
}

fn json_error(error: serde_json::Error) -> ApplicationError {
    ApplicationError::External(format!(
        "could not serialize postgres metadata JSON: {error}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postgres_schema_includes_all_registry_tables() {
        for table in [
            "tenants",
            "admin_users",
            "api_tokens",
            "projects",
            "releases",
            "artifacts",
            "attestations",
            "trusted_publishers",
            "audit_events",
        ] {
            assert!(
                POSTGRES_SCHEMA.contains(&format!("CREATE TABLE IF NOT EXISTS {table}")),
                "schema should define {table}"
            );
        }
    }

    #[test]
    fn postgres_schema_includes_query_optimization_indexes() {
        for index in [
            "idx_projects_tenant_updated",
            "idx_projects_tenant_normalized_prefix",
            "idx_releases_project_created",
            "idx_artifacts_release_filename",
            "idx_api_tokens_tenant_created",
        ] {
            assert!(
                POSTGRES_SCHEMA.contains(index),
                "schema should define optimization index {index}"
            );
        }
    }

    #[test]
    fn parses_supported_metadata_enums() {
        assert_eq!(
            parse_project_source("local".into()).expect("source"),
            ProjectSource::Local
        );
        assert_eq!(
            parse_artifact_kind("sdist".into()).expect("artifact kind"),
            ArtifactKind::SourceDistribution
        );
        assert_eq!(
            parse_provider("github-actions".into()).expect("provider"),
            TrustedPublisherProvider::GitHubActions
        );
    }

    #[test]
    fn parses_latest_release_versions_using_pep440_ordering() {
        assert_eq!(
            latest_release_version_from_values(vec!["0.1.9".into(), "0.1.14".into()])
                .expect("latest"),
            Some("0.1.14".into())
        );
        assert_eq!(
            latest_release_version_from_values(Vec::new()).expect("empty"),
            None
        );
        assert!(latest_release_version_from_values(vec!["not a version".into()]).is_err());
    }

    #[test]
    fn escapes_like_patterns_for_literal_searches() {
        assert_eq!(escape_like_pattern(r"demo\_%"), r"demo\\\_\%");
        assert_eq!(escape_like_pattern("plain"), "plain");
    }

    #[test]
    fn parses_json_backed_scopes_claims_and_publish_identity() {
        assert_eq!(
            parse_scopes_json(r#"["read","publish","admin"]"#.into()).expect("scopes"),
            vec![TokenScope::Read, TokenScope::Publish, TokenScope::Admin]
        );
        assert_eq!(
            parse_claims_json(r#"{"repository":"acme/demo"}"#.into())
                .expect("claims")
                .get("repository")
                .map(String::as_str),
            Some("acme/demo")
        );

        let identity = parse_publish_identity(
            Some("https://issuer.example".into()),
            Some("repo:acme/demo".into()),
            Some("pyregistry".into()),
            Some("github-actions".into()),
            Some(r#"{"repository":"acme/demo"}"#.into()),
        )
        .expect("identity")
        .expect("some identity");
        assert_eq!(identity.provider, TrustedPublisherProvider::GitHubActions);
        assert_eq!(
            identity.claims.get("repository").map(String::as_str),
            Some("acme/demo")
        );

        assert!(
            parse_publish_identity(None, None, None, None, None)
                .expect("empty identity")
                .is_none()
        );
        assert!(parse_publish_identity(Some("issuer".into()), None, None, None, None).is_err());
        assert!(parse_scopes_json(r#"["invalid"]"#.into()).is_err());
        assert!(parse_json::<BTreeMap<String, String>>("not json".into()).is_err());
    }

    #[test]
    fn parses_yank_columns_and_stringifies_domain_enums() {
        let now = Utc::now();

        assert_eq!(parse_yank(None, None), None);
        assert_eq!(
            parse_yank(Some("bad".into()), Some(now)),
            Some(YankState {
                reason: Some("bad".into()),
                changed_at: now
            })
        );
        assert!(parse_yank(Some("legacy".into()), None).is_some());

        let yanked = Some(YankState {
            reason: Some("bad".into()),
            changed_at: now,
        });
        assert_eq!(yank_columns(&yanked), (Some("bad".into()), Some(now)));
        assert_eq!(yank_columns(&None), (None, None));

        assert_eq!(project_source_str(&ProjectSource::Local), "local");
        assert_eq!(project_source_str(&ProjectSource::Mirrored), "mirrored");
        assert_eq!(artifact_kind_str(&ArtifactKind::Wheel), "wheel");
        assert_eq!(
            artifact_kind_str(&ArtifactKind::SourceDistribution),
            "sdist"
        );
        assert_eq!(token_scope_str(&TokenScope::Read), "read");
        assert_eq!(token_scope_str(&TokenScope::Publish), "publish");
        assert_eq!(token_scope_str(&TokenScope::Admin), "admin");
        assert_eq!(
            provider_str(&TrustedPublisherProvider::GitHubActions),
            "github-actions"
        );
        assert_eq!(provider_str(&TrustedPublisherProvider::GitLab), "gitlab");
        assert_eq!(
            attestation_source_str(&AttestationSource::Mirrored),
            "mirrored"
        );
        assert_eq!(
            attestation_source_str(&AttestationSource::TrustedPublish),
            "trusted-publish"
        );
    }

    #[test]
    fn rejects_unknown_metadata_enums() {
        assert!(parse_project_source("remote".into()).is_err());
        assert!(parse_artifact_kind("egg".into()).is_err());
        assert!(parse_token_scope("owner".into()).is_err());
        assert!(parse_provider("bitbucket".into()).is_err());
        assert!(parse_attestation_source("custom".into()).is_err());
        assert!(
            invalid_enum("thing", "value".into())
                .to_string()
                .contains("thing")
        );
    }
}
