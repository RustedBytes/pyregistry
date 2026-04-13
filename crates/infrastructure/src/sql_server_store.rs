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
use tiberius::{AuthMethod, Client, Config, FromSql, Row, ToSql};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_util::compat::{Compat, TokioAsyncWriteCompatExt};
use url::Url;
use uuid::Uuid;

use crate::SqlServerConfig;

const SQL_SERVER_SCHEMA: &str = r#"
IF OBJECT_ID(N'tenants', N'U') IS NULL
BEGIN
    CREATE TABLE tenants (
        id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
        slug NVARCHAR(256) NOT NULL UNIQUE,
        display_name NVARCHAR(512) NOT NULL,
        mirroring_enabled BIT NOT NULL,
        created_at DATETIME2 NOT NULL
    );
END;
IF OBJECT_ID(N'admin_users', N'U') IS NULL
BEGIN
    CREATE TABLE admin_users (
        id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
        tenant_id UNIQUEIDENTIFIER NULL,
        email NVARCHAR(512) NOT NULL UNIQUE,
        password_hash NVARCHAR(512) NOT NULL,
        is_superadmin BIT NOT NULL,
        created_at DATETIME2 NOT NULL,
        CONSTRAINT fk_admin_users_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE SET NULL
    );
END;
IF OBJECT_ID(N'api_tokens', N'U') IS NULL
BEGIN
    CREATE TABLE api_tokens (
        id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
        tenant_id UNIQUEIDENTIFIER NOT NULL,
        label NVARCHAR(512) NOT NULL,
        secret_hash NVARCHAR(512) NOT NULL,
        scopes_json NVARCHAR(MAX) NOT NULL,
        identity_issuer NVARCHAR(1024) NULL,
        identity_subject NVARCHAR(1024) NULL,
        identity_audience NVARCHAR(512) NULL,
        identity_provider NVARCHAR(128) NULL,
        identity_claims_json NVARCHAR(MAX) NULL,
        created_at DATETIME2 NOT NULL,
        expires_at DATETIME2 NULL,
        CONSTRAINT fk_api_tokens_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
    );
END;
IF OBJECT_ID(N'projects', N'U') IS NULL
BEGIN
    CREATE TABLE projects (
        id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
        tenant_id UNIQUEIDENTIFIER NOT NULL,
        original_name NVARCHAR(512) NOT NULL,
        normalized_name NVARCHAR(512) NOT NULL,
        source NVARCHAR(64) NOT NULL,
        summary NVARCHAR(MAX) NOT NULL,
        description NVARCHAR(MAX) NOT NULL,
        created_at DATETIME2 NOT NULL,
        updated_at DATETIME2 NOT NULL,
        CONSTRAINT fk_projects_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
        CONSTRAINT uq_projects_tenant_normalized UNIQUE (tenant_id, normalized_name)
    );
END;
IF OBJECT_ID(N'releases', N'U') IS NULL
BEGIN
    CREATE TABLE releases (
        id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
        project_id UNIQUEIDENTIFIER NOT NULL,
        version NVARCHAR(256) NOT NULL,
        yanked_reason NVARCHAR(MAX) NULL,
        yanked_changed_at DATETIME2 NULL,
        created_at DATETIME2 NOT NULL,
        CONSTRAINT fk_releases_project FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
        CONSTRAINT uq_releases_project_version UNIQUE (project_id, version)
    );
END;
IF OBJECT_ID(N'artifacts', N'U') IS NULL
BEGIN
    CREATE TABLE artifacts (
        id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
        release_id UNIQUEIDENTIFIER NOT NULL,
        filename NVARCHAR(512) NOT NULL,
        kind NVARCHAR(64) NOT NULL,
        size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
        sha256 NVARCHAR(128) NOT NULL,
        blake2b_256 NVARCHAR(128) NULL,
        object_key NVARCHAR(1024) NOT NULL,
        upstream_url NVARCHAR(2048) NULL,
        provenance_key NVARCHAR(1024) NULL,
        yanked_reason NVARCHAR(MAX) NULL,
        yanked_changed_at DATETIME2 NULL,
        created_at DATETIME2 NOT NULL,
        CONSTRAINT fk_artifacts_release FOREIGN KEY (release_id) REFERENCES releases(id) ON DELETE CASCADE,
        CONSTRAINT uq_artifacts_release_filename UNIQUE (release_id, filename)
    );
END;
IF OBJECT_ID(N'attestations', N'U') IS NULL
BEGIN
    CREATE TABLE attestations (
        artifact_id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
        media_type NVARCHAR(512) NOT NULL,
        payload NVARCHAR(MAX) NOT NULL,
        source NVARCHAR(64) NOT NULL,
        recorded_at DATETIME2 NOT NULL,
        CONSTRAINT fk_attestations_artifact FOREIGN KEY (artifact_id) REFERENCES artifacts(id) ON DELETE CASCADE
    );
END;
IF OBJECT_ID(N'trusted_publishers', N'U') IS NULL
BEGIN
    CREATE TABLE trusted_publishers (
        id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
        tenant_id UNIQUEIDENTIFIER NOT NULL,
        project_original_name NVARCHAR(512) NOT NULL,
        project_normalized_name NVARCHAR(512) NOT NULL,
        provider NVARCHAR(128) NOT NULL,
        issuer NVARCHAR(1024) NOT NULL,
        audience NVARCHAR(512) NOT NULL,
        claim_rules_json NVARCHAR(MAX) NOT NULL,
        created_at DATETIME2 NOT NULL,
        CONSTRAINT fk_trusted_publishers_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
    );
END;
IF OBJECT_ID(N'audit_events', N'U') IS NULL
BEGIN
    CREATE TABLE audit_events (
        id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
        occurred_at DATETIME2 NOT NULL,
        actor NVARCHAR(512) NOT NULL,
        action NVARCHAR(256) NOT NULL,
        tenant_slug NVARCHAR(256) NULL,
        target NVARCHAR(1024) NULL,
        metadata_json NVARCHAR(MAX) NOT NULL
    );
END;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_api_tokens_tenant' AND object_id = OBJECT_ID('api_tokens')) CREATE INDEX idx_api_tokens_tenant ON api_tokens(tenant_id);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_api_tokens_tenant_created' AND object_id = OBJECT_ID('api_tokens')) CREATE INDEX idx_api_tokens_tenant_created ON api_tokens(tenant_id, created_at DESC);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_projects_tenant' AND object_id = OBJECT_ID('projects')) CREATE INDEX idx_projects_tenant ON projects(tenant_id);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_projects_tenant_search' AND object_id = OBJECT_ID('projects')) CREATE INDEX idx_projects_tenant_search ON projects(tenant_id, normalized_name);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_projects_tenant_updated' AND object_id = OBJECT_ID('projects')) CREATE INDEX idx_projects_tenant_updated ON projects(tenant_id, updated_at DESC, normalized_name);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_releases_project' AND object_id = OBJECT_ID('releases')) CREATE INDEX idx_releases_project ON releases(project_id);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_releases_project_created' AND object_id = OBJECT_ID('releases')) CREATE INDEX idx_releases_project_created ON releases(project_id, created_at DESC);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_artifacts_release' AND object_id = OBJECT_ID('artifacts')) CREATE INDEX idx_artifacts_release ON artifacts(release_id);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_artifacts_release_filename' AND object_id = OBJECT_ID('artifacts')) CREATE INDEX idx_artifacts_release_filename ON artifacts(release_id, filename);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_trusted_publishers_tenant_project' AND object_id = OBJECT_ID('trusted_publishers')) CREATE INDEX idx_trusted_publishers_tenant_project ON trusted_publishers(tenant_id, project_normalized_name);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_audit_events_tenant_time' AND object_id = OBJECT_ID('audit_events')) CREATE INDEX idx_audit_events_tenant_time ON audit_events(tenant_slug, occurred_at);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_audit_events_time' AND object_id = OBJECT_ID('audit_events')) CREATE INDEX idx_audit_events_time ON audit_events(occurred_at);
"#;

pub struct SqlServerRegistryStore {
    client: Mutex<Client<Compat<TcpStream>>>,
}

impl SqlServerRegistryStore {
    pub async fn connect(config: &SqlServerConfig) -> Result<Self, ApplicationError> {
        let tds_config = sql_server_config_from_ado_string(&config.connection_url)?;
        let tcp = tokio::time::timeout(
            Duration::from_secs(config.acquire_timeout_seconds),
            TcpStream::connect(tds_config.get_addr()),
        )
        .await
        .map_err(|_| {
            ApplicationError::External(format!(
                "sql server metadata store connection timed out after {}s",
                config.acquire_timeout_seconds
            ))
        })?
        .map_err(|error| {
            ApplicationError::External(format!(
                "sql server metadata store TCP connection failed: {error}"
            ))
        })?;
        tcp.set_nodelay(true).map_err(|error| {
            ApplicationError::External(format!(
                "sql server metadata store TCP configuration failed: {error}"
            ))
        })?;
        if config.max_connections > 1 || config.min_connections > 1 {
            log::debug!(
                "sql server metadata adapter uses one tiberius connection guarded by a mutex; configured pool bounds are min={}, max={}",
                config.min_connections,
                config.max_connections
            );
        }
        let mut client = Client::connect(tds_config, tcp.compat_write())
            .await
            .map_err(sql_server_error)?;
        migrate(&mut client).await?;
        Ok(Self {
            client: Mutex::new(client),
        })
    }

    async fn execute(
        &self,
        statement: &str,
        params: &[&dyn ToSql],
    ) -> Result<u64, ApplicationError> {
        let mut client = self.client.lock().await;
        client
            .execute(statement, params)
            .await
            .map(|result| result.total())
            .map_err(sql_server_error)
    }

    async fn query(
        &self,
        statement: &str,
        params: &[&dyn ToSql],
    ) -> Result<Vec<Row>, ApplicationError> {
        let mut client = self.client.lock().await;
        client
            .query(statement, params)
            .await
            .map_err(sql_server_error)?
            .into_first_result()
            .await
            .map_err(sql_server_error)
    }

    async fn query_one(
        &self,
        statement: &str,
        params: &[&dyn ToSql],
    ) -> Result<Row, ApplicationError> {
        self.query_opt(statement, params).await?.ok_or_else(|| {
            ApplicationError::External("sql server metadata query returned no rows".into())
        })
    }

    async fn query_opt(
        &self,
        statement: &str,
        params: &[&dyn ToSql],
    ) -> Result<Option<Row>, ApplicationError> {
        let mut rows = self.query(statement, params).await?;
        Ok(rows.pop())
    }
}

#[async_trait]
impl RegistryStore for SqlServerRegistryStore {
    async fn registry_overview(&self) -> Result<RegistryOverview, ApplicationError> {
        let row = self.query_one(
                r#"
                SELECT
                    (SELECT CAST(COUNT(*) AS BIGINT) FROM tenants) AS tenant_count,
                    (SELECT CAST(COUNT(*) AS BIGINT) FROM projects) AS project_count,
                    (SELECT CAST(COUNT(*) AS BIGINT) FROM releases) AS release_count,
                    (SELECT CAST(COUNT(*) AS BIGINT) FROM artifacts) AS artifact_count,
                    (SELECT CAST(COALESCE(SUM(size_bytes), 0) AS BIGINT) FROM artifacts) AS total_storage_bytes,
                    (SELECT CAST(COUNT(*) AS BIGINT) FROM projects WHERE source = 'mirrored') AS mirrored_project_count
                "#,
                &[],
            )
            .await?;
        Ok(RegistryOverview {
            tenant_count: required::<i64>(&row, "tenant_count")? as usize,
            project_count: required::<i64>(&row, "project_count")? as usize,
            release_count: required::<i64>(&row, "release_count")? as usize,
            artifact_count: required::<i64>(&row, "artifact_count")? as usize,
            total_storage_bytes: required::<i64>(&row, "total_storage_bytes")? as u64,
            mirrored_project_count: required::<i64>(&row, "mirrored_project_count")? as usize,
        })
    }

    async fn save_tenant(&self, tenant: Tenant) -> Result<(), ApplicationError> {
        let id = tenant.id.into_inner();
        let slug = tenant.slug.as_str().to_string();
        self.execute(
            r#"
                UPDATE tenants
                SET slug = @P2, display_name = @P3, mirroring_enabled = @P4, created_at = @P5
                WHERE id = @P1;
                IF @@ROWCOUNT = 0
                INSERT INTO tenants (id, slug, display_name, mirroring_enabled, created_at)
                VALUES (@P1, @P2, @P3, @P4, @P5);
                "#,
            &[
                &id,
                &slug,
                &tenant.display_name,
                &tenant.mirror_rule.enabled,
                &tenant.created_at,
            ],
        )
        .await?;
        Ok(())
    }

    async fn list_tenants(&self) -> Result<Vec<Tenant>, ApplicationError> {
        let rows = self.query(
                "SELECT id, slug, display_name, mirroring_enabled, created_at FROM tenants ORDER BY slug",
                &[],
            )
            .await?;
        rows.iter().map(map_tenant).collect()
    }

    async fn get_tenant_by_slug(&self, slug: &str) -> Result<Option<Tenant>, ApplicationError> {
        let row = self.query_opt(
                "SELECT id, slug, display_name, mirroring_enabled, created_at FROM tenants WHERE slug = @P1",
                &[&slug],
            )
            .await?;
        row.as_ref().map(map_tenant).transpose()
    }

    async fn tenant_dashboard_stats(
        &self,
        tenant: &Tenant,
    ) -> Result<TenantDashboardStats, ApplicationError> {
        let tenant_id = tenant.id.into_inner();
        let counts = self.query_one(
                r#"
                SELECT
                    (SELECT CAST(COUNT(*) AS BIGINT) FROM projects WHERE tenant_id = @P1) AS project_count,
                    (
                        SELECT CAST(COUNT(*) AS BIGINT)
                        FROM releases r
                        INNER JOIN projects p ON p.id = r.project_id
                        WHERE p.tenant_id = @P1
                    ) AS release_count,
                    (
                        SELECT CAST(COUNT(*) AS BIGINT)
                        FROM artifacts a
                        INNER JOIN releases r ON r.id = a.release_id
                        INNER JOIN projects p ON p.id = r.project_id
                        WHERE p.tenant_id = @P1
                    ) AS artifact_count,
                    (SELECT CAST(COUNT(*) AS BIGINT) FROM api_tokens WHERE tenant_id = @P1) AS token_count,
                    (SELECT CAST(COUNT(*) AS BIGINT) FROM trusted_publishers WHERE tenant_id = @P1) AS trusted_publisher_count
                "#,
                &[&tenant_id],
            )
            .await?;

        let rows = self
            .query(
                r#"
                SELECT TOP 6 original_name, source, updated_at
                FROM projects
                WHERE tenant_id = @P1
                ORDER BY updated_at DESC, normalized_name
                "#,
                &[&tenant_id],
            )
            .await?;
        let mut recent_activity = Vec::with_capacity(rows.len());
        for row in rows {
            recent_activity.push(RecentActivity {
                project_name: required_string(&row, "original_name")?,
                tenant_slug: tenant.slug.as_str().to_string(),
                source: required_string(&row, "source")?,
                updated_at: required::<DateTime<Utc>>(&row, "updated_at")?,
            });
        }

        Ok(TenantDashboardStats {
            project_count: required::<i64>(&counts, "project_count")? as usize,
            release_count: required::<i64>(&counts, "release_count")? as usize,
            artifact_count: required::<i64>(&counts, "artifact_count")? as usize,
            token_count: required::<i64>(&counts, "token_count")? as usize,
            trusted_publisher_count: required::<i64>(&counts, "trusted_publisher_count")? as usize,
            recent_activity,
        })
    }

    async fn save_admin_user(&self, user: AdminUser) -> Result<(), ApplicationError> {
        let id = user.id.into_inner();
        let tenant_id = user.tenant_id.map(|id| id.into_inner());
        self.execute(
                r#"
                UPDATE admin_users
                SET id = @P1, tenant_id = @P2, password_hash = @P4, is_superadmin = @P5, created_at = @P6
                WHERE email = @P3;
                IF @@ROWCOUNT = 0
                INSERT INTO admin_users (id, tenant_id, email, password_hash, is_superadmin, created_at)
                VALUES (@P1, @P2, @P3, @P4, @P5, @P6);
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
            .await?;
        Ok(())
    }

    async fn get_admin_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<AdminUser>, ApplicationError> {
        let row = self
            .query_opt(
                r#"
                SELECT id, tenant_id, email, password_hash, is_superadmin, created_at
                FROM admin_users
                WHERE email = @P1
                "#,
                &[&email],
            )
            .await?;
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
        self.execute(
            r#"
                UPDATE api_tokens
                SET tenant_id = @P2, label = @P3, secret_hash = @P4, scopes_json = @P5,
                    identity_issuer = @P6, identity_subject = @P7, identity_audience = @P8,
                    identity_provider = @P9, identity_claims_json = @P10, created_at = @P11,
                    expires_at = @P12
                WHERE id = @P1;
                IF @@ROWCOUNT = 0
                INSERT INTO api_tokens (
                    id, tenant_id, label, secret_hash, scopes_json,
                    identity_issuer, identity_subject, identity_audience, identity_provider,
                    identity_claims_json, created_at, expires_at
                )
                VALUES (@P1, @P2, @P3, @P4, @P5, @P6, @P7, @P8, @P9, @P10, @P11, @P12);
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
        .await?;
        Ok(())
    }

    async fn list_api_tokens(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<ApiToken>, ApplicationError> {
        let tenant_id = tenant_id.into_inner();
        let rows = self
            .query(
                r#"
                SELECT id, tenant_id, label, secret_hash, scopes_json,
                       identity_issuer, identity_subject, identity_audience, identity_provider,
                       identity_claims_json, created_at, expires_at
                FROM api_tokens
                WHERE tenant_id = @P1
                ORDER BY created_at DESC, label
                "#,
                &[&tenant_id],
            )
            .await?;
        rows.iter().map(map_api_token).collect()
    }

    async fn revoke_api_token(
        &self,
        tenant_id: TenantId,
        token_id: TokenId,
    ) -> Result<(), ApplicationError> {
        let tenant_id = tenant_id.into_inner();
        let token_id = token_id.into_inner();
        self.execute(
            "DELETE FROM api_tokens WHERE id = @P1 AND tenant_id = @P2",
            &[&token_id, &tenant_id],
        )
        .await?;
        Ok(())
    }

    async fn save_project(&self, project: Project) -> Result<(), ApplicationError> {
        let id = project.id.into_inner();
        let tenant_id = project.tenant_id.into_inner();
        let original_name = project.name.original().to_string();
        let normalized_name = project.name.normalized().to_string();
        let source = project_source_str(&project.source);
        self.execute(
            r#"
                UPDATE projects
                SET tenant_id = @P2, original_name = @P3, normalized_name = @P4, source = @P5,
                    summary = @P6, description = @P7, created_at = @P8, updated_at = @P9
                WHERE id = @P1;
                IF @@ROWCOUNT = 0
                INSERT INTO projects (
                    id, tenant_id, original_name, normalized_name, source,
                    summary, description, created_at, updated_at
                )
                VALUES (@P1, @P2, @P3, @P4, @P5, @P6, @P7, @P8, @P9);
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
        .await?;
        Ok(())
    }

    async fn list_projects(&self, tenant_id: TenantId) -> Result<Vec<Project>, ApplicationError> {
        let tenant_id = tenant_id.into_inner();
        let rows = self.query(
                r#"
                SELECT id, tenant_id, original_name, source, summary, description, created_at, updated_at
                FROM projects
                WHERE tenant_id = @P1
                ORDER BY normalized_name
                "#,
                &[&tenant_id],
            )
            .await?;
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

        let rows = self.query(
                r#"
                SELECT t.slug AS tenant_slug, p.original_name, p.normalized_name, p.source, p.summary,
                       COALESCE(STRING_AGG(CAST(r.version AS NVARCHAR(MAX)), CHAR(30)), '') AS release_versions
                FROM projects p
                INNER JOIN tenants t ON t.id = p.tenant_id
                LEFT JOIN releases r ON r.project_id = p.id
                WHERE p.tenant_id = @P1
                  AND (
                      @P2 = ''
                      OR p.normalized_name LIKE @P3 ESCAPE '\'
                      OR lower(p.summary) LIKE @P3 ESCAPE '\'
                  )
                GROUP BY t.slug, p.id, p.original_name, p.normalized_name, p.source, p.summary
                ORDER BY
                    CASE
                        WHEN p.normalized_name = @P2 THEN 0
                        WHEN p.normalized_name LIKE @P4 ESCAPE '\' THEN 1
                        WHEN lower(p.summary) LIKE @P4 ESCAPE '\' THEN 2
                        ELSE 3
                    END,
                    p.normalized_name
                "#,
                &[&tenant_id, &query, &contains_pattern, &prefix_pattern],
            )
            .await?;

        let mut hits = Vec::new();
        for row in rows {
            let release_versions = required_string(&row, "release_versions")?
                .split('\u{001e}')
                .filter(|version| !version.is_empty())
                .map(ToOwned::to_owned)
                .collect();
            hits.push(SearchHit {
                tenant_slug: required_string(&row, "tenant_slug")?,
                project_name: required_string(&row, "original_name")?,
                normalized_name: required_string(&row, "normalized_name")?,
                source: required_string(&row, "source")?,
                summary: required_string(&row, "summary")?,
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
        let row = self.query_opt(
                r#"
                SELECT id, tenant_id, original_name, source, summary, description, created_at, updated_at
                FROM projects
                WHERE tenant_id = @P1 AND normalized_name = @P2
                "#,
                &[&tenant_id, &normalized_name],
            )
            .await?;
        row.as_ref().map(map_project).transpose()
    }

    async fn save_release(&self, release: Release) -> Result<(), ApplicationError> {
        let (reason, changed_at) = yank_columns(&release.yanked);
        let id = release.id.into_inner();
        let project_id = release.project_id.into_inner();
        let version = release.version.as_str().to_string();
        self.execute(
                r#"
                UPDATE releases
                SET project_id = @P2, version = @P3, yanked_reason = @P4,
                    yanked_changed_at = @P5, created_at = @P6
                WHERE id = @P1;
                IF @@ROWCOUNT = 0
                INSERT INTO releases (id, project_id, version, yanked_reason, yanked_changed_at, created_at)
                VALUES (@P1, @P2, @P3, @P4, @P5, @P6);
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
            .await?;
        Ok(())
    }

    async fn list_releases(&self, project_id: ProjectId) -> Result<Vec<Release>, ApplicationError> {
        let project_id = project_id.into_inner();
        let rows = self
            .query(
                r#"
                SELECT id, project_id, version, yanked_reason, yanked_changed_at, created_at
                FROM releases
                WHERE project_id = @P1
                ORDER BY created_at DESC, version DESC
                "#,
                &[&project_id],
            )
            .await?;
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
            .query_opt(
                r#"
                SELECT id, project_id, version, yanked_reason, yanked_changed_at, created_at
                FROM releases
                WHERE project_id = @P1 AND version = @P2
                "#,
                &[&project_id, &version],
            )
            .await?;
        row.as_ref().map(map_release).transpose()
    }

    async fn delete_release(&self, release_id: ReleaseId) -> Result<(), ApplicationError> {
        let release_id = release_id.into_inner();
        self.execute("DELETE FROM releases WHERE id = @P1", &[&release_id])
            .await?;
        Ok(())
    }

    async fn save_artifact(&self, artifact: Artifact) -> Result<(), ApplicationError> {
        let size_bytes = i64::try_from(artifact.size_bytes).map_err(|error| {
            ApplicationError::External(format!(
                "artifact `{}` is too large to store in sql server metadata: {error}",
                artifact.filename
            ))
        })?;
        let (reason, changed_at) = yank_columns(&artifact.yanked);
        let id = artifact.id.into_inner();
        let release_id = artifact.release_id.into_inner();
        let kind = artifact_kind_str(&artifact.kind);
        self.execute(
            r#"
                UPDATE artifacts
                SET release_id = @P2, filename = @P3, kind = @P4, size_bytes = @P5,
                    sha256 = @P6, blake2b_256 = @P7, object_key = @P8, upstream_url = @P9,
                    provenance_key = @P10, yanked_reason = @P11, yanked_changed_at = @P12,
                    created_at = @P13
                WHERE id = @P1;
                IF @@ROWCOUNT = 0
                INSERT INTO artifacts (
                    id, release_id, filename, kind, size_bytes, sha256, blake2b_256,
                    object_key, upstream_url, provenance_key, yanked_reason, yanked_changed_at,
                    created_at
                )
                VALUES (@P1, @P2, @P3, @P4, @P5, @P6, @P7, @P8, @P9, @P10, @P11, @P12, @P13);
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
        .await?;
        Ok(())
    }

    async fn list_artifacts(
        &self,
        release_id: ReleaseId,
    ) -> Result<Vec<Artifact>, ApplicationError> {
        let release_id = release_id.into_inner();
        let rows = self
            .query(
                r#"
                SELECT id, release_id, filename, kind, size_bytes, sha256, blake2b_256,
                       object_key, upstream_url, provenance_key, yanked_reason, yanked_changed_at,
                       created_at
                FROM artifacts
                WHERE release_id = @P1
                ORDER BY filename
                "#,
                &[&release_id],
            )
            .await?;
        rows.iter().map(map_artifact).collect()
    }

    async fn list_release_artifacts(
        &self,
        project_id: ProjectId,
    ) -> Result<Vec<ReleaseArtifacts>, ApplicationError> {
        let project_id = project_id.into_inner();
        let rows = self
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
                WHERE r.project_id = @P1
                ORDER BY r.created_at DESC, r.version DESC, a.filename
                "#,
                &[&project_id],
            )
            .await?;

        let mut grouped = Vec::<ReleaseArtifacts>::new();
        let mut release_positions = BTreeMap::<Uuid, usize>::new();
        for row in rows {
            let release = map_release_alias(&row)?;
            let release_id = release.id.into_inner();
            let artifact_id = optional::<Uuid>(&row, "artifact_id")?;
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
            .query_opt(
                r#"
                SELECT id, release_id, filename, kind, size_bytes, sha256, blake2b_256,
                       object_key, upstream_url, provenance_key, yanked_reason, yanked_changed_at,
                       created_at
                FROM artifacts
                WHERE release_id = @P1 AND filename = @P2
                "#,
                &[&release_id, &filename],
            )
            .await?;
        row.as_ref().map(map_artifact).transpose()
    }

    async fn delete_artifact(&self, artifact_id: ArtifactId) -> Result<(), ApplicationError> {
        let artifact_id = artifact_id.into_inner();
        self.execute("DELETE FROM artifacts WHERE id = @P1", &[&artifact_id])
            .await?;
        Ok(())
    }

    async fn save_attestation(
        &self,
        attestation: AttestationBundle,
    ) -> Result<(), ApplicationError> {
        let artifact_id = attestation.artifact_id.into_inner();
        let source = attestation_source_str(&attestation.source);
        self.execute(
            r#"
                UPDATE attestations
                SET media_type = @P2, payload = @P3, source = @P4, recorded_at = @P5
                WHERE artifact_id = @P1;
                IF @@ROWCOUNT = 0
                INSERT INTO attestations (artifact_id, media_type, payload, source, recorded_at)
                VALUES (@P1, @P2, @P3, @P4, @P5);
                "#,
            &[
                &artifact_id,
                &attestation.media_type,
                &attestation.payload,
                &source,
                &attestation.recorded_at,
            ],
        )
        .await?;
        Ok(())
    }

    async fn get_attestation_by_artifact(
        &self,
        artifact_id: ArtifactId,
    ) -> Result<Option<AttestationBundle>, ApplicationError> {
        let artifact_id = artifact_id.into_inner();
        let row = self
            .query_opt(
                r#"
                SELECT artifact_id, media_type, payload, source, recorded_at
                FROM attestations
                WHERE artifact_id = @P1
                "#,
                &[&artifact_id],
            )
            .await?;
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
        self.execute(
            r#"
                UPDATE trusted_publishers
                SET tenant_id = @P2, project_original_name = @P3, project_normalized_name = @P4,
                    provider = @P5, issuer = @P6, audience = @P7, claim_rules_json = @P8,
                    created_at = @P9
                WHERE id = @P1;
                IF @@ROWCOUNT = 0
                INSERT INTO trusted_publishers (
                    id, tenant_id, project_original_name, project_normalized_name,
                    provider, issuer, audience, claim_rules_json, created_at
                )
                VALUES (@P1, @P2, @P3, @P4, @P5, @P6, @P7, @P8, @P9);
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
        .await?;
        Ok(())
    }

    async fn list_trusted_publishers(
        &self,
        tenant_id: TenantId,
        normalized_project_name: &str,
    ) -> Result<Vec<TrustedPublisher>, ApplicationError> {
        let tenant_id = tenant_id.into_inner();
        let rows = self
            .query(
                r#"
                SELECT id, tenant_id, project_original_name, provider, issuer, audience,
                       claim_rules_json, created_at
                FROM trusted_publishers
                WHERE tenant_id = @P1
                  AND (@P2 = '' OR project_normalized_name = @P2)
                ORDER BY created_at DESC
                "#,
                &[&tenant_id, &normalized_project_name],
            )
            .await?;
        rows.iter().map(map_trusted_publisher).collect()
    }

    async fn delete_project(&self, project_id: ProjectId) -> Result<(), ApplicationError> {
        let project_id = project_id.into_inner();
        self.execute("DELETE FROM projects WHERE id = @P1", &[&project_id])
            .await?;
        Ok(())
    }

    async fn save_audit_event(&self, event: AuditEvent) -> Result<(), ApplicationError> {
        let metadata_json = serde_json::to_string(&event.metadata).map_err(json_error)?;
        let id = event.id.into_inner();
        self.execute(
            r#"
                INSERT INTO audit_events
                    (id, occurred_at, actor, action, tenant_slug, target, metadata_json)
                VALUES (@P1, @P2, @P3, @P4, @P5, @P6, @P7)
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
        .await?;
        Ok(())
    }

    async fn list_audit_events(
        &self,
        tenant_slug: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AuditEvent>, ApplicationError> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let rows = if let Some(tenant_slug) = tenant_slug {
            self.query(
                    r#"
                    SELECT TOP (@P2) id, occurred_at, actor, action, tenant_slug, target, metadata_json
                    FROM audit_events
                    WHERE tenant_slug = @P1
                    ORDER BY occurred_at DESC, id DESC
                    "#,
                    &[&tenant_slug, &limit],
                )
                .await?
        } else {
            self.query(
                    r#"
                    SELECT TOP (@P1) id, occurred_at, actor, action, tenant_slug, target, metadata_json
                    FROM audit_events
                    ORDER BY occurred_at DESC, id DESC
                    "#,
                    &[&limit],
                )
                .await?
        };
        rows.iter().map(map_audit_event).collect()
    }
}

async fn migrate(client: &mut Client<Compat<TcpStream>>) -> Result<(), ApplicationError> {
    client
        .simple_query(SQL_SERVER_SCHEMA)
        .await
        .map_err(sql_server_error)?
        .into_results()
        .await
        .map(|_| ())
        .map_err(sql_server_error)
}

fn sql_server_config_from_ado_string(connection_url: &str) -> Result<Config, ApplicationError> {
    if let Ok(mut config) = Config::from_ado_string(connection_url) {
        config.trust_cert();
        return Ok(config);
    }

    let url = Url::parse(connection_url).map_err(|error| {
        ApplicationError::External(format!(
            "sql server metadata store connection URL is invalid: {error}"
        ))
    })?;
    let mut config = Config::new();
    config.host(url.host_str().ok_or_else(|| {
        ApplicationError::External("sql server metadata store URL must include a host".into())
    })?);
    config.port(url.port().unwrap_or(1433));
    if let Some(database) = url
        .path_segments()
        .and_then(|segments| segments.filter(|segment| !segment.is_empty()).next())
    {
        config.database(database);
    }
    let username = url.username();
    if !username.is_empty() {
        config.authentication(AuthMethod::sql_server(
            username,
            url.password().unwrap_or_default(),
        ));
    }
    if url
        .query_pairs()
        .any(|(key, value)| key == "trust_server_certificate" && value == "true")
    {
        config.trust_cert();
    }
    Ok(config)
}

fn required<'a, T>(row: &'a Row, column: &'static str) -> Result<T, ApplicationError>
where
    T: FromSql<'a>,
{
    row.try_get::<T, _>(column)
        .map_err(sql_server_error)?
        .ok_or_else(|| ApplicationError::External(format!("missing sql server column `{column}`")))
}

fn optional<'a, T>(row: &'a Row, column: &'static str) -> Result<Option<T>, ApplicationError>
where
    T: FromSql<'a>,
{
    row.try_get::<T, _>(column).map_err(sql_server_error)
}

fn required_string(row: &Row, column: &'static str) -> Result<String, ApplicationError> {
    required::<&str>(&row, column).map(ToOwned::to_owned)
}

fn optional_string(row: &Row, column: &'static str) -> Result<Option<String>, ApplicationError> {
    optional::<&str>(&row, column).map(|value| value.map(ToOwned::to_owned))
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
        TenantId::new(required::<Uuid>(&row, "id")?),
        TenantSlug::new(required_string(&row, "slug")?)?,
        required_string(&row, "display_name")?,
        MirrorRule {
            enabled: required::<bool>(&row, "mirroring_enabled")?,
        },
        required::<DateTime<Utc>>(&row, "created_at")?,
    )
    .map_err(ApplicationError::Domain)
}

fn map_admin_user(row: &Row) -> Result<AdminUser, ApplicationError> {
    Ok(AdminUser {
        id: AdminUserId::new(required::<Uuid>(&row, "id")?),
        tenant_id: optional::<Uuid>(&row, "tenant_id")?.map(TenantId::new),
        email: required_string(&row, "email")?,
        password_hash: required_string(&row, "password_hash")?,
        is_superadmin: required::<bool>(&row, "is_superadmin")?,
        created_at: required::<DateTime<Utc>>(&row, "created_at")?,
    })
}

fn map_api_token(row: &Row) -> Result<ApiToken, ApplicationError> {
    Ok(ApiToken {
        id: TokenId::new(required::<Uuid>(&row, "id")?),
        tenant_id: TenantId::new(required::<Uuid>(&row, "tenant_id")?),
        label: required_string(&row, "label")?,
        secret_hash: required_string(&row, "secret_hash")?,
        scopes: parse_scopes_json(required_string(&row, "scopes_json")?)?,
        publish_identity: parse_publish_identity(
            optional_string(&row, "identity_issuer")?,
            optional_string(&row, "identity_subject")?,
            optional_string(&row, "identity_audience")?,
            optional_string(&row, "identity_provider")?,
            optional_string(&row, "identity_claims_json")?,
        )?,
        created_at: required::<DateTime<Utc>>(&row, "created_at")?,
        expires_at: optional::<DateTime<Utc>>(&row, "expires_at")?,
    })
}

fn map_project(row: &Row) -> Result<Project, ApplicationError> {
    Ok(Project {
        id: ProjectId::new(required::<Uuid>(&row, "id")?),
        tenant_id: TenantId::new(required::<Uuid>(&row, "tenant_id")?),
        name: ProjectName::new(required_string(&row, "original_name")?)?,
        source: parse_project_source(required_string(&row, "source")?)?,
        summary: required_string(&row, "summary")?,
        description: required_string(&row, "description")?,
        created_at: required::<DateTime<Utc>>(&row, "created_at")?,
        updated_at: required::<DateTime<Utc>>(&row, "updated_at")?,
    })
}

fn map_release(row: &Row) -> Result<Release, ApplicationError> {
    Ok(Release {
        id: ReleaseId::new(required::<Uuid>(&row, "id")?),
        project_id: ProjectId::new(required::<Uuid>(&row, "project_id")?),
        version: ReleaseVersion::new(required_string(&row, "version")?)?,
        yanked: parse_yank(
            optional_string(&row, "yanked_reason")?,
            optional::<DateTime<Utc>>(&row, "yanked_changed_at")?,
        ),
        created_at: required::<DateTime<Utc>>(&row, "created_at")?,
    })
}

fn map_release_alias(row: &Row) -> Result<Release, ApplicationError> {
    Ok(Release {
        id: ReleaseId::new(required::<Uuid>(&row, "release_id")?),
        project_id: ProjectId::new(required::<Uuid>(&row, "release_project_id")?),
        version: ReleaseVersion::new(required_string(&row, "release_version")?)?,
        yanked: parse_yank(
            optional_string(&row, "release_yanked_reason")?,
            optional::<DateTime<Utc>>(&row, "release_yanked_changed_at")?,
        ),
        created_at: required::<DateTime<Utc>>(&row, "release_created_at")?,
    })
}

fn map_artifact(row: &Row) -> Result<Artifact, ApplicationError> {
    let size_bytes = required::<i64>(&row, "size_bytes")?;
    if size_bytes < 0 {
        return Err(ApplicationError::External(
            "artifact size cannot be negative".into(),
        ));
    }

    Ok(Artifact {
        id: ArtifactId::new(required::<Uuid>(&row, "id")?),
        release_id: ReleaseId::new(required::<Uuid>(&row, "release_id")?),
        filename: required_string(&row, "filename")?,
        kind: parse_artifact_kind(required_string(&row, "kind")?)?,
        size_bytes: size_bytes as u64,
        digests: DigestSet::new(
            required_string(&row, "sha256")?,
            optional_string(&row, "blake2b_256")?,
        )?,
        object_key: required_string(&row, "object_key")?,
        upstream_url: optional_string(&row, "upstream_url")?,
        provenance_key: optional_string(&row, "provenance_key")?,
        yanked: parse_yank(
            optional_string(&row, "yanked_reason")?,
            optional::<DateTime<Utc>>(&row, "yanked_changed_at")?,
        ),
        created_at: required::<DateTime<Utc>>(&row, "created_at")?,
    })
}

fn map_artifact_alias(row: &Row) -> Result<Artifact, ApplicationError> {
    let size_bytes = required::<i64>(&row, "artifact_size_bytes")?;
    if size_bytes < 0 {
        return Err(ApplicationError::External(
            "artifact size cannot be negative".into(),
        ));
    }

    Ok(Artifact {
        id: ArtifactId::new(required::<Uuid>(&row, "artifact_id")?),
        release_id: ReleaseId::new(required::<Uuid>(&row, "artifact_release_id")?),
        filename: required_string(&row, "artifact_filename")?,
        kind: parse_artifact_kind(required_string(&row, "artifact_kind")?)?,
        size_bytes: size_bytes as u64,
        digests: DigestSet::new(
            required_string(&row, "artifact_sha256")?,
            optional_string(&row, "artifact_blake2b_256")?,
        )?,
        object_key: required_string(&row, "artifact_object_key")?,
        upstream_url: optional_string(&row, "artifact_upstream_url")?,
        provenance_key: optional_string(&row, "artifact_provenance_key")?,
        yanked: parse_yank(
            optional_string(&row, "artifact_yanked_reason")?,
            optional::<DateTime<Utc>>(&row, "artifact_yanked_changed_at")?,
        ),
        created_at: required::<DateTime<Utc>>(&row, "artifact_created_at")?,
    })
}

fn map_attestation(row: &Row) -> Result<AttestationBundle, ApplicationError> {
    Ok(AttestationBundle {
        artifact_id: ArtifactId::new(required::<Uuid>(&row, "artifact_id")?),
        media_type: required_string(&row, "media_type")?,
        payload: required_string(&row, "payload")?,
        source: parse_attestation_source(required_string(&row, "source")?)?,
        recorded_at: required::<DateTime<Utc>>(&row, "recorded_at")?,
    })
}

fn map_trusted_publisher(row: &Row) -> Result<TrustedPublisher, ApplicationError> {
    Ok(TrustedPublisher {
        id: TrustedPublisherId::new(required::<Uuid>(&row, "id")?),
        tenant_id: TenantId::new(required::<Uuid>(&row, "tenant_id")?),
        project_name: ProjectName::new(required_string(&row, "project_original_name")?)?,
        provider: parse_provider(required_string(&row, "provider")?)?,
        issuer: required_string(&row, "issuer")?,
        audience: required_string(&row, "audience")?,
        claim_rules: parse_claims_json(required_string(&row, "claim_rules_json")?)?,
        created_at: required::<DateTime<Utc>>(&row, "created_at")?,
    })
}

fn map_audit_event(row: &Row) -> Result<AuditEvent, ApplicationError> {
    AuditEvent::new(
        AuditEventId::new(required::<Uuid>(&row, "id")?),
        required::<DateTime<Utc>>(&row, "occurred_at")?,
        required_string(&row, "actor")?,
        required_string(&row, "action")?,
        optional_string(&row, "tenant_slug")?,
        optional_string(&row, "target")?,
        parse_claims_json(required_string(&row, "metadata_json")?)?,
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
            "sql server metadata row has incomplete publish identity columns".into(),
        )),
    }
}

fn parse_scopes_json(value: String) -> Result<Vec<TokenScope>, ApplicationError> {
    let scopes: Vec<String> = parse_json(value)?;
    scopes.into_iter().map(parse_token_scope).collect()
}

fn parse_claims_json(value: String) -> Result<BTreeMap<String, String>, ApplicationError> {
    parse_json(value)
}

fn parse_json<T: serde::de::DeserializeOwned>(value: String) -> Result<T, ApplicationError> {
    serde_json::from_str(&value).map_err(|error| {
        ApplicationError::External(format!(
            "could not deserialize sql server metadata JSON: {error}"
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
        "unknown {label} `{value}` in sql server metadata row"
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

fn sql_server_error(error: tiberius::error::Error) -> ApplicationError {
    ApplicationError::External(format!("sql server metadata store failure: {error}"))
}

fn json_error(error: serde_json::Error) -> ApplicationError {
    ApplicationError::External(format!(
        "could not serialize sql server metadata JSON: {error}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_server_schema_includes_all_registry_tables() {
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
                SQL_SERVER_SCHEMA.contains(&format!("CREATE TABLE {table}")),
                "schema should define {table}"
            );
        }
    }

    #[test]
    fn sql_server_schema_includes_query_optimization_indexes() {
        for index in [
            "idx_projects_tenant_updated",
            "idx_releases_project_created",
            "idx_artifacts_release_filename",
            "idx_api_tokens_tenant_created",
        ] {
            assert!(
                SQL_SERVER_SCHEMA.contains(index),
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
