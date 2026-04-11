use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pyregistry_application::{ApplicationError, RegistryOverview, RegistryStore, SearchHit};
use pyregistry_domain::{
    AdminUser, AdminUserId, ApiToken, Artifact, ArtifactId, ArtifactKind, AttestationBundle,
    AttestationSource, DigestSet, MirrorRule, Project, ProjectId, ProjectName, ProjectSource,
    PublishIdentity, Release, ReleaseId, ReleaseVersion, Tenant, TenantId, TenantSlug, TokenId,
    TokenScope, TrustedPublisher, TrustedPublisherId, TrustedPublisherProvider, YankState,
};
use rusqlite::types::Type;
use rusqlite::{Connection, OptionalExtension, Row, params};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use uuid::Uuid;

pub struct SqliteRegistryStore {
    connection: Mutex<Connection>,
}

impl SqliteRegistryStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ApplicationError> {
        let path = path.as_ref();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(|error| {
                ApplicationError::External(format!(
                    "could not create sqlite metadata directory `{}`: {error}",
                    parent.display()
                ))
            })?;
        }

        let connection = Connection::open(path).map_err(sqlite_error)?;
        connection
            .execute_batch(
                r#"
                PRAGMA foreign_keys = ON;
                PRAGMA journal_mode = WAL;
                PRAGMA busy_timeout = 5000;
                "#,
            )
            .map_err(sqlite_error)?;
        migrate(&connection)?;

        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    fn with_connection<T>(
        &self,
        operation: impl FnOnce(&Connection) -> rusqlite::Result<T>,
    ) -> Result<T, ApplicationError> {
        let connection = self.connection.lock().map_err(|error| {
            ApplicationError::External(format!("sqlite metadata connection lock poisoned: {error}"))
        })?;
        operation(&connection).map_err(sqlite_error)
    }
}

#[async_trait]
impl RegistryStore for SqliteRegistryStore {
    async fn registry_overview(&self) -> Result<RegistryOverview, ApplicationError> {
        self.with_connection(|connection| {
            Ok(RegistryOverview {
                tenant_count: count_table(connection, "tenants")?,
                project_count: count_table(connection, "projects")?,
                release_count: count_table(connection, "releases")?,
                artifact_count: count_table(connection, "artifacts")?,
                total_storage_bytes: connection.query_row(
                    "SELECT COALESCE(SUM(size_bytes), 0) FROM artifacts",
                    [],
                    |row| row.get::<_, i64>(0),
                )? as u64,
                mirrored_project_count: connection.query_row(
                    "SELECT COUNT(*) FROM projects WHERE source = 'mirrored'",
                    [],
                    |row| row.get::<_, i64>(0),
                )? as usize,
            })
        })
    }

    async fn save_tenant(&self, tenant: Tenant) -> Result<(), ApplicationError> {
        self.with_connection(|connection| {
            connection.execute(
                r#"
                INSERT INTO tenants (id, slug, display_name, mirroring_enabled, created_at)
                VALUES (?1, ?2, ?3, ?4, ?5)
                ON CONFLICT(id) DO UPDATE SET
                    slug = excluded.slug,
                    display_name = excluded.display_name,
                    mirroring_enabled = excluded.mirroring_enabled,
                    created_at = excluded.created_at
                "#,
                params![
                    uuid_string(tenant.id.into_inner()),
                    tenant.slug.as_str(),
                    tenant.display_name,
                    bool_i64(tenant.mirror_rule.enabled),
                    date_string(tenant.created_at),
                ],
            )?;
            Ok(())
        })
    }

    async fn list_tenants(&self) -> Result<Vec<Tenant>, ApplicationError> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, slug, display_name, mirroring_enabled, created_at FROM tenants ORDER BY slug",
            )?;
            collect_rows(statement.query_map([], map_tenant)?)
        })
    }

    async fn get_tenant_by_slug(&self, slug: &str) -> Result<Option<Tenant>, ApplicationError> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT id, slug, display_name, mirroring_enabled, created_at FROM tenants WHERE slug = ?1",
                    params![slug],
                    map_tenant,
                )
                .optional()
        })
    }

    async fn save_admin_user(&self, user: AdminUser) -> Result<(), ApplicationError> {
        self.with_connection(|connection| {
            connection.execute(
                r#"
                INSERT INTO admin_users (id, tenant_id, email, password_hash, is_superadmin, created_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                ON CONFLICT(email) DO UPDATE SET
                    id = excluded.id,
                    tenant_id = excluded.tenant_id,
                    password_hash = excluded.password_hash,
                    is_superadmin = excluded.is_superadmin,
                    created_at = excluded.created_at
                "#,
                params![
                    uuid_string(user.id.into_inner()),
                    user.tenant_id.map(|id| uuid_string(id.into_inner())),
                    user.email,
                    user.password_hash,
                    bool_i64(user.is_superadmin),
                    date_string(user.created_at),
                ],
            )?;
            Ok(())
        })
    }

    async fn get_admin_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<AdminUser>, ApplicationError> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    r#"
                    SELECT id, tenant_id, email, password_hash, is_superadmin, created_at
                    FROM admin_users
                    WHERE email = ?1
                    "#,
                    params![email],
                    map_admin_user,
                )
                .optional()
        })
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

        self.with_connection(|connection| {
            connection.execute(
                r#"
                INSERT INTO api_tokens (
                    id, tenant_id, label, secret_hash, scopes_json,
                    identity_issuer, identity_subject, identity_audience, identity_provider,
                    identity_claims_json, created_at, expires_at
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                ON CONFLICT(id) DO UPDATE SET
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
                params![
                    uuid_string(token.id.into_inner()),
                    uuid_string(token.tenant_id.into_inner()),
                    token.label,
                    token.secret_hash,
                    scopes_json,
                    identity_issuer,
                    identity_subject,
                    identity_audience,
                    identity_provider,
                    claims_json,
                    date_string(token.created_at),
                    token.expires_at.map(date_string),
                ],
            )?;
            Ok(())
        })
    }

    async fn list_api_tokens(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<ApiToken>, ApplicationError> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                r#"
                SELECT id, tenant_id, label, secret_hash, scopes_json,
                       identity_issuer, identity_subject, identity_audience, identity_provider,
                       identity_claims_json, created_at, expires_at
                FROM api_tokens
                WHERE tenant_id = ?1
                ORDER BY created_at DESC, label
                "#,
            )?;
            collect_rows(
                statement.query_map(params![uuid_string(tenant_id.into_inner())], map_api_token)?,
            )
        })
    }

    async fn revoke_api_token(
        &self,
        tenant_id: TenantId,
        token_id: TokenId,
    ) -> Result<(), ApplicationError> {
        self.with_connection(|connection| {
            connection.execute(
                "DELETE FROM api_tokens WHERE id = ?1 AND tenant_id = ?2",
                params![
                    uuid_string(token_id.into_inner()),
                    uuid_string(tenant_id.into_inner())
                ],
            )?;
            Ok(())
        })
    }

    async fn save_project(&self, project: Project) -> Result<(), ApplicationError> {
        self.with_connection(|connection| {
            connection.execute(
                r#"
                INSERT INTO projects (
                    id, tenant_id, original_name, normalized_name, source,
                    summary, description, created_at, updated_at
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                ON CONFLICT(id) DO UPDATE SET
                    tenant_id = excluded.tenant_id,
                    original_name = excluded.original_name,
                    normalized_name = excluded.normalized_name,
                    source = excluded.source,
                    summary = excluded.summary,
                    description = excluded.description,
                    created_at = excluded.created_at,
                    updated_at = excluded.updated_at
                "#,
                params![
                    uuid_string(project.id.into_inner()),
                    uuid_string(project.tenant_id.into_inner()),
                    project.name.original(),
                    project.name.normalized(),
                    project_source_str(&project.source),
                    project.summary,
                    project.description,
                    date_string(project.created_at),
                    date_string(project.updated_at),
                ],
            )?;
            Ok(())
        })
    }

    async fn list_projects(&self, tenant_id: TenantId) -> Result<Vec<Project>, ApplicationError> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                r#"
                SELECT id, tenant_id, original_name, source, summary, description, created_at, updated_at
                FROM projects
                WHERE tenant_id = ?1
                ORDER BY normalized_name
                "#,
            )?;
            collect_rows(statement.query_map(params![uuid_string(tenant_id.into_inner())], map_project)?)
        })
    }

    async fn search_projects(
        &self,
        tenant_id: TenantId,
        query: &str,
    ) -> Result<Vec<SearchHit>, ApplicationError> {
        let query = query.trim().to_ascii_lowercase();
        self.with_connection(|connection| {
            let tenant_slug = connection
                .query_row(
                    "SELECT slug FROM tenants WHERE id = ?1",
                    params![uuid_string(tenant_id.into_inner())],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .unwrap_or_default();

            let mut statement = connection.prepare(
                r#"
                SELECT id, original_name, normalized_name, source, summary
                FROM projects
                WHERE tenant_id = ?1
                  AND (?2 = '' OR lower(normalized_name || ' ' || summary) LIKE '%' || ?2 || '%')
                ORDER BY normalized_name
                "#,
            )?;
            let rows = statement.query_map(
                params![uuid_string(tenant_id.into_inner()), query],
                |row| {
                    let project_id = parse_uuid(row.get::<_, String>(0)?, 0)?;
                    let latest_version = latest_release_version(connection, project_id)?;
                    Ok(SearchHit {
                        tenant_slug: tenant_slug.clone(),
                        project_name: row.get(1)?,
                        normalized_name: row.get(2)?,
                        source: row.get(3)?,
                        summary: row.get(4)?,
                        latest_version,
                    })
                },
            )?;
            collect_rows(rows)
        })
    }

    async fn get_project_by_normalized_name(
        &self,
        tenant_id: TenantId,
        normalized_name: &str,
    ) -> Result<Option<Project>, ApplicationError> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    r#"
                    SELECT id, tenant_id, original_name, source, summary, description, created_at, updated_at
                    FROM projects
                    WHERE tenant_id = ?1 AND normalized_name = ?2
                    "#,
                    params![uuid_string(tenant_id.into_inner()), normalized_name],
                    map_project,
                )
                .optional()
        })
    }

    async fn save_release(&self, release: Release) -> Result<(), ApplicationError> {
        self.with_connection(|connection| {
            let (reason, changed_at) = yank_columns(&release.yanked);
            connection.execute(
                r#"
                INSERT INTO releases (id, project_id, version, yanked_reason, yanked_changed_at, created_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                ON CONFLICT(id) DO UPDATE SET
                    project_id = excluded.project_id,
                    version = excluded.version,
                    yanked_reason = excluded.yanked_reason,
                    yanked_changed_at = excluded.yanked_changed_at,
                    created_at = excluded.created_at
                "#,
                params![
                    uuid_string(release.id.into_inner()),
                    uuid_string(release.project_id.into_inner()),
                    release.version.as_str(),
                    reason,
                    changed_at,
                    date_string(release.created_at),
                ],
            )?;
            Ok(())
        })
    }

    async fn list_releases(&self, project_id: ProjectId) -> Result<Vec<Release>, ApplicationError> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                r#"
                SELECT id, project_id, version, yanked_reason, yanked_changed_at, created_at
                FROM releases
                WHERE project_id = ?1
                "#,
            )?;
            collect_rows(
                statement.query_map(params![uuid_string(project_id.into_inner())], map_release)?,
            )
        })
    }

    async fn get_release_by_version(
        &self,
        project_id: ProjectId,
        version: &ReleaseVersion,
    ) -> Result<Option<Release>, ApplicationError> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    r#"
                    SELECT id, project_id, version, yanked_reason, yanked_changed_at, created_at
                    FROM releases
                    WHERE project_id = ?1 AND version = ?2
                    "#,
                    params![uuid_string(project_id.into_inner()), version.as_str()],
                    map_release,
                )
                .optional()
        })
    }

    async fn delete_release(&self, release_id: ReleaseId) -> Result<(), ApplicationError> {
        self.with_connection(|connection| {
            connection.execute(
                "DELETE FROM releases WHERE id = ?1",
                params![uuid_string(release_id.into_inner())],
            )?;
            Ok(())
        })
    }

    async fn save_artifact(&self, artifact: Artifact) -> Result<(), ApplicationError> {
        let size_bytes = i64::try_from(artifact.size_bytes).map_err(|error| {
            ApplicationError::External(format!(
                "artifact `{}` is too large to store in sqlite metadata: {error}",
                artifact.filename
            ))
        })?;
        self.with_connection(|connection| {
            let (reason, changed_at) = yank_columns(&artifact.yanked);
            connection.execute(
                r#"
                INSERT INTO artifacts (
                    id, release_id, filename, kind, size_bytes, sha256, blake2b_256,
                    object_key, upstream_url, provenance_key, yanked_reason, yanked_changed_at,
                    created_at
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                ON CONFLICT(id) DO UPDATE SET
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
                params![
                    uuid_string(artifact.id.into_inner()),
                    uuid_string(artifact.release_id.into_inner()),
                    artifact.filename,
                    artifact_kind_str(&artifact.kind),
                    size_bytes,
                    artifact.digests.sha256,
                    artifact.digests.blake2b_256,
                    artifact.object_key,
                    artifact.upstream_url,
                    artifact.provenance_key,
                    reason,
                    changed_at,
                    date_string(artifact.created_at),
                ],
            )?;
            Ok(())
        })
    }

    async fn list_artifacts(
        &self,
        release_id: ReleaseId,
    ) -> Result<Vec<Artifact>, ApplicationError> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                r#"
                SELECT id, release_id, filename, kind, size_bytes, sha256, blake2b_256,
                       object_key, upstream_url, provenance_key, yanked_reason, yanked_changed_at,
                       created_at
                FROM artifacts
                WHERE release_id = ?1
                ORDER BY filename
                "#,
            )?;
            collect_rows(
                statement.query_map(params![uuid_string(release_id.into_inner())], map_artifact)?,
            )
        })
    }

    async fn get_artifact_by_filename(
        &self,
        release_id: ReleaseId,
        filename: &str,
    ) -> Result<Option<Artifact>, ApplicationError> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    r#"
                    SELECT id, release_id, filename, kind, size_bytes, sha256, blake2b_256,
                           object_key, upstream_url, provenance_key, yanked_reason, yanked_changed_at,
                           created_at
                    FROM artifacts
                    WHERE release_id = ?1 AND filename = ?2
                    "#,
                    params![uuid_string(release_id.into_inner()), filename],
                    map_artifact,
                )
                .optional()
        })
    }

    async fn delete_artifact(&self, artifact_id: ArtifactId) -> Result<(), ApplicationError> {
        self.with_connection(|connection| {
            connection.execute(
                "DELETE FROM artifacts WHERE id = ?1",
                params![uuid_string(artifact_id.into_inner())],
            )?;
            Ok(())
        })
    }

    async fn save_attestation(
        &self,
        attestation: AttestationBundle,
    ) -> Result<(), ApplicationError> {
        self.with_connection(|connection| {
            connection.execute(
                r#"
                INSERT INTO attestations (artifact_id, media_type, payload, source, recorded_at)
                VALUES (?1, ?2, ?3, ?4, ?5)
                ON CONFLICT(artifact_id) DO UPDATE SET
                    media_type = excluded.media_type,
                    payload = excluded.payload,
                    source = excluded.source,
                    recorded_at = excluded.recorded_at
                "#,
                params![
                    uuid_string(attestation.artifact_id.into_inner()),
                    attestation.media_type,
                    attestation.payload,
                    attestation_source_str(&attestation.source),
                    date_string(attestation.recorded_at),
                ],
            )?;
            Ok(())
        })
    }

    async fn get_attestation_by_artifact(
        &self,
        artifact_id: ArtifactId,
    ) -> Result<Option<AttestationBundle>, ApplicationError> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    r#"
                    SELECT artifact_id, media_type, payload, source, recorded_at
                    FROM attestations
                    WHERE artifact_id = ?1
                    "#,
                    params![uuid_string(artifact_id.into_inner())],
                    map_attestation,
                )
                .optional()
        })
    }

    async fn save_trusted_publisher(
        &self,
        publisher: TrustedPublisher,
    ) -> Result<(), ApplicationError> {
        let claim_rules_json = serde_json::to_string(&publisher.claim_rules).map_err(json_error)?;
        self.with_connection(|connection| {
            connection.execute(
                r#"
                INSERT INTO trusted_publishers (
                    id, tenant_id, project_original_name, project_normalized_name,
                    provider, issuer, audience, claim_rules_json, created_at
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                ON CONFLICT(id) DO UPDATE SET
                    tenant_id = excluded.tenant_id,
                    project_original_name = excluded.project_original_name,
                    project_normalized_name = excluded.project_normalized_name,
                    provider = excluded.provider,
                    issuer = excluded.issuer,
                    audience = excluded.audience,
                    claim_rules_json = excluded.claim_rules_json,
                    created_at = excluded.created_at
                "#,
                params![
                    uuid_string(publisher.id.into_inner()),
                    uuid_string(publisher.tenant_id.into_inner()),
                    publisher.project_name.original(),
                    publisher.project_name.normalized(),
                    provider_str(&publisher.provider),
                    publisher.issuer,
                    publisher.audience,
                    claim_rules_json,
                    date_string(publisher.created_at),
                ],
            )?;
            Ok(())
        })
    }

    async fn list_trusted_publishers(
        &self,
        tenant_id: TenantId,
        normalized_project_name: &str,
    ) -> Result<Vec<TrustedPublisher>, ApplicationError> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                r#"
                SELECT id, tenant_id, project_original_name, provider, issuer, audience,
                       claim_rules_json, created_at
                FROM trusted_publishers
                WHERE tenant_id = ?1
                  AND (?2 = '' OR project_normalized_name = ?2)
                ORDER BY created_at DESC
                "#,
            )?;
            collect_rows(statement.query_map(
                params![uuid_string(tenant_id.into_inner()), normalized_project_name],
                map_trusted_publisher,
            )?)
        })
    }

    async fn delete_project(&self, project_id: ProjectId) -> Result<(), ApplicationError> {
        self.with_connection(|connection| {
            connection.execute(
                "DELETE FROM projects WHERE id = ?1",
                params![uuid_string(project_id.into_inner())],
            )?;
            Ok(())
        })
    }
}

fn migrate(connection: &Connection) -> Result<(), ApplicationError> {
    connection
        .execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS tenants (
                id TEXT PRIMARY KEY,
                slug TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                mirroring_enabled INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS admin_users (
                id TEXT PRIMARY KEY,
                tenant_id TEXT REFERENCES tenants(id) ON DELETE SET NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                is_superadmin INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS api_tokens (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
                label TEXT NOT NULL,
                secret_hash TEXT NOT NULL,
                scopes_json TEXT NOT NULL,
                identity_issuer TEXT,
                identity_subject TEXT,
                identity_audience TEXT,
                identity_provider TEXT,
                identity_claims_json TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT
            );

            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
                original_name TEXT NOT NULL,
                normalized_name TEXT NOT NULL,
                source TEXT NOT NULL,
                summary TEXT NOT NULL,
                description TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(tenant_id, normalized_name)
            );

            CREATE TABLE IF NOT EXISTS releases (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                version TEXT NOT NULL,
                yanked_reason TEXT,
                yanked_changed_at TEXT,
                created_at TEXT NOT NULL,
                UNIQUE(project_id, version)
            );

            CREATE TABLE IF NOT EXISTS artifacts (
                id TEXT PRIMARY KEY,
                release_id TEXT NOT NULL REFERENCES releases(id) ON DELETE CASCADE,
                filename TEXT NOT NULL,
                kind TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                blake2b_256 TEXT,
                object_key TEXT NOT NULL,
                upstream_url TEXT,
                provenance_key TEXT,
                yanked_reason TEXT,
                yanked_changed_at TEXT,
                created_at TEXT NOT NULL,
                UNIQUE(release_id, filename)
            );

            CREATE TABLE IF NOT EXISTS attestations (
                artifact_id TEXT PRIMARY KEY REFERENCES artifacts(id) ON DELETE CASCADE,
                media_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                source TEXT NOT NULL,
                recorded_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS trusted_publishers (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
                project_original_name TEXT NOT NULL,
                project_normalized_name TEXT NOT NULL,
                provider TEXT NOT NULL,
                issuer TEXT NOT NULL,
                audience TEXT NOT NULL,
                claim_rules_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_api_tokens_tenant ON api_tokens(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_projects_tenant ON projects(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_releases_project ON releases(project_id);
            CREATE INDEX IF NOT EXISTS idx_artifacts_release ON artifacts(release_id);
            CREATE INDEX IF NOT EXISTS idx_trusted_publishers_tenant_project
                ON trusted_publishers(tenant_id, project_normalized_name);
            "#,
        )
        .map_err(sqlite_error)
}

fn count_table(connection: &Connection, table: &str) -> rusqlite::Result<usize> {
    let sql = format!("SELECT COUNT(*) FROM {table}");
    connection
        .query_row(&sql, [], |row| row.get::<_, i64>(0))
        .map(|count| count as usize)
}

fn latest_release_version(
    connection: &Connection,
    project_id: Uuid,
) -> rusqlite::Result<Option<String>> {
    let mut statement = connection.prepare("SELECT version FROM releases WHERE project_id = ?1")?;
    let versions = collect_rows(
        statement.query_map(params![uuid_string(project_id)], |row| {
            domain_value(ReleaseVersion::new(row.get::<_, String>(0)?), 0)
        })?,
    )?;
    Ok(versions
        .into_iter()
        .max()
        .map(|version| version.as_str().to_string()))
}

fn map_tenant(row: &Row<'_>) -> rusqlite::Result<Tenant> {
    Tenant::new(
        TenantId::new(parse_uuid(row.get(0)?, 0)?),
        domain_value(TenantSlug::new(row.get::<_, String>(1)?), 1)?,
        row.get::<_, String>(2)?,
        MirrorRule {
            enabled: i64_bool(row.get(3)?),
        },
        parse_datetime(row.get(4)?, 4)?,
    )
    .map_err(|error| rusqlite::Error::FromSqlConversionFailure(2, Type::Text, Box::new(error)))
}

fn map_admin_user(row: &Row<'_>) -> rusqlite::Result<AdminUser> {
    Ok(AdminUser {
        id: AdminUserId::new(parse_uuid(row.get(0)?, 0)?),
        tenant_id: row
            .get::<_, Option<String>>(1)?
            .map(|value| parse_uuid(value, 1).map(TenantId::new))
            .transpose()?,
        email: row.get(2)?,
        password_hash: row.get(3)?,
        is_superadmin: i64_bool(row.get(4)?),
        created_at: parse_datetime(row.get(5)?, 5)?,
    })
}

fn map_api_token(row: &Row<'_>) -> rusqlite::Result<ApiToken> {
    let identity = parse_publish_identity(
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
    )?;

    Ok(ApiToken {
        id: TokenId::new(parse_uuid(row.get(0)?, 0)?),
        tenant_id: TenantId::new(parse_uuid(row.get(1)?, 1)?),
        label: row.get(2)?,
        secret_hash: row.get(3)?,
        scopes: parse_scopes_json(row.get(4)?, 4)?,
        publish_identity: identity,
        created_at: parse_datetime(row.get(10)?, 10)?,
        expires_at: row
            .get::<_, Option<String>>(11)?
            .map(|value| parse_datetime(value, 11))
            .transpose()?,
    })
}

fn map_project(row: &Row<'_>) -> rusqlite::Result<Project> {
    Ok(Project {
        id: ProjectId::new(parse_uuid(row.get(0)?, 0)?),
        tenant_id: TenantId::new(parse_uuid(row.get(1)?, 1)?),
        name: domain_value(ProjectName::new(row.get::<_, String>(2)?), 2)?,
        source: parse_project_source(row.get::<_, String>(3)?, 3)?,
        summary: row.get(4)?,
        description: row.get(5)?,
        created_at: parse_datetime(row.get(6)?, 6)?,
        updated_at: parse_datetime(row.get(7)?, 7)?,
    })
}

fn map_release(row: &Row<'_>) -> rusqlite::Result<Release> {
    Ok(Release {
        id: ReleaseId::new(parse_uuid(row.get(0)?, 0)?),
        project_id: ProjectId::new(parse_uuid(row.get(1)?, 1)?),
        version: domain_value(ReleaseVersion::new(row.get::<_, String>(2)?), 2)?,
        yanked: parse_yank(row.get(3)?, row.get(4)?, 3)?,
        created_at: parse_datetime(row.get(5)?, 5)?,
    })
}

fn map_artifact(row: &Row<'_>) -> rusqlite::Result<Artifact> {
    let size_bytes = row.get::<_, i64>(4)?;
    if size_bytes < 0 {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            4,
            Type::Integer,
            "artifact size cannot be negative".into(),
        ));
    }

    Ok(Artifact {
        id: ArtifactId::new(parse_uuid(row.get(0)?, 0)?),
        release_id: ReleaseId::new(parse_uuid(row.get(1)?, 1)?),
        filename: row.get(2)?,
        kind: parse_artifact_kind(row.get(3)?, 3)?,
        size_bytes: size_bytes as u64,
        digests: domain_value(
            DigestSet::new(row.get::<_, String>(5)?, row.get::<_, Option<String>>(6)?),
            5,
        )?,
        object_key: row.get(7)?,
        upstream_url: row.get(8)?,
        provenance_key: row.get(9)?,
        yanked: parse_yank(row.get(10)?, row.get(11)?, 10)?,
        created_at: parse_datetime(row.get(12)?, 12)?,
    })
}

fn map_attestation(row: &Row<'_>) -> rusqlite::Result<AttestationBundle> {
    Ok(AttestationBundle {
        artifact_id: ArtifactId::new(parse_uuid(row.get(0)?, 0)?),
        media_type: row.get(1)?,
        payload: row.get(2)?,
        source: parse_attestation_source(row.get(3)?, 3)?,
        recorded_at: parse_datetime(row.get(4)?, 4)?,
    })
}

fn map_trusted_publisher(row: &Row<'_>) -> rusqlite::Result<TrustedPublisher> {
    Ok(TrustedPublisher {
        id: TrustedPublisherId::new(parse_uuid(row.get(0)?, 0)?),
        tenant_id: TenantId::new(parse_uuid(row.get(1)?, 1)?),
        project_name: domain_value(ProjectName::new(row.get::<_, String>(2)?), 2)?,
        provider: parse_provider(row.get(3)?, 3)?,
        issuer: row.get(4)?,
        audience: row.get(5)?,
        claim_rules: parse_claims_json(row.get(6)?, 6)?,
        created_at: parse_datetime(row.get(7)?, 7)?,
    })
}

fn parse_publish_identity(
    issuer: Option<String>,
    subject: Option<String>,
    audience: Option<String>,
    provider: Option<String>,
    claims_json: Option<String>,
) -> rusqlite::Result<Option<PublishIdentity>> {
    match (issuer, subject, audience, provider) {
        (Some(issuer), Some(subject), Some(audience), Some(provider)) => {
            Ok(Some(PublishIdentity {
                issuer,
                subject,
                audience,
                provider: parse_provider(provider, 8)?,
                claims: parse_claims_json(claims_json.unwrap_or_else(|| "{}".into()), 9)?,
            }))
        }
        (None, None, None, None) => Ok(None),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            5,
            Type::Text,
            "incomplete publish identity columns".into(),
        )),
    }
}

fn parse_scopes_json(value: String, column: usize) -> rusqlite::Result<Vec<TokenScope>> {
    let scopes: Vec<String> = parse_json(value, column)?;
    scopes
        .into_iter()
        .map(|scope| parse_token_scope(scope, column))
        .collect()
}

fn parse_claims_json(value: String, column: usize) -> rusqlite::Result<BTreeMap<String, String>> {
    parse_json(value, column)
}

fn parse_json<T: serde::de::DeserializeOwned>(value: String, column: usize) -> rusqlite::Result<T> {
    serde_json::from_str(&value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(column, Type::Text, Box::new(error))
    })
}

fn parse_uuid(value: String, column: usize) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(&value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(column, Type::Text, Box::new(error))
    })
}

fn parse_datetime(value: String, column: usize) -> rusqlite::Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(&value)
        .map(|datetime| datetime.with_timezone(&Utc))
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(column, Type::Text, Box::new(error))
        })
}

fn domain_value<T, E>(value: Result<T, E>, column: usize) -> rusqlite::Result<T>
where
    E: std::error::Error + Send + Sync + 'static,
{
    value.map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(column, Type::Text, Box::new(error))
    })
}

fn parse_yank(
    reason: Option<String>,
    changed_at: Option<String>,
    column: usize,
) -> rusqlite::Result<Option<YankState>> {
    match (reason, changed_at) {
        (None, None) => Ok(None),
        (reason, Some(changed_at)) => Ok(Some(YankState {
            reason,
            changed_at: parse_datetime(changed_at, column)?,
        })),
        (Some(reason), None) => Ok(Some(YankState {
            reason: Some(reason),
            changed_at: Utc::now(),
        })),
    }
}

fn parse_project_source(value: String, column: usize) -> rusqlite::Result<ProjectSource> {
    match value.as_str() {
        "local" => Ok(ProjectSource::Local),
        "mirrored" => Ok(ProjectSource::Mirrored),
        _ => Err(invalid_enum(column, "project source", value)),
    }
}

fn parse_artifact_kind(value: String, column: usize) -> rusqlite::Result<ArtifactKind> {
    match value.as_str() {
        "wheel" => Ok(ArtifactKind::Wheel),
        "sdist" => Ok(ArtifactKind::SourceDistribution),
        _ => Err(invalid_enum(column, "artifact kind", value)),
    }
}

fn parse_token_scope(value: String, column: usize) -> rusqlite::Result<TokenScope> {
    match value.as_str() {
        "read" => Ok(TokenScope::Read),
        "publish" => Ok(TokenScope::Publish),
        "admin" => Ok(TokenScope::Admin),
        _ => Err(invalid_enum(column, "token scope", value)),
    }
}

fn parse_provider(value: String, column: usize) -> rusqlite::Result<TrustedPublisherProvider> {
    match value.as_str() {
        "github-actions" => Ok(TrustedPublisherProvider::GitHubActions),
        "gitlab" => Ok(TrustedPublisherProvider::GitLab),
        _ => Err(invalid_enum(column, "trusted publisher provider", value)),
    }
}

fn parse_attestation_source(value: String, column: usize) -> rusqlite::Result<AttestationSource> {
    match value.as_str() {
        "mirrored" => Ok(AttestationSource::Mirrored),
        "trusted-publish" => Ok(AttestationSource::TrustedPublish),
        _ => Err(invalid_enum(column, "attestation source", value)),
    }
}

fn invalid_enum(column: usize, label: &'static str, value: String) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column,
        Type::Text,
        format!("unknown {label} `{value}`").into(),
    )
}

fn collect_rows<T>(rows: impl Iterator<Item = rusqlite::Result<T>>) -> rusqlite::Result<Vec<T>> {
    rows.collect()
}

fn yank_columns(yanked: &Option<YankState>) -> (Option<String>, Option<String>) {
    yanked
        .as_ref()
        .map(|state| (state.reason.clone(), Some(date_string(state.changed_at))))
        .unwrap_or((None, None))
}

fn date_string(value: DateTime<Utc>) -> String {
    value.to_rfc3339()
}

fn uuid_string(value: Uuid) -> String {
    value.to_string()
}

fn bool_i64(value: bool) -> i64 {
    i64::from(value)
}

fn i64_bool(value: i64) -> bool {
    value != 0
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

fn sqlite_error(error: rusqlite::Error) -> ApplicationError {
    ApplicationError::External(format!("sqlite metadata store failure: {error}"))
}

fn json_error(error: serde_json::Error) -> ApplicationError {
    ApplicationError::External(format!("could not serialize sqlite metadata JSON: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[tokio::test]
    async fn persists_core_registry_state_across_reopen() {
        let path = std::env::temp_dir().join(format!("pyregistry-{}.sqlite3", Uuid::new_v4()));
        let tenant_id = TenantId::new(Uuid::new_v4());
        let project_id = ProjectId::new(Uuid::new_v4());
        let release_id = ReleaseId::new(Uuid::new_v4());
        let artifact_id = ArtifactId::new(Uuid::new_v4());
        let now = Utc::now();

        {
            let store = SqliteRegistryStore::open(&path).expect("open sqlite store");
            let tenant = Tenant::new(
                tenant_id,
                TenantSlug::new("acme").expect("tenant slug"),
                "Acme Corp",
                MirrorRule { enabled: true },
                now,
            )
            .expect("tenant");
            store.save_tenant(tenant).await.expect("save tenant");

            let project = Project::new(
                project_id,
                tenant_id,
                ProjectName::new("demo-pkg").expect("project name"),
                ProjectSource::Local,
                "summary",
                "description",
                now,
            );
            store.save_project(project).await.expect("save project");

            store
                .save_release(Release {
                    id: release_id,
                    project_id,
                    version: ReleaseVersion::new("1.0.0").expect("version"),
                    yanked: None,
                    created_at: now,
                })
                .await
                .expect("save release");

            store
                .save_artifact(
                    Artifact::new(
                        artifact_id,
                        release_id,
                        "demo_pkg-1.0.0-py3-none-any.whl",
                        42,
                        DigestSet::new("a".repeat(64), Some("b".repeat(64))).expect("digests"),
                        "acme/demo-pkg/1.0.0/demo_pkg-1.0.0-py3-none-any.whl",
                        now,
                    )
                    .expect("artifact"),
                )
                .await
                .expect("save artifact");

            store
                .save_api_token(ApiToken {
                    id: TokenId::new(Uuid::new_v4()),
                    tenant_id,
                    label: "read".into(),
                    secret_hash: "hash".into(),
                    scopes: vec![TokenScope::Read],
                    publish_identity: None,
                    created_at: now,
                    expires_at: Some(now + Duration::hours(1)),
                })
                .await
                .expect("save token");
        }

        let reopened = SqliteRegistryStore::open(&path).expect("reopen sqlite store");
        let overview = reopened.registry_overview().await.expect("overview");
        assert_eq!(overview.tenant_count, 1);
        assert_eq!(overview.project_count, 1);
        assert_eq!(overview.release_count, 1);
        assert_eq!(overview.artifact_count, 1);
        assert_eq!(overview.total_storage_bytes, 42);

        let hits = reopened
            .search_projects(tenant_id, "demo")
            .await
            .expect("search");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].latest_version.as_deref(), Some("1.0.0"));

        let tokens = reopened.list_api_tokens(tenant_id).await.expect("tokens");
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].scopes, vec![TokenScope::Read]);

        let _ = fs::remove_file(path);
    }
}
