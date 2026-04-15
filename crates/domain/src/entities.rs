use crate::{
    AdminUserId, ArtifactId, ArtifactKind, AuditEventId, DigestSet, DomainError, MirrorRule,
    ProjectId, ProjectName, ProjectSource, PublishIdentity, ReleaseId, ReleaseVersion, TenantId,
    TenantSlug, TokenId, TokenScope, YankState,
};
use chrono::{DateTime, Utc};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tenant {
    pub id: TenantId,
    pub slug: TenantSlug,
    pub display_name: String,
    pub mirror_rule: MirrorRule,
    pub created_at: DateTime<Utc>,
}

impl Tenant {
    pub fn new(
        id: TenantId,
        slug: TenantSlug,
        display_name: impl Into<String>,
        mirror_rule: MirrorRule,
        created_at: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        let display_name = display_name.into().trim().to_string();
        if display_name.is_empty() {
            return Err(DomainError::InvalidValue {
                field: "tenant_display_name",
                message: "display name cannot be empty".into(),
            });
        }

        Ok(Self {
            id,
            slug,
            display_name,
            mirror_rule,
            created_at,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminUser {
    pub id: AdminUserId,
    pub tenant_id: Option<TenantId>,
    pub email: String,
    pub password_hash: String,
    pub is_superadmin: bool,
    pub created_at: DateTime<Utc>,
}

impl AdminUser {
    #[must_use]
    pub fn new(user: Self) -> Self {
        user
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiToken {
    pub id: TokenId,
    pub tenant_id: TenantId,
    pub label: String,
    pub secret_hash: String,
    pub scopes: Vec<TokenScope>,
    pub publish_identity: Option<PublishIdentity>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl ApiToken {
    #[must_use]
    pub fn new(token: Self) -> Self {
        token
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    pub id: ProjectId,
    pub tenant_id: TenantId,
    pub name: ProjectName,
    pub source: ProjectSource,
    pub summary: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Project {
    pub fn new(
        id: ProjectId,
        tenant_id: TenantId,
        name: ProjectName,
        source: ProjectSource,
        summary: impl Into<String>,
        description: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            tenant_id,
            name,
            source,
            summary: summary.into(),
            description: description.into(),
            created_at: now,
            updated_at: now,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub id: ReleaseId,
    pub project_id: ProjectId,
    pub version: ReleaseVersion,
    pub yanked: Option<YankState>,
    pub created_at: DateTime<Utc>,
}

impl Release {
    #[must_use]
    pub fn new(release: Self) -> Self {
        release
    }

    pub fn yank(&mut self, reason: Option<String>, now: DateTime<Utc>) {
        self.yanked = Some(YankState {
            reason,
            changed_at: now,
        });
    }

    pub fn unyank(&mut self) {
        self.yanked = None;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    pub id: ArtifactId,
    pub release_id: ReleaseId,
    pub filename: String,
    pub kind: ArtifactKind,
    pub size_bytes: u64,
    pub digests: DigestSet,
    pub object_key: String,
    pub upstream_url: Option<String>,
    pub provenance_key: Option<String>,
    pub yanked: Option<YankState>,
    pub created_at: DateTime<Utc>,
}

impl Artifact {
    pub fn new(
        id: ArtifactId,
        release_id: ReleaseId,
        filename: impl Into<String>,
        size_bytes: u64,
        digests: DigestSet,
        object_key: impl Into<String>,
        created_at: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        let filename = filename.into();
        validate_artifact_filename_segment(&filename)?;
        let kind = ArtifactKind::from_filename(&filename)?;

        Ok(Self {
            id,
            release_id,
            filename,
            kind,
            size_bytes,
            digests,
            object_key: object_key.into(),
            upstream_url: None,
            provenance_key: None,
            yanked: None,
            created_at,
        })
    }

    pub fn yank(&mut self, reason: Option<String>, now: DateTime<Utc>) {
        self.yanked = Some(YankState {
            reason,
            changed_at: now,
        });
    }

    pub fn unyank(&mut self) {
        self.yanked = None;
    }
}

fn validate_artifact_filename_segment(filename: &str) -> Result<(), DomainError> {
    if filename.is_empty()
        || filename == "."
        || filename == ".."
        || filename.contains('/')
        || filename.contains('\\')
        || filename.contains("..")
    {
        return Err(DomainError::InvalidValue {
            field: "artifact_filename",
            message: "artifact filename must be a single safe path segment".into(),
        });
    }

    Ok(())
}

pub fn ensure_unique_filenames(artifacts: &[Artifact]) -> Result<(), DomainError> {
    let mut seen = std::collections::HashSet::new();
    for artifact in artifacts {
        if !seen.insert(artifact.filename.clone()) {
            return Err(DomainError::DuplicateArtifactFilename(
                artifact.filename.clone(),
            ));
        }
    }
    Ok(())
}

pub fn ensure_purge_allowed(source: &ProjectSource) -> Result<(), DomainError> {
    if matches!(source, ProjectSource::Mirrored) {
        return Err(DomainError::MirroredProjectPurgeForbidden);
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub id: AuditEventId,
    pub occurred_at: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub tenant_slug: Option<String>,
    pub target: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

impl AuditEvent {
    pub fn new(
        id: AuditEventId,
        occurred_at: DateTime<Utc>,
        actor: impl Into<String>,
        action: impl Into<String>,
        tenant_slug: Option<String>,
        target: Option<String>,
        metadata: BTreeMap<String, String>,
    ) -> Result<Self, DomainError> {
        let actor = required_audit_text("audit_actor", actor.into())?;
        let action = required_audit_text("audit_action", action.into())?;
        let tenant_slug = optional_audit_text("audit_tenant_slug", tenant_slug)?;
        let target = optional_audit_text("audit_target", target)?;
        let metadata = normalize_audit_metadata(metadata)?;

        Ok(Self {
            id,
            occurred_at,
            actor,
            action,
            tenant_slug,
            target,
            metadata,
        })
    }
}

fn required_audit_text(field: &'static str, value: String) -> Result<String, DomainError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(DomainError::InvalidValue {
            field,
            message: "value cannot be empty".into(),
        });
    }

    Ok(value)
}

fn optional_audit_text(
    field: &'static str,
    value: Option<String>,
) -> Result<Option<String>, DomainError> {
    value
        .map(|value| required_audit_text(field, value))
        .transpose()
}

fn normalize_audit_metadata(
    metadata: BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, DomainError> {
    let mut normalized = BTreeMap::new();
    for (key, value) in metadata {
        let key = required_audit_text("audit_metadata_key", key)?;
        let value = value.trim().to_string();
        if !value.is_empty() {
            normalized.insert(key, value);
        }
    }

    Ok(normalized)
}
