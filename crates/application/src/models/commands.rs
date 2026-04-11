use chrono::{DateTime, Utc};
use pyregistry_domain::{DeletionMode, TokenScope, TrustedPublisherProvider};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct RecordAuditEventCommand {
    pub actor: String,
    pub action: String,
    pub tenant_slug: Option<String>,
    pub target: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTrailEntry {
    pub occurred_at: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub tenant_slug: Option<String>,
    pub target: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct CreateTenantCommand {
    pub slug: String,
    pub display_name: String,
    pub mirroring_enabled: bool,
    pub admin_email: String,
    pub admin_password: String,
}

#[derive(Debug, Clone)]
pub struct IssueApiTokenCommand {
    pub tenant_slug: String,
    pub label: String,
    pub scopes: Vec<TokenScope>,
    pub ttl_hours: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct IssuedApiToken {
    pub label: String,
    pub secret: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct UploadArtifactCommand {
    pub tenant_slug: String,
    pub project_name: String,
    pub version: String,
    pub filename: String,
    pub summary: String,
    pub description: String,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RegisterTrustedPublisherCommand {
    pub tenant_slug: String,
    pub project_name: String,
    pub provider: TrustedPublisherProvider,
    pub issuer: String,
    pub audience: String,
    pub claim_rules: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct MintOidcPublishTokenCommand {
    pub tenant_slug: String,
    pub project_name: String,
    pub oidc_token: String,
}

#[derive(Debug, Clone)]
pub struct DeletionCommand {
    pub tenant_slug: String,
    pub project_name: String,
    pub version: Option<String>,
    pub filename: Option<String>,
    pub reason: Option<String>,
    pub mode: DeletionMode,
}

#[derive(Debug, Clone)]
pub struct MirroredArtifactSnapshot {
    pub filename: String,
    pub version: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub blake2b_256: Option<String>,
    pub download_url: String,
    pub provenance_payload: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MirroredProjectSnapshot {
    pub canonical_name: String,
    pub summary: String,
    pub description: String,
    pub artifacts: Vec<MirroredArtifactSnapshot>,
}

#[derive(Debug, Clone)]
pub struct AuditWheelCommand {
    pub project_name: String,
    pub wheel_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct AuditStoredWheelCommand {
    pub tenant_slug: String,
    pub project_name: String,
    pub version: String,
    pub filename: String,
}

#[derive(Debug, Clone)]
pub struct ValidateDistributionCommand {
    pub file_path: PathBuf,
    pub expected_sha256: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ValidateRegistryDistributionsCommand {
    pub tenant_slug: Option<String>,
    pub project_name: Option<String>,
    pub parallelism: usize,
}
