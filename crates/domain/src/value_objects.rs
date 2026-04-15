use crate::{ArtifactId, DomainError, TenantId, TrustedPublisherId};
use chrono::{DateTime, Utc};
use regex::Regex;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::LazyLock;

static TENANT_SLUG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9]+(?:-[a-z0-9]+)*$").expect("valid tenant slug regex"));
static PROJECT_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$").expect("valid project name regex")
});
static PROJECT_NAME_SEPARATOR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[-_.]+").expect("valid project name regex"));
static RELEASE_VERSION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._+\-!]*$").expect("valid release version regex")
});
static SHA256_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-fA-F0-9]{64}$").expect("valid sha256 regex"));

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TenantSlug(String);

impl TenantSlug {
    pub fn new(input: impl Into<String>) -> Result<Self, DomainError> {
        let value = input.into().trim().to_ascii_lowercase();

        if value.is_empty() || !TENANT_SLUG_RE.is_match(&value) {
            return Err(DomainError::InvalidValue {
                field: "tenant_slug",
                message: "slug must contain only lowercase letters, numbers, and dashes".into(),
            });
        }

        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProjectName {
    original: String,
    normalized: String,
}

impl ProjectName {
    pub fn new(input: impl Into<String>) -> Result<Self, DomainError> {
        let original = input.into().trim().to_string();

        if original.is_empty() || !PROJECT_NAME_RE.is_match(&original) {
            return Err(DomainError::InvalidValue {
                field: "project_name",
                message:
                    "project name must contain only letters, numbers, dots, dashes, and underscores"
                        .into(),
            });
        }

        Ok(Self {
            normalized: normalize_project_name(&original),
            original,
        })
    }

    #[must_use]
    pub fn original(&self) -> &str {
        &self.original
    }

    #[must_use]
    pub fn normalized(&self) -> &str {
        &self.normalized
    }
}

fn normalize_project_name(input: &str) -> String {
    PROJECT_NAME_SEPARATOR_RE
        .replace_all(&input.trim().to_ascii_lowercase(), "-")
        .to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReleaseVersion(String);

impl ReleaseVersion {
    pub fn new(input: impl Into<String>) -> Result<Self, DomainError> {
        let value = input.into().trim().to_string();

        if value.is_empty() || !RELEASE_VERSION_RE.is_match(&value) {
            return Err(DomainError::InvalidValue {
                field: "release_version",
                message: "version must be non-empty and contain only packaging-safe characters"
                    .into(),
            });
        }

        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl PartialOrd for ReleaseVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ReleaseVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        match (
            pep440::Version::parse(self.as_str()),
            pep440::Version::parse(other.as_str()),
        ) {
            (Some(left), Some(right)) => left.cmp(&right),
            _ => self.as_str().cmp(other.as_str()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactKind {
    Wheel,
    SourceDistribution,
}

impl ArtifactKind {
    pub fn from_filename(filename: &str) -> Result<Self, DomainError> {
        if filename.ends_with(".whl") {
            return Ok(Self::Wheel);
        }

        if filename.ends_with(".tar.gz")
            || filename.ends_with(".tar.bz2")
            || filename.ends_with(".tar.xz")
            || filename.ends_with(".tgz")
            || filename.ends_with(".zip")
        {
            return Ok(Self::SourceDistribution);
        }

        Err(DomainError::InvalidValue {
            field: "artifact_filename",
            message: "artifact must be a wheel or source distribution".into(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectSource {
    Local,
    Mirrored,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenScope {
    Read,
    Publish,
    Admin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestSet {
    pub sha256: String,
    pub blake2b_256: Option<String>,
}

impl DigestSet {
    pub fn new(
        sha256: impl Into<String>,
        blake2b_256: Option<String>,
    ) -> Result<Self, DomainError> {
        let sha256 = sha256.into();

        if !SHA256_RE.is_match(&sha256) {
            return Err(DomainError::InvalidValue {
                field: "sha256",
                message: "sha256 digest must be 64 hexadecimal characters".into(),
            });
        }

        if let Some(ref digest) = blake2b_256
            && !SHA256_RE.is_match(digest)
        {
            return Err(DomainError::InvalidValue {
                field: "blake2b_256",
                message: "blake2b digest must be 64 hexadecimal characters".into(),
            });
        }

        Ok(Self {
            sha256: sha256.to_ascii_lowercase(),
            blake2b_256: blake2b_256.map(|value| value.to_ascii_lowercase()),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YankState {
    pub reason: Option<String>,
    pub changed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeletionMode {
    Yank,
    Purge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorRule {
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustedPublisherProvider {
    GitHubActions,
    GitLab,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishIdentity {
    pub issuer: String,
    pub subject: String,
    pub audience: String,
    pub provider: TrustedPublisherProvider,
    pub claims: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationSource {
    Mirrored,
    TrustedPublish,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationBundle {
    pub artifact_id: ArtifactId,
    pub media_type: String,
    pub payload: String,
    pub source: AttestationSource,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedPublisher {
    pub id: TrustedPublisherId,
    pub tenant_id: TenantId,
    pub project_name: ProjectName,
    pub provider: TrustedPublisherProvider,
    pub issuer: String,
    pub audience: String,
    pub claim_rules: BTreeMap<String, String>,
    pub created_at: DateTime<Utc>,
}

impl TrustedPublisher {
    pub fn matches(&self, identity: &PublishIdentity) -> Result<(), DomainError> {
        if self.provider != identity.provider {
            return Err(DomainError::TrustedPublisherMismatch);
        }

        if self.issuer != identity.issuer || self.audience != identity.audience {
            return Err(DomainError::TrustedPublisherMismatch);
        }

        for (claim, expected) in &self.claim_rules {
            let actual = identity.claims.get(claim);
            if actual != Some(expected) {
                return Err(DomainError::TrustedPublisherMismatch);
            }
        }

        Ok(())
    }
}
