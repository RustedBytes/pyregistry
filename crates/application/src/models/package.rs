use super::{ArtifactSecurityDetails, PackageSecuritySummary};
use pyregistry_domain::{Artifact, Release};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct ReleaseArtifacts {
    pub release: Release,
    pub artifacts: Vec<Artifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleProject {
    pub name: String,
    pub normalized_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleArtifactLink {
    pub filename: String,
    pub version: String,
    pub sha256: String,
    pub url: String,
    pub provenance_url: Option<String>,
    pub yanked_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleProjectPage {
    pub tenant_slug: String,
    pub project_name: String,
    pub artifacts: Vec<SimpleArtifactLink>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceDescriptor {
    pub filename: String,
    pub media_type: String,
    pub payload: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageArtifactDetails {
    pub filename: String,
    pub version: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub yanked_reason: Option<String>,
    pub security: ArtifactSecurityDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageReleaseDetails {
    pub version: String,
    pub yanked_reason: Option<String>,
    pub artifacts: Vec<PackageArtifactDetails>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedPublisherDescriptor {
    pub provider: String,
    pub issuer: String,
    pub audience: String,
    pub project_name: String,
    pub claim_rules: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageDetails {
    pub tenant_slug: String,
    pub project_name: String,
    pub normalized_name: String,
    pub summary: String,
    pub description: String,
    pub source: String,
    pub security: PackageSecuritySummary,
    pub releases: Vec<PackageReleaseDetails>,
    pub trusted_publishers: Vec<TrustedPublisherDescriptor>,
}
