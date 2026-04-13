use askama::Template;
use pyregistry_application::{
    AdminSession, PublishTokenGrant, RegistryOverview, SearchHit, TrustedPublisherDescriptor,
};
use serde::{Deserialize, Serialize};

#[derive(Template)]
#[template(path = "index.html")]
pub(crate) struct IndexTemplate {
    pub(crate) overview: RegistryOverview,
    pub(crate) total_storage_human: String,
    pub(crate) show_stats: bool,
}

#[derive(Template)]
#[template(path = "login.html")]
pub(crate) struct LoginTemplate<'a> {
    pub(crate) error: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
pub(crate) struct DashboardTemplate {
    pub(crate) overview: RegistryOverview,
    pub(crate) total_storage_human: String,
    pub(crate) tenants: Vec<TenantView>,
    pub(crate) selected_tenant: Option<String>,
    pub(crate) metrics: Option<DashboardView>,
    pub(crate) mirror_jobs: Vec<MirrorJobView>,
    pub(crate) audit_events: Vec<AuditTrailEntryView>,
    pub(crate) search_query: String,
    pub(crate) search_results: Vec<SearchHit>,
    pub(crate) session: AdminSession,
}

#[derive(Template)]
#[template(path = "package_detail.html")]
pub(crate) struct PackageDetailTemplate {
    pub(crate) details: PackageDetailView,
}

#[derive(Template)]
#[template(path = "simple_index.html")]
pub(crate) struct SimpleIndexTemplate {
    pub(crate) tenant_slug: String,
    pub(crate) projects: Vec<SimpleProjectView>,
}

#[derive(Template)]
#[template(path = "simple_project.html")]
pub(crate) struct SimpleProjectTemplate {
    pub(crate) project_name: String,
    pub(crate) artifacts: Vec<SimpleArtifactView>,
}

#[derive(Template)]
#[template(path = "message.html")]
pub(crate) struct MessageTemplate<'a> {
    pub(crate) title: &'a str,
    pub(crate) message: &'a str,
    pub(crate) back_href: &'a str,
}

#[derive(Clone, Serialize)]
pub(crate) struct TenantView {
    pub(crate) slug: String,
    pub(crate) display_name: String,
    pub(crate) mirroring_enabled: bool,
}

#[derive(Clone, Serialize)]
pub(crate) struct DashboardView {
    pub(crate) tenant_slug: String,
    pub(crate) project_count: usize,
    pub(crate) release_count: usize,
    pub(crate) artifact_count: usize,
    pub(crate) token_count: usize,
    pub(crate) trusted_publisher_count: usize,
}

#[derive(Clone, Serialize)]
pub(crate) struct MirrorJobView {
    pub(crate) project_name: String,
    pub(crate) status_label: String,
    pub(crate) detail: String,
    pub(crate) active: bool,
}

#[derive(Clone, Serialize)]
pub(crate) struct AuditTrailEntryView {
    pub(crate) occurred_at: String,
    pub(crate) actor: String,
    pub(crate) action: String,
    pub(crate) tenant_slug: Option<String>,
    pub(crate) target: Option<String>,
    pub(crate) metadata: Vec<AuditTrailMetadataView>,
}

#[derive(Clone, Serialize)]
pub(crate) struct AuditTrailMetadataView {
    pub(crate) key: String,
    pub(crate) value: String,
}

#[derive(Clone, Serialize)]
pub(crate) struct PackageDetailView {
    pub(crate) tenant_slug: String,
    pub(crate) project_name: String,
    pub(crate) normalized_name: String,
    pub(crate) summary: String,
    pub(crate) description: String,
    pub(crate) source: String,
    pub(crate) index_url: String,
    pub(crate) security: PackageSecuritySummaryView,
    pub(crate) pip_install_command: String,
    pub(crate) uv_install_command: String,
    pub(crate) releases: Vec<PackageReleaseView>,
    pub(crate) trusted_publishers: Vec<TrustedPublisherDescriptor>,
}

#[derive(Clone, Serialize)]
pub(crate) struct PackageReleaseView {
    pub(crate) version: String,
    pub(crate) yanked_reason: Option<String>,
    pub(crate) artifact_count: usize,
    pub(crate) total_size_human: String,
    pub(crate) expanded: bool,
    pub(crate) artifacts: Vec<PackageArtifactView>,
}

#[derive(Clone, Serialize)]
pub(crate) struct PackageArtifactView {
    pub(crate) filename: String,
    pub(crate) size_human: String,
    pub(crate) sha256: String,
    pub(crate) yanked_reason: Option<String>,
    pub(crate) is_wheel: bool,
    pub(crate) download_url: String,
    pub(crate) scan_url: String,
    pub(crate) security: ArtifactSecurityView,
}

#[derive(Clone, Serialize)]
pub(crate) struct PackageSecuritySummaryView {
    pub(crate) scanned_file_count: usize,
    pub(crate) vulnerable_file_count: usize,
    pub(crate) vulnerability_count: usize,
    pub(crate) highest_severity: Option<String>,
    pub(crate) scan_error: Option<String>,
    pub(crate) scan_unavailable: bool,
    pub(crate) scanned_dependency_count: usize,
    pub(crate) vulnerable_dependency_count: usize,
    pub(crate) dependency_vulnerability_count: usize,
    pub(crate) dependency_findings: Vec<DependencyVulnerabilityFindingView>,
    pub(crate) dependency_scan_error: Option<String>,
    pub(crate) dependency_scan_unavailable: bool,
}

#[derive(Clone, Serialize)]
pub(crate) struct ArtifactSecurityView {
    pub(crate) scanned: bool,
    pub(crate) vulnerability_count: usize,
    pub(crate) highest_severity: Option<String>,
    pub(crate) vulnerabilities: Vec<PackageVulnerabilityView>,
    pub(crate) hidden_vulnerability_count: usize,
    pub(crate) scan_error: Option<String>,
    pub(crate) dependency_count: usize,
    pub(crate) vulnerable_dependency_count: usize,
    pub(crate) dependency_vulnerability_count: usize,
    pub(crate) dependencies: Vec<DependencyVulnerabilityView>,
    pub(crate) dependency_scan_error: Option<String>,
}

#[derive(Clone, Serialize)]
pub(crate) struct PackageVulnerabilityView {
    pub(crate) id: String,
    pub(crate) summary: String,
    pub(crate) severity: String,
    pub(crate) fixed_versions: String,
    pub(crate) primary_reference: Option<String>,
}

#[derive(Clone, Serialize)]
pub(crate) struct DependencyVulnerabilityView {
    pub(crate) requirement: String,
    pub(crate) package_name: String,
    pub(crate) version: String,
    pub(crate) vulnerability_count: usize,
    pub(crate) highest_severity: Option<String>,
    pub(crate) vulnerabilities: Vec<PackageVulnerabilityView>,
    pub(crate) hidden_vulnerability_count: usize,
    pub(crate) scan_error: Option<String>,
}

#[derive(Clone, Serialize)]
pub(crate) struct DependencyVulnerabilityFindingView {
    pub(crate) artifact_filename: String,
    pub(crate) dependency: DependencyVulnerabilityView,
}

#[derive(Clone, Serialize)]
pub(crate) struct SimpleProjectView {
    pub(crate) name: String,
    pub(crate) normalized_name: String,
}

#[derive(Clone, Serialize)]
pub(crate) struct SimpleArtifactView {
    pub(crate) filename: String,
    pub(crate) version: String,
    pub(crate) sha256: String,
    pub(crate) url: String,
    pub(crate) provenance_url: Option<String>,
    pub(crate) yanked_reason: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct LoginFormData {
    pub(crate) email: String,
    pub(crate) password: String,
}

#[derive(Deserialize)]
pub(crate) struct CreateTenantFormData {
    pub(crate) slug: String,
    pub(crate) display_name: String,
    pub(crate) admin_email: String,
    pub(crate) admin_password: String,
    pub(crate) mirroring_enabled: Option<String>,
}

pub(crate) struct IssueTokenFormData {
    pub(crate) label: String,
    pub(crate) ttl_hours: Option<String>,
    pub(crate) scopes: Vec<String>,
}

#[derive(Deserialize)]
pub(crate) struct RevokeTokenFormData {
    pub(crate) label: String,
}

#[derive(Deserialize)]
pub(crate) struct SearchQuery {
    pub(crate) tenant: Option<String>,
    pub(crate) q: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct MirrorFormData {
    pub(crate) project_name: String,
}

#[derive(Deserialize)]
pub(crate) struct PublisherFormData {
    pub(crate) project_name: String,
    pub(crate) provider: String,
    pub(crate) issuer: String,
    pub(crate) audience: String,
    pub(crate) claim_repository: Option<String>,
    pub(crate) claim_workflow: Option<String>,
    pub(crate) claim_ref: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct YankFormData {
    pub(crate) reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct MintOidcRequest {
    pub(crate) tenant_slug: String,
    pub(crate) project_name: String,
    pub(crate) oidc_token: String,
}

pub(crate) type PublishTokenResponse = axum::Json<PublishTokenGrant>;

#[derive(Debug, Serialize)]
pub(crate) struct WheelAuditResponse {
    pub(crate) artifact_filename: String,
    pub(crate) report_text: String,
}
