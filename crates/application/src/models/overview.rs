use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub struct RegistryOverview {
    pub tenant_count: usize,
    pub project_count: usize,
    pub release_count: usize,
    pub artifact_count: usize,
    pub total_storage_bytes: u64,
    pub mirrored_project_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub tenant_slug: String,
    pub project_name: String,
    pub normalized_name: String,
    pub summary: String,
    pub source: String,
    pub latest_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentActivity {
    pub project_name: String,
    pub tenant_slug: String,
    pub source: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MirrorRefreshReport {
    pub tenant_count: usize,
    pub mirrored_project_count: usize,
    pub refreshed_project_count: usize,
    pub failed_project_count: usize,
    pub failures: Vec<MirrorRefreshFailure>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorRefreshFailure {
    pub tenant_slug: String,
    pub project_name: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardMetrics {
    pub tenant_slug: String,
    pub project_count: usize,
    pub release_count: usize,
    pub artifact_count: usize,
    pub token_count: usize,
    pub trusted_publisher_count: usize,
    pub recent_activity: Vec<RecentActivity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantDashboardStats {
    pub project_count: usize,
    pub release_count: usize,
    pub artifact_count: usize,
    pub token_count: usize,
    pub trusted_publisher_count: usize,
    pub recent_activity: Vec<RecentActivity>,
}
