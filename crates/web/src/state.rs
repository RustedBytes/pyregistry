use crate::rate_limit::RateLimiter;
use pyregistry_application::{AdminSession, PyregistryApp};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct MirrorJobStatus {
    pub tenant_slug: String,
    pub project_name: String,
    pub phase: MirrorJobPhase,
    pub detail: String,
}

impl MirrorJobStatus {
    #[must_use]
    pub fn queued(tenant_slug: String, project_name: String) -> Self {
        Self {
            tenant_slug,
            project_name,
            phase: MirrorJobPhase::Queued,
            detail: "Waiting for a background worker slot.".into(),
        }
    }

    #[must_use]
    pub fn running(tenant_slug: String, project_name: String) -> Self {
        Self {
            tenant_slug,
            project_name,
            phase: MirrorJobPhase::Running,
            detail: "Downloading package metadata and all available artifacts from PyPI.".into(),
        }
    }

    #[must_use]
    pub fn completed(tenant_slug: String, project_name: String, detail: String) -> Self {
        Self {
            tenant_slug,
            project_name,
            phase: MirrorJobPhase::Completed,
            detail,
        }
    }

    #[must_use]
    pub fn failed(tenant_slug: String, project_name: String, detail: String) -> Self {
        Self {
            tenant_slug,
            project_name,
            phase: MirrorJobPhase::Failed,
            detail,
        }
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(self.phase, MirrorJobPhase::Queued | MirrorJobPhase::Running)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MirrorJobPhase {
    Queued,
    Running,
    Completed,
    Failed,
}

pub type MirrorJobs = Arc<RwLock<HashMap<String, MirrorJobStatus>>>;

#[must_use]
pub fn mirror_job_key(tenant_slug: &str, project_name: &str) -> String {
    format!(
        "{}:{}",
        tenant_slug.trim().to_ascii_lowercase(),
        project_name.trim().to_ascii_lowercase()
    )
}

#[derive(Clone)]
pub struct AppState {
    pub app: Arc<PyregistryApp>,
    pub sessions: Arc<RwLock<HashMap<String, AdminSession>>>,
    pub mirror_jobs: MirrorJobs,
    pub rate_limiter: RateLimiter,
}
