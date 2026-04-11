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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mirror_job_status_factories_set_expected_phase_and_detail() {
        let queued = MirrorJobStatus::queued("Acme".into(), "RsLoop".into());
        assert_eq!(queued.tenant_slug, "Acme");
        assert_eq!(queued.project_name, "RsLoop");
        assert_eq!(queued.phase, MirrorJobPhase::Queued);
        assert!(queued.is_active());
        assert!(queued.detail.contains("Waiting"));

        let running = MirrorJobStatus::running("acme".into(), "rsloop".into());
        assert_eq!(running.phase, MirrorJobPhase::Running);
        assert!(running.is_active());
        assert!(running.detail.contains("Downloading"));

        let completed =
            MirrorJobStatus::completed("acme".into(), "rsloop".into(), "cached 12 files".into());
        assert_eq!(completed.phase, MirrorJobPhase::Completed);
        assert!(!completed.is_active());
        assert_eq!(completed.detail, "cached 12 files");

        let failed =
            MirrorJobStatus::failed("acme".into(), "rsloop".into(), "network timeout".into());
        assert_eq!(failed.phase, MirrorJobPhase::Failed);
        assert!(!failed.is_active());
        assert_eq!(failed.detail, "network timeout");
    }

    #[test]
    fn mirror_job_key_is_case_and_space_normalized() {
        assert_eq!(mirror_job_key(" Acme ", " RsLoop "), "acme:rsloop");
    }
}
