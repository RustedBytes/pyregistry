use chrono::{DateTime, Utc};
use pyregistry_domain::{ApiToken, Tenant};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishTokenGrant {
    pub tenant_slug: String,
    pub project_name: String,
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedAccess {
    pub tenant: Tenant,
    pub token: ApiToken,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminSession {
    pub email: String,
    pub tenant_slug: Option<String>,
    pub is_superadmin: bool,
}
