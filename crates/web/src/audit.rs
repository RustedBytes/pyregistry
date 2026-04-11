use crate::state::AppState;
use log::warn;
use pyregistry_application::RecordAuditEventCommand;
use std::collections::BTreeMap;

pub(crate) fn audit_metadata(
    entries: impl IntoIterator<Item = (&'static str, String)>,
) -> BTreeMap<String, String> {
    entries
        .into_iter()
        .filter_map(|(key, value)| {
            let value = value.trim().to_string();
            if value.is_empty() {
                None
            } else {
                Some((key.to_string(), value))
            }
        })
        .collect()
}

pub(crate) async fn record_audit_event(
    state: &AppState,
    actor: String,
    action: &'static str,
    tenant_slug: Option<String>,
    target: Option<String>,
    metadata: BTreeMap<String, String>,
) {
    if let Err(error) = state
        .app
        .record_audit_event(RecordAuditEventCommand {
            actor,
            action: action.to_string(),
            tenant_slug,
            target,
            metadata,
        })
        .await
    {
        warn!("failed to persist audit event `{action}`: {error}");
    }
}
