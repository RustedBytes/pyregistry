use crate::{ApplicationError, AuditTrailEntry, PyregistryApp, RecordAuditEventCommand};
use log::{debug, info};
use pyregistry_domain::{AuditEvent, AuditEventId};

const DEFAULT_AUDIT_LIMIT: usize = 25;
const MAX_AUDIT_LIMIT: usize = 100;

impl PyregistryApp {
    pub async fn record_audit_event(
        &self,
        command: RecordAuditEventCommand,
    ) -> Result<(), ApplicationError> {
        let event = AuditEvent::new(
            AuditEventId::new(self.ids.next()),
            self.clock.now(),
            command.actor,
            command.action,
            command.tenant_slug,
            command.target,
            command.metadata,
        )?;
        info!(
            "recording audit event action=`{}` actor=`{}` tenant={:?} target={:?}",
            event.action, event.actor, event.tenant_slug, event.target
        );
        self.store.save_audit_event(event).await
    }

    pub async fn list_audit_trail(
        &self,
        tenant_slug: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AuditTrailEntry>, ApplicationError> {
        let limit = if limit == 0 {
            DEFAULT_AUDIT_LIMIT
        } else {
            limit.min(MAX_AUDIT_LIMIT)
        };
        let events = self.store.list_audit_events(tenant_slug, limit).await?;
        debug!(
            "loaded {} audit event(s) for tenant filter {:?}",
            events.len(),
            tenant_slug
        );
        Ok(events
            .into_iter()
            .map(|event| AuditTrailEntry {
                occurred_at: event.occurred_at,
                actor: event.actor,
                action: event.action,
                tenant_slug: event.tenant_slug,
                target: event.target,
                metadata: event.metadata,
            })
            .collect())
    }
}
