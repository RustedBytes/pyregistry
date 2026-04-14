#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use chrono::{DateTime, Utc};
use libfuzzer_sys::fuzz_target;
use pyregistry_domain::{
    Artifact, ArtifactId, AuditEvent, AuditEventId, DigestSet, MirrorRule, Project, ProjectId,
    ProjectName, ProjectSource, ReleaseVersion, Tenant, TenantId, TenantSlug,
};
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Debug, Arbitrary)]
struct DomainInput {
    tenant_slug: String,
    project_name: String,
    release_version: String,
    display_name: String,
    artifact_filename: String,
    object_key: String,
    sha256: String,
    blake2b_256: Option<String>,
    summary: String,
    description: String,
    audit_actor: String,
    audit_action: String,
    audit_tenant_slug: Option<String>,
    audit_target: Option<String>,
    metadata_pairs: Vec<(String, String)>,
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = DomainInput::arbitrary(&mut unstructured) else {
        return;
    };

    let tenant_slug = TenantSlug::new(input.tenant_slug.clone());
    let project_name = ProjectName::new(input.project_name.clone());
    let release_version = ReleaseVersion::new(input.release_version.clone());
    let digest_set = DigestSet::new(input.sha256.clone(), input.blake2b_256.clone());

    if let Ok(slug) = &tenant_slug {
        assert_eq!(slug.as_str(), slug.as_str().trim());
        assert_eq!(slug.as_str(), slug.as_str().to_ascii_lowercase());
        assert!(TenantSlug::new(slug.as_str()).is_ok());
    }

    if let Ok(name) = &project_name {
        assert!(!name.original().is_empty());
        assert!(!name.normalized().is_empty());
        let normalized_again = ProjectName::new(name.normalized()).expect("normalized project name");
        assert_eq!(normalized_again.normalized(), name.normalized());
    }

    if let Ok(version) = &release_version {
        assert!(!version.as_str().is_empty());
        assert_eq!(version.cmp(version), std::cmp::Ordering::Equal);
    }

    if let Ok(digests) = &digest_set {
        assert_eq!(digests.sha256.len(), 64);
        assert!(digests.sha256.chars().all(|character| character.is_ascii_hexdigit()));
        assert_eq!(digests.sha256, digests.sha256.to_ascii_lowercase());
        if let Some(blake2b_256) = &digests.blake2b_256 {
            assert_eq!(blake2b_256.len(), 64);
            assert!(blake2b_256
                .chars()
                .all(|character| character.is_ascii_hexdigit()));
            assert_eq!(blake2b_256, &blake2b_256.to_ascii_lowercase());
        }
    }

    let now = DateTime::<Utc>::from(std::time::SystemTime::UNIX_EPOCH);
    if let Ok(slug) = tenant_slug.clone() {
        let _ = Tenant::new(
            TenantId::new(Uuid::from_u128(1)),
            slug,
            input.display_name.clone(),
            MirrorRule { enabled: true },
            now,
        );
    }

    if let Ok(name) = project_name.clone() {
        let _ = Project::new(
            ProjectId::new(Uuid::from_u128(2)),
            TenantId::new(Uuid::from_u128(1)),
            name,
            ProjectSource::Local,
            input.summary,
            input.description,
            now,
        );
    }

    if let (Ok(digests), Ok(_version)) = (digest_set, release_version) {
        let _ = Artifact::new(
            ArtifactId::new(Uuid::from_u128(3)),
            pyregistry_domain::ReleaseId::new(Uuid::from_u128(4)),
            input.artifact_filename,
            data.len() as u64,
            digests,
            input.object_key,
            now,
        );
    }

    let metadata = input
        .metadata_pairs
        .into_iter()
        .take(32)
        .collect::<BTreeMap<_, _>>();
    if let Ok(event) = AuditEvent::new(
        AuditEventId::new(Uuid::from_u128(5)),
        now,
        input.audit_actor,
        input.audit_action,
        input.audit_tenant_slug,
        input.audit_target,
        metadata,
    ) {
        assert_eq!(event.actor, event.actor.trim());
        assert_eq!(event.action, event.action.trim());
        assert!(event.metadata.keys().all(|key| key == key.trim()));
        assert!(event.metadata.values().all(|value| value == value.trim()));
        assert!(event.metadata.values().all(|value| !value.is_empty()));
    }
});
