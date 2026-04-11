#![cfg(test)]

use crate::{
    Artifact, ArtifactId, ArtifactKind, AuditEvent, AuditEventId, DigestSet, DomainError,
    MirrorRule, ProjectName, ProjectSource, PublishIdentity, ReleaseId, ReleaseVersion, Tenant,
    TenantId, TenantSlug, TrustedPublisher, TrustedPublisherId, TrustedPublisherProvider,
    ensure_purge_allowed, ensure_unique_filenames,
};
use chrono::Utc;
use std::collections::BTreeMap;

#[test]
fn normalizes_project_names_using_pep_503_rules() {
    let name = ProjectName::new("My.Pkg_Name").expect("project name");
    assert_eq!(name.normalized(), "my-pkg-name");
}

#[test]
fn rejects_bad_tenant_slug() {
    let error = TenantSlug::new("Bad Slug").expect_err("invalid slug");
    assert!(matches!(
        error,
        DomainError::InvalidValue {
            field: "tenant_slug",
            ..
        }
    ));
}

#[test]
fn validates_artifact_filename() {
    assert_eq!(
        ArtifactKind::from_filename("demo-1.0.0-py3-none-any.whl").expect("wheel"),
        ArtifactKind::Wheel
    );
    for filename in [
        "demo-1.0.0.tar.gz",
        "demo-1.0.0.tar.bz2",
        "demo-1.0.0.tar.xz",
        "demo-1.0.0.tgz",
        "demo-1.0.0.zip",
    ] {
        assert_eq!(
            ArtifactKind::from_filename(filename).expect("source distribution"),
            ArtifactKind::SourceDistribution
        );
    }

    let error = ArtifactKind::from_filename("README.txt").expect_err("invalid artifact");
    assert!(matches!(
        error,
        DomainError::InvalidValue {
            field: "artifact_filename",
            ..
        }
    ));
}

#[test]
fn prevents_mirrored_project_purge() {
    let error = ensure_purge_allowed(&ProjectSource::Mirrored).expect_err("must fail");
    assert_eq!(error, DomainError::MirroredProjectPurgeForbidden);
    assert!(ensure_purge_allowed(&ProjectSource::Local).is_ok());
}

#[test]
fn rejects_empty_tenant_display_name() {
    let error = Tenant::new(
        TenantId::default(),
        TenantSlug::new("acme").expect("slug"),
        "   ",
        MirrorRule { enabled: false },
        Utc::now(),
    )
    .expect_err("display name");

    assert!(matches!(
        error,
        DomainError::InvalidValue {
            field: "tenant_display_name",
            ..
        }
    ));
}

#[test]
fn detects_duplicate_artifact_filenames() {
    let release_id = ReleaseId::default();
    let first = Artifact::new(
        ArtifactId::default(),
        release_id,
        "demo-1.0.0-py3-none-any.whl",
        10,
        DigestSet::new("a".repeat(64), None).expect("digest"),
        "objects/demo.whl",
        Utc::now(),
    )
    .expect("artifact");
    let mut duplicate = first.clone();
    duplicate.id = ArtifactId::default();

    let error = ensure_unique_filenames(&[first, duplicate]).expect_err("duplicate");

    assert_eq!(
        error,
        DomainError::DuplicateArtifactFilename("demo-1.0.0-py3-none-any.whl".into())
    );
}

#[test]
fn matches_trusted_publisher_claims() {
    let publisher = TrustedPublisher {
        id: TrustedPublisherId::default(),
        tenant_id: TenantId::default(),
        project_name: ProjectName::new("demo").expect("project"),
        provider: TrustedPublisherProvider::GitHubActions,
        issuer: "https://token.actions.githubusercontent.com".into(),
        audience: "pyregistry".into(),
        claim_rules: BTreeMap::from([
            ("repository".into(), "acme/demo".into()),
            ("workflow".into(), "release.yml".into()),
        ]),
        created_at: Utc::now(),
    };

    let identity = PublishIdentity {
        issuer: "https://token.actions.githubusercontent.com".into(),
        subject: "repo:acme/demo".into(),
        audience: "pyregistry".into(),
        provider: TrustedPublisherProvider::GitHubActions,
        claims: BTreeMap::from([
            ("repository".into(), "acme/demo".into()),
            ("workflow".into(), "release.yml".into()),
        ]),
    };

    assert!(publisher.matches(&identity).is_ok());
}

#[test]
fn orders_release_versions_using_pep_440_rules() {
    let older = ReleaseVersion::new("0.1.9").expect("older");
    let newer = ReleaseVersion::new("0.1.14").expect("newer");
    let prerelease = ReleaseVersion::new("1.0rc1").expect("prerelease");
    let stable = ReleaseVersion::new("1.0").expect("stable");

    assert!(newer > older);
    assert!(stable > prerelease);
}

#[test]
fn audit_events_trim_and_validate_boundary_values() {
    let event = AuditEvent::new(
        AuditEventId::default(),
        Utc::now(),
        " admin@example.test ",
        " tenant.create ",
        Some(" acme ".into()),
        Some(" acme/demo ".into()),
        BTreeMap::from([
            (" project ".into(), " demo ".into()),
            (" empty ".into(), "   ".into()),
        ]),
    )
    .expect("audit event");

    assert_eq!(event.actor, "admin@example.test");
    assert_eq!(event.action, "tenant.create");
    assert_eq!(event.tenant_slug.as_deref(), Some("acme"));
    assert_eq!(event.target.as_deref(), Some("acme/demo"));
    assert_eq!(
        event.metadata.get("project").map(String::as_str),
        Some("demo")
    );
    assert!(!event.metadata.contains_key("empty"));

    let error = AuditEvent::new(
        AuditEventId::default(),
        Utc::now(),
        "",
        "tenant.create",
        None,
        None,
        BTreeMap::new(),
    )
    .expect_err("actor is required");
    assert!(matches!(
        error,
        DomainError::InvalidValue {
            field: "audit_actor",
            ..
        }
    ));
}
