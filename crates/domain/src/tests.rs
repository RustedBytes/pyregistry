#![cfg(test)]

use crate::{
    ArtifactKind, DomainError, ProjectName, ProjectSource, PublishIdentity, ReleaseVersion,
    TenantId, TenantSlug, TrustedPublisher, TrustedPublisherId, TrustedPublisherProvider,
    ensure_purge_allowed,
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
