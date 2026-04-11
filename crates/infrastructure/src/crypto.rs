use argon2::{
    Argon2, PasswordHash, PasswordHasher as _, PasswordVerifier, password_hash::SaltString,
};
use async_trait::async_trait;
use chrono::Utc;
use pyregistry_application::{ApplicationError, AttestationSigner, PasswordHasher, TokenHasher};
use pyregistry_domain::{Artifact, PublishIdentity};
use rand_core::OsRng;
use serde_json::json;
use sha2::{Digest, Sha256};

pub struct JsonAttestationSigner;

#[async_trait]
impl AttestationSigner for JsonAttestationSigner {
    async fn build_attestation(
        &self,
        project_name: &pyregistry_domain::ProjectName,
        version: &pyregistry_domain::ReleaseVersion,
        artifact: &Artifact,
        identity: &PublishIdentity,
    ) -> Result<String, ApplicationError> {
        Ok(json!({
            "version": 1,
            "kind": "publish-attestation",
            "subject": {
                "project": project_name.original(),
                "version": version.as_str(),
                "filename": artifact.filename,
                "sha256": artifact.digests.sha256,
            },
            "identity": {
                "issuer": identity.issuer,
                "subject": identity.subject,
                "audience": identity.audience,
                "claims": identity.claims,
            },
            "recorded_at": Utc::now().to_rfc3339(),
        })
        .to_string())
    }
}

pub struct ArgonPasswordHasher;

impl PasswordHasher for ArgonPasswordHasher {
    fn hash(&self, password: &str) -> Result<String, ApplicationError> {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|value| value.to_string())
            .map_err(|error| ApplicationError::External(error.to_string()))
    }

    fn verify(&self, password: &str, hash: &str) -> Result<bool, ApplicationError> {
        let parsed = PasswordHash::new(hash)
            .map_err(|error| ApplicationError::External(error.to_string()))?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    }
}

pub struct Sha256TokenHasher;

impl TokenHasher for Sha256TokenHasher {
    fn hash(&self, secret: &str) -> Result<String, ApplicationError> {
        Ok(hex::encode(Sha256::digest(secret.as_bytes())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use pyregistry_domain::{
        Artifact, ArtifactId, DigestSet, ProjectName, PublishIdentity, ReleaseId, ReleaseVersion,
        TrustedPublisherProvider,
    };
    use std::collections::BTreeMap;
    use uuid::Uuid;

    #[tokio::test]
    async fn json_attestation_contains_publish_identity_and_subject() {
        let artifact = Artifact::new(
            ArtifactId::new(Uuid::from_u128(1)),
            ReleaseId::new(Uuid::from_u128(2)),
            "demo-1.0.0-py3-none-any.whl",
            10,
            DigestSet::new("a".repeat(64), None).expect("digest"),
            "acme/demo/1.0.0/demo-1.0.0-py3-none-any.whl",
            Utc.with_ymd_and_hms(2026, 4, 11, 12, 0, 0)
                .single()
                .expect("timestamp"),
        )
        .expect("artifact");
        let payload = JsonAttestationSigner
            .build_attestation(
                &ProjectName::new("demo").expect("project name"),
                &ReleaseVersion::new("1.0.0").expect("version"),
                &artifact,
                &PublishIdentity {
                    issuer: "https://issuer.example".into(),
                    subject: "repo:acme/demo".into(),
                    audience: "pyregistry".into(),
                    provider: TrustedPublisherProvider::GitHubActions,
                    claims: BTreeMap::from([("repository".into(), "acme/demo".into())]),
                },
            )
            .await
            .expect("attestation");

        let document: serde_json::Value = serde_json::from_str(&payload).expect("json");
        assert_eq!(document["kind"], "publish-attestation");
        assert_eq!(document["subject"]["project"], "demo");
        assert_eq!(document["subject"]["version"], "1.0.0");
        assert_eq!(document["subject"]["filename"], artifact.filename);
        assert_eq!(document["identity"]["issuer"], "https://issuer.example");
        assert_eq!(document["identity"]["claims"]["repository"], "acme/demo");
    }

    #[test]
    fn argon_password_hash_verifies_only_matching_passwords() {
        let hasher = ArgonPasswordHasher;
        let hash = hasher.hash("correct horse").expect("hash");

        assert!(hasher.verify("correct horse", &hash).expect("verify"));
        assert!(!hasher.verify("wrong horse", &hash).expect("verify"));
        assert!(hasher.verify("anything", "not-an-argon-hash").is_err());
    }

    #[test]
    fn sha256_token_hasher_is_deterministic_hex() {
        let hasher = Sha256TokenHasher;

        assert_eq!(
            hasher.hash("secret").expect("hash"),
            "2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b"
        );
    }
}
