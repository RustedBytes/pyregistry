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
