use crate::OidcIssuerConfig;
use async_trait::async_trait;
use base64::Engine;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use log::{debug, info, warn};
use pyregistry_application::{ApplicationError, OidcVerifier};
use pyregistry_domain::PublishIdentity;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone)]
pub struct SimpleJwksOidcVerifier {
    client: reqwest::Client,
    issuers: Vec<OidcIssuerConfig>,
}

impl SimpleJwksOidcVerifier {
    #[must_use]
    pub fn new(issuers: Vec<OidcIssuerConfig>) -> Self {
        Self {
            client: reqwest::Client::new(),
            issuers,
        }
    }
}

#[derive(Debug, Deserialize)]
struct JwtClaims {
    iss: String,
    sub: String,
    aud: Value,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct JsonWebKeySet {
    keys: Vec<JsonWebKey>,
}

#[derive(Debug, Deserialize)]
struct JsonWebKey {
    kid: Option<String>,
    kty: String,
    n: Option<String>,
    e: Option<String>,
}

#[async_trait]
impl OidcVerifier for SimpleJwksOidcVerifier {
    async fn verify(
        &self,
        token: &str,
        audience: &str,
    ) -> Result<PublishIdentity, ApplicationError> {
        let claims = parse_claims_unverified(token)?;
        info!(
            "verifying OIDC token for issuer `{}` against audience `{audience}`",
            claims.iss
        );
        let issuer = self
            .issuers
            .iter()
            .find(|issuer| issuer.issuer == claims.iss)
            .ok_or_else(|| {
                warn!(
                    "OIDC verification failed because issuer `{}` is unknown",
                    claims.iss
                );
                ApplicationError::Unauthorized("unknown OIDC issuer".into())
            })?;

        if issuer.audience != audience {
            warn!(
                "OIDC verification failed because requested audience `{audience}` does not match configured audience `{}`",
                issuer.audience
            );
            return Err(ApplicationError::Unauthorized(
                "audience does not match configured issuer".into(),
            ));
        }

        let kid = decode_header(token)
            .map_err(|error| ApplicationError::Unauthorized(error.to_string()))?
            .kid
            .ok_or_else(|| {
                warn!("OIDC verification failed because JWT header is missing `kid`");
                ApplicationError::Unauthorized("JWT header missing kid".into())
            })?;

        debug!(
            "fetching JWKS from `{}` for issuer `{}` and kid `{kid}`",
            issuer.jwks_url, issuer.issuer
        );
        let jwks = self
            .client
            .get(&issuer.jwks_url)
            .send()
            .await
            .map_err(|error| ApplicationError::External(error.to_string()))?
            .error_for_status()
            .map_err(|error| ApplicationError::External(error.to_string()))?
            .json::<JsonWebKeySet>()
            .await
            .map_err(|error| ApplicationError::External(error.to_string()))?;

        let key = jwks
            .keys
            .into_iter()
            .find(|key| key.kid.as_deref() == Some(kid.as_str()) && key.kty == "RSA")
            .ok_or_else(|| {
                warn!("OIDC verification failed because no RSA JWKS key matched kid `{kid}`");
                ApplicationError::Unauthorized("matching JWKS key not found".into())
            })?;

        let decoding_key = DecodingKey::from_rsa_components(
            key.n
                .as_deref()
                .ok_or_else(|| ApplicationError::Unauthorized("JWKS missing modulus".into()))?,
            key.e
                .as_deref()
                .ok_or_else(|| ApplicationError::Unauthorized("JWKS missing exponent".into()))?,
        )
        .map_err(|error| ApplicationError::Unauthorized(error.to_string()))?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[audience]);
        validation.set_issuer(&[issuer.issuer.as_str()]);
        let claims = decode::<JwtClaims>(token, &decoding_key, &validation)
            .map_err(|error| ApplicationError::Unauthorized(error.to_string()))?
            .claims;

        let audience = match claims.aud {
            Value::String(value) => value,
            Value::Array(values) => values
                .first()
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            _ => String::new(),
        };
        let extra = claims
            .extra
            .into_iter()
            .filter_map(|(key, value)| value.as_str().map(|value| (key, value.to_string())))
            .collect();

        let identity = PublishIdentity {
            issuer: claims.iss,
            subject: claims.sub,
            audience,
            provider: issuer.provider.clone(),
            claims: extra,
        };
        info!(
            "OIDC token verified for issuer `{}` subject `{}` provider={:?}",
            identity.issuer, identity.subject, identity.provider
        );
        Ok(identity)
    }
}

fn parse_claims_unverified(token: &str) -> Result<JwtClaims, ApplicationError> {
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| ApplicationError::Unauthorized("malformed JWT".into()))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|error| ApplicationError::Unauthorized(error.to_string()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| ApplicationError::Unauthorized(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unsigned_token(payload: serde_json::Value) -> String {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"RS256","kid":"test"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string());
        format!("{header}.{payload}.signature")
    }

    #[test]
    fn parses_unverified_claims_with_extra_values() {
        let token = unsigned_token(serde_json::json!({
            "iss": "https://issuer.example",
            "sub": "repo:acme/demo",
            "aud": ["pyregistry", "other"],
            "repository": "acme/demo",
            "run_id": 42
        }));

        let claims = parse_claims_unverified(&token).expect("claims");

        assert_eq!(claims.iss, "https://issuer.example");
        assert_eq!(claims.sub, "repo:acme/demo");
        assert_eq!(claims.aud, serde_json::json!(["pyregistry", "other"]));
        assert_eq!(
            claims.extra.get("repository"),
            Some(&serde_json::json!("acme/demo"))
        );
        assert_eq!(claims.extra.get("run_id"), Some(&serde_json::json!(42)));
    }

    #[test]
    fn rejects_malformed_unverified_tokens() {
        assert!(matches!(
            parse_claims_unverified("missing-parts"),
            Err(ApplicationError::Unauthorized(_))
        ));
        assert!(matches!(
            parse_claims_unverified("header.not-base64.signature"),
            Err(ApplicationError::Unauthorized(_))
        ));
        let token = format!(
            "header.{}.signature",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("not json")
        );
        assert!(matches!(
            parse_claims_unverified(&token),
            Err(ApplicationError::Unauthorized(_))
        ));
    }
}
