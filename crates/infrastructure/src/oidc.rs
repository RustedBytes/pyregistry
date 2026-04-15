use crate::OidcIssuerConfig;
use async_trait::async_trait;
use base64::Engine;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use log::{debug, info, warn};
use pyregistry_application::{ApplicationError, OidcVerifier};
use pyregistry_domain::PublishIdentity;
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

const DEFAULT_JWKS_TIMEOUT: Duration = Duration::from_secs(5);
const JWKS_CACHE_TTL: Duration = Duration::from_secs(300);
const MAX_JWKS_BYTES: u64 = 1024 * 1024;
const MAX_JWT_PAYLOAD_BASE64_CHARS: usize = 96 * 1024;

#[derive(Clone)]
pub struct SimpleJwksOidcVerifier {
    client: reqwest::Client,
    issuers: Vec<OidcIssuerConfig>,
    jwks_cache: Arc<RwLock<HashMap<String, CachedJwks>>>,
}

#[derive(Debug, Clone)]
struct CachedJwks {
    fetched_at: Instant,
    keys: Vec<JsonWebKey>,
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

#[derive(Debug, Clone, Deserialize)]
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

        let jwks = self.fetch_jwks(issuer).await?;

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

impl SimpleJwksOidcVerifier {
    #[must_use]
    pub fn new(issuers: Vec<OidcIssuerConfig>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(DEFAULT_JWKS_TIMEOUT)
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .unwrap_or_else(|error| {
                warn!("failed to build timeout-bound OIDC HTTP client: {error}");
                reqwest::Client::new()
            });
        Self {
            client,
            issuers,
            jwks_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn fetch_jwks(
        &self,
        issuer: &OidcIssuerConfig,
    ) -> Result<JsonWebKeySet, ApplicationError> {
        let cache_key = issuer.jwks_url.clone();
        let now = Instant::now();
        if let Some(cached) = self.jwks_cache.read().await.get(&cache_key).cloned()
            && now.saturating_duration_since(cached.fetched_at) <= JWKS_CACHE_TTL
        {
            debug!(
                "using cached JWKS for issuer `{}` from `{}`",
                issuer.issuer, issuer.jwks_url
            );
            return Ok(JsonWebKeySet { keys: cached.keys });
        }

        debug!(
            "fetching JWKS from `{}` for issuer `{}`",
            issuer.jwks_url, issuer.issuer
        );
        let mut response = self
            .client
            .get(&issuer.jwks_url)
            .send()
            .await
            .map_err(|error| ApplicationError::External(error.to_string()))?
            .error_for_status()
            .map_err(|error| ApplicationError::External(error.to_string()))?;
        if let Some(content_length) = response.content_length()
            && content_length > MAX_JWKS_BYTES
        {
            return Err(ApplicationError::External(format!(
                "OIDC JWKS response from `{}` exceeds {} bytes",
                issuer.jwks_url, MAX_JWKS_BYTES
            )));
        }

        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| ApplicationError::External(error.to_string()))?
        {
            let next_len = body.len().saturating_add(chunk.len());
            if next_len as u64 > MAX_JWKS_BYTES {
                return Err(ApplicationError::External(format!(
                    "OIDC JWKS response from `{}` exceeded {} bytes",
                    issuer.jwks_url, MAX_JWKS_BYTES
                )));
            }
            body.extend_from_slice(&chunk);
        }

        let jwks: JsonWebKeySet = serde_json::from_slice(&body)
            .map_err(|error| ApplicationError::External(error.to_string()))?;
        self.jwks_cache.write().await.insert(
            cache_key,
            CachedJwks {
                fetched_at: now,
                keys: jwks.keys.clone(),
            },
        );
        Ok(jwks)
    }
}

fn parse_claims_unverified(token: &str) -> Result<JwtClaims, ApplicationError> {
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| ApplicationError::Unauthorized("malformed JWT".into()))?;
    if payload.len() > MAX_JWT_PAYLOAD_BASE64_CHARS {
        return Err(ApplicationError::Unauthorized(
            "JWT payload is too large".into(),
        ));
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|error| ApplicationError::Unauthorized(error.to_string()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| ApplicationError::Unauthorized(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyregistry_domain::TrustedPublisherProvider;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn unsigned_token(payload: serde_json::Value) -> String {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"RS256","kid":"test"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string());
        format!("{header}.{payload}.signature")
    }

    fn unsigned_token_without_kid(payload: serde_json::Value) -> String {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#);
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

    #[tokio::test]
    async fn verifier_rejects_unknown_issuer_before_fetching_jwks() {
        let verifier = SimpleJwksOidcVerifier::new(Vec::new());
        let token = unsigned_token(serde_json::json!({
            "iss": "https://unknown.example",
            "sub": "repo:acme/demo",
            "aud": "pyregistry"
        }));

        assert!(matches!(
            verifier.verify(&token, "pyregistry").await,
            Err(ApplicationError::Unauthorized(_))
        ));
    }

    #[tokio::test]
    async fn verifier_rejects_mismatched_configured_audience_before_fetching_jwks() {
        let verifier = SimpleJwksOidcVerifier::new(vec![OidcIssuerConfig {
            provider: TrustedPublisherProvider::GitHubActions,
            issuer: "https://issuer.example".into(),
            jwks_url: "http://127.0.0.1:9/jwks".into(),
            audience: "expected-audience".into(),
        }]);
        let token = unsigned_token(serde_json::json!({
            "iss": "https://issuer.example",
            "sub": "repo:acme/demo",
            "aud": "pyregistry"
        }));

        assert!(matches!(
            verifier.verify(&token, "pyregistry").await,
            Err(ApplicationError::Unauthorized(_))
        ));
    }

    #[tokio::test]
    async fn verifier_requires_kid_for_known_issuer() {
        let verifier = SimpleJwksOidcVerifier::new(vec![OidcIssuerConfig {
            provider: TrustedPublisherProvider::GitLab,
            issuer: "https://issuer.example".into(),
            jwks_url: "http://127.0.0.1:9/jwks".into(),
            audience: "pyregistry".into(),
        }]);
        let token = unsigned_token_without_kid(serde_json::json!({
            "iss": "https://issuer.example",
            "sub": "project_path:acme/demo",
            "aud": "pyregistry"
        }));

        assert!(matches!(
            verifier.verify(&token, "pyregistry").await,
            Err(ApplicationError::Unauthorized(_))
        ));
    }

    #[tokio::test]
    async fn verifier_rejects_jwks_without_matching_rsa_key() {
        let (jwks_url, server) = serve_jwks(r#"{"keys":[{"kid":"other","kty":"RSA"}]}"#).await;
        let verifier = SimpleJwksOidcVerifier::new(vec![OidcIssuerConfig {
            provider: TrustedPublisherProvider::GitHubActions,
            issuer: "https://issuer.example".into(),
            jwks_url,
            audience: "pyregistry".into(),
        }]);
        let token = unsigned_token(serde_json::json!({
            "iss": "https://issuer.example",
            "sub": "repo:acme/demo",
            "aud": "pyregistry"
        }));

        let error = verifier
            .verify(&token, "pyregistry")
            .await
            .expect_err("JWKS key should not match");

        assert!(matches!(error, ApplicationError::Unauthorized(_)));
        assert!(error.to_string().contains("matching JWKS key"));
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn verifier_requires_rsa_modulus_and_exponent() {
        let (jwks_url, server) = serve_jwks(r#"{"keys":[{"kid":"test","kty":"RSA"}]}"#).await;
        let verifier = SimpleJwksOidcVerifier::new(vec![OidcIssuerConfig {
            provider: TrustedPublisherProvider::GitLab,
            issuer: "https://issuer.example".into(),
            jwks_url,
            audience: "pyregistry".into(),
        }]);
        let token = unsigned_token(serde_json::json!({
            "iss": "https://issuer.example",
            "sub": "project_path:acme/demo",
            "aud": "pyregistry"
        }));

        let error = verifier
            .verify(&token, "pyregistry")
            .await
            .expect_err("JWKS key is incomplete");

        assert!(matches!(error, ApplicationError::Unauthorized(_)));
        assert!(error.to_string().contains("modulus"));
        server.await.expect("server task");
    }

    async fn serve_jwks(body: &'static str) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind JWKS listener");
        let address = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept JWKS request");
            let mut buffer = [0_u8; 1024];
            let _ = socket.read(&mut buffer).await.expect("read JWKS request");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write JWKS response");
        });
        (format!("http://{address}/jwks"), server)
    }
}
