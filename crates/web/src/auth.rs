use crate::{error::WebError, state::AppState};
use axum::http::{HeaderMap, StatusCode, header};
use axum_extra::extract::cookie::CookieJar;
use base64::Engine;
use log::{debug, warn};
use pyregistry_application::{AdminSession, AuthenticatedAccess};
use pyregistry_domain::TokenScope;

pub(crate) async fn require_session(
    state: &AppState,
    jar: &CookieJar,
) -> Result<AdminSession, WebError> {
    let session_id = jar
        .get("admin_session")
        .map(|cookie| cookie.value().to_string())
        .ok_or_else(|| {
            warn!("admin session lookup failed because the session cookie was missing");
            WebError {
                status: StatusCode::UNAUTHORIZED,
                message: "Please sign in first".into(),
            }
        })?;

    state
        .sessions
        .read()
        .await
        .get(&session_id)
        .cloned()
        .ok_or_else(|| {
            warn!("admin session lookup failed because the session was not found or expired");
            WebError {
                status: StatusCode::UNAUTHORIZED,
                message: "Session expired, please sign in again".into(),
            }
        })
}

pub(crate) fn ensure_tenant_access(session: &AdminSession, tenant: &str) -> Result<(), WebError> {
    if session.is_superadmin || session.tenant_slug.as_deref() == Some(tenant) {
        debug!(
            "tenant access granted to `{}` for tenant `{tenant}`",
            session.email
        );
        return Ok(());
    }

    warn!(
        "tenant access denied to `{}` for tenant `{tenant}`",
        session.email
    );
    Err(WebError {
        status: StatusCode::FORBIDDEN,
        message: "You do not have access to that tenant".into(),
    })
}

pub(crate) async fn package_access(
    state: &AppState,
    tenant: &str,
    headers: &HeaderMap,
    required_scope: TokenScope,
) -> Result<AuthenticatedAccess, WebError> {
    let secret = extract_basic_secret(headers)?;
    let scope_for_logs = required_scope.clone();
    let access = state
        .app
        .authenticate_tenant_token(tenant, &secret, required_scope)
        .await
        .map_err(|error| {
            warn!(
                "package API authentication failed for tenant `{tenant}` and scope {:?}: {}",
                scope_for_logs, error
            );
            WebError::from(error)
        })?;
    debug!(
        "package API authentication succeeded for tenant `{tenant}` and scope {:?}",
        scope_for_logs
    );
    Ok(access)
}

pub(crate) fn parse_scopes(raw_scopes: Vec<String>) -> Vec<TokenScope> {
    let mut scopes = Vec::new();
    for scope in raw_scopes {
        match scope.as_str() {
            "read" => scopes.push(TokenScope::Read),
            "publish" => scopes.push(TokenScope::Publish),
            "admin" => scopes.push(TokenScope::Admin),
            _ => {}
        }
    }
    if scopes.is_empty() {
        scopes.push(TokenScope::Read);
    }
    scopes
}

pub(crate) fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

fn extract_basic_secret(headers: &HeaderMap) -> Result<String, WebError> {
    let header_value = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| WebError {
            status: StatusCode::UNAUTHORIZED,
            message: "Missing Authorization header".into(),
        })?;
    let encoded = header_value
        .strip_prefix("Basic ")
        .ok_or_else(|| WebError {
            status: StatusCode::UNAUTHORIZED,
            message: "Expected HTTP Basic authentication".into(),
        })?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| WebError {
            status: StatusCode::UNAUTHORIZED,
            message: "Invalid basic auth encoding".into(),
        })?;
    let decoded = String::from_utf8(decoded).map_err(|_| WebError {
        status: StatusCode::UNAUTHORIZED,
        message: "Invalid basic auth payload".into(),
    })?;
    let Some((username, password)) = decoded.split_once(':') else {
        let token = decoded.trim();
        if token.is_empty() {
            return Err(WebError {
                status: StatusCode::UNAUTHORIZED,
                message: "Missing token secret".into(),
            });
        }
        return Ok(token.to_string());
    };

    let password = password.trim();
    debug!(
        "received package API basic auth username `{}` (password_present={})",
        username,
        !password.is_empty()
    );

    if !password.is_empty() {
        return Ok(password.to_string());
    }

    if username == "__token__" {
        return Err(WebError {
            status: StatusCode::UNAUTHORIZED,
            message: "Missing token secret in basic auth password".into(),
        });
    }

    let token = username.trim();
    if token.is_empty() {
        return Err(WebError {
            status: StatusCode::UNAUTHORIZED,
            message: "Missing token secret".into(),
        });
    }
    Ok(token.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn basic_header(payload: &str) -> HeaderValue {
        let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
        HeaderValue::from_str(&format!("Basic {encoded}")).expect("header")
    }

    #[test]
    fn extracts_basic_auth_secret() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, basic_header("__token__:secret"));
        assert_eq!(extract_basic_secret(&headers).expect("secret"), "secret");
    }

    #[test]
    fn rejects_reserved_token_username_without_password() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, basic_header("__token__:"));

        let error = extract_basic_secret(&headers).expect_err("missing password");

        assert_eq!(error.status, StatusCode::UNAUTHORIZED);
        assert!(error.message.contains("password"));
    }

    #[test]
    fn still_accepts_token_as_username_for_legacy_clients() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, basic_header("pyr_secret:"));

        assert_eq!(
            extract_basic_secret(&headers).expect("legacy secret"),
            "pyr_secret"
        );
    }
}
