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
    let session_id = admin_session_cookie(jar)?;

    let mut sessions = state.sessions.write().await;
    let stored = sessions.get(&session_id).cloned();
    let Some(stored) = stored else {
        return Err({
            warn!("admin session lookup failed because the session was not found or expired");
            WebError {
                status: StatusCode::UNAUTHORIZED,
                message: "Session expired, please sign in again".into(),
            }
        });
    };

    if stored.expires_at <= chrono::Utc::now() {
        sessions.remove(&session_id);
        warn!("admin session lookup failed because the server-side session expired");
        return Err(WebError {
            status: StatusCode::UNAUTHORIZED,
            message: "Session expired, please sign in again".into(),
        });
    }

    Ok(stored.session)
}

fn admin_session_cookie(jar: &CookieJar) -> Result<String, WebError> {
    jar.get("admin_session")
        .map(|cookie| cookie.value().to_string())
        .ok_or_else(|| {
            warn!("admin session lookup failed because the session cookie was missing");
            WebError {
                status: StatusCode::UNAUTHORIZED,
                message: "Please sign in first".into(),
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
    let decoded = decode_basic_payload(headers)?;
    secret_from_basic_payload(&decoded)
}

fn decode_basic_payload(headers: &HeaderMap) -> Result<String, WebError> {
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
    Ok(decoded)
}

fn secret_from_basic_payload(decoded: &str) -> Result<String, WebError> {
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

    #[test]
    fn parses_known_scopes_and_defaults_to_read() {
        assert_eq!(
            parse_scopes(vec!["read".into(), "publish".into(), "admin".into()]),
            vec![TokenScope::Read, TokenScope::Publish, TokenScope::Admin]
        );
        assert_eq!(parse_scopes(vec!["unknown".into()]), vec![TokenScope::Read]);
        assert_eq!(parse_scopes(Vec::new()), vec![TokenScope::Read]);
    }

    #[test]
    fn formats_bytes_for_ui() {
        assert_eq!(human_bytes(0), "0.0 B");
        assert_eq!(human_bytes(1023), "1023.0 B");
        assert_eq!(human_bytes(1024), "1.0 KB");
        assert_eq!(human_bytes(1024 * 1024 * 5 + 512 * 1024), "5.5 MB");
        assert_eq!(human_bytes(1024_u64.pow(4) * 2), "2.0 TB");
    }

    #[test]
    fn tenant_access_allows_superadmins_and_matching_tenant_admins() {
        let superadmin = AdminSession {
            email: "root@example.com".into(),
            tenant_slug: None,
            is_superadmin: true,
        };
        let tenant_admin = AdminSession {
            email: "admin@example.com".into(),
            tenant_slug: Some("acme".into()),
            is_superadmin: false,
        };

        assert!(ensure_tenant_access(&superadmin, "other").is_ok());
        assert!(ensure_tenant_access(&tenant_admin, "acme").is_ok());
    }

    #[test]
    fn tenant_access_rejects_other_tenants() {
        let session = AdminSession {
            email: "admin@example.com".into(),
            tenant_slug: Some("acme".into()),
            is_superadmin: false,
        };

        let error = ensure_tenant_access(&session, "other").expect_err("forbidden");

        assert_eq!(error.status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn rejects_missing_or_invalid_basic_auth_headers() {
        let headers = HeaderMap::new();
        assert_eq!(
            extract_basic_secret(&headers).expect_err("missing").status,
            StatusCode::UNAUTHORIZED
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer nope"),
        );
        assert!(
            extract_basic_secret(&headers)
                .expect_err("wrong scheme")
                .message
                .contains("Basic")
        );

        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic !!!"));
        assert!(
            extract_basic_secret(&headers)
                .expect_err("bad base64")
                .message
                .contains("encoding")
        );
    }

    #[test]
    fn accepts_token_without_colon_when_basic_payload_is_single_secret() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, basic_header("pyr_secret"));

        assert_eq!(
            extract_basic_secret(&headers).expect("secret"),
            "pyr_secret"
        );
    }

    #[test]
    fn rejects_empty_basic_payload() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, basic_header("   "));

        assert!(
            extract_basic_secret(&headers)
                .expect_err("empty secret")
                .message
                .contains("Missing token")
        );
    }

    #[test]
    fn rejects_invalid_utf8_and_blank_legacy_username_payloads() {
        let mut headers = HeaderMap::new();
        let encoded = base64::engine::general_purpose::STANDARD.encode([0xff]);
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}")).expect("header"),
        );
        assert!(
            extract_basic_secret(&headers)
                .expect_err("invalid UTF-8")
                .message
                .contains("payload")
        );

        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, basic_header("   :"));
        assert!(
            extract_basic_secret(&headers)
                .expect_err("blank username")
                .message
                .contains("Missing token")
        );
    }
}
