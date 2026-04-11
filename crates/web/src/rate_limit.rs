use crate::state::AppState;
use axum::{
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use log::{debug, warn};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

const RATE_LIMIT_IDLE_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests_per_minute: u32,
    pub burst: u32,
    pub max_tracked_clients: usize,
    pub trust_proxy_headers: bool,
}

impl RateLimitConfig {
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            requests_per_minute: 1,
            burst: 1,
            max_tracked_clients: 1,
            trust_proxy_headers: false,
        }
    }

    #[must_use]
    pub fn log_safe_summary(&self) -> String {
        format!(
            "enabled={}, requests_per_minute={}, burst={}, max_tracked_clients={}, trust_proxy_headers={}",
            self.enabled,
            self.requests_per_minute,
            self.burst,
            self.max_tracked_clients,
            self.trust_proxy_headers
        )
    }
}

#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<RateLimiterInner>,
}

struct RateLimiterInner {
    config: RateLimitConfig,
    buckets: Mutex<HashMap<String, RateLimitBucket>>,
}

#[derive(Debug, Clone)]
struct RateLimitBucket {
    tokens: f64,
    last_refill: Instant,
    last_seen: Instant,
}

#[derive(Debug, Clone, Copy)]
struct RateLimitDecision {
    allowed: bool,
    limit: u32,
    remaining: u32,
    retry_after: Duration,
}

impl RateLimiter {
    #[must_use]
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            inner: Arc::new(RateLimiterInner {
                config: normalize_config(config),
                buckets: Mutex::new(HashMap::new()),
            }),
        }
    }

    #[must_use]
    pub fn disabled() -> Self {
        Self::new(RateLimitConfig::disabled())
    }

    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.inner.config.enabled
    }

    #[must_use]
    pub fn trust_proxy_headers(&self) -> bool {
        self.inner.config.trust_proxy_headers
    }

    #[must_use]
    pub fn log_safe_summary(&self) -> String {
        self.inner.config.log_safe_summary()
    }

    async fn check(&self, client_key: &str) -> RateLimitDecision {
        let config = &self.inner.config;
        if !config.enabled {
            return RateLimitDecision {
                allowed: true,
                limit: config.requests_per_minute,
                remaining: config.burst,
                retry_after: Duration::ZERO,
            };
        }

        let now = Instant::now();
        let mut buckets = self.inner.buckets.lock().await;

        if !buckets.contains_key(client_key) && buckets.len() >= config.max_tracked_clients {
            prune_idle_buckets(&mut buckets, now);
            if buckets.len() >= config.max_tracked_clients {
                return RateLimitDecision {
                    allowed: false,
                    limit: config.requests_per_minute,
                    remaining: 0,
                    retry_after: RATE_LIMIT_IDLE_TTL,
                };
            }
        }

        let bucket = buckets
            .entry(client_key.to_string())
            .or_insert_with(|| RateLimitBucket {
                tokens: f64::from(config.burst),
                last_refill: now,
                last_seen: now,
            });
        refill_bucket(bucket, config, now);
        bucket.last_seen = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return RateLimitDecision {
                allowed: true,
                limit: config.requests_per_minute,
                remaining: bucket.tokens.floor() as u32,
                retry_after: Duration::ZERO,
            };
        }

        RateLimitDecision {
            allowed: false,
            limit: config.requests_per_minute,
            remaining: 0,
            retry_after: retry_after(bucket.tokens, config),
        }
    }
}

pub(crate) async fn enforce_api_rate_limit(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if !state.rate_limiter.is_enabled() || !should_rate_limit_path(request.uri().path()) {
        return next.run(request).await;
    }

    let client_key = client_key(&request, state.rate_limiter.trust_proxy_headers());
    let decision = state.rate_limiter.check(&client_key).await;
    if !decision.allowed {
        warn!(
            "rate limit exceeded for client `{client_key}` path `{}` retry_after={}s",
            request.uri().path(),
            decision.retry_after.as_secs().max(1)
        );
        return too_many_requests(decision);
    }

    debug!(
        "rate limit allowed client `{client_key}` path `{}` remaining={}",
        request.uri().path(),
        decision.remaining
    );
    let mut response = next.run(request).await;
    insert_rate_limit_headers(response.headers_mut(), decision);
    response
}

fn normalize_config(mut config: RateLimitConfig) -> RateLimitConfig {
    config.requests_per_minute = config.requests_per_minute.max(1);
    config.burst = config.burst.max(1);
    config.max_tracked_clients = config.max_tracked_clients.max(1);
    config
}

fn refill_bucket(bucket: &mut RateLimitBucket, config: &RateLimitConfig, now: Instant) {
    let elapsed = now.saturating_duration_since(bucket.last_refill);
    if elapsed.is_zero() {
        return;
    }

    let refill_per_second = f64::from(config.requests_per_minute) / 60.0;
    bucket.tokens =
        (bucket.tokens + elapsed.as_secs_f64() * refill_per_second).min(f64::from(config.burst));
    bucket.last_refill = now;
}

fn retry_after(tokens: f64, config: &RateLimitConfig) -> Duration {
    let refill_per_second = f64::from(config.requests_per_minute) / 60.0;
    let seconds = ((1.0 - tokens).max(0.0) / refill_per_second)
        .ceil()
        .max(1.0);
    Duration::from_secs(seconds as u64)
}

fn prune_idle_buckets(buckets: &mut HashMap<String, RateLimitBucket>, now: Instant) {
    buckets
        .retain(|_, bucket| now.saturating_duration_since(bucket.last_seen) <= RATE_LIMIT_IDLE_TTL);
}

fn should_rate_limit_path(path: &str) -> bool {
    path.starts_with("/t/") || path.starts_with("/_/oidc/")
}

fn client_key(request: &Request, trust_proxy_headers: bool) -> String {
    if trust_proxy_headers {
        if let Some(forwarded) = forwarded_client(request.headers()) {
            return forwarded;
        }
    }

    request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|connect_info| connect_info.0.ip().to_string())
        .unwrap_or_else(|| "unknown-client".into())
}

fn forwarded_client(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .and_then(sanitize_forwarded_client)
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .and_then(sanitize_forwarded_client)
        })
        .or_else(|| {
            headers
                .get("forwarded")
                .and_then(|value| value.to_str().ok())
                .and_then(parse_forwarded_header)
        })
}

fn parse_forwarded_header(raw: &str) -> Option<String> {
    raw.split(',').next().and_then(|entry| {
        entry.split(';').find_map(|part| {
            let (key, value) = part.split_once('=')?;
            if key.trim().eq_ignore_ascii_case("for") {
                sanitize_forwarded_client(value)
            } else {
                None
            }
        })
    })
}

fn sanitize_forwarded_client(raw: &str) -> Option<String> {
    let client = raw
        .trim()
        .trim_matches('"')
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim();
    if client.is_empty() || client.len() > 128 || client.eq_ignore_ascii_case("unknown") {
        return None;
    }
    Some(client.to_string())
}

fn too_many_requests(decision: RateLimitDecision) -> Response {
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        "Too many API requests; please retry later.",
    )
        .into_response();
    insert_rate_limit_headers(response.headers_mut(), decision);
    response
}

fn insert_rate_limit_headers(headers: &mut HeaderMap, decision: RateLimitDecision) {
    insert_numeric_header(headers, "x-ratelimit-limit", u64::from(decision.limit));
    insert_numeric_header(
        headers,
        "x-ratelimit-remaining",
        u64::from(decision.remaining),
    );
    if !decision.allowed {
        insert_numeric_header(
            headers,
            header::RETRY_AFTER,
            decision.retry_after.as_secs().max(1),
        );
    }
}

fn insert_numeric_header<K>(headers: &mut HeaderMap, key: K, value: u64)
where
    K: axum::http::header::IntoHeaderName,
{
    if let Ok(value) = HeaderValue::from_str(&value.to_string()) {
        headers.insert(key, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    #[tokio::test]
    async fn limits_after_burst_for_same_client() {
        let limiter = RateLimiter::new(RateLimitConfig {
            enabled: true,
            requests_per_minute: 60,
            burst: 2,
            max_tracked_clients: 16,
            trust_proxy_headers: false,
        });

        assert!(limiter.check("client-a").await.allowed);
        assert!(limiter.check("client-a").await.allowed);
        let decision = limiter.check("client-a").await;

        assert!(!decision.allowed);
        assert_eq!(decision.remaining, 0);
        assert!(decision.retry_after >= Duration::from_secs(1));
    }

    #[tokio::test]
    async fn tracks_clients_independently() {
        let limiter = RateLimiter::new(RateLimitConfig {
            enabled: true,
            requests_per_minute: 60,
            burst: 1,
            max_tracked_clients: 16,
            trust_proxy_headers: false,
        });

        assert!(limiter.check("client-a").await.allowed);
        assert!(!limiter.check("client-a").await.allowed);
        assert!(limiter.check("client-b").await.allowed);
    }

    #[test]
    fn only_limits_package_and_oidc_api_paths() {
        assert!(should_rate_limit_path("/t/acme/simple/"));
        assert!(should_rate_limit_path("/t/acme/files/demo/1.0/demo.whl"));
        assert!(should_rate_limit_path("/_/oidc/mint-token"));
        assert!(!should_rate_limit_path("/"));
        assert!(!should_rate_limit_path("/admin/dashboard"));
    }

    #[test]
    fn client_key_prefers_forwarded_header_only_when_trusted() {
        let request = Request::builder()
            .uri("/t/acme/simple/")
            .header("x-forwarded-for", "203.0.113.5, 10.0.0.1")
            .body(Body::empty())
            .expect("request");

        assert_eq!(client_key(&request, true), "203.0.113.5");
        assert_eq!(client_key(&request, false), "unknown-client");
    }

    #[test]
    fn parses_forwarded_header_for_client_address() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "forwarded",
            HeaderValue::from_static("for=\"198.51.100.7\";proto=https"),
        );

        assert_eq!(forwarded_client(&headers).as_deref(), Some("198.51.100.7"));
    }
}
