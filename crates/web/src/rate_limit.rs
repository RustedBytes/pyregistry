use crate::{error::WebError, state::AppState};
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
    if trust_proxy_headers && let Some(forwarded) = forwarded_client(request.headers()) {
        return forwarded;
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
    let mut response = WebError {
        status: StatusCode::TOO_MANY_REQUESTS,
        message: "Too many API requests; please retry later.".into(),
    }
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
    use std::net::{IpAddr, Ipv4Addr};

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

    #[test]
    fn disabled_config_is_safe_and_summary_is_loggable() {
        let config = RateLimitConfig::disabled();

        assert!(!config.enabled);
        assert_eq!(config.requests_per_minute, 1);
        assert_eq!(config.burst, 1);
        assert_eq!(config.max_tracked_clients, 1);
        assert!(config.log_safe_summary().contains("enabled=false"));

        let limiter = RateLimiter::disabled();
        assert!(!limiter.is_enabled());
        assert!(!limiter.trust_proxy_headers());
        assert!(limiter.log_safe_summary().contains("requests_per_minute=1"));
    }

    #[tokio::test]
    async fn disabled_limiter_always_allows_requests() {
        let limiter = RateLimiter::disabled();

        let first = limiter.check("client-a").await;
        let second = limiter.check("client-a").await;

        assert!(first.allowed);
        assert!(second.allowed);
        assert_eq!(first.retry_after, Duration::ZERO);
    }

    #[test]
    fn normalizes_zero_values_to_minimums() {
        let normalized = normalize_config(RateLimitConfig {
            enabled: true,
            requests_per_minute: 0,
            burst: 0,
            max_tracked_clients: 0,
            trust_proxy_headers: true,
        });

        assert_eq!(normalized.requests_per_minute, 1);
        assert_eq!(normalized.burst, 1);
        assert_eq!(normalized.max_tracked_clients, 1);
        assert!(normalized.trust_proxy_headers);
    }

    #[test]
    fn refill_bucket_restores_tokens_without_exceeding_burst() {
        let config = RateLimitConfig {
            enabled: true,
            requests_per_minute: 60,
            burst: 3,
            max_tracked_clients: 16,
            trust_proxy_headers: false,
        };
        let now = Instant::now();
        let mut bucket = RateLimitBucket {
            tokens: 0.0,
            last_refill: now - Duration::from_secs(10),
            last_seen: now,
        };

        refill_bucket(&mut bucket, &config, now);

        assert_eq!(bucket.tokens, 3.0);
        assert_eq!(bucket.last_refill, now);
    }

    #[test]
    fn retry_after_is_never_zero() {
        let config = RateLimitConfig {
            enabled: true,
            requests_per_minute: 60,
            burst: 1,
            max_tracked_clients: 16,
            trust_proxy_headers: false,
        };

        assert_eq!(retry_after(0.99, &config), Duration::from_secs(1));
        assert_eq!(retry_after(0.0, &config), Duration::from_secs(1));
    }

    #[test]
    fn prunes_only_idle_buckets() {
        let now = Instant::now();
        let mut buckets = HashMap::from([
            (
                "active".to_string(),
                RateLimitBucket {
                    tokens: 1.0,
                    last_refill: now,
                    last_seen: now,
                },
            ),
            (
                "idle".to_string(),
                RateLimitBucket {
                    tokens: 1.0,
                    last_refill: now,
                    last_seen: now - RATE_LIMIT_IDLE_TTL - Duration::from_secs(1),
                },
            ),
        ]);

        prune_idle_buckets(&mut buckets, now);

        assert!(buckets.contains_key("active"));
        assert!(!buckets.contains_key("idle"));
    }

    #[tokio::test]
    async fn rejects_new_clients_when_tracking_capacity_is_full() {
        let limiter = RateLimiter::new(RateLimitConfig {
            enabled: true,
            requests_per_minute: 60,
            burst: 1,
            max_tracked_clients: 1,
            trust_proxy_headers: false,
        });

        assert!(limiter.check("client-a").await.allowed);
        let decision = limiter.check("client-b").await;

        assert!(!decision.allowed);
        assert_eq!(decision.retry_after, RATE_LIMIT_IDLE_TTL);
    }

    #[tokio::test]
    async fn prunes_idle_client_to_make_room_for_new_client() {
        let limiter = RateLimiter::new(RateLimitConfig {
            enabled: true,
            requests_per_minute: 60,
            burst: 1,
            max_tracked_clients: 1,
            trust_proxy_headers: false,
        });
        let now = Instant::now();
        limiter.inner.buckets.lock().await.insert(
            "idle".into(),
            RateLimitBucket {
                tokens: 0.0,
                last_refill: now,
                last_seen: now - RATE_LIMIT_IDLE_TTL - Duration::from_secs(1),
            },
        );

        let decision = limiter.check("client-b").await;

        assert!(decision.allowed);
    }

    #[test]
    fn client_key_uses_connect_info_when_proxy_headers_are_not_trusted() {
        let mut request = Request::builder()
            .uri("/t/acme/simple/")
            .body(Body::empty())
            .expect("request");
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                3000,
            )));

        assert_eq!(client_key(&request, false), "192.0.2.10");
    }

    #[test]
    fn client_key_falls_back_when_trusted_proxy_header_is_unusable() {
        let mut request = Request::builder()
            .uri("/t/acme/simple/")
            .header("x-forwarded-for", "unknown")
            .body(Body::empty())
            .expect("request");
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)),
                3000,
            )));

        assert_eq!(client_key(&request, true), "192.0.2.11");
    }

    #[test]
    fn forwarded_client_prefers_x_forwarded_for_then_real_ip_then_forwarded() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", HeaderValue::from_static("198.51.100.10"));
        headers.insert(
            "forwarded",
            HeaderValue::from_static("for=\"198.51.100.11\";proto=https"),
        );
        assert_eq!(forwarded_client(&headers).as_deref(), Some("198.51.100.10"));

        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.12, 10.0.0.1"),
        );
        assert_eq!(forwarded_client(&headers).as_deref(), Some("203.0.113.12"));
    }

    #[test]
    fn forwarded_client_rejects_unknown_empty_and_overlong_values() {
        assert_eq!(sanitize_forwarded_client("unknown"), None);
        assert_eq!(sanitize_forwarded_client("   "), None);
        assert_eq!(sanitize_forwarded_client(&"a".repeat(129)), None);
        assert_eq!(
            sanitize_forwarded_client("\"[2001:db8::1]\"").as_deref(),
            Some("2001:db8::1")
        );
    }

    #[test]
    fn forwarded_header_skips_non_for_parts() {
        assert_eq!(
            parse_forwarded_header("proto=https; for=198.51.100.20").as_deref(),
            Some("198.51.100.20")
        );
    }

    #[test]
    fn too_many_requests_sets_retry_headers() {
        let response = too_many_requests(RateLimitDecision {
            allowed: false,
            limit: 10,
            remaining: 0,
            retry_after: Duration::from_secs(7),
        });

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response.headers().get("x-ratelimit-limit"),
            Some(&HeaderValue::from_static("10"))
        );
        assert_eq!(
            response.headers().get(header::RETRY_AFTER),
            Some(&HeaderValue::from_static("7"))
        );
    }
}
