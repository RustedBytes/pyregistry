use crate::{error::WebError, state::AppState};
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use log::{debug, warn};
use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

#[derive(Debug, Clone)]
pub struct NetworkSourceConfig {
    pub web_ui_allowed_cidrs: Vec<String>,
    pub api_allowed_cidrs: Vec<String>,
    pub trust_proxy_headers: bool,
}

impl NetworkSourceConfig {
    #[must_use]
    pub fn allow_all() -> Self {
        Self {
            web_ui_allowed_cidrs: Vec::new(),
            api_allowed_cidrs: Vec::new(),
            trust_proxy_headers: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkSourcePolicy {
    web_ui_allowed_networks: Vec<IpNetwork>,
    api_allowed_networks: Vec<IpNetwork>,
    trust_proxy_headers: bool,
}

impl NetworkSourcePolicy {
    #[must_use]
    pub fn new(config: NetworkSourceConfig) -> Self {
        Self {
            web_ui_allowed_networks: parse_networks(&config.web_ui_allowed_cidrs),
            api_allowed_networks: parse_networks(&config.api_allowed_cidrs),
            trust_proxy_headers: config.trust_proxy_headers,
        }
    }

    #[must_use]
    pub fn allow_all() -> Self {
        Self::new(NetworkSourceConfig::allow_all())
    }

    #[must_use]
    pub fn trust_proxy_headers(&self) -> bool {
        self.trust_proxy_headers
    }

    #[must_use]
    pub fn allows_web_ui(&self, ip: IpAddr) -> bool {
        allows(&self.web_ui_allowed_networks, ip)
    }

    #[must_use]
    pub fn allows_api(&self, ip: IpAddr) -> bool {
        allows(&self.api_allowed_networks, ip)
    }

    fn allows_all_for(&self, surface: AccessSurface) -> bool {
        match surface {
            AccessSurface::WebUi => self.web_ui_allowed_networks.is_empty(),
            AccessSurface::Api => self.api_allowed_networks.is_empty(),
        }
    }

    #[must_use]
    pub fn log_safe_summary(&self) -> String {
        format!(
            "web_ui_allowed_cidrs={}, api_allowed_cidrs={}, trust_proxy_headers={}",
            summarize_networks(&self.web_ui_allowed_networks),
            summarize_networks(&self.api_allowed_networks),
            self.trust_proxy_headers
        )
    }
}

pub(crate) async fn enforce_network_source_access(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(surface) = AccessSurface::from_path(request.uri().path()) else {
        return next.run(request).await;
    };
    if state.network_source.allows_all_for(surface) {
        return next.run(request).await;
    }

    let Some(client_ip) = client_ip(&request, state.network_source.trust_proxy_headers()) else {
        warn!(
            "network source access denied for {} path `{}` because client IP could not be determined",
            surface.as_str(),
            request.uri().path()
        );
        return forbidden_network_source().into_response();
    };

    let allowed = match surface {
        AccessSurface::WebUi => state.network_source.allows_web_ui(client_ip),
        AccessSurface::Api => state.network_source.allows_api(client_ip),
    };
    if !allowed {
        warn!(
            "network source access denied for {} client `{client_ip}` path `{}`",
            surface.as_str(),
            request.uri().path()
        );
        return forbidden_network_source().into_response();
    }

    debug!(
        "network source access allowed for {} client `{client_ip}` path `{}`",
        surface.as_str(),
        request.uri().path()
    );
    next.run(request).await
}

pub(crate) fn client_ip(request: &Request, trust_proxy_headers: bool) -> Option<IpAddr> {
    if trust_proxy_headers && let Some(forwarded) = forwarded_client_ip(request.headers()) {
        return Some(forwarded);
    }

    request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|connect_info| connect_info.0.ip())
}

pub(crate) fn client_key(request: &Request, trust_proxy_headers: bool) -> String {
    client_ip(request, trust_proxy_headers)
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown-client".into())
}

pub(crate) fn forwarded_client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .and_then(sanitize_forwarded_client_ip)
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .and_then(sanitize_forwarded_client_ip)
        })
        .or_else(|| {
            headers
                .get("forwarded")
                .and_then(|value| value.to_str().ok())
                .and_then(parse_forwarded_header)
        })
}

fn parse_forwarded_header(raw: &str) -> Option<IpAddr> {
    raw.split(',').next().and_then(|entry| {
        entry.split(';').find_map(|part| {
            let (key, value) = part.split_once('=')?;
            if key.trim().eq_ignore_ascii_case("for") {
                sanitize_forwarded_client_ip(value)
            } else {
                None
            }
        })
    })
}

fn sanitize_forwarded_client_ip(raw: &str) -> Option<IpAddr> {
    let client = raw
        .trim()
        .trim_matches('"')
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim();
    if client.is_empty() || client.len() > 128 || client.eq_ignore_ascii_case("unknown") {
        return None;
    }
    client.parse().ok()
}

fn forbidden_network_source() -> WebError {
    WebError {
        status: StatusCode::FORBIDDEN,
        message: "This network source is not allowed to access Pyregistry.".into(),
    }
}

#[derive(Debug, Clone, Copy)]
enum AccessSurface {
    WebUi,
    Api,
}

impl AccessSurface {
    fn from_path(path: &str) -> Option<Self> {
        if path.starts_with("/t/") || path.starts_with("/_/oidc/") {
            return Some(Self::Api);
        }
        if path == "/" || path.starts_with("/admin") {
            return Some(Self::WebUi);
        }
        None
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::WebUi => "web-ui",
            Self::Api => "api",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IpNetwork {
    addr: IpAddr,
    prefix: u8,
}

impl IpNetwork {
    fn contains(self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                let prefix = self.prefix.min(32);
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                u32::from(network) & mask == u32::from(candidate) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                let prefix = self.prefix.min(128);
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                u128::from(network) & mask == u128::from(candidate) & mask
            }
            _ => false,
        }
    }
}

impl FromStr for IpNetwork {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let raw = raw.trim();
        let Some((addr, prefix)) = raw.split_once('/') else {
            let addr: IpAddr = raw
                .parse()
                .map_err(|error| format!("invalid IP address `{raw}`: {error}"))?;
            let prefix = match addr {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            return Ok(Self { addr, prefix });
        };
        let addr: IpAddr = addr
            .trim()
            .parse()
            .map_err(|error| format!("invalid CIDR address `{raw}`: {error}"))?;
        let prefix: u8 = prefix
            .trim()
            .parse()
            .map_err(|error| format!("invalid CIDR prefix `{raw}`: {error}"))?;
        let max_prefix = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max_prefix {
            return Err(format!(
                "CIDR prefix `{prefix}` is too large for `{addr}`; max is {max_prefix}"
            ));
        }
        Ok(Self { addr, prefix })
    }
}

fn parse_networks(raw_networks: &[String]) -> Vec<IpNetwork> {
    raw_networks
        .iter()
        .map(|network| {
            network
                .parse()
                .expect("network source CIDRs must be validated before building web policy")
        })
        .collect()
}

fn allows(networks: &[IpNetwork], ip: IpAddr) -> bool {
    networks.is_empty() || networks.iter().any(|network| network.contains(ip))
}

fn summarize_networks(networks: &[IpNetwork]) -> String {
    if networks.is_empty() {
        return "all".into();
    }
    networks.len().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::HeaderValue;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn policy_allows_empty_lists_and_checks_distinct_surfaces() {
        let allow_all = NetworkSourcePolicy::allow_all();
        assert!(allow_all.allows_web_ui(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))));
        assert!(allow_all.allows_api(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))));

        let policy = NetworkSourcePolicy::new(NetworkSourceConfig {
            web_ui_allowed_cidrs: vec!["10.0.0.0/8".into()],
            api_allowed_cidrs: vec!["192.0.2.0/24".into()],
            trust_proxy_headers: false,
        });

        assert!(policy.allows_web_ui(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(!policy.allows_web_ui(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))));
        assert!(policy.allows_api(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))));
        assert!(!policy.allows_api(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
    }

    #[test]
    fn cidr_matching_supports_v4_v6_and_single_ip_entries() {
        let v4: IpNetwork = "192.0.2.0/24".parse().expect("v4 cidr");
        assert!(v4.contains(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55))));
        assert!(!v4.contains(IpAddr::V4(Ipv4Addr::new(192, 0, 3, 55))));

        let v6: IpNetwork = "2001:db8::/32".parse().expect("v6 cidr");
        assert!(v6.contains(IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().expect("v6"))));
        assert!(!v6.contains(IpAddr::V6("2001:db9::1".parse::<Ipv6Addr>().expect("v6"))));

        let single: IpNetwork = "203.0.113.8".parse().expect("single ip");
        assert!(single.contains(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8))));
        assert!(!single.contains(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))));
    }

    #[test]
    fn rejects_invalid_cidr_prefixes() {
        assert!("192.0.2.0/33".parse::<IpNetwork>().is_err());
        assert!("2001:db8::/129".parse::<IpNetwork>().is_err());
        assert!("not-an-ip".parse::<IpNetwork>().is_err());
    }

    #[test]
    fn client_ip_uses_connect_info_unless_proxy_headers_are_trusted() {
        let mut request = Request::builder()
            .uri("/admin/dashboard")
            .header("x-forwarded-for", "203.0.113.5")
            .body(Body::empty())
            .expect("request");
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                3000,
            )));

        assert_eq!(
            client_ip(&request, false),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
        );
        assert_eq!(
            client_ip(&request, true),
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)))
        );
    }

    #[test]
    fn forwarded_client_prefers_x_forwarded_for_then_real_ip_then_forwarded() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", HeaderValue::from_static("198.51.100.10"));
        headers.insert(
            "forwarded",
            HeaderValue::from_static("for=\"198.51.100.11\";proto=https"),
        );
        assert_eq!(
            forwarded_client_ip(&headers),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)))
        );

        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.12, 10.0.0.1"),
        );
        assert_eq!(
            forwarded_client_ip(&headers),
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 12)))
        );
    }

    #[test]
    fn forwarded_client_rejects_unknown_empty_and_non_ip_values() {
        assert_eq!(sanitize_forwarded_client_ip("unknown"), None);
        assert_eq!(sanitize_forwarded_client_ip("   "), None);
        assert_eq!(sanitize_forwarded_client_ip("example.test"), None);
        assert_eq!(
            sanitize_forwarded_client_ip("\"[2001:db8::1]\""),
            Some(IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().expect("v6")))
        );
    }
}
