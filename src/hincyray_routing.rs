//! Routing/resource helpers shared by daemon handlers and tests.
//!
//! The browser and HTTP layer pass a user-visible resource descriptor. This
//! module owns normalization into a typed domain/IP resource so downstream
//! handlers do not guess from raw UI strings.

use std::net::IpAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoutingResourceKind {
    Domain,
    Ip,
}

impl RoutingResourceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::Ip => "ip",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutingResource {
    pub kind: RoutingResourceKind,
    pub value: String,
}

pub fn normalize_routing_resource(raw: &str) -> Option<RoutingResource> {
    let mut value = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty() || value == "—" {
        return None;
    }
    if let Some(stripped) = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"))
        && let Some(host) = stripped.split('/').next()
    {
        value = host.to_owned();
    }
    if value.starts_with('[')
        && let Some(end) = value.find(']')
    {
        value = value[1..end].to_owned();
    } else if let Some((host, port)) = value.rsplit_once(':')
        && !host.contains(':')
        && port.bytes().all(|b| b.is_ascii_digit())
    {
        value = host.to_owned();
    }
    let value = value.trim().trim_end_matches('.').to_owned();
    if value.is_empty() {
        return None;
    }
    if value.parse::<IpAddr>().is_ok() {
        return Some(RoutingResource {
            kind: RoutingResourceKind::Ip,
            value,
        });
    }
    if value.contains('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
    {
        return Some(RoutingResource {
            kind: RoutingResourceKind::Domain,
            value,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_routing_resource_classifies_urls_hosts_and_ips() {
        let url = normalize_routing_resource("https://Api.Example.COM:443/path").expect("url");
        assert_eq!(url.kind, RoutingResourceKind::Domain);
        assert_eq!(url.value, "api.example.com");

        let ip = normalize_routing_resource("212.193.155.88:443").expect("ip");
        assert_eq!(ip.kind, RoutingResourceKind::Ip);
        assert_eq!(ip.value, "212.193.155.88");

        let ipv6 = normalize_routing_resource("[2001:db8::1]:443").expect("ipv6");
        assert_eq!(ipv6.kind, RoutingResourceKind::Ip);
        assert_eq!(ipv6.value, "2001:db8::1");
    }
}
