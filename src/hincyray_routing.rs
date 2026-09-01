//! Routing/resource helpers shared by daemon handlers and tests.
//!
//! The browser and HTTP layer pass a user-visible resource descriptor. This
//! module owns normalization into a typed domain/IP resource so downstream
//! handlers do not guess from raw UI strings.

use std::net::{IpAddr, Ipv4Addr};

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

pub fn is_mihomo_fake_ip(ip: IpAddr) -> bool {
    let IpAddr::V4(ip) = ip else {
        return false;
    };
    let value = u32::from(ip);
    value >= u32::from(Ipv4Addr::new(198, 18, 0, 0))
        && value <= u32::from(Ipv4Addr::new(198, 19, 255, 255))
}

pub fn normalize_domain_rule(raw: &str) -> Option<String> {
    let value = raw.trim();
    if value.is_empty() {
        return None;
    }
    for prefix in ["geosite:", "keyword:", "regex:", "wildcard:"] {
        if let Some(body) = value.strip_prefix(prefix) {
            let body = body.trim();
            return (!body.is_empty()).then(|| format!("{prefix}{body}"));
        }
    }
    let exact = value.starts_with('=');
    let domain = value
        .trim_start_matches('=')
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if !valid_domain_suffix(&domain) {
        return None;
    }
    Some(if exact { format!("={domain}") } else { domain })
}

fn valid_domain_suffix(value: &str) -> bool {
    value.len() <= 253
        && value.parse::<IpAddr>().is_err()
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
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
    if let Ok(ip) = value.parse::<IpAddr>() {
        if is_mihomo_fake_ip(ip) {
            return None;
        }
        return Some(RoutingResource {
            kind: RoutingResourceKind::Ip,
            value,
        });
    }
    if let Some(value) = normalize_domain_rule(&value) {
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

    #[test]
    fn normalizes_bare_tlds_and_leading_dot_suffixes() {
        for raw in ["ai", ".ai", "..AI."] {
            assert_eq!(normalize_domain_rule(raw).as_deref(), Some("ai"));
            assert_eq!(
                normalize_routing_resource(raw),
                Some(RoutingResource {
                    kind: RoutingResourceKind::Domain,
                    value: "ai".to_owned(),
                })
            );
        }
        assert_eq!(
            normalize_domain_rule("Example.AI.").as_deref(),
            Some("example.ai")
        );
        assert!(normalize_domain_rule("bad..ai").is_none());
    }

    #[test]
    fn rejects_the_full_mihomo_fake_ip_block_as_a_routing_resource() {
        for raw in ["198.18.0.0", "198.18.42.7", "198.19.255.255"] {
            assert!(normalize_routing_resource(raw).is_none(), "{raw}");
        }
        assert!(normalize_routing_resource("198.20.0.1").is_some());
    }
}
