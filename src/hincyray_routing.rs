//! Routing/resource helpers shared by daemon handlers and tests.
//!
//! The browser and HTTP layer pass a user-visible resource descriptor. This
//! module owns normalization into a typed domain/IP resource so downstream
//! handlers do not guess from raw UI strings.

use std::net::{IpAddr, Ipv4Addr};

/// Canonical port alternatives, preserving the legacy source/inbound prefixes.
/// Separators inside an item have the same OR meaning as separate array items.
pub fn normalize_port_items(items: &[String]) -> Result<Vec<String>, String> {
    if items.iter().map(String::len).sum::<usize>() > 4096 {
        return Err("port list exceeds 4096 bytes".to_owned());
    }
    let mut result = Vec::new();
    let mut count = 0;
    for item in items.iter().flat_map(|item| item.split([',', ';', '\n'])) {
        let item = item.trim();
        let (prefix, body) = if let Some(body) = item.strip_prefix("src-port:") {
            ("src-port:", body)
        } else if let Some(body) = item.strip_prefix("in-port:") {
            ("in-port:", body)
        } else {
            ("", item)
        };
        let previous_count = count;
        for spec in body.split('/').map(str::trim).filter(|s| !s.is_empty()) {
            count += 1;
            if count > 256 {
                return Err("port list exceeds 256 entries".to_owned());
            }
            let parse = |value: &str| -> Result<u16, String> {
                let value = value.trim();
                if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(
                        "expected ports 1–65535 or ascending ranges, e.g. 12000-64000".to_owned(),
                    );
                }
                value
                    .parse::<u16>()
                    .ok()
                    .filter(|port| *port > 0)
                    .ok_or_else(|| "ports must be between 1 and 65535".to_owned())
            };
            let canonical = if let Some((start, end)) = spec.split_once('-') {
                let (start, end) = (parse(start)?, parse(end)?);
                if start > end {
                    return Err("port range start must not exceed its end".to_owned());
                }
                if start == end {
                    start.to_string()
                } else {
                    format!("{start}-{end}")
                }
            } else {
                parse(spec)?.to_string()
            };
            let canonical = format!("{prefix}{canonical}");
            if !result.contains(&canonical) {
                result.push(canonical);
            }
        }
        if !item.is_empty() && previous_count == count {
            return Err("port item requires at least one port".to_owned());
        }
    }
    Ok(result)
}

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
    fn port_lists_accept_alternatives_ranges_and_legacy_prefixes() {
        let items = vec![
            "01119/3724,6113".to_owned(),
            "12000 - 64000; 443\n443".to_owned(),
            "src-port:80/81".to_owned(),
            "in-port:10809".to_owned(),
        ];
        assert_eq!(
            normalize_port_items(&items).expect("valid port list"),
            [
                "1119",
                "3724",
                "6113",
                "12000-64000",
                "443",
                "src-port:80",
                "src-port:81",
                "in-port:10809"
            ]
        );
        for invalid in [
            "0",
            "65536",
            "64000-12000",
            "443,DIRECT",
            "80-81-82",
            "src-port:",
            "///",
            "80 443",
            "-1",
        ] {
            assert!(
                normalize_port_items(&[invalid.to_owned()]).is_err(),
                "{invalid}"
            );
        }
        assert!(normalize_port_items(&["1,".repeat(257)]).is_err());
        assert!(normalize_port_items(&["1".repeat(4097)]).is_err());
        assert_eq!(
            normalize_port_items(&["src-port:80/81,443".to_owned()]).expect("mixed port list"),
            ["src-port:80", "src-port:81", "443"]
        );
    }

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
