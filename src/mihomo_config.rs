//! Mihomo (Clash.Meta) config generation for the HincyRay router daemon.
//!
//! Mihomo supports all protocols we need in a single binary:
//! VLESS (Reality + XHTTP), VMess, Trojan, Shadowsocks, and Hysteria2.
//! It also provides native domain sniffing (HTTP/TLS/QUIC), fake-ip DNS,
//! and redirect/tproxy listeners for transparent proxying via iptables
//! NAT REDIRECT (TCP) + mangle TPROXY (UDP).
//!
//! This module replaces both `xray_config::build_xray_router_config`
//! and `singbox_config::build_sing_box_router_config` for the router
//! daemon. The desktop benchmark tool (`tester.rs`) still uses
//! `xray_config` for its own config generation.

use serde_json::{Value, json};
use url::Url;

use crate::profiles::{Profile, Protocol, decode_vmess_json};
use crate::xray_config::{
    DNS_INBOUND_PORT, PortMode, QuicMode, RouterExtra, XrayRouteRule, extract_ss_credentials,
    percent_decode, query_value,
};

/// Tag/name constants used in generated Mihomo configs.
pub const PROXY_NAME: &str = "proxy";
pub const DIRECT_NAME: &str = "DIRECT";
pub const REJECT_NAME: &str = "REJECT";
pub const REDIR_LISTENER: &str = "redir-in";
pub const TPROXY_LISTENER: &str = "tproxy-in";

/// Build a simple Mihomo config with just a SOCKS5 listener.
/// Used when split routing is disabled.
pub fn build_mihomo_config(
    profile: &Profile,
    listen_host: &str,
    socks_port: u16,
) -> Result<String, String> {
    let proxy = build_proxy(profile, PROXY_NAME)?;
    let config = json!({
        "mode": "rule",
        "log-level": "info",
        "allow-lan": true,
        "bind-address": bind_address(listen_host),
        "find-process-mode": "off",
        "ipv6": false,
        "socks-port": socks_port,
        "proxies": [proxy],
        "rules": [format!("MATCH,{}", PROXY_NAME)],
    });
    serde_yaml::to_string(&config).map_err(|error| error.to_string())
}

/// Build a full router Mihomo config with transparent proxy listeners
/// (redirect/tproxy), DNS anti-leak, domain sniffing, and split routing
/// rules. Used when split routing is enabled.
#[allow(clippy::too_many_arguments)]
pub fn build_mihomo_router_config(
    active_profile: &Profile,
    extra_profiles: &[(&Profile, String)],
    route_rules: &[XrayRouteRule],
    listen_host: &str,
    socks_port: u16,
    redirect_port: Option<u16>,
    tproxy_available: bool,
    quic_mode: QuicMode,
    active_block_quic: bool,
    extra: &RouterExtra,
) -> Result<String, String> {
    let mut proxies = vec![build_proxy(active_profile, PROXY_NAME)?];
    for (profile, name) in extra_profiles {
        proxies.push(build_proxy(profile, name)?);
    }

    let mut rules = Vec::new();
    for rule in route_rules {
        rules.extend(rule_to_strings(rule));
    }

    let should_block_quic = active_block_quic || quic_mode == QuicMode::Block || !tproxy_available;
    if should_block_quic {
        rules.push(format!(
            "AND,((NETWORK,udp),(DST-PORT,443)),{}",
            REJECT_NAME
        ));
    }

    match extra.port_mode {
        PortMode::AllowList if !extra.proxy_ports.is_empty() => {
            for port in &extra.proxy_ports {
                rules.push(format!("DST-PORT,{},{}", port, PROXY_NAME));
            }
            rules.push(format!("MATCH,{}", DIRECT_NAME));
        }
        PortMode::DenyList if !extra.bypass_ports.is_empty() => {
            for port in &extra.bypass_ports {
                rules.push(format!("DST-PORT,{},{}", port, DIRECT_NAME));
            }
            rules.push(format!("MATCH,{}", PROXY_NAME));
        }
        _ => {
            rules.push(format!("MATCH,{}", PROXY_NAME));
        }
    }

    let redirect_port = redirect_port.unwrap_or(10810);
    let mut listeners = vec![json!({
        "name": REDIR_LISTENER,
        "type": "redir",
        "port": redirect_port,
        "listen": "0.0.0.0",
    })];
    if tproxy_available {
        listeners.push(json!({
            "name": TPROXY_LISTENER,
            "type": "tproxy",
            "port": redirect_port,
            "listen": "0.0.0.0",
            "udp": true,
        }));
    }

    let mut config = json!({
        "mode": "rule",
        "log-level": "info",
        "allow-lan": true,
        "bind-address": bind_address(listen_host),
        "find-process-mode": "off",
        "ipv6": false,
        "socks-port": socks_port,
        "listeners": listeners,
        "proxies": proxies,
        "rules": rules,
        "sniffer": {
            "enable": true,
            "force-dns-mapping": true,
            "parse-pure-ip": true,
            "override-destination": false,
            "sniff": {
                "HTTP": {
                    "ports": [80, "8080-8880"],
                    "override-destination": true,
                },
                "TLS": {
                    "ports": [443, 8443],
                },
                "QUIC": {
                    "ports": [443, 8443],
                },
            },
        },
    });

    if let Some(dns) = &extra.dns
        && dns.enabled
    {
        config["dns"] = build_dns_config(dns);
    }

    serde_yaml::to_string(&config).map_err(|error| error.to_string())
}

/// Build the DNS anti-leak section when enabled.
fn build_dns_config(dns: &crate::xray_config::DnsSettings) -> Value {
    let mut dns_config = json!({
        "enable": true,
        "listen": format!("0.0.0.0:{}", DNS_INBOUND_PORT),
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "nameserver": dns.remote_servers,
        "fallback": dns.remote_servers,
    });
    if !dns.local_servers.is_empty() {
        dns_config["nameserver-policy"] = json!({
            "geosite:cn": dns.local_servers,
        });
    }
    if dns.query_strategy == "UseIPv6" || dns.query_strategy == "UseIP" {
        dns_config["ipv6"] = json!(true);
    }
    dns_config
}

/// Map a listen host to the Mihomo `bind-address` value.
fn bind_address(listen_host: &str) -> &str {
    if listen_host == "0.0.0.0" {
        "*"
    } else {
        listen_host
    }
}

/// Build a Mihomo proxy object (without the wrapping array) for the given
/// profile and name tag.
fn build_proxy(profile: &Profile, name: &str) -> Result<Value, String> {
    match profile.protocol {
        Protocol::Vless => build_vless_proxy(profile, name),
        Protocol::VMess => build_vmess_proxy(profile, name),
        Protocol::Trojan => build_trojan_proxy(profile, name),
        Protocol::Shadowsocks => build_shadowsocks_proxy(profile, name),
        Protocol::Hysteria2 => build_hysteria2_proxy(profile, name),
        Protocol::Unknown(ref scheme) => Err(format!("Mihomo не поддерживает протокол {scheme}")),
    }
}

/// Build a VLESS proxy for Mihomo.
fn build_vless_proxy(profile: &Profile, name: &str) -> Result<Value, String> {
    let url = Url::parse(&profile.raw).map_err(|error| error.to_string())?;
    let uuid = url.username();
    if uuid.is_empty() {
        return Err("VLESS ссылка без UUID".to_owned());
    }

    let security = query_value(&url, "security").unwrap_or_else(|| "none".to_owned());
    let network = query_value(&url, "type").unwrap_or_else(|| "tcp".to_owned());

    let mut proxy = json!({
        "name": name,
        "type": "vless",
        "server": profile.address,
        "port": profile.port.unwrap_or(443),
        "uuid": uuid,
        "network": network,
        "packet-encoding": "xudp",
    });

    if let Some(flow) = query_value(&url, "flow").filter(|value| !value.is_empty()) {
        proxy["flow"] = json!(flow);
    }

    if security != "none" {
        proxy["tls"] = json!(true);
    }

    if let Some(servername) = query_value(&url, "sni").or_else(|| query_value(&url, "peer")) {
        proxy["servername"] = json!(servername);
    }

    if let Some(fingerprint) = query_value(&url, "fp").filter(|value| !value.is_empty()) {
        proxy["client-fingerprint"] = json!(fingerprint);
    }

    if is_truthy_option(
        query_value(&url, "allowInsecure")
            .or_else(|| query_value(&url, "insecure"))
            .as_deref(),
    ) {
        proxy["skip-cert-verify"] = json!(true);
    }

    if let Some(alpn) = query_value(&url, "alpn").filter(|value| !value.is_empty()) {
        proxy["alpn"] = json!(
            alpn.split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>()
        );
    }

    if security == "reality"
        && let Some(public_key) = query_value(&url, "pbk")
    {
        let mut reality_opts = json!({
            "public-key": public_key,
        });
        if let Some(short_id) = query_value(&url, "sid") {
            reality_opts["short-id"] = json!(short_id);
        }
        proxy["reality-opts"] = reality_opts;
    }

    match network.as_str() {
        "xhttp" => {
            let mut xhttp_opts = json!({});
            if let Some(path) = query_value(&url, "path").filter(|value| !value.is_empty()) {
                xhttp_opts["path"] = json!(path);
            }
            if let Some(host) = query_value(&url, "host").filter(|value| !value.is_empty()) {
                xhttp_opts["host"] = json!(host);
            }
            if let Some(mode) = query_value(&url, "mode").filter(|value| !value.is_empty()) {
                xhttp_opts["mode"] = json!(mode);
            }
            proxy["xhttp-opts"] = xhttp_opts;
        }
        "ws" => {
            let mut ws_opts = json!({});
            if let Some(path) = query_value(&url, "path").filter(|value| !value.is_empty()) {
                ws_opts["path"] = json!(path);
            }
            if let Some(host) = query_value(&url, "host").filter(|value| !value.is_empty()) {
                ws_opts["headers"] = json!({ "Host": host });
            }
            proxy["ws-opts"] = ws_opts;
        }
        "grpc" => {
            if let Some(service_name) =
                query_value(&url, "serviceName").filter(|value| !value.is_empty())
            {
                proxy["grpc-opts"] = json!({ "grpc-service-name": service_name });
            }
        }
        _ => {}
    }

    Ok(proxy)
}

/// Build a VMess proxy for Mihomo from a `vmess://base64(json)` link.
fn build_vmess_proxy(profile: &Profile, name: &str) -> Result<Value, String> {
    let json = decode_vmess_json(&profile.raw)
        .ok_or_else(|| "VMess: не удалось декодировать base64 JSON".to_owned())?;

    let address = json
        .get("add")
        .and_then(Value::as_str)
        .ok_or_else(|| "VMess: нет адреса (add)".to_owned())?;
    let port = json
        .get("port")
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
        })
        .ok_or_else(|| "VMess: нет порта (port)".to_owned())? as u16;
    let uuid = json
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| "VMess: нет UUID (id)".to_owned())?;
    let alter_id = json
        .get("aid")
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
        })
        .unwrap_or(0);
    let cipher = json.get("scy").and_then(Value::as_str).unwrap_or("auto");

    let network = json.get("net").and_then(Value::as_str).unwrap_or("tcp");
    let tls = json.get("tls").and_then(Value::as_str).unwrap_or("") == "tls";

    let mut proxy = json!({
        "name": name,
        "type": "vmess",
        "server": address,
        "port": port,
        "uuid": uuid,
        "alterId": alter_id,
        "cipher": cipher,
        "network": network,
        "packet-encoding": "xudp",
    });

    if tls {
        proxy["tls"] = json!(true);
    }

    if let Some(servername) = json
        .get("sni")
        .and_then(Value::as_str)
        .or_else(|| json.get("host").and_then(Value::as_str))
    {
        proxy["servername"] = json!(servername);
    }

    if let Some(fingerprint) = json.get("fp").and_then(Value::as_str) {
        proxy["client-fingerprint"] = json!(fingerprint);
    }

    if let Some(allow_insecure) = json.get("allowInsecure").and_then(Value::as_str)
        && (allow_insecure == "1" || allow_insecure.eq_ignore_ascii_case("true"))
    {
        proxy["skip-cert-verify"] = json!(true);
    }

    if let Some(alpn) = json.get("alpn").and_then(Value::as_str) {
        proxy["alpn"] = json!(
            alpn.split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>()
        );
    }

    if network == "ws" {
        let mut ws_opts = json!({});
        if let Some(path) = json.get("path").and_then(Value::as_str) {
            ws_opts["path"] = json!(path);
        }
        if let Some(host) = json.get("host").and_then(Value::as_str) {
            ws_opts["headers"] = json!({ "Host": host });
        }
        proxy["ws-opts"] = ws_opts;
    }

    Ok(proxy)
}

/// Build a Trojan proxy for Mihomo.
fn build_trojan_proxy(profile: &Profile, name: &str) -> Result<Value, String> {
    let url = Url::parse(&profile.raw).map_err(|error| error.to_string())?;
    let password = percent_decode(url.username());
    if password.is_empty() {
        return Err("Trojan ссылка без пароля".to_owned());
    }

    let security = query_value(&url, "security").unwrap_or_else(|| "tls".to_owned());
    let network = query_value(&url, "type").filter(|value| !value.is_empty());

    let mut proxy = json!({
        "name": name,
        "type": "trojan",
        "server": profile.address,
        "port": profile.port.unwrap_or(443),
        "password": password,
    });

    if security != "none" {
        proxy["tls"] = json!(true);
    }

    if let Some(sni) = query_value(&url, "sni").or_else(|| query_value(&url, "peer")) {
        proxy["sni"] = json!(sni);
    }

    if let Some(fingerprint) = query_value(&url, "fp").filter(|value| !value.is_empty()) {
        proxy["client-fingerprint"] = json!(fingerprint);
    }

    if is_truthy_option(
        query_value(&url, "allowInsecure")
            .or_else(|| query_value(&url, "insecure"))
            .as_deref(),
    ) {
        proxy["skip-cert-verify"] = json!(true);
    }

    if let Some(alpn) = query_value(&url, "alpn").filter(|value| !value.is_empty()) {
        proxy["alpn"] = json!(
            alpn.split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>()
        );
    }

    if let Some(net) = network {
        proxy["network"] = json!(net);
        if net == "ws" {
            let mut ws_opts = json!({});
            if let Some(path) = query_value(&url, "path").filter(|value| !value.is_empty()) {
                ws_opts["path"] = json!(path);
            }
            if let Some(host) = query_value(&url, "host").filter(|value| !value.is_empty()) {
                ws_opts["headers"] = json!({ "Host": host });
            }
            proxy["ws-opts"] = ws_opts;
        }
    }

    Ok(proxy)
}

/// Build a Shadowsocks proxy for Mihomo.
fn build_shadowsocks_proxy(profile: &Profile, name: &str) -> Result<Value, String> {
    let (method, password) = extract_ss_credentials(&profile.raw)?;

    Ok(json!({
        "name": name,
        "type": "ss",
        "server": profile.address,
        "port": profile.port.unwrap_or(8388),
        "cipher": method,
        "password": password,
    }))
}

/// Build a Hysteria2 proxy for Mihomo.
fn build_hysteria2_proxy(profile: &Profile, name: &str) -> Result<Value, String> {
    let url = Url::parse(&profile.raw).map_err(|error| error.to_string())?;

    let password = if url.username().is_empty() {
        query_value(&url, "password").unwrap_or_default()
    } else {
        percent_decode(url.username())
    };

    let mut proxy = json!({
        "name": name,
        "type": "hysteria2",
        "server": profile.address,
        "port": profile.port.unwrap_or(443),
        "password": password,
    });

    if let Some(sni) = query_value(&url, "sni") {
        proxy["sni"] = json!(sni);
    }

    if let Some(up) = query_value(&url, "upmbps").and_then(|value| value.parse::<u64>().ok()) {
        proxy["up"] = json!(format!("{up} Mbps"));
    }

    if let Some(down) = query_value(&url, "downmbps").and_then(|value| value.parse::<u64>().ok()) {
        proxy["down"] = json!(format!("{down} Mbps"));
    }

    if let Some(obfs) = query_value(&url, "obfs") {
        proxy["obfs"] = json!(obfs);
    }

    if let Some(obfs_password) =
        query_value(&url, "obfs-password").or_else(|| query_value(&url, "obfsPassword"))
    {
        proxy["obfs-password"] = json!(obfs_password);
    }

    if is_truthy_option(query_value(&url, "insecure").as_deref()) {
        proxy["skip-cert-verify"] = json!(true);
    }

    if let Some(alpn) = query_value(&url, "alpn").filter(|value| !value.is_empty()) {
        proxy["alpn"] = json!(
            alpn.split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>()
        );
    }

    Ok(proxy)
}

/// Convert a daemon-level route rule into Mihomo rule strings.
fn rule_to_strings(rule: &XrayRouteRule) -> Vec<String> {
    let target = outbound_tag_to_name(&rule.outbound_tag);
    let mut result = Vec::new();

    for domain in &rule.domains {
        result.push(domain_rule(domain, &target));
    }
    for ip in &rule.ips {
        result.push(format!("IP-CIDR,{},{}", ip, target));
    }
    for port in &rule.ports {
        result.push(format!("DST-PORT,{},{}", port, target));
    }
    if let Some(network) = &rule.network {
        result.push(format!("NETWORK,{},{}", network, target));
    }

    result
}

/// Build a single domain rule string for Mihomo.
fn domain_rule(domain: &str, target: &str) -> String {
    if let Some(name) = domain.strip_prefix("geosite:") {
        format!("GEOSITE,{},{}", name, target)
    } else if let Some(exact) = domain.strip_prefix('=') {
        format!("DOMAIN,{},{}", exact, target)
    } else {
        format!("DOMAIN-SUFFIX,{},{}", domain, target)
    }
}

/// Map an Xray outbound tag to a Mihomo proxy name.
fn outbound_tag_to_name(tag: &str) -> String {
    match tag {
        "active" => PROXY_NAME.to_owned(),
        "direct" => DIRECT_NAME.to_owned(),
        _ => tag.to_owned(),
    }
}

/// Check whether a query parameter value is truthy (1 or true).
fn is_truthy_option(value: Option<&str>) -> bool {
    value.is_some_and(|text| text == "1" || text.eq_ignore_ascii_case("true"))
}

#[cfg(test)]
mod tests {
    use super::{
        PROXY_NAME, REDIR_LISTENER, TPROXY_LISTENER, build_hysteria2_proxy, build_mihomo_config,
        build_mihomo_router_config, build_shadowsocks_proxy, build_trojan_proxy, build_vless_proxy,
        build_vmess_proxy,
    };
    use crate::profiles::parse_profiles;
    use crate::xray_config::{DnsSettings, PortMode, QuicMode, RouterExtra, XrayRouteRule};
    use base64::Engine as _;
    use serde_json::Value;

    #[test]
    fn build_vless_proxy_has_correct_fields() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp&security=tls&sni=example.com&fp=chrome#Test",
        );
        let profile = &profiles[0];
        let proxy = build_vless_proxy(profile, PROXY_NAME).expect("vless proxy");

        assert_eq!(proxy.get("type").and_then(Value::as_str), Some("vless"));
        assert_eq!(
            proxy.get("server").and_then(Value::as_str),
            Some("example.com")
        );
        assert_eq!(proxy.get("port").and_then(Value::as_u64), Some(443));
        assert_eq!(
            proxy.get("uuid").and_then(Value::as_str),
            Some("11111111-1111-1111-1111-111111111111")
        );
    }

    #[test]
    fn build_vless_reality_proxy_has_reality_opts() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&pbk=pubkey123&sid=shortid&sni=example.com#Test",
        );
        let profile = &profiles[0];
        let proxy = build_vless_proxy(profile, PROXY_NAME).expect("vless proxy");

        let reality_opts = proxy.get("reality-opts").expect("reality-opts");
        assert_eq!(
            reality_opts.get("public-key").and_then(Value::as_str),
            Some("pubkey123")
        );
        assert_eq!(
            reality_opts.get("short-id").and_then(Value::as_str),
            Some("shortid")
        );
    }

    #[test]
    fn build_vless_xhttp_proxy_has_xhttp_opts() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=xhttp&security=reality&pbk=pubkey123&sid=shortid&path=/path&host=example.com&sni=example.com&mode=auto#Test",
        );
        let profile = &profiles[0];
        let proxy = build_vless_proxy(profile, PROXY_NAME).expect("vless proxy");

        assert_eq!(proxy.get("network").and_then(Value::as_str), Some("xhttp"));
        let xhttp_opts = proxy.get("xhttp-opts").expect("xhttp-opts");
        assert_eq!(
            xhttp_opts.get("path").and_then(Value::as_str),
            Some("/path")
        );
        assert_eq!(
            xhttp_opts.get("host").and_then(Value::as_str),
            Some("example.com")
        );
        assert_eq!(xhttp_opts.get("mode").and_then(Value::as_str), Some("auto"));
    }

    #[test]
    fn build_vmess_proxy_decodes_base64_json() {
        let vmess_json = r#"{"v":"2","ps":"VMess Test","add":"example.com","port":"443","id":"11111111-1111-1111-1111-111111111111","aid":"0","net":"ws","type":"none","host":"example.com","path":"/ws","tls":"tls","sni":"example.com"}"#;
        let encoded = base64::engine::general_purpose::STANDARD.encode(vmess_json.as_bytes());
        let link = format!("vmess://{encoded}#VMess Test");
        let profiles = parse_profiles(&link);
        let profile = &profiles[0];
        let proxy = build_vmess_proxy(profile, PROXY_NAME).expect("vmess proxy");

        assert_eq!(proxy.get("type").and_then(Value::as_str), Some("vmess"));
        assert_eq!(
            proxy.get("server").and_then(Value::as_str),
            Some("example.com")
        );
        assert_eq!(proxy.get("port").and_then(Value::as_u64), Some(443));
        assert_eq!(proxy.get("network").and_then(Value::as_str), Some("ws"));
    }

    #[test]
    fn build_trojan_proxy_has_password() {
        let profiles = parse_profiles(
            "trojan://secretpass@example.com:443?security=tls&sni=www.example.com&type=tcp#Trojan Test",
        );
        let profile = &profiles[0];
        let proxy = build_trojan_proxy(profile, PROXY_NAME).expect("trojan proxy");

        assert_eq!(proxy.get("type").and_then(Value::as_str), Some("trojan"));
        assert_eq!(
            proxy.get("password").and_then(Value::as_str),
            Some("secretpass")
        );
        assert_eq!(proxy.get("tls").and_then(Value::as_bool), Some(true));
    }

    #[test]
    fn build_shadowsocks_proxy_has_method_and_password() {
        let profiles = parse_profiles("ss://aes-256-gcm:password@example.com:8388#SS Test");
        let profile = &profiles[0];
        let proxy = build_shadowsocks_proxy(profile, PROXY_NAME).expect("ss proxy");

        assert_eq!(proxy.get("type").and_then(Value::as_str), Some("ss"));
        assert_eq!(
            proxy.get("cipher").and_then(Value::as_str),
            Some("aes-256-gcm")
        );
        assert_eq!(
            proxy.get("password").and_then(Value::as_str),
            Some("password")
        );
    }

    #[test]
    fn build_hysteria2_proxy_has_password_and_tls() {
        let profiles = parse_profiles("hysteria2://secret@example.com:443?sni=example.com#Test");
        let profile = &profiles[0];
        let proxy = build_hysteria2_proxy(profile, PROXY_NAME).expect("hysteria2 proxy");

        assert_eq!(proxy.get("type").and_then(Value::as_str), Some("hysteria2"));
        assert_eq!(
            proxy.get("password").and_then(Value::as_str),
            Some("secret")
        );
        assert_eq!(
            proxy.get("sni").and_then(Value::as_str),
            Some("example.com")
        );
    }

    #[test]
    fn build_hysteria2_proxy_includes_up_down() {
        let profiles = parse_profiles(
            "hysteria2://secret@example.com:443?sni=example.com&upmbps=30&downmbps=200#Test",
        );
        let profile = &profiles[0];
        let proxy = build_hysteria2_proxy(profile, PROXY_NAME).expect("hysteria2 proxy");

        assert_eq!(proxy.get("up").and_then(Value::as_str), Some("30 Mbps"));
        assert_eq!(proxy.get("down").and_then(Value::as_str), Some("200 Mbps"));
    }

    #[test]
    fn build_mihomo_config_has_socks_port_and_match_rule() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let yaml = build_mihomo_config(profile, "127.0.0.1", 10808).expect("mihomo config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");

        assert_eq!(
            config.get("socks-port").and_then(Value::as_u64),
            Some(10808)
        );
        let rules = config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules");
        let last_rule = rules
            .last()
            .expect("last rule")
            .as_str()
            .expect("string rule");
        assert_eq!(last_rule, "MATCH,proxy");
    }

    #[test]
    fn build_mihomo_router_config_has_redirect_and_tproxy() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let yaml = build_mihomo_router_config(
            profile,
            &[],
            &[],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &RouterExtra::default(),
        )
        .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");

        let listeners = config
            .get("listeners")
            .and_then(Value::as_array)
            .expect("listeners");
        let names: Vec<_> = listeners
            .iter()
            .filter_map(|listener| listener.get("name").and_then(Value::as_str))
            .collect();
        assert!(names.contains(&REDIR_LISTENER));
        assert!(names.contains(&TPROXY_LISTENER));
    }

    #[test]
    fn build_mihomo_router_config_omits_tproxy_when_unavailable() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let yaml = build_mihomo_router_config(
            profile,
            &[],
            &[],
            "0.0.0.0",
            10808,
            Some(10810),
            false,
            QuicMode::Block,
            false,
            &RouterExtra::default(),
        )
        .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");

        let listeners = config
            .get("listeners")
            .and_then(Value::as_array)
            .expect("listeners");
        assert_eq!(listeners.len(), 1);
        assert_eq!(
            listeners[0].get("name").and_then(Value::as_str),
            Some(REDIR_LISTENER)
        );
    }

    #[test]
    fn build_mihomo_router_config_has_sniffer() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let yaml = build_mihomo_router_config(
            profile,
            &[],
            &[],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &RouterExtra::default(),
        )
        .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");

        let sniffer = config.get("sniffer").expect("sniffer");
        assert_eq!(sniffer.get("enable").and_then(Value::as_bool), Some(true));
        let sniff = sniffer.get("sniff").expect("sniff");
        assert!(sniff.get("HTTP").is_some());
        assert!(sniff.get("TLS").is_some());
        assert!(sniff.get("QUIC").is_some());
    }

    #[test]
    fn build_mihomo_router_config_has_dns_when_enabled() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let dns = DnsSettings {
            enabled: true,
            ..Default::default()
        };
        let extra = RouterExtra {
            dns: Some(dns),
            ..RouterExtra::default()
        };
        let yaml = build_mihomo_router_config(
            profile,
            &[],
            &[],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &extra,
        )
        .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");

        let dns_section = config.get("dns").expect("dns");
        assert_eq!(
            dns_section.get("enable").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            dns_section.get("listen").and_then(Value::as_str),
            Some("0.0.0.0:1053")
        );
    }

    #[test]
    fn build_mihomo_router_config_quic_block_adds_reject_rule() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let yaml = build_mihomo_router_config(
            profile,
            &[],
            &[],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &RouterExtra::default(),
        )
        .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");

        let rules = config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules");
        let has_quic_block = rules
            .iter()
            .any(|rule| rule.as_str() == Some("AND,((NETWORK,udp),(DST-PORT,443)),REJECT"));
        assert!(has_quic_block);
    }

    #[test]
    fn build_mihomo_router_config_all_protocols_supported() {
        let vmess_json = r#"{"v":"2","ps":"VMess","add":"example.com","port":443,"id":"11111111-1111-1111-1111-111111111111","aid":0,"net":"tcp"}"#;
        let encoded = base64::engine::general_purpose::STANDARD.encode(vmess_json.as_bytes());
        let links = vec![
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#VLESS"
                .to_owned(),
            format!("vmess://{encoded}#VMess"),
            "trojan://secret@example.com:443?sni=example.com#Trojan".to_owned(),
            "ss://aes-256-gcm:password@example.com:8388#SS".to_owned(),
            "hysteria2://secret@example.com:443?sni=example.com#Hy2".to_owned(),
        ];

        for link in &links {
            let profiles = parse_profiles(link);
            let profile = &profiles[0];
            let yaml = build_mihomo_router_config(
                profile,
                &[],
                &[],
                "0.0.0.0",
                10808,
                Some(10810),
                true,
                QuicMode::Block,
                false,
                &RouterExtra::default(),
            )
            .expect("router config for all protocols");
            assert!(yaml.contains("mode: rule"));
        }
    }

    #[test]
    fn build_mihomo_router_config_route_rules_map_outbound_tags() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let rule = XrayRouteRule {
            domains: vec!["geosite:cn".to_owned()],
            ips: vec!["192.168.0.0/16".to_owned()],
            outbound_tag: "direct".to_owned(),
            block_quic: false,
            ports: vec!["53".to_owned()],
            network: Some("udp".to_owned()),
        };
        let yaml = build_mihomo_router_config(
            profile,
            &[],
            &[rule],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &RouterExtra::default(),
        )
        .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");

        let rules = config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules");
        let rule_strings: Vec<_> = rules.iter().filter_map(|rule| rule.as_str()).collect();
        assert!(rule_strings.contains(&"GEOSITE,cn,DIRECT"));
        assert!(rule_strings.contains(&"IP-CIDR,192.168.0.0/16,DIRECT"));
        assert!(rule_strings.contains(&"DST-PORT,53,DIRECT"));
        assert!(rule_strings.contains(&"NETWORK,udp,DIRECT"));
    }

    #[test]
    fn build_mihomo_router_config_allowlist_ports_go_direct_by_default() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let extra = RouterExtra {
            port_mode: PortMode::AllowList,
            proxy_ports: vec!["443".to_owned(), "8443".to_owned()],
            ..RouterExtra::default()
        };
        let yaml = build_mihomo_router_config(
            profile,
            &[],
            &[],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &extra,
        )
        .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");

        let rules = config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules");
        let rule_strings: Vec<_> = rules.iter().filter_map(|rule| rule.as_str()).collect();
        assert!(rule_strings.contains(&"DST-PORT,443,proxy"));
        assert!(rule_strings.contains(&"DST-PORT,8443,proxy"));
        assert_eq!(rule_strings.last().copied(), Some("MATCH,DIRECT"));
    }
}
