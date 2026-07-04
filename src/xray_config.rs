//! Xray client config generation, shared between the desktop benchmark
//! harness and the HincyRay router daemon.
//!
//! Supports VLESS (Reality + xhttpSettings), VMess, Trojan, and
//! Shadowsocks profiles. Hysteria2 and WireGuard are not implemented
//! by Xray; `build_xray_config` returns an explicit error for them so
//! callers can surface the message rather than producing a broken
//! config.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

use crate::profiles::{Profile, Protocol, decode_vmess_json};

pub const REDIR_INBOUND_TAG: &str = "redir-in";
pub const TPROXY_INBOUND_TAG: &str = "tproxy-in";
pub const DNS_INBOUND_TAG: &str = "dns-in";
pub const DNS_INBOUND_PORT: u16 = 1053;
pub const DIRECT_OUTBOUND_TAG: &str = "direct";
pub const ACTIVE_OUTBOUND_TAG: &str = "active";
pub const BLOCK_OUTBOUND_TAG: &str = "block";

/// Port-based routing mode for WiFi VPN traffic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum PortMode {
    /// Proxy all ports (default, current behaviour).
    #[default]
    All,
    /// Only proxy ports listed in `proxy_ports`; everything else goes direct.
    AllowList,
    /// Proxy everything except ports in `bypass_ports` (those go direct).
    DenyList,
}

/// QUIC (UDP/443) handling mode for the WiFi VPN segment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum QuicMode {
    /// Block QUIC at the Xray routing level, forcing TCP fallback.
    /// Used when TPROXY is unavailable or when the proxy protocol
    /// doesn't support UDP well.
    #[default]
    Block,
    /// Proxy QUIC through TPROXY. Requires `xt_TPROXY` kernel module
    /// and `tproxy_available = true`.
    Proxy,
}

/// DNS anti-leak settings. When enabled, the Xray config includes a
/// `dns` section with remote DNS servers and routes DNS queries
/// through the proxy to prevent leaks via the system resolver.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_remote_dns")]
    pub remote_servers: Vec<String>,
    #[serde(default = "default_local_dns")]
    pub local_servers: Vec<String>,
    #[serde(default = "default_query_strategy")]
    pub query_strategy: String,
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            remote_servers: default_remote_dns(),
            local_servers: default_local_dns(),
            query_strategy: default_query_strategy(),
        }
    }
}

fn default_remote_dns() -> Vec<String> {
    vec!["https://1.1.1.1/dns-query".to_owned(), "8.8.8.8".to_owned()]
}

fn default_local_dns() -> Vec<String> {
    vec!["223.5.5.5".to_owned(), "223.6.6.6".to_owned()]
}

fn default_query_strategy() -> String {
    "UseIPv4".to_owned()
}

/// Extra router-level config passed to `build_xray_router_config` for
/// DNS anti-leak, port-based routing, and GeoIP/GeoSite asset paths.
#[derive(Clone, Debug, Default)]
pub struct RouterExtra {
    pub dns: Option<DnsSettings>,
    pub port_mode: PortMode,
    pub proxy_ports: Vec<String>,
    pub bypass_ports: Vec<String>,
    pub geo_asset_path: Option<String>,
    /// v0.16: RU Direct mode — `"off"`, `"tld"`, or `"geosite"`.
    pub ru_direct_mode: String,
    /// v0.16: Domains exempt from RU Direct (go through VPN).
    pub ru_direct_exceptions: Vec<String>,
    /// v0.16: MATCH rule target — `"proxy"` (default) or `"direct"`.
    /// Controls the final fallback rule: `MATCH,proxy` or `MATCH,direct`.
    pub match_target: String,
    /// v0.17: RKN Bypass — when true, injects a RULE-SET provider that
    /// downloads a list of domains blocked in Russia and routes them
    /// through proxy. Also injects GEOIP,RU,DIRECT and GEOIP,CN,DIRECT
    /// so Russian/Chinese IPs go direct.
    pub rkn_bypass_enabled: bool,
    /// v0.17: URL for the RKN bypass rule provider. Defaults to
    /// `itworksig/rublacklist` bypass.list on GitHub.
    pub rkn_bypass_url: String,
    /// v0.17: Update interval for the RKN bypass rule provider (seconds).
    /// Default: 86400 (24 hours).
    pub rkn_bypass_interval: u32,
}

/// A daemon-level Xray routing rule after HincyRay has resolved UI targets
/// (active/fixed/direct) into concrete outbound tags.
#[derive(Clone, Debug)]
pub struct XrayRouteRule {
    pub domains: Vec<String>,
    pub ips: Vec<String>,
    pub outbound_tag: String,
    pub block_quic: bool,
    pub ports: Vec<String>,
    pub network: Option<String>,
    /// v0.16: Port matching mode.
    /// `"include"` (default) — DST-PORT rules emitted separately.
    /// `"exclude"` — domain/IP rules wrapped in AND with NOT,DST-PORT.
    pub port_mode: String,
}

/// Build an Xray config for router mode: normal SOCKS inbound plus
/// optional dokodemo-door inbounds for NAT REDIRECT (TCP) and TPROXY
/// (UDP) transparent proxying. iptables redirects traffic from devices
/// assigned to the Keenetic "HincyRay" policy into these inbounds.
#[allow(clippy::too_many_arguments)]
pub fn build_xray_router_config(
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
) -> Result<Value, String> {
    let mut inbounds = vec![json!({
        "tag": "socks-in",
        "listen": listen_host,
        "port": socks_port,
        "protocol": "socks",
        "settings": { "udp": true }
    })];

    if let Some(port) = redirect_port {
        // TCP dokodemo-door for NAT REDIRECT. iptables nat PREROUTING
        // REDIRECTs TCP traffic from policy-marked devices to this port.
        // followRedirect: true tells Xray to use the original destination
        // from the redirected connection (SO_ORIGINAL_DST).
        inbounds.push(json!({
            "tag": REDIR_INBOUND_TAG,
            "listen": "0.0.0.0",
            "port": port,
            "protocol": "dokodemo-door",
            "settings": { "network": "tcp", "followRedirect": true },
            "sniffing": {
                "enabled": true,
                "routeOnly": true,
                "destOverride": ["http", "tls"]
            }
        }));

        // UDP dokodemo-door for mangle TPROXY. Only created when the
        // kernel has xt_TPROXY + xt_socket modules. iptables mangle
        // PREROUTING TPROXY-ies UDP traffic to this port. The
        // sockopt.tproxy: "tproxy" sets IP_TRANSPARENT on the socket.
        if tproxy_available {
            inbounds.push(json!({
                "tag": TPROXY_INBOUND_TAG,
                "listen": "0.0.0.0",
                "port": port,
                "protocol": "dokodemo-door",
                "settings": { "network": "udp", "followRedirect": true },
                "streamSettings": { "sockopt": { "tproxy": "tproxy" } },
                "sniffing": {
                    "enabled": true,
                    "routeOnly": true,
                    "destOverride": ["quic"]
                }
            }));
        }

        // Dokodemo DNS inbound for the VPN WiFi segment. DNS queries
        // from policy-marked devices are DNAT'd to 127.0.0.1:1053.
        // Xray receives them here and forwards to 1.1.1.1:53 through
        // the active outbound, preventing DNS leaks to the ISP.
        inbounds.push(json!({
            "tag": DNS_INBOUND_TAG,
            "listen": "127.0.0.1",
            "port": DNS_INBOUND_PORT,
            "protocol": "dokodemo-door",
            "settings": {
                "address": "1.1.1.1",
                "port": 53,
                "network": "tcp,udp"
            }
        }));
    }

    let mut outbounds = vec![
        build_profile_outbound(active_profile, ACTIVE_OUTBOUND_TAG)?,
        json!({
            "tag": DIRECT_OUTBOUND_TAG,
            "protocol": "freedom",
            "settings": {
                "domainStrategy": if extra.dns.as_ref().is_some_and(|d| d.enabled) {
                    "UseIP"
                } else {
                    "AsIs"
                }
            }
        }),
        json!({
            "tag": BLOCK_OUTBOUND_TAG,
            "protocol": "blackhole",
            "settings": {}
        }),
    ];

    for (profile, tag) in extra_profiles {
        outbounds.push(build_profile_outbound(profile, tag)?);
    }

    let mut rules = Vec::new();
    // DNS queries from the dokodemo inbound go through the active proxy.
    if redirect_port.is_some() {
        rules.push(json!({
            "type": "field",
            "inboundTag": [DNS_INBOUND_TAG],
            "outboundTag": ACTIVE_OUTBOUND_TAG,
        }));
    }

    // Build the list of transparent-proxy inbound tags. When TPROXY is
    // available, both TCP (redir-in) and UDP (tproxy-in) inbounds
    // exist. When TPROXY is unavailable, only TCP (redir-in) exists
    // and all UDP traffic (including QUIC) is blocked at the iptables
    // level (not proxied).
    let vpn_tags: Vec<&str> = if tproxy_available {
        vec![REDIR_INBOUND_TAG, TPROXY_INBOUND_TAG]
    } else {
        vec![REDIR_INBOUND_TAG]
    };

    for rule in route_rules {
        if rule.block_quic {
            rules.push(json!({
                "type": "field",
                "inboundTag": vpn_tags,
                "network": "udp",
                "port": "443",
                "outboundTag": BLOCK_OUTBOUND_TAG,
            }));
        }

        let mut route = json!({
            "type": "field",
            "inboundTag": vpn_tags,
            "outboundTag": rule.outbound_tag,
        });
        if !rule.domains.is_empty() {
            route["domain"] = json!(rule.domains);
        }
        if !rule.ips.is_empty() {
            route["ip"] = json!(rule.ips);
        }
        if !rule.ports.is_empty() {
            route["port"] = json!(rule.ports.join(","));
        }
        if let Some(net) = &rule.network {
            route["network"] = json!(net);
        }
        if route.get("domain").is_some()
            || route.get("ip").is_some()
            || route.get("port").is_some()
            || route.get("network").is_some()
        {
            rules.push(route);
        }
    }

    // Only transparent-proxy inbounds get split rules. Anything else,
    // including direct SOCKS clients, keeps the traditional
    // active-profile behaviour.
    if redirect_port.is_some() {
        // Port-based routing: insert port rules before the final fallback.
        match &extra.port_mode {
            PortMode::AllowList if !extra.proxy_ports.is_empty() => {
                rules.push(json!({
                    "type": "field",
                    "inboundTag": vpn_tags,
                    "port": extra.proxy_ports.join(","),
                    "outboundTag": ACTIVE_OUTBOUND_TAG,
                }));
                // Everything else goes direct.
                rules.push(json!({
                    "type": "field",
                    "inboundTag": vpn_tags,
                    "outboundTag": DIRECT_OUTBOUND_TAG,
                }));
            }
            PortMode::DenyList if !extra.bypass_ports.is_empty() => {
                rules.push(json!({
                    "type": "field",
                    "inboundTag": vpn_tags,
                    "port": extra.bypass_ports.join(","),
                    "outboundTag": DIRECT_OUTBOUND_TAG,
                }));
                // Everything else falls through to active below.
            }
            _ => {}
        }

        // QUIC handling: when QuicMode::Block (or TPROXY unavailable),
        // block UDP/443 at the Xray routing level. This forces browsers
        // to fall back to TCP, which works fine for streaming/browsing.
        let should_block_quic =
            active_block_quic || quic_mode == QuicMode::Block || !tproxy_available;
        if should_block_quic {
            rules.push(json!({
                "type": "field",
                "inboundTag": vpn_tags,
                "network": "udp",
                "port": "443",
                "outboundTag": BLOCK_OUTBOUND_TAG,
            }));
        }
        rules.push(json!({
            "type": "field",
            "inboundTag": vpn_tags,
            "outboundTag": ACTIVE_OUTBOUND_TAG,
        }));
    }

    let mut config = json!({
        "log": { "loglevel": "warning" },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": rules
        }
    });

    // DNS anti-leak section.
    if let Some(dns) = &extra.dns
        && dns.enabled
    {
        let mut dns_servers: Vec<Value> = Vec::new();
        // Remote DNS servers for proxied domains.
        for server in &dns.remote_servers {
            dns_servers.push(json!({
                "address": server,
                "domains": ["geosite:geolocation-!cn"],
            }));
        }
        // Local DNS servers for direct (e.g. Chinese) domains.
        if !dns.local_servers.is_empty() {
            for server in &dns.local_servers {
                dns_servers.push(json!({
                    "address": server,
                    "domains": ["geosite:cn"],
                    "expectIPs": ["geoip:cn"],
                }));
            }
        }
        // Fallback: localhost for everything else.
        dns_servers.push(json!("localhost"));

        config["dns"] = json!({
            "servers": dns_servers,
            "queryStrategy": dns.query_strategy,
        });
    }

    Ok(config)
}

/// Build an Xray client config that exposes a SOCKS5 endpoint on
/// `listen_host:port` and routes traffic through the given profile.
pub fn build_xray_config(profile: &Profile, listen_host: &str, port: u16) -> Result<Value, String> {
    let outbound = build_profile_outbound(profile, "proxy")?;

    Ok(json!({
        "log": { "loglevel": "error" },
        "inbounds": [{
            "listen": listen_host,
            "port": port,
            "protocol": "socks",
            "settings": { "udp": true }
        }],
        "outbounds": [outbound]
    }))
}

fn build_profile_outbound(profile: &Profile, tag: &str) -> Result<Value, String> {
    match &profile.protocol {
        Protocol::Vless => build_vless_outbound(profile, tag),
        Protocol::VMess => build_vmess_outbound(profile, tag),
        Protocol::Trojan => build_trojan_outbound(profile, tag),
        Protocol::Shadowsocks => build_shadowsocks_outbound(profile, tag),
        Protocol::ShadowsocksR
        | Protocol::Snell
        | Protocol::Http
        | Protocol::Socks
        | Protocol::AnyTls
        | Protocol::Hysteria
        | Protocol::Ssh
        | Protocol::Masque
        | Protocol::OpenVpn
        | Protocol::Tailscale => Err(format!(
            "Xray не поддерживает {}; используйте Mihomo",
            profile.protocol
        )),
        Protocol::Hysteria2 => {
            Err("Xray не поддерживает Hysteria2; используйте sing-box или mihomo".to_owned())
        }
        Protocol::WireGuard => {
            Err("Xray не поддерживает WireGuard; используйте sing-box или mihomo".to_owned())
        }
        Protocol::Tuic => {
            Err("Xray не поддерживает TUIC; используйте sing-box или mihomo".to_owned())
        }
        Protocol::Unknown(scheme) => Err(format!("Xray не поддерживает протокол {scheme}")),
    }
}

fn build_vless_outbound(profile: &Profile, tag: &str) -> Result<Value, String> {
    let url = Url::parse(&profile.raw).map_err(|error| error.to_string())?;
    let uuid = url.username();
    if uuid.is_empty() {
        return Err("VLESS ссылка без UUID".to_owned());
    }

    let mut user = json!({
        "id": uuid,
        "encryption": "none"
    });
    if let Some(flow) = query_value(&url, "flow").filter(|value| !value.is_empty()) {
        user["flow"] = json!(flow);
    }

    let mut outbound = json!({
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": profile.address,
                "port": profile.port.unwrap_or(443),
                "users": [user]
            }]
        },
        "streamSettings": build_stream_settings(&url)
    });

    outbound["tag"] = json!(tag);
    Ok(outbound)
}

/// Build a VMess outbound from a `vmess://base64(json)` link.
fn build_vmess_outbound(profile: &Profile, tag: &str) -> Result<Value, String> {
    let json = decode_vmess_json(&profile.raw)
        .ok_or_else(|| "VMess: не удалось декодировать base64 JSON".to_owned())?;

    let address = json
        .get("add")
        .and_then(Value::as_str)
        .ok_or_else(|| "VMess: нет адреса (add)".to_owned())?;
    let port = json
        .get("port")
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .ok_or_else(|| "VMess: нет порта (port)".to_owned())?;
    let uuid = json
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| "VMess: нет UUID (id)".to_owned())?;
    let alter_id = json
        .get("aid")
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .unwrap_or(0);
    let security = json.get("scy").and_then(Value::as_str).unwrap_or("auto");

    let mut user = json!({
        "id": uuid,
        "alterId": alter_id,
        "security": security,
    });

    if let Some(flow) = json.get("flow").and_then(Value::as_str)
        && !flow.is_empty()
    {
        user["flow"] = json!(flow);
    }

    let stream = build_vmess_stream_settings(&json);

    let mut outbound = json!({
        "protocol": "vmess",
        "settings": {
            "vnext": [{
                "address": address,
                "port": port,
                "users": [user]
            }]
        },
        "streamSettings": stream
    });

    outbound["tag"] = json!(tag);
    Ok(outbound)
}

/// Build stream settings from a VMess JSON config.
fn build_vmess_stream_settings(json: &Value) -> Value {
    let network = json.get("net").and_then(Value::as_str).unwrap_or("tcp");
    let tls = json.get("tls").and_then(Value::as_str).unwrap_or("");
    let security = if tls == "tls" { "tls" } else { "none" };

    let mut stream = json!({
        "network": network,
        "security": security,
    });

    if security == "tls" {
        let mut tls_settings = json!({});
        if let Some(sni) = json.get("sni").and_then(Value::as_str) {
            tls_settings["serverName"] = json!(sni);
        } else if let Some(host) = json.get("host").and_then(Value::as_str) {
            tls_settings["serverName"] = json!(host);
        }
        if let Some(fp) = json.get("fp").and_then(Value::as_str) {
            tls_settings["fingerprint"] = json!(fp);
        }
        if let Some(alpn) = json.get("alpn").and_then(Value::as_str) {
            tls_settings["alpn"] = json!(alpn.split(',').collect::<Vec<_>>());
        }
        if let Some(allow_insecure) = json.get("allowInsecure").and_then(Value::as_str)
            && (allow_insecure == "1" || allow_insecure == "true")
        {
            tls_settings["allowInsecure"] = json!(true);
        }
        stream["tlsSettings"] = tls_settings;
    }

    if network == "ws" {
        let mut ws = json!({});
        if let Some(path) = json.get("path").and_then(Value::as_str) {
            ws["path"] = json!(path);
        }
        if let Some(host) = json.get("host").and_then(Value::as_str) {
            ws["headers"] = json!({ "Host": host });
        }
        stream["wsSettings"] = ws;
    } else if network == "grpc" {
        let mut grpc = json!({});
        if let Some(path) = json
            .get("path")
            .and_then(Value::as_str)
            .or_else(|| json.get("serviceName").and_then(Value::as_str))
        {
            grpc["serviceName"] = json!(path);
        }
        stream["grpcSettings"] = grpc;
    } else if network == "tcp"
        && let Some(header_type) = json.get("type").and_then(Value::as_str)
        && header_type != "none"
        && !header_type.is_empty()
    {
        stream["tcpSettings"] = json!({
            "header": {
                "type": header_type,
            }
        });
    }

    stream
}

/// Build a Trojan outbound from a `trojan://password@host:port` link.
fn build_trojan_outbound(profile: &Profile, tag: &str) -> Result<Value, String> {
    let url = Url::parse(&profile.raw).map_err(|error| error.to_string())?;
    let password = percent_decode(url.username());
    if password.is_empty() {
        return Err("Trojan ссылка без пароля".to_owned());
    }

    let mut outbound = json!({
        "protocol": "trojan",
        "settings": {
            "servers": [{
                "address": profile.address,
                "port": profile.port.unwrap_or(443),
                "password": password
            }]
        },
        "streamSettings": build_stream_settings(&url)
    });

    outbound["tag"] = json!(tag);
    Ok(outbound)
}

/// Build a Shadowsocks outbound from an `ss://` link.
fn build_shadowsocks_outbound(profile: &Profile, tag: &str) -> Result<Value, String> {
    let (method, password) = extract_ss_credentials(&profile.raw)?;

    let mut outbound = json!({
        "protocol": "shadowsocks",
        "settings": {
            "servers": [{
                "address": profile.address,
                "port": profile.port.unwrap_or(8388),
                "method": method,
                "password": password
            }]
        }
    });

    outbound["tag"] = json!(tag);
    Ok(outbound)
}

/// Extract the Shadowsocks method and password from an `ss://` link.
/// Supports both the new format `ss://base64(method:password)@host:port`
/// and the legacy format `ss://base64(method:password@host:port)`.
pub fn extract_ss_credentials(raw: &str) -> Result<(String, String), String> {
    use base64::engine::general_purpose;

    // Parse manually: ss://userinfo@host:port#name or ss://base64#name
    // We avoid Url::parse here because base64 padding (`=`) in userinfo
    // can confuse some URL parsers.
    let rest = raw
        .strip_prefix("ss://")
        .ok_or_else(|| "Shadowsocks: некорректный формат ссылки".to_owned())?;
    let (before_hash, _) = rest.split_once('#').unwrap_or((rest, ""));

    // New format: userinfo@host:port
    if let Some((userinfo, _hostport)) = before_hash.split_once('@') {
        // Try base64 decode the userinfo first.
        let decoded = general_purpose::STANDARD
            .decode(userinfo)
            .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(userinfo))
            .or_else(|_| general_purpose::URL_SAFE.decode(userinfo))
            .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(userinfo))
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok());
        if let Some(ref decoded) = decoded
            && let Some((method, password)) = decoded.split_once(':')
        {
            return Ok((method.to_owned(), password.to_owned()));
        }
        // Try plain text userinfo (method:password).
        if let Some((method, password)) = userinfo.split_once(':') {
            return Ok((percent_decode(method), percent_decode(password)));
        }
    }

    // Legacy format: ss://base64(method:password@host:port)#name
    let b64_part = before_hash.trim();
    let decoded = general_purpose::STANDARD
        .decode(b64_part)
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(b64_part))
        .or_else(|_| general_purpose::URL_SAFE.decode(b64_part))
        .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(b64_part))
        .map_err(|_| "Shadowsocks: не удалось декодировать base64".to_owned())?;
    let text = String::from_utf8(decoded)
        .map_err(|_| "Shadowsocks: некорректный UTF-8 после декодирования".to_owned())?;

    let (userinfo, _) = text
        .rsplit_once('@')
        .ok_or_else(|| "Shadowsocks: нет @ в декодированной ссылке".to_owned())?;
    let (method, password) = userinfo
        .split_once(':')
        .ok_or_else(|| "Shadowsocks: нет : в методе/пароле".to_owned())?;

    Ok((method.to_owned(), password.to_owned()))
}

fn build_stream_settings(url: &Url) -> Value {
    let network = query_value(url, "type").unwrap_or_else(|| "tcp".to_owned());
    let security = query_value(url, "security").unwrap_or_else(|| "none".to_owned());
    let mut stream = json!({
        "network": network,
        "security": security
    });

    if security == "reality" {
        let mut reality = json!({});
        if let Some(server_name) = query_value(url, "sni").or_else(|| query_value(url, "peer")) {
            reality["serverName"] = json!(server_name);
        }
        if let Some(fingerprint) = query_value(url, "fp") {
            reality["fingerprint"] = json!(fingerprint);
        }
        if let Some(public_key) = query_value(url, "pbk") {
            reality["publicKey"] = json!(public_key);
        }
        if let Some(short_id) = query_value(url, "sid") {
            reality["shortId"] = json!(short_id);
        }
        stream["realitySettings"] = reality;
    }

    if query_value(url, "type").as_deref() == Some("xhttp") {
        let mut xhttp = json!({});
        if let Some(host) = query_value(url, "host").filter(|value| !value.is_empty()) {
            xhttp["host"] = json!(host);
        }
        if let Some(path) = query_value(url, "path")
            .filter(|value| !value.is_empty())
            .or_else(|| Some("/check-update".to_owned()))
        {
            xhttp["path"] = json!(path);
        }
        if let Some(mode) = query_value(url, "mode")
            .filter(|value| !value.is_empty())
            .or_else(|| Some("auto".to_owned()))
        {
            xhttp["mode"] = json!(mode);
        }
        stream["xhttpSettings"] = xhttp;
    }

    stream
}

/// Read a single query parameter from a share-link URL.
pub(crate) fn query_value(url: &Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}

/// Percent-decode a path/fragment component (used for Hysteria2 passwords
/// and other embedded values). Shared with `tester.rs` for sing-box
/// config generation so the two cores see identical decoded inputs.
pub(crate) fn percent_decode(value: &str) -> String {
    percent_encoding::percent_decode_str(value)
        .decode_utf8_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::build_xray_config;
    use crate::profiles::parse_profiles;
    use base64::Engine as _;
    use serde_json::Value;

    #[test]
    fn builds_vless_xhttp_reality_config_with_expected_fields() {
        let profile = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=xhttp&security=reality&sni=www.example.com&fp=chrome&pbk=0123456789abcdef0123456789abcdef0123456789a&sid=abcd#Test",
        )
        .remove(0);

        let config = build_xray_config(&profile, "127.0.0.1", 10808).expect("xray config");

        let inbounds = config
            .get("inbounds")
            .and_then(Value::as_array)
            .expect("inbounds");
        assert_eq!(inbounds.len(), 1);
        assert_eq!(
            inbounds[0].get("listen").and_then(Value::as_str),
            Some("127.0.0.1")
        );
        assert_eq!(inbounds[0].get("port").and_then(Value::as_u64), Some(10808));
        assert_eq!(
            inbounds[0].get("protocol").and_then(Value::as_str),
            Some("socks")
        );

        let outbound = config
            .get("outbounds")
            .and_then(Value::as_array)
            .and_then(|v| v.first())
            .expect("outbound");
        assert_eq!(
            outbound.get("protocol").and_then(Value::as_str),
            Some("vless")
        );
        assert_eq!(outbound.get("tag").and_then(Value::as_str), Some("proxy"));

        let stream = outbound.get("streamSettings").expect("streamSettings");
        assert_eq!(stream.get("network").and_then(Value::as_str), Some("xhttp"));
        assert_eq!(
            stream.get("security").and_then(Value::as_str),
            Some("reality")
        );
        assert_eq!(
            stream
                .get("realitySettings")
                .and_then(|r| r.get("serverName"))
                .and_then(Value::as_str),
            Some("www.example.com")
        );
        assert_eq!(
            stream
                .get("realitySettings")
                .and_then(|r| r.get("fingerprint"))
                .and_then(Value::as_str),
            Some("chrome")
        );
        assert_eq!(
            stream
                .get("realitySettings")
                .and_then(|r| r.get("publicKey"))
                .and_then(Value::as_str),
            Some("0123456789abcdef0123456789abcdef0123456789a")
        );
        assert_eq!(
            stream
                .get("realitySettings")
                .and_then(|r| r.get("shortId"))
                .and_then(Value::as_str),
            Some("abcd")
        );
        assert_eq!(
            stream
                .get("xhttpSettings")
                .and_then(|x| x.get("path"))
                .and_then(Value::as_str),
            Some("/check-update")
        );
        assert_eq!(
            stream
                .get("xhttpSettings")
                .and_then(|x| x.get("mode"))
                .and_then(Value::as_str),
            Some("auto")
        );
    }

    #[test]
    fn rejects_hysteria2_for_xray() {
        let profile =
            parse_profiles("hysteria2://secret@example.com:443?sni=example.com#Test").remove(0);
        let error = build_xray_config(&profile, "127.0.0.1", 10808)
            .expect_err("hysteria2 should be rejected");
        assert!(error.to_lowercase().contains("hysteria2"));
    }

    #[test]
    fn rejects_unknown_protocol_for_xray() {
        let profile =
            parse_profiles("vless://11111111-1111-1111-1111-111111111111@example.com:443#Test")
                .remove(0);
        // Manually corrupt the protocol to exercise the Unknown branch
        // with a genuinely unsupported scheme.
        let mut profile = profile;
        profile.protocol = crate::profiles::Protocol::Unknown("someproto".to_owned());
        let error = build_xray_config(&profile, "127.0.0.1", 10808)
            .expect_err("unknown protocol should be rejected");
        assert!(error.contains("someproto"));
    }

    #[test]
    fn rejects_wireguard_for_xray() {
        let profile =
            parse_profiles("vless://11111111-1111-1111-1111-111111111111@example.com:443#Test")
                .remove(0);
        let mut profile = profile;
        profile.protocol = crate::profiles::Protocol::WireGuard;
        let error = build_xray_config(&profile, "127.0.0.1", 10808)
            .expect_err("wireguard should be rejected");
        assert!(error.to_lowercase().contains("wireguard"));
    }

    #[test]
    fn builds_vmess_config_from_base64_json() {
        // vmess://base64(json) with standard fields.
        let vmess_json = r#"{"v":"2","ps":"VMess Test","add":"example.com","port":"443","id":"11111111-1111-1111-1111-111111111111","aid":"0","net":"ws","type":"none","host":"example.com","path":"/ws","tls":"tls","sni":"example.com"}"#;
        let encoded = base64::engine::general_purpose::STANDARD.encode(vmess_json.as_bytes());
        let link = format!("vmess://{encoded}#VMess Test");
        let profile = parse_profiles(&link).remove(0);

        let config = build_xray_config(&profile, "127.0.0.1", 10808).expect("vmess config");
        let outbound = &config["outbounds"][0];
        assert_eq!(
            outbound.get("protocol").and_then(Value::as_str),
            Some("vmess")
        );
        assert_eq!(outbound.get("tag").and_then(Value::as_str), Some("proxy"));
        let stream = outbound.get("streamSettings").expect("streamSettings");
        assert_eq!(stream.get("network").and_then(Value::as_str), Some("ws"));
        assert_eq!(stream.get("security").and_then(Value::as_str), Some("tls"));
        assert_eq!(
            stream
                .get("wsSettings")
                .and_then(|w| w.get("path"))
                .and_then(Value::as_str),
            Some("/ws")
        );
    }

    #[test]
    fn builds_trojan_config_from_share_link() {
        let profile = parse_profiles(
            "trojan://secretpass@example.com:443?security=tls&sni=www.example.com&type=tcp#Trojan Test",
        )
        .remove(0);

        let config = build_xray_config(&profile, "127.0.0.1", 10808).expect("trojan config");
        let outbound = &config["outbounds"][0];
        assert_eq!(
            outbound.get("protocol").and_then(Value::as_str),
            Some("trojan")
        );
        let servers = outbound
            .get("settings")
            .and_then(|s| s.get("servers"))
            .and_then(Value::as_array)
            .expect("servers array");
        assert_eq!(servers[0]["address"], "example.com");
        assert_eq!(servers[0]["password"], "secretpass");
        assert_eq!(servers[0]["port"], 443);
    }

    #[test]
    fn builds_shadowsocks_config_from_new_format() {
        // ss://base64(method:password)@host:port#name
        let credentials =
            base64::engine::general_purpose::STANDARD.encode(b"aes-256-gcm:secretpass");
        let link = format!("ss://{credentials}@example.com:8388#SS Test");
        let profile = parse_profiles(&link).remove(0);

        let config = build_xray_config(&profile, "127.0.0.1", 10808).expect("ss config");
        let outbound = &config["outbounds"][0];
        assert_eq!(
            outbound.get("protocol").and_then(Value::as_str),
            Some("shadowsocks")
        );
        let servers = outbound
            .get("settings")
            .and_then(|s| s.get("servers"))
            .and_then(Value::as_array)
            .expect("servers array");
        assert_eq!(servers[0]["address"], "example.com");
        assert_eq!(servers[0]["method"], "aes-256-gcm");
        assert_eq!(servers[0]["password"], "secretpass");
    }

    #[test]
    fn builds_shadowsocks_config_from_legacy_format() {
        // ss://base64(method:password@host:port)#name
        let payload = base64::engine::general_purpose::STANDARD
            .encode(b"aes-256-gcm:secretpass@example.com:8388");
        let link = format!("ss://{payload}#SS Legacy");
        let profile = parse_profiles(&link).remove(0);

        let config = build_xray_config(&profile, "127.0.0.1", 10808).expect("ss legacy config");
        let outbound = &config["outbounds"][0];
        assert_eq!(
            outbound.get("protocol").and_then(Value::as_str),
            Some("shadowsocks")
        );
        let servers = outbound
            .get("settings")
            .and_then(|s| s.get("servers"))
            .and_then(Value::as_array)
            .expect("servers array");
        assert_eq!(servers[0]["method"], "aes-256-gcm");
        assert_eq!(servers[0]["password"], "secretpass");
    }

    #[test]
    fn tcp_reality_includes_reality_settings_without_xhttp() {
        let profile = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&sni=www.example.com&type=tcp&fp=chrome&pbk=0123456789abcdef0123456789abcdef0123456789a&sid=abcd#Test",
        )
        .remove(0);

        let config = build_xray_config(&profile, "0.0.0.0", 10808).expect("xray config");
        let outbound = &config["outbounds"][0];
        let stream = &outbound["streamSettings"];
        assert_eq!(stream.get("network").and_then(Value::as_str), Some("tcp"));
        assert!(stream.get("realitySettings").is_some());
        assert!(stream.get("xhttpSettings").is_none());
    }

    #[test]
    fn router_config_with_dns_enabled_adds_dns_section() {
        use super::*;
        let profile = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#Test",
        )
        .remove(0);
        let extra = RouterExtra {
            dns: Some(DnsSettings {
                enabled: true,
                remote_servers: vec!["https://1.1.1.1/dns-query".to_owned()],
                local_servers: vec!["223.5.5.5".to_owned()],
                query_strategy: "UseIPv4".to_owned(),
            }),
            ..Default::default()
        };
        let config = build_xray_router_config(
            &profile,
            &[],
            &[],
            "127.0.0.1",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &extra,
        )
        .expect("router config");
        assert!(config.get("dns").is_some(), "dns section should exist");
        let dns = config.get("dns").expect("dns");
        let servers = dns
            .get("servers")
            .and_then(Value::as_array)
            .expect("dns servers");
        assert!(servers.len() >= 2);
        // Freedom outbound should use UseIP when DNS is enabled.
        let outbounds = config
            .get("outbounds")
            .and_then(Value::as_array)
            .expect("outbounds");
        let freedom = outbounds
            .iter()
            .find(|o| o["tag"] == "direct")
            .expect("direct outbound");
        assert_eq!(freedom["settings"]["domainStrategy"], "UseIP");
    }

    #[test]
    fn router_config_with_dns_disabled_uses_asis() {
        use super::*;
        let profile = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#Test",
        )
        .remove(0);
        let extra = RouterExtra {
            dns: Some(DnsSettings {
                enabled: false,
                ..Default::default()
            }),
            ..Default::default()
        };
        let config = build_xray_router_config(
            &profile,
            &[],
            &[],
            "127.0.0.1",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &extra,
        )
        .expect("router config");
        assert!(config.get("dns").is_none());
        let outbounds = config
            .get("outbounds")
            .and_then(Value::as_array)
            .expect("outbounds");
        let freedom = outbounds
            .iter()
            .find(|o| o["tag"] == "direct")
            .expect("direct outbound");
        assert_eq!(freedom["settings"]["domainStrategy"], "AsIs");
    }

    #[test]
    fn router_config_port_allow_list_proxies_only_listed_ports() {
        use super::*;
        let profile = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#Test",
        )
        .remove(0);
        let extra = RouterExtra {
            port_mode: PortMode::AllowList,
            proxy_ports: vec!["80".to_owned(), "443".to_owned()],
            ..Default::default()
        };
        let config = build_xray_router_config(
            &profile,
            &[],
            &[],
            "127.0.0.1",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &extra,
        )
        .expect("router config");
        let rules = config["routing"]["rules"].as_array().expect("rules");
        // Should have: proxy rule for listed ports, direct rule for everything else.
        assert!(
            rules
                .iter()
                .any(|r| { r["port"] == "80,443" && r["outboundTag"] == "active" })
        );
        assert!(
            rules
                .iter()
                .any(|r| { r["outboundTag"] == "direct" && r.get("port").is_none() })
        );
    }

    #[test]
    fn router_config_port_deny_list_bypasses_listed_ports() {
        use super::*;
        let profile = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#Test",
        )
        .remove(0);
        let extra = RouterExtra {
            port_mode: PortMode::DenyList,
            bypass_ports: vec!["25".to_owned(), "53".to_owned()],
            ..Default::default()
        };
        let config = build_xray_router_config(
            &profile,
            &[],
            &[],
            "127.0.0.1",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &extra,
        )
        .expect("router config");
        let rules = config["routing"]["rules"].as_array().expect("rules");
        // Should have a direct rule for bypassed ports.
        assert!(
            rules
                .iter()
                .any(|r| { r["port"] == "25,53" && r["outboundTag"] == "direct" })
        );
        // Final fallback should still be active.
        assert_eq!(rules.last().expect("fallback")["outboundTag"], "active");
    }
}
