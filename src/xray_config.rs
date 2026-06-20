//! Xray client config generation, shared between the desktop benchmark
//! harness and the HincyRay router daemon.
//!
//! Only VLESS profiles are supported here. Hysteria2 is not implemented
//! by Xray; `build_xray_config` returns an explicit error for it so
//! callers can surface the message rather than producing a broken
//! config. Reality and xhttpSettings are preserved from the share-link
//! query parameters.

use serde_json::{Value, json};
use url::Url;

use crate::profiles::{Profile, Protocol};

pub const WIFI_TUN_INBOUND_TAG: &str = "tun-socks-in";
pub const DIRECT_OUTBOUND_TAG: &str = "direct";
pub const ACTIVE_OUTBOUND_TAG: &str = "active";
pub const BLOCK_OUTBOUND_TAG: &str = "block";

/// A daemon-level Xray routing rule after HincyRay has resolved UI targets
/// (active/fixed/direct) into concrete outbound tags.
#[derive(Clone, Debug)]
pub struct XrayRouteRule {
    pub domains: Vec<String>,
    pub ips: Vec<String>,
    pub outbound_tag: String,
    pub block_quic: bool,
}

/// Build an Xray config for router mode: normal SOCKS inbound plus an
/// optional second SOCKS inbound for tun2socks whose traffic is split by
/// routing rules. tun2socks creates a TUN device and forwards WiFi VPN
/// traffic to this second SOCKS port; no iptables/TPROXY needed.
pub fn build_xray_router_config(
    active_profile: &Profile,
    extra_profiles: &[(&Profile, String)],
    route_rules: &[XrayRouteRule],
    listen_host: &str,
    socks_port: u16,
    tun_socks_port: Option<u16>,
    active_block_quic: bool,
) -> Result<Value, String> {
    let mut inbounds = vec![json!({
        "tag": "socks-in",
        "listen": listen_host,
        "port": socks_port,
        "protocol": "socks",
        "settings": { "udp": true }
    })];

    if let Some(port) = tun_socks_port {
        inbounds.push(json!({
            "tag": WIFI_TUN_INBOUND_TAG,
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "socks",
            "settings": { "udp": true },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"],
                "routeOnly": true
            }
        }));
    }

    let mut outbounds = vec![
        build_profile_outbound(active_profile, ACTIVE_OUTBOUND_TAG)?,
        json!({
            "tag": DIRECT_OUTBOUND_TAG,
            "protocol": "freedom",
            "settings": { "domainStrategy": "AsIs" }
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
    for rule in route_rules {
        if rule.block_quic {
            rules.push(json!({
                "type": "field",
                "inboundTag": [WIFI_TUN_INBOUND_TAG],
                "network": "udp",
                "port": "443",
                "outboundTag": BLOCK_OUTBOUND_TAG,
            }));
        }

        let mut route = json!({
            "type": "field",
            "inboundTag": [WIFI_TUN_INBOUND_TAG],
            "outboundTag": rule.outbound_tag,
        });
        if !rule.domains.is_empty() {
            route["domain"] = json!(rule.domains);
        }
        if !rule.ips.is_empty() {
            route["ip"] = json!(rule.ips);
        }
        if route.get("domain").is_some() || route.get("ip").is_some() {
            rules.push(route);
        }
    }

    // Only WiFi tun2socks inbound gets split rules. Anything else,
    // including direct SOCKS clients, keeps the traditional
    // active-profile behaviour.
    if tun_socks_port.is_some() {
        if active_block_quic {
            rules.push(json!({
                "type": "field",
                "inboundTag": [WIFI_TUN_INBOUND_TAG],
                "network": "udp",
                "port": "443",
                "outboundTag": BLOCK_OUTBOUND_TAG,
            }));
        }
        rules.push(json!({
            "type": "field",
            "inboundTag": [WIFI_TUN_INBOUND_TAG],
            "outboundTag": ACTIVE_OUTBOUND_TAG,
        }));
    }

    Ok(json!({
        "log": { "loglevel": "warning" },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": rules
        }
    }))
}

/// Build an Xray client config that exposes a SOCKS5 endpoint on
/// `listen_host:port` and routes traffic through the given profile.
pub fn build_xray_config(profile: &Profile, listen_host: &str, port: u16) -> Result<Value, String> {
    let outbound = match &profile.protocol {
        Protocol::Vless => build_profile_outbound(profile, "proxy")?,
        Protocol::Hysteria2 => {
            return Err(
                "Xray не поддерживает Hysteria2; используйте sing-box или mihomo".to_owned(),
            );
        }
        Protocol::Unknown(scheme) => {
            return Err(format!("Xray не поддерживает протокол {scheme}"));
        }
    };

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
        Protocol::Hysteria2 => {
            Err("Xray не поддерживает Hysteria2; используйте sing-box или mihomo".to_owned())
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
        // without depending on parse_input producing one.
        let mut profile = profile;
        profile.protocol = crate::profiles::Protocol::Unknown("trojan".to_owned());
        let error = build_xray_config(&profile, "127.0.0.1", 10808)
            .expect_err("unknown protocol should be rejected");
        assert!(error.contains("trojan"));
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
}
