use std::fmt;

use base64::{Engine as _, engine::general_purpose};
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Vless,
    Hysteria2,
    Unknown(String),
}

impl Protocol {
    fn from_scheme(scheme: &str) -> Self {
        match scheme.to_ascii_lowercase().as_str() {
            "vless" => Self::Vless,
            "hysteria" | "hysteria2" | "hy2" => Self::Hysteria2,
            other => Self::Unknown(other.to_owned()),
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vless => f.write_str("VLESS"),
            Self::Hysteria2 => f.write_str("Hysteria2"),
            Self::Unknown(value) => f.write_str(value),
        }
    }
}

impl Profile {
    pub fn transport(&self) -> String {
        Url::parse(&self.raw)
            .ok()
            .and_then(|url| {
                url.query_pairs()
                    .find(|(name, _)| name == "type")
                    .map(|(_, value)| value.into_owned())
            })
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "tcp".to_owned())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Profile {
    pub id: usize,
    pub name: String,
    pub protocol: Protocol,
    pub address: String,
    pub port: Option<u16>,
    pub raw: String,
    pub selected: bool,
    /// Optional subscription/group label. `None` (absent in older
    /// state files, populated via `serde(default)`) is shown as the
    /// "Direct" group in the daemon web panel. Profiles loaded from a
    /// subscription URL are tagged with that URL so the UI can group
    /// them; profiles pasted directly are tagged with the user-supplied
    /// group name (if any) on import.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SubscriptionSource {
    pub url: String,
}

#[derive(Clone, Debug, Default)]
pub struct ParseOutput {
    pub profiles: Vec<Profile>,
    pub subscriptions: Vec<SubscriptionSource>,
    pub candidates: usize,
    pub unsupported_placeholders: usize,
}

#[derive(Clone, Debug)]
pub struct SubscriptionLoadReport {
    pub profiles: Vec<Profile>,
    pub response_bytes: usize,
    pub decoded_chars: usize,
    pub unsupported_placeholders: usize,
}

pub fn parse_profiles(input: &str) -> Vec<Profile> {
    let mut output = parse_input(input);
    assign_ids(&mut output.profiles);
    output.profiles
}

pub fn parse_input(input: &str) -> ParseOutput {
    let mut output = ParseOutput::default();

    let candidates = extract_candidates(input);
    output.candidates = candidates.len();

    for candidate in candidates {
        if is_unsupported_placeholder(&candidate) {
            output.unsupported_placeholders += 1;
        } else if let Some(profile) = parse_profile_candidate(&candidate) {
            output.profiles.push(profile);
        } else if is_subscription_url(&candidate) {
            output
                .subscriptions
                .push(SubscriptionSource { url: candidate });
        }
    }

    if output.profiles.is_empty() {
        let json_profiles = parse_json_profiles(input);
        if !json_profiles.is_empty() {
            // Candidate scan picks up DNS-over-HTTPS and other URLs embedded in
            // Xray-style JSON; once outbounds parse into real profiles, those URLs
            // are not subscription sources, so drop the false positives.
            output.profiles = json_profiles;
            output.subscriptions.clear();
        }
    }

    assign_ids(&mut output.profiles);
    output
}

pub fn load_subscription(source: &SubscriptionSource) -> Result<Vec<Profile>, String> {
    load_subscription_detailed(source).map(|report| report.profiles)
}

pub fn load_subscription_detailed(
    source: &SubscriptionSource,
) -> Result<SubscriptionLoadReport, String> {
    load_subscription_detailed_via_proxy(source, None)
}

/// Fetch and parse a subscription, optionally through a proxy URL
/// (e.g. `socks5h://127.0.0.1:10808`). Used by the HincyRay daemon to
/// fall back to the local Xray SOCKS inbound on isolated routers when
/// direct fetch fails. `proxy = None` is the desktop path and must
/// behave exactly like `load_subscription_detailed`.
pub fn load_subscription_detailed_via_proxy(
    source: &SubscriptionSource,
    proxy: Option<&str>,
) -> Result<SubscriptionLoadReport, String> {
    let mut response = fetch_subscription(source, SubscriptionRequestMode::SingBox, proxy)?;
    let (mut decoded, mut parsed) = parse_subscription_response(&response);

    if should_retry_as_happ(&parsed) {
        response = fetch_subscription(source, SubscriptionRequestMode::HappAndroid, proxy)?;
        (decoded, parsed) = parse_subscription_response(&response);
    }

    Ok(SubscriptionLoadReport {
        profiles: parsed.profiles,
        response_bytes: response.len(),
        decoded_chars: decoded.chars().count(),
        unsupported_placeholders: parsed.unsupported_placeholders,
    })
}

enum SubscriptionRequestMode {
    SingBox,
    HappAndroid,
}

fn fetch_subscription(
    source: &SubscriptionSource,
    mode: SubscriptionRequestMode,
    proxy: Option<&str>,
) -> Result<String, String> {
    let mut builder = reqwest::blocking::Client::builder().user_agent(match mode {
        SubscriptionRequestMode::SingBox => subscription_user_agent(),
        SubscriptionRequestMode::HappAndroid => happ_user_agent(),
    });
    if let Some(proxy_url) = proxy {
        // `Proxy::all` validates the URL before any network I/O, so a
        // malformed proxy surfaces here without touching the network.
        let proxy = reqwest::Proxy::all(proxy_url)
            .map_err(|error| format!("{}: proxy {proxy_url}: {error}", source.url))?;
        builder = builder.proxy(proxy);
    }
    let client = builder.build().map_err(|error| error.to_string())?;
    let mut request = client.get(&source.url);

    if matches!(mode, SubscriptionRequestMode::HappAndroid) {
        request = request
            .header("X-HWID", "0000000000000000")
            .header("X-Ver-OS", "15")
            .header("X-Bundle-ID", "su.happ.proxyutility")
            .header("X-Device-model", "GM1911")
            .header("X-Device-OS", "Android")
            .header("X-API-Version", "1.0");
    }

    request
        .send()
        .map_err(|error| format!("{}: {error}", source.url))?
        .error_for_status()
        .map_err(|error| format!("{}: {error}", source.url))?
        .text()
        .map_err(|error| format!("{}: {error}", source.url))
}

fn parse_subscription_response(response: &str) -> (String, ParseOutput) {
    let decoded = decode_subscription_body(response);
    let mut parsed = parse_input(&decoded);

    if parsed.profiles.is_empty() {
        parsed.profiles = parse_json_profiles(&decoded);
        assign_ids(&mut parsed.profiles);
    }

    if parsed.profiles.is_empty() && decoded != response {
        parsed = parse_input(response);
        if parsed.profiles.is_empty() {
            parsed.profiles = parse_json_profiles(response);
            assign_ids(&mut parsed.profiles);
        }
    }

    (decoded, parsed)
}

fn should_retry_as_happ(parsed: &ParseOutput) -> bool {
    parsed.profiles.is_empty()
}

fn subscription_user_agent() -> &'static str {
    "sing-box/1.13.13"
}

fn happ_user_agent() -> &'static str {
    "Happ/3.22.1"
}

fn decode_subscription_body(body: &str) -> String {
    let compact = body.trim().replace(['\r', '\n', ' '], "");
    for engine in [
        &general_purpose::STANDARD,
        &general_purpose::STANDARD_NO_PAD,
        &general_purpose::URL_SAFE,
        &general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(bytes) = engine.decode(&compact)
            && let Ok(text) = String::from_utf8(bytes)
        {
            return text;
        }
    }

    body.to_owned()
}

fn extract_candidates(input: &str) -> Vec<String> {
    input
        .split(|character: char| {
            character.is_whitespace() || matches!(character, '"' | '\'' | '<' | '>')
        })
        .filter_map(clean_candidate)
        .collect()
}

fn clean_candidate(value: &str) -> Option<String> {
    let cleaned = value.trim().trim_matches(|character| {
        matches!(
            character,
            '\\' | '{' | '}' | ',' | ';' | ')' | '(' | '[' | ']' | '\u{00a0}'
        )
    });

    if cleaned.contains("://") {
        Some(cleaned.to_owned())
    } else {
        None
    }
}

fn is_subscription_url(candidate: &str) -> bool {
    Url::parse(candidate)
        .map(|url| matches!(url.scheme(), "http" | "https"))
        .unwrap_or(false)
}

fn is_unsupported_placeholder(candidate: &str) -> bool {
    Url::parse(candidate)
        .ok()
        .and_then(|url| url.fragment().map(percent_decode_name))
        .map(|name| {
            let name = name.to_ascii_lowercase();
            name.contains("unsupported") || name.contains("не поддерж")
        })
        .unwrap_or(false)
}

fn assign_ids(profiles: &mut [Profile]) {
    for (id, profile) in profiles.iter_mut().enumerate() {
        profile.id = id;
    }
}

fn parse_profile_candidate(candidate: &str) -> Option<Profile> {
    let url = Url::parse(candidate).ok()?;
    let protocol = Protocol::from_scheme(url.scheme());

    if matches!(protocol, Protocol::Unknown(_)) {
        return None;
    }

    let address = url.host_str()?.to_owned();
    let port = url.port();
    let name = url
        .fragment()
        .filter(|fragment| !fragment.is_empty())
        .map(percent_decode_name)
        .unwrap_or_else(|| format!("{}:{}", address, port.unwrap_or(0)));

    Some(Profile {
        id: 0,
        name,
        protocol,
        address,
        port,
        raw: candidate.to_owned(),
        selected: true,
        group: None,
    })
}

fn parse_json_profiles(input: &str) -> Vec<Profile> {
    let Ok(value) = serde_json::from_str::<Value>(input) else {
        return Vec::new();
    };

    let configs = match &value {
        Value::Array(items) => items.iter().collect::<Vec<_>>(),
        Value::Object(_) => vec![&value],
        _ => return Vec::new(),
    };

    let mut profiles = Vec::new();
    for config in configs {
        let remarks = config
            .get("remarks")
            .and_then(Value::as_str)
            .unwrap_or("JSON profile");

        let Some(outbounds) = config.get("outbounds").and_then(Value::as_array) else {
            continue;
        };

        for outbound in outbounds {
            if outbound.get("protocol").and_then(Value::as_str) == Some("vless")
                && let Some(raw) = xray_vless_to_share_link(outbound, remarks)
                && let Some(profile) = parse_profile_candidate(&raw)
            {
                profiles.push(profile);
            }
        }
    }

    profiles
}

fn xray_vless_to_share_link(outbound: &Value, remarks: &str) -> Option<String> {
    let vnext = outbound
        .get("settings")?
        .get("vnext")?
        .as_array()?
        .first()?;
    let address = vnext.get("address")?.as_str()?;
    let port = vnext.get("port")?.as_u64()?;
    let user = vnext.get("users")?.as_array()?.first()?;
    let uuid = user.get("id")?.as_str()?;

    let stream = outbound.get("streamSettings");
    let network = stream
        .and_then(|value| value.get("network"))
        .and_then(Value::as_str)
        .unwrap_or("tcp");
    let security = stream
        .and_then(|value| value.get("security"))
        .and_then(Value::as_str)
        .unwrap_or("none");

    let mut params = vec![
        ("type", network.to_owned()),
        ("security", security.to_owned()),
    ];

    if let Some(flow) = user.get("flow").and_then(Value::as_str) {
        params.push(("flow", flow.to_owned()));
    }

    if let Some(reality) = stream
        .and_then(|value| value.get("realitySettings"))
        .and_then(Value::as_object)
    {
        push_json_string_param(&mut params, reality, "serverName", "sni");
        push_json_string_param(&mut params, reality, "fingerprint", "fp");
        push_json_string_param(&mut params, reality, "publicKey", "pbk");
        push_json_string_param(&mut params, reality, "shortId", "sid");
    }

    if let Some(grpc) = stream
        .and_then(|value| value.get("grpcSettings"))
        .and_then(Value::as_object)
    {
        push_json_string_param(&mut params, grpc, "serviceName", "serviceName");
    }

    if let Some(xhttp) = stream
        .and_then(|value| value.get("xhttpSettings"))
        .and_then(Value::as_object)
    {
        push_json_string_param(&mut params, xhttp, "path", "path");
        push_json_string_param(&mut params, xhttp, "host", "host");
        push_json_string_param(&mut params, xhttp, "mode", "mode");
    }

    if let Some(ws) = stream
        .and_then(|value| value.get("wsSettings"))
        .and_then(Value::as_object)
    {
        push_json_string_param(&mut params, ws, "path", "path");
        if let Some(host) = ws
            .get("headers")
            .and_then(|value| value.get("Host"))
            .and_then(Value::as_str)
        {
            params.push(("host", host.to_owned()));
        }
    }

    let query = params
        .into_iter()
        .map(|(key, value)| format!("{key}={}", encode_url_component(&value)))
        .collect::<Vec<_>>()
        .join("&");
    let name = outbound
        .get("tag")
        .and_then(Value::as_str)
        .filter(|tag| *tag != "proxy")
        .unwrap_or(remarks);

    Some(format!(
        "vless://{uuid}@{address}:{port}?{query}#{}",
        encode_url_component(name)
    ))
}

fn push_json_string_param(
    params: &mut Vec<(&'static str, String)>,
    object: &serde_json::Map<String, Value>,
    json_key: &str,
    query_key: &'static str,
) {
    if let Some(value) = object.get(json_key).and_then(Value::as_str) {
        params.push((query_key, value.to_owned()));
    }
}

fn encode_url_component(value: &str) -> String {
    utf8_percent_encode(value, NON_ALPHANUMERIC).to_string()
}

fn percent_decode_name(value: &str) -> String {
    percent_decode_str(value)
        .decode_utf8_lossy()
        .replace('+', " ")
}

#[cfg(test)]
mod tests {
    use super::{SubscriptionSource, load_subscription_detailed_via_proxy, parse_input};

    #[test]
    fn parses_subscription_urls_from_rtf_text() {
        let input = r#"{\rtf1\ansi
\f0\fs24 \cf0 https://provider.example/sub/token-a\
\
https://provider.example/sub/token-b}"#;

        let output = parse_input(input);

        assert_eq!(output.subscriptions.len(), 2);
        assert_eq!(
            output.subscriptions[0].url,
            "https://provider.example/sub/token-a"
        );
        assert_eq!(
            output.subscriptions[1].url,
            "https://provider.example/sub/token-b"
        );
    }

    #[test]
    fn parses_direct_profiles() {
        let output = parse_input(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#DE",
        );

        assert_eq!(output.profiles.len(), 1);
        assert_eq!(output.profiles[0].name, "DE");
    }

    #[test]
    fn ignores_unsupported_app_placeholder_profile() {
        let output = parse_input(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&type=tcp#Приложение%20не%20поддерживается",
        );

        assert_eq!(output.profiles.len(), 0);
        assert_eq!(output.unsupported_placeholders, 1);
    }

    #[test]
    fn parses_xray_json_vless_outbound() {
        let output = parse_input(
            r#"[{
                "remarks": "NL JSON",
                "outbounds": [{
                    "protocol": "vless",
                    "tag": "proxy",
                    "settings": {
                        "vnext": [{
                            "address": "example.com",
                            "port": 443,
                            "users": [{
                                "id": "11111111-1111-1111-1111-111111111111",
                                "flow": "xtls-rprx-vision"
                            }]
                        }]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "serverName": "www.example.com",
                            "fingerprint": "chrome",
                            "publicKey": "public-key",
                            "shortId": "abcd"
                        }
                    }
                }]
            }]"#,
        );

        assert_eq!(output.profiles.len(), 1);
        assert_eq!(output.profiles[0].name, "NL JSON");
        assert!(output.profiles[0].raw.contains("security=reality"));
        assert!(output.profiles[0].raw.contains("pbk=public%2Dkey"));
    }

    #[test]
    fn parses_xray_json_with_dns_server_urls() {
        // Happ/TutNet Xray-style JSON subscriptions carry `https://...` URLs inside
        // `dns.servers`. The candidate scan picks those up as subscription
        // candidates, but the real payload is the `outbounds` array. Profiles must
        // still be recognised, and the false-positive subscriptions dropped.
        let output = parse_input(
            r#"{
                "remarks": "TutNet JSON",
                "dns": {
                    "servers": [
                        "https://1.1.1.1/dns-query",
                        "8.8.8.8"
                    ]
                },
                "outbounds": [{
                    "protocol": "vless",
                    "tag": "proxy",
                    "settings": {
                        "vnext": [{
                            "address": "example.com",
                            "port": 443,
                            "users": [{
                                "id": "11111111-1111-1111-1111-111111111111",
                                "flow": "xtls-rprx-vision"
                            }]
                        }]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "serverName": "www.example.com",
                            "fingerprint": "chrome",
                            "publicKey": "public-key",
                            "shortId": "abcd"
                        }
                    }
                }]
            }"#,
        );

        assert_eq!(output.profiles.len(), 1);
        assert_eq!(output.profiles[0].name, "TutNet JSON");
        assert!(output.profiles[0].raw.contains("security=reality"));
        assert!(output.profiles[0].raw.contains("pbk=public%2Dkey"));
        assert_eq!(
            output.subscriptions.len(),
            0,
            "DNS-over-HTTPS URLs must not be treated as subscriptions when outbounds parse"
        );
    }

    #[test]
    fn preserves_xhttp_settings_from_xray_json() {
        let output = parse_input(
            r#"[{
                "remarks": "Satellite",
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": "sputnik.example.com",
                            "port": 443,
                            "users": [{ "id": "11111111-1111-1111-1111-111111111111" }]
                        }]
                    },
                    "streamSettings": {
                        "network": "xhttp",
                        "xhttpSettings": {
                            "mode": "auto",
                            "path": "/check-update"
                        },
                        "security": "reality",
                        "realitySettings": {
                            "serverName": "media.example.com",
                            "fingerprint": "random",
                            "publicKey": "public-key",
                            "shortId": "abcd"
                        }
                    }
                }]
            }]"#,
        );

        assert_eq!(output.profiles.len(), 1);
        assert!(output.profiles[0].raw.contains("type=xhttp"));
        assert!(output.profiles[0].raw.contains("path=%2Fcheck%2Dupdate"));
        assert!(output.profiles[0].raw.contains("mode=auto"));
    }

    #[test]
    fn load_via_proxy_rejects_malformed_proxy_url_without_network() {
        // `reqwest::Proxy::all` validates the URL up front, so a clearly
        // malformed proxy string surfaces as an error mentioning "proxy"
        // before any TCP connection is attempted. This pins the
        // direct-vs-proxy split behaviour the daemon relies on.
        let source = SubscriptionSource {
            url: "https://provider.example/sub/none".to_owned(),
        };
        let error = load_subscription_detailed_via_proxy(&source, Some("not a valid url"))
            .expect_err("malformed proxy should error");
        assert!(
            error.contains("proxy"),
            "error should mention proxy marker: {error}"
        );
    }
}
