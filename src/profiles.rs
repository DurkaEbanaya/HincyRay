use std::fmt;

use base64::{Engine as _, engine::general_purpose};
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Vless,
    VMess,
    Trojan,
    Shadowsocks,
    ShadowsocksR,
    Snell,
    Http,
    Socks,
    AnyTls,
    Hysteria,
    Hysteria2,
    WireGuard,
    Tuic,
    Ssh,
    Masque,
    OpenVpn,
    Tailscale,
    Unknown(String),
}

impl Protocol {
    fn from_scheme(scheme: &str) -> Self {
        match scheme.to_ascii_lowercase().as_str() {
            "vless" => Self::Vless,
            "vmess" => Self::VMess,
            "trojan" => Self::Trojan,
            "ss" | "shadowsocks" => Self::Shadowsocks,
            "ssr" | "shadowsocksr" => Self::ShadowsocksR,
            "snell" => Self::Snell,
            // Plain http(s) URLs remain subscription URLs. HTTP proxy
            // profiles use an explicit Mihomo namespace to avoid changing
            // the subscription/import contract.
            "mihomo+http" | "mihomo+https" | "http-proxy" | "https-proxy" => Self::Http,
            "socks" | "socks4" | "socks5" => Self::Socks,
            "anytls" => Self::AnyTls,
            "hysteria" | "hy" => Self::Hysteria,
            "hysteria2" | "hy2" => Self::Hysteria2,
            "wireguard" | "wg" => Self::WireGuard,
            "tuic" => Self::Tuic,
            "ssh" => Self::Ssh,
            "masque" => Self::Masque,
            "openvpn" => Self::OpenVpn,
            "tailscale" | "ts" => Self::Tailscale,
            other => Self::Unknown(other.to_owned()),
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vless => f.write_str("VLESS"),
            Self::VMess => f.write_str("VMess"),
            Self::Trojan => f.write_str("Trojan"),
            Self::Shadowsocks => f.write_str("Shadowsocks"),
            Self::ShadowsocksR => f.write_str("ShadowsocksR"),
            Self::Snell => f.write_str("Snell"),
            Self::Http => f.write_str("HTTP"),
            Self::Socks => f.write_str("SOCKS"),
            Self::AnyTls => f.write_str("AnyTLS"),
            Self::Hysteria => f.write_str("Hysteria"),
            Self::Hysteria2 => f.write_str("Hysteria2"),
            Self::WireGuard => f.write_str("WireGuard"),
            Self::Tuic => f.write_str("TUIC"),
            Self::Ssh => f.write_str("SSH"),
            Self::Masque => f.write_str("MASQUE"),
            Self::OpenVpn => f.write_str("OpenVPN"),
            Self::Tailscale => f.write_str("Tailscale"),
            Self::Unknown(value) => f.write_str(value),
        }
    }
}

/// Hardcoded device fingerprint for Happ subscription fetches.
/// Values follow the HWID-HARDCODING.md pattern: a realistic 16-hex
/// HWID, consistent OS/model pair, and matching User-Agent so the
/// server's cross-check passes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HwidConfig {
    #[serde(default = "default_hwid")]
    pub hwid: String,
    #[serde(default = "default_os_version")]
    pub os_version: String,
    #[serde(default = "default_device_model")]
    pub device_model: String,
    #[serde(default = "default_device_os")]
    pub device_os: String,
    #[serde(default = "default_app_version")]
    pub app_version: String,
    #[serde(default = "default_bundle_id")]
    pub bundle_id: String,
    #[serde(default = "default_api_version")]
    pub api_version: String,
}

impl Default for HwidConfig {
    fn default() -> Self {
        Self {
            hwid: default_hwid(),
            os_version: default_os_version(),
            device_model: default_device_model(),
            device_os: default_device_os(),
            app_version: default_app_version(),
            bundle_id: default_bundle_id(),
            api_version: default_api_version(),
        }
    }
}

impl HwidConfig {
    /// Build the User-Agent string matching the real Happ app format:
    /// `Happ/<version>/<platform>/<build_number>`.
    pub fn user_agent(&self) -> String {
        format!("Happ/{}/Android/17800511170441525643", self.app_version)
    }
}

fn default_hwid() -> String {
    "a3f7e10d5c9b2486".to_owned()
}

fn default_os_version() -> String {
    "13".to_owned()
}

fn default_device_model() -> String {
    "Poco X3 Pro".to_owned()
}

fn default_device_os() -> String {
    "Android".to_owned()
}

fn default_app_version() -> String {
    "3.22.1".to_owned()
}

fn default_bundle_id() -> String {
    "su.happ.proxyutility".to_owned()
}

fn default_api_version() -> String {
    "1.0".to_owned()
}

impl Profile {
    pub fn transport(&self) -> String {
        if matches!(self.protocol, Protocol::VMess) {
            vmess_transport(&self.raw).unwrap_or_else(|| "tcp".to_owned())
        } else {
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
}

/// Extract the transport network type from a `vmess://` base64-JSON link.
fn vmess_transport(raw: &str) -> Option<String> {
    let json = decode_vmess_json(raw)?;
    json.get("net")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

/// Decode the base64 JSON payload from a `vmess://` link.
pub(crate) fn decode_vmess_json(raw: &str) -> Option<Value> {
    let b64 = raw.strip_prefix("vmess://")?.trim();
    // Strip fragment (#...) if present — some clients append a name.
    let b64 = b64.split('#').next()?.trim();
    let bytes = general_purpose::STANDARD
        .decode(b64)
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(b64))
        .or_else(|_| general_purpose::URL_SAFE.decode(b64))
        .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(b64))
        .ok()?;
    serde_json::from_slice(&bytes).ok()
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
    /// Per-profile QUIC/UDP 443 block flag. When the profile is the
    /// active server or a fixed target in a WiFi split-routing rule,
    /// HincyRay emits an Xray routing rule that drops UDP port 443 for
    /// matched WiFi traffic, forcing services to fall back to TCP.
    #[serde(default)]
    pub block_quic: bool,
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
    load_subscription_detailed_via_proxy_with_hwid(source, proxy, &HwidConfig::default())
}

/// Like `load_subscription_detailed_via_proxy` but with a custom HWID
/// fingerprint for the Happ Android fallback fetch. The daemon uses this
/// to pass user-configured HWID settings; the desktop app uses the
/// default via `load_subscription_detailed_via_proxy`.
pub fn load_subscription_detailed_via_proxy_with_hwid(
    source: &SubscriptionSource,
    proxy: Option<&str>,
    hwid: &HwidConfig,
) -> Result<SubscriptionLoadReport, String> {
    let mut response = fetch_subscription(source, SubscriptionRequestMode::SingBox, proxy, hwid)?;
    let (mut decoded, mut parsed) = parse_subscription_response(&response);

    if should_retry_as_happ(&parsed) {
        response = fetch_subscription(source, SubscriptionRequestMode::HappAndroid, proxy, hwid)?;
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
    hwid: &HwidConfig,
) -> Result<String, String> {
    let user_agent = match mode {
        SubscriptionRequestMode::SingBox => subscription_user_agent().to_owned(),
        SubscriptionRequestMode::HappAndroid => hwid.user_agent(),
    };
    let mut builder = reqwest::blocking::Client::builder().user_agent(user_agent);
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
            .header("X-HWID", &hwid.hwid)
            .header("X-Ver-OS", &hwid.os_version)
            .header("X-Bundle-ID", &hwid.bundle_id)
            .header("X-Device-model", &hwid.device_model)
            .header("X-Device-OS", &hwid.device_os)
            .header("X-App-Version", &hwid.app_version)
            .header("X-API-Version", &hwid.api_version);
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

    // VMess uses a base64-JSON payload, not a standard URL with
    // userinfo/host. Decode the JSON to extract fields.
    if matches!(protocol, Protocol::VMess) {
        return parse_vmess_candidate(candidate);
    }

    // Shadowsocks legacy format: ss://base64(method:password@host:port)#name
    // The base64 payload includes host and port, so there's no `@`
    // separator in the URL. We detect this by checking if the URL has
    // no userinfo (username is empty).
    if matches!(protocol, Protocol::Shadowsocks) && url.username().is_empty() {
        return parse_shadowsocks_legacy_candidate(candidate);
    }

    // WireGuard links: the private key may be in the username position
    // (percent-encoded) or in a `privatekey` query parameter.
    if matches!(protocol, Protocol::WireGuard) {
        return parse_wireguard_candidate(candidate);
    }

    // TUIC links: uuid:password in userinfo, same as standard URL.
    if matches!(protocol, Protocol::Tuic) {
        return parse_tuic_candidate(candidate);
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
        block_quic: false,
        group: None,
    })
}

/// Parse a `vmess://base64(json)` link into a Profile.
fn parse_vmess_candidate(raw: &str) -> Option<Profile> {
    let json = decode_vmess_json(raw)?;
    let address = json.get("add").and_then(Value::as_str)?.to_owned();
    let port = json
        .get("port")
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .map(|p| p as u16);
    let name = json
        .get("ps")
        .and_then(Value::as_str)
        .unwrap_or(&address)
        .to_owned();

    Some(Profile {
        id: 0,
        name,
        protocol: Protocol::VMess,
        address,
        port,
        raw: raw.to_owned(),
        selected: true,
        block_quic: false,
        group: None,
    })
}

/// Parse the legacy Shadowsocks format `ss://base64(method:password@host:port)#name`.
fn parse_shadowsocks_legacy_candidate(raw: &str) -> Option<Profile> {
    let b64_part = raw
        .strip_prefix("ss://")
        .and_then(|rest| rest.split('#').next())?
        .trim();

    let decoded = general_purpose::STANDARD
        .decode(b64_part)
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(b64_part))
        .or_else(|_| general_purpose::URL_SAFE.decode(b64_part))
        .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(b64_part))
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;

    // Format: method:password@host:port
    let (_userinfo, hostport) = text.rsplit_once('@')?;
    let (host, port_str) = hostport.rsplit_once(':')?;
    let port = port_str.parse::<u16>().ok()?;

    let name = Url::parse(raw)
        .ok()
        .and_then(|url| url.fragment().map(percent_decode_name))
        .unwrap_or_else(|| format!("{host}:{port}"));

    Some(Profile {
        id: 0,
        name,
        protocol: Protocol::Shadowsocks,
        address: host.to_owned(),
        port: Some(port),
        raw: raw.to_owned(),
        selected: true,
        block_quic: false,
        group: None,
    })
}

/// Parse a `wireguard://` (or `wg://`) share link into a Profile.
///
/// Supported format:
/// `wireguard://<private_key>@<host>:<port>?address=<ip>[&address=<ipv6>]&publickey=<peer_pub>&presharedkey=<psk>&mtu=<mtu>&reserved=<csv>#<name>`
///
/// The private key may be percent-encoded in the username position
/// or supplied via a `privatekey` query parameter. The `address`
/// parameter may include a CIDR suffix (stripped) and multiple
/// addresses are comma-separated (IPv4 and IPv6 separated).
fn parse_wireguard_candidate(raw: &str) -> Option<Profile> {
    let url = Url::parse(raw).ok()?;
    let address = url.host_str()?.to_owned();
    let port = url.port();

    // Private key: username (percent-decoded by url crate) or query param.
    let private_key = if !url.username().is_empty() {
        percent_decode_str(url.username())
            .decode_utf8_lossy()
            .to_string()
    } else {
        url.query_pairs()
            .find(|(k, _)| k == "privatekey" || k == "private-key")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default()
    };
    if private_key.is_empty() {
        return None;
    }

    let name = url
        .fragment()
        .filter(|fragment| !fragment.is_empty())
        .map(percent_decode_name)
        .unwrap_or_else(|| format!("{}:{}", address, port.unwrap_or(0)));

    Some(Profile {
        id: 0,
        name,
        protocol: Protocol::WireGuard,
        address,
        port,
        raw: raw.to_owned(),
        selected: true,
        block_quic: false,
        group: None,
    })
}

/// Parse a `tuic://` share link into a Profile.
///
/// Supported format:
/// `tuic://<uuid>:<password>@<host>:<port>?sni=<sni>&alpn=<alpn>&...#<name>`
///
/// Uses standard URL userinfo (uuid as username, password as password).
/// All TUIC-specific parameters are preserved in the raw link for the
/// Mihomo config builder to parse.
fn parse_tuic_candidate(raw: &str) -> Option<Profile> {
    let url = Url::parse(raw).ok()?;
    let address = url.host_str()?.to_owned();
    let port = url.port();

    // TUIC requires uuid (username) — if missing, it's not a valid link.
    if url.username().is_empty() {
        return None;
    }

    let name = url
        .fragment()
        .filter(|fragment| !fragment.is_empty())
        .map(percent_decode_name)
        .unwrap_or_else(|| format!("{}:{}", address, port.unwrap_or(0)));

    Some(Profile {
        id: 0,
        name,
        protocol: Protocol::Tuic,
        address,
        port,
        raw: raw.to_owned(),
        selected: true,
        block_quic: false,
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
            let protocol = outbound.get("protocol").and_then(Value::as_str);
            let raw = match protocol {
                Some("vless") => xray_vless_to_share_link(outbound, remarks),
                Some("vmess") => xray_vmess_to_share_link(outbound, remarks),
                Some("trojan") => xray_trojan_to_share_link(outbound, remarks),
                Some("shadowsocks") => xray_shadowsocks_to_share_link(outbound, remarks),
                _ => None,
            };
            if let Some(raw) = raw
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

/// Convert an Xray VMess outbound JSON to a `vmess://base64(json)` share link.
fn xray_vmess_to_share_link(outbound: &Value, remarks: &str) -> Option<String> {
    let vnext = outbound
        .get("settings")?
        .get("vnext")?
        .as_array()?
        .first()?;
    let address = vnext.get("address")?.as_str()?;
    let port = vnext.get("port")?.as_u64()?;
    let user = vnext.get("users")?.as_array()?.first()?;
    let uuid = user.get("id")?.as_str()?;
    let alter_id = user.get("alterId").and_then(Value::as_u64).unwrap_or(0);
    let security = user
        .get("security")
        .and_then(Value::as_str)
        .unwrap_or("auto");

    let stream = outbound.get("streamSettings");
    let network = stream
        .and_then(|v| v.get("network"))
        .and_then(Value::as_str)
        .unwrap_or("tcp");
    let tls = stream
        .and_then(|v| v.get("security"))
        .and_then(Value::as_str)
        .unwrap_or("");

    let mut vmess_json = json!({
        "v": "2",
        "ps": remarks,
        "add": address,
        "port": port.to_string(),
        "id": uuid,
        "aid": alter_id.to_string(),
        "scy": security,
        "net": network,
        "tls": if tls == "tls" { "tls" } else { "" },
        "type": "none",
    });

    if let Some(sni) = stream
        .and_then(|v| v.get("tlsSettings"))
        .and_then(|v| v.get("serverName"))
        .and_then(Value::as_str)
    {
        vmess_json["sni"] = json!(sni);
    }
    if let Some(fp) = stream
        .and_then(|v| v.get("tlsSettings"))
        .and_then(|v| v.get("fingerprint"))
        .and_then(Value::as_str)
    {
        vmess_json["fp"] = json!(fp);
    }
    if let Some(path) = stream
        .and_then(|v| v.get("wsSettings"))
        .and_then(|v| v.get("path"))
        .and_then(Value::as_str)
    {
        vmess_json["path"] = json!(path);
    }
    if let Some(host) = stream
        .and_then(|v| v.get("wsSettings"))
        .and_then(|v| v.get("headers"))
        .and_then(|v| v.get("Host"))
        .and_then(Value::as_str)
    {
        vmess_json["host"] = json!(host);
    }
    if let Some(service_name) = stream
        .and_then(|v| v.get("grpcSettings"))
        .and_then(|v| v.get("serviceName"))
        .and_then(Value::as_str)
    {
        vmess_json["path"] = json!(service_name);
    }

    let encoded =
        general_purpose::STANDARD.encode(serde_json::to_string(&vmess_json).ok()?.as_bytes());
    Some(format!("vmess://{encoded}"))
}

/// Convert an Xray Trojan outbound JSON to a `trojan://` share link.
fn xray_trojan_to_share_link(outbound: &Value, remarks: &str) -> Option<String> {
    let server = outbound
        .get("settings")?
        .get("servers")?
        .as_array()?
        .first()?;
    let address = server.get("address")?.as_str()?;
    let port = server.get("port")?.as_u64()?;
    let password = server.get("password")?.as_str()?;

    let stream = outbound.get("streamSettings");
    let network = stream
        .and_then(|v| v.get("network"))
        .and_then(Value::as_str)
        .unwrap_or("tcp");
    let security = stream
        .and_then(|v| v.get("security"))
        .and_then(Value::as_str)
        .unwrap_or("tls");

    let mut params = vec![
        ("type", network.to_owned()),
        ("security", security.to_owned()),
    ];

    if let Some(tls_settings) = stream
        .and_then(|v| v.get("tlsSettings"))
        .and_then(Value::as_object)
    {
        push_json_string_param(&mut params, tls_settings, "serverName", "sni");
        push_json_string_param(&mut params, tls_settings, "fingerprint", "fp");
    }

    if let Some(ws) = stream
        .and_then(|v| v.get("wsSettings"))
        .and_then(Value::as_object)
    {
        push_json_string_param(&mut params, ws, "path", "path");
        if let Some(host) = ws
            .get("headers")
            .and_then(|v| v.get("Host"))
            .and_then(Value::as_str)
        {
            params.push(("host", host.to_owned()));
        }
    }

    if let Some(grpc) = stream
        .and_then(|v| v.get("grpcSettings"))
        .and_then(Value::as_object)
    {
        push_json_string_param(&mut params, grpc, "serviceName", "serviceName");
    }

    let query = params
        .into_iter()
        .map(|(key, value)| format!("{key}={}", encode_url_component(&value)))
        .collect::<Vec<_>>()
        .join("&");

    Some(format!(
        "trojan://{}@{address}:{port}?{query}#{}",
        encode_url_component(password),
        encode_url_component(remarks)
    ))
}

/// Convert an Xray Shadowsocks outbound JSON to an `ss://` share link.
fn xray_shadowsocks_to_share_link(outbound: &Value, remarks: &str) -> Option<String> {
    let server = outbound
        .get("settings")?
        .get("servers")?
        .as_array()?
        .first()?;
    let address = server.get("address")?.as_str()?;
    let port = server.get("port")?.as_u64()?;
    let method = server.get("method")?.as_str()?;
    let password = server.get("password")?.as_str()?;

    let credentials = format!("{method}:{password}");
    let encoded = general_purpose::STANDARD.encode(credentials.as_bytes());

    Some(format!(
        "ss://{encoded}@{address}:{port}#{}",
        encode_url_component(remarks)
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
    use base64::Engine as _;

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

    #[test]
    fn hwid_config_defaults_match_hardcoded_fingerprint() {
        use super::HwidConfig;
        let config = HwidConfig::default();
        assert_eq!(config.hwid, "a3f7e10d5c9b2486");
        assert_eq!(config.os_version, "13");
        assert_eq!(config.device_model, "Poco X3 Pro");
        assert_eq!(config.device_os, "Android");
        assert_eq!(config.app_version, "3.22.1");
        assert_eq!(config.bundle_id, "su.happ.proxyutility");
        assert_eq!(config.api_version, "1.0");
    }

    #[test]
    fn hwid_user_agent_matches_happ_format() {
        use super::HwidConfig;
        let config = HwidConfig::default();
        let ua = config.user_agent();
        assert!(ua.starts_with("Happ/3.22.1/Android/"));
        assert!(ua.contains("1780051117044152"));
    }

    #[test]
    fn parses_vmess_share_link() {
        let vmess_json = r#"{"v":"2","ps":"VMess Test","add":"example.com","port":"443","id":"11111111-1111-1111-1111-111111111111","aid":"0","net":"ws","type":"none","host":"example.com","path":"/ws","tls":"tls"}"#;
        let encoded = base64::engine::general_purpose::STANDARD.encode(vmess_json.as_bytes());
        let link = format!("vmess://{encoded}");
        let output = parse_input(&link);
        assert_eq!(output.profiles.len(), 1);
        assert_eq!(output.profiles[0].name, "VMess Test");
        assert_eq!(output.profiles[0].address, "example.com");
        assert_eq!(output.profiles[0].port, Some(443));
        assert_eq!(output.profiles[0].transport(), "ws");
    }

    #[test]
    fn parses_trojan_share_link() {
        let output = parse_input(
            "trojan://secretpass@example.com:443?security=tls&sni=www.example.com&type=tcp#Trojan_Test",
        );
        assert_eq!(output.profiles.len(), 1);
        assert_eq!(output.profiles[0].name, "Trojan_Test");
        assert_eq!(output.profiles[0].address, "example.com");
        assert_eq!(output.profiles[0].port, Some(443));
    }

    #[test]
    fn parses_shadowsocks_new_format() {
        let credentials =
            base64::engine::general_purpose::STANDARD.encode(b"aes-256-gcm:secretpass");
        let link = format!("ss://{credentials}@example.com:8388#SS_Test");
        let output = parse_input(&link);
        assert_eq!(output.profiles.len(), 1);
        assert_eq!(output.profiles[0].name, "SS_Test");
        assert_eq!(output.profiles[0].address, "example.com");
        assert_eq!(output.profiles[0].port, Some(8388));
    }

    #[test]
    fn parses_shadowsocks_legacy_format() {
        let payload = base64::engine::general_purpose::STANDARD
            .encode(b"aes-256-gcm:secretpass@example.com:8388");
        let link = format!("ss://{payload}#SS_Legacy");
        let output = parse_input(&link);
        assert_eq!(output.profiles.len(), 1);
        assert_eq!(output.profiles[0].address, "example.com");
        assert_eq!(output.profiles[0].port, Some(8388));
    }

    #[test]
    fn parses_xray_json_vmess_outbound() {
        let output = parse_input(
            r#"[{
                "remarks": "VMess JSON",
                "outbounds": [{
                    "protocol": "vmess",
                    "tag": "proxy",
                    "settings": {
                        "vnext": [{
                            "address": "example.com",
                            "port": 443,
                            "users": [{
                                "id": "11111111-1111-1111-1111-111111111111",
                                "alterId": 0
                            }]
                        }]
                    },
                    "streamSettings": {
                        "network": "ws",
                        "security": "tls",
                        "wsSettings": { "path": "/ws" },
                        "tlsSettings": { "serverName": "example.com" }
                    }
                }]
            }]"#,
        );
        assert_eq!(output.profiles.len(), 1);
        assert_eq!(output.profiles[0].name, "VMess JSON");
        assert!(output.profiles[0].raw.starts_with("vmess://"));
    }

    #[test]
    fn parses_xray_json_trojan_outbound() {
        let output = parse_input(
            r#"[{
                "remarks": "Trojan JSON",
                "outbounds": [{
                    "protocol": "trojan",
                    "tag": "proxy",
                    "settings": {
                        "servers": [{
                            "address": "example.com",
                            "port": 443,
                            "password": "secretpass"
                        }]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "tls",
                        "tlsSettings": { "serverName": "www.example.com" }
                    }
                }]
            }]"#,
        );
        assert_eq!(output.profiles.len(), 1);
        assert_eq!(output.profiles[0].name, "Trojan JSON");
        assert!(output.profiles[0].raw.starts_with("trojan://"));
        assert!(output.profiles[0].raw.contains("secretpass"));
    }

    #[test]
    fn parses_xray_json_shadowsocks_outbound() {
        let output = parse_input(
            r#"[{
                "remarks": "SS JSON",
                "outbounds": [{
                    "protocol": "shadowsocks",
                    "tag": "proxy",
                    "settings": {
                        "servers": [{
                            "address": "example.com",
                            "port": 8388,
                            "method": "aes-256-gcm",
                            "password": "secretpass"
                        }]
                    }
                }]
            }]"#,
        );
        assert_eq!(output.profiles.len(), 1);
        assert_eq!(output.profiles[0].name, "SS JSON");
        assert!(output.profiles[0].raw.starts_with("ss://"));
    }

    #[test]
    fn parses_wireguard_share_link() {
        let output = parse_input(
            "wireguard://eCtXsJZ27%2B4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU%3D@162.159.192.1:2480?address=172.16.0.2&publickey=Cr8hWlKvtDt7nrvf%2Bf0brNQQzabAqrjfBvas9pmowjo%3D&mtu=1280#WARP",
        );
        assert_eq!(output.profiles.len(), 1);
        assert_eq!(output.profiles[0].name, "WARP");
        assert_eq!(output.profiles[0].address, "162.159.192.1");
        assert_eq!(output.profiles[0].port, Some(2480));
    }

    #[test]
    fn parses_wireguard_with_privatekey_param() {
        let output = parse_input(
            "wg://162.159.192.1:2480?privatekey=eCtXsJZ27%2B4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU%3D&address=172.16.0.2&publickey=Cr8hWlKvtDt7nrvf%2Bf0brNQQzabAqrjfBvas9pmowjo%3D#WARP",
        );
        assert_eq!(output.profiles.len(), 1);
        assert_eq!(output.profiles[0].name, "WARP");
        assert_eq!(output.profiles[0].address, "162.159.192.1");
    }

    #[test]
    fn parses_tuic_share_link() {
        let output = parse_input(
            "tuic://00000000-0000-0000-0000-000000000001:secretpass@example.com:443?sni=example.com&alpn=h3&congestion_controller=bbr&udp_relay_mode=native#TUIC_Test",
        );
        assert_eq!(output.profiles.len(), 1);
        assert_eq!(output.profiles[0].name, "TUIC_Test");
        assert_eq!(output.profiles[0].address, "example.com");
        assert_eq!(output.profiles[0].port, Some(443));
    }

    #[test]
    fn parses_tuic_link_without_password() {
        // Some TUIC links use only uuid (no password in userinfo).
        let output = parse_input(
            "tuic://00000000-0000-0000-0000-000000000001@example.com:443?sni=example.com#TUIC_NoPass",
        );
        assert_eq!(output.profiles.len(), 1);
        assert_eq!(output.profiles[0].name, "TUIC_NoPass");
    }
}
