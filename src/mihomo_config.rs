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

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

use crate::profiles::{Profile, Protocol, decode_vmess_json};
use crate::xray_config::{
    DNS_INBOUND_PORT, GeoBaseRuleBehavior, GeoBaseRuleProvider, GeoBaseRuleTarget, PortMode,
    QuicMode, RouterExtra, XrayRouteRule, extract_ss_credentials, percent_decode, query_value,
};

// ---------------------------------------------------------------------------
// MihomoFeatures — all opt-in Mihomo-specific config options
// ---------------------------------------------------------------------------

/// A single tunnel entry — TCP/UDP port forwarding through Mihomo.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TunnelConfig {
    /// `["tcp"]`, `["udp"]`, or `["tcp", "udp"]`.
    pub network: Vec<String>,
    /// Local listen address, e.g. `"127.0.0.1:6553"`.
    pub address: String,
    /// Forward target, e.g. `"8.8.8.8:53"`.
    pub target: String,
    /// Optional proxy/group name to route through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
}

/// Persisted credentials for the fixed internal external controller.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct ExternalControllerConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
}

/// Per-proxy default fields applied to every outbound proxy unless
/// overridden by individual profile settings.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PerProxyDefaults {
    #[serde(default)]
    pub tfo: bool,
    #[serde(default)]
    pub mptcp: bool,
    #[serde(default = "default_ip_version")]
    pub ip_version: String,
}

impl Default for PerProxyDefaults {
    fn default() -> Self {
        Self {
            tfo: false,
            mptcp: false,
            ip_version: default_ip_version(),
        }
    }
}

/// All Mihomo-specific opt-in features. Stored in `HincyrayState` and
/// persisted to `state.json`. Passed to `build_mihomo_config` and
/// `build_mihomo_router_config`.
///
/// Defaults are tuned for a resource-constrained router (Keenetic Giga
/// KN-1012, 496 MB RAM, aarch64, kernel 4.9):
/// - `unified-delay = true` — RTT-based latency.
/// - `store-fake-ip = true` and `per-proxy.udp = true` are fixed invariants.
/// - `store-selected = true` — persist group selections.
/// - `keep-alive-interval = 30, keep-alive-idle = 120` — router-tuned.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MihomoFeatures {
    // --- Global config ---
    #[serde(default = "default_true")]
    pub unified_delay: bool,
    #[serde(default = "default_true")]
    pub store_selected: bool,
    #[serde(default = "default_keep_alive_interval")]
    pub keep_alive_interval: u32,
    #[serde(default = "default_keep_alive_idle")]
    pub keep_alive_idle: u32,
    #[serde(default)]
    pub disable_keep_alive: bool,
    /// Connect to all resolved IPs concurrently, use first success.
    #[serde(default)]
    pub tcp_concurrent: bool,

    // --- Experimental ---
    #[serde(default)]
    pub quic_go_disable_gso: bool,
    #[serde(default)]
    pub quic_go_disable_ecn: bool,

    // --- Hosts ---
    #[serde(default)]
    pub hosts: HashMap<String, String>,

    // --- Tunnels ---
    #[serde(default)]
    pub tunnels: Vec<TunnelConfig>,

    // --- External Controller ---
    #[serde(default)]
    pub external_controller: ExternalControllerConfig,

    // --- Per-proxy defaults ---
    #[serde(default)]
    pub per_proxy: PerProxyDefaults,

    // --- DNS extra ---
    #[serde(default)]
    pub dns_prefer_h3: bool,
    #[serde(default)]
    pub dns_respect_rules: bool,
    /// DNS nameserver-policy: domain → list of DNS servers.
    /// Keys support domain wildcards (e.g. `+.google.com`) and geosite
    /// references (e.g. `geosite:cn`). Values are DNS server URLs.
    #[serde(default)]
    pub dns_nameserver_policy: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub dns_default_nameserver: Vec<String>,
    #[serde(default)]
    pub dns_proxy_server_nameserver_policy: HashMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_direct_nameserver_follow_policy: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_fake_ip_filter_mode: Option<String>,
    #[serde(default)]
    pub dns_fake_ip_filter: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_fake_ip_ttl: Option<u32>,
    // --- Sniffer extra ---
    /// Override destination with sniffed domain so DOMAIN-* rules match
    /// even when clients bypass the router's DNS (DoH/DoT).  Default true.
    #[serde(default = "default_true")]
    pub sniffer_override_destination: bool,
    #[serde(default)]
    pub sniffer_force_domain: Vec<String>,
    #[serde(default)]
    pub sniffer_skip_domain: Vec<String>,
    #[serde(default)]
    pub sniffer_skip_src_address: Vec<String>,
    #[serde(default)]
    pub sniffer_skip_dst_address: Vec<String>,
}

impl Default for MihomoFeatures {
    fn default() -> Self {
        Self {
            unified_delay: true,
            store_selected: true,
            keep_alive_interval: default_keep_alive_interval(),
            keep_alive_idle: default_keep_alive_idle(),
            disable_keep_alive: false,
            tcp_concurrent: false,
            quic_go_disable_gso: false,
            quic_go_disable_ecn: false,
            hosts: HashMap::new(),
            tunnels: Vec::new(),
            external_controller: ExternalControllerConfig::default(),
            per_proxy: PerProxyDefaults::default(),
            dns_prefer_h3: false,
            dns_respect_rules: false,
            dns_nameserver_policy: HashMap::new(),
            dns_default_nameserver: Vec::new(),
            dns_proxy_server_nameserver_policy: HashMap::new(),
            dns_direct_nameserver_follow_policy: None,
            dns_fake_ip_filter_mode: None,
            dns_fake_ip_filter: Vec::new(),
            dns_fake_ip_ttl: None,
            sniffer_override_destination: true,
            sniffer_force_domain: Vec::new(),
            sniffer_skip_domain: Vec::new(),
            sniffer_skip_src_address: Vec::new(),
            sniffer_skip_dst_address: Vec::new(),
        }
    }
}

// --- Serde default helpers ---

fn default_true() -> bool {
    true
}

fn default_keep_alive_interval() -> u32 {
    30
}

fn default_keep_alive_idle() -> u32 {
    120
}

fn default_ip_version() -> String {
    "dual".to_owned()
}

/// Tag/name constants used in generated Mihomo configs.
pub const PROXY_NAME: &str = "proxy";
pub const PROXY_ACTIVE_NAME: &str = "proxy-active";
pub const DIRECT_NAME: &str = "DIRECT";
pub const REJECT_NAME: &str = "REJECT";
pub const PAROVOZIK_PROXY_GROUP: &str = "parovozik-vpn";
pub const REDIR_LISTENER: &str = "redir-in";
pub const TPROXY_LISTENER: &str = "tproxy-in";

/// Health-check URL for the direct-fallback proxy group. Mihomo probes
/// this URL **through the proxy** to determine availability. When the
/// probe fails, mihomo automatically falls back to DIRECT — preventing
/// connection storms when the upstream proxy is unreachable.
pub const FALLBACK_HEALTH_URL: &str = "https://www.gstatic.com/generate_204";

/// A server-specific outbound and its routing target group.
///
/// Names are supplied by the daemon so persisted routes can use stable,
/// opaque references without coupling the config builder to profile IDs.
pub struct PinnedServerRoute<'a> {
    pub outbound_name: String,
    pub group_name: String,
    pub profile: &'a Profile,
}

// ---------------------------------------------------------------------------
// Feature application helpers
// ---------------------------------------------------------------------------

/// Apply global Mihomo feature flags to a config JSON object.
///
/// Adds retained expert options plus fixed router invariants.
fn apply_global_features(config: &mut Value, features: &MihomoFeatures) {
    config["geodata-loader"] = json!("memconservative");
    config["unified-delay"] = json!(features.unified_delay);

    // profile.store-* — persist fake-ip map and group selections
    let mut profile = json!({"store-fake-ip": true});
    if features.store_selected {
        profile["store-selected"] = json!(true);
    }
    if !profile.as_object().is_some_and(|m| m.is_empty()) {
        config["profile"] = profile;
    }

    if features.keep_alive_interval > 0 {
        config["keep-alive-interval"] = json!(features.keep_alive_interval);
    }
    if features.keep_alive_idle > 0 {
        config["keep-alive-idle"] = json!(features.keep_alive_idle);
    }
    if features.disable_keep_alive {
        config["disable-keep-alive"] = json!(true);
    }

    if features.tcp_concurrent {
        config["tcp-concurrent"] = json!(true);
    }

    // Experimental QUIC tuning
    if features.quic_go_disable_gso || features.quic_go_disable_ecn {
        let mut exp = json!({});
        if features.quic_go_disable_gso {
            exp["quic-go-disable-gso"] = json!(true);
        }
        if features.quic_go_disable_ecn {
            exp["quic-go-disable-ecn"] = json!(true);
        }
        config["experimental"] = exp;
    }

    if !features.hosts.is_empty() {
        config["hosts"] = json!(features.hosts);
    }

    if !features.tunnels.is_empty() {
        config["tunnels"] = build_tunnels_json(&features.tunnels);
    }

    config["external-controller"] = json!("127.0.0.1:9090");
    if let Some(secret) = &features.external_controller.secret
        && !secret.is_empty()
    {
        config["secret"] = json!(secret);
    }
}

/// Apply fixed UDP plus retained per-proxy expert fields.
fn apply_per_proxy_fields(proxy: &mut Value, features: &MihomoFeatures) {
    let pp = &features.per_proxy;
    proxy["udp"] = json!(true);
    if pp.tfo {
        proxy["tfo"] = json!(true);
    }
    if pp.mptcp {
        proxy["mptcp"] = json!(true);
    }
    if pp.ip_version != "dual" {
        proxy["ip-version"] = json!(pp.ip_version);
    }
}

/// Build the `tunnels` JSON array from a list of `TunnelConfig`.
fn build_tunnels_json(tunnels: &[TunnelConfig]) -> Value {
    json!(
        tunnels
            .iter()
            .map(|t| {
                let mut tunnel = json!({
                    "network": t.network,
                    "address": t.address,
                    "target": t.target,
                });
                if let Some(proxy) = &t.proxy
                    && !proxy.is_empty()
                {
                    tunnel["proxy"] = json!(proxy);
                }
                tunnel
            })
            .collect::<Vec<_>>()
    )
}

fn merge_router_rule_providers(
    managed: &[GeoBaseRuleProvider],
    mihomo_home: Option<&str>,
) -> Result<Option<Value>, String> {
    let mut map = serde_json::Map::new();
    let mut names = HashSet::new();
    let enabled_managed: Vec<&GeoBaseRuleProvider> =
        managed.iter().filter(|provider| provider.enabled).collect();
    let lexical_home =
        match mihomo_home {
            Some(home) => Some(lexical_absolute_path(Path::new(home)).ok_or_else(|| {
                format!("invalid Mihomo home {home:?}: expected an absolute path")
            })?),
            None => None,
        };
    let home =
        match mihomo_home {
            Some(home) => Some(normalize_absolute_path(Path::new(home)).ok_or_else(|| {
                format!("invalid Mihomo home {home:?}: expected an absolute path")
            })?),
            None if !enabled_managed.is_empty() => {
                return Err("Mihomo home is required for managed rule providers".to_owned());
            }
            None => None,
        };
    let mut effective_paths = HashMap::<PathBuf, String>::new();

    for provider in enabled_managed {
        provider.validate()?;
        let home = home
            .as_deref()
            .expect("managed providers require Mihomo home");
        let effective =
            effective_provider_path(&provider.path, Some(home), lexical_home.as_deref())
                .expect("validated managed provider path is absolute");
        if !effective.starts_with(home) {
            return Err(format!(
                "managed rule provider {:?} path {:?} is outside Mihomo home {:?}",
                provider.name, provider.path, home
            ));
        }
        insert_effective_provider_path(&mut effective_paths, effective, &provider.name)?;
        if !names.insert(provider.name.clone()) {
            return Err(format!("duplicate rule provider name {:?}", provider.name));
        }
        let behavior = match provider.behavior {
            GeoBaseRuleBehavior::Domain => "domain",
            GeoBaseRuleBehavior::Ipcidr => "ipcidr",
        };
        map.insert(
            provider.name.clone(),
            json!({
                "type": "file",
                "behavior": behavior,
                "format": "text",
                "path": provider.path,
            }),
        );
    }

    Ok((!map.is_empty()).then_some(Value::Object(map)))
}

fn normalize_absolute_path(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    if let Ok(canonical) = fs::canonicalize(path) {
        return Some(canonical);
    }

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    Some(normalized)
}

fn effective_provider_path(
    path: &str,
    mihomo_home: Option<&Path>,
    lexical_mihomo_home: Option<&Path>,
) -> Option<PathBuf> {
    let path = Path::new(path);
    if path.is_absolute() {
        let normalized = normalize_absolute_path(path)?;
        let Some(home) = mihomo_home else {
            return Some(normalized);
        };
        let lexical_home = lexical_mihomo_home?;
        let lexical_path = lexical_absolute_path(path)?;
        match lexical_path.strip_prefix(lexical_home) {
            Ok(relative) => normalize_absolute_path(&home.join(relative)),
            Err(_) => Some(normalized),
        }
    } else {
        normalize_absolute_path(&mihomo_home?.join(path))
    }
}

fn lexical_absolute_path(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    Some(normalized)
}

fn insert_effective_provider_path(
    paths: &mut HashMap<PathBuf, String>,
    path: PathBuf,
    name: &str,
) -> Result<(), String> {
    if let Some(existing) = paths.insert(path.clone(), name.to_owned()) {
        return Err(format!(
            "duplicate effective rule provider path {:?} for {:?} and {:?}",
            path, existing, name
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Config builders
// ---------------------------------------------------------------------------

/// Build a simple Mihomo config with just a SOCKS5 listener.
/// Used when split routing is disabled.
pub fn build_mihomo_config(
    profile: &Profile,
    listen_host: &str,
    socks_port: u16,
    features: &MihomoFeatures,
) -> Result<String, String> {
    let mut proxy = build_proxy(profile, PROXY_NAME)?;
    apply_per_proxy_fields(&mut proxy, features);
    let rules = vec![format!("MATCH,{}", PROXY_NAME)];
    let mut config = json!({
        "mode": "rule",
        "log-level": "info",
        "allow-lan": true,
        "bind-address": bind_address(listen_host),
        "find-process-mode": "off",
        "ipv6": false,
        "socks-port": socks_port,
        "proxies": [proxy],
        "rules": rules,
    });
    apply_global_features(&mut config, features);

    serde_yaml::to_string(&config).map_err(|error| error.to_string())
}

/// Build a minimal Mihomo config for desktop benchmarking.
/// SOCKS listener + single proxy outbound + MATCH rule. No DNS,
/// no transparent proxy, no geo files, no features.
pub fn build_mihomo_bench_config(
    profile: &Profile,
    listen_host: &str,
    socks_port: u16,
) -> Result<String, String> {
    let proxy = build_proxy(profile, PROXY_NAME)?;
    let config = json!({
        "mode": "rule",
        "log-level": "silent",
        "allow-lan": false,
        "bind-address": bind_address(listen_host),
        "find-process-mode": "off",
        "ipv6": false,
        "geo-auto-update": false,
        "socks-port": socks_port,
        "proxies": [proxy],
        "rules": [format!("MATCH,{}", PROXY_NAME)],
    });
    serde_yaml::to_string(&config).map_err(|error| error.to_string())
}

/// Build the sniffer JSON section with feature-enhanced options.
///
/// Base sniffer: HTTP/TLS/QUIC domain detection on common ports.
/// Feature additions: `force-domain`, `skip-domain`, `skip-src-address`,
/// `skip-dst-address` for granular sniffer control.
fn build_sniffer_json(features: &MihomoFeatures) -> Value {
    let mut sniffer = json!({
        "enable": true,
        "force-dns-mapping": true,
        "parse-pure-ip": true,
        // Override destination with the sniffed domain so that domain rules
        // match even when clients bypass the router's DNS (DoH/DoT).  Without
        // this the sniffer stores the SNI in `sniffHost` but leaves `host`
        // empty, and Mihomo matches DOMAIN-* rules against `host` only.
        "override-destination": features.sniffer_override_destination,
        "sniff": {
            "HTTP": {
                "ports": [80, "8080-8880"],
            },
            "TLS": {
                "ports": [443, 8443],
            },
            "QUIC": {
                "ports": [443, 8443],
            },
        },
    });
    if !features.sniffer_force_domain.is_empty() {
        sniffer["force-domain"] = json!(features.sniffer_force_domain);
    }
    if !features.sniffer_skip_domain.is_empty() {
        sniffer["skip-domain"] = json!(features.sniffer_skip_domain);
    }
    if !features.sniffer_skip_src_address.is_empty() {
        sniffer["skip-src-address"] = json!(features.sniffer_skip_src_address);
    }
    if !features.sniffer_skip_dst_address.is_empty() {
        sniffer["skip-dst-address"] = json!(features.sniffer_skip_dst_address);
    }
    sniffer
}

/// Build a full router Mihomo config with transparent proxy listeners
/// (redirect/tproxy), DNS anti-leak, domain sniffing, and split routing
/// rules. Used when split routing is enabled.
#[allow(clippy::too_many_arguments)]
pub fn build_mihomo_router_config(
    active_profile: &Profile,
    extra_profiles: &[(&Profile, String)],
    pinned_server_routes: &[PinnedServerRoute<'_>],
    route_rules: &[XrayRouteRule],
    listen_host: &str,
    socks_port: u16,
    redirect_port: Option<u16>,
    tproxy_available: bool,
    _quic_mode: QuicMode,
    active_block_quic: bool,
    extra: &RouterExtra,
    features: &MihomoFeatures,
) -> Result<String, String> {
    // The active profile outbound is always named "proxy-active".
    // A fallback proxy group named "proxy" wraps it with DIRECT as a
    // last-resort destination — so when the upstream proxy is
    // unreachable, mihomo automatically routes traffic direct instead
    // of timing out every connection (which causes a storm that can
    // OOM the router). When the proxy recovers, mihomo switches back.
    //
    let active_proxy_name = PROXY_ACTIVE_NAME.to_owned();

    let mut internal_names: HashSet<&str> =
        [PROXY_ACTIVE_NAME, PROXY_NAME, DIRECT_NAME, REJECT_NAME]
            .into_iter()
            .collect();
    for (_, name) in extra_profiles {
        if name.trim().is_empty() || !internal_names.insert(name) {
            return Err(format!("duplicate or empty proxy/group name {name:?}"));
        }
    }
    for route in pinned_server_routes {
        for name in [route.outbound_name.as_str(), route.group_name.as_str()] {
            if name.trim().is_empty() || !internal_names.insert(name) {
                return Err(format!("duplicate or empty proxy/group name {name:?}"));
            }
        }
    }

    let mut proxies = vec![build_proxy(active_profile, &active_proxy_name)?];
    for (profile, name) in extra_profiles {
        proxies.push(build_proxy(profile, name)?);
    }
    for route in pinned_server_routes {
        proxies.push(build_proxy(route.profile, &route.outbound_name)?);
    }
    for proxy in proxies.iter_mut() {
        apply_per_proxy_fields(proxy, features);
    }

    let mut rules = Vec::new();
    for rule in route_rules {
        rules.extend(rule_to_strings(rule));
    }

    // System-level QUIC block: block when TPROXY is unavailable (UDP
    // can't be transparent-proxied) or when the active profile doesn't
    // support QUIC. User-level QUIC blocking (quic_mode, block_quic_global)
    // is handled by a regular routing rule migrated in load_state().
    let system_quic_block = active_block_quic || !tproxy_available;
    if system_quic_block {
        rules.push(format!(
            "AND,((NETWORK,udp),(DST-PORT,443)),{}",
            REJECT_NAME
        ));
    }

    // Explicit VPN exceptions override all broad RU Direct rules.
    for domain in extra
        .auto_vpn_exceptions
        .iter()
        .map(|d| d.trim())
        .filter(|d| !d.is_empty())
    {
        rules.push(format!("DOMAIN-SUFFIX,{domain},{}", PROXY_NAME));
    }

    // GeoBase providers keep precedence over hot-updated Parovozik providers.
    for target in [
        GeoBaseRuleTarget::Active,
        GeoBaseRuleTarget::Direct,
        GeoBaseRuleTarget::ParovozikVpn,
        GeoBaseRuleTarget::ParovozikDirect,
    ] {
        for provider in extra
            .geobase_rule_providers
            .iter()
            .filter(|provider| provider.enabled && provider.target == target)
        {
            let target_name = match target {
                // GeoBase Active is a broad routing intent, not a raw outbound
                // identity.  It must therefore use the same direct-fallback
                // group as regular `active` routing rules.  Sending a large
                // generated RULE-SET directly to `proxy-active` bypasses the
                // `[proxy-active, DIRECT]` safety group and can make all
                // policy-marked clients lose internet when the upstream server
                // flaps or dies.
                GeoBaseRuleTarget::Active => PROXY_NAME,
                GeoBaseRuleTarget::Direct => DIRECT_NAME,
                GeoBaseRuleTarget::ParovozikDirect => DIRECT_NAME,
                GeoBaseRuleTarget::ParovozikVpn => PAROVOZIK_PROXY_GROUP,
            };
            rules.push(format!("RULE-SET,{},{}", provider.name, target_name));
        }
    }

    // v0.16: RU Direct — route Russian domains direct before port-mode
    // fallbacks and MATCH,proxy.  Exceptions (go through VPN) are emitted
    // first so they take precedence over the broad direct rules.
    let ru_mode = extra.ru_direct_mode.trim().to_ascii_lowercase();
    if ru_mode == "tld" || ru_mode == "geosite" {
        for domain in extra
            .ru_direct_exceptions
            .iter()
            .map(|d| d.trim())
            .filter(|d| !d.is_empty())
        {
            rules.push(format!("DOMAIN-SUFFIX,{domain},{}", PROXY_NAME));
        }
        if ru_mode == "tld" {
            rules.push(format!("DOMAIN-SUFFIX,ru,{}", DIRECT_NAME));
            rules.push(format!("DOMAIN-SUFFIX,xn--p1ai,{}", DIRECT_NAME));
        } else {
            rules.push(format!("GEOSITE,category-ru,{}", DIRECT_NAME));
        }
    }

    // v0.16: MATCH target is user-configurable (match_target field).
    // Default is "proxy" (everything through VPN). When set to "direct",
    // unmatched traffic goes direct and routing rules decide what goes
    // through VPN. PortMode adds explicit DST-PORT rules before MATCH.
    let match_target_name = match extra.match_target.trim() {
        "direct" => DIRECT_NAME,
        _ => PROXY_NAME,
    };

    match extra.port_mode {
        PortMode::AllowList if !extra.proxy_ports.is_empty() => {
            for port in &extra.proxy_ports {
                rules.push(format!("DST-PORT,{},{}", port, PROXY_NAME));
            }
            rules.push(format!("MATCH,{}", match_target_name));
        }
        PortMode::DenyList if !extra.bypass_ports.is_empty() => {
            for port in &extra.bypass_ports {
                rules.push(format!("DST-PORT,{},{}", port, DIRECT_NAME));
            }
            rules.push(format!("MATCH,{}", match_target_name));
        }
        _ => {
            rules.push(format!("MATCH,{}", match_target_name));
        }
    }

    let redirect_port = redirect_port.unwrap_or(10810);
    // TPROXY listener uses a separate port (redirect_port + 1) to
    // avoid a TCP bind conflict with the redir listener.
    let tproxy_port = redirect_port + 1;
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
            "port": tproxy_port,
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
        "geo-auto-update": false,
        "socks-port": socks_port,
        "listeners": listeners,
        "proxies": proxies,
        "rules": rules,
        "sniffer": build_sniffer_json(features),
    });

    config["proxy-groups"] = json!([{
        "name": PROXY_NAME,
        "type": "fallback",
        "proxies": [active_proxy_name, DIRECT_NAME],
        "url": FALLBACK_HEALTH_URL,
        "interval": 10,
        "timeout": 3000,
    }]);

    let groups = config
        .get_mut("proxy-groups")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "internal error: router proxy groups are missing".to_owned())?;
    groups.extend(pinned_server_routes.iter().map(|route| {
        json!({
            "name": &route.group_name,
            "type": "fallback",
            "proxies": [&route.outbound_name, PROXY_ACTIVE_NAME],
            "url": FALLBACK_HEALTH_URL,
            "interval": 10,
            "timeout": 3000,
        })
    }));
    if !extra.parovozik_vpn_target.is_empty() {
        let proxies: Vec<String> = std::iter::once(PROXY_ACTIVE_NAME.to_owned())
            .chain(extra.parovozik_vpn_outbounds.iter().cloned())
            .collect();
        groups.push(json!({
            "name": PAROVOZIK_PROXY_GROUP,
            "type": "fallback",
            "proxies": proxies,
            "url": FALLBACK_HEALTH_URL,
            "interval": 10,
            "timeout": 3000,
        }));
    }

    // Rule providers are validated local managed GeoBase sets only.
    if let Some(providers) =
        merge_router_rule_providers(&extra.geobase_rule_providers, extra.mihomo_home.as_deref())?
    {
        config["rule-providers"] = providers;
    }

    // DNS — always included in router config (firewall DNATs DNS to 1053).
    if let Some(dns) = &extra.dns {
        config["dns"] = build_dns_config(dns, features);
    }

    // Global features (geodata-loader, unified-delay, profile.store-*,
    // keep-alive, experimental, auth, hosts, tunnels, NTP, external-controller).
    apply_global_features(&mut config, features);

    serde_yaml::to_string(&config).map_err(|error| error.to_string())
}

/// Build the DNS section for the transparent proxy.
///
/// Uses `fake-ip` enhanced mode so clients get fake IPs (198.18.x.x)
/// and Mihomo can sniff the real domain from the TLS/HTTP SNI.  All
/// Proxy-bound queries use remote servers, while DIRECT outbounds use the
/// configured local servers so direct routes do not depend on VPN health. No
/// `nameserver-policy` with `geosite:cn` is used because:
///   1. It triggers MMDB (geoip.metadb) loading which blocks startup
///      when the file is missing and GitHub is unreachable.
///   2. Splitting DNS by geosite is unnecessary on a censorship-bypass
///      router where all traffic should go through the proxy.
///
/// `fake-ip-filter` is set to an empty array to prevent Mihomo from
/// using its default filter (which references `geosite:cn` and
/// requires the MMDB database).
///
/// Retained DNS options are applied from `MihomoFeatures`.
fn build_dns_config(dns: &crate::xray_config::DnsSettings, features: &MihomoFeatures) -> Value {
    let mut dns_config = json!({
        "enable": true,
        "listen": format!("0.0.0.0:{}", DNS_INBOUND_PORT),
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "fake-ip-filter": features.dns_fake_ip_filter,
        "cache-algorithm": "arc",
        "nameserver": dns.remote_servers,
        "fallback": dns.remote_servers,
    });
    if dns.query_strategy == "UseIPv6" || dns.query_strategy == "UseIP" {
        dns_config["ipv6"] = json!(true);
    }
    if features.dns_prefer_h3 {
        dns_config["prefer-h3"] = json!(true);
    }
    if !features.dns_default_nameserver.is_empty() {
        dns_config["default-nameserver"] = json!(features.dns_default_nameserver);
    }
    if let Some(mode) = &features.dns_fake_ip_filter_mode
        && !mode.is_empty()
    {
        dns_config["fake-ip-filter-mode"] = json!(mode);
    }
    if let Some(ttl) = features.dns_fake_ip_ttl {
        dns_config["fake-ip-ttl"] = json!(ttl);
    }
    if features.dns_respect_rules {
        dns_config["respect-rules"] = json!(true);
    }
    if !dns.local_servers.is_empty() {
        dns_config["proxy-server-nameserver"] = json!(dns.local_servers);
    }
    if !dns.local_servers.is_empty() {
        dns_config["direct-nameserver"] = json!(dns.local_servers);
    }
    if let Some(follow) = features.dns_direct_nameserver_follow_policy {
        dns_config["direct-nameserver-follow-policy"] = json!(follow);
    }
    if !features.dns_nameserver_policy.is_empty() {
        let mut policy = json!({});
        for (domain, servers) in &features.dns_nameserver_policy {
            if !servers.is_empty() {
                policy[domain] = json!(servers);
            }
        }
        if policy.as_object().is_some_and(|m| !m.is_empty()) {
            dns_config["nameserver-policy"] = policy;
        }
    }
    if !features.dns_proxy_server_nameserver_policy.is_empty() {
        let mut policy = json!({});
        for (domain, servers) in &features.dns_proxy_server_nameserver_policy {
            if !servers.is_empty() {
                policy[domain] = json!(servers);
            }
        }
        if policy.as_object().is_some_and(|m| !m.is_empty()) {
            dns_config["proxy-server-nameserver-policy"] = policy;
        }
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
        Protocol::ShadowsocksR => build_shadowsocksr_proxy(profile, name),
        Protocol::Snell => build_snell_proxy(profile, name),
        Protocol::Http => build_http_proxy(profile, name),
        Protocol::Socks => build_socks_proxy(profile, name),
        Protocol::AnyTls => build_anytls_proxy(profile, name),
        Protocol::Hysteria => build_hysteria_proxy(profile, name),
        Protocol::Hysteria2 => build_hysteria2_proxy(profile, name),
        Protocol::WireGuard => build_wireguard_proxy(profile, name),
        Protocol::Tuic => build_tuic_proxy(profile, name),
        Protocol::Ssh => build_ssh_proxy(profile, name),
        Protocol::Masque => build_masque_proxy(profile, name),
        Protocol::OpenVpn => build_openvpn_proxy(profile, name),
        Protocol::Tailscale => build_tailscale_proxy(profile, name),
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

    // mTLS (mutual TLS) — certificate + private-key, both required.
    apply_mtls_cert_key(&mut proxy, &url);

    if security == "reality"
        && let Some(public_key) = query_value(&url, "pbk")
    {
        let mut reality_opts = json!({
            "public-key": public_key,
        });
        if let Some(short_id) = query_value(&url, "sid") {
            reality_opts["short-id"] = json!(short_id);
        }
        if is_truthy_option(query_value(&url, "support-x25519mlkem768").as_deref()) {
            reality_opts["support-x25519mlkem768"] = json!(true);
        }
        proxy["reality-opts"] = reality_opts;
    }

    // ECH (Encrypted Client Hello) — parsed from `ech` query param.
    if let Some(ech_opts) = build_ech_opts(&url) {
        proxy["ech-opts"] = ech_opts;
    }

    match network.as_str() {
        "xhttp" => {
            proxy["xhttp-opts"] = build_xhttp_opts(&url)?;
        }
        "ws" => {
            let mut ws_opts = json!({});
            if let Some(path) = query_value(&url, "path").filter(|value| !value.is_empty()) {
                ws_opts["path"] = json!(path);
            }
            if let Some(host) = query_value(&url, "host").filter(|value| !value.is_empty()) {
                ws_opts["headers"] = json!({ "Host": host });
            }
            apply_ws_early_data(&mut ws_opts, &url);
            proxy["ws-opts"] = ws_opts;
        }
        "grpc" => {
            let mut grpc_opts = json!({});
            if let Some(service_name) =
                query_value(&url, "serviceName").filter(|value| !value.is_empty())
            {
                grpc_opts["grpc-service-name"] = json!(service_name);
            }
            apply_grpc_advanced(&mut grpc_opts, &url);
            if grpc_opts.as_object().is_some_and(|m| !m.is_empty()) {
                proxy["grpc-opts"] = grpc_opts;
            }
        }
        _ => {}
    }

    Ok(proxy)
}

const MAX_XHTTP_EXTRA_BYTES: usize = 16 * 1024;
const MAX_XHTTP_STRING_BYTES: usize = 4096;
const MAX_XHTTP_HEADERS: usize = 32;
const MAX_XHTTP_HEADER_NAME_BYTES: usize = 128;
const MAX_XHTTP_HEADER_VALUE_BYTES: usize = 4096;
const MAX_XHTTP_SESSION_LENGTH: u32 = 4096;

fn build_xhttp_opts(url: &Url) -> Result<Value, String> {
    let extra = parse_xhttp_extra(url)?;
    let xmux = match extra.get("xmux") {
        Some(Value::Object(object)) => Some(object),
        Some(_) => return Err(xhttp_extra_error("xmux", "must be an object")),
        None => None,
    };
    let mut opts = json!({});

    copy_xhttp_query_string(&mut opts, url, "path", &["path"])?;
    copy_xhttp_query_string(&mut opts, url, "host", &["host"])?;
    copy_xhttp_query_string(&mut opts, url, "mode", &["mode"])?;
    copy_xhttp_headers(&mut opts, url, &extra)?;

    copy_xhttp_bool(
        &mut opts,
        url,
        &extra,
        "no-grpc-header",
        &["noGRPCHeader", "no_grpc_header", "no-grpc-header"],
        "noGRPCHeader",
    )?;
    copy_xhttp_range(
        &mut opts,
        url,
        &extra,
        "x-padding-bytes",
        &["xPaddingBytes", "x_padding_bytes", "x-padding-bytes"],
        "xPaddingBytes",
        0,
    )?;
    copy_xhttp_bool(
        &mut opts,
        url,
        &extra,
        "x-padding-obfs-mode",
        &["xPaddingObfsMode", "x_padding_obfs_mode"],
        "xPaddingObfsMode",
    )?;
    copy_xhttp_string(
        &mut opts,
        url,
        &extra,
        "x-padding-key",
        &["xPaddingKey", "x_padding_key"],
        "xPaddingKey",
    )?;
    copy_xhttp_string(
        &mut opts,
        url,
        &extra,
        "x-padding-header",
        &["xPaddingHeader", "x_padding_header"],
        "xPaddingHeader",
    )?;
    copy_xhttp_enum(
        &mut opts,
        url,
        &extra,
        "x-padding-placement",
        &["xPaddingPlacement", "x_padding_placement"],
        &["xPaddingPlacement"],
        &["queryInHeader", "cookie", "header", "query"],
    )?;
    copy_xhttp_enum(
        &mut opts,
        url,
        &extra,
        "x-padding-method",
        &["xPaddingMethod", "x_padding_method"],
        &["xPaddingMethod"],
        &["repeat-x", "tokenish"],
    )?;
    copy_xhttp_http_method(
        &mut opts,
        url,
        &extra,
        &[
            "uplinkHTTPMethod",
            "uplinkHttpMethod",
            "uplink_http_method",
            "uplink-http-method",
        ],
        "uplinkHTTPMethod",
    )?;

    for (output, query_names, extra_keys, allowed) in [
        (
            "session-placement",
            &[
                "sessionIDPlacement",
                "sessionIdPlacement",
                "sessionPlacement",
                "session_id_placement",
                "session_placement",
            ][..],
            &[
                "sessionIDPlacement",
                "sessionIdPlacement",
                "sessionPlacement",
            ][..],
            &["path", "query", "cookie", "header"][..],
        ),
        (
            "seq-placement",
            &["seqPlacement", "seq_placement"][..],
            &["seqPlacement"][..],
            &["path", "query", "cookie", "header"][..],
        ),
        (
            "uplink-data-placement",
            &["uplinkDataPlacement", "uplink_data_placement"][..],
            &["uplinkDataPlacement"][..],
            &["auto", "body", "cookie", "header"][..],
        ),
    ] {
        copy_xhttp_enum(
            &mut opts,
            url,
            &extra,
            output,
            query_names,
            extra_keys,
            allowed,
        )?;
    }
    for (output, query_names, extra_keys) in [
        (
            "session-key",
            &[
                "sessionIDKey",
                "sessionIdKey",
                "sessionKey",
                "session_id_key",
                "session_key",
            ][..],
            &["sessionIDKey", "sessionIdKey", "sessionKey"][..],
        ),
        ("seq-key", &["seqKey", "seq_key"][..], &["seqKey"][..]),
        (
            "uplink-data-key",
            &["uplinkDataKey", "uplink_data_key"][..],
            &["uplinkDataKey"][..],
        ),
    ] {
        copy_xhttp_string_multi(&mut opts, url, &extra, output, query_names, extra_keys)?;
    }
    copy_xhttp_string_multi(
        &mut opts,
        url,
        &extra,
        "session-table",
        &[
            "sessionIDTable",
            "sessionIdTable",
            "sessionTable",
            "session_id_table",
            "session_table",
        ],
        &["sessionIDTable", "sessionIdTable", "sessionTable"],
    )?;
    copy_xhttp_range_multi(
        &mut opts,
        url,
        &extra,
        "session-length",
        &[
            "sessionIDLength",
            "sessionIdLength",
            "sessionLength",
            "session_id_length",
            "session_length",
        ],
        &["sessionIDLength", "sessionIdLength", "sessionLength"],
        1,
    )?;
    validate_xhttp_session_id(&opts)?;
    copy_xhttp_range_allow_zero(
        &mut opts,
        url,
        &extra,
        "uplink-chunk-size",
        &["uplinkChunkSize", "uplink_chunk_size"],
        "uplinkChunkSize",
        64,
    )?;
    if opts.get("uplink-chunk-size").is_none()
        && opts
            .get("uplink-data-placement")
            .and_then(Value::as_str)
            .is_some_and(|placement| matches!(placement, "header" | "cookie"))
    {
        // Mihomo v1.19.29 fails packet-up before sending when this range is
        // omitted. This matches Xray's header/cookie placement default.
        opts["uplink-chunk-size"] = json!("3000-4000");
    }
    for (output, query_names, extra_key, minimum) in [
        (
            "sc-max-each-post-bytes",
            &["scMaxEachPostBytes", "sc_max_each_post_bytes"][..],
            "scMaxEachPostBytes",
            1,
        ),
        (
            "sc-min-posts-interval-ms",
            &["scMinPostsIntervalMs", "sc_min_posts_interval_ms"][..],
            "scMinPostsIntervalMs",
            1,
        ),
    ] {
        copy_xhttp_range(
            &mut opts,
            url,
            &extra,
            output,
            query_names,
            extra_key,
            minimum,
        )?;
    }

    let mut reuse = json!({});
    for (output, query_names, extra_key) in [
        (
            "max-concurrency",
            &["xmuxMaxConcurrency", "xmux_max_concurrency"][..],
            "maxConcurrency",
        ),
        (
            "max-connections",
            &["xmuxMaxConnections", "xmux_max_connections"][..],
            "maxConnections",
        ),
        (
            "c-max-reuse-times",
            &["xmuxCMaxReuseTimes", "xmux_c_max_reuse_times"][..],
            "cMaxReuseTimes",
        ),
        (
            "h-max-request-times",
            &["xmuxHMaxRequestTimes", "xmux_h_max_request_times"][..],
            "hMaxRequestTimes",
        ),
        (
            "h-max-reusable-secs",
            &["xmuxHMaxReusableSecs", "xmux_h_max_reusable_secs"][..],
            "hMaxReusableSecs",
        ),
    ] {
        copy_xhttp_range_from(&mut reuse, url, xmux, output, query_names, extra_key, 0)?;
    }
    copy_xhttp_integer_from(
        &mut reuse,
        url,
        xmux,
        "h-keep-alive-period",
        &["xmuxHKeepAlivePeriod", "xmux_h_keep_alive_period"],
        "hKeepAlivePeriod",
    )?;
    if reuse.as_object().is_some_and(|object| !object.is_empty()) {
        opts["reuse-settings"] = reuse;
    }

    reject_xhttp_download_settings(url, &extra)?;

    Ok(opts)
}

fn copy_xhttp_headers(
    output: &mut Value,
    url: &Url,
    extra: &serde_json::Map<String, Value>,
) -> Result<(), String> {
    let value = query_value(url, "headers")
        .map(|raw| {
            if raw.len() > MAX_XHTTP_EXTRA_BYTES {
                return Err(xhttp_extra_error("headers", "exceeds the size limit"));
            }
            serde_json::from_str::<Value>(&raw)
                .map_err(|_| xhttp_extra_error("headers", "must be a JSON object"))
        })
        .transpose()?
        .or_else(|| extra.get("headers").cloned());
    let Some(value) = value else { return Ok(()) };
    let object = value
        .as_object()
        .ok_or_else(|| xhttp_extra_error("headers", "must be an object"))?;
    if object.len() > MAX_XHTTP_HEADERS {
        return Err(xhttp_extra_error("headers", "has too many entries"));
    }
    let mut headers = serde_json::Map::with_capacity(object.len());
    for (key, value) in object {
        if key.is_empty()
            || key.len() > MAX_XHTTP_HEADER_NAME_BYTES
            || !key.bytes().all(is_http_token_byte)
        {
            return Err(xhttp_extra_error(
                "headers",
                "contains an invalid header name",
            ));
        }
        let value = value
            .as_str()
            .ok_or_else(|| xhttp_extra_error("headers", "values must be strings"))?;
        if value.len() > MAX_XHTTP_HEADER_VALUE_BYTES || value.chars().any(char::is_control) {
            return Err(xhttp_extra_error(
                "headers",
                "contains an invalid header value",
            ));
        }
        headers.insert(key.clone(), json!(value));
    }
    output["headers"] = Value::Object(headers);
    Ok(())
}

fn reject_xhttp_download_settings(
    url: &Url,
    extra: &serde_json::Map<String, Value>,
) -> Result<(), String> {
    let value = query_value_multi(url, &["downloadSettings", "download_settings"])
        .map(|raw| {
            if raw.len() > MAX_XHTTP_EXTRA_BYTES {
                return Err(xhttp_extra_error(
                    "downloadSettings",
                    "exceeds the size limit",
                ));
            }
            serde_json::from_str::<Value>(&raw)
                .map_err(|_| xhttp_extra_error("downloadSettings", "must be a JSON object"))
        })
        .transpose()?
        .or_else(|| extra.get("downloadSettings").cloned());
    match value {
        None => Ok(()),
        Some(Value::Object(object)) if object.is_empty() => Ok(()),
        Some(Value::Object(_)) => Err(xhttp_extra_error(
            "downloadSettings",
            "is not compatible with Mihomo v1.19.29 without unsafe nested proxy/TLS passthrough",
        )),
        Some(_) => Err(xhttp_extra_error("downloadSettings", "must be an object")),
    }
}

fn validate_xhttp_session_id(opts: &Value) -> Result<(), String> {
    let Some(length) = opts.get("session-length").and_then(Value::as_str) else {
        return Ok(());
    };
    let (minimum, maximum) = parse_checked_xhttp_range(length)
        .ok_or_else(|| xhttp_extra_error("sessionIDLength", "has an invalid range"))?;
    if maximum > MAX_XHTTP_SESSION_LENGTH {
        return Err(xhttp_extra_error(
            "sessionIDLength",
            "exceeds the 4096-character limit",
        ));
    }
    let table = opts
        .get("session-table")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let alphabet_size = match table {
        "" | "uuid" => return Ok(()),
        "ALPHABET" | "alphabet" => 26_u64,
        "Alphabet" => 52,
        "BASE36" | "base36" => 36,
        "Base62" => 62,
        "HEX" | "hex" => 16,
        "number" => 10,
        custom => custom.chars().collect::<HashSet<_>>().len() as u64,
    };
    if alphabet_size < 2 {
        return Err(xhttp_extra_error(
            "sessionIDTable",
            "must contain at least two distinct characters",
        ));
    }
    let mut possibilities = 0_u64;
    let mut values_at_length = 1_u64;
    for current in 1..=maximum {
        values_at_length = values_at_length.saturating_mul(alphabet_size);
        if current >= minimum {
            possibilities = possibilities.saturating_add(values_at_length);
            if possibilities >= (2_u64 << 30) {
                return Ok(());
            }
        }
    }
    Err(xhttp_extra_error(
        "sessionIDTable/sessionIDLength",
        "must provide at least 2^31 possible session IDs",
    ))
}

fn parse_xhttp_extra(url: &Url) -> Result<serde_json::Map<String, Value>, String> {
    let Some(raw) = query_value(url, "extra") else {
        return Ok(serde_json::Map::new());
    };
    if raw.len() > MAX_XHTTP_EXTRA_BYTES {
        return Err(format!(
            "VLESS XHTTP extra exceeds the {MAX_XHTTP_EXTRA_BYTES}-byte limit"
        ));
    }
    match serde_json::from_str::<Value>(&raw) {
        Ok(Value::Object(object)) => Ok(object),
        Ok(_) => Err("VLESS XHTTP extra must be a JSON object".to_owned()),
        Err(_) => Err("VLESS XHTTP extra is not valid JSON".to_owned()),
    }
}

pub(crate) fn read_xhttp_tuning(raw: &str) -> Result<Option<XhttpTuningValues>, String> {
    let url = Url::parse(raw).map_err(|error| format!("invalid profile URL: {error}"))?;
    if !url.scheme().eq_ignore_ascii_case("vless")
        || query_value(&url, "type").as_deref() != Some("xhttp")
    {
        return Ok(None);
    }
    let extra = parse_xhttp_extra(&url)?;
    let read = |query_names: &[&str], extra_key: &str| -> Result<Option<String>, String> {
        let value = query_value_multi(&url, query_names)
            .map(Ok)
            .or_else(|| {
                extra
                    .get(extra_key)
                    .map(|value| xhttp_json_range(extra_key, value))
            })
            .transpose()?;
        value
            .map(|value| checked_xhttp_range(extra_key, &value, 1))
            .transpose()
    };
    Ok(Some((
        read(
            &["scMaxEachPostBytes", "sc_max_each_post_bytes"],
            "scMaxEachPostBytes",
        )?,
        read(
            &["scMinPostsIntervalMs", "sc_min_posts_interval_ms"],
            "scMinPostsIntervalMs",
        )?,
    )))
}

pub(crate) type XhttpTuningValues = (Option<String>, Option<String>);

pub(crate) fn update_xhttp_tuning(
    raw: &str,
    sc_max_each_post_bytes: Option<&str>,
    sc_min_posts_interval_ms: Option<&str>,
) -> Result<String, String> {
    let mut url = Url::parse(raw).map_err(|error| format!("invalid profile URL: {error}"))?;
    if !url.scheme().eq_ignore_ascii_case("vless")
        || query_value(&url, "type").as_deref() != Some("xhttp")
    {
        return Err("XHTTP tuning is available only for VLESS XHTTP profiles".to_owned());
    }
    let mut extra = parse_xhttp_extra(&url)?;
    for key in ["scMaxEachPostBytes", "scMinPostsIntervalMs"] {
        extra.remove(key);
    }
    let normalized = [
        (
            "scMaxEachPostBytes",
            sc_max_each_post_bytes,
            "scMaxEachPostBytes",
        ),
        (
            "scMinPostsIntervalMs",
            sc_min_posts_interval_ms,
            "scMinPostsIntervalMs",
        ),
    ];
    for (field, value, extra_key) in normalized {
        if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
            extra.insert(
                extra_key.to_owned(),
                Value::String(checked_xhttp_range(field, value, 1)?),
            );
        }
    }

    let retained: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(key, _)| {
            !matches!(
                key.as_ref(),
                "extra"
                    | "scMaxEachPostBytes"
                    | "sc_max_each_post_bytes"
                    | "scMinPostsIntervalMs"
                    | "sc_min_posts_interval_ms"
            )
        })
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    url.set_query(None);
    {
        let mut query = url.query_pairs_mut();
        query.extend_pairs(retained);
        if !extra.is_empty() {
            let encoded = serde_json::to_string(&extra)
                .map_err(|error| format!("serialize VLESS XHTTP extra: {error}"))?;
            if encoded.len() > MAX_XHTTP_EXTRA_BYTES {
                return Err(format!(
                    "VLESS XHTTP extra exceeds the {MAX_XHTTP_EXTRA_BYTES}-byte limit"
                ));
            }
            query.append_pair("extra", &encoded);
        }
    }
    Ok(url.to_string())
}

fn copy_xhttp_query_string(
    output: &mut Value,
    url: &Url,
    output_key: &str,
    query_names: &[&str],
) -> Result<(), String> {
    if let Some(value) = query_value_multi(url, query_names) {
        output[output_key] = json!(checked_xhttp_string(output_key, &value)?);
    }
    Ok(())
}

fn copy_xhttp_string(
    output: &mut Value,
    url: &Url,
    extra: &serde_json::Map<String, Value>,
    output_key: &str,
    query_names: &[&str],
    extra_key: &str,
) -> Result<(), String> {
    copy_xhttp_string_multi(output, url, extra, output_key, query_names, &[extra_key])
}

fn copy_xhttp_string_multi(
    output: &mut Value,
    url: &Url,
    extra: &serde_json::Map<String, Value>,
    output_key: &str,
    query_names: &[&str],
    extra_keys: &[&str],
) -> Result<(), String> {
    let value = if let Some(value) = query_value_multi(url, query_names) {
        Some(value)
    } else {
        json_value_multi(extra, extra_keys)
            .map(|(key, value)| xhttp_json_string(key, value))
            .transpose()?
    };
    if let Some(value) = value {
        output[output_key] = json!(checked_xhttp_string(extra_keys[0], &value)?);
    }
    Ok(())
}

fn copy_xhttp_bool(
    output: &mut Value,
    url: &Url,
    extra: &serde_json::Map<String, Value>,
    output_key: &str,
    query_names: &[&str],
    extra_key: &str,
) -> Result<(), String> {
    let value = if let Some(value) = query_value_multi(url, query_names) {
        Some(parse_xhttp_bool(extra_key, &value)?)
    } else {
        extra
            .get(extra_key)
            .map(|value| xhttp_json_bool(extra_key, value))
            .transpose()?
    };
    if let Some(value) = value {
        output[output_key] = json!(value);
    }
    Ok(())
}

fn copy_xhttp_enum(
    output: &mut Value,
    url: &Url,
    extra: &serde_json::Map<String, Value>,
    output_key: &str,
    query_names: &[&str],
    extra_keys: &[&str],
    allowed: &[&str],
) -> Result<(), String> {
    let value = if let Some(value) = query_value_multi(url, query_names) {
        Some(value)
    } else {
        json_value_multi(extra, extra_keys)
            .map(|(key, value)| xhttp_json_string(key, value))
            .transpose()?
    };
    if let Some(value) = value {
        let value = checked_xhttp_string(extra_keys[0], &value)?;
        if !allowed.contains(&value.as_str()) {
            return Err(xhttp_extra_error(extra_keys[0], "has an unsupported value"));
        }
        output[output_key] = json!(value);
    }
    Ok(())
}

fn copy_xhttp_http_method(
    output: &mut Value,
    url: &Url,
    extra: &serde_json::Map<String, Value>,
    query_names: &[&str],
    extra_key: &str,
) -> Result<(), String> {
    let value = if let Some(value) = query_value_multi(url, query_names) {
        Some(value)
    } else {
        extra
            .get(extra_key)
            .map(|value| xhttp_json_string(extra_key, value))
            .transpose()?
    };
    if let Some(value) = value {
        if value.is_empty() || value.len() > 32 || !value.bytes().all(is_http_token_byte) {
            return Err(xhttp_extra_error(extra_key, "must be a valid HTTP method"));
        }
        output["uplink-http-method"] = json!(value);
    }
    Ok(())
}

fn copy_xhttp_range(
    output: &mut Value,
    url: &Url,
    extra: &serde_json::Map<String, Value>,
    output_key: &str,
    query_names: &[&str],
    extra_key: &str,
    minimum: u32,
) -> Result<(), String> {
    copy_xhttp_range_from(
        output,
        url,
        Some(extra),
        output_key,
        query_names,
        extra_key,
        minimum,
    )
}

fn copy_xhttp_range_allow_zero(
    output: &mut Value,
    url: &Url,
    extra: &serde_json::Map<String, Value>,
    output_key: &str,
    query_names: &[&str],
    extra_key: &str,
    minimum_nonzero: u32,
) -> Result<(), String> {
    let value = if let Some(value) = query_value_multi(url, query_names) {
        Some(value)
    } else {
        extra
            .get(extra_key)
            .map(|value| xhttp_json_range(extra_key, value))
            .transpose()?
    };
    if let Some(value) = value {
        let checked = if value.trim() == "0" {
            "0".to_owned()
        } else {
            checked_xhttp_range(extra_key, &value, minimum_nonzero)?
        };
        output[output_key] = json!(checked);
    }
    Ok(())
}

fn copy_xhttp_range_multi(
    output: &mut Value,
    url: &Url,
    extra: &serde_json::Map<String, Value>,
    output_key: &str,
    query_names: &[&str],
    extra_keys: &[&str],
    minimum: u32,
) -> Result<(), String> {
    let value = if let Some(value) = query_value_multi(url, query_names) {
        Some(value)
    } else {
        json_value_multi(extra, extra_keys)
            .map(|(key, value)| xhttp_json_range(key, value))
            .transpose()?
    };
    if let Some(value) = value {
        output[output_key] = json!(checked_xhttp_range(extra_keys[0], &value, minimum)?);
    }
    Ok(())
}

fn json_value_multi<'a>(
    object: &'a serde_json::Map<String, Value>,
    keys: &[&'a str],
) -> Option<(&'a str, &'a Value)> {
    keys.iter()
        .find_map(|key| object.get(*key).map(|value| (*key, value)))
}

fn copy_xhttp_range_from(
    output: &mut Value,
    url: &Url,
    extra: Option<&serde_json::Map<String, Value>>,
    output_key: &str,
    query_names: &[&str],
    extra_key: &str,
    minimum: u32,
) -> Result<(), String> {
    let value = if let Some(value) = query_value_multi(url, query_names) {
        Some(value)
    } else {
        extra
            .and_then(|object| object.get(extra_key))
            .map(|value| xhttp_json_range(extra_key, value))
            .transpose()?
    };
    if let Some(value) = value {
        output[output_key] = json!(checked_xhttp_range(extra_key, &value, minimum)?);
    }
    Ok(())
}

fn copy_xhttp_integer_from(
    output: &mut Value,
    url: &Url,
    extra: Option<&serde_json::Map<String, Value>>,
    output_key: &str,
    query_names: &[&str],
    extra_key: &str,
) -> Result<(), String> {
    let value = if let Some(value) = query_value_multi(url, query_names) {
        value
            .parse::<i32>()
            .map_err(|_| xhttp_extra_error(extra_key, "must be a 32-bit integer"))?
    } else if let Some(value) = extra.and_then(|object| object.get(extra_key)) {
        match value {
            Value::Number(number) => number
                .as_i64()
                .and_then(|number| i32::try_from(number).ok())
                .ok_or_else(|| xhttp_extra_error(extra_key, "must be a 32-bit integer"))?,
            Value::String(text) => text
                .parse::<i32>()
                .map_err(|_| xhttp_extra_error(extra_key, "must be a 32-bit integer"))?,
            _ => return Err(xhttp_extra_error(extra_key, "must be an integer")),
        }
    } else {
        return Ok(());
    };
    output[output_key] = json!(value);
    Ok(())
}

fn xhttp_json_string(field: &str, value: &Value) -> Result<String, String> {
    value
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| xhttp_extra_error(field, "must be a string"))
}

fn xhttp_json_bool(field: &str, value: &Value) -> Result<bool, String> {
    match value {
        Value::Bool(value) => Ok(*value),
        Value::String(value) => parse_xhttp_bool(field, value),
        _ => Err(xhttp_extra_error(field, "must be a boolean")),
    }
}

fn parse_xhttp_bool(field: &str, value: &str) -> Result<bool, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(xhttp_extra_error(field, "must be a boolean")),
    }
}

fn xhttp_json_range(field: &str, value: &Value) -> Result<String, String> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(number) => number
            .as_u64()
            .filter(|number| *number <= u64::from(u32::MAX))
            .map(|number| number.to_string())
            .ok_or_else(|| xhttp_extra_error(field, "must be a non-negative 32-bit range")),
        _ => Err(xhttp_extra_error(
            field,
            "must be a string or integer range",
        )),
    }
}

fn checked_xhttp_range(field: &str, value: &str, minimum: u32) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 64 {
        return Err(xhttp_extra_error(field, "has an invalid range"));
    }
    let mut parts = value.split('-');
    let minimum_value = parts
        .next()
        .and_then(|part| part.trim().parse::<u32>().ok())
        .ok_or_else(|| xhttp_extra_error(field, "has an invalid range"))?;
    let maximum_value = parts
        .next()
        .map(str::trim)
        .map(str::parse::<u32>)
        .transpose()
        .map_err(|_| xhttp_extra_error(field, "has an invalid range"))?
        .unwrap_or(minimum_value);
    if parts.next().is_some() || minimum_value < minimum || maximum_value < minimum_value {
        return Err(xhttp_extra_error(field, "has an invalid range"));
    }
    if minimum_value == maximum_value {
        Ok(minimum_value.to_string())
    } else {
        Ok(format!("{minimum_value}-{maximum_value}"))
    }
}

fn parse_checked_xhttp_range(value: &str) -> Option<(u32, u32)> {
    let mut parts = value.split('-');
    let minimum = parts.next()?.parse().ok()?;
    let maximum = parts
        .next()
        .map(str::parse)
        .transpose()
        .ok()?
        .unwrap_or(minimum);
    (parts.next().is_none() && maximum >= minimum).then_some((minimum, maximum))
}

fn checked_xhttp_string(field: &str, value: &str) -> Result<String, String> {
    if value.len() > MAX_XHTTP_STRING_BYTES || value.chars().any(char::is_control) {
        return Err(xhttp_extra_error(
            field,
            "must be a bounded string without control characters",
        ));
    }
    Ok(value.to_owned())
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn xhttp_extra_error(field: &str, expectation: &str) -> String {
    format!("VLESS XHTTP extra field {field} {expectation}")
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

    // mTLS (mutual TLS) — certificate + private-key, both required.
    let cert = json
        .get("certificate")
        .and_then(Value::as_str)
        .or_else(|| json.get("cert").and_then(Value::as_str));
    let key = json
        .get("privateKey")
        .and_then(Value::as_str)
        .or_else(|| json.get("private_key").and_then(Value::as_str));
    if let (Some(cert), Some(key)) = (cert, key) {
        proxy["certificate"] = json!(cert);
        proxy["private-key"] = json!(key);
    }

    // ECH (Encrypted Client Hello) — parsed from vmess JSON `ech` field.
    if let Some(ech) = json.get("ech").and_then(Value::as_str) {
        let mut ech_opts = if ech == "1" || ech.eq_ignore_ascii_case("true") {
            json!({ "enable": true })
        } else {
            json!({ "enable": true, "config": ech })
        };
        if let Some(qsn) = json.get("echServerName").and_then(Value::as_str) {
            ech_opts["query-server-name"] = json!(qsn);
        }
        proxy["ech-opts"] = ech_opts;
    }

    if network == "ws" {
        let mut ws_opts = json!({});
        if let Some(path) = json.get("path").and_then(Value::as_str) {
            ws_opts["path"] = json!(path);
        }
        if let Some(host) = json.get("host").and_then(Value::as_str) {
            ws_opts["headers"] = json!({ "Host": host });
        }
        if let Some(v) = json.get("maxEarlyData").and_then(Value::as_u64) {
            ws_opts["max-early-data"] = json!(v);
        }
        if let Some(v) = json.get("earlyDataHeaderName").and_then(Value::as_str) {
            ws_opts["early-data-header-name"] = json!(v);
        }
        if let Some(v) = json.get("v2rayHttpUpgrade").and_then(Value::as_str)
            && (v == "1" || v.eq_ignore_ascii_case("true"))
        {
            ws_opts["v2ray-http-upgrade"] = json!(true);
        }
        if let Some(v) = json.get("v2rayHttpUpgradeFastOpen").and_then(Value::as_str)
            && (v == "1" || v.eq_ignore_ascii_case("true"))
        {
            ws_opts["v2ray-http-upgrade-fast-open"] = json!(true);
        }
        proxy["ws-opts"] = ws_opts;
    } else if network == "grpc" {
        let mut grpc_opts = json!({});
        // VMess stores grpc serviceName in the `path` JSON field.
        if let Some(service_name) = json.get("path").and_then(Value::as_str) {
            grpc_opts["grpc-service-name"] = json!(service_name);
        }
        if let Some(v) = json.get("grpcUserAgent").and_then(Value::as_str) {
            grpc_opts["grpc-user-agent"] = json!(v);
        }
        if let Some(v) = json.get("pingInterval").and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        }) {
            grpc_opts["ping-interval"] = json!(v);
        }
        if let Some(v) = json.get("maxConnections").and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        }) {
            grpc_opts["max-connections"] = json!(v);
        }
        if let Some(v) = json.get("minStreams").and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        }) {
            grpc_opts["min-streams"] = json!(v);
        }
        if let Some(v) = json.get("maxStreams").and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        }) {
            grpc_opts["max-streams"] = json!(v);
        }
        if grpc_opts.as_object().is_some_and(|m| !m.is_empty()) {
            proxy["grpc-opts"] = grpc_opts;
        }
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

    // mTLS (mutual TLS) — certificate + private-key, both required.
    apply_mtls_cert_key(&mut proxy, &url);

    // ECH (Encrypted Client Hello) — parsed from `ech` query param.
    if let Some(ech_opts) = build_ech_opts(&url) {
        proxy["ech-opts"] = ech_opts;
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
            apply_ws_early_data(&mut ws_opts, &url);
            proxy["ws-opts"] = ws_opts;
        } else if net == "grpc" {
            let mut grpc_opts = json!({});
            if let Some(service_name) =
                query_value(&url, "serviceName").filter(|value| !value.is_empty())
            {
                grpc_opts["grpc-service-name"] = json!(service_name);
            }
            apply_grpc_advanced(&mut grpc_opts, &url);
            if grpc_opts.as_object().is_some_and(|m| !m.is_empty()) {
                proxy["grpc-opts"] = grpc_opts;
            }
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

fn build_shadowsocksr_proxy(profile: &Profile, name: &str) -> Result<Value, String> {
    let url = Url::parse(&profile.raw).map_err(|error| error.to_string())?;
    let password = url_password_or_query(&url, "password");
    let cipher = required_query(&url, "cipher", "ShadowsocksR ссылка без cipher")?;
    let obfs = required_query(&url, "obfs", "ShadowsocksR ссылка без obfs")?;
    let protocol = required_query(&url, "protocol", "ShadowsocksR ссылка без protocol")?;
    let mut proxy = json!({
        "name": name,
        "type": "ssr",
        "server": profile.address,
        "port": profile.port.unwrap_or(443),
        "cipher": cipher,
        "password": password,
        "obfs": obfs,
        "protocol": protocol,
    });
    copy_optional_string(
        &mut proxy,
        &url,
        "obfs-param",
        &["obfs-param", "obfs_param"],
    );
    copy_optional_string(
        &mut proxy,
        &url,
        "protocol-param",
        &["protocol-param", "protocol_param"],
    );
    Ok(proxy)
}

fn build_snell_proxy(profile: &Profile, name: &str) -> Result<Value, String> {
    let url = Url::parse(&profile.raw).map_err(|error| error.to_string())?;
    let psk = if url.username().is_empty() {
        required_query(&url, "psk", "Snell ссылка без psk")?
    } else {
        percent_decode(url.username())
    };
    let mut proxy = json!({
        "name": name,
        "type": "snell",
        "server": profile.address,
        "port": profile.port.unwrap_or(44046),
        "psk": psk,
    });
    copy_optional_u32(&mut proxy, &url, "version", &["version"]);
    copy_optional_bool(&mut proxy, &url, "reuse", &["reuse"]);
    if let Some(mode) = query_value_multi(&url, &["obfs", "obfs-mode", "obfs_mode"])
        && !mode.is_empty()
    {
        let mut obfs_opts = json!({ "mode": mode });
        if let Some(host) = query_value_multi(&url, &["obfs-host", "obfs_host", "host"]) {
            obfs_opts["host"] = json!(host);
        }
        proxy["obfs-opts"] = obfs_opts;
    }
    Ok(proxy)
}

fn build_http_proxy(profile: &Profile, name: &str) -> Result<Value, String> {
    let url = Url::parse(&profile.raw).map_err(|error| error.to_string())?;
    let mut proxy = json!({
        "name": name,
        "type": "http",
        "server": profile.address,
        "port": profile.port.unwrap_or(80),
    });
    apply_user_password(&mut proxy, &url);
    apply_tls_common(&mut proxy, &url);
    Ok(proxy)
}

fn build_socks_proxy(profile: &Profile, name: &str) -> Result<Value, String> {
    let url = Url::parse(&profile.raw).map_err(|error| error.to_string())?;
    let scheme_type = match url.scheme() {
        "socks4" => "socks4",
        _ => "socks5",
    };
    let mut proxy = json!({
        "name": name,
        "type": scheme_type,
        "server": profile.address,
        "port": profile.port.unwrap_or(1080),
    });
    apply_user_password(&mut proxy, &url);
    apply_tls_common(&mut proxy, &url);
    Ok(proxy)
}

fn build_anytls_proxy(profile: &Profile, name: &str) -> Result<Value, String> {
    let url = Url::parse(&profile.raw).map_err(|error| error.to_string())?;
    let password = url_password_or_query(&url, "password");
    if password.is_empty() {
        return Err("AnyTLS ссылка без password".to_owned());
    }
    let mut proxy = json!({
        "name": name,
        "type": "anytls",
        "server": profile.address,
        "port": profile.port.unwrap_or(443),
        "password": password,
    });
    apply_tls_common(&mut proxy, &url);
    copy_optional_u32(
        &mut proxy,
        &url,
        "idle-session-check-interval",
        &["idle-session-check-interval", "idle_session_check_interval"],
    );
    copy_optional_u32(
        &mut proxy,
        &url,
        "idle-session-timeout",
        &["idle-session-timeout", "idle_session_timeout"],
    );
    copy_optional_u32(
        &mut proxy,
        &url,
        "min-idle-session",
        &["min-idle-session", "min_idle_session"],
    );
    Ok(proxy)
}

fn build_hysteria_proxy(profile: &Profile, name: &str) -> Result<Value, String> {
    let url = Url::parse(&profile.raw).map_err(|error| error.to_string())?;
    let auth_str = url_password_or_query(&url, "auth-str");
    if auth_str.is_empty() {
        return Err("Hysteria ссылка без auth-str".to_owned());
    }
    let mut proxy = json!({
        "name": name,
        "type": "hysteria",
        "server": profile.address,
        "port": profile.port.unwrap_or(443),
        "auth-str": auth_str,
    });
    copy_optional_string(&mut proxy, &url, "ports", &["ports"]);
    copy_optional_string(&mut proxy, &url, "obfs", &["obfs"]);
    copy_optional_string(&mut proxy, &url, "protocol", &["protocol"]);
    copy_optional_bandwidth(&mut proxy, &url, "up", &["up", "upmbps"]);
    copy_optional_bandwidth(&mut proxy, &url, "down", &["down", "downmbps"]);
    apply_tls_common(&mut proxy, &url);
    copy_optional_u32(
        &mut proxy,
        &url,
        "recv-window-conn",
        &["recv-window-conn", "recv_window_conn"],
    );
    copy_optional_u32(
        &mut proxy,
        &url,
        "recv-window",
        &["recv-window", "recv_window"],
    );
    copy_optional_bool(
        &mut proxy,
        &url,
        "disable_mtu_discovery",
        &["disable_mtu_discovery", "disable-mtu-discovery"],
    );
    copy_optional_bool(&mut proxy, &url, "fast-open", &["fast-open", "fast_open"]);
    Ok(proxy)
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

    // Port hopping: `mport` (standard Hysteria2 share-link param) or
    // `ports` specifies a port range (e.g. "443-8443"). When present,
    // Mihomo ignores the `port` field and hops across the range.
    if let Some(ports) = query_value_multi(&url, &["mport", "ports"]) {
        proxy["ports"] = json!(ports);
    }

    // Hop interval in seconds (default 30 in Mihomo). Supports a range
    // like "15-30" for randomised intervals.
    if let Some(hop) = query_value_multi(&url, &["hopInterval", "hopinterval", "hop_interval"]) {
        proxy["hop-interval"] = json!(hop);
    }

    Ok(proxy)
}

/// Build a WireGuard proxy for Mihomo.
///
/// Parses `wireguard://` (or `wg://`) share links with the private key
/// in the username position or as a `privatekey` query parameter.
///
/// Mihomo WireGuard outbound fields (verified against wiki.metacubex.one):
/// `type: wireguard`, `server`, `port`, `ip` (IPv4), `ipv6`,
/// `private-key`, `public-key`, `allowed-ips`, `pre-shared-key`,
/// `reserved`, `mtu`, `udp: true`.
fn build_wireguard_proxy(profile: &Profile, name: &str) -> Result<Value, String> {
    let url = Url::parse(&profile.raw).map_err(|error| error.to_string())?;

    // Private key: username (percent-decoded) or query param.
    let private_key = if !url.username().is_empty() {
        percent_decode(url.username())
    } else {
        url.query_pairs()
            .find(|(k, _)| k == "privatekey" || k == "private-key")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default()
    };
    if private_key.is_empty() {
        return Err("WireGuard ссылка без приватного ключа".to_owned());
    }

    // Public key: required for the simplified (single-peer) format.
    let public_key = url
        .query_pairs()
        .find(|(k, _)| k == "publickey" || k == "public-key" || k == "peer")
        .map(|(_, v)| v.into_owned())
        .ok_or_else(|| "WireGuard ссылка без публичного ключа (publickey)".to_owned())?;

    let mut proxy = json!({
        "name": name,
        "type": "wireguard",
        "server": profile.address,
        "port": profile.port.unwrap_or(51820),
        "private-key": private_key,
        "public-key": public_key,
        "udp": true,
    });

    // Interface addresses: `address` param may appear multiple times
    // or be comma-separated. Strip CIDR suffixes. Classify as IPv4/IPv6.
    let addresses: Vec<String> = url
        .query_pairs()
        .filter(|(k, _)| k == "address")
        .flat_map(|(_, v)| {
            v.split(',')
                .map(|s| s.trim().split('/').next().unwrap_or("").to_owned())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        })
        .collect();

    let ipv4: Vec<&String> = addresses.iter().filter(|a| a.contains('.')).collect();
    let ipv6: Vec<&String> = addresses.iter().filter(|a| a.contains(':')).collect();
    if let Some(ip) = ipv4.first() {
        proxy["ip"] = json!(ip);
    }
    if let Some(ip) = ipv6.first() {
        proxy["ipv6"] = json!(ip);
    }

    // Allowed IPs — default to 0.0.0.0/0 if not specified.
    let allowed_ips: Vec<String> = url
        .query_pairs()
        .find(|(k, _)| k == "allowedips" || k == "allowed-ips")
        .map(|(_, v)| v.split(',').map(|s| s.trim().to_owned()).collect())
        .unwrap_or_else(|| vec!["0.0.0.0/0".to_owned()]);
    proxy["allowed-ips"] = json!(allowed_ips);

    if let Some(psk) = url
        .query_pairs()
        .find(|(k, _)| k == "presharedkey" || k == "pre-shared-key" || k == "psk")
    {
        let (_, v) = psk;
        if !v.is_empty() {
            proxy["pre-shared-key"] = json!(v.into_owned());
        }
    }

    if let Some(mtu) = url
        .query_pairs()
        .find(|(k, _)| k == "mtu")
        .and_then(|(_, v)| v.parse::<u32>().ok())
    {
        proxy["mtu"] = json!(mtu);
    }

    // Reserved bytes — comma-separated integers (e.g. "209,98,59").
    if let Some(reserved) = url.query_pairs().find(|(k, _)| k == "reserved") {
        let (_, v) = reserved;
        let parts: Vec<u32> = v
            .split(',')
            .filter_map(|s| s.trim().parse::<u32>().ok())
            .collect();
        if !parts.is_empty() {
            proxy["reserved"] = json!(parts);
        }
    }

    if let Some(keepalive) = url
        .query_pairs()
        .find(|(k, _)| k == "keepalive" || k == "persistent-keepalive")
        .and_then(|(_, v)| v.parse::<u32>().ok())
    {
        proxy["persistent-keepalive"] = json!(keepalive);
    }

    Ok(proxy)
}

/// Build a TUIC proxy for Mihomo.
///
/// Parses `tuic://<uuid>:<password>@<host>:<port>?<params>#<name>` links.
/// TUIC V5 uses uuid+password; V4 uses token (not commonly seen in
/// share links — V5 is the modern standard).
///
/// Mihomo TUIC outbound fields (verified against wiki.metacubex.one):
/// `type: tuic`, `server`, `port`, `uuid`, `password`, `ip`,
/// `heartbeat-interval`, `alpn`, `disable-sni`, `reduce-rtt`,
/// `request-timeout`, `udp-relay-mode`, `congestion-controller`,
/// `max-udp-relay-packet-size`, `fast-open`, `max-open-streams`,
/// `sni`, `skip-cert-verify`.
fn build_tuic_proxy(profile: &Profile, name: &str) -> Result<Value, String> {
    let url = Url::parse(&profile.raw).map_err(|error| error.to_string())?;

    let uuid = percent_decode(url.username());
    if uuid.is_empty() {
        return Err("TUIC ссылка без UUID".to_owned());
    }

    let password = url.password().map(percent_decode).unwrap_or_default();

    let mut proxy = json!({
        "name": name,
        "type": "tuic",
        "server": profile.address,
        "port": profile.port.unwrap_or(443),
        "uuid": uuid,
    });

    if !password.is_empty() {
        proxy["password"] = json!(password);
    }

    if let Some(sni) = query_value(&url, "sni") {
        proxy["sni"] = json!(sni);
    }

    if let Some(alpn) = query_value(&url, "alpn").filter(|value| !value.is_empty()) {
        proxy["alpn"] = json!(
            alpn.split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>()
        );
    }

    if let Some(ip) = query_value(&url, "ip") {
        proxy["ip"] = json!(ip);
    }

    if is_truthy_option(
        query_value(&url, "disable-sni")
            .or_else(|| query_value(&url, "disable_sni"))
            .as_deref(),
    ) {
        proxy["disable-sni"] = json!(true);
    }

    if is_truthy_option(
        query_value(&url, "reduce-rtt")
            .or_else(|| query_value(&url, "reduce_rtt"))
            .as_deref(),
    ) {
        proxy["reduce-rtt"] = json!(true);
    }

    if let Some(timeout) = query_value(&url, "request-timeout")
        .or_else(|| query_value(&url, "request_timeout"))
        .and_then(|v| v.parse::<u32>().ok())
    {
        proxy["request-timeout"] = json!(timeout);
    }

    if let Some(mode) =
        query_value(&url, "udp-relay-mode").or_else(|| query_value(&url, "udp_relay_mode"))
    {
        proxy["udp-relay-mode"] = json!(mode);
    }

    if let Some(cc) = query_value(&url, "congestion-controller")
        .or_else(|| query_value(&url, "congestion_controller"))
    {
        proxy["congestion-controller"] = json!(cc);
    }

    if let Some(size) = query_value(&url, "max-udp-relay-packet-size")
        .or_else(|| query_value(&url, "max_udp_relay_packet_size"))
        .and_then(|v| v.parse::<u32>().ok())
    {
        proxy["max-udp-relay-packet-size"] = json!(size);
    }

    if let Some(hb) = query_value(&url, "heartbeat-interval")
        .or_else(|| query_value(&url, "heartbeat_interval"))
        .and_then(|v| v.parse::<u32>().ok())
    {
        proxy["heartbeat-interval"] = json!(hb);
    }

    if let Some(max_streams) = query_value(&url, "max-open-streams")
        .or_else(|| query_value(&url, "max_open_streams"))
        .and_then(|v| v.parse::<u32>().ok())
    {
        proxy["max-open-streams"] = json!(max_streams);
    }

    if is_truthy_option(
        query_value(&url, "fast-open")
            .or_else(|| query_value(&url, "fast_open"))
            .as_deref(),
    ) {
        proxy["fast-open"] = json!(true);
    }

    if is_truthy_option(query_value(&url, "insecure").as_deref()) {
        proxy["skip-cert-verify"] = json!(true);
    }

    Ok(proxy)
}

fn build_ssh_proxy(profile: &Profile, name: &str) -> Result<Value, String> {
    let url = Url::parse(&profile.raw).map_err(|error| error.to_string())?;
    let username = if url.username().is_empty() {
        required_query(&url, "username", "SSH ссылка без username")?
    } else {
        percent_decode(url.username())
    };
    let mut proxy = json!({
        "name": name,
        "type": "ssh",
        "server": profile.address,
        "port": profile.port.unwrap_or(22),
        "username": username,
    });
    if let Some(password) = url
        .password()
        .map(percent_decode)
        .or_else(|| query_value(&url, "password"))
        && !password.is_empty()
    {
        proxy["password"] = json!(password);
    }
    copy_optional_string(
        &mut proxy,
        &url,
        "private-key",
        &["private-key", "private_key"],
    );
    copy_optional_string(
        &mut proxy,
        &url,
        "private-key-passphrase",
        &["private-key-passphrase", "private_key_passphrase"],
    );
    copy_optional_string_list(&mut proxy, &url, "host-key", &["host-key", "host_key"]);
    copy_optional_string_list(
        &mut proxy,
        &url,
        "host-key-algorithms",
        &["host-key-algorithms", "host_key_algorithms"],
    );
    Ok(proxy)
}

fn build_masque_proxy(profile: &Profile, name: &str) -> Result<Value, String> {
    let url = Url::parse(&profile.raw).map_err(|error| error.to_string())?;
    let private_key = required_query(&url, "private-key", "MASQUE ссылка без private-key")?;
    let public_key = required_query(&url, "public-key", "MASQUE ссылка без public-key")?;
    let mut proxy = json!({
        "name": name,
        "type": "masque",
        "server": profile.address,
        "port": profile.port.unwrap_or(443),
        "private-key": private_key,
        "public-key": public_key,
    });
    copy_optional_string(&mut proxy, &url, "ip", &["ip"]);
    copy_optional_string(&mut proxy, &url, "ipv6", &["ipv6"]);
    copy_optional_u32(&mut proxy, &url, "mtu", &["mtu"]);
    copy_optional_bool(
        &mut proxy,
        &url,
        "remote-dns-resolve",
        &["remote-dns-resolve", "remote_dns_resolve"],
    );
    copy_optional_string_list(&mut proxy, &url, "dns", &["dns"]);
    copy_optional_string(
        &mut proxy,
        &url,
        "congestion-controller",
        &["congestion-controller", "congestion_controller"],
    );
    copy_optional_string(
        &mut proxy,
        &url,
        "bbr-profile",
        &["bbr-profile", "bbr_profile"],
    );
    copy_optional_string(&mut proxy, &url, "network", &["network"]);
    Ok(proxy)
}

fn build_openvpn_proxy(profile: &Profile, name: &str) -> Result<Value, String> {
    let url = Url::parse(&profile.raw).map_err(|error| error.to_string())?;
    let ca = required_query(&url, "ca", "OpenVPN ссылка без ca")?;
    let mut proxy = json!({
        "name": name,
        "type": "openvpn",
        "server": profile.address,
        "port": profile.port.unwrap_or(1194),
        "ca": ca,
    });
    apply_user_password(&mut proxy, &url);
    copy_optional_string(&mut proxy, &url, "proto", &["proto"]);
    copy_optional_string(&mut proxy, &url, "cert", &["cert"]);
    copy_optional_string(&mut proxy, &url, "key", &["key"]);
    copy_optional_string(&mut proxy, &url, "tls-crypt", &["tls-crypt", "tls_crypt"]);
    copy_optional_u32(&mut proxy, &url, "ping", &["ping"]);
    copy_optional_u32(
        &mut proxy,
        &url,
        "ping-restart",
        &["ping-restart", "ping_restart"],
    );
    copy_optional_string(&mut proxy, &url, "dev", &["dev"]);
    copy_optional_string(&mut proxy, &url, "cipher", &["cipher"]);
    copy_optional_string(&mut proxy, &url, "auth", &["auth"]);
    copy_optional_string(&mut proxy, &url, "comp-lzo", &["comp-lzo", "comp_lzo"]);
    copy_optional_u32(&mut proxy, &url, "mtu", &["mtu"]);
    copy_optional_bool(&mut proxy, &url, "udp", &["udp"]);
    copy_optional_bool(
        &mut proxy,
        &url,
        "remote-dns-resolve",
        &["remote-dns-resolve", "remote_dns_resolve"],
    );
    copy_optional_string_list(&mut proxy, &url, "dns", &["dns"]);
    Ok(proxy)
}

fn build_tailscale_proxy(profile: &Profile, name: &str) -> Result<Value, String> {
    let url = Url::parse(&profile.raw).map_err(|error| error.to_string())?;
    let mut proxy = json!({
        "name": name,
        "type": "tailscale",
    });
    let hostname = query_value(&url, "hostname").unwrap_or_else(|| profile.address.clone());
    if !hostname.is_empty() {
        proxy["hostname"] = json!(hostname);
    }
    copy_optional_string(&mut proxy, &url, "auth-key", &["auth-key", "auth_key"]);
    copy_optional_string(
        &mut proxy,
        &url,
        "control-url",
        &["control-url", "control_url"],
    );
    copy_optional_string(&mut proxy, &url, "state-dir", &["state-dir", "state_dir"]);
    copy_optional_bool(&mut proxy, &url, "ephemeral", &["ephemeral"]);
    copy_optional_bool(&mut proxy, &url, "udp", &["udp"]);
    copy_optional_bool(
        &mut proxy,
        &url,
        "accept-routes",
        &["accept-routes", "accept_routes"],
    );
    copy_optional_string(&mut proxy, &url, "exit-node", &["exit-node", "exit_node"]);
    copy_optional_bool(
        &mut proxy,
        &url,
        "exit-node-allow-lan-access",
        &["exit-node-allow-lan-access", "exit_node_allow_lan_access"],
    );
    Ok(proxy)
}

/// Convert a daemon-level route rule into Mihomo rule strings.
///
/// When a rule combines multiple condition types (domains/IPs + ports,
/// or ports + network), they are ANDed together so the rule matches
/// only when ALL conditions are satisfied. When only one condition type
/// is present, separate rules are emitted (current behaviour).
fn rule_to_strings(rule: &XrayRouteRule) -> Vec<String> {
    let target = outbound_tag_to_name(&rule.outbound_tag);
    let mut result = Vec::new();

    let exclude_ports = rule.port_mode.trim().eq_ignore_ascii_case("exclude");
    let network = rule.network.as_deref().and_then(normalize_mihomo_network);

    // Collect DST-PORT conditions (exclude src-port:/in-port: which are
    // emitted as separate rule types).
    let dst_ports: Vec<&String> = rule
        .ports
        .iter()
        .filter(|p| !p.starts_with("src-port:") && !p.starts_with("in-port:"))
        .collect();

    let port_conditions: Vec<String> = if exclude_ports {
        dst_ports
            .iter()
            .map(|p| format!("(NOT,(DST-PORT,{p}))"))
            .collect()
    } else {
        dst_ports
            .iter()
            .map(|p| format!("(DST-PORT,{p})"))
            .collect()
    };

    let net_condition = network.map(|n| format!("(NETWORK,{n})"));

    // Extra conditions = ports + network (anything besides domains/IPs).
    let mut extra_conditions = port_conditions.clone();
    if let Some(ref nc) = net_condition {
        extra_conditions.push(nc.clone());
    }
    let has_extra = !extra_conditions.is_empty();
    let has_domains_or_ips = !rule.domains.is_empty() || !rule.ips.is_empty();

    if has_domains_or_ips && has_extra {
        // AND mode: wrap each domain/IP rule with port/network conditions.
        // Example: AND,((DOMAIN-SUFFIX,example.com),(DST-PORT,443)),proxy
        let extra_joined = extra_conditions.join(",");
        for domain in &rule.domains {
            let dr = domain_rule_body(domain);
            result.push(format!("AND,(({dr}),{extra_joined}),{target}"));
        }
        for ip in &rule.ips {
            let (ir_body, modifier) = ip_rule_body(ip);
            let ir = match modifier {
                Some(m) => format!("{ir_body},{m}"),
                None => ir_body,
            };
            result.push(format!("AND,(({ir}),{extra_joined}),{target}"));
        }
    } else if !has_domains_or_ips && !port_conditions.is_empty() && net_condition.is_some() {
        // Ports + network without domains/IPs: AND them together.
        // Example: AND,((NETWORK,udp),(DST-PORT,443)),REJECT
        let mut conditions: Vec<String> = Vec::new();
        if let Some(ref nc) = net_condition {
            conditions.push(nc.clone());
        }
        conditions.extend(port_conditions.iter().cloned());
        let conditions_joined = conditions.join(",");
        result.push(format!("AND,({conditions_joined}),{target}"));
    } else {
        // Simple mode: emit separate rules for each condition.
        for domain in &rule.domains {
            result.push(domain_rule(domain, &target));
        }
        for ip in &rule.ips {
            result.push(ip_rule(ip, &target));
        }
        for port in &rule.ports {
            if let Some(rest) = port.strip_prefix("src-port:") {
                result.push(format!("SRC-PORT,{rest},{target}"));
            } else if let Some(rest) = port.strip_prefix("in-port:") {
                result.push(format!("IN-PORT,{rest},{target}"));
            } else {
                result.push(format!("DST-PORT,{port},{target}"));
            }
        }
        if let Some(net) = network {
            result.push(format!("NETWORK,{net},{target}"));
        }
    }

    result
}

fn normalize_mihomo_network(network: &str) -> Option<&'static str> {
    match network.trim().to_ascii_lowercase().as_str() {
        "tcp" => Some("tcp"),
        "udp" => Some("udp"),
        _ => None,
    }
}

/// Build a single domain rule string for Mihomo (with target).
///
/// Supported prefixes:
/// - `geosite:xxx` → `GEOSITE,xxx,target`
/// - `=exact` → `DOMAIN,exact,target`
/// - `keyword:xxx` → `DOMAIN-KEYWORD,xxx,target`
/// - `regex:xxx` → `DOMAIN-REGEX,xxx,target`
/// - `wildcard:xxx` → `DOMAIN-WILDCARD,wildcard,target`
/// - bare domain → `DOMAIN-SUFFIX,domain,target`
fn domain_rule(domain: &str, target: &str) -> String {
    format!("{},{}", domain_rule_body(domain), target)
}

/// Build the domain rule body without the target suffix.
/// Used inside AND rules where the target is only at the end.
fn domain_rule_body(domain: &str) -> String {
    if let Some(name) = domain.strip_prefix("geosite:") {
        format!("GEOSITE,{name}")
    } else if let Some(exact) = domain.strip_prefix('=') {
        format!("DOMAIN,{exact}")
    } else if let Some(keyword) = domain.strip_prefix("keyword:") {
        format!("DOMAIN-KEYWORD,{keyword}")
    } else if let Some(regex) = domain.strip_prefix("regex:") {
        format!("DOMAIN-REGEX,{regex}")
    } else if let Some(wildcard) = domain.strip_prefix("wildcard:") {
        format!("DOMAIN-WILDCARD,{wildcard}")
    } else {
        format!("DOMAIN-SUFFIX,{domain}")
    }
}

/// Build a single IP/routing rule string for Mihomo (with target).
///
/// Supported prefixes:
/// - `geoip:CN` → `GEOIP,CN,target`
/// - `geoip:CN,no-resolve` → `GEOIP,CN,target,no-resolve`
/// - `geoip-asn:13335` → `IP-ASN,13335,target`
/// - `ip-asn:13335` → `IP-ASN,13335,target`
/// - `src-geoip:CN` → `SRC-GEOIP,CN,target`
/// - `src-ip-asn:13335` → `SRC-IP-ASN,13335,target`
/// - `ip-suffix:8.8.8.8/24` → `IP-SUFFIX,8.8.8.8/24,target`
/// - `src-ip-cidr:192.168.1.0/24` → `SRC-IP-CIDR,192.168.1.0/24,target`
/// - `src-ip-suffix:192.168.1.0/8` → `SRC-IP-SUFFIX,192.168.1.0/8,target`
/// - bare IP/CIDR → `IP-CIDR,<ip>,<target>`
fn ip_rule(ip: &str, target: &str) -> String {
    let (body, modifier) = ip_rule_body(ip);
    match modifier {
        Some(m) => format!("{body},{target},{m}"),
        None => format!("{body},{target}"),
    }
}

/// Build the IP rule body and optional modifier (without target).
/// Used inside AND rules where the target is only at the end.
/// Returns `(rule_type+value, optional_modifier)`.
fn ip_rule_body(ip: &str) -> (String, Option<String>) {
    if let Some(rest) = ip.strip_prefix("geoip:") {
        if let Some((code, suffix)) = rest.split_once(',') {
            (format!("GEOIP,{code}"), Some(suffix.to_string()))
        } else {
            (format!("GEOIP,{rest}"), None)
        }
    } else if let Some(rest) = ip
        .strip_prefix("geoip-asn:")
        .or_else(|| ip.strip_prefix("ip-asn:"))
    {
        if let Some((asn, suffix)) = rest.split_once(',') {
            (format!("IP-ASN,{asn}"), Some(suffix.to_string()))
        } else {
            (format!("IP-ASN,{rest}"), None)
        }
    } else if let Some(rest) = ip.strip_prefix("src-geoip:") {
        (format!("SRC-GEOIP,{rest}"), None)
    } else if let Some(rest) = ip.strip_prefix("src-ip-asn:") {
        (format!("SRC-IP-ASN,{rest}"), None)
    } else if let Some(rest) = ip.strip_prefix("ip-suffix:") {
        if let Some((code, suffix)) = rest.split_once(',') {
            (format!("IP-SUFFIX,{code}"), Some(suffix.to_string()))
        } else {
            (format!("IP-SUFFIX,{rest}"), None)
        }
    } else if let Some(rest) = ip.strip_prefix("src-ip-cidr:") {
        (format!("SRC-IP-CIDR,{rest}"), None)
    } else if let Some(rest) = ip.strip_prefix("src-ip-suffix:") {
        (format!("SRC-IP-SUFFIX,{rest}"), None)
    } else {
        (format!("IP-CIDR,{ip}"), None)
    }
}

/// Map an Xray outbound tag to a Mihomo proxy name.
fn outbound_tag_to_name(tag: &str) -> String {
    match tag {
        "active" => PROXY_NAME.to_owned(),
        "direct" => DIRECT_NAME.to_owned(),
        "reject" => REJECT_NAME.to_owned(),
        _ => tag.to_owned(),
    }
}

/// Check whether a query parameter value is truthy (1 or true).
fn is_truthy_option(value: Option<&str>) -> bool {
    value.is_some_and(|text| text == "1" || text.eq_ignore_ascii_case("true"))
}

/// Query a URL parameter trying multiple naming conventions
/// (camelCase, snake_case, kebab-case). Returns the first match.
fn query_value_multi(url: &Url, names: &[&str]) -> Option<String> {
    for name in names {
        if let Some(value) = query_value(url, name) {
            return Some(value);
        }
    }
    None
}

fn required_query(url: &Url, name: &str, message: &str) -> Result<String, String> {
    query_value_multi(url, &[name, &name.replace('-', "_")])
        .filter(|value| !value.is_empty())
        .ok_or_else(|| message.to_owned())
}

fn url_password_or_query(url: &Url, query_name: &str) -> String {
    if !url.username().is_empty() {
        percent_decode(url.username())
    } else {
        query_value_multi(url, &[query_name, &query_name.replace('-', "_")]).unwrap_or_default()
    }
}

fn apply_user_password(proxy: &mut Value, url: &Url) {
    if !url.username().is_empty() {
        proxy["username"] = json!(percent_decode(url.username()));
    } else if let Some(username) = query_value(url, "username").filter(|value| !value.is_empty()) {
        proxy["username"] = json!(username);
    }
    if let Some(password) = url
        .password()
        .map(percent_decode)
        .or_else(|| query_value(url, "password"))
        .filter(|value| !value.is_empty())
    {
        proxy["password"] = json!(password);
    }
}

fn apply_tls_common(proxy: &mut Value, url: &Url) {
    if is_truthy_option(query_value(url, "tls").as_deref())
        || matches!(url.scheme(), "mihomo+https" | "https-proxy")
    {
        proxy["tls"] = json!(true);
    }
    copy_optional_string(proxy, url, "sni", &["sni", "servername"]);
    copy_optional_string(proxy, url, "fingerprint", &["fingerprint"]);
    if let Some(fp) = query_value(url, "fp").filter(|value| !value.is_empty()) {
        proxy["client-fingerprint"] = json!(fp);
    }
    if is_truthy_option(
        query_value_multi(url, &["skip-cert-verify", "skip_cert_verify", "insecure"]).as_deref(),
    ) {
        proxy["skip-cert-verify"] = json!(true);
    }
    if let Some(alpn) = query_value(url, "alpn").filter(|value| !value.is_empty()) {
        proxy["alpn"] = json!(split_csv(&alpn));
    }
}

fn copy_optional_string(proxy: &mut Value, url: &Url, field: &str, names: &[&str]) {
    if let Some(value) = query_value_multi(url, names).filter(|value| !value.is_empty()) {
        proxy[field] = json!(value);
    }
}

fn copy_optional_string_list(proxy: &mut Value, url: &Url, field: &str, names: &[&str]) {
    if let Some(value) = query_value_multi(url, names).filter(|value| !value.is_empty()) {
        proxy[field] = json!(split_csv(&value));
    }
}

fn copy_optional_u32(proxy: &mut Value, url: &Url, field: &str, names: &[&str]) {
    if let Some(value) = query_value_multi(url, names).and_then(|value| value.parse::<u32>().ok()) {
        proxy[field] = json!(value);
    }
}

fn copy_optional_bool(proxy: &mut Value, url: &Url, field: &str, names: &[&str]) {
    if let Some(value) = query_value_multi(url, names) {
        proxy[field] = json!(is_truthy_option(Some(&value)));
    }
}

fn copy_optional_bandwidth(proxy: &mut Value, url: &Url, field: &str, names: &[&str]) {
    if let Some(value) = query_value_multi(url, names).filter(|value| !value.is_empty()) {
        let text = if value.chars().all(|ch| ch.is_ascii_digit()) {
            format!("{value} Mbps")
        } else {
            value
        };
        proxy[field] = json!(text);
    }
}

fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// Build ECH options JSON from a share link's `ech` query parameter.
///
/// If `ech` is `1` or `true`, emits `ech-opts.enable: true` with no
/// config (Mihomo resolves via DNS). If `ech` is a base64 string, emits
/// both `enable: true` and `config: <base64>`. Optionally includes
/// `query-server-name` from `echServerName`/`ech_server_name` param.
fn build_ech_opts(url: &Url) -> Option<Value> {
    let ech = query_value(url, "ech")?;
    if ech == "1" || ech.eq_ignore_ascii_case("true") {
        let mut opts = json!({ "enable": true });
        if let Some(qsn) = query_value_multi(
            url,
            &["echServerName", "ech_server_name", "ech-server-name"],
        ) {
            opts["query-server-name"] = json!(qsn);
        }
        return Some(opts);
    }
    // Also check `echConfig` / `ech_config` for explicit base64 config.
    let config = if ech.contains('=') || ech.contains('+') || ech.len() > 20 {
        // Looks like base64 — use it as the config.
        ech
    } else {
        // Check for explicit config param.
        query_value_multi(url, &["echConfig", "ech_config", "ech-config"])?
    };
    let mut opts = json!({ "enable": true, "config": config });
    if let Some(qsn) = query_value_multi(
        url,
        &["echServerName", "ech_server_name", "ech-server-name"],
    ) {
        opts["query-server-name"] = json!(qsn);
    }
    Some(opts)
}

/// Add certificate and private-key (mTLS) fields from URL query parameters.
/// Both must be present to enable mTLS — if only one is set, it is ignored.
fn apply_mtls_cert_key(proxy: &mut Value, url: &Url) {
    let cert = query_value_multi(url, &["certificate", "cert"]);
    let key = query_value_multi(url, &["privateKey", "private_key", "private-key"]);
    if let (Some(cert), Some(key)) = (cert, key) {
        proxy["certificate"] = json!(cert);
        proxy["private-key"] = json!(key);
    }
}

/// Add ws-opts early-data fields from URL query parameters (VLESS/Trojan).
///
/// Parses `maxEarlyData`/`max_early_data` (int), `earlyDataHeaderName`/
/// `early_data_header_name` (string), `v2rayHttpUpgrade`/
/// `v2ray_http_upgrade` (bool), `v2rayHttpUpgradeFastOpen`/
/// `v2ray_http_upgrade_fast_open` (bool).
fn apply_ws_early_data(ws_opts: &mut Value, url: &Url) {
    if let Some(v) = query_value_multi(url, &["maxEarlyData", "max_early_data"])
        .and_then(|s| s.parse::<u32>().ok())
    {
        ws_opts["max-early-data"] = json!(v);
    }
    if let Some(v) = query_value_multi(url, &["earlyDataHeaderName", "early_data_header_name"]) {
        ws_opts["early-data-header-name"] = json!(v);
    }
    if is_truthy_option(
        query_value_multi(url, &["v2rayHttpUpgrade", "v2ray_http_upgrade"]).as_deref(),
    ) {
        ws_opts["v2ray-http-upgrade"] = json!(true);
    }
    if is_truthy_option(
        query_value_multi(
            url,
            &["v2rayHttpUpgradeFastOpen", "v2ray_http_upgrade_fast_open"],
        )
        .as_deref(),
    ) {
        ws_opts["v2ray-http-upgrade-fast-open"] = json!(true);
    }
}

/// Add grpc-opts advanced fields from URL query parameters (VLESS/Trojan).
///
/// Parses `grpcUserAgent`/`grpc_user_agent`, `pingInterval`/
/// `ping_interval` (int), `maxConnections`/`max_connections` (int),
/// `minStreams`/`min_streams` (int), `maxStreams`/`max_streams` (int).
fn apply_grpc_advanced(grpc_opts: &mut Value, url: &Url) {
    if let Some(v) = query_value_multi(url, &["grpcUserAgent", "grpc_user_agent"]) {
        grpc_opts["grpc-user-agent"] = json!(v);
    }
    if let Some(v) = query_value_multi(url, &["pingInterval", "ping_interval"])
        .and_then(|s| s.parse::<u32>().ok())
    {
        grpc_opts["ping-interval"] = json!(v);
    }
    if let Some(v) = query_value_multi(url, &["maxConnections", "max_connections"])
        .and_then(|s| s.parse::<u32>().ok())
    {
        grpc_opts["max-connections"] = json!(v);
    }
    if let Some(v) =
        query_value_multi(url, &["minStreams", "min_streams"]).and_then(|s| s.parse::<u32>().ok())
    {
        grpc_opts["min-streams"] = json!(v);
    }
    if let Some(v) =
        query_value_multi(url, &["maxStreams", "max_streams"]).and_then(|s| s.parse::<u32>().ok())
    {
        grpc_opts["max-streams"] = json!(v);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ExternalControllerConfig, FALLBACK_HEALTH_URL, MihomoFeatures, PAROVOZIK_PROXY_GROUP,
        PROXY_ACTIVE_NAME, PROXY_NAME, PerProxyDefaults, PinnedServerRoute, REDIR_LISTENER,
        TPROXY_LISTENER, TunnelConfig, build_anytls_proxy, build_http_proxy, build_hysteria_proxy,
        build_hysteria2_proxy, build_masque_proxy, build_mihomo_bench_config, build_mihomo_config,
        build_mihomo_router_config, build_openvpn_proxy, build_shadowsocks_proxy,
        build_shadowsocksr_proxy, build_snell_proxy, build_socks_proxy, build_ssh_proxy,
        build_tailscale_proxy, build_trojan_proxy, build_tuic_proxy, build_vless_proxy,
        build_vmess_proxy, build_wireguard_proxy, domain_rule_body, ip_rule_body,
        parse_xhttp_extra, read_xhttp_tuning, update_xhttp_tuning,
    };
    use crate::profiles::parse_profiles;
    use crate::xray_config::{
        DnsSettings, GeoBaseRuleBehavior, GeoBaseRuleProvider, GeoBaseRuleTarget, PortMode,
        QuicMode, RouterExtra, XrayRouteRule,
    };
    use base64::Engine as _;
    use serde_json::{Value, json};
    use url::Url;

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
    fn build_new_outbound_protocols_have_mihomo_types() {
        let cases: Vec<(&str, &str)> = vec![
            (
                "ssr://pass@example.com:443?cipher=chacha20-ietf&obfs=tls1.2_ticket_auth&protocol=auth_sha1_v4#SSR",
                "ssr",
            ),
            (
                "snell://psk@example.com:44046?version=4&obfs=http&obfs-host=bing.com#Snell",
                "snell",
            ),
            (
                "mihomo+https://user:pass@example.com:443?sni=example.com#HTTP",
                "http",
            ),
            ("socks5://user:pass@example.com:1080?udp=1#SOCKS", "socks5"),
            (
                "anytls://secret@example.com:443?sni=example.com#AnyTLS",
                "anytls",
            ),
            (
                "hysteria://secret@example.com:443?upmbps=30&downmbps=200#Hysteria",
                "hysteria",
            ),
            ("ssh://root:pass@example.com:22#SSH", "ssh"),
            (
                "masque://example.com:443?private-key=priv&public-key=pub&ip=172.16.0.2/32#MASQUE",
                "masque",
            ),
            (
                "openvpn://user:pass@example.com:1194?ca=CA#OpenVPN",
                "openvpn",
            ),
            (
                "tailscale://hincyray?auth-key=tskey-auth-example#Tailscale",
                "tailscale",
            ),
        ];

        for (link, expected_type) in cases {
            let profile = parse_profiles(link).pop().expect("profile");
            let proxy = match expected_type {
                "ssr" => build_shadowsocksr_proxy(&profile, PROXY_NAME),
                "snell" => build_snell_proxy(&profile, PROXY_NAME),
                "http" => build_http_proxy(&profile, PROXY_NAME),
                "socks5" => build_socks_proxy(&profile, PROXY_NAME),
                "anytls" => build_anytls_proxy(&profile, PROXY_NAME),
                "hysteria" => build_hysteria_proxy(&profile, PROXY_NAME),
                "ssh" => build_ssh_proxy(&profile, PROXY_NAME),
                "masque" => build_masque_proxy(&profile, PROXY_NAME),
                "openvpn" => build_openvpn_proxy(&profile, PROXY_NAME),
                "tailscale" => build_tailscale_proxy(&profile, PROXY_NAME),
                other => panic!("unexpected type {other}"),
            }
            .expect("proxy");
            assert_eq!(
                proxy.get("type").and_then(Value::as_str),
                Some(expected_type)
            );
        }
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
    fn build_hysteria2_proxy_port_hopping() {
        let profiles =
            parse_profiles("hysteria2://secret@example.com:443?mport=443-8443&hopInterval=30#Test");
        let profile = &profiles[0];
        let proxy = build_hysteria2_proxy(profile, PROXY_NAME).expect("hysteria2 proxy");

        assert_eq!(proxy.get("ports").and_then(Value::as_str), Some("443-8443"));
        assert_eq!(
            proxy.get("hop-interval").and_then(Value::as_str),
            Some("30")
        );
    }

    #[test]
    fn build_hysteria2_proxy_hop_interval_range() {
        let profiles = parse_profiles(
            "hysteria2://secret@example.com:443?ports=443-8443&hop_interval=15-30#Test",
        );
        let profile = &profiles[0];
        let proxy = build_hysteria2_proxy(profile, PROXY_NAME).expect("hysteria2 proxy");

        assert_eq!(proxy.get("ports").and_then(Value::as_str), Some("443-8443"));
        assert_eq!(
            proxy.get("hop-interval").and_then(Value::as_str),
            Some("15-30")
        );
    }

    #[test]
    fn build_mihomo_config_has_socks_port_and_match_rule() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let yaml = build_mihomo_config(profile, "127.0.0.1", 10808, &MihomoFeatures::default())
            .expect("mihomo config");
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
            &[],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &RouterExtra::default(),
            &MihomoFeatures::default(),
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

    fn pinned_route_rule(target: &str) -> XrayRouteRule {
        XrayRouteRule {
            domains: vec!["pinned.example".to_owned()],
            ips: Vec::new(),
            outbound_tag: target.to_owned(),
            block_quic: false,
            ports: Vec::new(),
            network: None,
            port_mode: "include".to_owned(),
        }
    }

    #[test]
    fn pinned_server_route_builds_exact_fallback_group_and_rule_target() {
        let active = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@active.example:443?type=tcp#Active",
        );
        let pinned = parse_profiles(
            "vless://22222222-2222-2222-2222-222222222222@pinned.example:443?type=tcp#Pinned",
        );
        let descriptor = PinnedServerRoute {
            outbound_name: "pinned-out-opaque-7".to_owned(),
            group_name: "pinned-route-opaque-7".to_owned(),
            profile: &pinned[0],
        };
        let yaml = build_mihomo_router_config(
            &active[0],
            &[],
            &[descriptor],
            &[pinned_route_rule("pinned-route-opaque-7")],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Proxy,
            false,
            &RouterExtra::default(),
            &MihomoFeatures::default(),
        )
        .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        let groups = config["proxy-groups"].as_array().expect("groups");
        assert_eq!(groups.len(), 2);
        assert_eq!(
            groups[1],
            json!({
                "name": "pinned-route-opaque-7",
                "type": "fallback",
                "proxies": ["pinned-out-opaque-7", PROXY_ACTIVE_NAME],
                "url": FALLBACK_HEALTH_URL,
                "interval": 10,
                "timeout": 3000,
            })
        );
        let members = groups[1]["proxies"].as_array().expect("members");
        assert!(
            !members
                .iter()
                .any(|name| name == "DIRECT" || name == PROXY_NAME)
        );
        assert!(
            router_rules(&yaml)
                .contains(&"DOMAIN-SUFFIX,pinned.example,pinned-route-opaque-7".to_owned())
        );
    }

    #[test]
    fn pinned_server_routes_stay_out_of_global_proxy_group() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@active.example:443?type=tcp#Active\n\
             vless://22222222-2222-2222-2222-222222222222@candidate.example:443?type=tcp#Candidate\n\
             vless://33333333-3333-3333-3333-333333333333@pinned.example:443?type=tcp#Pinned",
        );
        let descriptor = PinnedServerRoute {
            outbound_name: "pinned-out".to_owned(),
            group_name: "pinned-group".to_owned(),
            profile: &profiles[2],
        };
        let yaml = build_mihomo_router_config(
            &profiles[0],
            &[(&profiles[1], "candidate".to_owned())],
            &[descriptor],
            &[],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Proxy,
            false,
            &RouterExtra::default(),
            &MihomoFeatures::default(),
        )
        .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        let groups = config["proxy-groups"].as_array().expect("groups");
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0]["name"], PROXY_NAME);
        assert_eq!(groups[0]["proxies"], json!([PROXY_ACTIVE_NAME, "DIRECT"]));
        assert_eq!(
            groups[1]["proxies"],
            json!(["pinned-out", PROXY_ACTIVE_NAME])
        );
    }

    #[test]
    fn pinned_server_routes_reject_duplicate_and_reserved_names() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@active.example:443?type=tcp#Active\n\
             vless://22222222-2222-2222-2222-222222222222@pinned.example:443?type=tcp#Pinned",
        );
        let build = |routes: &[PinnedServerRoute<'_>]| {
            build_mihomo_router_config(
                &profiles[0],
                &[],
                routes,
                &[],
                "0.0.0.0",
                10808,
                Some(10810),
                true,
                QuicMode::Proxy,
                false,
                &RouterExtra::default(),
                &MihomoFeatures::default(),
            )
        };
        let duplicates = [
            PinnedServerRoute {
                outbound_name: "same".to_owned(),
                group_name: "group-a".to_owned(),
                profile: &profiles[1],
            },
            PinnedServerRoute {
                outbound_name: "out-b".to_owned(),
                group_name: "same".to_owned(),
                profile: &profiles[1],
            },
        ];
        assert!(
            build(&duplicates)
                .expect_err("duplicate must fail")
                .contains("duplicate")
        );
        let reserved = [PinnedServerRoute {
            outbound_name: PROXY_NAME.to_owned(),
            group_name: "pinned-group".to_owned(),
            profile: &profiles[1],
        }];
        assert!(
            build(&reserved)
                .expect_err("reserved must fail")
                .contains("duplicate")
        );
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
            &[],
            "0.0.0.0",
            10808,
            Some(10810),
            false,
            QuicMode::Block,
            false,
            &RouterExtra::default(),
            &MihomoFeatures::default(),
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
            &[],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &RouterExtra::default(),
            &MihomoFeatures::default(),
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
    fn sniffer_override_destination_default_true() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let yaml = build_mihomo_router_config(
            profile,
            &[],
            &[],
            &[],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &RouterExtra::default(),
            &MihomoFeatures::default(),
        )
        .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        let sniffer = config.get("sniffer").expect("sniffer");
        assert_eq!(
            sniffer.get("override-destination").and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn sniffer_override_destination_false_when_disabled() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let features = MihomoFeatures {
            sniffer_override_destination: false,
            ..MihomoFeatures::default()
        };
        let yaml = build_mihomo_router_config(
            profile,
            &[],
            &[],
            &[],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &RouterExtra::default(),
            &features,
        )
        .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        let sniffer = config.get("sniffer").expect("sniffer");
        assert_eq!(
            sniffer.get("override-destination").and_then(Value::as_bool),
            Some(false)
        );
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
            &[],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &extra,
            &MihomoFeatures::default(),
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
        // fake-ip-filter must be empty to avoid MMDB dependency.
        assert_eq!(
            dns_section.get("fake-ip-filter").and_then(Value::as_array),
            Some(&vec![])
        );
        // No nameserver-policy — it triggers MMDB loading.
        assert!(dns_section.get("nameserver-policy").is_none());
        // geo-auto-update must be false to prevent GitHub download.
        assert_eq!(
            config.get("geo-auto-update").and_then(Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn build_mihomo_router_config_quic_block_adds_reject_rule() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        // v0.16: QUIC block is now a regular routing rule, not auto-generated
        // from quic_mode. System-level QUIC block (TPROXY unavailable) still
        // works via the active_block_quic / tproxy_available parameters.
        let quic_rule = XrayRouteRule {
            domains: vec![],
            ips: vec![],
            outbound_tag: "reject".to_owned(),
            block_quic: false,
            ports: vec!["443".to_owned()],
            network: Some("udp".to_owned()),
            port_mode: "include".to_owned(),
        };
        let yaml = build_mihomo_router_config(
            profile,
            &[],
            &[],
            &[quic_rule],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Proxy,
            false,
            &RouterExtra::default(),
            &MihomoFeatures::default(),
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
                &[],
                "0.0.0.0",
                10808,
                Some(10810),
                true,
                QuicMode::Block,
                false,
                &RouterExtra::default(),
                &MihomoFeatures::default(),
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
            port_mode: "include".to_owned(),
        };
        let yaml = build_mihomo_router_config(
            profile,
            &[],
            &[],
            &[rule],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &RouterExtra::default(),
            &MihomoFeatures::default(),
        )
        .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");

        let rules = config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules");
        let rule_strings: Vec<_> = rules.iter().filter_map(|rule| rule.as_str()).collect();
        // v0.16: when a rule has domains/IPs + ports + network, they are
        // ANDed together: "geosite:cn on port 53 via UDP → DIRECT"
        assert!(rule_strings.contains(&"AND,((GEOSITE,cn),(DST-PORT,53),(NETWORK,udp)),DIRECT"));
        assert!(
            rule_strings
                .contains(&"AND,((IP-CIDR,192.168.0.0/16),(DST-PORT,53),(NETWORK,udp)),DIRECT")
        );
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
            match_target: "direct".to_owned(),
            ..RouterExtra::default()
        };
        let yaml = build_mihomo_router_config(
            profile,
            &[],
            &[],
            &[],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &extra,
            &MihomoFeatures::default(),
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

    // --- Helper for feature tests ---

    fn build_test_router_config(features: &MihomoFeatures) -> Value {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let extra = RouterExtra {
            dns: Some(DnsSettings::default()),
            ..RouterExtra::default()
        };
        let yaml = build_mihomo_router_config(
            profile,
            &[],
            &[],
            &[],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &extra,
            features,
        )
        .expect("router config");
        serde_yaml::from_str(&yaml).expect("parse yaml")
    }

    fn default_features() -> MihomoFeatures {
        MihomoFeatures::default()
    }

    // --- Global features tests ---

    #[test]
    fn global_features_include_geodata_loader_and_unified_delay() {
        let config = build_test_router_config(&default_features());
        assert_eq!(
            config.get("geodata-loader").and_then(Value::as_str),
            Some("memconservative")
        );
        assert_eq!(
            config.get("unified-delay").and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn global_features_include_profile_store_fake_ip_and_selected() {
        let config = build_test_router_config(&default_features());
        let profile = config.get("profile").expect("profile section");
        assert_eq!(
            profile.get("store-fake-ip").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            profile.get("store-selected").and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn global_features_include_keep_alive_settings() {
        let config = build_test_router_config(&default_features());
        assert_eq!(
            config.get("keep-alive-interval").and_then(Value::as_u64),
            Some(30)
        );
        assert_eq!(
            config.get("keep-alive-idle").and_then(Value::as_u64),
            Some(120)
        );
    }

    #[test]
    fn experimental_section_added_when_enabled() {
        let mut features = default_features();
        features.quic_go_disable_gso = true;
        features.quic_go_disable_ecn = true;
        let config = build_test_router_config(&features);
        let exp = config.get("experimental").expect("experimental");
        assert_eq!(
            exp.get("quic-go-disable-gso").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            exp.get("quic-go-disable-ecn").and_then(Value::as_bool),
            Some(true)
        );
    }

    // --- Hosts tests ---

    #[test]
    fn hosts_added_when_configured() {
        let mut features = default_features();
        features
            .hosts
            .insert("example.com".to_owned(), "1.2.3.4".to_owned());
        let config = build_test_router_config(&features);
        let hosts = config.get("hosts").expect("hosts");
        assert_eq!(
            hosts.get("example.com").and_then(Value::as_str),
            Some("1.2.3.4")
        );
    }

    // --- Tunnels tests ---

    #[test]
    fn tunnels_added_when_configured() {
        let mut features = default_features();
        features.tunnels = vec![TunnelConfig {
            network: vec!["tcp".to_owned(), "udp".to_owned()],
            address: "127.0.0.1:6553".to_owned(),
            target: "8.8.8.8:53".to_owned(),
            proxy: Some("proxy".to_owned()),
        }];
        let config = build_test_router_config(&features);
        let tunnels = config
            .get("tunnels")
            .and_then(Value::as_array)
            .expect("tunnels");
        assert_eq!(tunnels.len(), 1);
        let tunnel = &tunnels[0];
        assert_eq!(
            tunnel.get("address").and_then(Value::as_str),
            Some("127.0.0.1:6553")
        );
        assert_eq!(
            tunnel.get("target").and_then(Value::as_str),
            Some("8.8.8.8:53")
        );
        assert_eq!(tunnel.get("proxy").and_then(Value::as_str), Some("proxy"));
    }

    // --- External controller tests ---

    #[test]
    fn external_controller_is_fixed_and_preserves_secret() {
        let mut features = default_features();
        features.external_controller = ExternalControllerConfig {
            secret: Some("test-secret".to_owned()),
        };
        let config = build_test_router_config(&features);
        assert_eq!(
            config.get("external-controller").and_then(Value::as_str),
            Some("127.0.0.1:9090")
        );
        assert_eq!(
            config.get("secret").and_then(Value::as_str),
            Some("test-secret")
        );
    }

    #[test]
    fn external_controller_has_no_cors() {
        let config = build_test_router_config(&default_features());
        assert_eq!(config["external-controller"], "127.0.0.1:9090");
        assert!(config.get("external-controller-cors").is_none());
    }

    // --- DNS enhancement tests ---

    #[test]
    fn dns_includes_cache_algorithm_arc() {
        let config = build_test_router_config(&default_features());
        let dns = config.get("dns").expect("dns");
        assert_eq!(
            dns.get("cache-algorithm").and_then(Value::as_str),
            Some("arc")
        );
    }

    #[test]
    fn dns_uses_local_servers_to_bootstrap_proxy_hostnames_by_default() {
        let config = build_test_router_config(&default_features());
        let dns = config.get("dns").expect("dns");
        assert_eq!(
            dns.get("proxy-server-nameserver")
                .and_then(Value::as_array)
                .expect("proxy-server-nameserver")[0]
                .as_str(),
            Some("223.5.5.5")
        );
    }

    #[test]
    fn dns_uses_local_servers_for_direct_routes_by_default() {
        let config = build_test_router_config(&default_features());
        let dns = config.get("dns").expect("dns");
        assert_eq!(
            dns.get("direct-nameserver")
                .and_then(Value::as_array)
                .expect("direct-nameserver")[0]
                .as_str(),
            Some("223.5.5.5")
        );
    }

    #[test]
    fn dns_includes_prefer_h3_when_enabled() {
        let mut features = default_features();
        features.dns_prefer_h3 = true;
        let config = build_test_router_config(&features);
        let dns = config.get("dns").expect("dns");
        assert_eq!(dns.get("prefer-h3").and_then(Value::as_bool), Some(true));
    }

    #[test]
    fn dns_includes_respect_rules_when_enabled() {
        let mut features = default_features();
        features.dns_respect_rules = true;
        let config = build_test_router_config(&features);
        let dns = config.get("dns").expect("dns");
        assert_eq!(
            dns.get("respect-rules").and_then(Value::as_bool),
            Some(true)
        );
    }

    // --- Sniffer enhancement tests ---

    #[test]
    fn sniffer_includes_force_domain_when_configured() {
        let mut features = default_features();
        features.sniffer_force_domain = vec!["+.v2ex.com".to_owned()];
        let config = build_test_router_config(&features);
        let sniffer = config.get("sniffer").expect("sniffer");
        let fd = sniffer
            .get("force-domain")
            .and_then(Value::as_array)
            .expect("force-domain");
        assert_eq!(fd[0].as_str(), Some("+.v2ex.com"));
    }

    #[test]
    fn sniffer_includes_skip_domain_when_configured() {
        let mut features = default_features();
        features.sniffer_skip_domain = vec!["Mijia Cloud".to_owned()];
        let config = build_test_router_config(&features);
        let sniffer = config.get("sniffer").expect("sniffer");
        let sd = sniffer
            .get("skip-domain")
            .and_then(Value::as_array)
            .expect("skip-domain");
        assert_eq!(sd[0].as_str(), Some("Mijia Cloud"));
    }

    #[test]
    fn sniffer_includes_skip_addresses_when_configured() {
        let mut features = default_features();
        features.sniffer_skip_src_address = vec!["192.168.0.3/32".to_owned()];
        features.sniffer_skip_dst_address = vec!["10.0.0.0/8".to_owned()];
        let config = build_test_router_config(&features);
        let sniffer = config.get("sniffer").expect("sniffer");
        assert!(sniffer.get("skip-src-address").is_some());
        assert!(sniffer.get("skip-dst-address").is_some());
    }

    // --- Per-proxy field tests ---

    #[test]
    fn per_proxy_udp_added_by_default() {
        let config = build_test_router_config(&default_features());
        let proxies = config
            .get("proxies")
            .and_then(Value::as_array)
            .expect("proxies");
        assert_eq!(proxies[0].get("udp").and_then(Value::as_bool), Some(true));
    }

    #[test]
    fn per_proxy_tfo_added_when_enabled() {
        let mut features = default_features();
        features.per_proxy.tfo = true;
        let config = build_test_router_config(&features);
        let proxies = config
            .get("proxies")
            .and_then(Value::as_array)
            .expect("proxies");
        assert_eq!(proxies[0].get("tfo").and_then(Value::as_bool), Some(true));
    }

    #[test]
    fn per_proxy_ip_version_added_when_not_dual() {
        let mut features = default_features();
        features.per_proxy.ip_version = "ipv4-prefer".to_owned();
        let config = build_test_router_config(&features);
        let proxies = config
            .get("proxies")
            .and_then(Value::as_array)
            .expect("proxies");
        assert_eq!(
            proxies[0].get("ip-version").and_then(Value::as_str),
            Some("ipv4-prefer")
        );
    }

    #[test]
    fn proxy_group_disabled_uses_single_proxy_name() {
        let config = build_test_router_config(&default_features());
        // When proxy groups disabled, active proxy outbound is named
        // "proxy-active" and a direct-fallback group named "proxy" wraps
        // it with DIRECT as last resort.
        let proxies = config
            .get("proxies")
            .and_then(Value::as_array)
            .expect("proxies");
        assert_eq!(
            proxies[0].get("name").and_then(Value::as_str),
            Some("proxy-active")
        );
        // Direct-fallback proxy group is always present
        let groups = config
            .get("proxy-groups")
            .and_then(Value::as_array)
            .expect("proxy-groups");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].get("name").and_then(Value::as_str), Some("proxy"));
        assert_eq!(
            groups[0].get("type").and_then(Value::as_str),
            Some("fallback")
        );
        let group_proxies = groups[0]
            .get("proxies")
            .and_then(Value::as_array)
            .expect("group proxies");
        assert_eq!(group_proxies.len(), 2);
        assert_eq!(group_proxies[0].as_str(), Some("proxy-active"));
        assert_eq!(group_proxies[1].as_str(), Some("DIRECT"));
    }

    // --- Domain rule prefix tests ---

    #[test]
    fn domain_rule_regex_prefix_generates_domain_regex() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let rule = XrayRouteRule {
            domains: vec!["regex:^abc.*com".to_owned()],
            ips: vec![],
            outbound_tag: "direct".to_owned(),
            block_quic: false,
            ports: vec![],
            network: None,
            port_mode: "include".to_owned(),
        };
        let yaml = build_mihomo_router_config(
            profile,
            &[],
            &[],
            &[rule],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &RouterExtra::default(),
            &MihomoFeatures::default(),
        )
        .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        let rules = config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules");
        assert!(
            rules
                .iter()
                .any(|r| r.as_str() == Some("DOMAIN-REGEX,^abc.*com,DIRECT"))
        );
    }

    #[test]
    fn domain_rule_wildcard_prefix_generates_domain_wildcard() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let rule = XrayRouteRule {
            domains: vec!["wildcard:*.google.com".to_owned()],
            ips: vec![],
            outbound_tag: "active".to_owned(),
            block_quic: false,
            ports: vec![],
            network: None,
            port_mode: "include".to_owned(),
        };
        let yaml = build_mihomo_router_config(
            profile,
            &[],
            &[],
            &[rule],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &RouterExtra::default(),
            &MihomoFeatures::default(),
        )
        .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        let rules = config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules");
        assert!(
            rules
                .iter()
                .any(|r| r.as_str() == Some("DOMAIN-WILDCARD,*.google.com,proxy"))
        );
    }

    // --- MihomoFeatures serde round-trip test ---

    #[test]
    fn mihomo_features_serde_round_trip() {
        let features = MihomoFeatures {
            unified_delay: false,
            store_selected: false,
            keep_alive_interval: 60,
            keep_alive_idle: 240,
            disable_keep_alive: true,
            tcp_concurrent: true,
            quic_go_disable_gso: true,
            quic_go_disable_ecn: false,
            hosts: {
                let mut h = std::collections::HashMap::new();
                h.insert("local.test".to_owned(), "127.0.0.1".to_owned());
                h
            },
            tunnels: vec![TunnelConfig {
                network: vec!["tcp".to_owned()],
                address: "127.0.0.1:1234".to_owned(),
                target: "example.com:443".to_owned(),
                proxy: None,
            }],
            external_controller: ExternalControllerConfig {
                secret: Some("secret123".to_owned()),
            },
            per_proxy: PerProxyDefaults {
                tfo: true,
                mptcp: false,
                ip_version: "ipv4".to_owned(),
            },
            dns_prefer_h3: true,
            dns_respect_rules: true,
            dns_nameserver_policy: {
                let mut p = std::collections::HashMap::new();
                p.insert(
                    "+.google.com".to_owned(),
                    vec!["https://dns.google/dns-query".to_owned()],
                );
                p
            },
            sniffer_force_domain: vec!["+.test.com".to_owned()],
            sniffer_skip_domain: vec!["skip.test".to_owned()],
            sniffer_skip_src_address: vec!["192.168.1.0/24".to_owned()],
            sniffer_skip_dst_address: vec!["10.0.0.0/8".to_owned()],
            ..MihomoFeatures::default()
        };
        let json = serde_json::to_string(&features).expect("serialize");
        let deserialized: MihomoFeatures = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(features, deserialized);
    }

    #[test]
    fn mihomo_features_default_serde_uses_defaults() {
        // Empty JSON should produce default MihomoFeatures
        let json = "{}";
        let features: MihomoFeatures = serde_json::from_str(json).expect("deserialize empty");
        assert!(features.unified_delay);
        assert!(features.store_selected);
        assert_eq!(features.keep_alive_interval, 30);
        assert_eq!(features.keep_alive_idle, 120);
        assert_eq!(features.per_proxy.ip_version, "dual");
    }

    #[test]
    fn legacy_removed_fields_are_ignored_and_not_projected() {
        let legacy = json!({
            "relay": {"enabled": true},
            "ntp": {"enabled": true, "server": "time.example"},
            "authentication": ["user:secret"],
            "skip_auth_prefixes": ["0.0.0.0/0"],
            "proxy_group": {"enabled": true, "group_type": "relay"},
            "proxy_providers": [{"name": "remote", "url": "https://provider.example/sub/token"}],
            "rule_providers": [{"name": "rules", "url": "https://provider.example/rules"}],
            "sub_rules": [{"name": "legacy", "rules": ["MATCH,DIRECT"]}],
            "raw_rules": ["DOMAIN,legacy.example,DIRECT"],
            "typed_rules": [{"rule_type": "DOMAIN", "value": "typed.example", "target": "DIRECT"}],
            "dns_ecs": "1.2.3.0/24",
            "dns_disable_ipv4": true,
            "dns_disable_qtypes": [65],
            "dns_fallback_filter": {"geoip": true},
            "per_proxy": {"udp": false, "smux": {"enabled": true}, "dialer_proxy": "legacy"},
            "external_controller": {
                "enabled": false,
                "address": "0.0.0.0:9999",
                "secret": "preserved-secret",
                "allow_origins": ["*"],
                "allow_private_network": true
            }
        });
        let features: MihomoFeatures = serde_json::from_value(legacy).expect("legacy state");
        assert_eq!(
            features.external_controller.secret.as_deref(),
            Some("preserved-secret")
        );
        let config = build_test_router_config(&features);
        for key in [
            "ntp",
            "authentication",
            "skip-auth-prefixes",
            "proxy-providers",
            "sub-rules",
            "external-controller-cors",
        ] {
            assert!(
                config.get(key).is_none(),
                "unexpected legacy projection {key}"
            );
        }
        assert_eq!(config["external-controller"], "127.0.0.1:9090");
        assert_eq!(config["profile"]["store-fake-ip"], true);
        assert_eq!(config["proxies"][0]["udp"], true);
        let rules = config["rules"].as_array().expect("rules");
        assert!(!rules.iter().any(|rule| {
            rule.as_str().is_some_and(|rule| {
                rule.contains("legacy.example") || rule.contains("typed.example")
            })
        }));
        let dns = &config["dns"];
        assert!(dns.get("ecs").is_none());
        assert!(dns.get("disable-ipv4").is_none());
        assert!(dns.get("disable-qtype-65").is_none());
        assert!(dns.get("fallback-filter").is_none());
    }

    // --- Simple config (build_mihomo_config) feature tests ---

    #[test]
    fn simple_config_includes_global_features() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let features = default_features();
        let yaml =
            build_mihomo_config(profile, "127.0.0.1", 10808, &features).expect("mihomo config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        assert_eq!(
            config.get("geodata-loader").and_then(Value::as_str),
            Some("memconservative")
        );
        assert_eq!(
            config.get("unified-delay").and_then(Value::as_bool),
            Some(true)
        );
        // Per-proxy udp should be applied
        let proxies = config
            .get("proxies")
            .and_then(Value::as_array)
            .expect("proxies");
        assert_eq!(proxies[0].get("udp").and_then(Value::as_bool), Some(true));
    }

    #[test]
    fn simple_config_includes_external_controller_when_enabled() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let features = default_features();
        let yaml =
            build_mihomo_config(profile, "127.0.0.1", 10808, &features).expect("mihomo config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        assert!(config.get("external-controller").is_some());
    }

    // ── Tier 1: tcp-concurrent global feature ──────────────────────

    #[test]
    fn tcp_concurrent_emitted_when_enabled() {
        let mut features = default_features();
        features.tcp_concurrent = true;
        let config = build_test_router_config(&features);
        assert_eq!(
            config.get("tcp-concurrent").and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn tcp_concurrent_absent_when_disabled() {
        let config = build_test_router_config(&default_features());
        assert!(config.get("tcp-concurrent").is_none());
    }

    // ── WireGuard proxy tests ───────────────────────────────────────

    #[test]
    fn build_wireguard_proxy_has_correct_fields() {
        let profiles = parse_profiles(
            "wireguard://eCtXsJZ27%2B4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU%3D@162.159.192.1:2480?address=172.16.0.2&publickey=Cr8hWlKvtDt7nrvf%2Bf0brNQQzabAqrjfBvas9pmowjo%3D&mtu=1280#WARP",
        );
        let profile = &profiles[0];
        let proxy = build_wireguard_proxy(profile, PROXY_NAME).expect("wg proxy");

        assert_eq!(proxy.get("type").and_then(Value::as_str), Some("wireguard"));
        assert_eq!(
            proxy.get("server").and_then(Value::as_str),
            Some("162.159.192.1")
        );
        assert_eq!(proxy.get("port").and_then(Value::as_u64), Some(2480));
        assert_eq!(proxy.get("ip").and_then(Value::as_str), Some("172.16.0.2"));
        assert_eq!(
            proxy.get("private-key").and_then(Value::as_str),
            Some("eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=")
        );
        assert_eq!(
            proxy.get("public-key").and_then(Value::as_str),
            Some("Cr8hWlKvtDt7nrvf+f0brNQQzabAqrjfBvas9pmowjo=")
        );
        assert_eq!(proxy.get("mtu").and_then(Value::as_u64), Some(1280));
        assert_eq!(proxy.get("udp").and_then(Value::as_bool), Some(true));
    }

    #[test]
    fn build_wireguard_proxy_with_ipv6_and_reserved() {
        let profiles = parse_profiles(
            "wireguard://eCtXsJZ27%2B4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU%3D@162.159.192.1:2480?address=172.16.0.2,fd01:5ca1:ab1e::1&publickey=Cr8hWlKvtDt7nrvf%2Bf0brNQQzabAqrjfBvas9pmowjo%3D&reserved=209,98,59&presharedkey=31aIhAPwktDGpH4JDhA8GNvjFXEf%2Fa6%2BUaQRyOAiyfM%3D#WARP",
        );
        let profile = &profiles[0];
        let proxy = build_wireguard_proxy(profile, PROXY_NAME).expect("wg proxy");

        assert_eq!(proxy.get("ip").and_then(Value::as_str), Some("172.16.0.2"));
        assert_eq!(
            proxy.get("ipv6").and_then(Value::as_str),
            Some("fd01:5ca1:ab1e::1")
        );
        let reserved = proxy
            .get("reserved")
            .and_then(Value::as_array)
            .expect("reserved");
        assert_eq!(reserved.len(), 3);
        assert_eq!(reserved[0].as_u64(), Some(209));
        assert_eq!(reserved[1].as_u64(), Some(98));
        assert_eq!(reserved[2].as_u64(), Some(59));
        assert!(proxy.get("pre-shared-key").is_some());
    }

    #[test]
    fn build_wireguard_proxy_strips_cidr_from_address() {
        let profiles = parse_profiles(
            "wireguard://eCtXsJZ27%2B4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU%3D@162.159.192.1:2480?address=172.16.0.2/32&publickey=Cr8hWlKvtDt7nrvf%2Bf0brNQQzabAqrjfBvas9pmowjo%3D#WARP",
        );
        let profile = &profiles[0];
        let proxy = build_wireguard_proxy(profile, PROXY_NAME).expect("wg proxy");
        assert_eq!(proxy.get("ip").and_then(Value::as_str), Some("172.16.0.2"));
    }

    #[test]
    fn build_wireguard_proxy_uses_privatekey_param() {
        let profiles = parse_profiles(
            "wg://162.159.192.1:2480?privatekey=eCtXsJZ27%2B4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU%3D&address=172.16.0.2&publickey=Cr8hWlKvtDt7nrvf%2Bf0brNQQzabAqrjfBvas9pmowjo%3D#WARP",
        );
        let profile = &profiles[0];
        let proxy = build_wireguard_proxy(profile, PROXY_NAME).expect("wg proxy");
        assert_eq!(
            proxy.get("private-key").and_then(Value::as_str),
            Some("eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=")
        );
    }

    // ── TUIC proxy tests ────────────────────────────────────────────

    #[test]
    fn build_tuic_proxy_has_correct_fields() {
        let profiles = parse_profiles(
            "tuic://00000000-0000-0000-0000-000000000001:secretpass@example.com:443?sni=example.com&alpn=h3&congestion_controller=bbr&udp_relay_mode=native#TUIC",
        );
        let profile = &profiles[0];
        let proxy = build_tuic_proxy(profile, PROXY_NAME).expect("tuic proxy");

        assert_eq!(proxy.get("type").and_then(Value::as_str), Some("tuic"));
        assert_eq!(
            proxy.get("server").and_then(Value::as_str),
            Some("example.com")
        );
        assert_eq!(proxy.get("port").and_then(Value::as_u64), Some(443));
        assert_eq!(
            proxy.get("uuid").and_then(Value::as_str),
            Some("00000000-0000-0000-0000-000000000001")
        );
        assert_eq!(
            proxy.get("password").and_then(Value::as_str),
            Some("secretpass")
        );
        assert_eq!(
            proxy.get("sni").and_then(Value::as_str),
            Some("example.com")
        );
        assert_eq!(
            proxy.get("congestion-controller").and_then(Value::as_str),
            Some("bbr")
        );
        assert_eq!(
            proxy.get("udp-relay-mode").and_then(Value::as_str),
            Some("native")
        );
    }

    #[test]
    fn build_tuic_proxy_with_alpn_list() {
        let profiles = parse_profiles(
            "tuic://uuid:pass@example.com:443?alpn=h3,h2,http/1.1&sni=example.com#TUIC",
        );
        let profile = &profiles[0];
        let proxy = build_tuic_proxy(profile, PROXY_NAME).expect("tuic proxy");
        let alpn = proxy.get("alpn").and_then(Value::as_array).expect("alpn");
        assert_eq!(alpn.len(), 3);
        assert_eq!(alpn[0].as_str(), Some("h3"));
    }

    #[test]
    fn build_tuic_proxy_with_disable_sni_and_reduce_rtt() {
        let profiles = parse_profiles(
            "tuic://uuid:pass@example.com:443?disable_sni=1&reduce_rtt=true&sni=example.com#TUIC",
        );
        let profile = &profiles[0];
        let proxy = build_tuic_proxy(profile, PROXY_NAME).expect("tuic proxy");
        assert_eq!(
            proxy.get("disable-sni").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(proxy.get("reduce-rtt").and_then(Value::as_bool), Some(true));
    }

    #[test]
    fn build_tuic_proxy_without_password() {
        let profiles = parse_profiles(
            "tuic://00000000-0000-0000-0000-000000000001@example.com:443?sni=example.com#TUIC",
        );
        let profile = &profiles[0];
        let proxy = build_tuic_proxy(profile, PROXY_NAME).expect("tuic proxy");
        assert!(proxy.get("password").is_none());
    }

    // ── ECH tests ───────────────────────────────────────────────────

    #[test]
    fn build_vless_proxy_with_ech_enable_only() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&sni=example.com&ech=1#ECH",
        );
        let profile = &profiles[0];
        let proxy = build_vless_proxy(profile, PROXY_NAME).expect("vless proxy");
        let ech_opts = proxy.get("ech-opts").expect("ech-opts");
        assert_eq!(ech_opts.get("enable").and_then(Value::as_bool), Some(true));
        assert!(ech_opts.get("config").is_none());
    }

    #[test]
    fn build_vless_proxy_with_ech_config() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&sni=example.com&ech=AEn%2BDQBFKwAgACABWIHUGj4u%2BPIggYXcR5JF0gYk3dCRioBW8uJq9H4mKAAIAAEAAQABAANAEnB1YmxpYy50bHMtZWNoLmRldgAA#ECH",
        );
        let profile = &profiles[0];
        let proxy = build_vless_proxy(profile, PROXY_NAME).expect("vless proxy");
        let ech_opts = proxy.get("ech-opts").expect("ech-opts");
        assert_eq!(ech_opts.get("enable").and_then(Value::as_bool), Some(true));
        assert!(ech_opts.get("config").is_some());
    }

    #[test]
    fn build_trojan_proxy_with_ech() {
        let profiles = parse_profiles(
            "trojan://secretpass@example.com:443?security=tls&sni=example.com&ech=1#ECH",
        );
        let profile = &profiles[0];
        let proxy = build_trojan_proxy(profile, PROXY_NAME).expect("trojan proxy");
        let ech_opts = proxy.get("ech-opts").expect("ech-opts");
        assert_eq!(ech_opts.get("enable").and_then(Value::as_bool), Some(true));
    }

    #[test]
    fn build_vless_proxy_without_ech_when_not_specified() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&sni=example.com#NoECH",
        );
        let profile = &profiles[0];
        let proxy = build_vless_proxy(profile, PROXY_NAME).expect("vless proxy");
        assert!(proxy.get("ech-opts").is_none());
    }

    // ── xhttp advanced tests ────────────────────────────────────────

    #[test]
    fn build_vless_xhttp_with_no_grpc_header() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=xhttp&security=reality&pbk=pubkey&noGRPCHeader=1#Test",
        );
        let profile = &profiles[0];
        let proxy = build_vless_proxy(profile, PROXY_NAME).expect("vless proxy");
        let xhttp_opts = proxy.get("xhttp-opts").expect("xhttp-opts");
        assert_eq!(
            xhttp_opts.get("no-grpc-header").and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn build_vless_xhttp_with_padding_fields() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=xhttp&security=reality&pbk=pubkey&xPaddingBytes=100-1000&xPaddingObfsMode=true#Test",
        );
        let profile = &profiles[0];
        let proxy = build_vless_proxy(profile, PROXY_NAME).expect("vless proxy");
        let xhttp_opts = proxy.get("xhttp-opts").expect("xhttp-opts");
        assert_eq!(
            xhttp_opts.get("x-padding-bytes").and_then(Value::as_str),
            Some("100-1000")
        );
        assert_eq!(
            xhttp_opts
                .get("x-padding-obfs-mode")
                .and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn build_vless_xhttp_maps_happ_extra_with_mihomo_types() {
        let extra = json!({
            "xPaddingBytes": "100-1000",
            "xPaddingObfsMode": true,
            "xPaddingKey": "padding_key",
            "xPaddingHeader": "X-Cache",
            "xPaddingPlacement": "queryInHeader",
            "xPaddingMethod": "tokenish",
            "uplinkHTTPMethod": "PUT",
            "sessionPlacement": "header",
            "sessionKey": "X-Session",
            "seqPlacement": "query",
            "seqKey": "seq",
            "uplinkDataPlacement": "cookie",
            "uplinkDataKey": "chunk",
            "uplinkChunkSize": "3072-4096",
            "scMaxEachPostBytes": 1000000,
            "scMinPostsIntervalMs": "20-40",
            "noGRPCHeader": "true",
            "xmux": {
                "maxConcurrency": "16-32",
                "maxConnections": 4,
                "cMaxReuseTimes": "64-128",
                "hMaxRequestTimes": "800-900",
                "hMaxReusableSecs": "900-1800",
                "hKeepAlivePeriod": -1
            }
        });
        let mut url = url::Url::parse(
            "vless://11111111-1111-1111-1111-111111111111@provider.example:443?type=xhttp&security=reality&pbk=public-key#Test",
        )
        .expect("base URL");
        url.query_pairs_mut()
            .append_pair("extra", &extra.to_string());
        let profiles = parse_profiles(url.as_str());
        let proxy = build_vless_proxy(&profiles[0], PROXY_NAME).expect("vless proxy");
        let xhttp = proxy.get("xhttp-opts").expect("xhttp-opts");

        assert_eq!(
            xhttp,
            &json!({
                "no-grpc-header": true,
                "x-padding-bytes": "100-1000",
                "x-padding-obfs-mode": true,
                "x-padding-key": "padding_key",
                "x-padding-header": "X-Cache",
                "x-padding-placement": "queryInHeader",
                "x-padding-method": "tokenish",
                "uplink-http-method": "PUT",
                "session-placement": "header",
                "session-key": "X-Session",
                "seq-placement": "query",
                "seq-key": "seq",
                "uplink-data-placement": "cookie",
                "uplink-data-key": "chunk",
                "uplink-chunk-size": "3072-4096",
                "sc-max-each-post-bytes": "1000000",
                "sc-min-posts-interval-ms": "20-40",
                "reuse-settings": {
                    "max-concurrency": "16-32",
                    "max-connections": "4",
                    "c-max-reuse-times": "64-128",
                    "h-max-request-times": "800-900",
                    "h-max-reusable-secs": "900-1800",
                    "h-keep-alive-period": -1
                }
            })
        );

        let yaml =
            build_mihomo_bench_config(&profiles[0], "127.0.0.1", 20808).expect("generated config");
        let config: Value = serde_yaml::from_str(&yaml).expect("structural YAML");
        assert_eq!(config["proxies"][0]["xhttp-opts"], *xhttp);
    }

    #[test]
    fn build_vless_xhttp_defaults_chunk_size_for_header_uplink() {
        let extra = json!({
            "uplinkHTTPMethod": "GET",
            "uplinkDataPlacement": "header",
            "uplinkDataKey": "X-Data",
            "scMaxEachPostBytes": "2048-2048"
        });
        let mut url = url::Url::parse(
            "vless://11111111-1111-1111-1111-111111111111@provider.example:443?type=xhttp&mode=packet-up#Test",
        )
        .expect("base URL");
        url.query_pairs_mut()
            .append_pair("extra", &extra.to_string());
        let profile = parse_profiles(url.as_str()).pop().expect("profile");
        let proxy = build_vless_proxy(&profile, PROXY_NAME).expect("xhttp proxy");
        assert_eq!(proxy["xhttp-opts"]["uplink-chunk-size"], "3000-4000");
    }

    #[test]
    fn build_vless_xhttp_top_level_values_override_extra() {
        let extra = json!({
            "xPaddingBytes": "100-200",
            "xPaddingObfsMode": false,
            "headers": { "X-Origin": "extra" },
            "sessionIDPlacement": "cookie",
            "xmux": { "maxConcurrency": "16-32" }
        });
        let mut url = url::Url::parse(
            "vless://11111111-1111-1111-1111-111111111111@provider.example:443?type=xhttp&xPaddingBytes=300-400&xPaddingObfsMode=on&headers=%7B%22X-Origin%22%3A%22top-level%22%7D&sessionIDPlacement=header&xmuxMaxConcurrency=8-12#Test",
        )
        .expect("base URL");
        url.query_pairs_mut()
            .append_pair("extra", &extra.to_string());
        let profiles = parse_profiles(url.as_str());
        let proxy = build_vless_proxy(&profiles[0], PROXY_NAME).expect("vless proxy");
        let xhttp = proxy.get("xhttp-opts").expect("xhttp-opts");

        assert_eq!(xhttp["x-padding-bytes"], "300-400");
        assert_eq!(xhttp["x-padding-obfs-mode"], true);
        assert_eq!(xhttp["headers"], json!({"X-Origin": "top-level"}));
        assert_eq!(xhttp["session-placement"], "header");
        assert_eq!(xhttp["reuse-settings"]["max-concurrency"], "8-12");
    }

    #[test]
    fn build_vless_xhttp_consumes_current_official_extra_shape() {
        let extra = json!({
            "headers": {
                "X-Trace": "diagnostic-value",
                "User-Agent": "fixture-agent"
            },
            "xPaddingBytes": "100-1000",
            "xPaddingObfsMode": true,
            "xPaddingKey": "padding-name",
            "xPaddingHeader": "Referer",
            "xPaddingPlacement": "queryInHeader",
            "xPaddingMethod": "tokenish",
            "sessionIDPlacement": "header",
            "sessionIDKey": "X-Session",
            "sessionIDTable": "Base62",
            "sessionIDLength": "16-32",
            "uplinkChunkSize": 0,
            "scMaxEachPostBytes": 1000000,
            "scMinPostsIntervalMs": 30,
            "downloadSettings": {}
        });
        let mut url = url::Url::parse(
            "vless://11111111-1111-1111-1111-111111111111@provider.example:443?type=xhttp#Test",
        )
        .expect("base URL");
        url.query_pairs_mut()
            .append_pair("extra", &extra.to_string());
        let profile = parse_profiles(url.as_str()).pop().expect("profile");
        let proxy = build_vless_proxy(&profile, PROXY_NAME).expect("supported official shape");
        let xhttp = proxy["xhttp-opts"].as_object().expect("xhttp opts");

        assert_eq!(
            xhttp.len(),
            14,
            "every supplied nonempty key must be mapped"
        );
        assert_eq!(xhttp["headers"]["X-Trace"], "diagnostic-value");
        assert_eq!(xhttp["session-placement"], "header");
        assert_eq!(xhttp["session-key"], "X-Session");
        assert_eq!(xhttp["session-table"], "Base62");
        assert_eq!(xhttp["session-length"], "16-32");
        assert_eq!(xhttp["uplink-chunk-size"], "0");
    }

    #[test]
    fn build_vless_xhttp_preserves_legacy_session_aliases() {
        let extra = json!({
            "sessionPlacement": "cookie",
            "sessionKey": "sid",
            "sessionTable": "hex",
            "sessionLength": 24
        });
        let mut url = url::Url::parse(
            "vless://11111111-1111-1111-1111-111111111111@provider.example:443?type=xhttp#Test",
        )
        .expect("base URL");
        url.query_pairs_mut()
            .append_pair("extra", &extra.to_string());
        let profile = parse_profiles(url.as_str()).pop().expect("profile");
        let proxy = build_vless_proxy(&profile, PROXY_NAME).expect("legacy aliases");
        assert_eq!(
            proxy["xhttp-opts"],
            json!({
                "session-placement": "cookie",
                "session-key": "sid",
                "session-table": "hex",
                "session-length": "24"
            })
        );
    }

    #[test]
    fn build_vless_xhttp_validates_headers_sessions_and_positive_bounds() {
        for (field, value) in [
            ("headers", json!({"Bad Header": "value"})),
            ("headers", json!({"X-Test": 7})),
            ("sessionIDPlacement", json!("body")),
            ("sessionIDLength", json!(0)),
            ("sessionIDLength", json!(4097)),
            ("uplinkChunkSize", json!(63)),
            ("scMaxEachPostBytes", json!(0)),
            ("scMinPostsIntervalMs", json!(0)),
        ] {
            let mut url = url::Url::parse(
                "vless://11111111-1111-1111-1111-111111111111@provider.example:443?type=xhttp#Test",
            )
            .expect("base URL");
            url.query_pairs_mut()
                .append_pair("extra", &json!({field: value}).to_string());
            let profile = parse_profiles(url.as_str()).pop().expect("profile");
            let error = build_vless_proxy(&profile, PROXY_NAME).expect_err("invalid field");
            assert!(error.contains(field), "{field}: {error}");
            assert!(
                !error.contains("custom-secret-table"),
                "value leaked: {error}"
            );
        }
    }

    #[test]
    fn xhttp_tuning_update_preserves_unknown_extra_and_supports_removal() {
        let raw = "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=xhttp&extra=%7B%22xPaddingBytes%22%3A%22100-200%22%2C%22scMaxEachPostBytes%22%3A%222048-2048%22%7D#Demo";
        let updated =
            update_xhttp_tuning(raw, Some("4096-4096"), Some("15-15")).expect("update tuning");
        let tuning = read_xhttp_tuning(&updated)
            .expect("read tuning")
            .expect("XHTTP profile");
        assert_eq!(tuning, (Some("4096".to_owned()), Some("15".to_owned())));
        let extra =
            parse_xhttp_extra(&Url::parse(&updated).expect("updated URL")).expect("extra JSON");
        assert_eq!(extra["xPaddingBytes"], "100-200");
        assert_eq!(extra["scMaxEachPostBytes"], "4096");
        assert_eq!(extra["scMinPostsIntervalMs"], "15");

        let defaults = update_xhttp_tuning(&updated, None, None).expect("remove tuning");
        assert_eq!(
            read_xhttp_tuning(&defaults).expect("read defaults"),
            Some((None, None))
        );
        let remaining = parse_xhttp_extra(&Url::parse(&defaults).expect("defaults URL"))
            .expect("remaining extra");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining["xPaddingBytes"], "100-200");
    }

    #[test]
    fn xhttp_tuning_rejects_wrong_transport_and_invalid_ranges() {
        let ws = "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=ws#Demo";
        assert!(update_xhttp_tuning(ws, Some("4096"), None).is_err());
        let xhttp = "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=xhttp#Demo";
        assert!(update_xhttp_tuning(xhttp, Some("4096-2048"), None).is_err());
        assert!(update_xhttp_tuning(xhttp, None, Some("0")).is_err());
    }

    #[test]
    fn build_vless_xhttp_accepts_custom_session_table() {
        let mut url = url::Url::parse(
            "vless://11111111-1111-1111-1111-111111111111@provider.example:443?type=xhttp#Test",
        )
        .expect("base URL");
        url.query_pairs_mut().append_pair(
            "extra",
            &json!({"sessionIDTable":"abcXYZ09-_","sessionIDLength":16}).to_string(),
        );
        let profile = parse_profiles(url.as_str()).pop().expect("profile");
        let proxy = build_vless_proxy(&profile, PROXY_NAME).expect("custom session table");
        assert_eq!(proxy["xhttp-opts"]["session-table"], "abcXYZ09-_");
        assert_eq!(proxy["xhttp-opts"]["session-length"], "16");
    }

    #[test]
    fn build_vless_xhttp_rejects_too_small_session_id_space() {
        let extra = json!({
            "sessionIDTable": "number",
            "sessionIDLength": 3
        });
        let mut url = url::Url::parse(
            "vless://11111111-1111-1111-1111-111111111111@provider.example:443?type=xhttp#Test",
        )
        .expect("base URL");
        url.query_pairs_mut()
            .append_pair("extra", &extra.to_string());
        let profile = parse_profiles(url.as_str()).pop().expect("profile");
        let error = build_vless_proxy(&profile, PROXY_NAME).expect_err("small session space");

        assert!(error.contains("sessionIDTable/sessionIDLength"));
        assert!(error.contains("2^31"));
    }

    #[test]
    fn build_vless_xhttp_rejects_nonempty_download_settings_explicitly() {
        let extra = json!({
            "downloadSettings": {
                "host": "download.example",
                "headers": {"Authorization": "secret-value"}
            }
        });
        let mut url = url::Url::parse(
            "vless://11111111-1111-1111-1111-111111111111@provider.example:443?type=xhttp#Test",
        )
        .expect("base URL");
        url.query_pairs_mut()
            .append_pair("extra", &extra.to_string());
        let profile = parse_profiles(url.as_str()).pop().expect("profile");
        let error = build_vless_proxy(&profile, PROXY_NAME).expect_err("unsupported download");

        assert!(error.contains("downloadSettings"));
        assert!(error.contains("Mihomo v1.19.29"));
        assert!(!error.contains("download.example"));
        assert!(!error.contains("secret-value"));
    }

    #[test]
    fn build_vless_xhttp_rejects_malformed_extra_without_echoing_it() {
        for extra in [
            "not-json-secret",
            "[]",
            r#"{"xPaddingObfsMode":"sometimes"}"#,
        ] {
            let mut url = url::Url::parse(
                "vless://11111111-1111-1111-1111-111111111111@provider.example:443?type=xhttp#Test",
            )
            .expect("base URL");
            url.query_pairs_mut().append_pair("extra", extra);
            let profiles = parse_profiles(url.as_str());
            let error = build_vless_proxy(&profiles[0], PROXY_NAME).expect_err("invalid extra");
            assert!(error.contains("VLESS XHTTP extra"), "{error}");
            assert!(!error.contains(extra), "extra leaked in error: {error}");
        }
    }

    #[test]
    fn build_vless_xhttp_rejects_oversized_extra() {
        let extra = format!(r#"{{"unknown":"{}"}}"#, "x".repeat(16 * 1024));
        let mut url = url::Url::parse(
            "vless://11111111-1111-1111-1111-111111111111@provider.example:443?type=xhttp#Test",
        )
        .expect("base URL");
        url.query_pairs_mut().append_pair("extra", &extra);
        let profiles = parse_profiles(url.as_str());
        let error = build_vless_proxy(&profiles[0], PROXY_NAME).expect_err("oversized extra");

        assert_eq!(error, "VLESS XHTTP extra exceeds the 16384-byte limit");
        assert!(!error.contains(&"x".repeat(64)));
    }

    #[test]
    fn build_vless_xhttp_with_reuse_settings() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=xhttp&security=reality&pbk=pubkey&xmuxMaxConcurrency=16&xmuxMaxConnections=4&xmuxHKeepAlivePeriod=30#Test",
        );
        let profile = &profiles[0];
        let proxy = build_vless_proxy(profile, PROXY_NAME).expect("vless proxy");
        let xhttp_opts = proxy.get("xhttp-opts").expect("xhttp-opts");
        let reuse = xhttp_opts.get("reuse-settings").expect("reuse-settings");
        assert_eq!(
            reuse.get("max-concurrency").and_then(Value::as_str),
            Some("16")
        );
        assert_eq!(
            reuse.get("max-connections").and_then(Value::as_str),
            Some("4")
        );
        assert_eq!(
            reuse.get("h-keep-alive-period").and_then(Value::as_u64),
            Some(30)
        );
    }

    #[test]
    fn build_vless_xhttp_with_uplink_http_method() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=xhttp&security=reality&pbk=pubkey&uplinkHttpMethod=PUT#Test",
        );
        let profile = &profiles[0];
        let proxy = build_vless_proxy(profile, PROXY_NAME).expect("vless proxy");
        let xhttp_opts = proxy.get("xhttp-opts").expect("xhttp-opts");
        assert_eq!(
            xhttp_opts.get("uplink-http-method").and_then(Value::as_str),
            Some("PUT")
        );
    }

    #[test]
    fn build_vless_xhttp_advanced_absent_when_not_set() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=xhttp&security=reality&pbk=pubkey&path=/path&mode=auto#Test",
        );
        let profile = &profiles[0];
        let proxy = build_vless_proxy(profile, PROXY_NAME).expect("vless proxy");
        let xhttp_opts = proxy.get("xhttp-opts").expect("xhttp-opts");
        assert!(xhttp_opts.get("no-grpc-header").is_none());
        assert!(xhttp_opts.get("x-padding-bytes").is_none());
        assert!(xhttp_opts.get("reuse-settings").is_none());
    }

    // ── GEOIP / IP-ASN rule tests ───────────────────────────────────

    #[test]
    fn ip_rule_geoip_prefix_generates_geoip_rule() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let rule = XrayRouteRule {
            domains: vec![],
            ips: vec!["geoip:CN".to_owned()],
            outbound_tag: "direct".to_owned(),
            block_quic: false,
            ports: vec![],
            network: None,
            port_mode: "include".to_owned(),
        };
        let yaml = build_mihomo_router_config(
            profile,
            &[],
            &[],
            &[rule],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &RouterExtra::default(),
            &MihomoFeatures::default(),
        )
        .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        let rules = config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules");
        assert!(rules.iter().any(|r| r.as_str() == Some("GEOIP,CN,DIRECT")));
    }

    #[test]
    fn ip_rule_geoip_with_no_resolve() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let rule = XrayRouteRule {
            domains: vec![],
            ips: vec!["geoip:CN,no-resolve".to_owned()],
            outbound_tag: "direct".to_owned(),
            block_quic: false,
            ports: vec![],
            network: None,
            port_mode: "include".to_owned(),
        };
        let yaml = build_mihomo_router_config(
            profile,
            &[],
            &[],
            &[rule],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &RouterExtra::default(),
            &MihomoFeatures::default(),
        )
        .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        let rules = config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules");
        assert!(
            rules
                .iter()
                .any(|r| r.as_str() == Some("GEOIP,CN,DIRECT,no-resolve"))
        );
    }

    #[test]
    fn ip_rule_asn_prefix_generates_ip_asn_rule() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let rule = XrayRouteRule {
            domains: vec![],
            ips: vec!["geoip-asn:13335".to_owned()],
            outbound_tag: "active".to_owned(),
            block_quic: false,
            ports: vec![],
            network: None,
            port_mode: "include".to_owned(),
        };
        let yaml = build_mihomo_router_config(
            profile,
            &[],
            &[],
            &[rule],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &RouterExtra::default(),
            &MihomoFeatures::default(),
        )
        .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        let rules = config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules");
        assert!(
            rules
                .iter()
                .any(|r| r.as_str() == Some("IP-ASN,13335,proxy"))
        );
    }

    #[test]
    fn ip_rule_src_geoip_prefix() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let rule = XrayRouteRule {
            domains: vec![],
            ips: vec!["src-geoip:cn".to_owned()],
            outbound_tag: "direct".to_owned(),
            block_quic: false,
            ports: vec![],
            network: None,
            port_mode: "include".to_owned(),
        };
        let yaml = build_mihomo_router_config(
            profile,
            &[],
            &[],
            &[rule],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &RouterExtra::default(),
            &MihomoFeatures::default(),
        )
        .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        let rules = config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules");
        assert!(
            rules
                .iter()
                .any(|r| r.as_str() == Some("SRC-GEOIP,cn,DIRECT"))
        );
    }

    #[test]
    fn ip_rule_bare_ip_still_uses_ip_cidr() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let rule = XrayRouteRule {
            domains: vec![],
            ips: vec!["192.168.0.0/16".to_owned()],
            outbound_tag: "direct".to_owned(),
            block_quic: false,
            ports: vec![],
            network: None,
            port_mode: "include".to_owned(),
        };
        let yaml = build_mihomo_router_config(
            profile,
            &[],
            &[],
            &[rule],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &RouterExtra::default(),
            &MihomoFeatures::default(),
        )
        .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        let rules = config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules");
        assert!(
            rules
                .iter()
                .any(|r| r.as_str() == Some("IP-CIDR,192.168.0.0/16,DIRECT"))
        );
    }

    // ── VLESS reality support-x25519mlkem768 ────────────────────────

    #[test]
    fn build_vless_reality_with_support_x25519mlkem768() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&pbk=pubkey123&sid=shortid&sni=example.com&support-x25519mlkem768=1#Test",
        );
        let profile = &profiles[0];
        let proxy = build_vless_proxy(profile, PROXY_NAME).expect("vless proxy");
        let reality_opts = proxy.get("reality-opts").expect("reality-opts");
        assert_eq!(
            reality_opts
                .get("support-x25519mlkem768")
                .and_then(Value::as_bool),
            Some(true)
        );
    }

    // ── v0.11.0: DOMAIN-KEYWORD rule ───────────────────────────────

    #[test]
    fn domain_rule_keyword_prefix_generates_domain_keyword() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let rule = XrayRouteRule {
            domains: vec!["keyword:google".to_owned()],
            ips: vec![],
            outbound_tag: "direct".to_owned(),
            block_quic: false,
            ports: vec![],
            network: None,
            port_mode: "include".to_owned(),
        };
        let yaml = build_mihomo_router_config(
            profile,
            &[],
            &[],
            &[rule],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &RouterExtra::default(),
            &MihomoFeatures::default(),
        )
        .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        let rules = config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules");
        assert!(
            rules
                .iter()
                .any(|r| r.as_str() == Some("DOMAIN-KEYWORD,google,DIRECT"))
        );
    }

    // ── v0.11.0: IP-SUFFIX / SRC-IP-CIDR / SRC-IP-SUFFIX rules ─────

    #[test]
    fn ip_rule_ip_suffix_prefix_generates_ip_suffix() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let rule = XrayRouteRule {
            domains: vec![],
            ips: vec!["ip-suffix:8.8.8.8/24".to_owned()],
            outbound_tag: "direct".to_owned(),
            block_quic: false,
            ports: vec![],
            network: None,
            port_mode: "include".to_owned(),
        };
        let yaml = build_mihomo_router_config(
            profile,
            &[],
            &[],
            &[rule],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &RouterExtra::default(),
            &MihomoFeatures::default(),
        )
        .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        let rules = config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules");
        assert!(
            rules
                .iter()
                .any(|r| r.as_str() == Some("IP-SUFFIX,8.8.8.8/24,DIRECT"))
        );
    }

    #[test]
    fn ip_rule_src_ip_cidr_prefix() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let rule = XrayRouteRule {
            domains: vec![],
            ips: vec!["src-ip-cidr:192.168.1.0/24".to_owned()],
            outbound_tag: "direct".to_owned(),
            block_quic: false,
            ports: vec![],
            network: None,
            port_mode: "include".to_owned(),
        };
        let yaml = build_mihomo_router_config(
            profile,
            &[],
            &[],
            &[rule],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &RouterExtra::default(),
            &MihomoFeatures::default(),
        )
        .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        let rules = config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules");
        assert!(
            rules
                .iter()
                .any(|r| r.as_str() == Some("SRC-IP-CIDR,192.168.1.0/24,DIRECT"))
        );
    }

    #[test]
    fn ip_rule_src_ip_suffix_prefix() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let rule = XrayRouteRule {
            domains: vec![],
            ips: vec!["src-ip-suffix:192.168.1.0/8".to_owned()],
            outbound_tag: "direct".to_owned(),
            block_quic: false,
            ports: vec![],
            network: None,
            port_mode: "include".to_owned(),
        };
        let yaml = build_mihomo_router_config(
            profile,
            &[],
            &[],
            &[rule],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &RouterExtra::default(),
            &MihomoFeatures::default(),
        )
        .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        let rules = config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules");
        assert!(
            rules
                .iter()
                .any(|r| r.as_str() == Some("SRC-IP-SUFFIX,192.168.1.0/8,DIRECT"))
        );
    }

    // ── v0.11.0: SRC-PORT / IN-PORT rules ──────────────────────────

    #[test]
    fn rule_to_strings_src_port_prefix() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let rule = XrayRouteRule {
            domains: vec![],
            ips: vec![],
            outbound_tag: "active".to_owned(),
            block_quic: false,
            ports: vec!["src-port:7777".to_owned()],
            network: None,
            port_mode: "include".to_owned(),
        };
        let yaml = build_mihomo_router_config(
            profile,
            &[],
            &[],
            &[rule],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &RouterExtra::default(),
            &MihomoFeatures::default(),
        )
        .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        let rules = config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules");
        assert!(
            rules
                .iter()
                .any(|r| r.as_str() == Some("SRC-PORT,7777,proxy"))
        );
    }

    #[test]
    fn rule_to_strings_in_port_prefix() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let rule = XrayRouteRule {
            domains: vec![],
            ips: vec![],
            outbound_tag: "active".to_owned(),
            block_quic: false,
            ports: vec!["in-port:7890".to_owned()],
            network: None,
            port_mode: "include".to_owned(),
        };
        let yaml = build_mihomo_router_config(
            profile,
            &[],
            &[],
            &[rule],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &RouterExtra::default(),
            &MihomoFeatures::default(),
        )
        .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        let rules = config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules");
        assert!(
            rules
                .iter()
                .any(|r| r.as_str() == Some("IN-PORT,7890,proxy"))
        );
    }

    // ── v0.11.0: ws-opts early-data ────────────────────────────────

    #[test]
    fn vless_ws_early_data_fields() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=ws&security=tls&sni=example.com&path=/ws&host=example.com&maxEarlyData=2048&earlyDataHeaderName=Sec-WebSocket-Protocol&v2rayHttpUpgrade=1#Test",
        );
        let profile = &profiles[0];
        let proxy = build_vless_proxy(profile, PROXY_NAME).expect("vless proxy");
        let ws_opts = proxy.get("ws-opts").expect("ws-opts");
        assert_eq!(
            ws_opts.get("max-early-data").and_then(Value::as_u64),
            Some(2048)
        );
        assert_eq!(
            ws_opts
                .get("early-data-header-name")
                .and_then(Value::as_str),
            Some("Sec-WebSocket-Protocol")
        );
        assert_eq!(
            ws_opts.get("v2ray-http-upgrade").and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn vmess_ws_early_data_fields() {
        let vmess_json = r#"{"v":"2","ps":"VMess WS","add":"example.com","port":"443","id":"11111111-1111-1111-1111-111111111111","aid":"0","net":"ws","type":"none","host":"example.com","path":"/ws","tls":"tls","sni":"example.com","maxEarlyData":1024,"earlyDataHeaderName":"Sec-WebSocket-Protocol"}"#;
        let encoded = base64::engine::general_purpose::STANDARD.encode(vmess_json.as_bytes());
        let link = format!("vmess://{encoded}#VMess WS");
        let profiles = parse_profiles(&link);
        let profile = &profiles[0];
        let proxy = build_vmess_proxy(profile, PROXY_NAME).expect("vmess proxy");
        let ws_opts = proxy.get("ws-opts").expect("ws-opts");
        assert_eq!(
            ws_opts.get("max-early-data").and_then(Value::as_u64),
            Some(1024)
        );
        assert_eq!(
            ws_opts
                .get("early-data-header-name")
                .and_then(Value::as_str),
            Some("Sec-WebSocket-Protocol")
        );
    }

    // ── v0.11.0: grpc-opts advanced ────────────────────────────────

    #[test]
    fn vless_grpc_advanced_fields() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=grpc&security=tls&sni=example.com&serviceName=grpc_service&grpcUserAgent=custom-agent&pingInterval=30&maxConnections=4&minStreams=2&maxStreams=10#Test",
        );
        let profile = &profiles[0];
        let proxy = build_vless_proxy(profile, PROXY_NAME).expect("vless proxy");
        let grpc_opts = proxy.get("grpc-opts").expect("grpc-opts");
        assert_eq!(
            grpc_opts.get("grpc-service-name").and_then(Value::as_str),
            Some("grpc_service")
        );
        assert_eq!(
            grpc_opts.get("grpc-user-agent").and_then(Value::as_str),
            Some("custom-agent")
        );
        assert_eq!(
            grpc_opts.get("ping-interval").and_then(Value::as_u64),
            Some(30)
        );
        assert_eq!(
            grpc_opts.get("max-connections").and_then(Value::as_u64),
            Some(4)
        );
        assert_eq!(
            grpc_opts.get("min-streams").and_then(Value::as_u64),
            Some(2)
        );
        assert_eq!(
            grpc_opts.get("max-streams").and_then(Value::as_u64),
            Some(10)
        );
    }

    #[test]
    fn trojan_grpc_transport() {
        let profiles = parse_profiles(
            "trojan://secretpass@example.com:443?security=tls&sni=example.com&type=grpc&serviceName=grpc_service#Test",
        );
        let profile = &profiles[0];
        let proxy = build_trojan_proxy(profile, PROXY_NAME).expect("trojan proxy");
        assert_eq!(proxy.get("network").and_then(Value::as_str), Some("grpc"));
        let grpc_opts = proxy.get("grpc-opts").expect("grpc-opts");
        assert_eq!(
            grpc_opts.get("grpc-service-name").and_then(Value::as_str),
            Some("grpc_service")
        );
    }

    // ── v0.11.0: mTLS certificate/private-key ──────────────────────

    #[test]
    fn vless_mtls_certificate_and_key() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp&security=tls&sni=example.com&certificate=cert123&privateKey=key456#Test",
        );
        let profile = &profiles[0];
        let proxy = build_vless_proxy(profile, PROXY_NAME).expect("vless proxy");
        assert_eq!(
            proxy.get("certificate").and_then(Value::as_str),
            Some("cert123")
        );
        assert_eq!(
            proxy.get("private-key").and_then(Value::as_str),
            Some("key456")
        );
    }

    #[test]
    fn vmess_mtls_certificate_and_key() {
        let vmess_json = r#"{"v":"2","ps":"VMess mTLS","add":"example.com","port":"443","id":"11111111-1111-1111-1111-111111111111","aid":"0","net":"tcp","tls":"tls","sni":"example.com","certificate":"cert123","privateKey":"key456"}"#;
        let encoded = base64::engine::general_purpose::STANDARD.encode(vmess_json.as_bytes());
        let link = format!("vmess://{encoded}#VMess mTLS");
        let profiles = parse_profiles(&link);
        let profile = &profiles[0];
        let proxy = build_vmess_proxy(profile, PROXY_NAME).expect("vmess proxy");
        assert_eq!(
            proxy.get("certificate").and_then(Value::as_str),
            Some("cert123")
        );
        assert_eq!(
            proxy.get("private-key").and_then(Value::as_str),
            Some("key456")
        );
    }

    // ── v0.11.0: ECH query-server-name ─────────────────────────────

    #[test]
    fn vless_ech_with_query_server_name() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&sni=example.com&ech=1&echServerName=ech.example.com#ECH",
        );
        let profile = &profiles[0];
        let proxy = build_vless_proxy(profile, PROXY_NAME).expect("vless proxy");
        let ech_opts = proxy.get("ech-opts").expect("ech-opts");
        assert_eq!(ech_opts.get("enable").and_then(Value::as_bool), Some(true));
        assert_eq!(
            ech_opts.get("query-server-name").and_then(Value::as_str),
            Some("ech.example.com")
        );
    }

    #[test]
    fn vmess_ech_with_query_server_name() {
        let vmess_json = r#"{"v":"2","ps":"VMess ECH","add":"example.com","port":"443","id":"11111111-1111-1111-1111-111111111111","aid":"0","net":"tcp","tls":"tls","sni":"example.com","ech":"1","echServerName":"ech.example.com"}"#;
        let encoded = base64::engine::general_purpose::STANDARD.encode(vmess_json.as_bytes());
        let link = format!("vmess://{encoded}#VMess ECH");
        let profiles = parse_profiles(&link);
        let profile = &profiles[0];
        let proxy = build_vmess_proxy(profile, PROXY_NAME).expect("vmess proxy");
        let ech_opts = proxy.get("ech-opts").expect("ech-opts");
        assert_eq!(ech_opts.get("enable").and_then(Value::as_bool), Some(true));
        assert_eq!(
            ech_opts.get("query-server-name").and_then(Value::as_str),
            Some("ech.example.com")
        );
    }

    // ── v0.11.0: DNS nameserver-policy ─────────────────────────────

    #[test]
    fn dns_includes_nameserver_policy_when_configured() {
        let mut features = default_features();
        let mut policy = std::collections::HashMap::new();
        policy.insert(
            "+.google.com".to_owned(),
            vec!["https://dns.google/dns-query".to_owned()],
        );
        policy.insert(
            "geosite:cn".to_owned(),
            vec!["223.5.5.5".to_owned(), "223.6.6.6".to_owned()],
        );
        features.dns_nameserver_policy = policy;
        let config = build_test_router_config(&features);
        let dns = config.get("dns").expect("dns");
        let np = dns.get("nameserver-policy").expect("nameserver-policy");
        let google = np
            .get("+.google.com")
            .and_then(Value::as_array)
            .expect("google servers");
        assert_eq!(google.len(), 1);
        assert_eq!(google[0].as_str(), Some("https://dns.google/dns-query"));
        let cn = np
            .get("geosite:cn")
            .and_then(Value::as_array)
            .expect("cn servers");
        assert_eq!(cn.len(), 2);
        assert_eq!(cn[0].as_str(), Some("223.5.5.5"));
        assert_eq!(cn[1].as_str(), Some("223.6.6.6"));
    }

    #[test]
    fn dns_omits_nameserver_policy_when_empty() {
        let config = build_test_router_config(&default_features());
        let dns = config.get("dns").expect("dns");
        assert!(dns.get("nameserver-policy").is_none());
    }

    #[test]
    fn dns_parity_fields_are_emitted_when_configured() {
        let mut features = default_features();
        features.dns_fake_ip_filter_mode = Some("blacklist".to_owned());
        features.dns_fake_ip_filter = vec!["MATCH,fake-ip".to_owned()];
        features.dns_fake_ip_ttl = Some(60);
        features.dns_default_nameserver = vec!["1.1.1.1".to_owned()];
        features.dns_direct_nameserver_follow_policy = Some(true);
        let mut proxy_policy = std::collections::HashMap::new();
        proxy_policy.insert("node.example.com".to_owned(), vec!["8.8.8.8".to_owned()]);
        features.dns_proxy_server_nameserver_policy = proxy_policy;

        let config = build_test_router_config(&features);
        let dns = config.get("dns").expect("dns");
        assert_eq!(
            dns.get("fake-ip-filter-mode").and_then(Value::as_str),
            Some("blacklist")
        );
        assert_eq!(dns.get("fake-ip-ttl").and_then(Value::as_u64), Some(60));
        assert_eq!(
            dns.get("direct-nameserver-follow-policy")
                .and_then(Value::as_bool),
            Some(true)
        );
        assert!(dns.get("ecs").is_none());
        assert!(dns.get("disable-ipv4").is_none());
        assert!(dns.get("proxy-server-nameserver-policy").is_some());
    }

    #[test]
    fn routing_rule_reject_target_produces_reject() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let rule = XrayRouteRule {
            domains: vec!["geosite:category-ads-all".to_owned()],
            ips: vec![],
            outbound_tag: "reject".to_owned(),
            block_quic: false,
            ports: vec![],
            network: None,
            port_mode: "include".to_owned(),
        };
        let yaml = build_mihomo_router_config(
            profile,
            &[],
            &[],
            &[rule],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &RouterExtra::default(),
            &MihomoFeatures::default(),
        )
        .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        let rules = config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules");
        assert!(
            rules.iter().any(|r| {
                r.as_str()
                    .is_some_and(|s| s == "GEOSITE,category-ads-all,REJECT")
            }),
            "REJECT rule not found, rules: {rules:?}"
        );
    }

    #[test]
    fn bench_config_vless_has_socks_and_match() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp&security=tls&sni=example.com#Test",
        );
        let yaml =
            build_mihomo_bench_config(&profiles[0], "127.0.0.1", 20808).expect("bench config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        assert_eq!(config["socks-port"], json!(20808));
        assert_eq!(config["log-level"], json!("silent"));
        assert_eq!(config["allow-lan"], json!(false));
        assert_eq!(config["geo-auto-update"], json!(false));
        let rules = config["rules"].as_array().expect("rules array");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].as_str(), Some("MATCH,proxy"));
        let proxies = config["proxies"].as_array().expect("proxies array");
        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0]["type"], json!("vless"));
    }

    #[test]
    fn bench_config_vmess_builds_successfully() {
        let vmess_json = r#"{"v":"2","ps":"Test","add":"example.com","port":"443","id":"11111111-1111-1111-1111-111111111111","aid":"0","net":"ws","type":"none","host":"example.com","path":"/ws","tls":"tls","sni":"example.com"}"#;
        let encoded = base64::engine::general_purpose::STANDARD.encode(vmess_json.as_bytes());
        let link = format!("vmess://{encoded}#Test");
        let profiles = parse_profiles(&link);
        let yaml =
            build_mihomo_bench_config(&profiles[0], "127.0.0.1", 20809).expect("bench config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        let proxies = config["proxies"].as_array().expect("proxies array");
        assert_eq!(proxies[0]["type"], json!("vmess"));
    }

    #[test]
    fn bench_config_hysteria2_builds_successfully() {
        let profiles = parse_profiles("hysteria2://secret@example.com:443?sni=example.com#Test");
        let yaml =
            build_mihomo_bench_config(&profiles[0], "127.0.0.1", 20810).expect("bench config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        let proxies = config["proxies"].as_array().expect("proxies array");
        assert_eq!(proxies[0]["type"], json!("hysteria2"));
    }

    #[test]
    fn bench_config_wireguard_builds_successfully() {
        let profiles = parse_profiles(
            "wireguard://privkey123@example.com:51820?address=10.0.0.2/32&publickey=pubkey456#Test",
        );
        let yaml =
            build_mihomo_bench_config(&profiles[0], "127.0.0.1", 20811).expect("bench config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        let proxies = config["proxies"].as_array().expect("proxies array");
        assert_eq!(proxies[0]["type"], json!("wireguard"));
    }

    #[test]
    fn bench_config_tuic_builds_successfully() {
        let profiles = parse_profiles(
            "tuic://11111111-1111-1111-1111-111111111111:password@example.com:443?sni=example.com#Test",
        );
        let yaml =
            build_mihomo_bench_config(&profiles[0], "127.0.0.1", 20812).expect("bench config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        let proxies = config["proxies"].as_array().expect("proxies array");
        assert_eq!(proxies[0]["type"], json!("tuic"));
    }

    #[test]
    fn bench_config_no_dns_section() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let yaml =
            build_mihomo_bench_config(&profiles[0], "127.0.0.1", 20813).expect("bench config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        // Bench config should NOT have a dns section — no DNS needed for benchmarking.
        assert!(config.get("dns").is_none());
    }

    // ── RU Direct tests ──────────────────────────────────────────────

    fn router_rules(yaml: &str) -> Vec<String> {
        let config: Value = serde_yaml::from_str(yaml).expect("parse yaml");
        config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules")
            .iter()
            .filter_map(|r| r.as_str().map(ToOwned::to_owned))
            .collect()
    }

    fn managed_provider(
        name: &str,
        path: &str,
        behavior: GeoBaseRuleBehavior,
        target: GeoBaseRuleTarget,
    ) -> GeoBaseRuleProvider {
        GeoBaseRuleProvider {
            enabled: true,
            name: name.to_owned(),
            path: path.to_owned(),
            behavior,
            target,
        }
    }

    fn build_router_with_extra(
        extra: &RouterExtra,
        route_rules: &[XrayRouteRule],
        tproxy_available: bool,
        features: &MihomoFeatures,
    ) -> Result<String, String> {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        build_mihomo_router_config(
            &profiles[0],
            &[],
            &[],
            route_rules,
            "0.0.0.0",
            10808,
            Some(10810),
            tproxy_available,
            QuicMode::Proxy,
            false,
            extra,
            features,
        )
    }

    #[test]
    fn geobase_providers_emit_safe_file_config_and_rules() {
        let extra = RouterExtra {
            geobase_rule_providers: vec![
                managed_provider(
                    "geobase-vpn",
                    "/opt/etc/hincyray/geobase/vpn.txt",
                    GeoBaseRuleBehavior::Domain,
                    GeoBaseRuleTarget::Active,
                ),
                managed_provider(
                    "geobase-static",
                    "/opt/etc/hincyray/geobase/static.txt",
                    GeoBaseRuleBehavior::Ipcidr,
                    GeoBaseRuleTarget::Direct,
                ),
            ],
            mihomo_home: Some("/opt/etc/hincyray".to_owned()),
            ..RouterExtra::default()
        };
        let yaml = build_router_with_extra(&extra, &[], true, &MihomoFeatures::default())
            .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        let providers = config["rule-providers"].as_object().expect("providers");

        assert_eq!(
            providers["geobase-vpn"],
            json!({
                "type": "file",
                "behavior": "domain",
                "format": "text",
                "path": "/opt/etc/hincyray/geobase/vpn.txt",
            })
        );
        assert_eq!(providers["geobase-static"]["behavior"], "ipcidr");
        assert_eq!(
            providers["geobase-static"]["path"],
            "/opt/etc/hincyray/geobase/static.txt"
        );
        let rules = router_rules(&yaml);
        assert!(rules.contains(&"RULE-SET,geobase-vpn,proxy".to_owned()));
        assert!(
            !rules
                .iter()
                .any(|rule| rule.starts_with("RULE-SET,") && rule.ends_with(",proxy-active")),
            "broad GeoBase rules must target the fallback group, not raw proxy-active"
        );
        assert!(rules.contains(&"RULE-SET,geobase-static,DIRECT".to_owned()));
    }

    #[test]
    fn geobase_rule_order_is_active_before_direct_in_full_pipeline() {
        let route_rule = XrayRouteRule {
            domains: vec!["ordinary.example".to_owned()],
            ips: vec![],
            outbound_tag: "direct".to_owned(),
            block_quic: false,
            ports: vec![],
            network: None,
            port_mode: "include".to_owned(),
        };
        let extra = RouterExtra {
            geobase_rule_providers: vec![
                managed_provider(
                    "direct-first-in-input",
                    "/opt/etc/hincyray/geobase/direct.txt",
                    GeoBaseRuleBehavior::Domain,
                    GeoBaseRuleTarget::Direct,
                ),
                managed_provider(
                    "active-second-in-input",
                    "/opt/etc/hincyray/geobase/active.txt",
                    GeoBaseRuleBehavior::Domain,
                    GeoBaseRuleTarget::Active,
                ),
            ],
            mihomo_home: Some("/opt/etc/hincyray".to_owned()),
            auto_vpn_exceptions: vec!["auto.example".to_owned()],
            ru_direct_mode: "tld".to_owned(),
            port_mode: PortMode::AllowList,
            proxy_ports: vec!["443".to_owned()],
            ..RouterExtra::default()
        };
        let yaml =
            build_router_with_extra(&extra, &[route_rule], false, &MihomoFeatures::default())
                .expect("router config");
        let rules = router_rules(&yaml);
        assert_eq!(
            rules,
            [
                "DOMAIN-SUFFIX,ordinary.example,DIRECT",
                "AND,((NETWORK,udp),(DST-PORT,443)),REJECT",
                "DOMAIN-SUFFIX,auto.example,proxy",
                "RULE-SET,active-second-in-input,proxy",
                "RULE-SET,direct-first-in-input,DIRECT",
                "DOMAIN-SUFFIX,ru,DIRECT",
                "DOMAIN-SUFFIX,xn--p1ai,DIRECT",
                "DST-PORT,443,proxy",
                "MATCH,proxy",
            ]
        );
    }

    #[test]
    fn parovozik_provider_rules_follow_geobase_and_use_fallback_group() {
        let extra = RouterExtra {
            geobase_rule_providers: vec![
                managed_provider(
                    "managed-direct",
                    "/opt/etc/hincyray/geobase/direct.txt",
                    GeoBaseRuleBehavior::Domain,
                    GeoBaseRuleTarget::Direct,
                ),
                managed_provider(
                    "parovozik-vpn-rules",
                    "/opt/etc/hincyray/parovozik-vpn.txt",
                    GeoBaseRuleBehavior::Domain,
                    GeoBaseRuleTarget::ParovozikVpn,
                ),
                managed_provider(
                    "parovozik-direct",
                    "/opt/etc/hincyray/parovozik-direct.txt",
                    GeoBaseRuleBehavior::Domain,
                    GeoBaseRuleTarget::ParovozikDirect,
                ),
            ],
            mihomo_home: Some("/opt/etc/hincyray".to_owned()),
            parovozik_vpn_target: PAROVOZIK_PROXY_GROUP.to_owned(),
            parovozik_vpn_outbounds: vec!["srv-route-test".to_owned()],
            ..RouterExtra::default()
        };
        let yaml = build_router_with_extra(&extra, &[], false, &MihomoFeatures::default())
            .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("config");
        let rules = config["rules"].as_array().expect("rules");
        let geobase = rules
            .iter()
            .position(|rule| rule == "RULE-SET,managed-direct,DIRECT")
            .expect("GeoBase rule");
        let vpn = rules
            .iter()
            .position(|rule| rule == "RULE-SET,parovozik-vpn-rules,parovozik-vpn")
            .expect("Parovozik VPN rule");
        let direct = rules
            .iter()
            .position(|rule| rule == "RULE-SET,parovozik-direct,DIRECT")
            .expect("Parovozik Direct rule");
        assert!(geobase < vpn && vpn < direct);
        let group = config["proxy-groups"]
            .as_array()
            .expect("groups")
            .iter()
            .find(|group| group["name"] == PAROVOZIK_PROXY_GROUP)
            .expect("Parovozik group");
        assert_eq!(group["type"], "fallback");
        assert_eq!(
            group["proxies"],
            json!([PROXY_ACTIVE_NAME, "srv-route-test"])
        );
    }

    #[test]
    fn invalid_geobase_descriptors_are_rejected() {
        for provider in [
            managed_provider(
                &"x".repeat(65),
                "/opt/etc/hincyray/geobase/list.txt",
                GeoBaseRuleBehavior::Domain,
                GeoBaseRuleTarget::Active,
            ),
            managed_provider(
                "relative-path",
                "geobase/list.txt",
                GeoBaseRuleBehavior::Domain,
                GeoBaseRuleTarget::Active,
            ),
            managed_provider(
                "traversal-path",
                "/opt/etc/hincyray/../state.json",
                GeoBaseRuleBehavior::Ipcidr,
                GeoBaseRuleTarget::Direct,
            ),
        ] {
            let extra = RouterExtra {
                geobase_rule_providers: vec![provider],
                mihomo_home: Some("/opt/etc/hincyray".to_owned()),
                ..RouterExtra::default()
            };
            assert!(
                build_router_with_extra(&extra, &[], true, &MihomoFeatures::default()).is_err()
            );
        }
    }

    #[test]
    fn managed_provider_requires_mihomo_home_and_stays_below_it() {
        let provider = managed_provider(
            "geobase-active",
            "/srv/geobases/active.txt",
            GeoBaseRuleBehavior::Domain,
            GeoBaseRuleTarget::Active,
        );
        let missing_home = RouterExtra {
            geobase_rule_providers: vec![provider.clone()],
            ..RouterExtra::default()
        };
        let error = build_router_with_extra(&missing_home, &[], true, &MihomoFeatures::default())
            .expect_err("managed provider without home must fail");
        assert!(error.contains("Mihomo home is required"));

        let outside_home = RouterExtra {
            geobase_rule_providers: vec![provider],
            mihomo_home: Some("/opt/etc/hincyray".to_owned()),
            ..RouterExtra::default()
        };
        let error = build_router_with_extra(&outside_home, &[], true, &MihomoFeatures::default())
            .expect_err("managed provider outside home must fail");
        assert!(error.contains("outside Mihomo home"));
    }

    #[test]
    fn duplicate_effective_provider_paths_are_rejected() {
        let extra = RouterExtra {
            geobase_rule_providers: vec![
                managed_provider(
                    "geobase-active",
                    "/opt/etc/hincyray/geobases/shared.txt",
                    GeoBaseRuleBehavior::Domain,
                    GeoBaseRuleTarget::Active,
                ),
                managed_provider(
                    "geobase-direct",
                    "/opt/etc/hincyray/geobases/shared.txt",
                    GeoBaseRuleBehavior::Domain,
                    GeoBaseRuleTarget::Direct,
                ),
            ],
            mihomo_home: Some("/opt/etc/hincyray".to_owned()),
            ..RouterExtra::default()
        };
        let error = build_router_with_extra(&extra, &[], true, &MihomoFeatures::default())
            .expect_err("duplicate managed paths must fail");
        assert!(error.contains("duplicate effective rule provider path"));
    }

    #[test]
    fn empty_geobase_providers_emit_nothing() {
        let yaml = build_router_with_extra(
            &RouterExtra::default(),
            &[],
            true,
            &MihomoFeatures::default(),
        )
        .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        assert!(config.get("rule-providers").is_none());
        assert!(
            !router_rules(&yaml)
                .iter()
                .any(|rule| rule.starts_with("RULE-SET,"))
        );
    }

    #[test]
    fn ru_direct_off_emits_no_ru_rules() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let extra = RouterExtra {
            ru_direct_mode: "off".to_owned(),
            ..RouterExtra::default()
        };
        let yaml = build_mihomo_router_config(
            &profiles[0],
            &[],
            &[],
            &[],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &extra,
            &MihomoFeatures::default(),
        )
        .expect("config");
        let rules = router_rules(&yaml);
        assert!(
            !rules.iter().any(|r| r.contains("DOMAIN-SUFFIX,ru,")
                || r.contains("category-ru")
                || r.contains("xn--p1ai")),
            "off mode must not emit any RU Direct rules, got: {rules:?}"
        );
    }

    #[test]
    fn ru_direct_tld_emits_suffix_rules() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let extra = RouterExtra {
            ru_direct_mode: "tld".to_owned(),
            ..RouterExtra::default()
        };
        let yaml = build_mihomo_router_config(
            &profiles[0],
            &[],
            &[],
            &[],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &extra,
            &MihomoFeatures::default(),
        )
        .expect("config");
        let rules = router_rules(&yaml);
        assert!(
            rules.contains(&"DOMAIN-SUFFIX,ru,DIRECT".to_owned()),
            "tld mode must emit DOMAIN-SUFFIX,ru,DIRECT, got: {rules:?}"
        );
        assert!(
            rules.contains(&"DOMAIN-SUFFIX,xn--p1ai,DIRECT".to_owned()),
            "tld mode must emit .рф (xn--p1ai) rule, got: {rules:?}"
        );
    }

    #[test]
    fn ru_direct_geosite_emits_category_ru() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let extra = RouterExtra {
            ru_direct_mode: "geosite".to_owned(),
            ..RouterExtra::default()
        };
        let yaml = build_mihomo_router_config(
            &profiles[0],
            &[],
            &[],
            &[],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &extra,
            &MihomoFeatures::default(),
        )
        .expect("config");
        let rules = router_rules(&yaml);
        assert!(
            rules.contains(&"GEOSITE,category-ru,DIRECT".to_owned()),
            "geosite mode must emit GEOSITE,category-ru,DIRECT, got: {rules:?}"
        );
        // Should NOT emit TLD rules in geosite mode.
        assert!(
            !rules.contains(&"DOMAIN-SUFFIX,ru,DIRECT".to_owned()),
            "geosite mode must not emit DOMAIN-SUFFIX,ru,DIRECT"
        );
    }

    #[test]
    fn ru_direct_exceptions_emitted_before_main_rules() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let extra = RouterExtra {
            ru_direct_mode: "tld".to_owned(),
            ru_direct_exceptions: vec!["2ip.ru".to_owned(), "blocked.ru".to_owned()],
            ..RouterExtra::default()
        };
        let yaml = build_mihomo_router_config(
            &profiles[0],
            &[],
            &[],
            &[],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &extra,
            &MihomoFeatures::default(),
        )
        .expect("config");
        let rules = router_rules(&yaml);

        // Exceptions must use PROXY (not DIRECT).
        let exc_idx_2ip = rules.iter().position(|r| r == "DOMAIN-SUFFIX,2ip.ru,proxy");
        let exc_idx_blocked = rules
            .iter()
            .position(|r| r == "DOMAIN-SUFFIX,blocked.ru,proxy");
        let main_idx = rules.iter().position(|r| r == "DOMAIN-SUFFIX,ru,DIRECT");

        assert!(exc_idx_2ip.is_some(), "2ip.ru exception must exist");
        assert!(exc_idx_blocked.is_some(), "blocked.ru exception must exist");
        assert!(main_idx.is_some(), "main RU rule must exist");

        // Exceptions must come before the main rule.
        assert!(
            exc_idx_2ip.expect("2ip idx") < main_idx.expect("main idx"),
            "exceptions must precede main RU Direct rules"
        );
        assert!(
            exc_idx_blocked.expect("blocked idx") < main_idx.expect("main idx"),
            "exceptions must precede main RU Direct rules"
        );
    }

    #[test]
    fn ru_direct_rules_after_user_rules_before_match() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        // User rule: youtube via proxy.
        let user_rules = vec![XrayRouteRule {
            domains: vec!["geosite:youtube".to_owned()],
            ips: vec![],
            outbound_tag: "active".to_owned(),
            block_quic: false,
            ports: vec![],
            network: None,
            port_mode: "include".to_owned(),
        }];
        let extra = RouterExtra {
            ru_direct_mode: "tld".to_owned(),
            ..RouterExtra::default()
        };
        let yaml = build_mihomo_router_config(
            &profiles[0],
            &[],
            &[],
            &user_rules,
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Block,
            false,
            &extra,
            &MihomoFeatures::default(),
        )
        .expect("config");
        let rules = router_rules(&yaml);

        let user_idx = rules.iter().position(|r| r == "GEOSITE,youtube,proxy");
        let ru_idx = rules.iter().position(|r| r == "DOMAIN-SUFFIX,ru,DIRECT");
        let match_idx = rules.iter().position(|r| r == "MATCH,proxy");

        assert!(user_idx.is_some(), "user rule must exist");
        assert!(ru_idx.is_some(), "RU Direct rule must exist");
        assert!(match_idx.is_some(), "MATCH must exist");

        // User < RU Direct < MATCH.
        assert!(
            user_idx.expect("user idx") < ru_idx.expect("ru idx"),
            "user rules must precede RU Direct rules"
        );
        assert!(
            ru_idx.expect("ru idx") < match_idx.expect("match idx"),
            "RU Direct rules must precede MATCH"
        );
    }

    #[test]
    fn port_exclude_generates_and_with_not() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let rule = XrayRouteRule {
            domains: vec!["example.com".to_owned()],
            ips: vec![],
            outbound_tag: "direct".to_owned(),
            block_quic: false,
            ports: vec!["22".to_owned()],
            network: None,
            port_mode: "exclude".to_owned(),
        };
        let extra = RouterExtra {
            match_target: "proxy".to_owned(),
            ..RouterExtra::default()
        };
        let yaml = build_mihomo_router_config(
            profile,
            &[],
            &[],
            &[rule],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Proxy,
            false,
            &extra,
            &MihomoFeatures::default(),
        )
        .expect("config");
        let rules = router_rules(&yaml);
        // Exclude mode: AND,((DOMAIN-SUFFIX,example.com),(NOT,(DST-PORT,22))),DIRECT
        let has_exclude = rules
            .iter()
            .any(|r| r == "AND,((DOMAIN-SUFFIX,example.com),(NOT,(DST-PORT,22))),DIRECT");
        assert!(
            has_exclude,
            "expected AND with NOT,DST-PORT, got: {rules:?}"
        );
    }

    #[test]
    fn match_target_direct_generates_match_direct_in_config() {
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Test",
        );
        let profile = &profiles[0];
        let rule = XrayRouteRule {
            domains: vec!["geosite:youtube".to_owned()],
            ips: vec![],
            outbound_tag: "active".to_owned(),
            block_quic: false,
            ports: vec![],
            network: None,
            port_mode: "include".to_owned(),
        };
        let extra = RouterExtra {
            match_target: "direct".to_owned(),
            ..RouterExtra::default()
        };
        let yaml = build_mihomo_router_config(
            profile,
            &[],
            &[],
            &[rule],
            "0.0.0.0",
            10808,
            Some(10810),
            true,
            QuicMode::Proxy,
            false,
            &extra,
            &MihomoFeatures::default(),
        )
        .expect("config");
        let rules = router_rules(&yaml);
        let last = rules.last().map(|r| r.as_str()).expect("last rule");
        assert_eq!(last, "MATCH,DIRECT");
    }

    #[test]
    fn domain_and_ip_rule_bodies_exclude_target() {
        assert_eq!(domain_rule_body("geosite:youtube"), "GEOSITE,youtube");
        assert_eq!(domain_rule_body("example.com"), "DOMAIN-SUFFIX,example.com");
        assert_eq!(domain_rule_body("=exact.com"), "DOMAIN,exact.com");
        assert_eq!(domain_rule_body("keyword:foo"), "DOMAIN-KEYWORD,foo");

        let (body, modi) = ip_rule_body("geoip:CN");
        assert_eq!(body, "GEOIP,CN");
        assert_eq!(modi, None);

        let (body, modi) = ip_rule_body("geoip:CN,no-resolve");
        assert_eq!(body, "GEOIP,CN");
        assert_eq!(modi, Some("no-resolve".to_string()));

        let (body, _) = ip_rule_body("192.168.1.0/24");
        assert_eq!(body, "IP-CIDR,192.168.1.0/24");
    }
}
