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

/// Sing-mux (multiplexing) settings for proxy connections.
///
/// Multiplexes multiple streams over a single TCP connection, reducing
/// connection-setup overhead — especially valuable on high-latency or
/// unreliable links (e.g. LTE with poor CINR).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SmuxConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_smux_protocol")]
    pub protocol: String,
    #[serde(default)]
    pub max_connections: u32,
    #[serde(default)]
    pub min_streams: u32,
    #[serde(default)]
    pub max_streams: u32,
    #[serde(default)]
    pub statistic: bool,
    #[serde(default)]
    pub only_tcp: bool,
    #[serde(default)]
    pub padding: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub brutal_up: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub brutal_down: Option<u32>,
}

impl Default for SmuxConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            protocol: default_smux_protocol(),
            max_connections: 0,
            min_streams: 0,
            max_streams: 0,
            statistic: false,
            only_tcp: false,
            padding: false,
            brutal_up: None,
            brutal_down: None,
        }
    }
}

/// Proxy group type. When `enabled`, Mihomo manages failover/auto-select
/// internally — no core restart needed on profile switch.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyGroupType {
    /// Manual selection — user picks a proxy from the group.
    Select,
    /// Auto-select by lowest latency (health-checked periodically).
    #[default]
    UrlTest,
    /// Failover in list order — switch to next when current fails.
    Fallback,
    /// Distribute traffic across proxies by strategy.
    LoadBalance,
    /// Chain proxies in order. Deprecated by upstream in favour of
    /// per-proxy `dialer-proxy`, but still supported for config parity.
    Relay,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum LoadBalanceStrategy {
    /// Round-robin — each request to a different proxy.
    RoundRobin,
    /// Same target domain → same proxy (sticky by domain).
    #[default]
    ConsistentHashing,
    /// Same source+target → same proxy (sticky by pair, 10-min TTL).
    StickySessions,
}

/// Configuration for the proxy-group feature.
///
/// When `enabled`, instead of a single `proxy` outbound, Mihomo gets a
/// `proxy-groups` section with a group named `proxy` (so existing rules
/// still work unchanged). The group wraps all profiles and handles
/// auto-select / failover / load-balance internally.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ProxyGroupConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub group_type: ProxyGroupType,
    #[serde(default = "default_health_check_url")]
    pub url: String,
    #[serde(default = "default_health_check_interval")]
    pub interval: u32,
    #[serde(default)]
    pub tolerance: u32,
    #[serde(default = "default_health_check_timeout")]
    pub timeout: u32,
    #[serde(default = "default_true")]
    pub lazy: bool,
    #[serde(default = "default_max_failed_times")]
    pub max_failed_times: u32,
    #[serde(default)]
    pub strategy: LoadBalanceStrategy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_status: Option<String>,
    /// Regex filter — only include nodes whose name matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    /// Regex filter — exclude nodes whose name matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude_filter: Option<String>,
    /// Exclude by proxy type, pipe-separated (e.g. "Shadowsocks|Http").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude_type: Option<String>,
    /// Auto-include all nodes from all proxy-providers in this group.
    #[serde(default)]
    pub include_all_providers: bool,
    /// Include all proxies AND all proxy-providers (sorted by name).
    #[serde(default)]
    pub include_all: bool,
    /// Include all proxies only (no providers), sorted by name.
    #[serde(default)]
    pub include_all_proxies: bool,
}

impl Default for ProxyGroupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            group_type: ProxyGroupType::default(),
            url: default_health_check_url(),
            interval: default_health_check_interval(),
            tolerance: 0,
            timeout: default_health_check_timeout(),
            lazy: true,
            max_failed_times: default_max_failed_times(),
            strategy: LoadBalanceStrategy::default(),
            expected_status: None,
            filter: None,
            exclude_filter: None,
            exclude_type: None,
            include_all_providers: false,
            include_all: false,
            include_all_proxies: false,
        }
    }
}

/// A single proxy-provider entry — Mihomo fetches and refreshes the
/// subscription itself, with optional health-check and filtering.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ProxyProviderConfig {
    pub name: String,
    #[serde(default = "default_provider_type")]
    pub provider_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default = "default_provider_interval")]
    pub interval: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude_filter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude_type: Option<String>,
    #[serde(default)]
    pub health_check_enabled: bool,
    #[serde(default = "default_health_check_url")]
    pub health_check_url: String,
    #[serde(default = "default_health_check_interval")]
    pub health_check_interval: u32,
    #[serde(default = "default_health_check_timeout")]
    pub health_check_timeout: u32,
    #[serde(default = "default_true")]
    pub health_check_lazy: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_check_expected_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_secret_key: Option<String>,
    #[serde(default)]
    pub header: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub size_limit: u64,
    /// For `inline` type: raw proxy YAML lines.
    #[serde(default)]
    pub payload: Vec<String>,
}

impl Default for ProxyProviderConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            provider_type: default_provider_type(),
            url: None,
            path: None,
            interval: default_provider_interval(),
            proxy: None,
            filter: None,
            exclude_filter: None,
            exclude_type: None,
            health_check_enabled: false,
            health_check_url: default_health_check_url(),
            health_check_interval: default_health_check_interval(),
            health_check_timeout: default_health_check_timeout(),
            health_check_lazy: true,
            health_check_expected_status: None,
            age_secret_key: None,
            header: HashMap::new(),
            size_limit: 0,
            payload: Vec::new(),
        }
    }
}

/// A single rule-provider entry — external rule sets (domain/ipcidr/
/// classical) loaded from HTTP, file, or inline.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RuleProviderConfig {
    pub name: String,
    #[serde(default = "default_provider_type")]
    pub provider_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default = "default_provider_interval")]
    pub interval: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    #[serde(default = "default_rule_behavior")]
    pub behavior: String,
    #[serde(default = "default_rule_format")]
    pub format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_in_bundle: Option<String>,
    #[serde(default)]
    pub size_limit: u64,
    #[serde(default)]
    pub header: HashMap<String, Vec<String>>,
    /// For `inline` type: raw rule strings.
    #[serde(default)]
    pub payload: Vec<String>,
}

impl Default for RuleProviderConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            provider_type: default_provider_type(),
            url: None,
            path: None,
            interval: default_provider_interval(),
            proxy: None,
            behavior: default_rule_behavior(),
            format: default_rule_format(),
            path_in_bundle: None,
            size_limit: 0,
            header: HashMap::new(),
            payload: Vec::new(),
        }
    }
}

/// A single tunnel entry — TCP/UDP port forwarding through Mihomo.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq)]
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

/// NTP service configuration. Synchronises system time — critical for
/// TLS certificate validation after router reboot without RTC battery.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct NtpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub write_to_system: bool,
    #[serde(default = "default_ntp_server")]
    pub server: String,
    #[serde(default = "default_ntp_port")]
    pub port: u16,
    #[serde(default = "default_ntp_interval")]
    pub interval: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dialer_proxy: Option<String>,
}

impl Default for NtpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            write_to_system: false,
            server: default_ntp_server(),
            port: default_ntp_port(),
            interval: default_ntp_interval(),
            dialer_proxy: None,
        }
    }
}

/// External REST API controller. Enables `/proxies/{name}/delay`,
/// `/connections`, `/traffic`, `/configs` (hot-reload), `/restart`, etc.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ExternalControllerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_external_controller_addr")]
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(default)]
    pub allow_origins: Vec<String>,
    #[serde(default)]
    pub allow_private_network: bool,
}

impl Default for ExternalControllerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            address: default_external_controller_addr(),
            secret: None,
            allow_origins: Vec::new(),
            allow_private_network: false,
        }
    }
}

/// DNS fallback filter — determines when fallback DNS results are used.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct FallbackFilter {
    #[serde(default = "default_true")]
    pub geoip: bool,
    #[serde(default = "default_geoip_code")]
    pub geoip_code: String,
    #[serde(default)]
    pub geosite: Vec<String>,
    #[serde(default)]
    pub ipcidr: Vec<String>,
    #[serde(default)]
    pub domain: Vec<String>,
}

impl Default for FallbackFilter {
    fn default() -> Self {
        Self {
            geoip: true,
            geoip_code: default_geoip_code(),
            geosite: Vec::new(),
            ipcidr: Vec::new(),
            domain: Vec::new(),
        }
    }
}

/// Per-proxy default fields applied to every outbound proxy unless
/// overridden by individual profile settings.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PerProxyDefaults {
    /// Allow UDP through proxy (Mihomo default is `false`).
    #[serde(default = "default_true")]
    pub udp: bool,
    #[serde(default)]
    pub tfo: bool,
    #[serde(default)]
    pub mptcp: bool,
    #[serde(default = "default_ip_version")]
    pub ip_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smux: Option<SmuxConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dialer_proxy: Option<String>,
}

impl Default for PerProxyDefaults {
    fn default() -> Self {
        Self {
            udp: true,
            tfo: false,
            mptcp: false,
            ip_version: default_ip_version(),
            smux: None,
            dialer_proxy: None,
        }
    }
}

/// A single sub-rule group — a named set of routing rules that can be
/// referenced from the main rules via `SUB-RULE,(conditions),<name>`.
///
/// Sub-rules allow complex nested routing: the main rule set delegates
/// to a named sub-rule group, which evaluates its own rules and
/// returns the first match. If no sub-rule matches, evaluation
/// continues in the main rule set.
///
/// Example Mihomo config:
/// ```yaml
/// sub-rules:
///   ad-block:
///     - DOMAIN-SUFFIX,doubleclick.net,REJECT
///     - DOMAIN-SUFFIX,googleadservices.com,REJECT
///     - MATCH,PROXY
/// rules:
///   - GEOSITE,category-ads,SUB-RULE,(>ad-block)
/// ```
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct SubRuleConfig {
    /// Name of the sub-rule group — referenced in main rules.
    pub name: String,
    /// Rules in this group (Mihomo rule strings).
    #[serde(default)]
    pub rules: Vec<String>,
}

/// All Mihomo-specific opt-in features. Stored in `HincyrayState` and
/// persisted to `state.json`. Passed to `build_mihomo_config` and
/// `build_mihomo_router_config`.
///
/// Defaults are tuned for a resource-constrained router (Keenetic Giga
/// KN-1012, 496 MB RAM, aarch64, kernel 4.9):
/// - `geodata-loader = memconservative` — on-demand GEO loading.
/// - `unified-delay = true` — RTT-based latency.
/// - `store-fake-ip / store-selected = true` — persist across restarts.
/// - `keep-alive-interval = 30, keep-alive-idle = 120` — router-tuned.
/// - `dns-cache-algorithm = arc` — better hit rate than LRU.
/// - `per-proxy.udp = true` — UDP is needed for QUIC/DNS.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MihomoFeatures {
    // --- Global config ---
    #[serde(default = "default_geodata_loader")]
    pub geodata_loader: String,
    #[serde(default = "default_true")]
    pub unified_delay: bool,
    #[serde(default = "default_true")]
    pub store_fake_ip: bool,
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

    // --- Authentication ---
    #[serde(default)]
    pub authentication: Vec<String>,
    #[serde(default)]
    pub skip_auth_prefixes: Vec<String>,

    // --- Hosts ---
    #[serde(default)]
    pub hosts: HashMap<String, String>,

    // --- Tunnels ---
    #[serde(default)]
    pub tunnels: Vec<TunnelConfig>,

    // --- NTP ---
    #[serde(default)]
    pub ntp: NtpConfig,

    // --- External Controller ---
    #[serde(default)]
    pub external_controller: ExternalControllerConfig,

    // --- Proxy Groups ---
    #[serde(default)]
    pub proxy_group: ProxyGroupConfig,

    // --- Proxy Providers ---
    #[serde(default)]
    pub proxy_providers: Vec<ProxyProviderConfig>,

    // --- Rule Providers ---
    #[serde(default)]
    pub rule_providers: Vec<RuleProviderConfig>,

    // --- Sub-rules ---
    #[serde(default)]
    pub sub_rules: Vec<SubRuleConfig>,

    // --- Per-proxy defaults ---
    #[serde(default)]
    pub per_proxy: PerProxyDefaults,

    // --- DNS extra ---
    #[serde(default = "default_dns_cache_algorithm")]
    pub dns_cache_algorithm: String,
    #[serde(default)]
    pub dns_prefer_h3: bool,
    #[serde(default)]
    pub dns_respect_rules: bool,
    #[serde(default)]
    pub dns_proxy_server_nameserver: Vec<String>,
    #[serde(default)]
    pub dns_direct_nameserver: Vec<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_use_hosts: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_use_system_hosts: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_ecs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_ecs_override: Option<bool>,
    #[serde(default)]
    pub dns_disable_ipv4: bool,
    #[serde(default)]
    pub dns_disable_ipv6: bool,
    #[serde(default)]
    pub dns_disable_qtypes: Vec<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_fallback_filter: Option<FallbackFilter>,

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

    // --- Raw rules ---
    /// Raw Mihomo rule strings appended before MATCH (e.g. AND/OR/NOT
    /// logic rules that can't be expressed via the domain/ip/port model).
    #[serde(default)]
    pub raw_rules: Vec<String>,
    #[serde(default)]
    pub typed_rules: Vec<MihomoRuleConfig>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MihomoRuleConfig {
    pub rule_type: String,
    pub value: String,
    pub target: String,
    #[serde(default)]
    pub options: Vec<String>,
}

impl Default for MihomoFeatures {
    fn default() -> Self {
        Self {
            geodata_loader: default_geodata_loader(),
            unified_delay: true,
            store_fake_ip: true,
            store_selected: true,
            keep_alive_interval: default_keep_alive_interval(),
            keep_alive_idle: default_keep_alive_idle(),
            disable_keep_alive: false,
            tcp_concurrent: false,
            quic_go_disable_gso: false,
            quic_go_disable_ecn: false,
            authentication: Vec::new(),
            skip_auth_prefixes: Vec::new(),
            hosts: HashMap::new(),
            tunnels: Vec::new(),
            ntp: NtpConfig::default(),
            external_controller: ExternalControllerConfig::default(),
            proxy_group: ProxyGroupConfig::default(),
            proxy_providers: Vec::new(),
            rule_providers: Vec::new(),
            sub_rules: Vec::new(),
            per_proxy: PerProxyDefaults::default(),
            dns_cache_algorithm: default_dns_cache_algorithm(),
            dns_prefer_h3: false,
            dns_respect_rules: false,
            dns_proxy_server_nameserver: Vec::new(),
            dns_direct_nameserver: Vec::new(),
            dns_nameserver_policy: HashMap::new(),
            dns_default_nameserver: Vec::new(),
            dns_proxy_server_nameserver_policy: HashMap::new(),
            dns_direct_nameserver_follow_policy: None,
            dns_fake_ip_filter_mode: None,
            dns_fake_ip_filter: Vec::new(),
            dns_fake_ip_ttl: None,
            dns_use_hosts: None,
            dns_use_system_hosts: None,
            dns_ecs: None,
            dns_ecs_override: None,
            dns_disable_ipv4: false,
            dns_disable_ipv6: false,
            dns_disable_qtypes: Vec::new(),
            dns_fallback_filter: None,
            sniffer_override_destination: true,
            sniffer_force_domain: Vec::new(),
            sniffer_skip_domain: Vec::new(),
            sniffer_skip_src_address: Vec::new(),
            sniffer_skip_dst_address: Vec::new(),
            raw_rules: Vec::new(),
            typed_rules: Vec::new(),
        }
    }
}

// --- Serde default helpers ---

fn default_true() -> bool {
    true
}

fn default_geodata_loader() -> String {
    "memconservative".to_owned()
}

fn default_keep_alive_interval() -> u32 {
    30
}

fn default_keep_alive_idle() -> u32 {
    120
}

fn default_dns_cache_algorithm() -> String {
    "arc".to_owned()
}

fn default_ip_version() -> String {
    "dual".to_owned()
}

fn default_ntp_server() -> String {
    "time.apple.com".to_owned()
}

fn default_ntp_port() -> u16 {
    123
}

fn default_ntp_interval() -> u32 {
    30
}

fn default_external_controller_addr() -> String {
    "127.0.0.1:9090".to_owned()
}

fn default_health_check_url() -> String {
    "https://www.gstatic.com/generate_204".to_owned()
}

fn default_health_check_interval() -> u32 {
    300
}

fn default_health_check_timeout() -> u32 {
    5000
}

fn default_max_failed_times() -> u32 {
    5
}

fn default_provider_type() -> String {
    "http".to_owned()
}

fn default_provider_interval() -> u32 {
    3600
}

fn default_rule_behavior() -> String {
    "classical".to_owned()
}

fn default_rule_format() -> String {
    "yaml".to_owned()
}

fn default_geoip_code() -> String {
    "CN".to_owned()
}

fn default_smux_protocol() -> String {
    "h2mux".to_owned()
}

/// Tag/name constants used in generated Mihomo configs.
pub const PROXY_NAME: &str = "proxy";
pub const PROXY_ACTIVE_NAME: &str = "proxy-active";
pub const DIRECT_NAME: &str = "DIRECT";
pub const REJECT_NAME: &str = "REJECT";
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
/// Adds: `geodata-loader`, `unified-delay`, `profile.store-*`,
/// `keep-alive-*`, `experimental`, `authentication`, `skip-auth-prefixes`,
/// `hosts`, `tunnels`, `ntp`, `external-controller`.
fn apply_global_features(config: &mut Value, features: &MihomoFeatures) {
    config["geodata-loader"] = json!(features.geodata_loader);
    config["unified-delay"] = json!(features.unified_delay);

    // profile.store-* — persist fake-ip map and group selections
    let mut profile = json!({});
    if features.store_fake_ip {
        profile["store-fake-ip"] = json!(true);
    }
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

    if !features.authentication.is_empty() {
        config["authentication"] = json!(features.authentication);
    }
    if !features.skip_auth_prefixes.is_empty() {
        config["skip-auth-prefixes"] = json!(features.skip_auth_prefixes);
    }

    if !features.hosts.is_empty() {
        config["hosts"] = json!(features.hosts);
    }

    if !features.tunnels.is_empty() {
        config["tunnels"] = build_tunnels_json(&features.tunnels);
    }

    if features.ntp.enabled {
        config["ntp"] = build_ntp_json(&features.ntp);
    }

    if features.external_controller.enabled {
        config["external-controller"] = json!(features.external_controller.address);
        if let Some(secret) = &features.external_controller.secret
            && !secret.is_empty()
        {
            config["secret"] = json!(secret);
        }
        if !features.external_controller.allow_origins.is_empty()
            || features.external_controller.allow_private_network
        {
            let mut cors = json!({});
            if !features.external_controller.allow_origins.is_empty() {
                cors["allow-origins"] = json!(features.external_controller.allow_origins);
            }
            if features.external_controller.allow_private_network {
                cors["allow-private-network"] = json!(true);
            }
            config["external-controller-cors"] = cors;
        }
    }
}

/// Apply per-proxy default fields (udp, tfo, mptcp, ip-version, smux,
/// dialer-proxy) to a proxy JSON object.
fn apply_per_proxy_fields(proxy: &mut Value, features: &MihomoFeatures) {
    let pp = &features.per_proxy;
    if pp.udp {
        proxy["udp"] = json!(true);
    }
    if pp.tfo {
        proxy["tfo"] = json!(true);
    }
    if pp.mptcp {
        proxy["mptcp"] = json!(true);
    }
    if pp.ip_version != "dual" {
        proxy["ip-version"] = json!(pp.ip_version);
    }
    // smux is incompatible with flow-based proxies (xtls-rprx-vision etc.)
    // because flow requires raw TCP passthrough for TLS splicing, while
    // smux multiplexes streams and breaks the TLS handshake.
    let has_flow = proxy
        .get("flow")
        .and_then(Value::as_str)
        .is_some_and(|f| !f.is_empty());
    if let Some(smux) = &pp.smux
        && smux.enabled
        && !has_flow
    {
        proxy["smux"] = build_smux_json(smux);
    }
    if let Some(dialer) = &pp.dialer_proxy
        && !dialer.is_empty()
    {
        proxy["dialer-proxy"] = json!(dialer);
    }
}

/// Build the `smux` JSON object from `SmuxConfig`.
fn build_smux_json(smux: &SmuxConfig) -> Value {
    let mut s = json!({
        "enabled": true,
        "protocol": smux.protocol,
        "statistic": smux.statistic,
        "only-tcp": smux.only_tcp,
        "padding": smux.padding,
    });
    if smux.max_connections > 0 {
        s["max-connections"] = json!(smux.max_connections);
    }
    if smux.min_streams > 0 {
        s["min-streams"] = json!(smux.min_streams);
    }
    if smux.max_streams > 0 {
        s["max-streams"] = json!(smux.max_streams);
    }
    if smux.brutal_up.is_some() || smux.brutal_down.is_some() {
        let mut brutal = json!({"enabled": true});
        if let Some(up) = smux.brutal_up {
            brutal["up"] = json!(up);
        }
        if let Some(down) = smux.brutal_down {
            brutal["down"] = json!(down);
        }
        s["brutal-opts"] = brutal;
    }
    s
}

/// Build the `ntp` JSON object from `NtpConfig`.
fn build_ntp_json(ntp: &NtpConfig) -> Value {
    let mut n = json!({
        "enable": true,
        "server": ntp.server,
        "port": ntp.port,
        "interval": ntp.interval,
    });
    if ntp.write_to_system {
        n["write-to-system"] = json!(true);
    }
    if let Some(dp) = &ntp.dialer_proxy
        && !dp.is_empty()
    {
        n["dialer-proxy"] = json!(dp);
    }
    n
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

/// Build the `proxy-providers` JSON object from a list of configs.
fn build_proxy_providers_json(providers: &[ProxyProviderConfig]) -> Value {
    let mut map = serde_json::Map::new();
    for p in providers {
        let mut entry = json!({
            "type": p.provider_type,
            "interval": p.interval,
        });
        if let Some(url) = &p.url {
            entry["url"] = json!(url);
        }
        if let Some(path) = &p.path {
            entry["path"] = json!(path);
        }
        if let Some(proxy) = &p.proxy {
            entry["proxy"] = json!(proxy);
        }
        if let Some(filter) = &p.filter {
            entry["filter"] = json!(filter);
        }
        if let Some(exclude) = &p.exclude_filter {
            entry["exclude-filter"] = json!(exclude);
        }
        if let Some(exclude_type) = &p.exclude_type {
            entry["exclude-type"] = json!(exclude_type);
        }
        if p.health_check_enabled {
            let mut hc = json!({
                "enable": true,
                "url": p.health_check_url,
                "interval": p.health_check_interval,
                "timeout": p.health_check_timeout,
                "lazy": p.health_check_lazy,
            });
            if let Some(status) = &p.health_check_expected_status {
                hc["expected-status"] = json!(status);
            }
            entry["health-check"] = hc;
        }
        if let Some(key) = &p.age_secret_key {
            entry["age-secret-key"] = json!(key);
        }
        if !p.header.is_empty() {
            entry["header"] = json!(p.header);
        }
        if p.size_limit > 0 {
            entry["size-limit"] = json!(p.size_limit);
        }
        if !p.payload.is_empty() {
            entry["payload"] = json!(p.payload);
        }
        map.insert(p.name.clone(), entry);
    }
    Value::Object(map)
}

/// Build the `rule-providers` JSON object from a list of configs.
fn build_rule_providers_json(providers: &[RuleProviderConfig]) -> Result<Value, String> {
    let mut map = serde_json::Map::new();
    for r in providers {
        if map.contains_key(&r.name) {
            return Err(format!("duplicate rule provider name {:?}", r.name));
        }
        let mut entry = json!({
            "type": r.provider_type,
            "behavior": r.behavior,
            "format": r.format,
            "interval": r.interval,
        });
        if let Some(url) = &r.url {
            entry["url"] = json!(url);
        }
        if let Some(path) = &r.path {
            entry["path"] = json!(path);
        }
        if let Some(proxy) = &r.proxy {
            entry["proxy"] = json!(proxy);
        }
        if let Some(pib) = &r.path_in_bundle {
            entry["path-in-bundle"] = json!(pib);
        }
        if r.size_limit > 0 {
            entry["size-limit"] = json!(r.size_limit);
        }
        if !r.header.is_empty() {
            entry["header"] = json!(r.header);
        }
        if !r.payload.is_empty() {
            entry["payload"] = json!(r.payload);
        }
        map.insert(r.name.clone(), entry);
    }
    Ok(Value::Object(map))
}

fn merge_router_rule_providers(
    providers: &[RuleProviderConfig],
    managed: &[GeoBaseRuleProvider],
    mihomo_home: Option<&str>,
) -> Result<Option<Value>, String> {
    let mut map = build_rule_providers_json(providers)?
        .as_object()
        .cloned()
        .unwrap_or_default();
    let mut names: HashSet<String> = map.keys().cloned().collect();
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

    for provider in providers
        .iter()
        .filter(|provider| provider.provider_type == "file")
    {
        let Some(path) = provider.path.as_deref() else {
            continue;
        };
        if let Some(effective) =
            effective_provider_path(path, home.as_deref(), lexical_home.as_deref())
        {
            insert_effective_provider_path(&mut effective_paths, effective, &provider.name)?;
        }
    }

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

/// Build the `sub-rules` JSON object from a list of `SubRuleConfig`.
///
/// Each sub-rule group becomes a named key with an array of rule strings.
fn build_sub_rules_json(sub_rules: &[SubRuleConfig]) -> Value {
    let mut map = serde_json::Map::new();
    for sr in sub_rules {
        if sr.name.is_empty() || sr.rules.is_empty() {
            continue;
        }
        map.insert(sr.name.clone(), json!(sr.rules));
    }
    Value::Object(map)
}

/// Build a proxy-groups JSON array.
///
/// When proxy groups are enabled, the active profile and all extra
/// profiles become individual proxies (named `profile-0`, `profile-1`,
/// etc.), and a proxy group named `proxy` (so existing rules still
/// work) wraps them with auto-select / failover / load-balance.
fn build_proxy_groups_json(
    group_config: &ProxyGroupConfig,
    proxy_names: &[String],
    extra_group_names: &[String],
) -> Option<Value> {
    if !group_config.enabled || proxy_names.is_empty() {
        return None;
    }

    let mut group = json!({
        "name": PROXY_NAME,
        "url": group_config.url,
        "interval": group_config.interval,
        "timeout": group_config.timeout,
        "lazy": group_config.lazy,
        "max-failed-times": group_config.max_failed_times,
    });

    let group_type_str = match group_config.group_type {
        ProxyGroupType::Select => "select",
        ProxyGroupType::UrlTest => "url-test",
        ProxyGroupType::Fallback => "fallback",
        ProxyGroupType::LoadBalance => "load-balance",
        ProxyGroupType::Relay => "relay",
    };
    group["type"] = json!(group_type_str);

    // DIRECT is included in "select" groups (user can manually choose
    // it) and as a last-resort in "fallback" groups (so traffic goes
    // direct when all proxies are unreachable, preventing storms).
    // In url-test / load-balance groups DIRECT is excluded because it
    // would always win the latency test (direct is always faster than
    // any VPN), defeating the purpose of the group.
    let mut proxies = Vec::new();
    if group_config.group_type == ProxyGroupType::Select {
        proxies.push(DIRECT_NAME.to_owned());
    }
    proxies.extend(proxy_names.iter().cloned());
    proxies.extend(extra_group_names.iter().cloned());
    if group_config.group_type == ProxyGroupType::Fallback {
        proxies.push(DIRECT_NAME.to_owned());
    }
    group["proxies"] = json!(proxies);

    if group_config.group_type == ProxyGroupType::UrlTest {
        group["tolerance"] = json!(group_config.tolerance);
    }

    if group_config.group_type == ProxyGroupType::LoadBalance {
        let strategy_str = match group_config.strategy {
            LoadBalanceStrategy::RoundRobin => "round-robin",
            LoadBalanceStrategy::ConsistentHashing => "consistent-hashing",
            LoadBalanceStrategy::StickySessions => "sticky-sessions",
        };
        group["strategy"] = json!(strategy_str);
    }

    if let Some(status) = &group_config.expected_status {
        group["expected-status"] = json!(status);
    }

    // Node filtering by name regex or proxy type.
    if let Some(filter) = &group_config.filter
        && !filter.is_empty()
    {
        group["filter"] = json!(filter);
    }
    if let Some(exclude) = &group_config.exclude_filter
        && !exclude.is_empty()
    {
        group["exclude-filter"] = json!(exclude);
    }
    if let Some(exclude_type) = &group_config.exclude_type
        && !exclude_type.is_empty()
    {
        group["exclude-type"] = json!(exclude_type);
    }

    // Auto-include all nodes from all proxy-providers.
    if group_config.include_all_providers {
        group["include-all-providers"] = json!(true);
    }
    // Include all proxies AND all proxy-providers (sorted by name).
    if group_config.include_all {
        group["include-all"] = json!(true);
    }
    // Include all proxies only (no providers), sorted by name.
    if group_config.include_all_proxies {
        group["include-all-proxies"] = json!(true);
    }

    Some(json!([group]))
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
    let mut rules: Vec<String> = features
        .typed_rules
        .iter()
        .filter_map(mihomo_typed_rule_to_string)
        .collect();
    rules.extend(features.raw_rules.iter().filter(|r| !r.is_empty()).cloned());
    rules.push(format!("MATCH,{}", PROXY_NAME));
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

    // Sub-rules — named rule groups referenced via SUB-RULE rule type.
    if !features.sub_rules.is_empty() {
        let sub_rules = build_sub_rules_json(&features.sub_rules);
        if sub_rules.as_object().is_some_and(|m| !m.is_empty()) {
            config["sub-rules"] = sub_rules;
        }
    }

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
    // When the user has explicitly enabled proxy groups (url-test /
    // fallback / load-balance / select), those groups are used instead
    // and the direct-fallback is merged into them.
    let active_proxy_name = PROXY_ACTIVE_NAME.to_owned();

    let proxy_provider_names: HashSet<&str> = features
        .proxy_providers
        .iter()
        .map(|provider| provider.name.as_str())
        .collect();
    let mut internal_names: HashSet<&str> =
        [PROXY_ACTIVE_NAME, PROXY_NAME, DIRECT_NAME, REJECT_NAME]
            .into_iter()
            .collect();
    for (_, name) in extra_profiles {
        if name.trim().is_empty() || !internal_names.insert(name) {
            return Err(format!("duplicate or empty proxy/group name {name:?}"));
        }
        if proxy_provider_names.contains(name.as_str()) {
            return Err(format!("proxy name collides with provider {name:?}"));
        }
    }
    for route in pinned_server_routes {
        for name in [route.outbound_name.as_str(), route.group_name.as_str()] {
            if name.trim().is_empty() || !internal_names.insert(name) {
                return Err(format!("duplicate or empty proxy/group name {name:?}"));
            }
            if proxy_provider_names.contains(name) {
                return Err(format!("proxy/group name collides with provider {name:?}"));
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

    // First-class extra Mihomo rules and user-defined raw Mihomo rules
    // inserted before port-mode fallbacks and MATCH.
    rules.extend(
        features
            .typed_rules
            .iter()
            .filter_map(mihomo_typed_rule_to_string),
    );
    rules.extend(features.raw_rules.iter().filter(|r| !r.is_empty()).cloned());

    // Explicit VPN exceptions override all broad RU Direct rules.
    for domain in extra
        .auto_vpn_exceptions
        .iter()
        .map(|d| d.trim())
        .filter(|d| !d.is_empty())
    {
        rules.push(format!("DOMAIN-SUFFIX,{domain},{}", PROXY_NAME));
    }

    // GeoBase ACTIVE providers must take precedence over broad DIRECT sets.
    for target in [GeoBaseRuleTarget::Active, GeoBaseRuleTarget::Direct] {
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

    // Proxy groups — wraps all profiles in an auto-select / failover /
    // load-balance group named "proxy" (so existing rules still work).
    if features.proxy_group.enabled {
        let proxy_names: Vec<String> = std::iter::once(active_proxy_name.clone())
            .chain(extra_profiles.iter().map(|(_, name)| name.clone()))
            .collect();
        if let Some(groups) = build_proxy_groups_json(&features.proxy_group, &proxy_names, &[]) {
            config["proxy-groups"] = groups;
        }
    } else {
        // Direct-fallback: when proxy groups are not explicitly enabled,
        // wrap the single active proxy in a `fallback` group with DIRECT
        // as the last resort. This prevents connection storms when the
        // upstream proxy is unreachable — mihomo automatically routes
        // traffic direct instead of timing out every connection.
        config["proxy-groups"] = json!([{
            "name": PROXY_NAME,
            "type": "fallback",
            "proxies": [active_proxy_name, DIRECT_NAME],
            "url": FALLBACK_HEALTH_URL,
            "interval": 10,
            "timeout": 3000,
        }]);
    }

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

    // Proxy providers — Mihomo fetches subscriptions itself.
    if !features.proxy_providers.is_empty() {
        config["proxy-providers"] = build_proxy_providers_json(&features.proxy_providers);
        // If proxy groups are enabled, add `use` to reference providers.
        if let Some(groups) = config
            .get_mut("proxy-groups")
            .and_then(|g| g.as_array_mut())
            && let Some(first_group) = groups.first_mut()
        {
            let provider_names: Vec<String> = features
                .proxy_providers
                .iter()
                .map(|p| p.name.clone())
                .collect();
            first_group["use"] = json!(provider_names);
        }
    }

    // Rule providers — user-defined entries plus validated local GeoBase sets.
    if let Some(providers) = merge_router_rule_providers(
        &features.rule_providers,
        &extra.geobase_rule_providers,
        extra.mihomo_home.as_deref(),
    )? {
        config["rule-providers"] = providers;
    }

    // Sub-rules — named rule groups referenced via SUB-RULE rule type.
    if !features.sub_rules.is_empty() {
        let sub_rules = build_sub_rules_json(&features.sub_rules);
        if sub_rules.as_object().is_some_and(|m| !m.is_empty()) {
            config["sub-rules"] = sub_rules;
        }
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
/// Feature-enhanced DNS options (cache-algorithm, proxy-server-nameserver,
/// direct-nameserver, prefer-h3, respect-rules, fallback-filter) are
/// applied from `MihomoFeatures`.
fn build_dns_config(dns: &crate::xray_config::DnsSettings, features: &MihomoFeatures) -> Value {
    let mut dns_config = json!({
        "enable": true,
        "listen": format!("0.0.0.0:{}", DNS_INBOUND_PORT),
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "fake-ip-filter": features.dns_fake_ip_filter,
        "cache-algorithm": features.dns_cache_algorithm,
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
    if let Some(use_hosts) = features.dns_use_hosts {
        dns_config["use-hosts"] = json!(use_hosts);
    }
    if let Some(use_system_hosts) = features.dns_use_system_hosts {
        dns_config["use-system-hosts"] = json!(use_system_hosts);
    }
    if features.dns_respect_rules {
        dns_config["respect-rules"] = json!(true);
    }
    if !features.dns_proxy_server_nameserver.is_empty() {
        dns_config["proxy-server-nameserver"] = json!(features.dns_proxy_server_nameserver);
    }
    let direct_nameservers = if features.dns_direct_nameserver.is_empty() {
        &dns.local_servers
    } else {
        &features.dns_direct_nameserver
    };
    if !direct_nameservers.is_empty() {
        dns_config["direct-nameserver"] = json!(direct_nameservers);
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
    if let Some(ecs) = &features.dns_ecs
        && !ecs.is_empty()
    {
        dns_config["ecs"] = json!(ecs);
    }
    if let Some(override_ecs) = features.dns_ecs_override {
        dns_config["ecs-override"] = json!(override_ecs);
    }
    if features.dns_disable_ipv4 {
        dns_config["disable-ipv4"] = json!(true);
    }
    if features.dns_disable_ipv6 {
        dns_config["disable-ipv6"] = json!(true);
    }
    for qtype in &features.dns_disable_qtypes {
        dns_config[format!("disable-qtype-{qtype}")] = json!(true);
    }
    if let Some(filter) = &features.dns_fallback_filter {
        let mut ff = json!({});
        if filter.geoip {
            ff["geoip"] = json!(true);
        }
        ff["geoip-code"] = json!(filter.geoip_code);
        if !filter.geosite.is_empty() {
            ff["geosite"] = json!(filter.geosite);
        }
        if !filter.ipcidr.is_empty() {
            ff["ipcidr"] = json!(filter.ipcidr);
        }
        if !filter.domain.is_empty() {
            ff["domain"] = json!(filter.domain);
        }
        dns_config["fallback-filter"] = ff;
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

            // ── Advanced xhttp fields (anti-DPI / XMUX / session) ──

            // no-grpc-header
            if is_truthy_option(
                query_value_multi(&url, &["noGRPCHeader", "no_grpc_header", "no-grpc-header"])
                    .as_deref(),
            ) {
                xhttp_opts["no-grpc-header"] = json!(true);
            }

            // x-padding-* fields
            if let Some(v) = query_value_multi(
                &url,
                &["xPaddingBytes", "x_padding_bytes", "x-padding-bytes"],
            ) {
                xhttp_opts["x-padding-bytes"] = json!(v);
            }
            if let Some(v) = query_value_multi(&url, &["xPaddingObfsMode", "x_padding_obfs_mode"]) {
                xhttp_opts["x-padding-obfs-mode"] = json!(v);
            }
            if let Some(v) = query_value_multi(&url, &["xPaddingKey", "x_padding_key"]) {
                xhttp_opts["x-padding-key"] = json!(v);
            }
            if let Some(v) = query_value_multi(&url, &["xPaddingHeader", "x_padding_header"]) {
                xhttp_opts["x-padding-header"] = json!(v);
            }
            if let Some(v) = query_value_multi(&url, &["xPaddingPlacement", "x_padding_placement"])
            {
                xhttp_opts["x-padding-placement"] = json!(v);
            }
            if let Some(v) = query_value_multi(&url, &["xPaddingMethod", "x_padding_method"]) {
                xhttp_opts["x-padding-method"] = json!(v);
            }

            // uplink-http-method
            if let Some(v) = query_value_multi(
                &url,
                &[
                    "uplinkHttpMethod",
                    "uplink_http_method",
                    "uplink-http-method",
                ],
            ) {
                xhttp_opts["uplink-http-method"] = json!(v);
            }

            // session-* fields
            if let Some(v) = query_value_multi(&url, &["sessionPlacement", "session_placement"]) {
                xhttp_opts["session-placement"] = json!(v);
            }
            if let Some(v) = query_value_multi(&url, &["sessionKey", "session_key"]) {
                xhttp_opts["session-key"] = json!(v);
            }

            // seq-* fields
            if let Some(v) = query_value_multi(&url, &["seqPlacement", "seq_placement"]) {
                xhttp_opts["seq-placement"] = json!(v);
            }
            if let Some(v) = query_value_multi(&url, &["seqKey", "seq_key"]) {
                xhttp_opts["seq-key"] = json!(v);
            }

            // uplink-data-* fields
            if let Some(v) =
                query_value_multi(&url, &["uplinkDataPlacement", "uplink_data_placement"])
            {
                xhttp_opts["uplink-data-placement"] = json!(v);
            }
            if let Some(v) = query_value_multi(&url, &["uplinkDataKey", "uplink_data_key"]) {
                xhttp_opts["uplink-data-key"] = json!(v);
            }

            // uplink-chunk-size (integer)
            if let Some(v) = query_value_multi(&url, &["uplinkChunkSize", "uplink_chunk_size"])
                .and_then(|s| s.parse::<u32>().ok())
            {
                xhttp_opts["uplink-chunk-size"] = json!(v);
            }

            // sc-max-each-post-bytes (integer, stream-up mode)
            if let Some(v) =
                query_value_multi(&url, &["scMaxEachPostBytes", "sc_max_each_post_bytes"])
                    .and_then(|s| s.parse::<u32>().ok())
            {
                xhttp_opts["sc-max-each-post-bytes"] = json!(v);
            }

            // sc-min-posts-interval-ms (integer, stream-up mode)
            if let Some(v) =
                query_value_multi(&url, &["scMinPostsIntervalMs", "sc_min_posts_interval_ms"])
                    .and_then(|s| s.parse::<u32>().ok())
            {
                xhttp_opts["sc-min-posts-interval-ms"] = json!(v);
            }

            // reuse-settings (XMUX-like connection reuse)
            let mut reuse = json!({});
            if let Some(v) =
                query_value_multi(&url, &["xmuxMaxConcurrency", "xmux_max_concurrency"])
                    .and_then(|s| s.parse::<u32>().ok())
            {
                reuse["max-concurrency"] = json!(v);
            }
            if let Some(v) =
                query_value_multi(&url, &["xmuxMaxConnections", "xmux_max_connections"])
                    .and_then(|s| s.parse::<u32>().ok())
            {
                reuse["max-connections"] = json!(v);
            }
            if let Some(v) =
                query_value_multi(&url, &["xmuxCMaxReuseTimes", "xmux_c_max_reuse_times"])
                    .and_then(|s| s.parse::<u32>().ok())
            {
                reuse["c-max-reuse-times"] = json!(v);
            }
            if let Some(v) =
                query_value_multi(&url, &["xmuxHMaxRequestTimes", "xmux_h_max_request_times"])
                    .and_then(|s| s.parse::<u32>().ok())
            {
                reuse["h-max-request-times"] = json!(v);
            }
            if let Some(v) =
                query_value_multi(&url, &["xmuxHMaxReusableSecs", "xmux_h_max_reusable_secs"])
                    .and_then(|s| s.parse::<u32>().ok())
            {
                reuse["h-max-reusable-secs"] = json!(v);
            }
            if let Some(v) =
                query_value_multi(&url, &["xmuxHKeepAlivePeriod", "xmux_h_keep_alive_period"])
                    .and_then(|s| s.parse::<u32>().ok())
            {
                reuse["h-keep-alive-period"] = json!(v);
            }
            if reuse.as_object().is_some_and(|m| !m.is_empty()) {
                xhttp_opts["reuse-settings"] = reuse;
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

fn mihomo_typed_rule_to_string(rule: &MihomoRuleConfig) -> Option<String> {
    let rule_type = rule.rule_type.trim().to_ascii_uppercase();
    let value = rule.value.trim();
    let target = outbound_tag_to_name(rule.target.trim());
    if rule_type.is_empty() || value.is_empty() || target.is_empty() {
        return None;
    }
    let mut parts = vec![rule_type, value.to_owned(), target];
    parts.extend(rule.options.iter().filter(|item| !item.is_empty()).cloned());
    Some(parts.join(","))
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
        ExternalControllerConfig, FALLBACK_HEALTH_URL, FallbackFilter, LoadBalanceStrategy,
        MihomoFeatures, NtpConfig, PROXY_ACTIVE_NAME, PROXY_NAME, PerProxyDefaults,
        PinnedServerRoute, ProxyGroupConfig, ProxyGroupType, ProxyProviderConfig, REDIR_LISTENER,
        RuleProviderConfig, SmuxConfig, SubRuleConfig, TPROXY_LISTENER, TunnelConfig,
        build_anytls_proxy, build_http_proxy, build_hysteria_proxy, build_hysteria2_proxy,
        build_masque_proxy, build_mihomo_bench_config, build_mihomo_config,
        build_mihomo_router_config, build_openvpn_proxy, build_shadowsocks_proxy,
        build_shadowsocksr_proxy, build_snell_proxy, build_socks_proxy, build_ssh_proxy,
        build_tailscale_proxy, build_trojan_proxy, build_tuic_proxy, build_vless_proxy,
        build_vmess_proxy, build_wireguard_proxy, domain_rule_body, ip_rule_body,
    };
    use crate::profiles::parse_profiles;
    use crate::xray_config::{
        DnsSettings, GeoBaseRuleBehavior, GeoBaseRuleProvider, GeoBaseRuleTarget, PortMode,
        QuicMode, RouterExtra, XrayRouteRule,
    };
    use base64::Engine as _;
    use serde_json::{Value, json};

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
        let mut features = MihomoFeatures::default();
        features.proxy_group.enabled = true;
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
            &features,
        )
        .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        let groups = config["proxy-groups"].as_array().expect("groups");
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0]["name"], PROXY_NAME);
        assert_eq!(
            groups[0]["proxies"],
            json!([PROXY_ACTIVE_NAME, "candidate"])
        );
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

    // --- Authentication tests ---

    #[test]
    fn authentication_added_when_configured() {
        let mut features = default_features();
        features.authentication = vec!["user1:pass1".to_owned()];
        features.skip_auth_prefixes = vec!["127.0.0.1/8".to_owned()];
        let config = build_test_router_config(&features);
        assert_eq!(
            config
                .get("authentication")
                .and_then(Value::as_array)
                .expect("authentication")[0]
                .as_str(),
            Some("user1:pass1")
        );
        assert_eq!(
            config
                .get("skip-auth-prefixes")
                .and_then(Value::as_array)
                .expect("skip-auth-prefixes")[0]
                .as_str(),
            Some("127.0.0.1/8")
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

    // --- NTP tests ---

    #[test]
    fn ntp_section_added_when_enabled() {
        let mut features = default_features();
        features.ntp = NtpConfig {
            enabled: true,
            write_to_system: true,
            server: "pool.ntp.org".to_owned(),
            port: 123,
            interval: 60,
            dialer_proxy: None,
        };
        let config = build_test_router_config(&features);
        let ntp = config.get("ntp").expect("ntp");
        assert_eq!(ntp.get("enable").and_then(Value::as_bool), Some(true));
        assert_eq!(
            ntp.get("server").and_then(Value::as_str),
            Some("pool.ntp.org")
        );
        assert_eq!(
            ntp.get("write-to-system").and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn ntp_section_omitted_when_disabled() {
        let config = build_test_router_config(&default_features());
        assert!(config.get("ntp").is_none());
    }

    // --- External controller tests ---

    #[test]
    fn external_controller_added_when_enabled() {
        let mut features = default_features();
        features.external_controller = ExternalControllerConfig {
            enabled: true,
            address: "0.0.0.0:9090".to_owned(),
            secret: Some("test-secret".to_owned()),
            allow_origins: vec!["*".to_owned()],
            allow_private_network: true,
        };
        let config = build_test_router_config(&features);
        assert_eq!(
            config.get("external-controller").and_then(Value::as_str),
            Some("0.0.0.0:9090")
        );
        assert_eq!(
            config.get("secret").and_then(Value::as_str),
            Some("test-secret")
        );
    }

    #[test]
    fn external_controller_omitted_when_disabled() {
        let config = build_test_router_config(&default_features());
        assert!(config.get("external-controller").is_none());
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
    fn dns_includes_proxy_server_nameserver_when_configured() {
        let mut features = default_features();
        features.dns_proxy_server_nameserver = vec!["223.5.5.5".to_owned()];
        let config = build_test_router_config(&features);
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
    fn dns_includes_direct_nameserver_when_configured() {
        let mut features = default_features();
        features.dns_direct_nameserver = vec!["system".to_owned()];
        let config = build_test_router_config(&features);
        let dns = config.get("dns").expect("dns");
        assert_eq!(
            dns.get("direct-nameserver")
                .and_then(Value::as_array)
                .expect("direct-nameserver")[0]
                .as_str(),
            Some("system")
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

    #[test]
    fn dns_includes_fallback_filter_when_configured() {
        let mut features = default_features();
        features.dns_fallback_filter = Some(FallbackFilter {
            geoip: true,
            geoip_code: "CN".to_owned(),
            geosite: vec!["gfw".to_owned()],
            ipcidr: vec!["240.0.0.0/4".to_owned()],
            domain: vec!["+.google.com".to_owned()],
        });
        let config = build_test_router_config(&features);
        let dns = config.get("dns").expect("dns");
        let ff = dns.get("fallback-filter").expect("fallback-filter");
        assert_eq!(ff.get("geoip").and_then(Value::as_bool), Some(true));
        assert_eq!(ff.get("geoip-code").and_then(Value::as_str), Some("CN"));
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
    fn per_proxy_smux_added_when_enabled() {
        let mut features = default_features();
        features.per_proxy.smux = Some(SmuxConfig {
            enabled: true,
            protocol: "h2mux".to_owned(),
            padding: true,
            ..SmuxConfig::default()
        });
        let config = build_test_router_config(&features);
        let proxies = config
            .get("proxies")
            .and_then(Value::as_array)
            .expect("proxies");
        let smux = &proxies[0].get("smux").expect("smux");
        assert_eq!(smux.get("enabled").and_then(Value::as_bool), Some(true));
        assert_eq!(smux.get("protocol").and_then(Value::as_str), Some("h2mux"));
        assert_eq!(smux.get("padding").and_then(Value::as_bool), Some(true));
    }

    #[test]
    fn per_proxy_smux_skipped_for_flow_proxy() {
        // VLESS Reality with xtls-rprx-vision flow is incompatible with smux.
        // The config builder must skip smux for proxies that have a flow field.
        let mut features = default_features();
        features.per_proxy.smux = Some(SmuxConfig {
            enabled: true,
            protocol: "h2mux".to_owned(),
            padding: true,
            ..SmuxConfig::default()
        });
        // Build a config with a Reality+vision profile (has flow field)
        let profiles = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp&security=reality&flow=xtls-rprx-vision&pbk=AAAA&sid=00#TestReality",
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
            &features,
        )
        .expect("router config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        let proxies = config
            .get("proxies")
            .and_then(Value::as_array)
            .expect("proxies");
        // The proxy should have flow but NOT smux
        assert!(
            proxies[0].get("flow").is_some(),
            "proxy should have flow field"
        );
        assert!(
            proxies[0].get("smux").is_none(),
            "smux must NOT be applied to flow-based proxies"
        );
    }

    #[test]
    fn per_proxy_dialer_proxy_added_when_configured() {
        let mut features = default_features();
        features.per_proxy.dialer_proxy = Some("dialer-group".to_owned());
        let config = build_test_router_config(&features);
        let proxies = config
            .get("proxies")
            .and_then(Value::as_array)
            .expect("proxies");
        assert_eq!(
            proxies[0].get("dialer-proxy").and_then(Value::as_str),
            Some("dialer-group")
        );
    }

    // --- Proxy group tests ---

    #[test]
    fn proxy_group_url_test_generates_group_section() {
        let mut features = default_features();
        features.proxy_group = ProxyGroupConfig {
            enabled: true,
            group_type: ProxyGroupType::UrlTest,
            url: "https://www.gstatic.com/generate_204".to_owned(),
            interval: 300,
            tolerance: 50,
            timeout: 5000,
            lazy: true,
            max_failed_times: 5,
            strategy: LoadBalanceStrategy::default(),
            expected_status: None,
            ..ProxyGroupConfig::default()
        };
        let config = build_test_router_config(&features);
        let groups = config
            .get("proxy-groups")
            .and_then(Value::as_array)
            .expect("proxy-groups");
        assert_eq!(groups.len(), 1);
        let group = &groups[0];
        assert_eq!(group.get("name").and_then(Value::as_str), Some("proxy"));
        assert_eq!(group.get("type").and_then(Value::as_str), Some("url-test"));
        assert_eq!(group.get("tolerance").and_then(Value::as_u64), Some(50));
        // Active profile renamed to "proxy-active"
        let proxies = group
            .get("proxies")
            .and_then(Value::as_array)
            .expect("group proxies");
        // DIRECT must NOT be in url-test groups (it would always win)
        assert!(
            !proxies.iter().any(|p| p.as_str() == Some("DIRECT")),
            "DIRECT must not be in url-test groups"
        );
        assert!(proxies.iter().any(|p| p.as_str() == Some("proxy-active")));
    }

    #[test]
    fn proxy_group_select_includes_direct() {
        let mut features = default_features();
        features.proxy_group = ProxyGroupConfig {
            enabled: true,
            group_type: ProxyGroupType::Select,
            ..ProxyGroupConfig::default()
        };
        let config = build_test_router_config(&features);
        let groups = config
            .get("proxy-groups")
            .and_then(Value::as_array)
            .expect("proxy-groups");
        let proxies = groups[0]
            .get("proxies")
            .and_then(Value::as_array)
            .expect("group proxies");
        // SELECT groups should include DIRECT as a manual option
        assert!(
            proxies.iter().any(|p| p.as_str() == Some("DIRECT")),
            "SELECT groups should include DIRECT"
        );
        assert!(proxies.iter().any(|p| p.as_str() == Some("proxy-active")));
    }

    #[test]
    fn proxy_group_load_balance_includes_strategy() {
        let mut features = default_features();
        features.proxy_group = ProxyGroupConfig {
            enabled: true,
            group_type: ProxyGroupType::LoadBalance,
            strategy: LoadBalanceStrategy::RoundRobin,
            ..ProxyGroupConfig::default()
        };
        let config = build_test_router_config(&features);
        let groups = config
            .get("proxy-groups")
            .and_then(Value::as_array)
            .expect("proxy-groups");
        assert_eq!(
            groups[0].get("strategy").and_then(Value::as_str),
            Some("round-robin")
        );
    }

    #[test]
    fn proxy_group_relay_emits_relay_type() {
        let mut features = default_features();
        features.proxy_group = ProxyGroupConfig {
            enabled: true,
            group_type: ProxyGroupType::Relay,
            ..ProxyGroupConfig::default()
        };
        let config = build_test_router_config(&features);
        let groups = config
            .get("proxy-groups")
            .and_then(Value::as_array)
            .expect("proxy-groups");
        assert_eq!(groups[0].get("type").and_then(Value::as_str), Some("relay"));
        assert!(groups[0].get("proxies").is_some());
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

    // --- Proxy provider tests ---

    #[test]
    fn proxy_providers_added_when_configured() {
        let mut features = default_features();
        features.proxy_providers = vec![ProxyProviderConfig {
            name: "provider1".to_owned(),
            provider_type: "http".to_owned(),
            url: Some("https://provider.example/sub".to_owned()),
            interval: 3600,
            health_check_enabled: true,
            ..ProxyProviderConfig::default()
        }];
        let config = build_test_router_config(&features);
        let providers = config
            .get("proxy-providers")
            .and_then(Value::as_object)
            .expect("proxy-providers");
        assert!(providers.contains_key("provider1"));
        let p = &providers["provider1"];
        assert_eq!(p.get("type").and_then(Value::as_str), Some("http"));
        assert_eq!(
            p.get("url").and_then(Value::as_str),
            Some("https://provider.example/sub")
        );
        assert!(p.get("health-check").is_some());
    }

    // --- Rule provider tests ---

    #[test]
    fn rule_providers_added_when_configured() {
        let mut features = default_features();
        features.rule_providers = vec![RuleProviderConfig {
            name: "ads".to_owned(),
            provider_type: "http".to_owned(),
            url: Some("https://example.com/ads.yaml".to_owned()),
            behavior: "domain".to_owned(),
            format: "yaml".to_owned(),
            interval: 86400,
            ..RuleProviderConfig::default()
        }];
        let config = build_test_router_config(&features);
        let providers = config
            .get("rule-providers")
            .and_then(Value::as_object)
            .expect("rule-providers");
        assert!(providers.contains_key("ads"));
        let r = &providers["ads"];
        assert_eq!(r.get("behavior").and_then(Value::as_str), Some("domain"));
        assert_eq!(r.get("format").and_then(Value::as_str), Some("yaml"));
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
            geodata_loader: "standard".to_owned(),
            unified_delay: false,
            store_fake_ip: false,
            store_selected: false,
            keep_alive_interval: 60,
            keep_alive_idle: 240,
            disable_keep_alive: true,
            tcp_concurrent: true,
            quic_go_disable_gso: true,
            quic_go_disable_ecn: false,
            authentication: vec!["admin:secret".to_owned()],
            skip_auth_prefixes: vec!["10.0.0.0/8".to_owned()],
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
            ntp: NtpConfig {
                enabled: true,
                write_to_system: true,
                server: "time.cloudflare.com".to_owned(),
                port: 123,
                interval: 15,
                dialer_proxy: Some("DIRECT".to_owned()),
            },
            external_controller: ExternalControllerConfig {
                enabled: true,
                address: "0.0.0.0:9090".to_owned(),
                secret: Some("secret123".to_owned()),
                allow_origins: vec!["*".to_owned()],
                allow_private_network: true,
            },
            proxy_group: ProxyGroupConfig {
                enabled: true,
                group_type: ProxyGroupType::Fallback,
                url: "https://cp.cloudflare.com".to_owned(),
                interval: 600,
                tolerance: 100,
                timeout: 3000,
                lazy: false,
                max_failed_times: 3,
                strategy: LoadBalanceStrategy::StickySessions,
                expected_status: Some("204".to_owned()),
                ..ProxyGroupConfig::default()
            },
            proxy_providers: vec![],
            rule_providers: vec![],
            sub_rules: vec![SubRuleConfig {
                name: "ad-block".to_owned(),
                rules: vec!["DOMAIN-SUFFIX,doubleclick.net,REJECT".to_owned()],
            }],
            per_proxy: PerProxyDefaults {
                udp: false,
                tfo: true,
                mptcp: false,
                ip_version: "ipv4".to_owned(),
                smux: Some(SmuxConfig {
                    enabled: true,
                    protocol: "smux".to_owned(),
                    max_connections: 4,
                    min_streams: 4,
                    max_streams: 0,
                    statistic: true,
                    only_tcp: false,
                    padding: true,
                    brutal_up: Some(50),
                    brutal_down: Some(100),
                }),
                dialer_proxy: Some("relay".to_owned()),
            },
            dns_cache_algorithm: "lru".to_owned(),
            dns_prefer_h3: true,
            dns_respect_rules: true,
            dns_proxy_server_nameserver: vec!["223.5.5.5".to_owned()],
            dns_direct_nameserver: vec!["system".to_owned()],
            dns_nameserver_policy: {
                let mut p = std::collections::HashMap::new();
                p.insert(
                    "+.google.com".to_owned(),
                    vec!["https://dns.google/dns-query".to_owned()],
                );
                p
            },
            dns_fallback_filter: Some(FallbackFilter {
                geoip: false,
                geoip_code: "US".to_owned(),
                geosite: vec!["gfw".to_owned()],
                ipcidr: vec!["240.0.0.0/4".to_owned()],
                domain: vec!["+.google.com".to_owned()],
            }),
            sniffer_force_domain: vec!["+.test.com".to_owned()],
            sniffer_skip_domain: vec!["skip.test".to_owned()],
            sniffer_skip_src_address: vec!["192.168.1.0/24".to_owned()],
            sniffer_skip_dst_address: vec!["10.0.0.0/8".to_owned()],
            raw_rules: vec!["AND,((DOMAIN,test.com),(NETWORK,udp)),DIRECT".to_owned()],
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
        assert_eq!(features.geodata_loader, "memconservative");
        assert!(features.unified_delay);
        assert!(features.store_fake_ip);
        assert!(features.store_selected);
        assert_eq!(features.keep_alive_interval, 30);
        assert_eq!(features.keep_alive_idle, 120);
        assert_eq!(features.dns_cache_algorithm, "arc");
        assert!(features.per_proxy.udp);
        assert_eq!(features.per_proxy.ip_version, "dual");
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
        let mut features = default_features();
        features.external_controller = ExternalControllerConfig {
            enabled: true,
            address: "127.0.0.1:9090".to_owned(),
            secret: None,
            allow_origins: vec![],
            allow_private_network: false,
        };
        let yaml =
            build_mihomo_config(profile, "127.0.0.1", 10808, &features).expect("mihomo config");
        let config: Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        assert!(config.get("external-controller").is_some());
    }

    // ── Tier 1: proxy group filtering ──────────────────────────────

    #[test]
    fn proxy_group_filter_emits_filter_field() {
        let mut features = default_features();
        features.proxy_group = ProxyGroupConfig {
            enabled: true,
            filter: Some("HK|Hong Kong".to_owned()),
            ..ProxyGroupConfig::default()
        };
        let config = build_test_router_config(&features);
        let group = &config["proxy-groups"][0];
        assert_eq!(
            group.get("filter").and_then(Value::as_str),
            Some("HK|Hong Kong")
        );
    }

    #[test]
    fn proxy_group_exclude_filter_emits_exclude_filter() {
        let mut features = default_features();
        features.proxy_group = ProxyGroupConfig {
            enabled: true,
            exclude_filter: Some("REJECT|DIRECT".to_owned()),
            ..ProxyGroupConfig::default()
        };
        let config = build_test_router_config(&features);
        let group = &config["proxy-groups"][0];
        assert_eq!(
            group.get("exclude-filter").and_then(Value::as_str),
            Some("REJECT|DIRECT")
        );
    }

    #[test]
    fn proxy_group_exclude_type_emits_exclude_type() {
        let mut features = default_features();
        features.proxy_group = ProxyGroupConfig {
            enabled: true,
            exclude_type: Some("Shadowsocks|Http".to_owned()),
            ..ProxyGroupConfig::default()
        };
        let config = build_test_router_config(&features);
        let group = &config["proxy-groups"][0];
        assert_eq!(
            group.get("exclude-type").and_then(Value::as_str),
            Some("Shadowsocks|Http")
        );
    }

    #[test]
    fn proxy_group_include_all_providers_flag() {
        let mut features = default_features();
        features.proxy_group = ProxyGroupConfig {
            enabled: true,
            include_all_providers: true,
            ..ProxyGroupConfig::default()
        };
        let config = build_test_router_config(&features);
        let group = &config["proxy-groups"][0];
        assert_eq!(
            group.get("include-all-providers").and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn proxy_group_no_filter_fields_when_not_set() {
        let mut features = default_features();
        features.proxy_group = ProxyGroupConfig {
            enabled: true,
            ..ProxyGroupConfig::default()
        };
        let config = build_test_router_config(&features);
        let group = &config["proxy-groups"][0];
        assert!(group.get("filter").is_none());
        assert!(group.get("exclude-filter").is_none());
        assert!(group.get("exclude-type").is_none());
        assert!(group.get("include-all-providers").is_none());
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
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=xhttp&security=reality&pbk=pubkey&xPaddingBytes=100-1000&xPaddingObfsMode=random#Test",
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
                .and_then(Value::as_str),
            Some("random")
        );
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
            reuse.get("max-concurrency").and_then(Value::as_u64),
            Some(16)
        );
        assert_eq!(
            reuse.get("max-connections").and_then(Value::as_u64),
            Some(4)
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

    // ── Sub-rules tests ─────────────────────────────────────────────

    #[test]
    fn sub_rules_emitted_when_configured() {
        let mut features = default_features();
        features.sub_rules = vec![SubRuleConfig {
            name: "ad-block".to_owned(),
            rules: vec![
                "DOMAIN-SUFFIX,doubleclick.net,REJECT".to_owned(),
                "MATCH,PROXY".to_owned(),
            ],
        }];
        let config = build_test_router_config(&features);
        let sub_rules = config
            .get("sub-rules")
            .and_then(Value::as_object)
            .expect("sub-rules");
        assert!(sub_rules.contains_key("ad-block"));
        let rules = sub_rules["ad-block"].as_array().expect("rules array");
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn sub_rules_absent_when_empty() {
        let config = build_test_router_config(&default_features());
        assert!(config.get("sub-rules").is_none());
    }

    #[test]
    fn sub_rules_skips_empty_names() {
        let mut features = default_features();
        features.sub_rules = vec![SubRuleConfig {
            name: String::new(),
            rules: vec!["MATCH,PROXY".to_owned()],
        }];
        let config = build_test_router_config(&features);
        assert!(config.get("sub-rules").is_none());
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
        features.dns_fake_ip_filter_mode = Some("rule".to_owned());
        features.dns_fake_ip_filter = vec!["MATCH,fake-ip".to_owned()];
        features.dns_fake_ip_ttl = Some(60);
        features.dns_use_hosts = Some(false);
        features.dns_use_system_hosts = Some(false);
        features.dns_default_nameserver = vec!["1.1.1.1".to_owned()];
        features.dns_direct_nameserver_follow_policy = Some(true);
        features.dns_ecs = Some("1.2.3.0/24".to_owned());
        features.dns_ecs_override = Some(true);
        features.dns_disable_ipv4 = true;
        features.dns_disable_qtypes = vec![65];
        let mut proxy_policy = std::collections::HashMap::new();
        proxy_policy.insert("node.example.com".to_owned(), vec!["8.8.8.8".to_owned()]);
        features.dns_proxy_server_nameserver_policy = proxy_policy;

        let config = build_test_router_config(&features);
        let dns = config.get("dns").expect("dns");
        assert_eq!(
            dns.get("fake-ip-filter-mode").and_then(Value::as_str),
            Some("rule")
        );
        assert_eq!(dns.get("fake-ip-ttl").and_then(Value::as_u64), Some(60));
        assert_eq!(dns.get("use-hosts").and_then(Value::as_bool), Some(false));
        assert_eq!(
            dns.get("use-system-hosts").and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            dns.get("direct-nameserver-follow-policy")
                .and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(dns.get("ecs").and_then(Value::as_str), Some("1.2.3.0/24"));
        assert_eq!(dns.get("ecs-override").and_then(Value::as_bool), Some(true));
        assert_eq!(dns.get("disable-ipv4").and_then(Value::as_bool), Some(true));
        assert_eq!(
            dns.get("disable-qtype-65").and_then(Value::as_bool),
            Some(true)
        );
        assert!(dns.get("proxy-server-nameserver-policy").is_some());
    }

    // ── v0.11.0: Proxy group include-all / include-all-proxies ────

    #[test]
    fn proxy_group_include_all_flag() {
        let mut features = default_features();
        features.proxy_group = ProxyGroupConfig {
            enabled: true,
            include_all: true,
            ..ProxyGroupConfig::default()
        };
        let config = build_test_router_config(&features);
        let group = &config["proxy-groups"][0];
        assert_eq!(
            group.get("include-all").and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn proxy_group_include_all_proxies_flag() {
        let mut features = default_features();
        features.proxy_group = ProxyGroupConfig {
            enabled: true,
            include_all_proxies: true,
            ..ProxyGroupConfig::default()
        };
        let config = build_test_router_config(&features);
        let group = &config["proxy-groups"][0];
        assert_eq!(
            group.get("include-all-proxies").and_then(Value::as_bool),
            Some(true)
        );
    }

    // ── v0.11.0: Raw rules (AND/OR/NOT logic) ──────────────────────

    #[test]
    fn raw_rules_emitted_in_router_config() {
        let mut features = default_features();
        features.raw_rules = vec![
            "AND,((DOMAIN,baidu.com),(NETWORK,udp)),DIRECT".to_owned(),
            "NOT,((DOMAIN,baidu.com)),PROXY".to_owned(),
        ];
        let config = build_test_router_config(&features);
        let rules = config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules");
        assert!(
            rules
                .iter()
                .any(|r| r.as_str() == Some("AND,((DOMAIN,baidu.com),(NETWORK,udp)),DIRECT")),
            "AND rule should be present"
        );
        assert!(
            rules
                .iter()
                .any(|r| r.as_str() == Some("NOT,((DOMAIN,baidu.com)),PROXY")),
            "NOT rule should be present"
        );
        // Raw rules should appear before MATCH
        let match_idx = rules
            .iter()
            .position(|r| r.as_str().is_some_and(|s| s.starts_with("MATCH,")));
        let and_idx = rules
            .iter()
            .position(|r| r.as_str() == Some("AND,((DOMAIN,baidu.com),(NETWORK,udp)),DIRECT"));
        assert!(and_idx.is_some_and(|ai| match_idx.is_some_and(|mi| ai < mi)));
    }

    #[test]
    fn raw_rules_absent_when_empty() {
        let config = build_test_router_config(&default_features());
        let rules = config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules");
        // Only the QUIC block AND rule and MATCH should be present — no user raw rules
        assert!(
            !rules
                .iter()
                .any(|r| { r.as_str().is_some_and(|s| s.starts_with("NOT,")) })
        );
    }

    #[test]
    fn typed_rules_emitted_before_raw_rules() {
        let mut features = default_features();
        features.typed_rules = vec![super::MihomoRuleConfig {
            rule_type: "IN-NAME".to_owned(),
            value: REDIR_LISTENER.to_owned(),
            target: "active".to_owned(),
            options: Vec::new(),
        }];
        features.raw_rules = vec!["DSCP,4,DIRECT".to_owned()];
        let config = build_test_router_config(&features);
        let rules = config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules");
        let typed_idx = rules
            .iter()
            .position(|r| r.as_str() == Some("IN-NAME,redir-in,proxy"))
            .expect("typed rule");
        let raw_idx = rules
            .iter()
            .position(|r| r.as_str() == Some("DSCP,4,DIRECT"))
            .expect("raw rule");
        assert!(typed_idx < raw_idx);
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
        let features = MihomoFeatures {
            typed_rules: vec![super::MihomoRuleConfig {
                rule_type: "DSCP".to_owned(),
                value: "4".to_owned(),
                target: "direct".to_owned(),
                options: vec![],
            }],
            raw_rules: vec!["DOMAIN,raw.example,DIRECT".to_owned()],
            ..MihomoFeatures::default()
        };
        let yaml = build_router_with_extra(&extra, &[route_rule], false, &features)
            .expect("router config");
        let rules = router_rules(&yaml);
        assert_eq!(
            rules,
            [
                "DOMAIN-SUFFIX,ordinary.example,DIRECT",
                "AND,((NETWORK,udp),(DST-PORT,443)),REJECT",
                "DSCP,4,DIRECT",
                "DOMAIN,raw.example,DIRECT",
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
    fn duplicate_rule_provider_names_are_rejected() {
        let extra = RouterExtra {
            geobase_rule_providers: vec![managed_provider(
                "shared-name",
                "/opt/etc/hincyray/geobase/list.txt",
                GeoBaseRuleBehavior::Domain,
                GeoBaseRuleTarget::Active,
            )],
            mihomo_home: Some("/opt/etc/hincyray".to_owned()),
            ..RouterExtra::default()
        };
        let features = MihomoFeatures {
            rule_providers: vec![RuleProviderConfig {
                name: "shared-name".to_owned(),
                ..RuleProviderConfig::default()
            }],
            ..MihomoFeatures::default()
        };
        let error = build_router_with_extra(&extra, &[], true, &features)
            .expect_err("duplicate provider must fail");
        assert!(error.contains("duplicate rule provider name"));
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
    fn managed_provider_path_cannot_collide_with_user_path() {
        let extra = RouterExtra {
            geobase_rule_providers: vec![managed_provider(
                "geobase-active",
                "/opt/etc/hincyray/geobases/shared.txt",
                GeoBaseRuleBehavior::Domain,
                GeoBaseRuleTarget::Active,
            )],
            mihomo_home: Some("/opt/etc/hincyray".to_owned()),
            ..RouterExtra::default()
        };
        let features = MihomoFeatures {
            rule_providers: vec![RuleProviderConfig {
                name: "user-file".to_owned(),
                provider_type: "file".to_owned(),
                path: Some("./geobases/../geobases/shared.txt".to_owned()),
                ..RuleProviderConfig::default()
            }],
            ..MihomoFeatures::default()
        };
        let error = build_router_with_extra(&extra, &[], true, &features)
            .expect_err("user file path collision must fail");
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
