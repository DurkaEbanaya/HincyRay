//! Typed HTTP contracts shared by daemon handlers, tests, and browser fixtures.
//!
//! The daemon may internally use Mihomo IDs and large state objects, but API
//! callers receive bounded projections expressed by these types.

use std::collections::HashMap;

use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::benchmark::{
    ActiveBenchProfile, AdaptiveSearchOptions, BenchResult, PreflightFailure, SearchProgress,
    ServiceCheckOptions,
};
use crate::direct_monitor::{
    DirectMonitorSettingsRequest, DirectMonitorSettingsResponse, DirectMonitorStatusResponse,
};
use crate::hincyray::BestOfBestSettings;
use crate::mihomo_config::TunnelConfig;
use crate::policy_automation::{PolicyAutomationRequest, PolicyAutomationStatus};
use crate::telegram_probe::TelegramProbeConfig;

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MihomoPerProxyParameters {
    pub tfo: bool,
    pub mptcp: bool,
    pub ip_version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MihomoDnsParameters {
    pub prefer_h3: bool,
    pub respect_rules: bool,
    pub default_nameserver: Vec<String>,
    pub nameserver_policy: HashMap<String, Vec<String>>,
    pub proxy_server_nameserver_policy: HashMap<String, Vec<String>>,
    pub direct_nameserver_follow_policy: Option<bool>,
    pub fake_ip_filter_mode: Option<String>,
    pub fake_ip_filter: Vec<String>,
    pub fake_ip_ttl: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MihomoSnifferParameters {
    pub force_domain: Vec<String>,
    pub skip_domain: Vec<String>,
    pub skip_src_address: Vec<String>,
    pub skip_dst_address: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MihomoExperimentalParameters {
    pub quic_go_disable_gso: bool,
    pub quic_go_disable_ecn: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MihomoParameters {
    pub unified_delay: bool,
    pub store_selected: bool,
    pub keep_alive_interval: u32,
    pub keep_alive_idle: u32,
    pub disable_keep_alive: bool,
    pub tcp_concurrent: bool,
    pub hosts: HashMap<String, String>,
    pub tunnels: Vec<TunnelConfig>,
    pub per_proxy: MihomoPerProxyParameters,
    pub dns: MihomoDnsParameters,
    pub sniffer: MihomoSnifferParameters,
    pub experimental: MihomoExperimentalParameters,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MihomoParametersUpdateRequest {
    pub parameters: MihomoParameters,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct MihomoParametersRuntime {
    pub geodata_loader: &'static str,
    pub store_fake_ip: bool,
    pub udp: bool,
    pub external_controller: MihomoExternalControllerRuntime,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct MihomoExternalControllerRuntime {
    pub enabled: bool,
    pub address: &'static str,
    pub connected: bool,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct MihomoParametersResponse {
    pub parameters: MihomoParameters,
    pub runtime: MihomoParametersRuntime,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ReadinessCheck {
    pub id: &'static str,
    pub label: &'static str,
    pub status: &'static str,
    pub detail: String,
    pub remediation: Option<&'static str>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct OnboardingStatusResponse {
    pub ready: bool,
    pub version: &'static str,
    pub checks: Vec<ReadinessCheck>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct RoutingSummaryResponse {
    pub enabled: bool,
    pub safe_mode_enabled: bool,
    pub match_target: String,
    pub user_rule_count: usize,
    pub enabled_user_rule_count: usize,
    pub device_route_count: usize,
    pub managed_rule_count: usize,
    pub server_count: usize,
    pub conflict_count: usize,
    pub geobase_requires_apply: bool,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct RoutingServerSummary {
    #[serde(rename = "ref")]
    pub reference: String,
    pub id: usize,
    pub name: String,
    pub protocol: String,
    pub address: String,
    pub group: Option<String>,
    pub active: bool,
    pub dead: bool,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct RoutingConnectionContextResponse {
    pub servers: Vec<RoutingServerSummary>,
}

#[derive(Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TorrentSocksSettingsUpdate {
    pub enabled: Option<bool>,
    #[schemars(length(max = 64))]
    pub listen: Option<String>,
    pub port: Option<u16>,
    #[schemars(length(max = 128))]
    pub username: Option<String>,
    #[schemars(length(max = 512))]
    pub password: Option<String>,
    pub clear_credentials: Option<bool>,
    #[schemars(length(max = 64))]
    pub target: Option<String>,
}

impl std::fmt::Debug for TorrentSocksSettingsUpdate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TorrentSocksSettingsUpdate")
            .field("enabled", &self.enabled)
            .field("listen", &self.listen)
            .field("port", &self.port)
            .field("username", &self.username.as_ref().map(|_| "<redacted>"))
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("clear_credentials", &self.clear_credentials)
            .field("target", &self.target)
            .finish()
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct TorrentSocksSettingsResponse {
    pub enabled: bool,
    pub listen: String,
    pub port: u16,
    pub username: String,
    pub password_set: bool,
    pub target: String,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoutingSettingsUpdateRequest {
    pub apply: Option<bool>,
    pub enabled: Option<bool>,
    pub auto_switch: Option<bool>,
    pub block_quic_global: Option<bool>,
    pub rule_source: Option<String>,
    pub vpn_subnet: Option<String>,
    pub redirect_port: Option<u16>,
    pub policy_name: Option<String>,
    pub quic_mode: Option<String>,
    pub port_mode: Option<String>,
    pub proxy_ports: Option<Vec<String>>,
    pub bypass_ports: Option<Vec<String>>,
    pub geo_asset_path: Option<String>,
    pub ru_direct_mode: Option<String>,
    pub ru_direct_exceptions: Option<Vec<String>>,
    pub auto_vpn_learning_enabled: Option<bool>,
    pub auto_vpn_exceptions: Option<Vec<String>>,
    pub parovozik_enabled: Option<bool>,
    pub parovozik_direct_domains: Option<Vec<String>>,
    pub parovozik_vpn_domains: Option<Vec<String>>,
    pub parovozik_server_refs: Option<Vec<String>>,
    pub match_target: Option<String>,
    pub torrent_socks: Option<TorrentSocksSettingsUpdate>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct RoutingSettingsUpdateResponse {
    pub settings: Value,
    pub applied: bool,
    pub requires_apply: Option<bool>,
    pub core_status: Option<String>,
    pub firewall_status: Option<String>,
    pub generation: Option<u64>,
    pub gc_warning: Option<String>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoutingResourceReloadRequest {
    #[schemars(length(min = 1, max = 1024))]
    pub resource: String,
    #[serde(default)]
    #[schemars(length(max = 64))]
    pub source_ip: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    #[schemars(length(max = 8))]
    pub network: Option<String>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct RoutingResourceReloadResponse {
    pub ok: bool,
    pub resource: String,
    pub target: String,
    pub fallback_active: bool,
    pub runtime_evaluation: bool,
    pub applied: bool,
    pub core_status: String,
    pub firewall_status: String,
    pub generation: u64,
    pub closed_connections: usize,
    #[schemars(length(max = 20), inner(length(max = 512)))]
    pub close_errors: Vec<String>,
    pub gc_warning: Option<String>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ProfileDetail {
    pub id: usize,
    pub server_ref: String,
    pub name: String,
    pub raw: String,
    pub protocol: String,
    pub transport: String,
    pub address: String,
    pub port: Option<u16>,
    pub group: Option<String>,
    pub active: bool,
    pub favorite: bool,
    pub dead: bool,
    pub block_quic: bool,
    pub subscription_managed: bool,
    pub xhttp_tuning: Option<XhttpTuning>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ProfileDetailResponse {
    pub profile: ProfileDetail,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfileUpdateRequest {
    pub profile_id: usize,
    pub expected_server_ref: String,
    pub name: Option<String>,
    pub raw: Option<String>,
    pub block_quic: Option<bool>,
    pub xhttp_tuning: Option<XhttpTuning>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct XhttpTuning {
    pub sc_max_each_post_bytes: Option<String>,
    pub sc_min_posts_interval_ms: Option<String>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ActiveProfileApplyStatusResponse {
    pub generation: u64,
    pub state: String,
    pub profile_id: Option<usize>,
    pub profile_name: Option<String>,
    pub stage: String,
    pub updated_at_unix: u64,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ProfileUpdateResponse {
    pub profile: ProfileSafeFields,
    pub dataplane_applied: bool,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionMoveRequest {
    pub url: String,
    pub adjacent_url: String,
    pub direction: String,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct SubscriptionMoveResponse {
    pub url: String,
    pub moved: bool,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ProfileSafeFields {
    pub id: usize,
    pub server_ref: String,
    pub name: String,
    pub protocol: String,
    pub transport: String,
    pub address: String,
    pub port: Option<u16>,
    pub group: Option<String>,
    pub active: bool,
    pub favorite: bool,
    pub dead: bool,
    pub block_quic: bool,
    pub subscription_managed: bool,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ProfileRevalidationError {
    pub profile_id: usize,
    pub name: String,
    pub error: String,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ProfilesRevalidateResponse {
    pub checked: usize,
    pub updated: usize,
    pub unchanged: usize,
    pub dataplane_applied: bool,
    pub errors: Vec<ProfileRevalidationError>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct RoutingPreviewDiff {
    pub kind: &'static str,
    pub title: String,
    pub before: Option<String>,
    pub after: Option<String>,
    pub delta: Option<i64>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct RoutingPreviewResponse {
    pub requires_apply: bool,
    pub core_restart: bool,
    pub firewall_reload: bool,
    pub desired_config_sha256: String,
    pub applied_config_sha256: Option<String>,
    pub changes: Vec<String>,
    pub diff: Vec<RoutingPreviewDiff>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
pub struct ConnectionQueryRequest {
    #[serde(default)]
    pub query: String,
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "default_connection_limit")]
    pub limit: usize,
}

fn default_connection_limit() -> usize {
    100
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ConnectionPageResponse {
    pub total: usize,
    pub filtered: usize,
    pub offset: usize,
    pub limit: usize,
    pub connections: Vec<Value>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
pub struct DeviceTrafficRequest {
    #[serde(default)]
    pub source_ips: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, JsonSchema)]
pub struct DeviceTrafficSummary {
    pub upload: u64,
    pub download: u64,
    pub connections: usize,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct DeviceTrafficResponse {
    pub devices: HashMap<String, DeviceTrafficSummary>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfileDiagnosticStartRequest {
    pub profile_id: usize,
    pub duration_seconds: u32,
    pub source_ip: String,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfileDiagnosticSessionRequest {
    pub session_id: String,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfileDiagnosticDiscardRequest {
    pub session_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ProfileDiagnosticSessionStatus {
    pub session_id: String,
    pub state: String,
    pub profile_id: usize,
    pub profile_name: String,
    pub server_ref: String,
    pub source_ip: String,
    pub started_at_unix: u64,
    pub deadline_unix: u64,
    pub completed_at_unix: Option<u64>,
    pub finalization_reason: Option<String>,
    pub connection_count: usize,
    pub event_count: usize,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ProfileDiagnosticStartResponse {
    pub session: ProfileDiagnosticSessionStatus,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ProfileDiagnosticStatusResponse {
    pub active: Option<ProfileDiagnosticSessionStatus>,
    pub completed: Option<ProfileDiagnosticSessionStatus>,
    pub completed_ttl_seconds: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct ProfileDiagnosticProfile {
    pub id: usize,
    pub server_ref: String,
    pub name: String,
    pub protocol: String,
    pub transport: String,
    pub address: String,
    pub port: Option<u16>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct ProfileDiagnosticMemory {
    pub hincyray_rss_kb: u64,
    pub mihomo_rss_kb: u64,
    pub system_available_kb: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct ProfileDiagnosticEnvironment {
    pub hincyray_version: String,
    pub mihomo_version: Option<String>,
    pub core_generation: u64,
    pub core_status: String,
    pub firewall_status: String,
    pub socks_port: u16,
    pub mixed_port: Option<u16>,
    pub redirect_port: u16,
    pub tproxy_port: u16,
    pub dns_port: u16,
    pub memory: ProfileDiagnosticMemory,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct ProfileDiagnosticConnection {
    pub id: String,
    pub domain: String,
    pub destination_ip: String,
    pub destination_port: u16,
    pub network: String,
    pub rule: String,
    pub rule_payload: String,
    pub chains: Vec<String>,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub first_seen_unix: u64,
    pub last_seen_unix: u64,
    pub open: bool,
    pub source_ip: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct ProfileDiagnosticEvent {
    pub timestamp_unix: u64,
    pub severity: String,
    pub message: String,
    pub classification: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct ProfileDiagnosticServiceResult {
    pub id: String,
    pub name: String,
    pub attempts: u32,
    pub successes: u32,
    pub reachable: bool,
    pub stable: bool,
    pub avg_ttfb_ms: u32,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct ProfileDiagnosticLatestStats {
    pub checked_at_unix: u64,
    pub latency_ms: u32,
    pub jitter_ms: u32,
    pub download_mbps: f32,
    pub upload_mbps: f32,
    pub loss_percent: f32,
    pub last_service_test_success: Option<bool>,
    pub services: Vec<ProfileDiagnosticServiceResult>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct ProfileDiagnosticSummary {
    pub connections: usize,
    pub open_connections: usize,
    pub closed_connections: usize,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub events: usize,
    pub poll_errors: usize,
    pub dropped_connections: usize,
    pub dropped_events: usize,
    pub failure_classifications: HashMap<String, usize>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct ProfileDiagnosticReport {
    pub session_id: String,
    pub purpose: String,
    pub state: String,
    pub started_at_unix: u64,
    pub ended_at_unix: u64,
    pub requested_duration_seconds: u32,
    pub observed_duration_seconds: u64,
    pub finalization_reason: String,
    pub source_ip: String,
    pub profile: ProfileDiagnosticProfile,
    pub environment_start: ProfileDiagnosticEnvironment,
    pub environment_end: ProfileDiagnosticEnvironment,
    pub summary: ProfileDiagnosticSummary,
    pub connections: Vec<ProfileDiagnosticConnection>,
    pub events: Vec<ProfileDiagnosticEvent>,
    pub latest_stats: Option<ProfileDiagnosticLatestStats>,
    pub config_summary: String,
    pub redaction_note: String,
    pub markdown: String,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ProfileDiagnosticReportResponse {
    pub report: ProfileDiagnosticReport,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ProfileDiagnosticDiscardResponse {
    pub discarded: bool,
    pub session_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct MemoryEstimateResponse {
    pub risk: &'static str,
    pub rule_source_bytes: u64,
    pub current_mihomo_rss_kb: u64,
    pub available_memory_kb: u64,
    pub user_rules: usize,
    pub rule_provider_count: usize,
    pub geobase_entries: usize,
    pub safe_mode_enabled: bool,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
pub struct SafeModeRequest {
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub apply: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct SafeModeResponse {
    pub enabled: bool,
    pub applied: bool,
    pub core_status: String,
    pub firewall_status: String,
    pub suppressed: Vec<&'static str>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct TelegramProbeStatusResponse {
    pub configured: bool,
    pub session_exists: bool,
    pub authorized: bool,
    pub login_pending: bool,
    pub peer: Option<String>,
    pub message_id: Option<i32>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
pub struct TelegramProbeConfirmRequest {
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub password: String,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct TelegramProbeCodeResponse {
    pub code_requested: bool,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct TelegramProbeConfirmResponse {
    pub authorized: bool,
    pub password_required: bool,
    pub hint: Option<String>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct TelegramProbeDeleteResponse {
    pub deleted: bool,
    pub revoked: bool,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
pub struct BenchStartRequest {
    /// Availability methods check channel previews; quick/full retain native playback compatibility.
    #[schemars(regex(
        pattern = "^(tcp|head|get|quick|full|availability_quick|availability_full)$"
    ))]
    pub method: Option<String>,
    pub probe_url: Option<String>,
    pub download_url: Option<String>,
    pub upload_url: Option<String>,
    #[schemars(range(min = 1, max = 6))]
    pub concurrency: Option<usize>,
    pub test_download: Option<bool>,
    pub test_upload: Option<bool>,
    pub profile_ids: Option<Vec<usize>>,
    pub subscription_url: Option<String>,
    /// Quick/availability_quick adaptive search; speed stages must be disabled.
    pub search: Option<AdaptiveSearchOptions>,
    /// Availability-only ordered service prefix and fail-fast policy; mutually exclusive with search.
    pub service_checks: Option<ServiceCheckOptions>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct BenchStartResponse {
    pub started: bool,
    pub method: String,
    pub total: usize,
    pub running: bool,
    pub requested_concurrency: usize,
    pub concurrency: usize,
    pub search: Option<SearchProgress>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct BenchSummary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub inconclusive: usize,
    pub avg_latency_ms: f32,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BenchConcurrencyLimit {
    MemoryCap,
    CandidateCount,
    TargetSlots,
}

#[derive(Clone, Debug, Default, Serialize, JsonSchema)]
pub struct BenchConcurrencyStatus {
    #[schemars(range(min = 0, max = 6))]
    pub requested: usize,
    #[schemars(range(min = 0, max = 6))]
    pub effective: usize,
    #[schemars(range(min = 0, max = 6))]
    pub active: usize,
    #[schemars(range(min = 0, max = 6))]
    pub admission_limit: usize,
    #[schemars(length(max = 3))]
    pub limit_reasons: Vec<BenchConcurrencyLimit>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct BenchStatusResult {
    #[serde(flatten)]
    pub result: BenchResult,
    #[schemars(regex(pattern = "^srv-v2-[0-9a-f]{32}$"))]
    pub server_ref: String,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct BenchStatusResponse {
    pub running: bool,
    pub method: Option<String>,
    pub total: usize,
    pub completed: usize,
    pub current_profile_id: Option<usize>,
    pub current_profile_name: Option<String>,
    #[schemars(length(max = 6))]
    pub active_profiles: Vec<ActiveBenchProfile>,
    pub concurrency_status: BenchConcurrencyStatus,
    pub last_updated: u64,
    pub cancel_requested: bool,
    pub results: Vec<BenchStatusResult>,
    pub summary: BenchSummary,
    pub search: Option<SearchProgress>,
    #[schemars(length(max = 20))]
    pub preflight_failures: Vec<PreflightFailure>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProfileTestSettings {
    pub promote_successful_tested_servers: bool,
    pub auto_move_no_ping_to_dead_servers: bool,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfileTestSettingsUpdateRequest {
    pub promote_successful_tested_servers: bool,
    pub auto_move_no_ping_to_dead_servers: bool,
}

impl From<ProfileTestSettingsUpdateRequest> for ProfileTestSettings {
    fn from(request: ProfileTestSettingsUpdateRequest) -> Self {
        Self {
            promote_successful_tested_servers: request.promote_successful_tested_servers,
            auto_move_no_ping_to_dead_servers: request.auto_move_no_ping_to_dead_servers,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ProfileTestSettingsResponse {
    pub settings: ProfileTestSettings,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ApiEndpointContract {
    pub method: &'static str,
    pub path: &'static str,
    pub request_schema: Option<&'static str>,
    pub response_schema: &'static str,
    pub bounded: bool,
    pub mutates_state: bool,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ApiContractDescriptor {
    pub version: u32,
    pub bounded_endpoints: Vec<&'static str>,
    pub schema_endpoint: &'static str,
    pub endpoints: Vec<ApiEndpointContract>,
    pub state_changing_requires_same_origin: bool,
    pub authentication: &'static str,
}

pub fn api_endpoint_contracts() -> Vec<ApiEndpointContract> {
    vec![
        ApiEndpointContract {
            method: "GET",
            path: "/api/mihomo-features",
            request_schema: None,
            response_schema: "MihomoParametersResponse",
            bounded: true,
            mutates_state: false,
        },
        ApiEndpointContract {
            method: "POST",
            path: "/api/routing/settings",
            request_schema: Some("RoutingSettingsUpdateRequest"),
            response_schema: "RoutingSettingsUpdateResponse",
            bounded: true,
            mutates_state: true,
        },
        ApiEndpointContract {
            method: "POST",
            path: "/api/mihomo-features",
            request_schema: Some("MihomoParametersUpdateRequest"),
            response_schema: "MihomoParametersResponse",
            bounded: true,
            mutates_state: true,
        },
        ApiEndpointContract {
            method: "GET",
            path: "/api/onboarding/status",
            request_schema: None,
            response_schema: "OnboardingStatusResponse",
            bounded: true,
            mutates_state: false,
        },
        ApiEndpointContract {
            method: "GET",
            path: "/api/profiles/{id}",
            request_schema: None,
            response_schema: "ProfileDetailResponse",
            bounded: true,
            mutates_state: false,
        },
        ApiEndpointContract {
            method: "POST",
            path: "/api/profiles/update",
            request_schema: Some("ProfileUpdateRequest"),
            response_schema: "ProfileUpdateResponse",
            bounded: true,
            mutates_state: true,
        },
        ApiEndpointContract {
            method: "POST",
            path: "/api/subscriptions/move",
            request_schema: Some("SubscriptionMoveRequest"),
            response_schema: "SubscriptionMoveResponse",
            bounded: true,
            mutates_state: true,
        },
        ApiEndpointContract {
            method: "GET",
            path: "/api/active-profile/status",
            request_schema: None,
            response_schema: "ActiveProfileApplyStatusResponse",
            bounded: true,
            mutates_state: false,
        },
        ApiEndpointContract {
            method: "POST",
            path: "/api/profiles/revalidate-ungrouped",
            request_schema: None,
            response_schema: "ProfilesRevalidateResponse",
            bounded: true,
            mutates_state: true,
        },
        ApiEndpointContract {
            method: "GET",
            path: "/api/routing/summary",
            request_schema: None,
            response_schema: "RoutingSummaryResponse",
            bounded: true,
            mutates_state: false,
        },
        ApiEndpointContract {
            method: "GET",
            path: "/api/routing/connection-context",
            request_schema: None,
            response_schema: "RoutingConnectionContextResponse",
            bounded: true,
            mutates_state: false,
        },
        ApiEndpointContract {
            method: "GET",
            path: "/api/routing/preview",
            request_schema: None,
            response_schema: "RoutingPreviewResponse",
            bounded: true,
            mutates_state: false,
        },
        ApiEndpointContract {
            method: "POST",
            path: "/api/routing/explain",
            request_schema: Some("RoutingExplainRequest"),
            response_schema: "RoutingExplainResponse",
            bounded: true,
            mutates_state: false,
        },
        ApiEndpointContract {
            method: "POST",
            path: "/api/routing/resource-reload",
            request_schema: Some("RoutingResourceReloadRequest"),
            response_schema: "RoutingResourceReloadResponse",
            bounded: true,
            mutates_state: true,
        },
        ApiEndpointContract {
            method: "GET",
            path: "/api/memory-estimate",
            request_schema: None,
            response_schema: "MemoryEstimateResponse",
            bounded: true,
            mutates_state: false,
        },
        ApiEndpointContract {
            method: "GET",
            path: "/api/safe-mode",
            request_schema: None,
            response_schema: "SafeModeResponse",
            bounded: true,
            mutates_state: false,
        },
        ApiEndpointContract {
            method: "GET",
            path: "/api/diagnostics/direct-availability",
            request_schema: None,
            response_schema: "DirectAvailabilityDiagnosticsResponse",
            bounded: true,
            mutates_state: false,
        },
        ApiEndpointContract {
            method: "GET",
            path: "/api/diagnostics/direct-monitor",
            request_schema: None,
            response_schema: "DirectMonitorStatusResponse",
            bounded: true,
            mutates_state: false,
        },
        ApiEndpointContract {
            method: "POST",
            path: "/api/diagnostics/direct-monitor",
            request_schema: Some("DirectMonitorSettingsRequest"),
            response_schema: "DirectMonitorSettingsResponse",
            bounded: true,
            mutates_state: true,
        },
        ApiEndpointContract {
            method: "GET",
            path: "/api/automation/direct-policy",
            request_schema: None,
            response_schema: "PolicyAutomationStatus",
            bounded: true,
            mutates_state: false,
        },
        ApiEndpointContract {
            method: "GET",
            path: "/api/automation/best-of-best",
            request_schema: None,
            response_schema: "BestOfBestStatus",
            bounded: true,
            mutates_state: false,
        },
        ApiEndpointContract {
            method: "POST",
            path: "/api/automation/best-of-best",
            request_schema: Some("BestOfBestSettings"),
            response_schema: "BestOfBestStatus",
            bounded: true,
            mutates_state: true,
        },
        ApiEndpointContract {
            method: "POST",
            path: "/api/automation/direct-policy",
            request_schema: Some("PolicyAutomationRequest"),
            response_schema: "PolicyAutomationStatus",
            bounded: true,
            mutates_state: true,
        },
        ApiEndpointContract {
            method: "POST",
            path: "/api/safe-mode",
            request_schema: Some("SafeModeRequest"),
            response_schema: "SafeModeResponse",
            bounded: true,
            mutates_state: true,
        },
        ApiEndpointContract {
            method: "GET",
            path: "/api/telegram-probe/status",
            request_schema: None,
            response_schema: "TelegramProbeStatusResponse",
            bounded: true,
            mutates_state: false,
        },
        ApiEndpointContract {
            method: "POST",
            path: "/api/telegram-probe/request-code",
            request_schema: Some("TelegramProbeConfig"),
            response_schema: "TelegramProbeCodeResponse",
            bounded: true,
            mutates_state: true,
        },
        ApiEndpointContract {
            method: "POST",
            path: "/api/telegram-probe/confirm",
            request_schema: Some("TelegramProbeConfirmRequest"),
            response_schema: "TelegramProbeConfirmResponse",
            bounded: true,
            mutates_state: true,
        },
        ApiEndpointContract {
            method: "POST",
            path: "/api/telegram-probe/delete",
            request_schema: None,
            response_schema: "TelegramProbeDeleteResponse",
            bounded: true,
            mutates_state: true,
        },
        ApiEndpointContract {
            method: "POST",
            path: "/api/bench/start",
            request_schema: Some("BenchStartRequest"),
            response_schema: "BenchStartResponse",
            bounded: true,
            mutates_state: true,
        },
        ApiEndpointContract {
            method: "GET",
            path: "/api/bench/status",
            request_schema: None,
            response_schema: "BenchStatusResponse",
            bounded: true,
            mutates_state: false,
        },
        ApiEndpointContract {
            method: "GET",
            path: "/api/bench/settings",
            request_schema: None,
            response_schema: "ProfileTestSettingsResponse",
            bounded: true,
            mutates_state: false,
        },
        ApiEndpointContract {
            method: "POST",
            path: "/api/bench/settings",
            request_schema: Some("ProfileTestSettingsUpdateRequest"),
            response_schema: "ProfileTestSettingsResponse",
            bounded: true,
            mutates_state: true,
        },
        ApiEndpointContract {
            method: "POST",
            path: "/api/mihomo-api/connections/page",
            request_schema: Some("ConnectionQueryRequest"),
            response_schema: "ConnectionPageResponse",
            bounded: true,
            mutates_state: false,
        },
        ApiEndpointContract {
            method: "POST",
            path: "/api/mihomo-api/connections/device-traffic",
            request_schema: Some("DeviceTrafficRequest"),
            response_schema: "DeviceTrafficResponse",
            bounded: true,
            mutates_state: false,
        },
        ApiEndpointContract {
            method: "POST",
            path: "/api/profile-diagnostics/start",
            request_schema: Some("ProfileDiagnosticStartRequest"),
            response_schema: "ProfileDiagnosticStartResponse",
            bounded: true,
            mutates_state: true,
        },
        ApiEndpointContract {
            method: "GET",
            path: "/api/profile-diagnostics/status",
            request_schema: None,
            response_schema: "ProfileDiagnosticStatusResponse",
            bounded: true,
            mutates_state: false,
        },
        ApiEndpointContract {
            method: "POST",
            path: "/api/profile-diagnostics/stop",
            request_schema: Some("ProfileDiagnosticSessionRequest"),
            response_schema: "ProfileDiagnosticReportResponse",
            bounded: true,
            mutates_state: true,
        },
        ApiEndpointContract {
            method: "POST",
            path: "/api/profile-diagnostics/report",
            request_schema: Some("ProfileDiagnosticSessionRequest"),
            response_schema: "ProfileDiagnosticReportResponse",
            bounded: true,
            mutates_state: false,
        },
        ApiEndpointContract {
            method: "POST",
            path: "/api/profile-diagnostics/discard",
            request_schema: Some("ProfileDiagnosticDiscardRequest"),
            response_schema: "ProfileDiagnosticDiscardResponse",
            bounded: true,
            mutates_state: true,
        },
    ]
}

fn schema_value<T: JsonSchema>() -> Value {
    serde_json::to_value(schema_for!(T))
        .unwrap_or_else(|_| json!({"error":"schema generation failed"}))
}

pub fn openapi_document() -> Value {
    let base_schemas = json!({
        "ReadinessCheck": schema_value::<ReadinessCheck>(),
        "MihomoPerProxyParameters": schema_value::<MihomoPerProxyParameters>(),
        "MihomoDnsParameters": schema_value::<MihomoDnsParameters>(),
        "MihomoSnifferParameters": schema_value::<MihomoSnifferParameters>(),
        "MihomoExperimentalParameters": schema_value::<MihomoExperimentalParameters>(),
        "MihomoParameters": schema_value::<MihomoParameters>(),
        "MihomoParametersUpdateRequest": schema_value::<MihomoParametersUpdateRequest>(),
        "MihomoParametersRuntime": schema_value::<MihomoParametersRuntime>(),
        "MihomoExternalControllerRuntime": schema_value::<MihomoExternalControllerRuntime>(),
        "MihomoParametersResponse": schema_value::<MihomoParametersResponse>(),
        "OnboardingStatusResponse": schema_value::<OnboardingStatusResponse>(),
        "RoutingSummaryResponse": schema_value::<RoutingSummaryResponse>(),
        "RoutingServerSummary": schema_value::<RoutingServerSummary>(),
        "RoutingConnectionContextResponse": schema_value::<RoutingConnectionContextResponse>(),
        "ProfileDetail": schema_value::<ProfileDetail>(),
        "ProfileDetailResponse": schema_value::<ProfileDetailResponse>(),
        "ProfileUpdateRequest": schema_value::<ProfileUpdateRequest>(),
        "ProfileUpdateResponse": schema_value::<ProfileUpdateResponse>(),
        "SubscriptionMoveRequest": schema_value::<SubscriptionMoveRequest>(),
        "SubscriptionMoveResponse": schema_value::<SubscriptionMoveResponse>(),
        "XhttpTuning": schema_value::<XhttpTuning>(),
        "ActiveProfileApplyStatusResponse": schema_value::<ActiveProfileApplyStatusResponse>(),
        "ProfileSafeFields": schema_value::<ProfileSafeFields>(),
        "ProfileRevalidationError": schema_value::<ProfileRevalidationError>(),
        "ProfilesRevalidateResponse": schema_value::<ProfilesRevalidateResponse>(),
        "RoutingPreviewDiff": schema_value::<RoutingPreviewDiff>(),
        "RoutingPreviewResponse": schema_value::<RoutingPreviewResponse>(),
        "ConnectionQueryRequest": schema_value::<ConnectionQueryRequest>(),
        "ConnectionPageResponse": schema_value::<ConnectionPageResponse>(),
        "DeviceTrafficRequest": schema_value::<DeviceTrafficRequest>(),
        "DeviceTrafficResponse": schema_value::<DeviceTrafficResponse>(),
        "DeviceTrafficSummary": schema_value::<DeviceTrafficSummary>(),
        "MemoryEstimateResponse": schema_value::<MemoryEstimateResponse>(),
        "SafeModeRequest": schema_value::<SafeModeRequest>(),
        "SafeModeResponse": schema_value::<SafeModeResponse>(),
        "TelegramProbeConfig": schema_value::<TelegramProbeConfig>(),
        "TelegramProbeStatusResponse": schema_value::<TelegramProbeStatusResponse>(),
        "TelegramProbeConfirmRequest": schema_value::<TelegramProbeConfirmRequest>(),
        "TelegramProbeCodeResponse": schema_value::<TelegramProbeCodeResponse>(),
        "TelegramProbeConfirmResponse": schema_value::<TelegramProbeConfirmResponse>(),
        "TelegramProbeDeleteResponse": schema_value::<TelegramProbeDeleteResponse>(),
    });
    let diagnostic_schemas = json!({
        "DirectMonitorSettingsRequest": schema_value::<DirectMonitorSettingsRequest>(),
        "DirectMonitorSettingsResponse": schema_value::<DirectMonitorSettingsResponse>(),
        "DirectMonitorStatusResponse": schema_value::<DirectMonitorStatusResponse>(),
        "PolicyAutomationRequest": schema_value::<PolicyAutomationRequest>(),
        "PolicyAutomationStatus": schema_value::<PolicyAutomationStatus>(),
        "RoutingResourceReloadRequest": schema_value::<RoutingResourceReloadRequest>(),
        "RoutingResourceReloadResponse": schema_value::<RoutingResourceReloadResponse>(),
        "ProfileDiagnosticStartRequest": schema_value::<ProfileDiagnosticStartRequest>(),
        "ProfileDiagnosticSessionRequest": schema_value::<ProfileDiagnosticSessionRequest>(),
        "ProfileDiagnosticDiscardRequest": schema_value::<ProfileDiagnosticDiscardRequest>(),
        "ProfileDiagnosticSessionStatus": schema_value::<ProfileDiagnosticSessionStatus>(),
        "ProfileDiagnosticStartResponse": schema_value::<ProfileDiagnosticStartResponse>(),
        "ProfileDiagnosticStatusResponse": schema_value::<ProfileDiagnosticStatusResponse>(),
        "ProfileDiagnosticProfile": schema_value::<ProfileDiagnosticProfile>(),
        "ProfileDiagnosticMemory": schema_value::<ProfileDiagnosticMemory>(),
        "ProfileDiagnosticEnvironment": schema_value::<ProfileDiagnosticEnvironment>(),
        "ProfileDiagnosticConnection": schema_value::<ProfileDiagnosticConnection>(),
        "ProfileDiagnosticEvent": schema_value::<ProfileDiagnosticEvent>(),
        "ProfileDiagnosticServiceResult": schema_value::<ProfileDiagnosticServiceResult>(),
        "ProfileDiagnosticLatestStats": schema_value::<ProfileDiagnosticLatestStats>(),
        "ProfileDiagnosticSummary": schema_value::<ProfileDiagnosticSummary>(),
        "ProfileDiagnosticReport": schema_value::<ProfileDiagnosticReport>(),
        "ProfileDiagnosticReportResponse": schema_value::<ProfileDiagnosticReportResponse>(),
        "ProfileDiagnosticDiscardResponse": schema_value::<ProfileDiagnosticDiscardResponse>(),
        "BenchStartRequest": schema_value::<BenchStartRequest>(),
        "BenchStartResponse": schema_value::<BenchStartResponse>(),
        "BenchConcurrencyLimit": schema_value::<BenchConcurrencyLimit>(),
        "BenchConcurrencyStatus": schema_value::<BenchConcurrencyStatus>(),
        "BenchStatusResponse": schema_value::<BenchStatusResponse>(),
        "BenchStatusResult": schema_value::<BenchStatusResult>(),
        "BenchSummary": schema_value::<BenchSummary>(),
        "PreflightFailure": schema_value::<PreflightFailure>(),
        "AdaptiveSearchOptions": schema_value::<AdaptiveSearchOptions>(),
        "ServiceCheckOptions": schema_value::<ServiceCheckOptions>(),
        "ServiceCheckPrefix": schema_value::<crate::benchmark::ServiceCheckPrefix>(),
        "SearchProgress": schema_value::<SearchProgress>(),
        "ActiveBenchProfile": schema_value::<ActiveBenchProfile>(),
        "BenchResult": schema_value::<BenchResult>(),
        "ProfileTestSettings": schema_value::<ProfileTestSettings>(),
        "ProfileTestSettingsUpdateRequest": schema_value::<ProfileTestSettingsUpdateRequest>(),
        "ProfileTestSettingsResponse": schema_value::<ProfileTestSettingsResponse>(),
    });
    let routing_settings_schemas = json!({
        "BestOfBestSettings": schema_value::<BestOfBestSettings>(),
        "BestOfBestStatus": json!({"type":"object","description":"Bounded best-of-best settings and ranked candidates"}),
        "TorrentSocksSettingsUpdate": schema_value::<TorrentSocksSettingsUpdate>(),
        "TorrentSocksSettingsResponse": schema_value::<TorrentSocksSettingsResponse>(),
        "RoutingSettingsUpdateRequest": schema_value::<RoutingSettingsUpdateRequest>(),
        "RoutingSettingsUpdateResponse": schema_value::<RoutingSettingsUpdateResponse>(),
    });
    let mut schemas = base_schemas.as_object().cloned().unwrap_or_default();
    schemas.extend(diagnostic_schemas.as_object().cloned().unwrap_or_default());
    schemas.extend(
        routing_settings_schemas
            .as_object()
            .cloned()
            .unwrap_or_default(),
    );
    let mut paths = serde_json::Map::new();
    for endpoint in api_endpoint_contracts() {
        let request = endpoint
            .request_schema
            .map(|schema| json!({"$ref": format!("#/components/schemas/{schema}")}));
        let operation = json!({
            "x-bounded": endpoint.bounded,
            "x-mutates-state": endpoint.mutates_state,
            "requestBody": request.map(|schema| json!({"content":{"application/json":{"schema":schema}}})),
            "responses": {
                "200": {"content":{"application/json":{"schema":{"$ref": format!("#/components/schemas/{}", endpoint.response_schema)}}}}
            }
        });
        let path_item = paths
            .entry(endpoint.path.to_owned())
            .or_insert_with(|| json!({}));
        if let Some(path_item) = path_item.as_object_mut() {
            path_item.insert(endpoint.method.to_ascii_lowercase(), operation);
        }
    }
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "HincyRay daemon API",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "x-contract-version": 1,
        "x-state-changing-requires-same-origin": true,
        "x-authentication": "argon2id-password+cSPRNG-bearer-expiry",
        "paths": paths,
        "components": {
            "schemas": Value::Object(schemas)
        }
    })
}
