//! Typed HTTP contracts shared by daemon handlers, tests, and browser fixtures.
//!
//! The daemon may internally use Mihomo IDs and large state objects, but API
//! callers receive bounded projections expressed by these types.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize)]
pub struct ReadinessCheck {
    pub id: &'static str,
    pub label: &'static str,
    pub status: &'static str,
    pub detail: String,
    pub remediation: Option<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct OnboardingStatusResponse {
    pub ready: bool,
    pub version: &'static str,
    pub checks: Vec<ReadinessCheck>,
}

#[derive(Clone, Debug, Serialize)]
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

#[derive(Clone, Debug, Serialize)]
pub struct RoutingServerSummary {
    #[serde(rename = "ref")]
    pub reference: String,
    pub id: usize,
    pub name: String,
    pub protocol: String,
    pub address: String,
    pub group: Option<String>,
    pub active: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct RoutingConnectionContextResponse {
    pub servers: Vec<RoutingServerSummary>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RoutingPreviewResponse {
    pub requires_apply: bool,
    pub core_restart: bool,
    pub firewall_reload: bool,
    pub desired_config_sha256: String,
    pub applied_config_sha256: Option<String>,
    pub changes: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
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

#[derive(Clone, Debug, Serialize)]
pub struct ConnectionPageResponse {
    pub total: usize,
    pub filtered: usize,
    pub offset: usize,
    pub limit: usize,
    pub connections: Vec<Value>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DeviceTrafficRequest {
    #[serde(default)]
    pub source_ips: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct DeviceTrafficSummary {
    pub upload: u64,
    pub download: u64,
    pub connections: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeviceTrafficResponse {
    pub devices: HashMap<String, DeviceTrafficSummary>,
}

#[derive(Clone, Debug, Serialize)]
pub struct MemoryEstimateResponse {
    pub risk: &'static str,
    pub rule_source_bytes: u64,
    pub current_mihomo_rss_kb: u64,
    pub available_memory_kb: u64,
    pub user_rules: usize,
    pub rule_provider_count: usize,
    pub geobase_entries: usize,
    pub rkn_bypass_enabled: bool,
    pub safe_mode_enabled: bool,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SafeModeRequest {
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub apply: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Serialize)]
pub struct SafeModeResponse {
    pub enabled: bool,
    pub applied: bool,
    pub core_status: String,
    pub firewall_status: String,
    pub suppressed: Vec<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ApiContractDescriptor {
    pub version: u32,
    pub bounded_endpoints: Vec<&'static str>,
    pub state_changing_requires_same_origin: bool,
    pub authentication: &'static str,
}
