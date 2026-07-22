//! Typed HTTP contracts shared by daemon handlers, tests, and browser fixtures.
//!
//! The daemon may internally use Mihomo IDs and large state objects, but API
//! callers receive bounded projections expressed by these types.

use std::collections::HashMap;

use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::telegram_probe::TelegramProbeConfig;

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
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct RoutingConnectionContextResponse {
    pub servers: Vec<RoutingServerSummary>,
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
            path: "/api/onboarding/status",
            request_schema: None,
            response_schema: "OnboardingStatusResponse",
            bounded: true,
            mutates_state: false,
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
    ]
}

fn schema_value<T: JsonSchema>() -> Value {
    serde_json::to_value(schema_for!(T))
        .unwrap_or_else(|_| json!({"error":"schema generation failed"}))
}

pub fn openapi_document() -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "HincyRay daemon API",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "x-contract-version": 1,
        "x-state-changing-requires-same-origin": true,
        "x-authentication": "argon2id-password+cSPRNG-bearer-expiry",
        "paths": api_endpoint_contracts().into_iter().map(|endpoint| {
            let request = endpoint.request_schema.map(|schema| json!({"$ref": format!("#/components/schemas/{schema}")}));
            (
                endpoint.path.to_owned(),
                json!({
                    endpoint.method.to_ascii_lowercase(): {
                        "x-bounded": endpoint.bounded,
                        "x-mutates-state": endpoint.mutates_state,
                        "requestBody": request.map(|schema| json!({"content":{"application/json":{"schema":schema}}})),
                        "responses": {
                            "200": {"content":{"application/json":{"schema":{"$ref": format!("#/components/schemas/{}", endpoint.response_schema)}}}}
                        }
                    }
                }),
            )
        }).collect::<serde_json::Map<_, _>>(),
        "components": {
            "schemas": {
                "ReadinessCheck": schema_value::<ReadinessCheck>(),
                "OnboardingStatusResponse": schema_value::<OnboardingStatusResponse>(),
                "RoutingSummaryResponse": schema_value::<RoutingSummaryResponse>(),
                "RoutingServerSummary": schema_value::<RoutingServerSummary>(),
                "RoutingConnectionContextResponse": schema_value::<RoutingConnectionContextResponse>(),
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
            }
        }
    })
}
