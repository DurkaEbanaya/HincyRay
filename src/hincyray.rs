//! HincyRay router daemon.
//!
//! Lightweight sync HTTP server on `std::net::TcpListener`, no async
//! runtime, no web framework. Shares `profiles`, `xray_config`, and
//! `scoring` with the desktop app so parser/scoring logic is not
//! duplicated.
//!
//! Default bind: `0.0.0.0:8088`. Override with `HINCYRAY_LISTEN`.
//! State path: see `resolve_state_path`. Override with `HINCYRAY_STATE`.
//! Xray config path: alongside state. Override with `HINCYRAY_XRAY_CONFIG`.

use std::{
    collections::HashSet,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::benchmark::{
    BenchJob, BenchMethod, BenchResult, DEFAULT_DOWNLOAD_URL, DEFAULT_PROBE_URL, SharedJob,
    run_bench,
};
use crate::profiles::{
    Profile, SubscriptionSource, load_subscription_detailed_via_proxy, parse_input,
};
use crate::xray_config::build_xray_config;
use crate::xray_config::{
    ACTIVE_OUTBOUND_TAG, DIRECT_OUTBOUND_TAG, XrayRouteRule, build_xray_router_config,
};

const DEFAULT_LISTEN: &str = "0.0.0.0:8088";
const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_HISTORY_SAMPLES: usize = 1000;

/// Entry point for the `hincyray` binary. Binds the listener and serves
/// requests on the calling thread; spawn background threads per
/// connection to avoid one slow client blocking the API.
pub fn run() -> Result<(), String> {
    let listen = std::env::var("HINCYRAY_LISTEN").unwrap_or_else(|_| DEFAULT_LISTEN.to_owned());
    let state_path = resolve_state_path();
    let xray_config_path = resolve_xray_config_path(&state_path);
    let state = load_state(&state_path);
    let daemon = Daemon::new(state, state_path, xray_config_path);

    let listener = TcpListener::bind(&listen).map_err(|error| format!("bind {listen}: {error}"))?;
    eprintln!("hincyray listening on {listen}");
    eprintln!("hincyray state: {}", daemon.state_path.to_string_lossy());
    eprintln!(
        "hincyray xray config: {}",
        daemon.xray_config_path.to_string_lossy()
    );

    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("hincyray accept: {error}");
                continue;
            }
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(15)));
        let daemon = daemon.clone();
        thread::spawn(move || {
            if let Err(error) = handle_connection(stream, &daemon) {
                eprintln!("hincyray handler: {error}");
            }
        });
    }

    Ok(())
}

/// Top-level daemon state plus on-disk paths. Cloning is cheap: only
/// the `Arc` is duplicated.
#[derive(Clone)]
pub struct Daemon {
    inner: Arc<Mutex<DaemonInner>>,
    state_path: PathBuf,
    xray_config_path: PathBuf,
}

struct DaemonInner {
    state: HincyrayState,
    core: CoreManager,
    bench: BenchRuntime,
}

/// Holds the live benchmark job (if any), its cancel flag, and the
/// worker thread handle. The active Xray `CoreManager` is intentionally
/// separate: benchmarks spin up their own temporary Xray children and
/// must never touch the running core.
struct BenchRuntime {
    job: Option<SharedJob>,
    cancel: Option<Arc<AtomicBool>>,
    handle: Option<JoinHandle<()>>,
}

impl BenchRuntime {
    fn new() -> Self {
        Self {
            job: None,
            cancel: None,
            handle: None,
        }
    }

    fn is_running(&self) -> bool {
        self.job
            .as_ref()
            .map(|job| {
                job.lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .running
            })
            .unwrap_or(false)
    }

    fn request_cancel(&self) {
        if let Some(flag) = self.cancel.as_ref() {
            flag.store(true, Ordering::Relaxed);
            if let Some(job) = self.job.as_ref() {
                let mut state = job.lock().unwrap_or_else(|poison| poison.into_inner());
                state.cancel_requested = true;
            }
        }
    }

    fn snapshot(&self) -> BenchJob {
        self.job
            .as_ref()
            .map(|job| {
                job.lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .clone()
            })
            .unwrap_or_default()
    }
}

/// Persisted HincyRay state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HincyrayState {
    #[serde(default)]
    pub profiles: Vec<Profile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_profile_id: Option<usize>,
    #[serde(default)]
    pub auto_select: bool,
    #[serde(default = "default_listen_host")]
    pub listen_host: String,
    #[serde(default = "default_socks_port")]
    pub socks_port: u16,
    #[serde(default = "default_http_port")]
    pub http_port: Option<u16>,
    #[serde(default = "default_xray_path")]
    pub xray_path: String,
    #[serde(default)]
    pub metrics_history: Vec<MetricSample>,
    #[serde(default)]
    pub routing_rules: Vec<RoutingRule>,
    #[serde(default)]
    pub split_routing: SplitRoutingSettings,
    /// v0.2: saved subscription sources so `/api/subscriptions/refresh`
    /// can re-fetch them without re-entering URLs.
    #[serde(default)]
    pub subscriptions: Vec<StoredSubscription>,
    /// v0.2: favorite profile share-link strings. Stored by raw link so
    /// favorites survive profile renumbering across imports.
    #[serde(default)]
    pub favorites: Vec<String>,
    /// v0.2: per-profile benchmark statistics keyed by raw share link.
    #[serde(default)]
    pub stats: Vec<ProfileStats>,
}

impl Default for HincyrayState {
    fn default() -> Self {
        Self {
            profiles: Vec::new(),
            active_profile_id: None,
            auto_select: false,
            listen_host: default_listen_host(),
            socks_port: default_socks_port(),
            http_port: default_http_port(),
            xray_path: default_xray_path(),
            metrics_history: Vec::new(),
            routing_rules: Vec::new(),
            split_routing: SplitRoutingSettings::default(),
            subscriptions: Vec::new(),
            favorites: Vec::new(),
            stats: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetricSample {
    pub timestamp: u64,
    pub profile_id: usize,
    pub score: u32,
    pub passed: bool,
    pub latency_ms: u32,
    pub download_mbps: f32,
}

/// v0.2: persisted subscription source plus its last refresh metadata.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StoredSubscription {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_loaded_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default)]
    pub profile_count: usize,
}

/// v0.2: per-profile benchmark statistics keyed by raw share link so
/// stats survive profile renumbering across imports/refreshes.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProfileStats {
    pub profile_raw: String,
    #[serde(default)]
    pub last_latency_ms: u32,
    #[serde(default)]
    pub last_jitter_ms: u32,
    #[serde(default)]
    pub last_download_mbps: f32,
    #[serde(default)]
    pub last_loss_percent: f32,
    #[serde(default)]
    pub last_score: u32,
    #[serde(default)]
    pub success_count: u32,
    #[serde(default)]
    pub failure_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default)]
    pub last_checked_unix: u64,
}

/// WiFi split-routing controls. Rules are scoped to the TPROXY WiFi inbound;
/// SOCKS clients keep using the active profile.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SplitRoutingSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub auto_switch: bool,
    #[serde(default)]
    pub block_quic_global: bool,
    #[serde(default = "default_rule_source")]
    pub rule_source: String,
    #[serde(default = "default_vpn_subnet")]
    pub vpn_subnet: String,
    #[serde(default = "default_tproxy_port")]
    pub tproxy_port: u16,
}

impl Default for SplitRoutingSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            auto_switch: false,
            block_quic_global: false,
            rule_source: default_rule_source(),
            vpn_subnet: default_vpn_subnet(),
            tproxy_port: default_tproxy_port(),
        }
    }
}

fn default_rule_source() -> String {
    "metacubex-lite".to_owned()
}

fn default_vpn_subnet() -> String {
    "192.168.2.0/24".to_owned()
}

fn default_tproxy_port() -> u16 {
    10810
}

/// Policy-routing rule. `kind`/`pattern`/`target` existed as a v0.1
/// placeholder, so they remain strings for safe state migration. New UI uses
/// `domains`/`ips`/`services`; `target` is one of: `direct`, `active`,
/// `best`, or `profile:<id>`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RoutingRule {
    #[serde(default)]
    pub enabled: bool,
    pub name: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub pattern: String,
    #[serde(default = "default_routing_target")]
    pub target: String,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub ips: Vec<String>,
    #[serde(default)]
    pub services: Vec<String>,
}

fn default_routing_target() -> String {
    "active".to_owned()
}

fn default_listen_host() -> String {
    "127.0.0.1".to_owned()
}

fn default_socks_port() -> u16 {
    10808
}

fn default_http_port() -> Option<u16> {
    Some(10809)
}

fn default_xray_path() -> String {
    "xray".to_owned()
}

impl Daemon {
    fn new(state: HincyrayState, state_path: PathBuf, xray_config_path: PathBuf) -> Self {
        Self {
            inner: Arc::new(Mutex::new(DaemonInner {
                state,
                core: CoreManager::new(),
                bench: BenchRuntime::new(),
            })),
            state_path,
            xray_config_path,
        }
    }
}

/// Xray core lifecycle. Holds at most one child in memory; restart
/// stops and starts in sequence.
struct CoreManager {
    child: Option<Child>,
}

impl CoreManager {
    fn new() -> Self {
        Self { child: None }
    }

    fn is_running(&mut self) -> bool {
        let Some(child) = self.child.as_mut() else {
            return false;
        };
        match child.try_wait() {
            Ok(None) => true,
            Ok(Some(_)) => {
                self.child = None;
                false
            }
            Err(_) => false,
        }
    }

    fn status(&mut self) -> &'static str {
        if self.is_running() {
            "running"
        } else {
            "stopped"
        }
    }

    fn start(&mut self, xray_path: &str, config_path: &Path) -> Result<(), String> {
        if self.is_running() {
            return Ok(());
        }
        if !config_path.exists() {
            return Err(format!(
                "xray config not found at {}",
                config_path.display()
            ));
        }
        let child = Command::new(xray_path)
            .arg("run")
            .arg("-format")
            .arg("json")
            .arg("-c")
            .arg(config_path)
            .stdout(Stdio::null())
            // Long-lived daemon child: do not pipe stderr without a
            // reader, or the OS buffer fills and xray blocks. For the
            // MVP we discard stderr; route to a file later if a
            // diagnostics surface is needed.
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("xray spawn: {error}"))?;
        self.child = Some(child);
        Ok(())
    }

    fn stop(&mut self) -> Result<(), String> {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.child = None;
        Ok(())
    }

    fn restart(&mut self, xray_path: &str, config_path: &Path) -> Result<(), String> {
        self.stop()?;
        self.start(xray_path, config_path)
    }
}

fn resolve_state_path() -> PathBuf {
    if let Some(path) = std::env::var_os("HINCYRAY_STATE") {
        return PathBuf::from(path);
    }
    if Path::new("/opt/etc").is_dir() {
        return PathBuf::from("/opt/etc/hincyray/state.json");
    }
    if Path::new("/etc/openwrt_release").is_file() {
        return PathBuf::from("/etc/hincyray/state.json");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".config/hincyray/state.json");
    }
    PathBuf::from("./hincyray-state.json")
}

fn resolve_xray_config_path(state_path: &Path) -> PathBuf {
    if let Some(path) = std::env::var_os("HINCYRAY_XRAY_CONFIG") {
        return PathBuf::from(path);
    }
    state_path.with_file_name("xray-client.json")
}

fn load_state(state_path: &Path) -> HincyrayState {
    fs::read_to_string(state_path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

fn persist_state(state_path: &Path, state: &HincyrayState) -> Result<(), String> {
    if let Some(parent) = state_path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let text = serde_json::to_string_pretty(state).map_err(|error| error.to_string())?;
    let tmp = state_path.with_extension("tmp");
    fs::write(&tmp, &text).map_err(|error| error.to_string())?;
    fs::rename(&tmp, state_path).map_err(|error| error.to_string())
}

fn write_xray_config(path: &Path, config: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let text = serde_json::to_string_pretty(config).map_err(|error| error.to_string())?;
    fs::write(path, text).map_err(|error| error.to_string())
}

fn build_daemon_xray_config(state: &HincyrayState) -> Result<Value, String> {
    let Some(active_id) = state.active_profile_id else {
        return Err("no active profile".to_owned());
    };
    let Some(active_profile) = state
        .profiles
        .iter()
        .find(|profile| profile.id == active_id)
    else {
        return Err("active profile missing".to_owned());
    };

    if !state.split_routing.enabled {
        return build_xray_config(active_profile, &state.listen_host, state.socks_port);
    }

    let mut extra_profiles: Vec<(&Profile, String)> = Vec::new();
    let mut routes = Vec::new();
    for rule in state.routing_rules.iter().filter(|rule| rule.enabled) {
        let mut domains = normalize_route_items(&rule.domains);
        let mut ips = normalize_route_items(&rule.ips);
        for service in &rule.services {
            let service = service.trim().trim_start_matches("geosite:");
            if !service.is_empty() {
                domains.push(format!("geosite:{service}"));
            }
        }
        if domains.is_empty() && ips.is_empty() && !rule.pattern.trim().is_empty() {
            match rule.kind.as_str() {
                "ip" | "geoip" => ips.push(rule.pattern.trim().to_owned()),
                _ => domains.push(rule.pattern.trim().to_owned()),
            }
        }
        if domains.is_empty() && ips.is_empty() {
            continue;
        }

        let outbound_tag = match rule.target.as_str() {
            "direct" => DIRECT_OUTBOUND_TAG.to_owned(),
            "active" | "best" | "" => ACTIVE_OUTBOUND_TAG.to_owned(),
            target if target.starts_with("profile:") => {
                let id = target.trim_start_matches("profile:").parse::<usize>().ok();
                if let Some(id) = id {
                    if id == active_id {
                        ACTIVE_OUTBOUND_TAG.to_owned()
                    } else if let Some(profile) = state.profiles.iter().find(|p| p.id == id) {
                        let tag = format!("profile-{id}");
                        if !extra_profiles.iter().any(|(_, existing)| existing == &tag) {
                            extra_profiles.push((profile, tag.clone()));
                        }
                        tag
                    } else {
                        ACTIVE_OUTBOUND_TAG.to_owned()
                    }
                } else {
                    ACTIVE_OUTBOUND_TAG.to_owned()
                }
            }
            _ => ACTIVE_OUTBOUND_TAG.to_owned(),
        };

        let profile_for_quic = match rule.target.as_str() {
            "active" | "best" | "" => Some(active_profile),
            target if target.starts_with("profile:") => {
                let id = target.trim_start_matches("profile:").parse::<usize>().ok();
                id.and_then(|id| state.profiles.iter().find(|p| p.id == id))
            }
            _ => None,
        };
        let profile_quic = profile_for_quic
            .map(|profile| profile.block_quic)
            .unwrap_or(false);

        routes.push(XrayRouteRule {
            domains,
            ips,
            outbound_tag,
            block_quic: state.split_routing.block_quic_global || profile_quic,
        });
    }

    let active_block_quic = state.split_routing.block_quic_global || active_profile.block_quic;
    build_xray_router_config(
        active_profile,
        &extra_profiles,
        &routes,
        &state.listen_host,
        state.socks_port,
        Some(state.split_routing.tproxy_port),
        active_block_quic,
    )
}

fn normalize_route_items(items: &[String]) -> Vec<String> {
    items
        .iter()
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

/// Cached SOCKS fallback info for the running core. Captured under a
/// short lock and then used by `load_subscription_for_daemon` outside
/// the mutex so network I/O does not block the API.
struct DaemonProxyInfo {
    socks_url: String,
    core_running: bool,
}

/// Result of `load_subscription_for_daemon`: either a successful
/// `SubscriptionLoadReport` (regardless of whether direct or proxy
/// path was used), or the direct error paired with an optional proxy
/// fallback error. The `direct` error is always present on failure;
/// `proxy` is `Some` only when a proxy attempt was actually made and
/// also failed, so callers can build a single combined error string.
enum SubscriptionLoadOutcome {
    Ok(crate::profiles::SubscriptionLoadReport),
    Failed {
        direct: String,
        proxy: Option<String>,
    },
}

impl SubscriptionLoadOutcome {
    fn format_error(direct: &str, proxy: Option<&str>) -> String {
        match proxy {
            Some(proxy_err) => format!("{direct}; via proxy: {proxy_err}"),
            None => direct.to_owned(),
        }
    }
}

fn proxy_info_for_daemon(inner: &mut DaemonInner) -> DaemonProxyInfo {
    let core_running = inner.core.is_running();
    let socks_url = format!(
        "socks5h://{}:{}",
        inner.state.listen_host, inner.state.socks_port
    );
    DaemonProxyInfo {
        socks_url,
        core_running,
    }
}

/// Try direct fetch first; on failure, fall back to the local Xray
/// SOCKS inbound (`socks5h://127.0.0.1:<socks_port>`) iff the active
/// core is running. Network I/O happens here, so the caller must NOT
/// hold the daemon mutex.
fn load_subscription_for_daemon(
    source: &SubscriptionSource,
    proxy_info: &DaemonProxyInfo,
) -> SubscriptionLoadOutcome {
    match load_subscription_detailed_via_proxy(source, None) {
        Ok(report) => SubscriptionLoadOutcome::Ok(report),
        Err(direct_err) => {
            if !proxy_info.core_running {
                return SubscriptionLoadOutcome::Failed {
                    direct: direct_err,
                    proxy: None,
                };
            }
            match load_subscription_detailed_via_proxy(source, Some(&proxy_info.socks_url)) {
                Ok(report) => SubscriptionLoadOutcome::Ok(report),
                Err(proxy_err) => SubscriptionLoadOutcome::Failed {
                    direct: direct_err,
                    proxy: Some(proxy_err),
                },
            }
        }
    }
}

fn handle_connection(mut stream: TcpStream, daemon: &Daemon) -> Result<(), String> {
    let mut reader = BufReader::new(stream.try_clone().map_err(|error| error.to_string())?);

    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .map_err(|error| error.to_string())?;
    if request_line.is_empty() {
        return Ok(());
    }

    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        let lower = trimmed.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("content-length:") {
            content_length = rest.trim().parse::<usize>().unwrap_or(0);
        }
    }

    let mut body = Vec::new();
    if content_length > 0 {
        let limited = content_length.min(MAX_BODY_BYTES);
        body.resize(limited, 0u8);
        reader
            .read_exact(&mut body)
            .map_err(|error| error.to_string())?;
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        write_response(
            &mut stream,
            400,
            "application/json",
            &json!({"error": "malformed request line"}).to_string(),
        )?;
        return Ok(());
    }
    let method = parts[0];
    let raw_path = parts[1];
    let (path, _query) = split_query(raw_path);
    let body_text = String::from_utf8_lossy(&body).to_string();

    let (status, content_type, response_body) = dispatch(method, path, &body_text, daemon);
    write_response(&mut stream, status, content_type, &response_body)
}

fn split_query(raw_path: &str) -> (&str, Option<&str>) {
    if let Some(idx) = raw_path.find('?') {
        (&raw_path[..idx], Some(&raw_path[idx + 1..]))
    } else {
        (raw_path, None)
    }
}

fn dispatch(method: &str, path: &str, body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    match (method, path) {
        ("GET", "/") => (200, "text/html; charset=utf-8", index_html().to_owned()),
        ("GET", "/api/health") => (
            200,
            "application/json",
            json!({
                "ok": true,
                "service": "hincyray",
                "version": env!("CARGO_PKG_VERSION")
            })
            .to_string(),
        ),
        ("GET", "/api/status") => {
            let mut inner = lock(&daemon.inner);
            let active = inner
                .state
                .active_profile_id
                .and_then(|id| inner.state.profiles.iter().find(|p| p.id == id));
            let response = json!({
                "active_profile_id": inner.state.active_profile_id,
                "active_profile_name": active.map(|p| p.name.clone()),
                "profile_count": inner.state.profiles.len(),
                "auto_select": inner.state.auto_select,
                "listen_host": inner.state.listen_host,
                "socks_port": inner.state.socks_port,
                "http_port": inner.state.http_port,
                "xray_config_path": daemon.xray_config_path.to_string_lossy(),
                "state_path": daemon.state_path.to_string_lossy(),
                "xray_path": inner.state.xray_path,
                "core_status": inner.core.status(),
                "split_routing": inner.state.split_routing,
            });
            (200, "application/json", response.to_string())
        }
        ("GET", "/api/profiles") => {
            let inner = lock(&daemon.inner);
            let active_id = inner.state.active_profile_id;
            let profiles: Vec<Value> = inner
                .state
                .profiles
                .iter()
                .map(|profile| {
                    json!({
                        "id": profile.id,
                        "name": profile.name,
                        "protocol": profile.protocol.to_string(),
                        "transport": profile.transport(),
                        "address": profile.address,
                        "port": profile.port,
                        "active": active_id == Some(profile.id),
                        "group": profile.group,
                        "block_quic": profile.block_quic,
                    })
                })
                .collect();
            (
                200,
                "application/json",
                json!({"profiles": profiles}).to_string(),
            )
        }
        ("POST", "/api/profiles/import") => handle_import(body, daemon),
        ("POST", "/api/profiles/block-quic") => handle_profile_block_quic(body, daemon),
        ("POST", "/api/active-profile") => handle_set_active(body, daemon),
        ("GET", "/api/xray/config") => handle_get_xray_config(daemon),
        ("POST", "/api/core/start") => handle_core_start(daemon),
        ("POST", "/api/core/stop") => handle_core_stop(daemon),
        ("POST", "/api/core/restart") => handle_core_restart(daemon),
        ("GET", "/api/bench/status") => handle_bench_status(daemon),
        ("POST", "/api/bench/start") => handle_bench_start(body, daemon),
        ("POST", "/api/bench/stop") => handle_bench_stop(daemon),
        ("GET", "/api/stats") => handle_stats(daemon),
        ("POST", "/api/favorites/toggle") => handle_favorites_toggle(body, daemon),
        ("GET", "/api/favorites") => handle_favorites_list(daemon),
        ("POST", "/api/subscriptions/refresh") => handle_subscriptions_refresh(daemon),
        ("POST", "/api/subscriptions/refresh-one") => {
            handle_subscriptions_refresh_one(body, daemon)
        }
        ("GET", "/api/subscriptions") => handle_subscriptions_list(daemon),
        ("GET", "/api/routing") => handle_routing_get(daemon),
        ("POST", "/api/routing/settings") => handle_routing_settings(body, daemon),
        ("POST", "/api/routing/rules") => handle_routing_rules(body, daemon),
        ("POST", "/api/routing/catalog/refresh") => handle_routing_catalog_refresh(body, daemon),
        ("POST", "/api/routing/apply") => handle_routing_apply(daemon),
        ("GET", "/api/routing/tproxy-status") => handle_tproxy_status(daemon),
        ("POST", "/api/routing/tproxy-install") => handle_tproxy_script("tproxy-setup.sh"),
        ("POST", "/api/routing/tproxy-rollback") => handle_tproxy_script("tproxy-rollback.sh"),
        _ => (
            404,
            "application/json",
            json!({"error": "not found", "path": path}).to_string(),
        ),
    }
}

fn handle_import(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    // Accept two import body shapes (backward compatible):
    //   * JSON object `{"text": "...", "group": "Tutnet online"}` —
    //     `group` is optional. Empty/whitespace string is treated as
    //     `None`. Used by the web panel's optional "Group name" field.
    //   * Raw text (any other body) — old path; group stays `None`.
    let (import_text, group_param): (String, Option<String>) =
        match serde_json::from_str::<Value>(body) {
            Ok(value) if value.get("text").and_then(Value::as_str).is_some() => {
                let text = value
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                let group = value
                    .get("group")
                    .and_then(Value::as_str)
                    .map(|s| s.trim().to_owned())
                    .filter(|s| !s.is_empty());
                (text, group)
            }
            _ => (body.to_owned(), None),
        };

    let parsed = parse_input(&import_text);
    let mut incoming = parsed.profiles;
    // Tag direct profiles with the user-supplied group name (if any).
    for profile in &mut incoming {
        if profile.group.is_none() {
            profile.group = group_param.clone();
        }
    }
    let mut errors: Vec<String> = Vec::new();
    // Stored per-source outcome so we can update `subscriptions` meta
    // after merging profiles. `Ok` carries only the count since the
    // profiles themselves are moved into `incoming`.
    enum StoredOutcome {
        Ok { count: usize },
        Failed { error: String },
    }
    let mut loaded_subs: Vec<(SubscriptionSource, StoredOutcome)> = Vec::new();

    // Grab proxy fallback info under a short lock; network I/O below
    // runs without holding the mutex so the API stays responsive.
    let proxy_info = {
        let mut inner = lock(&daemon.inner);
        proxy_info_for_daemon(&mut inner)
    };

    for source in &parsed.subscriptions {
        let outcome = load_subscription_for_daemon(source, &proxy_info);
        let stored = match outcome {
            SubscriptionLoadOutcome::Ok(report) => {
                let count = report.profiles.len();
                // Tag subscription-loaded profiles with the source URL so
                // the UI can group them per subscription.
                let mut sub_profiles = report.profiles;
                for profile in &mut sub_profiles {
                    if profile.group.is_none() {
                        profile.group = Some(source.url.clone());
                    }
                }
                incoming.extend(sub_profiles);
                StoredOutcome::Ok { count }
            }
            SubscriptionLoadOutcome::Failed { direct, proxy } => {
                let error = SubscriptionLoadOutcome::format_error(&direct, proxy.as_deref());
                errors.push(error.clone());
                StoredOutcome::Failed { error }
            }
        };
        loaded_subs.push((source.clone(), stored));
    }

    let mut inner = lock(&daemon.inner);
    let count_before = inner.state.profiles.len();
    let mut seen: HashSet<String> = inner
        .state
        .profiles
        .iter()
        .map(|profile| profile.raw.clone())
        .collect();
    for mut profile in incoming {
        if seen.insert(profile.raw.clone()) {
            profile.id = inner.state.profiles.len();
            inner.state.profiles.push(profile);
        } else if profile.group.is_some() {
            // Dedup: keep the existing profile but, if it has no group
            // yet, adopt the new one so a later import with a group
            // name still tags previously-seen direct profiles.
            let raw = profile.raw.clone();
            if let Some(existing) = inner
                .state
                .profiles
                .iter_mut()
                .find(|p| p.raw == raw && p.group.is_none())
            {
                existing.group = profile.group.take();
            }
        }
    }
    let count_after = inner.state.profiles.len();
    let added = count_after.saturating_sub(count_before);

    // v0.2: persist any subscription URLs from the import so they can be
    // refreshed later via /api/subscriptions/refresh. Merge by URL.
    let now = unix_now();
    for (source, outcome) in &loaded_subs {
        let stored = inner
            .state
            .subscriptions
            .iter_mut()
            .find(|existing| existing.url == source.url);
        let entry = if let Some(stored) = stored {
            stored
        } else {
            inner.state.subscriptions.push(StoredSubscription {
                url: source.url.clone(),
                last_loaded_unix: None,
                last_error: None,
                profile_count: 0,
            });
            inner
                .state
                .subscriptions
                .last_mut()
                .expect("just pushed a subscription entry")
        };
        match outcome {
            StoredOutcome::Ok { count } => {
                entry.last_loaded_unix = Some(now);
                entry.last_error = None;
                entry.profile_count = *count;
            }
            StoredOutcome::Failed { error } => {
                entry.last_error = Some(error.clone());
            }
        }
    }

    if let Err(error) = persist_state(&daemon.state_path, &inner.state) {
        errors.push(format!("persist: {error}"));
    }

    let response = json!({
        "profile_count": count_after,
        "added": added,
        "subscriptions": parsed.subscriptions.len(),
        "candidate_count": parsed.candidates,
        "unsupported_placeholders": parsed.unsupported_placeholders,
        "group": group_param,
        "errors": errors,
    });
    (200, "application/json", response.to_string())
}

fn handle_set_active(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return (
            400,
            "application/json",
            json!({"error": "invalid JSON body"}).to_string(),
        );
    };
    let id = value
        .get("profile_id")
        .and_then(Value::as_u64)
        .or_else(|| value.get("id").and_then(Value::as_u64));
    let Some(id) = id else {
        return (
            400,
            "application/json",
            json!({"error": "missing profile_id"}).to_string(),
        );
    };
    let id = id as usize;

    let mut inner = lock(&daemon.inner);
    let Some(profile) = inner
        .state
        .profiles
        .iter()
        .find(|profile| profile.id == id)
        .cloned()
    else {
        return (
            404,
            "application/json",
            json!({"error": "profile not found", "profile_id": id}).to_string(),
        );
    };

    inner.state.active_profile_id = Some(id);
    let config = match build_daemon_xray_config(&inner.state) {
        Ok(config) => config,
        Err(error) => {
            return (
                400,
                "application/json",
                json!({"error": error, "profile_id": id}).to_string(),
            );
        }
    };

    if let Err(error) = write_xray_config(&daemon.xray_config_path, &config) {
        return (
            500,
            "application/json",
            json!({"error": format!("write xray config: {error}")}).to_string(),
        );
    }

    if let Err(error) = persist_state(&daemon.state_path, &inner.state) {
        return (
            500,
            "application/json",
            json!({"error": format!("persist state: {error}")}).to_string(),
        );
    }

    let response = json!({
        "active_profile_id": id,
        "active_profile_name": profile.name,
        "xray_config_path": daemon.xray_config_path.to_string_lossy(),
    });
    (200, "application/json", response.to_string())
}

fn handle_get_xray_config(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    match build_daemon_xray_config(&inner.state) {
        Ok(config) => (200, "application/json", config.to_string()),
        Err(error) => (
            400,
            "application/json",
            json!({"error": error, "profile_id": inner.state.active_profile_id}).to_string(),
        ),
    }
}

fn handle_core_start(daemon: &Daemon) -> (u16, &'static str, String) {
    let mut inner = lock(&daemon.inner);
    let xray_path = inner.state.xray_path.clone();
    let config_path = daemon.xray_config_path.clone();
    match inner.core.start(&xray_path, &config_path) {
        Ok(()) => (
            200,
            "application/json",
            json!({"core_status": inner.core.status()}).to_string(),
        ),
        Err(error) => (500, "application/json", json!({"error": error}).to_string()),
    }
}

fn handle_core_stop(daemon: &Daemon) -> (u16, &'static str, String) {
    let mut inner = lock(&daemon.inner);
    match inner.core.stop() {
        Ok(()) => (
            200,
            "application/json",
            json!({"core_status": inner.core.status()}).to_string(),
        ),
        Err(error) => (500, "application/json", json!({"error": error}).to_string()),
    }
}

fn handle_core_restart(daemon: &Daemon) -> (u16, &'static str, String) {
    let mut inner = lock(&daemon.inner);
    let xray_path = inner.state.xray_path.clone();
    let config_path = daemon.xray_config_path.clone();
    match inner.core.restart(&xray_path, &config_path) {
        Ok(()) => (
            200,
            "application/json",
            json!({"core_status": inner.core.status()}).to_string(),
        ),
        Err(error) => (500, "application/json", json!({"error": error}).to_string()),
    }
}

fn handle_bench_status(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    let job = inner.bench.snapshot();
    let method = job.method.map(|m| m.as_str().to_owned());
    let summary = bench_summary(&job);
    let response = json!({
        "running": job.running,
        "method": method,
        "total": job.total,
        "completed": job.completed,
        "current_profile_id": job.current_profile_id,
        "current_profile_name": job.current_profile_name,
        "last_updated": job.last_updated,
        "cancel_requested": job.cancel_requested,
        "results": job.results,
        "summary": summary,
    });
    (200, "application/json", response.to_string())
}

fn bench_summary(job: &BenchJob) -> Value {
    let total = job.results.len();
    let passed = job.results.iter().filter(|r| r.success).count();
    let failed = total.saturating_sub(passed);
    let avg_latency = if passed == 0 {
        0.0
    } else {
        let sum: u64 = job
            .results
            .iter()
            .filter(|r| r.success)
            .map(|r| r.latency_ms as u64)
            .sum();
        sum as f32 / passed as f32
    };
    json!({
        "total": total,
        "passed": passed,
        "failed": failed,
        "avg_latency_ms": avg_latency,
    })
}

fn handle_bench_start(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return (
            400,
            "application/json",
            json!({"error": "invalid JSON body"}).to_string(),
        );
    };
    let method_str = value.get("method").and_then(Value::as_str).unwrap_or("tcp");
    let Some(method) = BenchMethod::parse_method(method_str) else {
        return (
            400,
            "application/json",
            json!({
                "error": "unknown method",
                "supported": ["tcp", "head", "get"],
            })
            .to_string(),
        );
    };
    let probe_url = value
        .get("probe_url")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(DEFAULT_PROBE_URL)
        .to_owned();
    let download_url = value
        .get("download_url")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(DEFAULT_DOWNLOAD_URL)
        .to_owned();

    // Decide which profiles to benchmark. Either an explicit `profile_ids`
    // array (single ping if length 1) or all imported profiles.
    let requested_ids: Option<Vec<usize>> =
        value
            .get("profile_ids")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_u64().map(|n| n as usize))
                    .collect()
            });

    let (profiles, xray_path) = {
        let inner = lock(&daemon.inner);
        if inner.bench.is_running() {
            return (
                409,
                "application/json",
                json!({"error": "benchmark already running; call /api/bench/stop first"})
                    .to_string(),
            );
        }
        let profiles: Vec<Profile> = match requested_ids {
            Some(ids) if !ids.is_empty() => inner
                .state
                .profiles
                .iter()
                .filter(|p| ids.contains(&p.id))
                .cloned()
                .collect(),
            _ => inner.state.profiles.clone(),
        };
        (profiles, inner.state.xray_path.clone())
    };

    if profiles.is_empty() {
        return (
            400,
            "application/json",
            json!({"error": "no profiles to benchmark; import first"}).to_string(),
        );
    }

    let job = Arc::new(Mutex::new(BenchJob::default()));
    let cancel = Arc::new(AtomicBool::new(false));
    let daemon_for_callback = daemon.clone();
    let on_result = Box::new(move |result: BenchResult| {
        apply_bench_result(&daemon_for_callback, result);
    });

    let handle = run_bench(
        profiles,
        method,
        probe_url,
        download_url,
        xray_path,
        Arc::clone(&job),
        Arc::clone(&cancel),
        on_result,
    );

    {
        let mut inner = lock(&daemon.inner);
        // Drop a previously finished handle, if any.
        if let Some(prev) = inner.bench.handle.take() {
            let _ = prev.join();
        }
        inner.bench.job = Some(job);
        inner.bench.cancel = Some(cancel);
        inner.bench.handle = Some(handle);
    }

    let inner = lock(&daemon.inner);
    let snapshot = inner.bench.snapshot();
    let response = json!({
        "started": true,
        "method": method.as_str(),
        "total": snapshot.total,
        "running": snapshot.running,
    });
    (200, "application/json", response.to_string())
}

fn handle_bench_stop(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    let running = inner.bench.is_running();
    if running {
        inner.bench.request_cancel();
    }
    (
        200,
        "application/json",
        json!({
            "stopped": running,
            "cancel_requested": running,
        })
        .to_string(),
    )
}

/// Apply a single benchmark result to persisted state: update the
/// per-profile `ProfileStats`, push a `MetricSample` (capped at
/// `MAX_HISTORY_SAMPLES`), and persist. Called from the benchmark
/// worker thread via the `on_result` callback.
fn apply_bench_result(daemon: &Daemon, result: BenchResult) {
    let mut inner = lock(&daemon.inner);
    let now = result.timestamp;

    // Find or insert the stats entry by index to avoid aliased mutable
    // borrows of `inner.state.stats` while we also touch
    // `inner.state.metrics_history` below.
    let stats_idx = match inner
        .state
        .stats
        .iter()
        .position(|s| s.profile_raw == result.profile_raw)
    {
        Some(idx) => idx,
        None => {
            inner.state.stats.push(ProfileStats {
                profile_raw: result.profile_raw.clone(),
                ..Default::default()
            });
            inner.state.stats.len() - 1
        }
    };

    {
        let stats_entry = &mut inner.state.stats[stats_idx];
        if result.success {
            stats_entry.last_latency_ms = result.latency_ms;
            stats_entry.last_jitter_ms = result.jitter_ms;
            stats_entry.last_download_mbps = result.download_mbps;
            stats_entry.last_loss_percent = result.loss_percent;
            stats_entry.last_score = result.score;
            stats_entry.last_error = None;
            stats_entry.success_count = stats_entry.success_count.saturating_add(1);
        } else {
            stats_entry.failure_count = stats_entry.failure_count.saturating_add(1);
            stats_entry.last_error = result.error.clone();
        }
        stats_entry.last_checked_unix = now;
    }

    inner.state.metrics_history.push(MetricSample {
        timestamp: now,
        profile_id: result.profile_id,
        score: result.score,
        passed: result.success,
        latency_ms: result.latency_ms,
        download_mbps: result.download_mbps,
    });
    if inner.state.metrics_history.len() > MAX_HISTORY_SAMPLES {
        let excess = inner.state.metrics_history.len() - MAX_HISTORY_SAMPLES;
        inner.state.metrics_history.drain(0..excess);
    }

    let _ = persist_state(&daemon.state_path, &inner.state);
}

fn handle_stats(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    let active_id = inner.state.active_profile_id;
    let favorites = &inner.state.favorites;
    let stats = &inner.state.stats;
    let profiles = &inner.state.profiles;

    let mut entries: Vec<Value> = profiles
        .iter()
        .map(|profile| {
            let stat = stats.iter().find(|s| s.profile_raw == profile.raw);
            let favorite = favorites.iter().any(|raw| raw == &profile.raw);
            json!({
                "profile_id": profile.id,
                "name": profile.name,
                "protocol": profile.protocol.to_string(),
                "transport": profile.transport(),
                "address": profile.address,
                "port": profile.port,
                "active": active_id == Some(profile.id),
                "favorite": favorite,
                "group": profile.group,
                "last_latency_ms": stat.map(|s| s.last_latency_ms).unwrap_or(0),
                "last_jitter_ms": stat.map(|s| s.last_jitter_ms).unwrap_or(0),
                "last_download_mbps": stat.map(|s| s.last_download_mbps).unwrap_or(0.0),
                "last_loss_percent": stat.map(|s| s.last_loss_percent).unwrap_or(0.0),
                "score": stat.map(|s| s.last_score).unwrap_or(0),
                "success_count": stat.map(|s| s.success_count).unwrap_or(0),
                "failure_count": stat.map(|s| s.failure_count).unwrap_or(0),
                "last_error": stat.and_then(|s| s.last_error.clone()),
                "last_checked": stat.map(|s| s.last_checked_unix).unwrap_or(0),
            })
        })
        .collect();
    // Sort by score descending so the rating table is meaningful by default.
    entries.sort_by(|a, b| {
        let sa = a.get("score").and_then(Value::as_u64).unwrap_or(0);
        let sb = b.get("score").and_then(Value::as_u64).unwrap_or(0);
        sb.cmp(&sa)
    });

    let response = json!({
        "stats": entries,
        "favorites_count": favorites.len(),
        "profiles_count": profiles.len(),
    });
    (200, "application/json", response.to_string())
}

fn handle_profile_block_quic(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return (
            400,
            "application/json",
            json!({"error": "invalid JSON body"}).to_string(),
        );
    };
    let Some(id) = value
        .get("profile_id")
        .and_then(Value::as_u64)
        .map(|n| n as usize)
    else {
        return (
            400,
            "application/json",
            json!({"error": "missing profile_id"}).to_string(),
        );
    };
    let Some(block) = value.get("block_quic").and_then(Value::as_bool) else {
        return (
            400,
            "application/json",
            json!({"error": "missing block_quic"}).to_string(),
        );
    };

    let mut inner = lock(&daemon.inner);
    let Some(profile) = inner.state.profiles.iter_mut().find(|p| p.id == id) else {
        return (
            404,
            "application/json",
            json!({"error": "profile not found", "profile_id": id}).to_string(),
        );
    };
    profile.block_quic = block;
    if let Err(error) = persist_state(&daemon.state_path, &inner.state) {
        return (
            500,
            "application/json",
            json!({"error": format!("persist state: {error}")}).to_string(),
        );
    }
    (
        200,
        "application/json",
        json!({"profile_id": id, "block_quic": block}).to_string(),
    )
}

fn handle_favorites_toggle(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return (
            400,
            "application/json",
            json!({"error": "invalid JSON body"}).to_string(),
        );
    };
    let Some(id) = value
        .get("profile_id")
        .and_then(Value::as_u64)
        .map(|n| n as usize)
    else {
        return (
            400,
            "application/json",
            json!({"error": "missing profile_id"}).to_string(),
        );
    };

    let mut inner = lock(&daemon.inner);
    let Some(profile) = inner.state.profiles.iter().find(|p| p.id == id).cloned() else {
        return (
            404,
            "application/json",
            json!({"error": "profile not found", "profile_id": id}).to_string(),
        );
    };

    let raw = profile.raw.clone();
    let already = inner
        .state
        .favorites
        .iter()
        .position(|existing| existing == &raw);
    let now_favorite = if let Some(idx) = already {
        inner.state.favorites.remove(idx);
        false
    } else {
        inner.state.favorites.push(raw.clone());
        true
    };

    if let Err(error) = persist_state(&daemon.state_path, &inner.state) {
        return (
            500,
            "application/json",
            json!({"error": format!("persist state: {error}")}).to_string(),
        );
    }

    let response = json!({
        "profile_id": id,
        "profile_name": profile.name,
        "favorite": now_favorite,
    });
    (200, "application/json", response.to_string())
}

fn handle_favorites_list(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    let favorites = &inner.state.favorites;
    let entries: Vec<Value> = inner
        .state
        .profiles
        .iter()
        .filter(|p| favorites.iter().any(|raw| raw == &p.raw))
        .map(|p| {
            json!({
                "profile_id": p.id,
                "name": p.name,
                "protocol": p.protocol.to_string(),
                "address": p.address,
                "port": p.port,
            })
        })
        .collect();
    (
        200,
        "application/json",
        json!({"favorites": entries, "count": entries.len()}).to_string(),
    )
}

fn handle_subscriptions_refresh(daemon: &Daemon) -> (u16, &'static str, String) {
    // Read saved subscription sources plus the SOCKS fallback info
    // under a single short lock; network I/O happens below without
    // holding the mutex so the API stays responsive.
    let (subs, proxy_info) = {
        let mut inner = lock(&daemon.inner);
        let subs: Vec<SubscriptionSource> = inner
            .state
            .subscriptions
            .iter()
            .map(|stored| SubscriptionSource {
                url: stored.url.clone(),
            })
            .collect();
        let proxy_info = proxy_info_for_daemon(&mut inner);
        (subs, proxy_info)
    };

    if subs.is_empty() {
        return (
            200,
            "application/json",
            json!({
                "refreshed": 0,
                "added": 0,
                "errors": Vec::<String>::new(),
                "note": "no saved subscriptions; import a subscription URL first"
            })
            .to_string(),
        );
    }

    let mut errors: Vec<String> = Vec::new();
    let mut added_total = 0usize;
    let mut refreshed = 0usize;
    let now = unix_now();

    for source in &subs {
        let outcome = load_subscription_for_daemon(source, &proxy_info);
        let mut inner = lock(&daemon.inner);
        let stored = inner
            .state
            .subscriptions
            .iter_mut()
            .find(|s| s.url == source.url);
        match outcome {
            SubscriptionLoadOutcome::Ok(report) => {
                let count = report.profiles.len();
                if let Some(stored) = stored {
                    stored.last_loaded_unix = Some(now);
                    stored.last_error = None;
                    stored.profile_count = count;
                }
                let count_before = inner.state.profiles.len();
                let mut seen: HashSet<String> =
                    inner.state.profiles.iter().map(|p| p.raw.clone()).collect();
                let mut sub_profiles = report.profiles;
                // Tag subscription-loaded profiles with the source URL
                // so they keep their group across refreshes.
                for profile in &mut sub_profiles {
                    if profile.group.is_none() {
                        profile.group = Some(source.url.clone());
                    }
                }
                for mut profile in sub_profiles {
                    if seen.insert(profile.raw.clone()) {
                        profile.id = inner.state.profiles.len();
                        inner.state.profiles.push(profile);
                    } else if profile.group.is_some() {
                        let raw = profile.raw.clone();
                        if let Some(existing) = inner
                            .state
                            .profiles
                            .iter_mut()
                            .find(|p| p.raw == raw && p.group.is_none())
                        {
                            existing.group = profile.group.take();
                        }
                    }
                }
                let added = inner.state.profiles.len().saturating_sub(count_before);
                added_total += added;
                refreshed += 1;
            }
            SubscriptionLoadOutcome::Failed { direct, proxy } => {
                let error = SubscriptionLoadOutcome::format_error(&direct, proxy.as_deref());
                if let Some(stored) = stored {
                    stored.last_error = Some(error.clone());
                }
                errors.push(error);
            }
        }
        let _ = persist_state(&daemon.state_path, &inner.state);
    }

    let response = json!({
        "refreshed": refreshed,
        "added": added_total,
        "errors": errors,
    });
    (200, "application/json", response.to_string())
}

/// Refresh a single saved subscription by URL. Body: `{"url": "..."}`.
/// Used by the per-group "Refresh" button in the web panel so the
/// user can re-fetch one subscription without re-running all of them.
/// Behaviour mirrors `handle_subscriptions_refresh` for the matched
/// source; unknown URLs return 404.
fn handle_subscriptions_refresh_one(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return (
            400,
            "application/json",
            json!({"error": "invalid JSON body"}).to_string(),
        );
    };
    let Some(url) = value.get("url").and_then(Value::as_str) else {
        return (
            400,
            "application/json",
            json!({"error": "missing url"}).to_string(),
        );
    };
    let url = url.trim();
    if url.is_empty() {
        return (
            400,
            "application/json",
            json!({"error": "missing url"}).to_string(),
        );
    }

    // Confirm the URL is a known saved subscription before any network
    // I/O, so we never fetch an arbitrary URL supplied by the client.
    let (proxy_info, exists) = {
        let mut inner = lock(&daemon.inner);
        let exists = inner.state.subscriptions.iter().any(|s| s.url == url);
        (proxy_info_for_daemon(&mut inner), exists)
    };
    if !exists {
        return (
            404,
            "application/json",
            json!({"error": "subscription not found", "url": url}).to_string(),
        );
    }

    let source = SubscriptionSource {
        url: url.to_owned(),
    };
    let outcome = load_subscription_for_daemon(&source, &proxy_info);
    let now = unix_now();

    let mut inner = lock(&daemon.inner);
    let stored = inner
        .state
        .subscriptions
        .iter_mut()
        .find(|s| s.url == source.url);
    match outcome {
        SubscriptionLoadOutcome::Ok(report) => {
            let count = report.profiles.len();
            if let Some(stored) = stored {
                stored.last_loaded_unix = Some(now);
                stored.last_error = None;
                stored.profile_count = count;
            }
            let mut seen: HashSet<String> =
                inner.state.profiles.iter().map(|p| p.raw.clone()).collect();
            let mut sub_profiles = report.profiles;
            for profile in &mut sub_profiles {
                if profile.group.is_none() {
                    profile.group = Some(source.url.clone());
                }
            }
            let mut added = 0usize;
            for mut profile in sub_profiles {
                if seen.insert(profile.raw.clone()) {
                    profile.id = inner.state.profiles.len();
                    inner.state.profiles.push(profile);
                    added += 1;
                } else if profile.group.is_some() {
                    let raw = profile.raw.clone();
                    if let Some(existing) = inner
                        .state
                        .profiles
                        .iter_mut()
                        .find(|p| p.raw == raw && p.group.is_none())
                    {
                        existing.group = profile.group.take();
                    }
                }
            }
            let _ = persist_state(&daemon.state_path, &inner.state);
            let response = json!({
                "url": source.url,
                "refreshed": 1,
                "added": added,
                "profile_count": count,
                "errors": Vec::<String>::new(),
            });
            (200, "application/json", response.to_string())
        }
        SubscriptionLoadOutcome::Failed { direct, proxy } => {
            let error = SubscriptionLoadOutcome::format_error(&direct, proxy.as_deref());
            if let Some(stored) = stored {
                stored.last_error = Some(error.clone());
            }
            let _ = persist_state(&daemon.state_path, &inner.state);
            (
                200,
                "application/json",
                json!({
                    "url": source.url,
                    "refreshed": 0,
                    "added": 0,
                    "errors": [error],
                })
                .to_string(),
            )
        }
    }
}

fn handle_subscriptions_list(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    let entries: Vec<Value> = inner
        .state
        .subscriptions
        .iter()
        .map(|s| {
            json!({
                "url": s.url,
                "profile_count": s.profile_count,
                "last_loaded_unix": s.last_loaded_unix,
                "last_error": s.last_error,
            })
        })
        .collect();
    (
        200,
        "application/json",
        json!({"subscriptions": entries, "count": entries.len()}).to_string(),
    )
}

fn handle_routing_get(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    let response = json!({
        "settings": inner.state.split_routing,
        "rules": inner.state.routing_rules,
        "catalog": popular_service_catalog(),
        "sources": rule_sources(),
    });
    (200, "application/json", response.to_string())
}

fn handle_routing_settings(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return (
            400,
            "application/json",
            json!({"error": "invalid JSON body"}).to_string(),
        );
    };
    let mut inner = lock(&daemon.inner);
    if let Some(v) = value.get("enabled").and_then(Value::as_bool) {
        inner.state.split_routing.enabled = v;
    }
    if let Some(v) = value.get("auto_switch").and_then(Value::as_bool) {
        inner.state.split_routing.auto_switch = v;
    }
    if let Some(v) = value.get("block_quic_global").and_then(Value::as_bool) {
        inner.state.split_routing.block_quic_global = v;
    }
    if let Some(v) = value.get("rule_source").and_then(Value::as_str) {
        inner.state.split_routing.rule_source = v.trim().to_owned();
    }
    if let Some(v) = value
        .get("vpn_subnet")
        .and_then(Value::as_str)
        .filter(|v| !v.trim().is_empty())
    {
        inner.state.split_routing.vpn_subnet = v.trim().to_owned();
    }
    if let Some(v) = value.get("tproxy_port").and_then(Value::as_u64) {
        inner.state.split_routing.tproxy_port = v as u16;
    }
    if let Err(error) = persist_state(&daemon.state_path, &inner.state) {
        return (
            500,
            "application/json",
            json!({"error": format!("persist state: {error}")}).to_string(),
        );
    }
    (
        200,
        "application/json",
        json!({"settings": inner.state.split_routing}).to_string(),
    )
}

fn handle_routing_rules(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return (
            400,
            "application/json",
            json!({"error": "invalid JSON body"}).to_string(),
        );
    };
    let rules_value = value.get("rules").cloned().unwrap_or(value);
    let Ok(mut rules) = serde_json::from_value::<Vec<RoutingRule>>(rules_value) else {
        return (
            400,
            "application/json",
            json!({"error": "expected rules array"}).to_string(),
        );
    };
    for rule in &mut rules {
        rule.name = rule.name.trim().to_owned();
        rule.kind = rule.kind.trim().to_owned();
        rule.pattern = rule.pattern.trim().to_owned();
        rule.target = rule.target.trim().to_owned();
        if rule.target.is_empty() {
            rule.target = default_routing_target();
        }
        rule.domains = normalize_route_items(&rule.domains);
        rule.ips = normalize_route_items(&rule.ips);
        rule.services = normalize_route_items(&rule.services);
    }
    let mut inner = lock(&daemon.inner);
    inner.state.routing_rules = rules;
    if let Err(error) = persist_state(&daemon.state_path, &inner.state) {
        return (
            500,
            "application/json",
            json!({"error": format!("persist state: {error}")}).to_string(),
        );
    }
    (
        200,
        "application/json",
        json!({"rules": inner.state.routing_rules}).to_string(),
    )
}

fn handle_routing_catalog_refresh(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let source = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("source")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(default_rule_source);
    let proxy_info = {
        let mut inner = lock(&daemon.inner);
        proxy_info_for_daemon(&mut inner)
    };
    let proxy = proxy_info
        .core_running
        .then_some(proxy_info.socks_url.as_str());
    match fetch_service_catalog(&source, proxy) {
        Ok(catalog) => (
            200,
            "application/json",
            json!({"source": source, "catalog": catalog}).to_string(),
        ),
        Err(error) => (
            500,
            "application/json",
            json!({"error": error, "fallback": popular_service_catalog()}).to_string(),
        ),
    }
}

fn handle_routing_apply(daemon: &Daemon) -> (u16, &'static str, String) {
    let mut inner = lock(&daemon.inner);
    let config = match build_daemon_xray_config(&inner.state) {
        Ok(config) => config,
        Err(error) => return (400, "application/json", json!({"error": error}).to_string()),
    };
    if let Err(error) = write_xray_config(&daemon.xray_config_path, &config) {
        return (
            500,
            "application/json",
            json!({"error": format!("write xray config: {error}")}).to_string(),
        );
    }
    let was_running = inner.core.is_running();
    let xray_path = inner.state.xray_path.clone();
    let config_path = daemon.xray_config_path.clone();
    let core_status = if was_running {
        match inner.core.restart(&xray_path, &config_path) {
            Ok(()) => inner.core.status().to_owned(),
            Err(error) => return (500, "application/json", json!({"error": error}).to_string()),
        }
    } else {
        inner.core.status().to_owned()
    };
    (
        200,
        "application/json",
        json!({"applied": true, "core_status": core_status}).to_string(),
    )
}

fn handle_tproxy_status(_daemon: &Daemon) -> (u16, &'static str, String) {
    let chain = shell_status("iptables -t mangle -S HINCYRAY >/dev/null 2>&1");
    let rule = shell_status("ip rule show 2>/dev/null | grep -q 'fwmark 0x111' ");
    let port = shell_status("netstat -ltnp 2>/dev/null | grep -q ':10810' ");
    (
        200,
        "application/json",
        json!({"chain": chain, "ip_rule": rule, "tproxy_port": port}).to_string(),
    )
}

fn handle_tproxy_script(script_name: &str) -> (u16, &'static str, String) {
    let script = format!("/opt/etc/hincyray/scripts/{script_name}");
    if !Path::new(&script).is_file() {
        return (
            404,
            "application/json",
            json!({"error": "script not found", "script": script}).to_string(),
        );
    }
    match Command::new("sh").arg(&script).output() {
        Ok(output) => {
            let ok = output.status.success();
            let status = if ok { 200 } else { 500 };
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            (
                status,
                "application/json",
                json!({"ok": ok, "stdout": stdout, "stderr": stderr}).to_string(),
            )
        }
        Err(error) => (
            500,
            "application/json",
            json!({"error": error.to_string()}).to_string(),
        ),
    }
}

fn shell_status(command: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(command)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn rule_sources() -> Vec<Value> {
    vec![
        json!({"id":"metacubex-lite","name":"MetaCubeX Lite","kind":"xray-dat","recommended":true}),
        json!({"id":"metacubex-full","name":"MetaCubeX Full","kind":"xray-dat"}),
        json!({"id":"loyalsoldier","name":"Loyalsoldier v2ray-rules-dat","kind":"xray-dat"}),
        json!({"id":"v2fly-dlc","name":"v2fly/domain-list-community","kind":"geosite-catalog"}),
        json!({"id":"blackmatrix7","name":"blackmatrix7 ios_rule_script","kind":"service-catalog"}),
        json!({"id":"custom","name":"Custom URLs","kind":"manual"}),
    ]
}

fn popular_service_catalog() -> Vec<Value> {
    let services = [
        (
            "youtube",
            "YouTube",
            ["youtube", "googlevideo", "ytimg"].as_slice(),
        ),
        (
            "instagram",
            "Instagram",
            ["instagram", "facebook", "fbcdn"].as_slice(),
        ),
        ("telegram", "Telegram", ["telegram"].as_slice()),
        ("discord", "Discord", ["discord"].as_slice()),
        ("tiktok", "TikTok", ["tiktok"].as_slice()),
        ("netflix", "Netflix", ["netflix"].as_slice()),
        ("twitch", "Twitch", ["twitch"].as_slice()),
        ("spotify", "Spotify", ["spotify"].as_slice()),
        ("steam", "Steam", ["steam"].as_slice()),
        ("google", "Google", ["google"].as_slice()),
        ("apple", "Apple", ["apple"].as_slice()),
        ("microsoft", "Microsoft", ["microsoft"].as_slice()),
        ("openai", "OpenAI", ["openai"].as_slice()),
        ("cloudflare", "Cloudflare", ["cloudflare"].as_slice()),
        ("ru", "Russia / RU", ["ru"].as_slice()),
    ];
    services
        .into_iter()
        .map(|(id, name, geosite)| json!({"id": id, "name": name, "geosite": geosite}))
        .collect()
}

fn fetch_service_catalog(source: &str, proxy: Option<&str>) -> Result<Vec<Value>, String> {
    match source {
        "v2fly-dlc" => fetch_github_names(
            "https://api.github.com/repos/v2fly/domain-list-community/contents/data?ref=master",
            proxy,
        ),
        "blackmatrix7" => fetch_github_names(
            "https://api.github.com/repos/blackmatrix7/ios_rule_script/contents/rule/Clash?ref=master",
            proxy,
        ),
        // Dat releases are assets, not a category index. Keep a curated
        // catalog while using the selected project for geosite/geoip files.
        "metacubex-lite" | "metacubex-full" | "loyalsoldier" | "custom" => {
            Ok(popular_service_catalog())
        }
        other => Err(format!("unknown rule source: {other}")),
    }
}

fn fetch_github_names(url: &str, proxy: Option<&str>) -> Result<Vec<Value>, String> {
    let mut builder = reqwest::blocking::Client::builder().timeout(Duration::from_secs(20));
    if let Some(proxy) = proxy {
        let proxy = reqwest::Proxy::all(proxy).map_err(|error| error.to_string())?;
        builder = builder.proxy(proxy);
    }
    let client = builder.build().map_err(|error| error.to_string())?;
    let response = client
        .get(url)
        .header("User-Agent", "HincyRay")
        .send()
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!("GitHub returned HTTP {}", response.status()));
    }
    let text = response.text().map_err(|error| error.to_string())?;
    let value: Value = serde_json::from_str(&text).map_err(|error| error.to_string())?;
    let Some(items) = value.as_array() else {
        return Err("GitHub response is not an array".to_owned());
    };
    let mut names: Vec<String> = items
        .iter()
        .filter_map(|item| item.get("name").and_then(Value::as_str))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    names.sort_by_key(|name| name.to_ascii_lowercase());
    names.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    Ok(names
        .into_iter()
        .take(800)
        .map(|name| {
            let id = name.to_ascii_lowercase();
            json!({"id": id, "name": name, "geosite": [id]})
        })
        .collect())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
) -> Result<(), String> {
    let status_text = status_text(status);
    let head = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: {content_type}\r\nContent-Length: {len}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        len = body.len()
    );
    stream
        .write_all(head.as_bytes())
        .map_err(|error| error.to_string())?;
    stream
        .write_all(body.as_bytes())
        .map_err(|error| error.to_string())?;
    stream.flush().map_err(|error| error.to_string())
}

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

fn index_html() -> &'static str {
    r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HincyRay</title>
<style>
:root{color-scheme:light dark}
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;max-width:1180px;margin:1.4em auto;padding:0 .8em;color:#1f2328;background:#f6f8fa}
h1{margin:0 0 .15em;font-size:1.6em}
h2{margin:1.3em 0 .4em;font-size:1.05em;border-bottom:1px solid #d0d7de;padding-bottom:.25em}
h2 .toggle{font-size:.78em;font-weight:normal;color:#1f6feb;cursor:pointer;margin-left:.5em}
.subtle{color:#57606a;font-size:.88em}
code{background:#eaeef2;padding:.12em .35em;border-radius:4px;font-size:.88em}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:.6em;margin:.7em 0}
.card{background:#fff;border:1px solid #d0d7de;border-radius:6px;padding:.55em .75em}
.card .label{color:#57606a;font-size:.75em;text-transform:uppercase;letter-spacing:.04em}
.card .value{font-size:.95em;margin-top:.18em;word-break:break-all}
.badge{display:inline-block;padding:.12em .5em;border-radius:12px;font-size:.78em;font-weight:600}
.badge.ok{background:#dafbe1;color:#1a7f37}
.badge.stop{background:#ffebe9;color:#cf222e}
.badge.run{background:#ddf4ff;color:#0969da}
button{font:inherit;padding:.34em .8em;border:1px solid #1f2328;background:#f6f8fa;border-radius:5px;cursor:pointer}
button:hover{background:#eaeef2}
button.primary{background:#1f6feb;color:#fff;border-color:#1f6feb}
button.primary:hover{background:#218bff}
button.danger{background:#cf222e;color:#fff;border-color:#cf222e}
button.danger:hover{background:#a40e26}
button.star{background:transparent;border:none;font-size:1em;color:#d0d7de;cursor:pointer;padding:0 .2em}
button.star.on{color:#d4a72c}
button.quic{background:transparent;border:none;font-size:.78em;color:#d0d7de;cursor:pointer;padding:.15em .35em;border-radius:999px;white-space:nowrap}
button.quic.on{background:#ffebe9;color:#cf222e;font-weight:600}
.row{display:flex;gap:.5em;flex-wrap:wrap;align-items:center}
textarea,input[type=text],select{font:inherit;padding:.32em .55em;border:1px solid #d0d7de;border-radius:5px;box-sizing:border-box}
textarea{width:100%;min-height:108px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85em}
input[type=text]{width:100%}
.field{display:flex;flex-direction:column;gap:.18em;margin:.25em 0}
.field label{font-size:.78em;color:#57606a;text-transform:uppercase;letter-spacing:.04em}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:.6em}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #d0d7de;border-radius:6px;overflow:hidden}
th,td{padding:.4em .6em;text-align:left;border-bottom:1px solid #eaeef2;font-size:.9em;vertical-align:middle}
th{background:#eaeef2;font-weight:600}
tr:last-child td{border-bottom:none}
tr.active{background:#fff8c5}
tr.fav td:first-child{border-left:3px solid #d4a72c}
.msg{margin:.6em 0;padding:.55em .75em;border-radius:6px;font-size:.9em;display:none}
.msg.err{background:#ffebe9;border:1px solid #ff8182;color:#82071e;display:block}
.msg.ok{background:#dafbe1;border:1px solid #4ac26b;color:#1a7f37;display:block}
progress{width:100%;height:6px;border-radius:3px;overflow:hidden}
.collapsible{display:none}
.collapsible.open{display:block}
pre{background:#1f2328;color:#e6edf3;padding:.7em;border-radius:6px;overflow:auto;max-height:420px;font-size:.82em}
.star.on::after{content:"\2605"}
.star:not(.on)::after{content:"\2606"}
tr.group-header td{background:#eaeef2;font-weight:600;cursor:pointer;user-select:none}
tr.group-header .caret{display:inline-block;width:1em;text-align:center}
tr.group-header .grp-name{margin-left:.35em}
tr.group-header .grp-count{color:#57606a;font-weight:normal;font-size:.82em;margin-left:.45em}
tr.group-header .grp-refresh{margin-left:.7em;font-weight:normal}
tr.group-row.collapsed{display:none}
.chips{display:flex;flex-wrap:wrap;gap:.35em;margin:.35em 0;max-height:170px;overflow:auto;background:#fff;border:1px solid #d0d7de;border-radius:6px;padding:.45em}
.chip{display:inline-flex;gap:.25em;align-items:center;border:1px solid #d0d7de;border-radius:999px;padding:.18em .55em;background:#f6f8fa;font-size:.86em}
.mini{font-size:.78em;padding:.18em .5em}
</style>
</head>
<body>
<h1>HincyRay daemon</h1>
<p class="subtle">Lightweight Keenetic VPN/proxy panel &middot; v0.3 &middot; ping, stats, favorites, subscription refresh, WiFi traffic split. Talks to the local JSON API over fetch.</p>

<div id="msg" class="msg" role="status" aria-live="polite"></div>

<h2>Status</h2>
<div class="cards">
  <div class="card"><div class="label">Core</div><div class="value" id="card-core">&mdash;</div></div>
  <div class="card"><div class="label">Active profile</div><div class="value" id="card-active">&mdash;</div></div>
  <div class="card"><div class="label">Profiles</div><div class="value" id="card-count">&mdash;</div></div>
  <div class="card"><div class="label">SOCKS listen</div><div class="value" id="card-socks">&mdash;</div></div>
  <div class="card"><div class="label">State path</div><div class="value" id="card-state">&mdash;</div></div>
  <div class="card"><div class="label">Xray config path</div><div class="value" id="card-xray-path">&mdash;</div></div>
</div>

<div class="row">
  <button class="primary" id="btn-refresh">Refresh</button>
  <button id="btn-start">Start core</button>
  <button id="btn-stop">Stop core</button>
  <button id="btn-restart">Restart core</button>
</div>

<h2>Benchmark / ping</h2>
<p class="subtle">TCP probes <code>address:port</code> directly (no Xray). HEAD/GET spin up a temporary Xray SOCKS per VLESS profile, run curl, then tear it down &mdash; the active core is never touched. Hysteria2 is unsupported by the Xray benchmark; use TCP for it.</p>
<div class="grid2">
  <div class="field">
    <label for="bench-method">Method</label>
    <select id="bench-method">
      <option value="tcp">TCP (address:port, no Xray)</option>
      <option value="head">HEAD via temp Xray SOCKS</option>
      <option value="get">GET via temp Xray SOCKS (+ short download)</option>
    </select>
  </div>
  <div class="field">
    <label for="probe-url">Probe URL</label>
    <input type="text" id="probe-url" value="https://www.gstatic.com/generate_204">
  </div>
  <div class="field">
    <label for="download-url">Download URL (GET only)</label>
    <input type="text" id="download-url" value="https://proof.ovh.net/files/100Mb.dat">
  </div>
  <div class="field" style="justify-content:flex-end">
    <button class="primary" id="btn-bench-all">Ping all</button>
  </div>
</div>
<div class="row" style="margin-top:.3em">
  <progress id="bench-progress" value="0" max="1"></progress>
  <span class="subtle" id="bench-progress-text">&mdash;</span>
</div>

<h2>Import</h2>
<p class="subtle">Paste a subscription URL, direct share links (<code>vless://</code>, <code>hysteria2://</code>), or an Xray JSON config; one per line or mixed. Subscription URLs are saved for later refresh. Optional group name tags direct profiles so they appear under that group in the table below.</p>
<textarea id="import-text" placeholder="https://example.com/sub&#10;vless://...&#10;{ &quot;outbounds&quot;: [...] }"></textarea>
<div class="grid2" style="margin-top:.4em">
  <div class="field">
    <label for="import-group">Group name (optional)</label>
    <input type="text" id="import-group" placeholder="e.g. Tutnet online">
  </div>
  <div class="field" style="justify-content:flex-end">
    <button class="primary" id="btn-import">Import</button>
    <span class="subtle" id="import-status"></span>
  </div>
</div>

<h2>Subscriptions <span id="subs-toggle" class="toggle">show</span></h2>
<div id="subs-panel" class="collapsible">
  <div class="row">
    <button id="btn-subs-refresh">Refresh all subscriptions</button>
    <span class="subtle" id="subs-status"></span>
  </div>
  <table style="margin-top:.4em">
    <thead><tr><th>URL</th><th>Profiles</th><th>Last loaded</th><th>Last error</th></tr></thead>
    <tbody id="subs-body"><tr><td colspan="4" class="subtle">No saved subscriptions.</td></tr></tbody>
  </table>
</div>

<h2>WiFi Traffic Split <span id="routing-toggle" class="toggle">show</span></h2>
<div id="routing-panel" class="collapsible">
  <p class="subtle">Rules apply only to the <code>HincyRay-VPN</code> WiFi/TPROXY inbound. SOCKS clients keep using the active server. First matching rule wins; unmatched WiFi traffic falls back to the active server.</p>
  <div class="grid2">
    <label class="chip"><input type="checkbox" id="route-enabled"> Enable WiFi split routing</label>
    <label class="chip"><input type="checkbox" id="route-auto-switch"> Auto switch servers</label>
    <label class="chip"><input type="checkbox" id="route-block-quic"> Block QUIC / UDP 443 globally</label>
    <div class="field"><label for="route-source">Rule source project</label><select id="route-source"></select></div>
  </div>
  <div class="row" style="margin:.45em 0">
    <button id="btn-routing-save">Save settings</button>
    <button id="btn-catalog-refresh">Refresh service catalog</button>
    <button class="primary" id="btn-routing-apply">Apply Xray config</button>
    <button id="btn-tproxy-status">TPROXY status</button>
    <button id="btn-tproxy-install">Install/repair TPROXY</button>
    <button class="danger" id="btn-tproxy-rollback">Rollback TPROXY</button>
    <span class="subtle" id="routing-status"></span>
  </div>
  <h3 style="font-size:.95em;margin:.8em 0 .35em">Add rule</h3>
  <div class="grid2">
    <div class="field"><label for="rule-name">Rule name</label><input type="text" id="rule-name" placeholder="YouTube via server A"></div>
    <div class="field"><label for="rule-target">Target</label><select id="rule-target"></select></div>
  </div>
  <div class="field"><label for="rule-domains">Manual domains / geosite (one per line)</label><textarea id="rule-domains" placeholder="geosite:youtube&#10;domain:youtube.com&#10;domain:googlevideo.com"></textarea></div>
  <div class="field"><label for="rule-ips">Manual IP / CIDR / geoip (one per line)</label><textarea id="rule-ips" placeholder="geoip:ru&#10;8.8.8.8&#10;142.250.0.0/15"></textarea></div>
  <div class="field"><label>Popular services</label><div id="service-catalog" class="chips"></div></div>
  <div class="row" style="margin:.45em 0"><button id="btn-rule-add">Add rule</button><button id="btn-rule-save">Save rules</button></div>
  <table>
    <thead><tr><th>On</th><th>Name</th><th>Match</th><th>Target</th><th></th></tr></thead>
    <tbody id="routing-rules-body"><tr><td colspan="5" class="subtle">No routing rules.</td></tr></tbody>
  </table>
</div>

<h2>Profiles</h2>
<div class="row" style="margin:.3em 0">
  <span class="subtle">Sort by:</span>
  <select id="profile-sort">
    <option value="default">Import order</option>
    <option value="rating" selected>Rating (desc)</option>
    <option value="latency">Latency (asc)</option>
    <option value="name">Name (A-Z)</option>
  </select>
  <span class="subtle">Click a group header to collapse/expand it.</span>
</div>
<table>
  <thead><tr><th>Fav</th><th>QUIC</th><th>ID</th><th>Name</th><th>Protocol</th><th>Transport</th><th>Latency (ms)</th><th>Jitter (ms)</th><th>Speed (Mbps)</th><th>Fail</th><th>Score</th><th></th></tr></thead>
  <tbody id="profiles-body"><tr><td colspan="12" class="subtle">No profiles yet.</td></tr></tbody>
</table>

<h2>Favorites <span id="fav-toggle" class="toggle">show</span></h2>
<div id="fav-panel" class="collapsible">
  <table>
    <thead><tr><th>ID</th><th>Name</th><th>Protocol</th><th>Address:port</th><th></th></tr></thead>
    <tbody id="fav-body"><tr><td colspan="5" class="subtle">No favorites yet.</td></tr></tbody>
  </table>
</div>

<h2>Generated Xray config</h2>
<div class="row">
  <button id="btn-load-config">Load / show</button>
  <span class="subtle">Fetches <code>GET /api/xray/config</code> for the active profile.</span>
</div>
<pre id="xray-config">&mdash;</pre>

<hr class="subtle">
<p class="subtle">HincyRay daemon &middot; API: <code>/api/health</code>, <code>/api/status</code>, <code>/api/profiles</code>, <code>/api/bench/*</code>, <code>/api/stats</code>, <code>/api/favorites/*</code>, <code>/api/subscriptions/refresh</code>, <code>/api/subscriptions/refresh-one</code>, <code>/api/xray/config</code>, <code>/api/core/*</code>.</p>

<script>
(function(){
"use strict";
var msgEl = document.getElementById("msg");
var benchPollHandle = null;
var lastStats = [];
var routingState = { settings: {}, rules: [], catalog: [], sources: [] };
var lastProfiles = [];

function setMsg(text, kind){
  if(!text){ msgEl.className = "msg"; msgEl.textContent = ""; return; }
  msgEl.className = "msg " + (kind || "err");
  msgEl.textContent = text;
}
function clearMsg(){ setMsg("", ""); }
function showOk(text){ setMsg(text, "ok"); }

function api(method, path, body){
  var opts = { method: method, headers: {} };
  if(body !== undefined && body !== null){
    opts.headers["Content-Type"] = "application/json";
    opts.body = body;
  }
  return fetch(path, opts).then(function(resp){
    var ctype = resp.headers.get("Content-Type") || "";
    return resp.text().then(function(text){
      var data = null;
      if(text){
        if(ctype.indexOf("json") >= 0){ data = JSON.parse(text); }
        else { data = text; }
      }
      if(!resp.ok){
        var m = (data && data.error) ? data.error : ("HTTP " + resp.status + " " + resp.statusText);
        var e = new Error(m); e.data = data; throw e;
      }
      return data;
    });
  }).catch(function(err){
    if(err && err.message){ throw err; }
    throw new Error("network error: " + (err && err.message ? err.message : "fetch failed"));
  });
}

function esc(s){
  return String(s == null ? "" : s)
    .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
    .replace(/"/g,"&quot;").replace(/'/g,"&#39;");
}

function fmtTime(unix){
  if(!unix){ return "&mdash;"; }
  var d = new Date(unix * 1000);
  return esc(d.toLocaleString());
}

function renderStatus(s){
  var running = s.core_status === "running";
  var coreEl = document.getElementById("card-core");
  coreEl.innerHTML = '<span class="badge ' + (running ? "ok" : "stop") + '">' + esc(s.core_status) + '</span>';
  var active = s.active_profile_name ? s.active_profile_name
    : (s.active_profile_id == null ? "—" : ("#" + s.active_profile_id));
  document.getElementById("card-active").textContent = active;
  document.getElementById("card-count").textContent = String(s.profile_count);
  document.getElementById("card-socks").textContent = s.listen_host + ":" + s.socks_port;
  document.getElementById("card-state").textContent = s.state_path;
  document.getElementById("card-xray-path").textContent = s.xray_config_path;
}

function groupLabel(group){
  // `null`/`undefined` group is shown as "Direct".
  return (group == null || group === "") ? "Direct" : String(group);
}

function groupStorageKey(group){
  // Per-group collapse state in localStorage. Key is namespaced and
  // contains the group label so URL groups and named groups do not clash.
  return "hincyray-collapsed-" + groupLabel(group);
}

function isGroupCollapsed(group){
  try { return localStorage.getItem(groupStorageKey(group)) === "1"; }
  catch(e){ return false; }
}

function setGroupCollapsed(group, collapsed){
  try { localStorage.setItem(groupStorageKey(group), collapsed ? "1" : "0"); }
  catch(e){ /* private mode etc — ignore */ }
}

function isUrlGroup(group){
  if(!group){ return false; }
  var g = String(group);
  return g.indexOf("http://") === 0 || g.indexOf("https://") === 0;
}

function renderProfiles(profiles, stats){
  var tbody = document.getElementById("profiles-body");
  if(!profiles || !profiles.length){
    tbody.innerHTML = '<tr><td colspan="11" class="subtle">No profiles yet. Import above.</td></tr>';
    return;
  }
  var sortKey = document.getElementById("profile-sort").value;
  var enriched = profiles.map(function(p){
    var st = (stats || []).find(function(s){ return s.profile_id === p.id; }) || {};
    return {
      p: p,
      score: st.score || 0,
      latency: st.last_latency_ms || 0,
      jitter: st.last_jitter_ms || 0,
      speed: st.last_download_mbps || 0,
      fail: st.failure_count || 0,
      name: p.name || ""
    };
  });
  // Sorting applies INSIDE each group, not across groups.
  function sortGroup(items){
    if(sortKey === "rating"){
      items.sort(function(a,b){
        var d = b.score - a.score;
        if(d !== 0){ return d; }
        return a.p.id - b.p.id;
      });
    }
    else if(sortKey === "default"){
      items.sort(function(a,b){ return a.p.id - b.p.id; });
    }
    else if(sortKey === "latency"){
      items.sort(function(a,b){
        var la = a.latency || 1e9, lb = b.latency || 1e9;
        return la - lb;
      });
    }
    else if(sortKey === "name"){ items.sort(function(a,b){ return a.name.localeCompare(b.name); });
    }
    return items;
  }

  // Group order: named/URL groups in first-appearance order, "Direct"
  // (None) last.
  var groupOrder = [];
  var groups = {};
  enriched.forEach(function(e){
    var g = e.p.group;
    if(g === undefined || g === null || g === "") { g = null; }
    if(!groups.hasOwnProperty(g === null ? "__direct__" : g)){
      groups[g === null ? "__direct__" : g] = [];
      if(g === null){ /* Direct is appended last explicitly */ }
      else { groupOrder.push(g); }
    }
    groups[g === null ? "__direct__" : g].push(e);
  });
  if(groups.hasOwnProperty("__direct__")){ groupOrder.push(null); }

  var html = [];
  groupOrder.forEach(function(g){
    var items = sortGroup(groups[g === null ? "__direct__" : g].slice());
    var label = groupLabel(g);
    var collapsed = isGroupCollapsed(g);
    var caret = collapsed ? "&#9654;" : "&#9660;";
    var refreshBtn = isUrlGroup(g)
      ? '<button class="grp-refresh" data-refresh-url="' + esc(g) + '">Refresh</button>'
      : '';
    html.push(
      '<tr class="group-header" data-group-key="' + esc(g === null ? "" : g) + '">'
      + '<td colspan="11">'
      + '<span class="caret">' + caret + '</span>'
      + '<span class="grp-name">' + esc(label) + '</span>'
      + '<span class="grp-count">' + items.length + ' profile' + (items.length === 1 ? "" : "s") + '</span>'
      + refreshBtn
      + '</td></tr>'
    );
    items.forEach(function(e){
      var p = e.p;
      var favClass = p.favorite ? " fav" : "";
      var starClass = p.favorite ? "star on" : "star";
      var quicClass = p.block_quic ? "quic on" : "quic";
      var quicTitle = p.block_quic ? "QUIC / UDP 443 blocked for this server" : "Block QUIC / UDP 443 for this server";
      var rowClass = (p.active ? "active" : "") + favClass + " group-row" + (collapsed ? " collapsed" : "");
      html.push(
        '<tr class="' + rowClass.trim() + '" data-group-row="' + esc(g === null ? "" : g) + '">'
        + '<td><button class="' + starClass + '" data-fav="' + p.id + '" title="Toggle favorite"></button></td>'
        + '<td><button class="' + quicClass + '" data-quic="' + p.id + '" title="' + quicTitle + '">&#8856; QUIC</button></td>'
        + '<td>' + p.id + '</td>'
        + '<td>' + esc(p.name) + '</td>'
        + '<td>' + esc(p.protocol) + '</td>'
        + '<td>' + esc(p.transport) + '</td>'
        + '<td>' + (e.latency || 0) + '</td>'
        + '<td>' + (e.jitter || 0) + '</td>'
        + '<td>' + (e.speed ? e.speed.toFixed(1) : "0.0") + '</td>'
        + '<td>' + (e.fail || 0) + '</td>'
        + '<td><strong>' + (e.score || 0) + '</strong></td>'
        + '<td class="row">'
          + '<button class="ping-btn" data-id="' + p.id + '">Ping</button>'
          + '<button class="select-btn" data-id="' + p.id + '">Select</button>'
        + '</td>'
        + '</tr>'
      );
    });
  });
  tbody.innerHTML = html.join("");

  // Group header click: toggle collapse of the following rows in the
  // same group, persist to localStorage, and update the caret.
  Array.prototype.forEach.call(tbody.querySelectorAll("tr.group-header"), function(hdr){
    hdr.addEventListener("click", function(ev){
      // Ignore clicks on the per-group Refresh button (it has its own
      // handler that should not also toggle the group).
      if(ev.target && ev.target.classList && ev.target.classList.contains("grp-refresh")){ return; }
      var key = hdr.getAttribute("data-group-key") || "";
      var g = key === "" ? null : key;
      var nowCollapsed = !isGroupCollapsed(g);
      setGroupCollapsed(g, nowCollapsed);
      var caretEl = hdr.querySelector(".caret");
      if(caretEl){ caretEl.innerHTML = nowCollapsed ? "&#9654;" : "&#9660;"; }
      Array.prototype.forEach.call(
        tbody.querySelectorAll('tr.group-row[data-group-row="' + (g === null ? "" : esc(g)) + '"]'),
        function(row){
          if(nowCollapsed){ row.classList.add("collapsed"); }
          else { row.classList.remove("collapsed"); }
        }
      );
    });
  });

  Array.prototype.forEach.call(tbody.querySelectorAll(".grp-refresh"), function(btn){
    btn.addEventListener("click", function(ev){
      ev.stopPropagation();
      var url = btn.getAttribute("data-refresh-url");
      if(!url){ return; }
      api("POST", "/api/subscriptions/refresh-one", JSON.stringify({url: url})).then(function(data){
        if(data.errors && data.errors.length){
          setMsg("Refresh failed: " + data.errors.join("; "), "err");
        } else {
          showOk("Subscription refreshed: +" + (data.added || 0) + " new profile(s).");
        }
        return refreshAll();
      }).catch(function(err){ setMsg("Refresh failed: " + err.message); });
    });
  });

  Array.prototype.forEach.call(tbody.querySelectorAll(".select-btn"), function(btn){
    btn.addEventListener("click", function(){
      var id = btn.getAttribute("data-id");
      api("POST", "/api/active-profile", JSON.stringify({profile_id: Number(id)}))
        .then(function(){
          showOk("Profile " + id + " selected. Xray config regenerated.");
          return refreshAll();
        })
        .catch(function(err){ setMsg("Select failed: " + err.message); });
    });
  });
  Array.prototype.forEach.call(tbody.querySelectorAll(".ping-btn"), function(btn){
    btn.addEventListener("click", function(){
      var id = Number(btn.getAttribute("data-id"));
      startBench([id]);
    });
  });
  Array.prototype.forEach.call(tbody.querySelectorAll("[data-fav]"), function(btn){
    btn.addEventListener("click", function(){
      var id = Number(btn.getAttribute("data-fav"));
      api("POST", "/api/favorites/toggle", JSON.stringify({profile_id: id}))
        .then(function(){ return refreshAll(); })
        .catch(function(err){ setMsg("Favorite toggle failed: " + err.message); });
    });
  });
  Array.prototype.forEach.call(tbody.querySelectorAll("[data-quic]"), function(btn){
    btn.addEventListener("click", function(ev){
      ev.stopPropagation();
      var id = Number(btn.getAttribute("data-quic"));
      var current = btn.classList.contains("on");
      api("POST", "/api/profiles/block-quic", JSON.stringify({profile_id: id, block_quic: !current}))
        .then(function(){ return refreshAll(); })
        .catch(function(err){ setMsg("QUIC toggle failed: " + err.message); });
    });
  });
}

function renderFavorites(profiles){
  var tbody = document.getElementById("fav-body");
  if(!profiles || !profiles.length){
    tbody.innerHTML = '<tr><td colspan="5" class="subtle">No favorites yet.</td></tr>';
    return;
  }
  var rows = profiles.map(function(p){
    var addr = esc(p.address) + ":" + (p.port == null ? "?" : p.port);
    return '<tr>'
      + '<td>' + p.profile_id + '</td>'
      + '<td>' + esc(p.name) + '</td>'
      + '<td>' + esc(p.protocol) + '</td>'
      + '<td>' + addr + '</td>'
      + '<td><button class="select-btn" data-id="' + p.profile_id + '">Select</button></td>'
      + '</tr>';
  });
  tbody.innerHTML = rows.join("");
  Array.prototype.forEach.call(tbody.querySelectorAll(".select-btn"), function(btn){
    btn.addEventListener("click", function(){
      var id = btn.getAttribute("data-id");
      api("POST", "/api/active-profile", JSON.stringify({profile_id: Number(id)}))
        .then(function(){ showOk("Profile " + id + " selected."); return refreshAll(); })
        .catch(function(err){ setMsg("Select failed: " + err.message); });
    });
  });
}

function renderSubscriptions(subs){
  var tbody = document.getElementById("subs-body");
  if(!subs || !subs.length){
    tbody.innerHTML = '<tr><td colspan="4" class="subtle">No saved subscriptions. Import a subscription URL to save it here.</td></tr>';
    return;
  }
  var rows = subs.map(function(s){
    var err = s.last_error ? esc(s.last_error).slice(0, 80) : "&mdash;";
    return '<tr>'
      + '<td><code>' + esc(s.url) + '</code></td>'
      + '<td>' + (s.profile_count || 0) + '</td>'
      + '<td>' + fmtTime(s.last_loaded_unix) + '</td>'
      + '<td>' + err + '</td>'
      + '</tr>';
  });
  tbody.innerHTML = rows.join("");
}

function linesFrom(id){
  return (document.getElementById(id).value || "").split(/\r?\n/).map(function(s){ return s.trim(); }).filter(Boolean);
}

function renderRouting(data, profiles){
  routingState = data || routingState;
  var settings = routingState.settings || {};
  document.getElementById("route-enabled").checked = !!settings.enabled;
  document.getElementById("route-auto-switch").checked = !!settings.auto_switch;
  document.getElementById("route-block-quic").checked = !!settings.block_quic_global;

  var source = document.getElementById("route-source");
  source.innerHTML = (routingState.sources || []).map(function(s){
    return '<option value="' + esc(s.id) + '"' + (s.id === settings.rule_source ? ' selected' : '') + '>' + esc(s.name) + '</option>';
  }).join("");

  var target = document.getElementById("rule-target");
  var opts = ['<option value="active">Active server</option>','<option value="direct">Direct</option>','<option value="best">Best server (auto)</option>'];
  (profiles || []).forEach(function(p){ opts.push('<option value="profile:' + p.id + '">#' + p.id + ' ' + esc(p.name) + '</option>'); });
  target.innerHTML = opts.join("");

  var catalog = document.getElementById("service-catalog");
  catalog.innerHTML = (routingState.catalog || []).map(function(s){
    var geosite = (s.geosite || []).join(",");
    return '<label class="chip"><input type="checkbox" data-service="' + esc(s.id) + '" data-geosite="' + esc(geosite) + '"> ' + esc(s.name) + '</label>';
  }).join("");

  renderRoutingRules();
}

function routingMatchSummary(rule){
  var parts = [];
  if(rule.services && rule.services.length){ parts.push("services: " + rule.services.join(", ")); }
  if(rule.domains && rule.domains.length){ parts.push("domains: " + rule.domains.slice(0,4).join(", ") + (rule.domains.length > 4 ? "…" : "")); }
  if(rule.ips && rule.ips.length){ parts.push("ip: " + rule.ips.slice(0,4).join(", ") + (rule.ips.length > 4 ? "…" : "")); }
  return parts.join("; ") || "—";
}

function renderRoutingRules(){
  var tbody = document.getElementById("routing-rules-body");
  var rules = routingState.rules || [];
  if(!rules.length){ tbody.innerHTML = '<tr><td colspan="6" class="subtle">No routing rules.</td></tr>'; return; }
  tbody.innerHTML = rules.map(function(r, idx){
    return '<tr>'
      + '<td><input type="checkbox" data-rule-on="' + idx + '"' + (r.enabled ? ' checked' : '') + '></td>'
      + '<td>' + esc(r.name || ("Rule " + (idx + 1))) + '</td>'
      + '<td>' + esc(routingMatchSummary(r)) + '</td>'
      + '<td><code>' + esc(r.target || "active") + '</code></td>'
      + '<td><button class="mini" data-rule-up="' + idx + '">↑</button> <button class="mini" data-rule-down="' + idx + '">↓</button> <button class="mini danger" data-rule-del="' + idx + '">Delete</button></td>'
      + '</tr>';
  }).join("");
  Array.prototype.forEach.call(tbody.querySelectorAll("[data-rule-on]"), function(el){ el.addEventListener("change", function(){ routingState.rules[Number(el.getAttribute("data-rule-on"))].enabled = el.checked; }); });
  Array.prototype.forEach.call(tbody.querySelectorAll("[data-rule-del]"), function(el){ el.addEventListener("click", function(){ routingState.rules.splice(Number(el.getAttribute("data-rule-del")),1); renderRoutingRules(); }); });
  Array.prototype.forEach.call(tbody.querySelectorAll("[data-rule-up]"), function(el){ el.addEventListener("click", function(){ var i=Number(el.getAttribute("data-rule-up")); if(i>0){ var r=routingState.rules.splice(i,1)[0]; routingState.rules.splice(i-1,0,r); renderRoutingRules(); } }); });
  Array.prototype.forEach.call(tbody.querySelectorAll("[data-rule-down]"), function(el){ el.addEventListener("click", function(){ var i=Number(el.getAttribute("data-rule-down")); if(i<routingState.rules.length-1){ var r=routingState.rules.splice(i,1)[0]; routingState.rules.splice(i+1,0,r); renderRoutingRules(); } }); });
}

function addRoutingRule(){
  var services = [];
  var domains = linesFrom("rule-domains");
  Array.prototype.forEach.call(document.querySelectorAll("#service-catalog input:checked"), function(el){
    services.push(el.getAttribute("data-service"));
    (el.getAttribute("data-geosite") || "").split(",").forEach(function(g){ if(g){ domains.push("geosite:" + g); } });
    el.checked = false;
  });
  var rule = {
    enabled: true,
    name: (document.getElementById("rule-name").value || "").trim() || "Routing rule",
    kind: "custom",
    pattern: "",
    target: document.getElementById("rule-target").value,
    domains: domains,
    ips: linesFrom("rule-ips"),
    services: services
  };
  routingState.rules = routingState.rules || [];
  routingState.rules.push(rule);
  document.getElementById("rule-name").value = "";
  document.getElementById("rule-domains").value = "";
  document.getElementById("rule-ips").value = "";
  renderRoutingRules();
}

function renderBenchStatus(b){
  var progress = document.getElementById("bench-progress");
  var text = document.getElementById("bench-progress-text");
  var btnAll = document.getElementById("btn-bench-all");
  if(b.running){
    var pct = b.total > 0 ? b.completed / b.total : 0;
    progress.max = b.total || 1;
    progress.value = b.completed;
    var cur = b.current_profile_name ? ("current: " + esc(b.current_profile_name)) : "";
    text.innerHTML = (b.method || "") + " " + b.completed + "/" + b.total
      + (b.cancel_requested ? " (stopping)" : "")
      + (cur ? " &middot; " + cur : "");
    btnAll.textContent = "Stop ping";
    btnAll.classList.remove("primary");
    btnAll.classList.add("danger");
  } else {
    progress.value = 0;
    progress.max = 1;
    if(b.total > 0 && b.completed >= b.total){
      var sum = b.summary || {};
      text.innerHTML = "last run: " + (b.method || "")
        + " " + sum.passed + "/" + sum.total + " ok"
        + (sum.failed ? ", " + sum.failed + " failed" : "");
    } else {
      text.textContent = "—";
    }
    btnAll.textContent = "Ping all";
    btnAll.classList.add("primary");
    btnAll.classList.remove("danger");
  }
}

function refreshAll(){
  var promises = [
    api("GET","/api/status"),
    api("GET","/api/profiles"),
    api("GET","/api/stats"),
    api("GET","/api/favorites"),
    api("GET","/api/bench/status"),
    api("GET","/api/subscriptions"),
    api("GET","/api/routing")
  ];
  return Promise.all(promises).then(function(results){
    renderStatus(results[0]);
    var stats = results[2].stats || [];
    lastStats = stats;
    var profiles = (results[1].profiles || []).map(function(p){
      var st = stats.find(function(s){ return s.profile_id === p.id; });
      p.favorite = st ? st.favorite : false;
      return p;
    });
    lastProfiles = profiles;
    renderProfiles(profiles, stats);
    renderFavorites(results[3].favorites || []);
    renderBenchStatus(results[4]);
    renderSubscriptions(results[5].subscriptions || []);
    renderRouting(results[6], profiles);
    maybePollBench(results[4]);
  }).catch(function(err){ setMsg("Refresh failed: " + err.message); });
}

function loadSubscriptions(){
  return api("GET", "/api/subscriptions").then(function(data){
    renderSubscriptions(data.subscriptions || []);
  }).catch(function(){ /* leave panel as-is */ });
}

function maybePollBench(b){
  if(b && b.running){
    if(benchPollHandle){ return; }
    benchPollHandle = setInterval(function(){
      api("GET","/api/bench/status").then(function(status){
        renderBenchStatus(status);
        if(!status.running){
          stopBenchPoll();
          refreshAll();
        }
      }).catch(function(){ /* keep polling, transient */ });
    }, 1500);
  } else {
    stopBenchPoll();
  }
}

function stopBenchPoll(){
  if(benchPollHandle){ clearInterval(benchPollHandle); benchPollHandle = null; }
}

function startBench(profileIds){
  var method = document.getElementById("bench-method").value;
  var probeUrl = document.getElementById("probe-url").value.trim();
  var downloadUrl = document.getElementById("download-url").value.trim();
  var body = JSON.stringify({
    method: method,
    probe_url: probeUrl,
    download_url: downloadUrl,
    profile_ids: profileIds
  });
  api("POST", "/api/bench/start", body).then(function(data){
    showOk("Benchmark started: " + (data.method || method) + ", " + (data.total || 0) + " profile(s).");
    return refreshAll();
  }).catch(function(err){
    setMsg("Benchmark start failed: " + err.message);
    return refreshAll();
  });
}

function stopBench(){
  api("POST", "/api/bench/stop").then(function(){
    showOk("Stop requested. In-flight profile will finish first.");
    return refreshAll();
  }).catch(function(err){ setMsg("Stop failed: " + err.message); });
}

function coreAction(path, label){
  api("POST", path).then(function(data){
    showOk(label + " &rarr; " + (data && data.core_status ? data.core_status : "ok"));
    return refreshAll();
  }).catch(function(err){ setMsg(label + " failed: " + err.message); });
}

function toggleCollapsible(toggleId, panelId){
  var t = document.getElementById(toggleId);
  var p = document.getElementById(panelId);
  if(!t || !p){ return; }
  if(p.classList.contains("open")){
    p.classList.remove("open");
    t.textContent = "show";
  } else {
    p.classList.add("open");
    t.textContent = "hide";
  }
}

document.getElementById("btn-refresh").addEventListener("click", function(){ clearMsg(); refreshAll(); });
document.getElementById("btn-start").addEventListener("click", function(){ coreAction("/api/core/start", "Start core"); });
document.getElementById("btn-stop").addEventListener("click", function(){ coreAction("/api/core/stop", "Stop core"); });
document.getElementById("btn-restart").addEventListener("click", function(){ coreAction("/api/core/restart", "Restart core"); });

document.getElementById("btn-bench-all").addEventListener("click", function(){
  // Toggle action depends on current state.
  api("GET", "/api/bench/status").then(function(b){
    if(b.running){ stopBench(); }
    else { startBench([]); }
  }).catch(function(err){ setMsg("Status check failed: " + err.message); });
});

document.getElementById("profile-sort").addEventListener("change", function(){
  // Re-render with the latest profiles/stats without a network round trip.
  api("GET", "/api/profiles").then(function(profilesResp){
    var profiles = (profilesResp.profiles || []).map(function(p){
      var st = lastStats.find(function(s){ return s.profile_id === p.id; });
      p.favorite = st ? st.favorite : false;
      return p;
    });
    renderProfiles(profiles, lastStats);
  }).catch(function(){ /* ignore */ });
});

document.getElementById("btn-import").addEventListener("click", function(){
  var text = document.getElementById("import-text").value.trim();
  if(!text){ setMsg("Paste something first."); return; }
  var group = (document.getElementById("import-group").value || "").trim();
  // Always send the JSON shape now: {text, group}. The handler on the
  // daemon side still accepts raw text for backward compatibility.
  var body = JSON.stringify({text: text, group: group ? group : null});
  var status = document.getElementById("import-status");
  status.textContent = "Importing…";
  api("POST", "/api/profiles/import", body).then(function(data){
    status.textContent = "";
    var parts = ["added " + data.added, "total " + data.profile_count];
    if(data.errors && data.errors.length){
      setMsg("Import finished with errors: " + data.errors.join("; "), "err");
    } else {
      showOk("Imported: " + parts.join(", "));
    }
    document.getElementById("import-text").value = "";
    document.getElementById("import-group").value = "";
    return refreshAll();
  }).catch(function(err){
    status.textContent = "";
    setMsg("Import failed: " + err.message);
  });
});

document.getElementById("btn-subs-refresh").addEventListener("click", function(){
  var status = document.getElementById("subs-status");
  status.textContent = "Refreshing…";
  api("POST", "/api/subscriptions/refresh").then(function(data){
    status.textContent = "refreshed " + data.refreshed + ", added " + data.added;
    if(data.errors && data.errors.length){
      setMsg("Subscription refresh had errors: " + data.errors.join("; "), "err");
    } else {
      showOk("Subscriptions refreshed: +" + data.added + " profile(s).");
    }
    return refreshAll();
  }).catch(function(err){
    status.textContent = "";
    setMsg("Refresh failed: " + err.message);
  });
});

document.getElementById("btn-load-config").addEventListener("click", function(){
  api("GET", "/api/xray/config").then(function(data){
    document.getElementById("xray-config").textContent = JSON.stringify(data, null, 2);
  }).catch(function(err){ setMsg("Load config failed: " + err.message); });
});

document.getElementById("btn-routing-save").addEventListener("click", function(){
  var body = JSON.stringify({
    enabled: document.getElementById("route-enabled").checked,
    auto_switch: document.getElementById("route-auto-switch").checked,
    block_quic_global: document.getElementById("route-block-quic").checked,
    rule_source: document.getElementById("route-source").value
  });
  api("POST", "/api/routing/settings", body).then(function(data){
    routingState.settings = data.settings || routingState.settings;
    showOk("Routing settings saved.");
    return refreshAll();
  }).catch(function(err){ setMsg("Routing settings failed: " + err.message); });
});

document.getElementById("btn-rule-add").addEventListener("click", addRoutingRule);
document.getElementById("btn-catalog-refresh").addEventListener("click", function(){
  var source = document.getElementById("route-source").value;
  document.getElementById("routing-status").textContent = "Refreshing catalog…";
  api("POST", "/api/routing/catalog/refresh", JSON.stringify({source: source})).then(function(data){
    routingState.catalog = data.catalog || routingState.catalog || [];
    document.getElementById("routing-status").textContent = "catalog: " + routingState.catalog.length + " item(s)";
    renderRouting(routingState, lastProfiles);
  }).catch(function(err){
    document.getElementById("routing-status").textContent = "";
    setMsg("Catalog refresh failed: " + err.message);
  });
});
document.getElementById("btn-rule-save").addEventListener("click", function(){
  api("POST", "/api/routing/rules", JSON.stringify({rules: routingState.rules || []})).then(function(data){
    routingState.rules = data.rules || [];
    showOk("Routing rules saved.");
    renderRoutingRules();
  }).catch(function(err){ setMsg("Save rules failed: " + err.message); });
});
document.getElementById("btn-routing-apply").addEventListener("click", function(){
  api("POST", "/api/routing/settings", JSON.stringify({
    enabled: document.getElementById("route-enabled").checked,
    auto_switch: document.getElementById("route-auto-switch").checked,
    block_quic_global: document.getElementById("route-block-quic").checked,
    rule_source: document.getElementById("route-source").value
  })).then(function(){
    return api("POST", "/api/routing/rules", JSON.stringify({rules: routingState.rules || []}));
  }).then(function(){
    return api("POST", "/api/routing/apply");
  }).then(function(data){
    showOk("Routing applied. Core: " + (data.core_status || "ok"));
    return refreshAll();
  }).catch(function(err){ setMsg("Apply routing failed: " + err.message); });
});

document.getElementById("btn-tproxy-status").addEventListener("click", function(){
  api("GET", "/api/routing/tproxy-status").then(function(data){
    document.getElementById("routing-status").textContent = "chain=" + data.chain + ", rule=" + data.ip_rule + ", port=" + data.tproxy_port;
  }).catch(function(err){ setMsg("TPROXY status failed: " + err.message); });
});
document.getElementById("btn-tproxy-install").addEventListener("click", function(){
  api("POST", "/api/routing/tproxy-install").then(function(){ showOk("TPROXY installed/repaired."); }).catch(function(err){ setMsg("TPROXY install failed: " + err.message); });
});
document.getElementById("btn-tproxy-rollback").addEventListener("click", function(){
  api("POST", "/api/routing/tproxy-rollback").then(function(){ showOk("TPROXY rollback done."); }).catch(function(err){ setMsg("TPROXY rollback failed: " + err.message); });
});

document.getElementById("subs-toggle").addEventListener("click", function(){
  toggleCollapsible("subs-toggle", "subs-panel");
});
document.getElementById("fav-toggle").addEventListener("click", function(){
  toggleCollapsible("fav-toggle", "fav-panel");
});
document.getElementById("routing-toggle").addEventListener("click", function(){
  toggleCollapsible("routing-toggle", "routing-panel");
});

refreshAll();
})();
</script>
</body>
</html>"##
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_daemon() -> (TempDir, Daemon) {
        let dir = TempDir::new().expect("temp dir");
        let state_path = dir.path().join("state.json");
        let xray_config_path = dir.path().join("xray-client.json");
        let daemon = Daemon::new(HincyrayState::default(), state_path, xray_config_path);
        (dir, daemon)
    }

    #[test]
    fn proxy_info_for_daemon_uses_state_socks_port() {
        let (_dir, daemon) = test_daemon();
        let mut inner = lock(&daemon.inner);
        let proxy_info = proxy_info_for_daemon(&mut inner);
        // Default state has the core stopped, so no fallback should be
        // attempted by load_subscription_for_daemon. The SOCKS URL is
        // built from listen_host + socks_port.
        assert!(!proxy_info.core_running);
        assert_eq!(proxy_info.socks_url, "socks5h://127.0.0.1:10808");
    }

    #[test]
    fn format_error_combines_direct_and_proxy_messages() {
        let direct = "https://provider.example/sub/x: connection refused";
        let proxy = "socks5h://127.0.0.1:10808: connect error";
        let combined = SubscriptionLoadOutcome::format_error(direct, Some(proxy));
        assert!(combined.contains(direct));
        assert!(combined.contains("via proxy"));
        assert!(combined.contains(proxy));
        let direct_only = SubscriptionLoadOutcome::format_error(direct, None);
        assert_eq!(direct_only, direct);
    }

    #[test]
    fn state_round_trips_through_json_with_defaults() {
        let dir = TempDir::new().expect("temp dir");
        let state_path = dir.path().join("nested/state.json");
        let mut state = HincyrayState::default();
        state.profiles.push(Profile {
            id: 0,
            name: "demo".to_owned(),
            protocol: crate::profiles::Protocol::Vless,
            address: "example.com".to_owned(),
            port: Some(443),
            raw: "vless://11111111-1111-1111-1111-111111111111@example.com:443#demo".to_owned(),
            selected: true,
            block_quic: false,
            group: None,
        });
        state.active_profile_id = Some(0);

        persist_state(&state_path, &state).expect("persist");
        let loaded = load_state(&state_path);

        assert_eq!(loaded.profiles.len(), 1);
        assert_eq!(loaded.active_profile_id, Some(0));
        assert_eq!(loaded.socks_port, 10808);
        assert_eq!(loaded.http_port, Some(10809));
        assert_eq!(loaded.xray_path, "xray");
        assert_eq!(loaded.listen_host, "127.0.0.1");
        assert!(state_path.exists());
    }

    #[test]
    fn load_state_returns_default_when_missing() {
        let loaded = load_state(Path::new("/nonexistent/hincyray-state-test.json"));
        assert!(loaded.profiles.is_empty());
        assert_eq!(loaded.socks_port, 10808);
    }

    #[test]
    fn import_direct_profile_parses_and_persists() {
        let (_dir, daemon) = test_daemon();
        let body = "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&sni=example.com&type=tcp#Demo";

        let (status, content_type, response_text) = handle_import(body, &daemon);
        assert_eq!(status, 200);
        assert_eq!(content_type, "application/json");

        let response: Value = serde_json::from_str(&response_text).expect("parse response");
        assert_eq!(response["profile_count"], 1);
        assert_eq!(response["added"], 1);
        assert!(
            response["errors"]
                .as_array()
                .is_some_and(|errors| errors.is_empty())
        );

        let inner = lock(&daemon.inner);
        assert_eq!(inner.state.profiles.len(), 1);
        assert_eq!(inner.state.profiles[0].name, "Demo");
    }

    #[test]
    fn import_dedups_by_raw_url() {
        let (_dir, daemon) = test_daemon();
        let body = "vless://11111111-1111-1111-1111-111111111111@example.com:443#Demo";

        let (_, _, _) = handle_import(body, &daemon);
        let (status, _, response_text) = handle_import(body, &daemon);
        assert_eq!(status, 200);

        let response: Value = serde_json::from_str(&response_text).expect("parse response");
        assert_eq!(response["profile_count"], 1);
        assert_eq!(response["added"], 0);

        let inner = lock(&daemon.inner);
        assert_eq!(inner.state.profiles.len(), 1);
    }

    #[test]
    fn set_active_profile_writes_xray_config() {
        let (_dir, daemon) = test_daemon();
        let body = "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=xhttp&security=reality&sni=www.example.com&fp=chrome&pbk=0123456789abcdef0123456789abcdef0123456789a&sid=abcd#XHTTP";
        handle_import(body, &daemon);

        let (status, _, response_text) = handle_set_active(r#"{"profile_id":0}"#, &daemon);
        assert_eq!(status, 200);
        let response: Value = serde_json::from_str(&response_text).expect("parse response");
        assert_eq!(response["active_profile_id"], 0);
        assert_eq!(response["active_profile_name"], "XHTTP");

        let config_text = fs::read_to_string(&daemon.xray_config_path).expect("read config");
        let config: Value = serde_json::from_str(&config_text).expect("parse config");
        assert_eq!(config["inbounds"][0]["protocol"], "socks");
        assert_eq!(config["outbounds"][0]["protocol"], "vless");
        assert_eq!(config["outbounds"][0]["streamSettings"]["network"], "xhttp");
    }

    #[test]
    fn split_routing_config_is_wifi_only_and_falls_back_to_active() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#Active\n\
             vless://22222222-2222-2222-2222-222222222222@example.org:443?security=tls#YouTube",
            &daemon,
        );
        {
            let mut inner = lock(&daemon.inner);
            inner.state.active_profile_id = Some(0);
            inner.state.split_routing.enabled = true;
            inner.state.routing_rules.push(RoutingRule {
                enabled: true,
                name: "RU direct".to_owned(),
                target: "direct".to_owned(),
                domains: vec!["geosite:ru".to_owned()],
                ips: vec!["geoip:ru".to_owned()],
                ..Default::default()
            });
            inner.state.profiles[0].block_quic = true;
            inner.state.routing_rules.push(RoutingRule {
                enabled: true,
                name: "YouTube".to_owned(),
                target: "profile:1".to_owned(),
                services: vec!["youtube".to_owned()],
                ..Default::default()
            });
        }

        let (status, _, body) = handle_get_xray_config(&daemon);
        assert_eq!(status, 200);
        let config: Value = serde_json::from_str(&body).expect("parse config");
        assert!(
            config["inbounds"]
                .as_array()
                .expect("inbounds array")
                .iter()
                .any(|inbound| {
                    inbound["tag"] == "wifi-tproxy" && inbound["protocol"] == "dokodemo-door"
                })
        );
        assert!(
            config["outbounds"]
                .as_array()
                .expect("outbounds array")
                .iter()
                .any(|outbound| {
                    outbound["tag"] == "profile-1" && outbound["protocol"] == "vless"
                })
        );
        let rules = config["routing"]["rules"]
            .as_array()
            .expect("routing rules");
        assert!(rules.iter().any(|rule| {
            rule["outboundTag"] == "direct"
                && rule["domain"]
                    .as_array()
                    .is_some_and(|d| d.contains(&json!("geosite:ru")))
                && rule["ip"]
                    .as_array()
                    .is_some_and(|d| d.contains(&json!("geoip:ru")))
        }));
        assert!(rules.iter().any(|rule| rule["outboundTag"] == "block"
            && rule["network"] == "udp"
            && rule["port"] == "443"));
        assert_eq!(
            rules.last().expect("fallback rule")["outboundTag"],
            "active"
        );
    }

    #[test]
    fn routing_api_saves_settings_and_rules() {
        let (_dir, daemon) = test_daemon();
        let (status, _, _) = handle_routing_settings(
            r#"{"enabled":true,"auto_switch":true,"block_quic_global":true,"rule_source":"blackmatrix7"}"#,
            &daemon,
        );
        assert_eq!(status, 200);
        let body = r#"{"rules":[{"enabled":true,"name":"Instagram","target":"active","domains":["domain:instagram.com"],"ips":["1.2.3.0/24"],"services":["instagram"]}]}"#;
        let (status, _, response) = handle_routing_rules(body, &daemon);
        assert_eq!(status, 200);
        assert!(response.contains("Instagram"));
        let inner = lock(&daemon.inner);
        assert!(inner.state.split_routing.enabled);
        assert!(inner.state.split_routing.auto_switch);
        assert!(inner.state.split_routing.block_quic_global);
        assert_eq!(inner.state.split_routing.rule_source, "blackmatrix7");
        assert_eq!(inner.state.routing_rules.len(), 1);
        assert_eq!(inner.state.routing_rules[0].services, vec!["instagram"]);
    }

    #[test]
    fn profile_block_quic_toggle_persists_and_affects_config() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#Active\n\
             vless://22222222-2222-2222-2222-222222222222@example.org:443?security=tls#YouTube",
            &daemon,
        );
        {
            let mut inner = lock(&daemon.inner);
            inner.state.active_profile_id = Some(0);
            inner.state.split_routing.enabled = true;
            inner.state.routing_rules.push(RoutingRule {
                enabled: true,
                name: "YouTube".to_owned(),
                target: "profile:1".to_owned(),
                services: vec!["youtube".to_owned()],
                ..Default::default()
            });
        }

        // Toggle block_quic on the fixed target profile (id=1).
        let (status, _, _) =
            handle_profile_block_quic(r#"{"profile_id":1,"block_quic":true}"#, &daemon);
        assert_eq!(status, 200);

        let (status, _, body) = handle_get_xray_config(&daemon);
        assert_eq!(status, 200);
        let config: Value = serde_json::from_str(&body).expect("parse config");
        let rules = config["routing"]["rules"]
            .as_array()
            .expect("routing rules");
        let mut block_count = 0usize;
        let mut youtube_block_seen = false;
        for (i, rule) in rules.iter().enumerate() {
            if rule["outboundTag"] == "block" && rule["network"] == "udp" && rule["port"] == "443" {
                block_count += 1;
                // The block should appear immediately before a YouTube rule if it
                // belongs to the fixed profile target.
                if i + 1 < rules.len() && rules[i + 1]["outboundTag"] == "profile-1" {
                    youtube_block_seen = true;
                }
            }
        }
        assert!(block_count > 0, "expected at least one QUIC block rule");
        assert!(
            youtube_block_seen,
            "expected QUIC block before fixed-profile YouTube rule"
        );
    }

    #[test]
    fn routing_catalog_refresh_returns_curated_for_dat_sources() {
        let (_dir, daemon) = test_daemon();
        let (status, _, body) =
            handle_routing_catalog_refresh(r#"{"source":"metacubex-lite"}"#, &daemon);
        assert_eq!(status, 200);
        let response: Value = serde_json::from_str(&body).expect("parse catalog response");
        let catalog = response["catalog"].as_array().expect("catalog array");
        assert!(catalog.iter().any(|item| item["id"] == "youtube"));
        assert!(catalog.iter().any(|item| item["id"] == "instagram"));
    }

    #[test]
    fn set_active_rejects_hysteria2_with_400() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "hysteria2://secret@example.com:443?sni=example.com#Hy2",
            &daemon,
        );
        let (status, _, response_text) = handle_set_active(r#"{"profile_id":0}"#, &daemon);
        assert_eq!(status, 400);
        assert!(response_text.contains("Hysteria2"));
    }

    #[test]
    fn set_active_accepts_legacy_id_field() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#Demo",
            &daemon,
        );
        let (status, _, _) = handle_set_active(r#"{"id":0}"#, &daemon);
        assert_eq!(status, 200);
    }

    #[test]
    fn set_active_returns_404_for_missing_profile() {
        let (_dir, daemon) = test_daemon();
        let (status, _, _) = handle_set_active(r#"{"profile_id":99}"#, &daemon);
        assert_eq!(status, 404);
    }

    #[test]
    fn get_xray_config_returns_400_without_active() {
        let (_dir, daemon) = test_daemon();
        let (status, _, _) = handle_get_xray_config(&daemon);
        assert_eq!(status, 400);
    }

    #[test]
    fn get_xray_config_returns_config_after_activation() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#Demo",
            &daemon,
        );
        handle_set_active(r#"{"profile_id":0}"#, &daemon);
        let (status, content_type, body) = handle_get_xray_config(&daemon);
        assert_eq!(status, 200);
        assert_eq!(content_type, "application/json");
        assert!(body.contains("\"protocol\":\"socks\""));
    }

    #[test]
    fn unknown_route_returns_404() {
        let (_dir, daemon) = test_daemon();
        let (status, _, _) = dispatch("GET", "/api/unknown", "", &daemon);
        assert_eq!(status, 404);
    }

    #[test]
    fn health_endpoint_reports_service() {
        let (_dir, daemon) = test_daemon();
        let (status, _, body) = dispatch("GET", "/api/health", "", &daemon);
        assert_eq!(status, 200);
        assert!(body.contains("\"service\":\"hincyray\""));
        assert!(body.contains("\"ok\":true"));
    }

    #[test]
    fn status_endpoint_reports_defaults_and_paths() {
        let (_dir, daemon) = test_daemon();
        let (status, _, body) = dispatch("GET", "/api/status", "", &daemon);
        assert_eq!(status, 200);
        assert!(body.contains("\"socks_port\":10808"));
        assert!(body.contains("\"core_status\":\"stopped\""));
        assert!(body.contains("\"xray_path\":\"xray\""));
    }

    #[test]
    fn profiles_endpoint_lists_imported_profile() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#Demo",
            &daemon,
        );
        let (_, _, body) = dispatch("GET", "/api/profiles", "", &daemon);
        let response: Value = serde_json::from_str(&body).expect("parse");
        let profiles = response["profiles"].as_array().expect("profiles array");
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0]["name"], "Demo");
        assert_eq!(profiles[0]["protocol"], "VLESS");
        assert_eq!(profiles[0]["active"], false);
    }

    #[test]
    fn import_with_group_name_tags_profiles() {
        // JSON body `{"text": ..., "group": "Tutnet online"}` must tag
        // every directly-parsed profile with that group name. The
        // import response echoes the group back for the UI.
        let (_dir, daemon) = test_daemon();
        let body = r#"{"text":"vless://11111111-1111-1111-1111-111111111111@example.com:443#Demo","group":"Tutnet online"}"#;
        let (status, _, response_text) = handle_import(body, &daemon);
        assert_eq!(status, 200);
        let response: Value = serde_json::from_str(&response_text).expect("parse response");
        assert_eq!(response["profile_count"], 1);
        assert_eq!(response["added"], 1);
        assert_eq!(response["group"], "Tutnet online");

        let inner = lock(&daemon.inner);
        assert_eq!(inner.state.profiles.len(), 1);
        assert_eq!(
            inner.state.profiles[0].group.as_deref(),
            Some("Tutnet online")
        );
    }

    #[test]
    fn import_raw_text_without_group_leaves_none() {
        // Backward-compatible raw-text body (no JSON, no group) must
        // leave the new `group` field as `None`.
        let (_dir, daemon) = test_daemon();
        let body = "vless://11111111-1111-1111-1111-111111111111@example.com:443#Demo";
        let (status, _, response_text) = handle_import(body, &daemon);
        assert_eq!(status, 200);
        let response: Value = serde_json::from_str(&response_text).expect("parse response");
        assert_eq!(response["profile_count"], 1);
        assert!(
            response["group"].is_null(),
            "group should be null in response"
        );

        let inner = lock(&daemon.inner);
        assert_eq!(inner.state.profiles.len(), 1);
        assert!(inner.state.profiles[0].group.is_none());
    }

    #[test]
    fn profiles_endpoint_includes_group() {
        // `/api/profiles` exposes `group` per profile (null when None)
        // so the UI can build collapsible groups without /api/stats.
        let (_dir, daemon) = test_daemon();
        handle_import(
            r#"{"text":"vless://11111111-1111-1111-1111-111111111111@example.com:443#Demo","group":"Tutnet online"}"#,
            &daemon,
        );
        let (_, _, body) = dispatch("GET", "/api/profiles", "", &daemon);
        let response: Value = serde_json::from_str(&body).expect("parse");
        let profiles = response["profiles"].as_array().expect("profiles array");
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0]["group"], "Tutnet online");
    }

    #[test]
    fn profiles_endpoint_group_is_null_for_ungrouped_direct_import() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443#Demo",
            &daemon,
        );
        let (_, _, body) = dispatch("GET", "/api/profiles", "", &daemon);
        let response: Value = serde_json::from_str(&body).expect("parse");
        let profiles = response["profiles"].as_array().expect("profiles array");
        assert_eq!(profiles.len(), 1);
        assert!(profiles[0]["group"].is_null());
    }

    #[test]
    fn import_json_without_group_field_leaves_none() {
        // JSON body that omits the group field is the same as raw text
        // from a group perspective: group stays None.
        let (_dir, daemon) = test_daemon();
        let body =
            r#"{"text":"vless://11111111-1111-1111-1111-111111111111@example.com:443#Demo"}"#;
        let (status, _, _) = handle_import(body, &daemon);
        assert_eq!(status, 200);
        let inner = lock(&daemon.inner);
        assert_eq!(inner.state.profiles.len(), 1);
        assert!(inner.state.profiles[0].group.is_none());
    }

    #[test]
    fn import_does_not_overwrite_existing_group_on_dedup() {
        // Re-importing the same raw link with a different group name
        // must NOT overwrite the existing profile's group (otherwise a
        // later import could silently change a profile's group).
        let (_dir, daemon) = test_daemon();
        handle_import(
            r#"{"text":"vless://11111111-1111-1111-1111-111111111111@example.com:443#Demo","group":"First"}"#,
            &daemon,
        );
        handle_import(
            r#"{"text":"vless://11111111-1111-1111-1111-111111111111@example.com:443#Demo","group":"Second"}"#,
            &daemon,
        );
        let inner = lock(&daemon.inner);
        assert_eq!(inner.state.profiles.len(), 1);
        assert_eq!(inner.state.profiles[0].group.as_deref(), Some("First"));
    }

    #[test]
    fn import_fills_group_for_previously_ungrouped_profile() {
        // First import without a group, then again with one: the new
        // group should be adopted because the existing profile had no
        // group yet (the safe upgrade path documented in handle_import).
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443#Demo",
            &daemon,
        );
        handle_import(
            r#"{"text":"vless://11111111-1111-1111-1111-111111111111@example.com:443#Demo","group":"Late"}"#,
            &daemon,
        );
        let inner = lock(&daemon.inner);
        assert_eq!(inner.state.profiles.len(), 1);
        assert_eq!(inner.state.profiles[0].group.as_deref(), Some("Late"));
    }

    #[test]
    fn stats_endpoint_includes_group() {
        // /api/stats must also expose `group` so the UI can group the
        // unified table from stats alone if needed.
        let (_dir, daemon) = test_daemon();
        handle_import(
            r#"{"text":"vless://11111111-1111-1111-1111-111111111111@example.com:443#Demo","group":"Tutnet online"}"#,
            &daemon,
        );
        let (status, _, body) = dispatch("GET", "/api/stats", "", &daemon);
        assert_eq!(status, 200);
        let response: Value = serde_json::from_str(&body).expect("parse");
        let stats = response["stats"].as_array().expect("stats array");
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0]["group"], "Tutnet online");
    }

    #[test]
    fn subscriptions_refresh_one_rejects_unknown_url() {
        // Refreshing an unsaved URL must 404 without any network I/O.
        let (_dir, daemon) = test_daemon();
        let (status, _, _) = dispatch(
            "POST",
            "/api/subscriptions/refresh-one",
            r#"{"url":"https://provider.example/sub/never-saved"}"#,
            &daemon,
        );
        assert_eq!(status, 404);
    }

    #[test]
    fn subscriptions_refresh_one_rejects_missing_url() {
        let (_dir, daemon) = test_daemon();
        let (status, _, body) =
            dispatch("POST", "/api/subscriptions/refresh-one", r#"{}"#, &daemon);
        assert_eq!(status, 400);
        assert!(body.contains("missing url"));
    }

    #[test]
    fn subscriptions_refresh_one_rejects_invalid_json() {
        let (_dir, daemon) = test_daemon();
        let (status, _, _) = dispatch(
            "POST",
            "/api/subscriptions/refresh-one",
            "not json",
            &daemon,
        );
        assert_eq!(status, 400);
    }

    #[test]
    fn root_endpoint_returns_html() {
        let (_dir, daemon) = test_daemon();
        let (status, content_type, body) = dispatch("GET", "/", "", &daemon);
        assert_eq!(status, 200);
        assert!(content_type.starts_with("text/html"));
        assert!(body.contains("HincyRay daemon"));
    }

    #[test]
    fn core_stop_when_stopped_is_idempotent() {
        let (_dir, daemon) = test_daemon();
        let (status, _, body) = dispatch("POST", "/api/core/stop", "", &daemon);
        assert_eq!(status, 200);
        assert!(body.contains("\"core_status\":\"stopped\""));
    }

    #[test]
    fn legacy_state_json_without_v02_fields_loads_with_defaults() {
        // Pre-v0.2 state file: no subscriptions, favorites, stats, or
        // profile `group` keys. serde defaults must fill them in so
        // existing state.json on routers upgrades cleanly, and the new
        // `group` field deserialises to `None`.
        let dir = TempDir::new().expect("temp dir");
        let state_path = dir.path().join("state.json");
        let legacy = r#"{
            "profiles": [
                {
                    "id": 0,
                    "name": "demo",
                    "protocol": "Vless",
                    "address": "example.com",
                    "port": 443,
                    "raw": "vless://11111111-1111-1111-1111-111111111111@example.com:443#demo",
                    "selected": true
                }
            ],
            "active_profile_id": 0,
            "auto_select": false,
            "listen_host": "127.0.0.1",
            "socks_port": 10808,
            "http_port": 10809,
            "xray_path": "xray",
            "metrics_history": [],
            "routing_rules": []
        }"#;
        fs::write(&state_path, legacy).expect("write legacy state");
        let loaded = load_state(&state_path);
        assert_eq!(loaded.profiles.len(), 1);
        assert_eq!(loaded.active_profile_id, Some(0));
        assert!(
            loaded.profiles[0].group.is_none(),
            "group must default to None"
        );
        assert!(loaded.subscriptions.is_empty());
        assert!(loaded.favorites.is_empty());
        assert!(loaded.stats.is_empty());
    }

    #[test]
    fn bench_status_defaults_to_not_running() {
        let (_dir, daemon) = test_daemon();
        let (status, _, body) = dispatch("GET", "/api/bench/status", "", &daemon);
        assert_eq!(status, 200);
        let response: Value = serde_json::from_str(&body).expect("parse");
        assert_eq!(response["running"], false);
        assert_eq!(response["total"], 0);
        assert_eq!(response["completed"], 0);
        assert_eq!(response["cancel_requested"], false);
    }

    #[test]
    fn bench_start_rejects_unknown_method() {
        let (_dir, daemon) = test_daemon();
        let (status, _, body) =
            dispatch("POST", "/api/bench/start", r#"{"method":"quic"}"#, &daemon);
        assert_eq!(status, 400);
        assert!(body.contains("unknown method"));
    }

    #[test]
    fn bench_start_rejects_empty_profile_set() {
        let (_dir, daemon) = test_daemon();
        let (status, _, body) =
            dispatch("POST", "/api/bench/start", r#"{"method":"tcp"}"#, &daemon);
        assert_eq!(status, 400);
        assert!(body.contains("no profiles to benchmark"));
    }

    #[test]
    fn bench_start_returns_409_when_already_running() {
        let (_dir, daemon) = test_daemon();
        // Simulate a running job without actually spawning the worker.
        let job: SharedJob = Arc::new(Mutex::new(BenchJob {
            running: true,
            ..Default::default()
        }));
        {
            let mut inner = lock(&daemon.inner);
            inner.bench.job = Some(Arc::clone(&job));
            inner.bench.cancel = Some(Arc::new(AtomicBool::new(false)));
        }
        // Import a profile so the empty-profile guard does not fire.
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#Demo",
            &daemon,
        );
        let (status, _, body) =
            dispatch("POST", "/api/bench/start", r#"{"method":"tcp"}"#, &daemon);
        assert_eq!(status, 409);
        assert!(body.contains("already running"));
    }

    #[test]
    fn bench_stop_when_idle_reports_not_running() {
        let (_dir, daemon) = test_daemon();
        let (status, _, body) = dispatch("POST", "/api/bench/stop", "", &daemon);
        assert_eq!(status, 200);
        let response: Value = serde_json::from_str(&body).expect("parse");
        assert_eq!(response["stopped"], false);
    }

    #[test]
    fn stats_endpoint_lists_imported_profile_with_zeroes() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#Demo",
            &daemon,
        );
        let (status, _, body) = dispatch("GET", "/api/stats", "", &daemon);
        assert_eq!(status, 200);
        let response: Value = serde_json::from_str(&body).expect("parse");
        let stats = response["stats"].as_array().expect("stats array");
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0]["name"], "Demo");
        assert_eq!(stats[0]["score"], 0);
        assert_eq!(stats[0]["favorite"], false);
        assert_eq!(stats[0]["active"], false);
    }

    #[test]
    fn favorites_toggle_adds_then_removes_by_id() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#Demo",
            &daemon,
        );

        let (status, _, body) = dispatch(
            "POST",
            "/api/favorites/toggle",
            r#"{"profile_id":0}"#,
            &daemon,
        );
        assert_eq!(status, 200);
        let response: Value = serde_json::from_str(&body).expect("parse");
        assert_eq!(response["favorite"], true);

        let inner = lock(&daemon.inner);
        assert_eq!(inner.state.favorites.len(), 1);
        drop(inner);

        // Toggle again removes it.
        let (_, _, body) = dispatch(
            "POST",
            "/api/favorites/toggle",
            r#"{"profile_id":0}"#,
            &daemon,
        );
        let response: Value = serde_json::from_str(&body).expect("parse");
        assert_eq!(response["favorite"], false);

        let inner = lock(&daemon.inner);
        assert!(inner.state.favorites.is_empty());
    }

    #[test]
    fn favorites_toggle_returns_404_for_missing_profile() {
        let (_dir, daemon) = test_daemon();
        let (status, _, _) = dispatch(
            "POST",
            "/api/favorites/toggle",
            r#"{"profile_id":99}"#,
            &daemon,
        );
        assert_eq!(status, 404);
    }

    #[test]
    fn favorites_toggle_rejects_missing_field() {
        let (_dir, daemon) = test_daemon();
        let (status, _, _) = dispatch("POST", "/api/favorites/toggle", r#"{}"#, &daemon);
        assert_eq!(status, 400);
    }

    #[test]
    fn favorites_list_endpoint_returns_imported_favorites() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#Demo",
            &daemon,
        );
        dispatch(
            "POST",
            "/api/favorites/toggle",
            r#"{"profile_id":0}"#,
            &daemon,
        );
        let (status, _, body) = dispatch("GET", "/api/favorites", "", &daemon);
        assert_eq!(status, 200);
        let response: Value = serde_json::from_str(&body).expect("parse");
        let favorites = response["favorites"].as_array().expect("favorites array");
        assert_eq!(favorites.len(), 1);
        assert_eq!(favorites[0]["name"], "Demo");
    }

    #[test]
    fn subscriptions_refresh_with_no_sources_returns_note() {
        let (_dir, daemon) = test_daemon();
        let (status, _, body) = dispatch("POST", "/api/subscriptions/refresh", "", &daemon);
        assert_eq!(status, 200);
        let response: Value = serde_json::from_str(&body).expect("parse");
        assert_eq!(response["refreshed"], 0);
        assert!(response["note"].as_str().is_some());
    }

    #[test]
    fn apply_bench_result_updates_stats_and_history() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#Demo",
            &daemon,
        );
        let raw = lock(&daemon.inner).state.profiles[0].raw.clone();

        let success = BenchResult {
            profile_id: 0,
            profile_name: "Demo".to_owned(),
            profile_raw: raw.clone(),
            method: "tcp".to_owned(),
            latency_ms: 80,
            jitter_ms: 4,
            download_mbps: 0.0,
            loss_percent: 0.0,
            score: 70,
            success: true,
            error: None,
            timestamp: 1_700_000_000,
        };
        apply_bench_result(&daemon, success);

        let inner = lock(&daemon.inner);
        assert_eq!(inner.state.stats.len(), 1);
        let stat = &inner.state.stats[0];
        assert_eq!(stat.profile_raw, raw);
        assert_eq!(stat.last_latency_ms, 80);
        assert_eq!(stat.last_score, 70);
        assert_eq!(stat.success_count, 1);
        assert_eq!(stat.failure_count, 0);
        assert_eq!(inner.state.metrics_history.len(), 1);
        drop(inner);

        // A failure outcome increments failure_count and stores last_error.
        let failure = BenchResult {
            profile_id: 0,
            profile_name: "Demo".to_owned(),
            profile_raw: raw,
            method: "tcp".to_owned(),
            latency_ms: 0,
            jitter_ms: 0,
            download_mbps: 0.0,
            loss_percent: 100.0,
            score: 0,
            success: false,
            error: Some("tcp connect failed".to_owned()),
            timestamp: 1_700_000_001,
        };
        apply_bench_result(&daemon, failure);
        let inner = lock(&daemon.inner);
        let stat = &inner.state.stats[0];
        assert_eq!(stat.success_count, 1);
        assert_eq!(stat.failure_count, 1);
        assert_eq!(stat.last_error.as_deref(), Some("tcp connect failed"));
        assert_eq!(inner.state.metrics_history.len(), 2);
    }

    #[test]
    fn apply_bench_result_caps_history_at_max() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#Demo",
            &daemon,
        );
        let raw = lock(&daemon.inner).state.profiles[0].raw.clone();
        for i in 0..(MAX_HISTORY_SAMPLES + 5) {
            apply_bench_result(
                &daemon,
                BenchResult {
                    profile_id: 0,
                    profile_name: "Demo".to_owned(),
                    profile_raw: raw.clone(),
                    method: "tcp".to_owned(),
                    latency_ms: 10 + i as u32,
                    jitter_ms: 0,
                    download_mbps: 0.0,
                    loss_percent: 0.0,
                    score: 50,
                    success: true,
                    error: None,
                    timestamp: 1_700_000_000 + i as u64,
                },
            );
        }
        let inner = lock(&daemon.inner);
        assert_eq!(inner.state.metrics_history.len(), MAX_HISTORY_SAMPLES);
        // The oldest samples should have been dropped; the first kept
        // sample's latency must be greater than the very first sample's.
        let first_kept = &inner.state.metrics_history[0];
        assert!(first_kept.latency_ms > 10);
    }
}
