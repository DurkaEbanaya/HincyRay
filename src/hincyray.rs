//! HincyRay router daemon.
//!
//! Lightweight sync HTTP server on `std::net::TcpListener`, no async
//! runtime, no web framework. Shares `profiles`, `xray_config`, and
//! benchmark execution with the desktop app so parser/probe logic is not
//! duplicated.
//!
//! Default bind: `0.0.0.0:8088`. Override with `HINCYRAY_LISTEN`.
//! State path: see `resolve_state_path`. Override with `HINCYRAY_STATE`.
//! Mihomo config path: alongside state. Override with `HINCYRAY_MIHOMO_CONFIG`.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use percent_encoding::NON_ALPHANUMERIC;
use percent_encoding::utf8_percent_encode;
use qrcode::{QrCode, render::svg};
use tempfile::NamedTempFile;

use crate::benchmark::{
    BenchJob, BenchMethod, BenchResult, DEFAULT_DOWNLOAD_URL, DEFAULT_PROBE_URL,
    DEFAULT_UPLOAD_URL, QuickProbeConfig, ResourceTestResult, SharedJob, run_bench,
};
use crate::geobase::{
    self, Classification, DomainClassification, GeoBaseArtifactKind, GeoBaseGenerationInput,
    GeoBaseListMetadata, GeoBaseSource, GeoBaseSourceKind, GeoBaseStatus, GeoBaseStore,
    GeoBaseUpsertRequest, StaticRouteEntry,
};
use crate::hincyray_api::{
    ApiContractDescriptor, ConnectionPageResponse, ConnectionQueryRequest, DeviceTrafficRequest,
    DeviceTrafficResponse, DeviceTrafficSummary, MemoryEstimateResponse, OnboardingStatusResponse,
    ReadinessCheck, RoutingConnectionContextResponse, RoutingPreviewDiff, RoutingPreviewResponse,
    RoutingServerSummary, RoutingSummaryResponse, SafeModeRequest, SafeModeResponse,
    api_endpoint_contracts, openapi_document,
};
#[cfg(test)]
use crate::hincyray_mihomo_api::{controller_dial_address, first_stream_json};
use crate::hincyray_mihomo_api::{
    mihomo_api_delay, mihomo_api_delete, mihomo_api_get, mihomo_api_get_json,
    mihomo_api_get_response, mihomo_api_post, mihomo_api_post_response, mihomo_api_put,
    mihomo_api_stream_get, mihomo_api_stream_get_json, mihomo_controller,
};
use crate::hincyray_routing::{RoutingResource, RoutingResourceKind, normalize_routing_resource};
#[cfg(test)]
use crate::hincyray_security::verify_password;
use crate::hincyray_security::{
    LoginLimiter, MAX_CONCURRENT_PASSWORD_OPS, MAX_WEB_SESSIONS, PasswordWorkLimiter, WebSession,
    generate_session_token, hash_password, hash_password_with_permit, verify_password_with_permit,
};
use crate::hincyray_webui::index_html;
use crate::mihomo_config::{
    DIRECT_NAME, MihomoFeatures, PAROVOZIK_PROXY_GROUP, PROXY_ACTIVE_NAME, PROXY_NAME,
    PinnedServerRoute, REJECT_NAME, build_mihomo_config, build_mihomo_router_config,
};
use crate::profiles::{
    HwidConfig, Profile, SubscriptionMetadata, SubscriptionSource,
    load_subscription_detailed_via_proxy_with_hwid, parse_input,
};
use crate::telegram_probe::{
    ConfirmResult, LoginState, TelegramProbeConfig, confirm_login as telegram_confirm_login,
    load_config as load_telegram_config, request_login_code as telegram_request_login_code,
    revoke_and_delete as telegram_revoke_and_delete, save_config as save_telegram_config,
};
use crate::xray_config::{DnsSettings, PortMode, QuicMode, RouterExtra, XrayRouteRule};
use crate::xray_config::{GeoBaseRuleBehavior, GeoBaseRuleProvider, GeoBaseRuleTarget};

const DEFAULT_LISTEN: &str = "0.0.0.0:8088";
const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_GEOBASE_ANALYZE_BODY_BYTES: usize = 9 * 1024 * 1024;
const MAX_HISTORY_SAMPLES: usize = 1000;
const MAX_CONNECTION_LOG: usize = 500;
const MAX_STALE_PROFILE_STATS: usize = 256;
const MAX_AUTO_VPN_EXCEPTIONS: usize = 200;
const MAX_AUTO_VPN_PENDING_DOMAINS: usize = 200;
const MAX_PAROVOZIK_DOMAINS: usize = 500;
const MAX_PAROVOZIK_SERVERS: usize = 5;
const AUTO_VPN_PROBE_INTERVAL_TICKS: u64 = 3; // 30 seconds
const AUTO_VPN_RECHECK_INTERVAL_SECS: u64 = 24 * 60 * 60;
const AUTO_VPN_PROBE_CONTRACT_VERSION: u8 = 1;
const MAX_BACKUPS: usize = 20;
const MAX_UNDO_STACK: usize = 10;
const MAX_REFRESH_REPORT_ENTRIES: usize = 100;
const MIHOMO_VALIDATE_TIMEOUT: Duration = Duration::from_secs(15);
const MIHOMO_VALIDATE_MEMORY_LIMIT: &str = "64MiB";
const MIHOMO_VALIDATE_GOGC: &str = "20";
const COMMAND_OUTPUT_LIMIT_BYTES: u64 = 64 * 1024;
const GEOBASE_JOB_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const GEOBASE_PROBE_TIMEOUT: Duration = Duration::from_secs(4);
const GEOBASE_DNS_TIMEOUT: Duration = Duration::from_secs(3);
const PAROVOZIK_DIRECT_PROVIDER: &str = "parovozik-direct";
const PAROVOZIK_VPN_PROVIDER: &str = "parovozik-vpn-rules";
const PAROVOZIK_DIRECT_FILE: &str = "parovozik-direct.txt";
const PAROVOZIK_VPN_FILE: &str = "parovozik-vpn.txt";

/// Global shutdown flag set by the SIGTERM/SIGINT handler.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_signal(_sig: i32) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

fn register_signal_handlers() {
    unsafe extern "C" {
        fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize;
    }
    const SIGINT: i32 = 2;
    const SIGTERM: i32 = 15;
    // SAFETY: `signal` is a standard C library function that registers
    // a handler function pointer. The handler only writes to an atomic
    // bool, which is async-signal-safe.
    unsafe {
        signal(SIGINT, handle_signal);
        signal(SIGTERM, handle_signal);
    }
}

/// Entry point for the `hincyray` binary. Binds the listener and serves
/// requests on the calling thread; spawn background threads per
/// connection to avoid one slow client blocking the API.
pub fn run() -> Result<(), String> {
    register_signal_handlers();

    let listen = std::env::var("HINCYRAY_LISTEN").unwrap_or_else(|_| DEFAULT_LISTEN.to_owned());
    let state_path = resolve_state_path();
    let mihomo_config_path = resolve_mihomo_config_path(&state_path);
    let state = load_state(&state_path);
    let daemon = Daemon::new(state, state_path, mihomo_config_path);
    let mihomo_log_path = resolve_log_dir().join("mihomo.log");
    let mihomo_log_cursor = MihomoLogCursor::start_at_end(&mihomo_log_path);

    // Regenerate config from state on startup so the transparent proxy
    // inbounds are included when split routing is enabled.
    {
        let mut inner = lock(&daemon.inner);
        if let Err(error) = write_parovozik_provider_files(&inner.state) {
            eprintln!("hincyray: startup Parovozik providers failed: {error}");
        }
        if let Err(error) = regenerate_config(&inner.state, &daemon) {
            eprintln!("hincyray: startup config regeneration failed: {error}");
        }
        let split = &inner.state.split_routing;
        if split.enabled {
            let redirect_port = split.redirect_port;
            let vpn_subnet = split.vpn_subnet.clone();
            let policy_name = split.policy_name.clone();
            let cached_mark = split.policy_mark.clone();
            if let Err(error) = inner.firewall.start(
                redirect_port,
                &vpn_subnet,
                &policy_name,
                cached_mark.as_deref(),
            ) {
                eprintln!("hincyray: firewall startup failed: {error}");
            } else {
                eprintln!("hincyray: firewall started, redirect port {redirect_port}");
                // Persist the discovered policy mark.
                if let Some(ref mark) = inner.firewall.policy_mark {
                    inner.state.split_routing.policy_mark = Some(mark.clone());
                }
                let _ = persist_state(&daemon.state_path, &inner.state);
            }
        }
    }

    // Cache the current Mihomo version on startup so the web UI
    // can display it without spawning `mihomo -v` on every status poll.
    {
        let mut inner = lock(&daemon.inner);
        if inner.state.mihomo_version.is_none()
            && let Ok(version) = get_mihomo_version(&inner.state.mihomo_path)
        {
            eprintln!("hincyray: mihomo version: {version}");
            inner.state.mihomo_version = Some(version);
            let _ = persist_state(&daemon.state_path, &inner.state);
        }
    }

    // Start watchdog on router targets.
    start_watchdog(daemon.clone(), mihomo_log_path, mihomo_log_cursor);

    let listener = TcpListener::bind(&listen).map_err(|error| format!("bind {listen}: {error}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("set_nonblocking: {error}"))?;
    eprintln!("hincyray listening on {listen}");
    eprintln!("hincyray state: {}", daemon.state_path.to_string_lossy());
    eprintln!(
        "hincyray mihomo config: {}",
        daemon.mihomo_config_path.to_string_lossy()
    );

    loop {
        if SHUTDOWN.load(Ordering::SeqCst) {
            eprintln!("hincyray: shutdown signal received, cleaning up...");
            break;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(15)));
                let daemon = daemon.clone();
                thread::spawn(move || {
                    if let Err(error) = handle_connection(stream, &daemon) {
                        eprintln!("hincyray handler: {error}");
                    }
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(200));
            }
            Err(error) => {
                eprintln!("hincyray accept: {error}");
                thread::sleep(Duration::from_millis(200));
            }
        }
    }

    // GeoBase may be using the controller or store. Stop and join it before
    // tearing either the core or its filesystem dependencies down.
    eprintln!("hincyray: shutting down...");
    cancel_and_join_geobase(&daemon);
    {
        let mut inner = lock(&daemon.inner);
        let _ = inner.core.stop();
        let vpn_subnet = inner.state.split_routing.vpn_subnet.clone();
        let _ = inner.firewall.stop(&vpn_subnet);
        // v0.19.8: flush any pending dirty state from the watchdog
        // before exiting. If nothing is dirty, this is a no-op.
        flush_if_dirty(&mut inner, &daemon.state_path);
        eprintln!("hincyray: state persisted, children stopped, iptables cleaned");
    }
    Ok(())
}

pub fn run_cli() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let Some(cmd) = args.next() else {
        return run();
    };
    match cmd.as_str() {
        "serve" | "daemon" => run(),
        "status" => cli_api("GET", "/api/status", None).map(|body| println!("{body}")),
        "doctor" => cli_doctor(),
        "validate-config" => cli_api("POST", "/api/mihomo-config/validate", Some("{}"))
            .map(|body| println!("{body}")),
        "restart-core" => {
            cli_api("POST", "/api/core/restart", Some("{}")).map(|body| println!("{body}"))
        }
        "apply-routing" => {
            cli_api("POST", "/api/routing/apply", Some("{}")).map(|body| println!("{body}"))
        }
        "backup" => {
            cli_api("POST", "/api/backups/create", Some("{}")).map(|body| println!("{body}"))
        }
        "help" | "--help" | "-h" => {
            println!(
                "hincyray [serve|status|doctor|validate-config|restart-core|apply-routing|backup]"
            );
            Ok(())
        }
        other => Err(format!("unknown command '{other}', run 'hincyray help'")),
    }
}

fn cli_base_url() -> String {
    std::env::var("HINCYRAY_API").unwrap_or_else(|_| "http://127.0.0.1:8088".to_owned())
}

fn cli_api(method: &str, path: &str, body: Option<&str>) -> Result<String, String> {
    let url = format!("{}{}", cli_base_url().trim_end_matches('/'), path);
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|error| error.to_string())?;
    let request = match method {
        "GET" => client.get(&url),
        "POST" => client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(body.unwrap_or("").to_owned()),
        _ => return Err(format!("unsupported CLI method {method}")),
    };
    let response = request.send().map_err(|error| format!("{url}: {error}"))?;
    let status = response.status();
    let text = response.text().map_err(|error| error.to_string())?;
    if status.is_success() {
        Ok(text)
    } else {
        Err(format!("{url}: HTTP {status}: {text}"))
    }
}

fn cli_doctor() -> Result<(), String> {
    let checks = [
        ("status", "GET", "/api/status"),
        ("system", "GET", "/api/system"),
        ("memory_guard", "GET", "/api/memory-guard"),
        ("dns", "GET", "/api/diagnostics/dns"),
        ("udp_quic", "GET", "/api/diagnostics/udp-quic"),
        ("config_validator", "POST", "/api/mihomo-config/validate"),
    ];
    let mut report = serde_json::Map::new();
    for (name, method, path) in checks {
        let value = match cli_api(method, path, Some("{}")) {
            Ok(text) => {
                serde_json::from_str::<Value>(&text).unwrap_or_else(|_| json!({"raw": text}))
            }
            Err(error) => json!({"ok": false, "error": error}),
        };
        report.insert(name.to_owned(), value);
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&Value::Object(report)).map_err(|error| error.to_string())?
    );
    Ok(())
}

/// Top-level daemon state plus on-disk paths. Cloning is cheap: only
/// the `Arc` is duplicated.
#[derive(Clone)]
pub struct Daemon {
    inner: Arc<Mutex<DaemonInner>>,
    apply: Arc<Mutex<()>>,
    password_work: Arc<PasswordWorkLimiter>,
    state_path: PathBuf,
    mihomo_config_path: PathBuf,
    geobase_store_root: PathBuf,
    geobase_store: GeoBaseStore,
}

struct DaemonInner {
    state: HincyrayState,
    core: CoreManager,
    firewall: FirewallManager,
    bench: BenchRuntime,
    /// v0.19.8: write-behind dirty flag. Set by `mark_dirty()` when the
    /// watchdog mutates state; flushed to disk once per tick by
    /// `flush_if_dirty()`. This eliminates write amplification —
    /// previously the watchdog could call `persist_state()` up to 6
    /// times per 10-second tick (6 × 660KB = 3.96MB), now it's at most
    /// 1 write per tick.
    dirty: bool,
    /// v0.6: consecutive health-check failures for the active profile.
    /// Reset to 0 on success. When it reaches the threshold (3), the
    /// watchdog triggers a failover to the next-best profile.
    failover_fail_count: u32,
    /// v0.6.1: previous `/proc/stat` aggregate sample for CPU usage
    /// delta computation. `None` on first call → usage returns 0%.
    prev_cpu: Option<CpuTimes>,
    /// v0.6.1: per-core previous samples for per-core usage.
    prev_cpu_per_core: Vec<CpuTimes>,
    /// Auth runtime is deliberately not persisted. Sessions expire on idle and
    /// absolute deadlines; login throttling is keyed by observed peer IP.
    sessions: HashMap<String, WebSession>,
    login_limiter: LoginLimiter,
    telegram_login: Option<LoginState>,
    /// v0.20: Deep Bench runtime — background thread + cancel flag.
    /// Separate from `bench` so a running deep bench does not block
    /// manual quick benches from the UI (the daemon decides which to
    /// start based on `is_running()` checks).
    deep_bench_cancel: Option<Arc<std::sync::atomic::AtomicBool>>,
    deep_bench_handle: Option<JoinHandle<()>>,
    /// v0.20: true while the deep bench background thread is running.
    /// Set to true by the launcher before spawn, reset to false by
    /// the thread on exit (success or cancel). Used by Phase 3 to
    /// skip health check during deep bench (avoids EC contention),
    /// and by Phase 12 to avoid double-spawn.
    deep_bench_active: bool,
    /// v0.20: live status of the running (or last) deep bench. Updated
    /// by the background thread, read by `/api/deep-bench/status`.
    /// In-memory only — a fresh daemon starts in `idle` state.
    deep_bench_status: DeepBenchStatus,
    geobase: GeoBaseRuntime,
    pinned_route_now: HashMap<String, String>,
}

#[derive(Clone, Debug, Serialize)]
struct GeoBaseRuntimeStatus {
    job_id: u64,
    phase: String,
    total: usize,
    completed: usize,
    direct: usize,
    active: usize,
    unresolved: usize,
    error: Option<String>,
    id: Option<String>,
    running: bool,
    progress_percent: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_diff: Option<geobase::SourceDiff>,
    removed_static_entries: usize,
}

impl Default for GeoBaseRuntimeStatus {
    fn default() -> Self {
        Self {
            phase: "idle".to_owned(),
            job_id: 0,
            total: 0,
            completed: 0,
            direct: 0,
            active: 0,
            unresolved: 0,
            error: None,
            id: None,
            running: false,
            progress_percent: 0,
            source_diff: None,
            removed_static_entries: 0,
        }
    }
}

#[cfg(test)]
type GeoBaseAnalyzer = Arc<dyn Fn(&str) -> Classification + Send + Sync>;

#[derive(Default)]
struct GeoBaseRuntime {
    next_job_id: u64,
    current_job_id: Option<u64>,
    cancel: Option<Arc<AtomicBool>>,
    handle: Option<JoinHandle<()>>,
    status: GeoBaseRuntimeStatus,
    #[cfg(test)]
    analyzer: Option<GeoBaseAnalyzer>,
}

/// One row of `/proc/stat` for a CPU (aggregate or per-core).
/// Fields: user, nice, system, idle, iowait, irq, softirq, steal.
/// All in clock ticks (USER_HZ, typically 100 on ARM).
#[derive(Clone, Copy, Debug, Default)]
struct CpuTimes {
    user: u64,
    nice: u64,
    system: u64,
    idle: u64,
    iowait: u64,
    irq: u64,
    softirq: u64,
    steal: u64,
}

impl CpuTimes {
    /// Total of all fields = total time elapsed.
    fn total(&self) -> u64 {
        self.user
            + self.nice
            + self.system
            + self.idle
            + self.iowait
            + self.irq
            + self.softirq
            + self.steal
    }

    /// Idle time = idle + iowait.
    fn idle_total(&self) -> u64 {
        self.idle + self.iowait
    }

    /// Compute usage percentage (0.0–100.0) between two samples.
    fn usage_pct(prev: &CpuTimes, cur: &CpuTimes) -> f64 {
        let total_delta = cur.total().saturating_sub(prev.total());
        if total_delta == 0 {
            return 0.0;
        }
        let idle_delta = cur.idle_total().saturating_sub(prev.idle_total());
        let busy_delta = total_delta.saturating_sub(idle_delta);
        (busy_delta as f64 / total_delta as f64) * 100.0
    }

    /// Parse a single `cpu` line from `/proc/stat`.
    /// Format: `cpu  user nice system idle iowait irq softirq steal 0 0`
    fn parse_line(line: &str) -> Option<Self> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }
        // parts[0] = "cpu" or "cpu0" etc.
        let nums: Vec<u64> = parts[1..]
            .iter()
            .filter_map(|s| s.parse::<u64>().ok())
            .collect();
        if nums.len() < 4 {
            return None;
        }
        Some(Self {
            user: nums[0],
            nice: *nums.get(1).unwrap_or(&0),
            system: nums[2],
            idle: nums[3],
            iowait: *nums.get(4).unwrap_or(&0),
            irq: *nums.get(5).unwrap_or(&0),
            softirq: *nums.get(6).unwrap_or(&0),
            steal: *nums.get(7).unwrap_or(&0),
        })
    }
}

/// Decode ARM `CPU part` code to human-readable name.
/// Source: ARM ARM Table D-13-1 (CPU part numbers).
fn arm_cpu_part_name(part: &str) -> &'static str {
    match part {
        "0xd01" => "Cortex-A32",
        "0xd03" => "Cortex-A53",
        "0xd04" => "Cortex-A35",
        "0xd05" => "Cortex-A55",
        "0xd07" => "Cortex-A57",
        "0xd08" => "Cortex-A72",
        "0xd09" => "Cortex-A73",
        "0xd0a" => "Cortex-A76",
        "0xd0b" => "Cortex-A77",
        "0xd0d" => "Cortex-A78",
        "0xd40" => "Neoverse-V1",
        "0xd41" => "Cortex-A78",
        "0xd44" => "Cortex-X1",
        "0xd0c" => "Neoverse-N1",
        "0xd4a" => "Neoverse-N2",
        _ => "",
    }
}

/// Holds the live benchmark job (if any), its cancel flag, and the
/// worker thread handle. The active Mihomo `CoreManager` is intentionally
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

/// Web UI authentication settings. Only an Argon2id PHC string is persisted.
/// `password` exists solely as a deserialization bridge for pre-v0.21 state and
/// is never serialized back to disk.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WebUiAuth {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_auth_username")]
    pub username: String,
    #[serde(default, skip_serializing)]
    pub password: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password_hash: String,
}

impl WebUiAuth {
    fn has_password(&self) -> bool {
        !self.password_hash.is_empty() || !self.password.is_empty()
    }

    fn migrate_legacy_password_with(
        &mut self,
        hash: impl FnOnce(&str) -> Result<String, String>,
    ) -> AuthMigration {
        if !self.password_hash.is_empty() {
            let removed_legacy_password = !self.password.is_empty();
            self.password.clear();
            return if removed_legacy_password {
                AuthMigration::Migrated
            } else {
                AuthMigration::Unchanged
            };
        }
        if self.password.is_empty() {
            return AuthMigration::Unchanged;
        }
        match hash(&self.password) {
            Ok(password_hash) => {
                self.password_hash = password_hash;
                self.password.clear();
                AuthMigration::Migrated
            }
            Err(error) => {
                self.enabled = false;
                self.password.clear();
                AuthMigration::Disabled(error)
            }
        }
    }

    #[cfg(test)]
    fn set_password(&mut self, password: &str) -> Result<(), String> {
        self.password_hash = hash_password(password)?;
        self.password.clear();
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
enum AuthMigration {
    Unchanged,
    Migrated,
    Disabled(String),
}

impl AuthMigration {
    fn changed(&self) -> bool {
        !matches!(self, Self::Unchanged)
    }
}

fn default_auth_username() -> String {
    "admin".to_owned()
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
    /// Path to the Mihomo binary. Mihomo handles all protocols
    /// (VLESS/Reality/XHTTP, VMess, Trojan, Shadowsocks, Hysteria2)
    /// in a single binary, replacing the previous dual-engine approach.
    #[serde(default = "default_mihomo_path")]
    pub mihomo_path: String,
    /// Not persisted — transient data, rebuilt on each session.
    #[serde(skip)]
    pub metrics_history: Vec<MetricSample>,
    #[serde(default)]
    pub routing_rules: Vec<RoutingRule>,
    #[serde(default)]
    server_route_registry: Vec<ServerRouteRegistryEntry>,
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
    /// v0.5: DNS anti-leak settings for the router core config.
    #[serde(default)]
    pub dns_settings: DnsSettings,
    /// v0.5: Hardcoded HWID fingerprint for Happ subscription fetches.
    #[serde(default)]
    pub hwid_config: HwidConfig,
    /// v0.6: Auto-benchmark interval in hours (0 = disabled). When > 0,
    /// the watchdog triggers a TCP benchmark on all profiles every N
    /// hours. If `auto_select` is true, switches to the lowest-latency
    /// recently successful profile after the benchmark completes.
    #[serde(default)]
    pub auto_bench_interval_hours: u32,
    /// v0.6: Unix timestamp of the last auto-triggered benchmark.
    #[serde(default)]
    pub last_auto_bench_unix: u64,
    /// v0.12: Auto-refresh subscriptions from their source URLs
    /// periodically. Disabled by default.
    #[serde(default)]
    pub auto_refresh_enabled: bool,
    /// v0.12: Auto-refresh interval in hours (0 = disabled).
    #[serde(default)]
    pub auto_refresh_interval_hours: u32,
    /// v0.12: Unix timestamp of the last auto-refresh.
    #[serde(default)]
    pub last_auto_refresh_unix: u64,
    /// v0.12: Cumulative uploaded bytes through the proxy (persisted).
    #[serde(default)]
    pub traffic_total_up_bytes: u64,
    /// v0.12: Cumulative downloaded bytes through the proxy (persisted).
    #[serde(default)]
    pub traffic_total_down_bytes: u64,
    /// Not persisted — transient data, rebuilt on each session by the watchdog.
    #[serde(skip)]
    pub connection_log: Vec<ConnectionLogEntry>,
    /// v0.12: Per-device routing rules. Each sends a specific device's
    /// traffic to a different target (direct, specific profile, etc.).
    #[serde(default)]
    pub device_routes: Vec<DeviceRoute>,
    /// v0.7.1: Mihomo auto-update enabled. When true, the watchdog
    /// periodically checks GitHub for new Mihomo releases through the
    /// local SOCKS proxy and auto-installs them.
    #[serde(default)]
    pub auto_update_enabled: bool,
    /// v0.7.1: Auto-update check interval in hours.
    #[serde(default = "default_auto_update_interval_hours")]
    pub auto_update_interval_hours: u32,
    /// v0.7.1: Unix timestamp of the last update check.
    #[serde(default)]
    pub last_update_check_unix: u64,
    /// v0.7.1: Latest available version found by the last check
    /// (e.g. "v1.19.28"). None if no check has been performed or
    /// the last check found no update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_available_version: Option<String>,
    /// v0.7.1: Currently installed Mihomo version (cached from
    /// `mihomo -v`). Refreshed on startup, on check, and after
    /// applying an update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mihomo_version: Option<String>,
    /// v0.9: All Mihomo-specific opt-in features (proxy groups,
    /// external controller, NTP, smux, DNS enhancements, sniffer
    /// enhancements, tunnels, hosts, authentication, experimental).
    #[serde(default)]
    pub mihomo_features: MihomoFeatures,
    /// v0.13: Web UI authentication (login/password).
    #[serde(default)]
    pub web_ui_auth: WebUiAuth,
    /// v0.14: Sub-Store Lite profile cleanup pipeline.
    #[serde(default)]
    pub sub_store_lite: SubStoreLiteSettings,
    /// v0.14: scheduled maintenance window settings.
    #[serde(default)]
    pub maintenance: MaintenanceSettings,
    /// v0.19: last structured subscription refresh report shown in Web UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_subscription_refresh_report: Option<SubscriptionRefreshReport>,
    /// v0.19: bounded server-side undo snapshots for destructive state changes.
    /// Not persisted — undo is session-level only (lost on daemon restart)
    /// to avoid bloating state.json with 3MB+ of JSON snapshots.
    #[serde(skip)]
    pub undo_stack: Vec<UndoEntry>,
    /// v0.19: memory guard thresholds and last warning state.
    #[serde(default)]
    pub memory_guard: MemoryGuardSettings,
    /// v0.21: runtime projection that suppresses memory-heavy optional rule
    /// sources without destroying their persisted configuration.
    #[serde(default)]
    pub safe_mode_enabled: bool,
    /// v0.20: Deep Bench settings (scheduled quality testing).
    #[serde(default)]
    pub deep_bench: DeepBenchSettings,
    /// Opaque canonical server references assigned to the virtual
    /// "Dead Servers" lifecycle group. Profile provenance remains in
    /// `Profile.group`; lifecycle membership survives subscription refresh,
    /// profile renumbering, and display-name changes.
    #[serde(default, alias = "trash_raws")]
    pub dead_server_refs: std::collections::HashSet<String>,
    /// Unix timestamp when each canonical server reference was promoted.
    /// Used for garbage collection (purge entries older than 90 days
    /// that are no longer present in any subscription).
    #[serde(default, alias = "trash_promoted_at")]
    pub dead_promoted_at: std::collections::HashMap<String, u64>,
    /// v0.20: Daily quality snapshots — persisted to a separate file
    /// (`/opt/etc/hincyray/quality-history.json`) to avoid bloating
    /// state.json. Loaded lazily by `/api/deep-bench/history`.
    #[serde(skip)]
    pub quality_history: Vec<DailyQualitySnapshot>,
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
            mihomo_path: default_mihomo_path(),
            metrics_history: Vec::new(),
            routing_rules: Vec::new(),
            server_route_registry: Vec::new(),
            split_routing: SplitRoutingSettings::default(),
            subscriptions: Vec::new(),
            favorites: Vec::new(),
            stats: Vec::new(),
            dns_settings: DnsSettings::default(),
            hwid_config: HwidConfig::default(),
            auto_bench_interval_hours: 0,
            last_auto_bench_unix: 0,
            auto_refresh_enabled: false,
            auto_refresh_interval_hours: 0,
            last_auto_refresh_unix: 0,
            traffic_total_up_bytes: 0,
            traffic_total_down_bytes: 0,
            connection_log: Vec::new(),
            device_routes: Vec::new(),
            auto_update_enabled: false,
            auto_update_interval_hours: default_auto_update_interval_hours(),
            last_update_check_unix: 0,
            update_available_version: None,
            mihomo_version: None,
            mihomo_features: MihomoFeatures::default(),
            web_ui_auth: WebUiAuth::default(),
            sub_store_lite: SubStoreLiteSettings::default(),
            maintenance: MaintenanceSettings::default(),
            last_subscription_refresh_report: None,
            undo_stack: Vec::new(),
            memory_guard: MemoryGuardSettings::default(),
            safe_mode_enabled: false,
            deep_bench: DeepBenchSettings::default(),
            dead_server_refs: std::collections::HashSet::new(),
            dead_promoted_at: std::collections::HashMap::new(),
            quality_history: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SubscriptionRefreshReport {
    pub timestamp: u64,
    pub refreshed: usize,
    pub added: usize,
    pub removed: usize,
    pub changed: usize,
    pub failed: usize,
    #[serde(default)]
    pub entries: Vec<SubscriptionRefreshEntry>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SubscriptionRefreshEntry {
    pub url: String,
    pub status: String,
    pub previous_count: usize,
    pub new_count: usize,
    pub added: usize,
    pub removed: usize,
    pub changed: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UndoEntry {
    pub id: String,
    pub label: String,
    pub timestamp: u64,
    /// JSON snapshot with `undo_stack` cleared to avoid recursive state growth.
    pub state_json: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryGuardSettings {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_memory_guard_mihomo_rss_kb")]
    pub mihomo_rss_warn_kb: u64,
    #[serde(default = "default_memory_guard_system_pct")]
    pub system_usage_warn_pct: f64,
}

impl Default for MemoryGuardSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            mihomo_rss_warn_kb: default_memory_guard_mihomo_rss_kb(),
            system_usage_warn_pct: default_memory_guard_system_pct(),
        }
    }
}

fn default_memory_guard_mihomo_rss_kb() -> u64 {
    180 * 1024
}

fn default_memory_guard_system_pct() -> f64 {
    90.0
}

// =========================================================================
// v0.20: Deep Bench — scheduled quality testing of all profiles.
// =========================================================================

/// Default stability-test duration per server (minutes). 3 minutes was
/// chosen so that 60 servers × 3m = 3h fits in a typical 4-hour night
/// window (02:00–06:00) alongside the ~35 min Phase A quick bench.
fn default_deep_bench_stability_minutes() -> u32 {
    3
}

/// Default window: every day, 02:00–06:00. Weekdays bitmask 0x7F = all
/// 7 days (bits 0..=6 set, where bit 0 = Sunday, bit 6 = Saturday).
fn default_deep_bench_weekdays() -> u8 {
    0x7F
}

fn default_deep_bench_start_hour() -> u8 {
    2
}

fn default_deep_bench_end_hour() -> u8 {
    6
}

/// Bitmask: bit (1 << day_of_week) where day_of_week is 0=Sunday..=6=Saturday
/// (matches `chrono::Weekday::num_days_from_sunday`).
pub const WEEKDAY_SUN: u8 = 1 << 0;
pub const WEEKDAY_MON: u8 = 1 << 1;
pub const WEEKDAY_TUE: u8 = 1 << 2;
pub const WEEKDAY_WED: u8 = 1 << 3;
pub const WEEKDAY_THU: u8 = 1 << 4;
pub const WEEKDAY_FRI: u8 = 1 << 5;
pub const WEEKDAY_SAT: u8 = 1 << 6;

/// v0.20: Deep Bench settings. Schedules a two-phase quality test:
/// Phase A runs a quick bench (latency+jitter+speed) on selected
/// profiles, Phase B observes each server that passed Phase A for
/// `stability_minutes` to measure drop rate, latency variance, and
/// unlock capability. Results are persisted to
/// `/opt/etc/hincyray/quality-history.json` for 30-day trend analysis.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DeepBenchSettings {
    /// Master switch. When false, the watchdog never triggers a deep
    /// bench, but manual `/api/deep-bench/start` still works.
    #[serde(default)]
    pub enabled: bool,
    /// Bitmask of weekdays (1<<day). 0x7F = every day.
    #[serde(default = "default_deep_bench_weekdays")]
    pub weekdays: u8,
    /// Start of the testing window (hour, 0-23). Deep bench may start
    /// at any tick where `current_hour >= start_hour && current_hour <
    /// end_hour`.
    #[serde(default = "default_deep_bench_start_hour")]
    pub start_hour: u8,
    /// End of the testing window (exclusive). Must be > start_hour.
    #[serde(default = "default_deep_bench_end_hour")]
    pub end_hour: u8,
    /// Stability-test duration per server in Phase B. Default 3 minutes
    /// = 18 latency samples (one every 10s).
    #[serde(default = "default_deep_bench_stability_minutes")]
    pub stability_minutes: u32,
    /// Which profiles to test. Empty filter = all profiles.
    #[serde(default)]
    pub profile_filter: ProfileFilter,
    /// Unix timestamp of the last deep bench start (manual or auto).
    #[serde(default)]
    pub last_run_unix: u64,
    /// Date (YYYYMMDD) of the last completed deep bench. Used to
    /// enforce one-shot-per-day: if today's date matches, the
    /// scheduler skips even if the window is active.
    #[serde(default)]
    pub last_completed_date: u32,
}

/// v0.20: Selector for which profiles to deep-bench.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ProfileFilter {
    /// Test every profile in state.profiles.
    #[default]
    All,
    /// Test only profiles whose `group` matches the subscription URL.
    Subscription(String),
    /// Test only profiles whose opaque canonical server reference is in the
    /// given list. Explicit scope is deliberate diagnostics and may include
    /// profiles assigned to Dead Servers.
    Explicit(Vec<String>),
}

/// v0.20: Per-server stability metrics collected during Phase B by
/// observing the proxy for `stability_minutes`. All latency samples
/// are kept so the UI can plot a sparkline; aggregates are precomputed
/// for fast sort/filter.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StabilityMetrics {
    /// Total observation time in seconds (e.g. 180 for 3 minutes).
    pub observation_secs: u32,
    /// One latency sample every 10 seconds (ms). 18 entries for 3 min.
    pub latency_samples: Vec<u32>,
    pub latency_min: u32,
    pub latency_avg: u32,
    pub latency_p95: u32,
    pub latency_stddev: u32,
    /// Number of delay tests that returned no answer within timeout.
    pub drop_count: u32,
    /// drop_count / total_samples × 100.
    pub loss_percent: f32,
    /// Whether the post-spawn warm-up probe succeeded before measured
    /// sampling began. Warm-up is excluded from loss statistics.
    #[serde(default)]
    pub warmup_ok: bool,
    /// Average download speed over a 30-second sustained test.
    pub sustained_download_mbps: f32,
    /// Which URL produced the sustained download speed reading.
    #[serde(default)]
    pub sustained_download_source: String,
    /// Last sustained-download error if no candidate URL succeeded.
    #[serde(default)]
    pub sustained_download_error: String,
    /// Average upload speed over a 30-second sustained test.
    pub sustained_upload_mbps: f32,
}

/// v0.20: Reachability result for one of the four unlock-test services.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UnlockStatus {
    /// True if at least one of the 2 retry attempts returned HTTP 2xx/3xx.
    pub reachable: bool,
    /// Last HTTP status code observed (0 if never reached).
    pub http_status: u16,
    /// Time-to-first-byte in ms (0 if never reached).
    pub ttfb_ms: u32,
}

/// v0.20: Unlock-test result — checks whether the server can reach
/// four commonly-blocked services. Each service is probed twice to
/// avoid false negatives from transient failures (e.g. the Italian
/// LTE server today cannot reach github.com but its subdomains work).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UnlockTestResult {
    pub github: UnlockStatus,
    pub cloudflare: UnlockStatus,
    pub google: UnlockStatus,
    pub telegram: UnlockStatus,
}

impl UnlockTestResult {
    /// Number of services that are reachable (0..=4).
    pub fn reachable_count(&self) -> u32 {
        [
            self.github.reachable,
            self.cloudflare.reachable,
            self.google.reachable,
            self.telegram.reachable,
        ]
        .iter()
        .filter(|&&r| r)
        .count() as u32
    }
}

/// v0.20: One row of quality history. Stored by opaque canonical server
/// reference (not `profile_id` or a credential-bearing share link) so it
/// survives subscription refresh, profile renumbering, and display-name
/// changes without exposing connection secrets through the history API.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DailyQualitySnapshot {
    /// YYYYMMDD (e.g. 20260707 for 2026-07-07).
    pub date: u32,
    /// Opaque canonical server identity. The alias reads legacy history files;
    /// `load_quality_history` converts their raw values before returning them.
    #[serde(default, alias = "profile_raw")]
    pub server_ref: String,
    /// Snapshot of profile name at test time (for UI display when the
    /// profile is no longer in any subscription).
    pub profile_name: String,
    /// Whether Phase A reached the profile successfully.
    #[serde(default)]
    pub phase_a_success: bool,
    /// Stability metrics from Phase B. None if the profile did not
    /// pass Phase A (filtered out as unavailable or low-quality).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stability: Option<StabilityMetrics>,
    /// Unlock-test result from Phase B.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unlock: Option<UnlockTestResult>,
}

/// v0.20: Live status of a running (or last) deep bench. Polled by
/// the UI every 5 seconds while `state == running`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DeepBenchStatus {
    /// "idle" | "phase_a" | "phase_b" | "completed" | "failed" | "cancelled"
    pub state: String,
    /// 0..=100 progress within the current phase.
    pub phase_progress: u32,
    /// "12/84 profiles quick-benched"
    pub phase_detail: String,
    /// Unix timestamp when the run started.
    pub started_unix: u64,
    /// Estimated total remaining seconds (0 if unknown/idle).
    pub eta_secs: u64,
    /// Last error message (empty if no error).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_error: String,
}

/// v0.14: lightweight subscription cleanup inspired by Sub-Store.
/// This intentionally works on already parsed profiles: it never rewrites
/// share-link internals, so protocol-specific builders keep their existing
/// contract and cannot drift from profile parsing.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SubStoreLiteSettings {
    #[serde(default)]
    pub enabled: bool,
    /// Case-insensitive contains filters separated by `|`. Empty = keep all.
    #[serde(default)]
    pub include_filter: String,
    /// Case-insensitive contains filters separated by `|`. Empty = exclude none.
    #[serde(default)]
    pub exclude_filter: String,
    #[serde(default)]
    pub rename_rules: Vec<SubStoreRenameRule>,
    #[serde(default = "default_true")]
    pub deduplicate: bool,
    /// `name`, `group`, `protocol`, `address`, or `latency`.
    #[serde(default = "default_substore_sort")]
    pub sort_by: String,
    #[serde(default)]
    pub last_applied_unix: u64,
}

fn default_true() -> bool {
    true
}

fn default_substore_sort() -> String {
    "name".to_owned()
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SubStoreRenameRule {
    pub from: String,
    pub to: String,
}

fn default_smart_cooldown_secs() -> u64 {
    300
}

/// v0.14: daily/periodic maintenance actions performed by the watchdog.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MaintenanceSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub hour_utc: u8,
    #[serde(default)]
    pub minute_utc: u8,
    #[serde(default = "default_maintenance_interval_days")]
    pub interval_days: u32,
    #[serde(default = "default_true")]
    pub create_backup: bool,
    #[serde(default)]
    pub refresh_subscriptions: bool,
    #[serde(default = "default_true")]
    pub restart_core: bool,
    #[serde(default)]
    pub close_connections: bool,
    #[serde(default)]
    pub last_run_unix: u64,
}

impl Default for MaintenanceSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            hour_utc: 4,
            minute_utc: 0,
            interval_days: default_maintenance_interval_days(),
            create_backup: true,
            refresh_subscriptions: false,
            restart_core: true,
            close_connections: false,
            last_run_unix: 0,
        }
    }
}

fn default_maintenance_interval_days() -> u32 {
    1
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetricSample {
    pub timestamp: u64,
    pub profile_id: usize,
    pub passed: bool,
    pub latency_ms: u32,
    pub download_mbps: f32,
}

/// v0.12: A single entry in the persisted connection log. Captures
/// metadata about a connection seen through the Mihomo proxy.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ConnectionLogEntry {
    pub timestamp: u64,
    pub host: String,
    pub source_ip: String,
    pub destination_ip: String,
    #[serde(default)]
    pub destination_port: u16,
    pub network: String,
    pub chains: Vec<String>,
    pub rule: String,
    pub upload: u64,
    pub download: u64,
}

/// v0.12: Per-device routing rule. Sends a specific device's traffic
/// (identified by IP) to a different target than the default proxy.
/// Implemented as `SRC-IP-CIDR,<ip>/32,<target>` rules emitted BEFORE
/// general routing rules in the Mihomo config.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DeviceRoute {
    pub enabled: bool,
    pub name: String,
    pub ip: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// "direct", "active", "best", "reject", or "server:<ref>".
    #[serde(default = "default_routing_target")]
    pub target: String,
}

/// v0.13: Predefined routing rule bundles that can be applied in one click.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoutingPreset {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub rules: Vec<RoutingRule>,
    /// Optional port mode change: "all", "allow_list", "deny_list".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_mode: Option<String>,
    /// Proxy ports for allow_list mode.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxy_ports: Vec<&'static str>,
    /// Clear existing custom routing rules before applying this preset.
    #[serde(default, skip_serializing_if = "is_false")]
    pub clear_existing: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn routing_presets() -> Vec<RoutingPreset> {
    vec![
        RoutingPreset {
            id: "all-vpn",
            name: "No presets / All VPN",
            description: "Clear custom routing rules; all intercepted policy traffic falls through to MATCH,proxy",
            rules: vec![],
            port_mode: Some("all".to_owned()),
            proxy_ports: vec![],
            clear_existing: true,
        },
        RoutingPreset {
            id: "ru-ip-direct",
            name: "RU IP Direct (advanced)",
            description: "All Russian destination IPs go direct, independently of the RU Direct GeoSite mode",
            rules: vec![RoutingRule {
                enabled: true,
                name: "RU IPs direct".to_owned(),
                target: "direct".to_owned(),
                ips: vec!["geoip:RU".to_owned()],
                ..Default::default()
            }],
            port_mode: None,
            proxy_ports: vec![],
            clear_existing: false,
        },
        RoutingPreset {
            id: "ad-block",
            name: "Ad Block",
            description: "Block ad domains via geosite:category-ads-all",
            rules: vec![RoutingRule {
                enabled: true,
                name: "Block ads".to_owned(),
                target: "reject".to_owned(),
                domains: vec!["geosite:category-ads-all".to_owned()],
                ..Default::default()
            }],
            port_mode: None,
            proxy_ports: vec![],
            clear_existing: false,
        },
        RoutingPreset {
            id: "only-web-vpn",
            name: "Only Web VPN",
            description: "Proxy only ports 80 and 443, everything else direct",
            rules: vec![],
            port_mode: Some("allow_list".to_owned()),
            proxy_ports: vec!["80", "443"],
            clear_existing: false,
        },
        RoutingPreset {
            id: "block-social",
            name: "Block Social",
            description: "Block Facebook, Instagram, Twitter/X domains",
            rules: vec![RoutingRule {
                enabled: true,
                name: "Block social media".to_owned(),
                target: "reject".to_owned(),
                domains: vec![
                    "geosite:facebook".to_owned(),
                    "geosite:instagram".to_owned(),
                    "geosite:twitter".to_owned(),
                ],
                ..Default::default()
            }],
            port_mode: None,
            proxy_ports: vec![],
            clear_existing: false,
        },
        RoutingPreset {
            id: "ru-ip-direct-ad-block",
            name: "RU IP Direct + Ad Block (advanced)",
            description: "All Russian destination IPs direct + block ads",
            rules: vec![
                RoutingRule {
                    enabled: true,
                    name: "RU IPs direct".to_owned(),
                    target: "direct".to_owned(),
                    ips: vec!["geoip:RU".to_owned()],
                    ..Default::default()
                },
                RoutingRule {
                    enabled: true,
                    name: "Block ads".to_owned(),
                    target: "reject".to_owned(),
                    domains: vec!["geosite:category-ads-all".to_owned()],
                    ..Default::default()
                },
            ],
            port_mode: None,
            proxy_ports: vec![],
            clear_existing: false,
        },
    ]
}

/// v0.2: persisted subscription source plus its last refresh metadata.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StoredSubscription {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub announcement: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_loaded_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default)]
    pub profile_count: usize,
}

fn apply_subscription_metadata(
    subscription: &mut StoredSubscription,
    metadata: SubscriptionMetadata,
) {
    subscription.title = metadata.title;
    subscription.announcement = metadata.announcement;
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
    pub last_upload_mbps: f32,
    #[serde(default)]
    pub last_loss_percent: f32,
    #[serde(default)]
    pub success_count: u32,
    #[serde(default)]
    pub failure_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default)]
    pub last_checked_unix: u64,
    #[serde(default)]
    pub resource_tests: Vec<ResourceTestResult>,
    #[serde(default)]
    pub ewma_latency_ms: f32,
    #[serde(default)]
    pub ewma_download_mbps: f32,
    #[serde(default)]
    pub consecutive_failures: u32,
    #[serde(default)]
    pub cooldown_until_unix: u64,
    #[serde(default)]
    pub has_latency: bool,
    #[serde(default)]
    pub has_jitter: bool,
    #[serde(default)]
    pub has_download: bool,
    #[serde(default)]
    pub has_upload: bool,
    #[serde(default)]
    pub has_loss: bool,
    #[serde(default)]
    pub has_ewma: bool,
}

/// WiFi split-routing controls. Traffic from devices assigned to the
/// Keenetic "HincyRay" policy is transparent-proxied via iptables NAT
/// REDIRECT (TCP) + mangle TPROXY (UDP) to Mihomo's redirect/tproxy
/// listeners. Direct SOCKS clients keep using the active server.
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
    #[serde(default = "default_redirect_port")]
    pub redirect_port: u16,
    /// Keenetic traffic policy name for device selection.
    #[serde(default = "default_policy_name")]
    pub policy_name: String,
    /// Cached connmark from RCI API (e.g. "0xffffaaa"). None if not yet queried.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_mark: Option<String>,
    /// QUIC (UDP/443) handling mode.
    #[serde(default)]
    pub quic_mode: QuicMode,
    /// Whether TPROXY kernel modules are available. Detected at runtime
    /// by FirewallManager; cached in state so config generation can use
    /// the correct value. Defaults to true (optimistic).
    #[serde(default = "default_tproxy_available")]
    pub tproxy_available: bool,
    /// v0.5: Port-based routing mode for WiFi VPN traffic.
    #[serde(default)]
    pub port_mode: PortMode,
    /// v0.5: Ports to proxy when `port_mode` is `AllowList`.
    #[serde(default)]
    pub proxy_ports: Vec<String>,
    /// v0.5: Ports to bypass (direct) when `port_mode` is `DenyList`.
    #[serde(default)]
    pub bypass_ports: Vec<String>,
    /// v0.5: Path to GeoIP/GeoSite .dat files for the core. The parent
    /// directory is passed as the Mihomo `-d` home directory flag.
    #[serde(default = "default_geo_asset_path")]
    pub geo_asset_path: String,
    /// v0.16: RU Direct mode — route Russian domains direct before MATCH,proxy.
    /// `"off"` (default), `"tld"` (.ru + .рф suffixes), `"geosite"` (GEOSITE,category-ru).
    #[serde(default)]
    pub ru_direct_mode: String,
    /// v0.16: Domains that bypass RU Direct and go through VPN instead.
    /// One domain per line in the UI; stored as a Vec.
    #[serde(default)]
    pub ru_direct_exceptions: Vec<String>,
    /// Auto-learned domains that failed direct access but succeeded via
    /// the active VPN. Emitted before broad RKN/RU Direct rules.
    #[serde(default)]
    pub auto_vpn_exceptions: Vec<String>,
    /// Per-domain last probe timestamp for auto_vpn_exceptions and recent
    /// DIRECT candidates. This is a bounded probe cache, not a routing list.
    #[serde(default)]
    pub auto_vpn_last_checked_unix: HashMap<String, u64>,
    /// Passive learning switch. Disabled by default; writes only after a
    /// verified direct-fail/proxy-success probe.
    #[serde(default)]
    pub auto_vpn_learning_enabled: bool,
    /// Persisted migration marker for auto-VPN probe semantics.
    #[serde(default)]
    pub auto_vpn_probe_contract_version: u8,
    /// Experimental direct-first classifier for hosts absent from enabled
    /// managed GeoBases. Disabled by default.
    #[serde(default)]
    pub parovozik_enabled: bool,
    #[serde(default)]
    pub parovozik_direct_domains: Vec<String>,
    #[serde(default)]
    pub parovozik_vpn_domains: Vec<String>,
    /// Stable routing refs tried after the current active VPN, max five.
    #[serde(default)]
    pub parovozik_server_refs: Vec<String>,
    #[serde(default)]
    pub parovozik_last_checked_unix: HashMap<String, u64>,
    /// v0.16: Controls the final MATCH rule target.
    /// `"proxy"` = everything through VPN, `"direct"` = everything direct.
    /// Empty string (old state) is migrated in `load_state()`.
    #[serde(default)]
    pub match_target: String,
}

impl Default for SplitRoutingSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            auto_switch: false,
            block_quic_global: false,
            rule_source: default_rule_source(),
            vpn_subnet: default_vpn_subnet(),
            redirect_port: default_redirect_port(),
            policy_name: default_policy_name(),
            policy_mark: None,
            quic_mode: QuicMode::default(),
            tproxy_available: default_tproxy_available(),
            port_mode: PortMode::default(),
            proxy_ports: Vec::new(),
            bypass_ports: Vec::new(),
            geo_asset_path: default_geo_asset_path(),
            ru_direct_mode: "off".to_owned(),
            ru_direct_exceptions: Vec::new(),
            auto_vpn_exceptions: Vec::new(),
            auto_vpn_last_checked_unix: HashMap::new(),
            auto_vpn_learning_enabled: false,
            auto_vpn_probe_contract_version: AUTO_VPN_PROBE_CONTRACT_VERSION,
            parovozik_enabled: false,
            parovozik_direct_domains: Vec::new(),
            parovozik_vpn_domains: Vec::new(),
            parovozik_server_refs: Vec::new(),
            parovozik_last_checked_unix: HashMap::new(),
            match_target: String::new(),
        }
    }
}

fn default_rule_source() -> String {
    "metacubex-lite".to_owned()
}

fn default_vpn_subnet() -> String {
    "192.168.2.0/24".to_owned()
}

fn default_redirect_port() -> u16 {
    10810
}

fn default_policy_name() -> String {
    "HincyRay".to_owned()
}

fn default_tproxy_available() -> bool {
    true
}

fn default_geo_asset_path() -> String {
    if Path::new("/opt/etc/hincyray").is_dir() {
        "/opt/etc/hincyray".to_owned()
    } else {
        String::new()
    }
}

/// Policy-routing rule. `kind`/`pattern`/`target` existed as a v0.1
/// placeholder, so they remain strings for safe state migration. New UI uses
/// `domains`/`ips`/`services`; `target` is one of: `direct`, `active`,
/// `best`, `reject`, or `server:<ref>`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    /// v0.5: Port specifications for port-based routing (e.g. "80", "443", "1000-2000").
    #[serde(default)]
    pub ports: Vec<String>,
    /// v0.5: Network type filter: "tcp", "udp", or empty for both.
    #[serde(default)]
    pub network: String,
    /// v0.16: Port matching mode.
    /// `"include"` (default) — rule applies only to listed ports.
    /// `"exclude"` — rule applies to all ports except listed ones.
    #[serde(default = "default_rule_port_mode")]
    pub port_mode: String,
}

fn default_routing_target() -> String {
    "active".to_owned()
}

const MAX_PINNED_SERVERS: usize = 16;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct ServerRouteRegistryEntry {
    server_ref: String,
    canonical_raw: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RoutingTarget {
    Direct,
    Active,
    Reject,
    Parovozik,
    Server(String),
    LegacyProfile(usize),
}

impl RoutingTarget {
    fn parse(value: &str) -> Result<Self, String> {
        let value = value.trim();
        match value {
            "" | "active" | "best" => Ok(Self::Active),
            "direct" => Ok(Self::Direct),
            "reject" => Ok(Self::Reject),
            "parovozik" => Ok(Self::Parovozik),
            _ if value.starts_with("server:") => {
                let server_ref = &value[7..];
                if valid_routing_server_ref(server_ref) {
                    Ok(Self::Server(server_ref.to_owned()))
                } else {
                    Err(format!("malformed server target {value:?}"))
                }
            }
            _ if value.starts_with("profile:") => value[8..]
                .parse::<usize>()
                .map(Self::LegacyProfile)
                .map_err(|_| format!("malformed legacy profile target {value:?}")),
            _ => Err(format!("unsupported routing target {value:?}")),
        }
    }
}

fn valid_routing_server_ref(value: &str) -> bool {
    value.len() == 39
        && value.starts_with("srv-v1-")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_lifecycle_ref(value: &str) -> bool {
    value.len() == 39
        && (value.starts_with("srv-v1-") || value.starts_with("srv-v2-"))
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn canonical_profile_raw(profile: &Profile) -> String {
    canonical_profile_raw_from_raw(&profile.raw)
}

fn canonical_profile_raw_from_raw(raw: &str) -> String {
    let raw = raw.trim();
    let Some((scheme, payload)) = raw.split_once("://") else {
        return raw.split('#').next().unwrap_or(raw).to_owned();
    };
    if scheme.eq_ignore_ascii_case("vmess") {
        use base64::Engine as _;
        let encoded = payload.split('#').next().unwrap_or(payload);
        for engine in [
            &base64::engine::general_purpose::STANDARD,
            &base64::engine::general_purpose::URL_SAFE,
            &base64::engine::general_purpose::STANDARD_NO_PAD,
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        ] {
            if let Ok(bytes) = engine.decode(encoded)
                && let Ok(mut value) = serde_json::from_slice::<Value>(&bytes)
            {
                if let Some(object) = value.as_object_mut() {
                    object.remove("ps");
                }
                if let Ok(canonical) = serde_json::to_string(&value) {
                    return format!("vmess-json:{canonical}");
                }
            }
        }
    }
    raw.split('#').next().unwrap_or(raw).to_owned()
}

fn canonical_lifecycle_identity(profile: &Profile) -> String {
    canonical_lifecycle_identity_from_raw(&profile.raw)
}

fn canonical_lifecycle_identity_from_raw(raw: &str) -> String {
    let legacy_canonical = canonical_profile_raw_from_raw(raw);
    if legacy_canonical.starts_with("vmess-json:") {
        return legacy_canonical;
    }
    let Ok(mut url) = url::Url::parse(raw.trim()) else {
        return legacy_canonical;
    };
    url.set_fragment(None);
    if let Some(url::Host::Domain(domain)) = url.host() {
        let normalized = domain.to_lowercase();
        if normalized != domain && url.set_host(Some(&normalized)).is_err() {
            return legacy_canonical;
        }
    }
    let mut query: Vec<(String, String)> = url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    query.sort_by(|left, right| left.0.cmp(&right.0));
    url.set_query(None);
    if !query.is_empty() {
        url.query_pairs_mut().extend_pairs(query);
    }
    url.to_string()
}

fn server_ref_for_canonical(canonical: &str) -> String {
    let digest = sha256(canonical.as_bytes());
    let mut hex = String::with_capacity(32);
    for byte in &digest[..16] {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    format!("srv-v1-{hex}")
}

fn lifecycle_ref_for_canonical(canonical: &str) -> String {
    let digest = sha256(canonical.as_bytes());
    let mut hex = String::with_capacity(32);
    for byte in &digest[..16] {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    format!("srv-v2-{hex}")
}

fn profile_server_ref(profile: &Profile) -> String {
    lifecycle_ref_for_canonical(&canonical_lifecycle_identity(profile))
}

fn migrate_lifecycle_ref(value: &str, profiles: &[Profile]) -> (String, bool) {
    if value.starts_with("srv-v2-") && valid_lifecycle_ref(value) {
        return (value.to_owned(), false);
    }
    if value.starts_with("srv-v1-") && valid_lifecycle_ref(value) {
        if let Some(profile) = profiles
            .iter()
            .find(|profile| server_ref_for_canonical(&canonical_profile_raw(profile)) == value)
        {
            return (profile_server_ref(profile), true);
        }
        return (value.to_owned(), false);
    }
    (
        lifecycle_ref_for_canonical(&canonical_lifecycle_identity_from_raw(value)),
        true,
    )
}

fn profile_is_dead(state: &HincyrayState, profile: &Profile) -> bool {
    state
        .dead_server_refs
        .contains(&profile_server_ref(profile))
}

fn migrate_legacy_dead_server_refs(state: &mut HincyrayState) -> bool {
    let legacy_refs = std::mem::take(&mut state.dead_server_refs);
    let legacy_promoted = std::mem::take(&mut state.dead_promoted_at);
    let original_refs = legacy_refs.clone();
    let original_promoted = legacy_promoted.clone();
    let mut changed = false;
    for value in legacy_refs {
        let (server_ref, migrated) = migrate_lifecycle_ref(&value, &state.profiles);
        changed |= migrated;
        state.dead_server_refs.insert(server_ref.clone());
        if let Some(promoted_at) = legacy_promoted.get(&value).copied() {
            state.dead_promoted_at.insert(server_ref, promoted_at);
        }
    }
    for (value, promoted_at) in legacy_promoted {
        let (server_ref, migrated) = migrate_lifecycle_ref(&value, &state.profiles);
        changed |= migrated;
        if state.dead_server_refs.contains(&server_ref) {
            state
                .dead_promoted_at
                .entry(server_ref)
                .or_insert(promoted_at);
        }
    }
    changed
        || state.dead_server_refs != original_refs
        || state.dead_promoted_at != original_promoted
}

fn migrate_legacy_deep_bench_filter_refs(state: &mut HincyrayState) -> bool {
    let profiles = state.profiles.clone();
    let ProfileFilter::Explicit(values) = &mut state.deep_bench.profile_filter else {
        return false;
    };
    let mut changed = false;
    let mut unique = HashSet::new();
    for value in std::mem::take(values) {
        let (server_ref, migrated) = migrate_lifecycle_ref(&value, &profiles);
        changed |= migrated;
        if !unique.insert(server_ref.clone()) {
            changed = true;
        }
    }
    *values = unique.into_iter().collect();
    changed
}

fn reconcile_active_dead_server_membership(state: &mut HincyrayState) -> bool {
    let Some(active_ref) = state
        .active_profile_id
        .and_then(|id| state.profiles.iter().find(|profile| profile.id == id))
        .map(profile_server_ref)
    else {
        return false;
    };
    let removed = state.dead_server_refs.remove(&active_ref);
    let removed_timestamp = state.dead_promoted_at.remove(&active_ref).is_some();
    removed || removed_timestamp
}

fn sync_server_route_registry(state: &mut HincyrayState) {
    for profile in &state.profiles {
        let canonical_raw = canonical_profile_raw(profile);
        if !state
            .server_route_registry
            .iter()
            .any(|entry| entry.canonical_raw == canonical_raw)
        {
            state.server_route_registry.push(ServerRouteRegistryEntry {
                server_ref: server_ref_for_canonical(&canonical_raw),
                canonical_raw,
            });
        }
    }
    let current: HashSet<String> = state.profiles.iter().map(canonical_profile_raw).collect();
    let referenced: HashSet<String> = state
        .routing_rules
        .iter()
        .map(|rule| rule.target.as_str())
        .chain(
            state
                .device_routes
                .iter()
                .map(|route| route.target.as_str()),
        )
        .filter_map(|target| match RoutingTarget::parse(target).ok()? {
            RoutingTarget::Server(server_ref) => Some(server_ref),
            _ => None,
        })
        .chain(state.split_routing.parovozik_server_refs.iter().cloned())
        .collect();
    state.server_route_registry.retain(|entry| {
        current.contains(&entry.canonical_raw) || referenced.contains(&entry.server_ref)
    });
}

fn sha256(input: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let bit_len = (input.len() as u64) * 8;
    let mut data = input.to_vec();
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bit_len.to_be_bytes());
    let mut h = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    for chunk in data.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(word);
            w[i] = u32::from_be_bytes(bytes);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, value) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *slot = slot.wrapping_add(value);
        }
    }
    let mut out = [0u8; 32];
    for (chunk, value) in out.chunks_exact_mut(4).zip(h) {
        chunk.copy_from_slice(&value.to_be_bytes());
    }
    out
}

fn default_rule_port_mode() -> String {
    "include".to_owned()
}

fn unsafe_router_geosite_ref(value: &str) -> Option<&'static str> {
    let low = value.trim().to_ascii_lowercase();
    let name = low.strip_prefix("geosite:").unwrap_or(&low);
    match name {
        "category-ads-all" => Some(
            "geosite:category-ads-all exhausts memory on Keenetic/Mihomo during matcher construction",
        ),
        _ => None,
    }
}

fn validate_router_routing_rules(rules: &[RoutingRule]) -> Result<(), String> {
    for rule in rules.iter().filter(|rule| rule.enabled) {
        for item in rule.domains.iter().chain(rule.services.iter()) {
            if let Some(reason) = unsafe_router_geosite_ref(item) {
                return Err(format!("routing rule '{}' is unsafe: {reason}", rule.name));
            }
        }
        if let Some(reason) = unsafe_router_geosite_ref(&rule.pattern) {
            return Err(format!("routing rule '{}' is unsafe: {reason}", rule.name));
        }
    }
    Ok(())
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

fn default_mihomo_path() -> String {
    "mihomo".to_owned()
}

fn benchmark_mihomo_path(configured: &str) -> String {
    if configured.trim().is_empty() {
        default_mihomo_path()
    } else {
        configured.to_owned()
    }
}

fn default_auto_update_interval_hours() -> u32 {
    24
}

impl Daemon {
    fn new(state: HincyrayState, state_path: PathBuf, mihomo_config_path: PathBuf) -> Self {
        let geobase_store_root = state_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("geobases");
        let geobase_store = GeoBaseStore::new(&geobase_store_root);
        Self {
            inner: Arc::new(Mutex::new(DaemonInner {
                state,
                core: CoreManager::new(),
                firewall: FirewallManager::new(),
                bench: BenchRuntime::new(),
                dirty: false,
                failover_fail_count: 0,
                prev_cpu: None,
                prev_cpu_per_core: Vec::new(),
                sessions: HashMap::new(),
                login_limiter: LoginLimiter::default(),
                telegram_login: None,
                deep_bench_cancel: None,
                deep_bench_handle: None,
                deep_bench_active: false,
                deep_bench_status: DeepBenchStatus::default(),
                geobase: GeoBaseRuntime::default(),
                pinned_route_now: HashMap::new(),
            })),
            apply: Arc::new(Mutex::new(())),
            password_work: Arc::new(PasswordWorkLimiter::new(MAX_CONCURRENT_PASSWORD_OPS)),
            state_path,
            mihomo_config_path,
            geobase_store_root,
            geobase_store,
        }
    }

    fn geobase_store(&self) -> &GeoBaseStore {
        &self.geobase_store
    }
}

/// Proxy core lifecycle (Mihomo). Holds at most one child in memory;
/// restart stops and starts in sequence. Mihomo handles all supported
/// protocols in a single binary, replacing the previous dual-engine
/// approach.
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

    fn pid(&mut self) -> Option<u32> {
        if self.is_running() {
            self.child.as_ref().map(Child::id)
        } else {
            None
        }
    }

    fn start(
        &mut self,
        binary_path: &str,
        config_path: &Path,
        geo_dir: Option<&str>,
    ) -> Result<(), String> {
        if self.is_running() {
            return Ok(());
        }
        if !config_path.exists() {
            return Err(format!(
                "mihomo config not found at {}",
                config_path.display()
            ));
        }
        let stderr = open_log_file("mihomo.log").unwrap_or(Stdio::null());

        let mut cmd = Command::new(binary_path);
        cmd.arg("-f").arg(config_path);
        if let Some(dir) = geo_dir.filter(|d| !d.is_empty()) {
            cmd.arg("-d").arg(dir);
        }
        // Redirect both stdout and stderr to the log file — Mihomo
        // writes log messages to stdout (not stderr), so sending
        // stdout to /dev/null hides all diagnostic output and may
        // interfere with the process's initialisation.
        let stdout = open_log_file("mihomo.log").unwrap_or(Stdio::null());
        cmd.stdout(stdout).stderr(stderr);
        let child = cmd
            .spawn()
            .map_err(|error| format!("mihomo spawn: {error}"))?;
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

    fn restart(
        &mut self,
        binary_path: &str,
        config_path: &Path,
        geo_dir: Option<&str>,
    ) -> Result<(), String> {
        self.stop()?;
        self.start(binary_path, config_path, geo_dir)
    }
}

/// Firewall lifecycle manager. Installs iptables NAT REDIRECT (TCP) +
/// mangle TPROXY (UDP) rules for transparent proxying of devices
/// assigned to the Keenetic "HincyRay" traffic policy. Survives ndm
/// firewall reloads via an ndm hook script in
/// `/opt/etc/ndm/netfilter.d/`. No tun2socks, no TUN device, no
/// userspace TCP stack — kernel iptables + Mihomo redirect/tproxy only.
struct FirewallManager {
    active: bool,
    tproxy_available: bool,
    policy_mark: Option<String>,
    redirect_port: Option<u16>,
    vpn_subnet: Option<String>,
    policy_name: Option<String>,
}

impl FirewallManager {
    fn new() -> Self {
        Self {
            active: false,
            tproxy_available: false,
            policy_mark: None,
            redirect_port: None,
            vpn_subnet: None,
            policy_name: None,
        }
    }

    fn is_running(&self) -> bool {
        self.active
    }

    fn status(&self) -> &'static str {
        if self.active { "running" } else { "stopped" }
    }

    fn start(
        &mut self,
        redirect_port: u16,
        vpn_subnet: &str,
        policy_name: &str,
        cached_mark: Option<&str>,
    ) -> Result<(), String> {
        if self.active {
            return Ok(());
        }

        // 1. Load kernel modules required by the transparent firewall path.
        // Keenetic 4.9 does not reliably auto-load x_tables extensions when
        // an iptables rule first references them. Capability detection must
        // therefore make the receiving side (kernel/iptables) ready before it
        // asks whether the TPROXY contract is supported.
        load_kernel_module("xt_comment");
        load_kernel_module("xt_TPROXY");
        load_kernel_module("xt_socket");

        // 2. Detect TPROXY capability after module loading.
        self.tproxy_available = detect_tproxy();
        if !self.tproxy_available {
            eprintln!(
                "hincyray: TPROXY unavailable, using TCP-only REDIRECT (UDP will be blocked)"
            );
        }

        // 3. Query or create Keenetic policy and get connmark.
        let mark = if let Some(m) = cached_mark.filter(|m| !m.is_empty()) {
            m.to_owned()
        } else {
            match query_policy_mark(policy_name) {
                Some(m) => m,
                None => {
                    // Try to create the policy via RCI.
                    match create_policy(policy_name) {
                        Ok(()) => {
                            // Re-query after creation.
                            query_policy_mark(policy_name)
                                .ok_or_else(|| format!(
                                    "Keenetic policy '{policy_name}' not found and auto-creation failed. \
                                     Create a traffic policy named '{policy_name}' in the Keenetic Web UI \
                                     and assign devices to it."
                                ))?
                        }
                        Err(e) => {
                            return Err(format!(
                                "Keenetic policy '{policy_name}' not found. \
                                 Auto-create failed: {e}. \
                                 Create it manually in the Keenetic Web UI."
                            ));
                        }
                    }
                }
            }
        };
        // Ensure 0x prefix for iptables.
        let mark = if mark.starts_with("0x") || mark.starts_with("0X") {
            mark
        } else {
            format!("0x{mark}")
        };
        self.policy_mark = Some(mark.clone());

        // 4. Install iptables rules.
        install_firewall_rules(&mark, redirect_port, vpn_subnet, self.tproxy_available)?;

        // 5. Install TPROXY policy routing (ip rule + ip route).
        if self.tproxy_available {
            install_tproxy_route();
        }

        // 6. Generate and install ndm hook script.
        install_ndm_hook(&mark, redirect_port, vpn_subnet, self.tproxy_available);

        // 7. Create ready marker.
        let _ = fs::write("/tmp/hincyray_ready", b"1");

        self.active = true;
        self.redirect_port = Some(redirect_port);
        self.vpn_subnet = Some(vpn_subnet.to_owned());
        self.policy_name = Some(policy_name.to_owned());
        eprintln!(
            "hincyray: firewall started (mark={mark}, tproxy={}, port={redirect_port})",
            self.tproxy_available
        );
        Ok(())
    }

    fn stop(&mut self, _vpn_subnet: &str) -> Result<(), String> {
        // Remove ready marker first so ndm hook becomes a no-op.
        let _ = fs::remove_file("/tmp/hincyray_ready");

        // Truncate ndm hook script so ndm stops re-applying rules.
        let _ = fs::write("/opt/etc/ndm/netfilter.d/hincyray.sh", b"");

        // Remove all iptables rules tagged "hincyray".
        remove_firewall_rules(self.tproxy_available);

        // Remove TPROXY policy routing.
        if self.tproxy_available {
            remove_tproxy_route();
        }

        self.active = false;
        self.policy_mark = None;
        self.redirect_port = None;
        self.vpn_subnet = None;
        self.policy_name = None;
        eprintln!("hincyray: firewall stopped, iptables rules cleaned");
        Ok(())
    }
}

/// Load a kernel module by name. Tries `/lib/modules/$(uname -r)/<name>.ko`
/// then `/opt/lib/modules/<name>.ko` via `insmod`. Returns true if the module
/// is visible in `/proc/modules` after the attempt. Built-in kernel support is
/// still accepted later by `detect_tproxy()` even when no module row appears.
fn load_kernel_module(name: &str) -> bool {
    if kernel_module_loaded(name) {
        return true;
    }
    let module_path = format!("/lib/modules/{}/{}.ko", unsafe_kernver(), name);
    let alt_path = format!("/opt/lib/modules/{}.ko", name);
    for path in [&module_path, &alt_path] {
        if !Path::new(path).exists() {
            continue;
        }
        match Command::new("insmod").arg(path).output() {
            Ok(output) if output.status.success() || kernel_module_loaded(name) => return true,
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.trim().is_empty() {
                    eprintln!("hincyray: insmod {path} failed: {}", stderr.trim());
                }
            }
            Err(e) => eprintln!("hincyray: cannot run insmod {path}: {e}"),
        }
    }
    kernel_module_loaded(name)
}

fn kernel_module_loaded(name: &str) -> bool {
    fs::read_to_string("/proc/modules")
        .map(|modules| {
            modules
                .lines()
                .any(|line| line.split_whitespace().next() == Some(name))
        })
        .unwrap_or(false)
}

/// Get the kernel version string for module path construction.
/// Uses `uname -r` which returns e.g. "4.9-ndm-5".
fn unsafe_kernver() -> String {
    Command::new("uname")
        .arg("-r")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_else(|_| "4.9-ndm-5".to_owned())
}

/// Detect whether the kernel supports TPROXY by trying to create a
/// test TPROXY rule. Returns true if both `xt_TPROXY` and `xt_socket`
/// modules are loaded and the iptables target/match work.
fn detect_tproxy() -> bool {
    cleanup_tproxy_test_chain();

    // Try creating a TPROXY rule in a test chain.
    let ok = iptables_ok(
        &["-t", "mangle", "-N", "HINCYRAY_TEST_TP"],
        "create TPROXY test chain",
    );
    if !ok {
        return false;
    }
    let tproxy_ok = iptables_ok(
        &[
            "-t",
            "mangle",
            "-A",
            "HINCYRAY_TEST_TP",
            "-p",
            "udp",
            "-j",
            "TPROXY",
            "--on-ip",
            "127.0.0.1",
            "--on-port",
            "10810",
            "--tproxy-mark",
            "0x111",
        ],
        "append TPROXY target test rule",
    );
    let socket_ok = iptables_ok(
        &[
            "-t",
            "mangle",
            "-A",
            "HINCYRAY_TEST_TP",
            "-p",
            "udp",
            "-m",
            "socket",
            "--transparent",
            "-j",
            "MARK",
            "--set-mark",
            "0x111",
        ],
        "append socket transparent match test rule",
    );
    // Cleanup test chain.
    cleanup_tproxy_test_chain();
    tproxy_ok && socket_ok
}

fn cleanup_tproxy_test_chain() {
    let _ = Command::new("iptables")
        .args(["-t", "mangle", "-F", "HINCYRAY_TEST_TP"])
        .status();
    let _ = Command::new("iptables")
        .args(["-t", "mangle", "-X", "HINCYRAY_TEST_TP"])
        .status();
}

fn iptables_ok(args: &[&str], context: &str) -> bool {
    match Command::new("iptables").args(args).output() {
        Ok(output) if output.status.success() => true,
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("hincyray: iptables {context} failed: {}", stderr.trim());
            false
        }
        Err(e) => {
            eprintln!("hincyray: cannot run iptables for {context}: {e}");
            false
        }
    }
}

/// Query the Keenetic RCI API for a traffic policy's connmark.
/// Returns the mark as a hex string (e.g. "0xffffaaa") or None.
fn query_policy_mark(policy_name: &str) -> Option<String> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "curl -s --max-time 5 localhost:79/rci/show/ip/policy 2>/dev/null | \
             jq -r --arg name '{}' \
             '.[] | select(.description | ascii_downcase == ($name | ascii_downcase)) | .mark' \
             2>/dev/null",
            policy_name
        ))
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if text.is_empty() || text == "null" {
        None
    } else {
        Some(text)
    }
}

/// Create a Keenetic traffic policy via the RCI API.
fn create_policy(policy_name: &str) -> Result<(), String> {
    let body = format!(r#"{{"description":"{}"}}"#, policy_name);
    let output = Command::new("curl")
        .args([
            "-s",
            "--max-time",
            "5",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            &body,
            "localhost:79/rci/add/ip/policy",
        ])
        .output()
        .map_err(|e| format!("curl: {e}"))?;
    let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    // RCI typically returns the created object or an error.
    if text.contains("error") || text.is_empty() {
        Err(format!("RCI add/ip/policy returned: {text}"))
    } else {
        Ok(())
    }
}

/// Install all iptables rules for transparent proxying.
/// Uses comment tag "hincyray" for cleanup and idempotency.
fn install_firewall_rules(
    mark: &str,
    redirect_port: u16,
    _vpn_subnet: &str,
    tproxy_available: bool,
) -> Result<(), String> {
    let port_str = redirect_port.to_string();
    // TPROXY listener is on redirect_port + 1 (see mihomo_config.rs
    // for the rationale — redir and tproxy cannot share the same
    // TCP port).
    let tproxy_port_str = (redirect_port + 1).to_string();
    let comment = "-m comment --comment hincyray";

    // ── nat table: TCP REDIRECT ──
    // Create + flush custom chain.
    let _ = Command::new("iptables")
        .args(["-t", "nat", "-N", "HINCYRAY"])
        .status();
    let _ = Command::new("iptables")
        .args(["-t", "nat", "-F", "HINCYRAY"])
        .status();

    // Bypass rules: don't re-intercept DNAT'd traffic (port forwards),
    // bypass local networks, link-local traffic, and broadcasts.
    let _ = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "iptables -t nat -A HINCYRAY -m conntrack --ctstate DNAT {comment} -j RETURN"
        ))
        .status();
    append_firewall_bypass_rules("nat", "HINCYRAY");

    // REDIRECT TCP to the dokodemo-door port.
    let _ = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-A",
            "HINCYRAY",
            "-p",
            "tcp",
            "-m",
            "comment",
            "--comment",
            "hincyray",
            "-j",
            "REDIRECT",
            "--to-ports",
            &port_str,
        ])
        .status();

    // Jump from PREROUTING (match by policy connmark).
    // Remove old jump first (idempotent), then add.
    let _ = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-D",
            "PREROUTING",
            "-m",
            "connmark",
            "--mark",
            mark,
            "-p",
            "tcp",
            "-m",
            "comment",
            "--comment",
            "hincyray",
            "-j",
            "HINCYRAY",
        ])
        .status();
    let _ = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-A",
            "PREROUTING",
            "-m",
            "connmark",
            "--mark",
            mark,
            "-p",
            "tcp",
            "-m",
            "comment",
            "--comment",
            "hincyray",
            "-j",
            "HINCYRAY",
        ])
        .status();

    // ── nat table: DNS DNAT (connmark-matched) ──
    // Redirect DNS queries from policy-marked devices to Mihomo's
    // DNS inbound (127.0.0.1:1053).
    let dns_dst = DNS_REDIRECT;
    // Remove old rules first (idempotent).
    let _ = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-D",
            "PREROUTING",
            "-m",
            "connmark",
            "--mark",
            mark,
            "-p",
            "udp",
            "--dport",
            "53",
            "-m",
            "comment",
            "--comment",
            "hincyray",
            "-j",
            "DNAT",
            "--to-destination",
            dns_dst,
        ])
        .status();
    let _ = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-D",
            "PREROUTING",
            "-m",
            "connmark",
            "--mark",
            mark,
            "-p",
            "tcp",
            "--dport",
            "53",
            "-m",
            "comment",
            "--comment",
            "hincyray",
            "-j",
            "DNAT",
            "--to-destination",
            dns_dst,
        ])
        .status();
    // Insert at positions 1 and 2 (before Keenetic's own chains).
    let _ = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-I",
            "PREROUTING",
            "1",
            "-m",
            "connmark",
            "--mark",
            mark,
            "-p",
            "udp",
            "--dport",
            "53",
            "-m",
            "comment",
            "--comment",
            "hincyray",
            "-j",
            "DNAT",
            "--to-destination",
            dns_dst,
        ])
        .status();
    let _ = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-I",
            "PREROUTING",
            "2",
            "-m",
            "connmark",
            "--mark",
            mark,
            "-p",
            "tcp",
            "--dport",
            "53",
            "-m",
            "comment",
            "--comment",
            "hincyray",
            "-j",
            "DNAT",
            "--to-destination",
            dns_dst,
        ])
        .status();

    // ── mangle table: UDP TPROXY (only if available) ──
    if tproxy_available {
        let _ = Command::new("iptables")
            .args(["-t", "mangle", "-N", "HINCYRAY_UDP"])
            .status();
        let _ = Command::new("iptables")
            .args(["-t", "mangle", "-F", "HINCYRAY_UDP"])
            .status();

        let _ = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "iptables -t mangle -A HINCYRAY_UDP -m conntrack --ctstate DNAT {comment} -j RETURN"
            ))
            .status();
        append_firewall_bypass_rules("mangle", "HINCYRAY_UDP");

        // TPROXY: first mark packets with an existing transparent socket,
        // then TPROXY new packets.
        let _ = Command::new("iptables")
            .args([
                "-t",
                "mangle",
                "-A",
                "HINCYRAY_UDP",
                "-p",
                "udp",
                "-m",
                "socket",
                "--transparent",
                "-m",
                "comment",
                "--comment",
                "hincyray",
                "-j",
                "MARK",
                "--set-mark",
                "0x111",
            ])
            .status();
        let _ = Command::new("iptables")
            .args([
                "-t",
                "mangle",
                "-A",
                "HINCYRAY_UDP",
                "-p",
                "udp",
                "-m",
                "comment",
                "--comment",
                "hincyray",
                "-j",
                "TPROXY",
                "--on-ip",
                "127.0.0.1",
                "--on-port",
                &tproxy_port_str,
                "--tproxy-mark",
                "0x111",
            ])
            .status();

        // Jump from PREROUTING (match by policy connmark).
        let _ = Command::new("iptables")
            .args([
                "-t",
                "mangle",
                "-D",
                "PREROUTING",
                "-m",
                "connmark",
                "--mark",
                mark,
                "-p",
                "udp",
                "-m",
                "comment",
                "--comment",
                "hincyray",
                "-j",
                "HINCYRAY_UDP",
            ])
            .status();
        let _ = Command::new("iptables")
            .args([
                "-t",
                "mangle",
                "-A",
                "PREROUTING",
                "-m",
                "connmark",
                "--mark",
                mark,
                "-p",
                "udp",
                "-m",
                "comment",
                "--comment",
                "hincyray",
                "-j",
                "HINCYRAY_UDP",
            ])
            .status();
    }

    // Suppress unused warning for _vpn_subnet (kept for future
    // source-based fallback if connmark is unavailable).

    Ok(())
}

const FIREWALL_BYPASS_CIDRS: &[&str] = &[
    "10.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
];

fn append_firewall_bypass_rules(table: &str, chain: &str) {
    for cidr in FIREWALL_BYPASS_CIDRS {
        let _ = Command::new("iptables")
            .args([
                "-t",
                table,
                "-A",
                chain,
                "-d",
                cidr,
                "-m",
                "comment",
                "--comment",
                "hincyray",
                "-j",
                "RETURN",
            ])
            .status();
    }
}

/// Remove all iptables rules tagged "hincyray".
fn remove_firewall_rules(tproxy_available: bool) {
    // Remove DNS DNAT rules from nat PREROUTING.
    // We don't know the exact mark here, so use a broader match:
    // delete all rules with comment "hincyray" that have DNAT.
    let _ = Command::new("sh")
        .arg("-c")
        .arg(
            "iptables -t nat -S PREROUTING 2>/dev/null | grep 'hincyray' | grep 'DNAT' | \
         while read -r line; do \
           iptables -t nat -D PREROUTING ${line#-A PREROUTING } 2>/dev/null; \
         done",
        )
        .status();

    // Remove nat PREROUTING jump rules tagged "hincyray".
    let _ = Command::new("sh")
        .arg("-c")
        .arg(
            "iptables -t nat -S PREROUTING 2>/dev/null | grep 'hincyray' | grep 'HINCYRAY' | \
         while read -r line; do \
           iptables -t nat -D PREROUTING ${line#-A PREROUTING } 2>/dev/null; \
         done",
        )
        .status();

    // Flush + delete nat chain.
    let _ = Command::new("iptables")
        .args(["-t", "nat", "-F", "HINCYRAY"])
        .status();
    let _ = Command::new("iptables")
        .args(["-t", "nat", "-X", "HINCYRAY"])
        .status();

    if tproxy_available {
        // Remove mangle PREROUTING jump rules.
        let _ = Command::new("sh").arg("-c").arg(
            "iptables -t mangle -S PREROUTING 2>/dev/null | grep 'hincyray' | grep 'HINCYRAY_UDP' | \
             while read -r line; do \
               iptables -t mangle -D PREROUTING ${line#-A PREROUTING } 2>/dev/null; \
             done"
        ).status();

        // Flush + delete mangle chain.
        let _ = Command::new("iptables")
            .args(["-t", "mangle", "-F", "HINCYRAY_UDP"])
            .status();
        let _ = Command::new("iptables")
            .args(["-t", "mangle", "-X", "HINCYRAY_UDP"])
            .status();
    }
}

/// Install ip rule + ip route for TPROXY (fwmark 0x111 → table 111 →
/// local default dev lo).
fn install_tproxy_route() {
    let ip_cmd = resolve_ip_cmd();
    let _ = Command::new(&ip_cmd)
        .args(["rule", "del", "fwmark", "0x111", "lookup", "111"])
        .status();
    let _ = Command::new(&ip_cmd)
        .args(["rule", "add", "fwmark", "0x111", "lookup", "111"])
        .status();
    let _ = Command::new(&ip_cmd)
        .args(["route", "flush", "table", "111"])
        .status();
    let _ = Command::new(&ip_cmd)
        .args([
            "route", "add", "local", "default", "dev", "lo", "table", "111",
        ])
        .status();
}

/// Remove TPROXY policy routing.
fn remove_tproxy_route() {
    let ip_cmd = resolve_ip_cmd();
    let _ = Command::new(&ip_cmd)
        .args(["rule", "del", "fwmark", "0x111", "lookup", "111"])
        .status();
    let _ = Command::new(&ip_cmd)
        .args(["route", "flush", "table", "111"])
        .status();
}

/// Generate the ndm hook script content. This script is called by
/// Keenetic's ndm daemon after every firewall reload, reinstalling
/// our iptables rules atomically.
fn generate_ndm_hook_script(
    mark: &str,
    redirect_port: u16,
    _vpn_subnet: &str,
    tproxy_available: bool,
) -> String {
    let port_str = redirect_port.to_string();
    let tproxy_port_str = (redirect_port + 1).to_string();
    let nat_bypass = firewall_bypass_script("nat", "HINCYRAY");
    let udp_bypass = firewall_bypass_script("mangle", "HINCYRAY_UDP");
    let tproxy_section = if tproxy_available {
        format!(
            r##"# ── mangle table: UDP TPROXY ──
insmod /lib/modules/$(uname -r)/xt_TPROXY.ko 2>/dev/null
insmod /lib/modules/$(uname -r)/xt_socket.ko 2>/dev/null
iptables -t mangle -N HINCYRAY_UDP 2>/dev/null
iptables -t mangle -F HINCYRAY_UDP
iptables -t mangle -A HINCYRAY_UDP -m conntrack --ctstate DNAT -m comment --comment hincyray -j RETURN
{udp_bypass}
iptables -t mangle -A HINCYRAY_UDP -p udp -m socket --transparent -m comment --comment hincyray -j MARK --set-mark 0x111
iptables -t mangle -A HINCYRAY_UDP -p udp -m comment --comment hincyray -j TPROXY --on-ip 127.0.0.1 --on-port {tproxy_port} --tproxy-mark 0x111
iptables -t mangle -D PREROUTING -m connmark --mark {mark} -p udp -m comment --comment hincyray -j HINCYRAY_UDP 2>/dev/null
iptables -t mangle -A PREROUTING -m connmark --mark {mark} -p udp -m comment --comment hincyray -j HINCYRAY_UDP

# ── TPROXY policy routing ──
ip rule del fwmark 0x111 lookup 111 2>/dev/null
ip rule add fwmark 0x111 lookup 111 2>/dev/null
ip route flush table 111 2>/dev/null
ip route add local default dev lo table 111 2>/dev/null
"##,
            tproxy_port = tproxy_port_str,
            mark = mark,
            udp_bypass = udp_bypass,
        )
    } else {
        String::new()
    };

    format!(
        r##"#!/bin/sh
# HincyRay: Auto-generated ndm netfilter hook. DO NOT EDIT!
# Called by Keenetic ndm after every firewall reload.
[ -f /tmp/hincyray_ready ] || exit 0

# Load xt_comment module (not auto-loaded on Keenetic 4.9).
insmod /lib/modules/$(uname -r)/xt_comment.ko 2>/dev/null

MARK="{mark}"
PORT="{port}"
DNS_DST="127.0.0.1:1053"

# ── nat table: TCP REDIRECT ──
iptables -t nat -N HINCYRAY 2>/dev/null
iptables -t nat -F HINCYRAY
iptables -t nat -A HINCYRAY -m conntrack --ctstate DNAT -m comment --comment hincyray -j RETURN
{nat_bypass}
iptables -t nat -A HINCYRAY -p tcp -m comment --comment hincyray -j REDIRECT --to-ports $PORT
iptables -t nat -D PREROUTING -m connmark --mark $MARK -p tcp -m comment --comment hincyray -j HINCYRAY 2>/dev/null
iptables -t nat -A PREROUTING -m connmark --mark $MARK -p tcp -m comment --comment hincyray -j HINCYRAY

# ── nat table: DNS DNAT (connmark-matched) ──
iptables -t nat -D PREROUTING -m connmark --mark $MARK -p udp --dport 53 -m comment --comment hincyray -j DNAT --to-destination $DNS_DST 2>/dev/null
iptables -t nat -D PREROUTING -m connmark --mark $MARK -p tcp --dport 53 -m comment --comment hincyray -j DNAT --to-destination $DNS_DST 2>/dev/null
iptables -t nat -I PREROUTING 1 -m connmark --mark $MARK -p udp --dport 53 -m comment --comment hincyray -j DNAT --to-destination $DNS_DST
iptables -t nat -I PREROUTING 2 -m connmark --mark $MARK -p tcp --dport 53 -m comment --comment hincyray -j DNAT --to-destination $DNS_DST

{tproxy}
"##,
        mark = mark,
        port = port_str,
        nat_bypass = nat_bypass,
        tproxy = tproxy_section,
    )
}

fn firewall_bypass_script(table: &str, chain: &str) -> String {
    FIREWALL_BYPASS_CIDRS
        .iter()
        .map(|cidr| {
            format!(
                "iptables -t {table} -A {chain} -d {cidr} -m comment --comment hincyray -j RETURN"
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Write the ndm hook script to `/opt/etc/ndm/netfilter.d/hincyray.sh`
/// and make it executable.
fn install_ndm_hook(mark: &str, redirect_port: u16, vpn_subnet: &str, tproxy_available: bool) {
    let script = generate_ndm_hook_script(mark, redirect_port, vpn_subnet, tproxy_available);
    let hook_dir = "/opt/etc/ndm/netfilter.d";
    let _ = fs::create_dir_all(hook_dir);
    let hook_path = format!("{hook_dir}/hincyray.sh");
    let _ = fs::write(&hook_path, &script);
    let _ = Command::new("chmod").arg("+x").arg(&hook_path).status();
    // Run it immediately to apply rules now.
    let _ = Command::new("sh").arg(&hook_path).status();
}

/// Check whether firewall rules are currently installed.
fn firewall_rules_exist(tproxy_available: bool) -> bool {
    let nat_ok =
        shell_status("iptables -t nat -S PREROUTING 2>/dev/null | grep -q 'hincyray.*HINCYRAY'");
    let dns_ok =
        shell_status("iptables -t nat -S PREROUTING 2>/dev/null | grep -q 'hincyray.*DNAT'");
    let tproxy_ok = if tproxy_available {
        shell_status(
            "iptables -t mangle -S PREROUTING 2>/dev/null | grep -q 'hincyray.*HINCYRAY_UDP'",
        )
    } else {
        true
    };
    nat_ok && dns_ok && tproxy_ok
}

/// Resolve the bridge interface name for the VPN subnet by querying
/// `ip -o addr show`. Falls back to `br1` if the command fails or no
/// match is found (Keenetic default for 192.168.2.0/24).
#[allow(dead_code)]
fn resolve_vpn_bridge(vpn_subnet: &str) -> String {
    let prefix = vpn_subnet
        .rsplit_once('.')
        .map(|(base, _)| base)
        .unwrap_or(vpn_subnet);
    let output = Command::new("sh")
        .arg("-c")
        .arg("ip -o addr show 2>/dev/null")
        .output();
    if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            // e.g. "17: br1    inet 192.168.2.1/24 ..."
            if line.contains(prefix)
                && line.contains("inet ")
                && let Some(iface) = line.split_whitespace().nth(1)
                && (iface.starts_with("br") || iface.starts_with("wlan"))
            {
                return iface.to_owned();
            }
        }
    }
    "br1".to_owned()
}

#[allow(dead_code)]
const FWMARK_TABLE: u32 = 111;
#[allow(dead_code)]
const TPROXY_FWMARK: u32 = 0x111;
const DNS_REDIRECT: &str = "127.0.0.1:1053";

fn resolve_ip_cmd() -> String {
    for candidate in ["/opt/sbin/ip", "/sbin/ip", "/usr/sbin/ip", "ip"] {
        if Path::new(candidate).exists() || candidate == "ip" {
            return candidate.to_owned();
        }
    }
    "ip".to_owned()
}

/// Resolve the log directory for daemon and child process logs.
fn resolve_log_dir() -> PathBuf {
    if Path::new("/opt/var/log").is_dir() {
        return PathBuf::from("/opt/var/log/hincyray");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".local/share/hincyray/logs");
    }
    PathBuf::from("./hincyray-logs")
}

/// Open a log file in the daemon log directory, rotating if the existing
/// file exceeds 1 MB. A new inode gives incremental readers an unambiguous
/// generation boundary.
fn open_log_file(name: &str) -> Result<Stdio, String> {
    let dir = resolve_log_dir();
    fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    let path = dir.join(name);
    // Rotate if the file is too large (> 1 MB).
    if let Ok(meta) = fs::metadata(&path)
        && meta.len() > 1_048_576
    {
        let rotated = path.with_extension("log.1");
        let _ = fs::remove_file(&rotated);
        fs::rename(&path, &rotated).map_err(|e| format!("rotate {}: {e}", path.display()))?;
    }
    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    Ok(Stdio::from(file))
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

fn resolve_mihomo_config_path(state_path: &Path) -> PathBuf {
    if let Some(path) = std::env::var_os("HINCYRAY_MIHOMO_CONFIG") {
        return PathBuf::from(path);
    }
    state_path.with_file_name("mihomo-config.yaml")
}

fn telegram_config_path(state_path: &Path) -> PathBuf {
    state_path.with_file_name("telegram-probe.json")
}

fn telegram_session_path(state_path: &Path) -> PathBuf {
    state_path.with_file_name("telegram.session")
}

fn load_state(state_path: &Path) -> HincyrayState {
    load_state_with_hasher(state_path, hash_password)
}

fn load_state_with_hasher(
    state_path: &Path,
    hash: impl FnOnce(&str) -> Result<String, String>,
) -> HincyrayState {
    let Ok(text) = fs::read_to_string(state_path) else {
        return HincyrayState::default();
    };
    let (mut state, auth_migration) = match deserialize_persisted_state_with_hasher(&text, hash) {
        Ok(result) => result,
        Err(error) => {
            eprintln!(
                "hincyray: state file {} is corrupted ({}), backing up and starting fresh",
                state_path.display(),
                error
            );
            let backup = state_path.with_extension("json.corrupt");
            let _ = fs::write(&backup, &text);
            eprintln!("hincyray: corrupted state saved to {}", backup.display());
            (HincyrayState::default(), AuthMigration::Unchanged)
        }
    };
    // The transparent proxy requires DNS — force enabled when split
    // routing is on so the state matches the firewall DNAT rules.
    if state.split_routing.enabled {
        state.dns_settings.enabled = true;
    }

    // Migrate legacy numeric benchmark fields to explicit presence flags.
    // A historical zero speed is ambiguous because speed-stage errors were
    // previously erased to 0.0, so only positive speed values prove that a
    // measurement actually completed.
    for stat in &mut state.stats {
        if stat.success_count > 0 {
            stat.has_latency = true;
            stat.has_jitter = true;
            stat.has_loss = true;
            stat.has_ewma = true;
        }
        stat.has_download |= stat.last_download_mbps > 0.0;
        stat.has_upload |= stat.last_upload_mbps > 0.0;
    }

    // v0.16 migration: match_target. Old state files don't have this
    // field (empty string). Preserve old MATCH behaviour:
    //   AllowList → MATCH,direct (only listed ports proxied)
    //   All/DenyList → MATCH,proxy (everything through VPN)
    if state.split_routing.match_target.is_empty() {
        state.split_routing.match_target = match &state.split_routing.port_mode {
            PortMode::AllowList if !state.split_routing.proxy_ports.is_empty() => {
                "direct".to_owned()
            }
            _ => "proxy".to_owned(),
        };
    }

    // v0.16 migration: QUIC block. Convert block_quic_global / quic_mode
    // into a regular routing rule so the user can see and edit it in the
    // rules table. Per-profile block_quic and !tproxy_available remain
    // system-level automatic rules in the config generator.
    let needs_quic_rule =
        state.split_routing.block_quic_global || state.split_routing.quic_mode == QuicMode::Block;
    let has_quic_rule = state.routing_rules.iter().any(|r| r.name == "QUIC Block");
    if needs_quic_rule && !has_quic_rule {
        state.routing_rules.insert(
            0,
            RoutingRule {
                enabled: true,
                name: "QUIC Block".to_owned(),
                kind: String::new(),
                pattern: String::new(),
                target: "reject".to_owned(),
                domains: Vec::new(),
                ips: Vec::new(),
                services: Vec::new(),
                ports: vec!["443".to_owned()],
                network: "udp".to_owned(),
                port_mode: "include".to_owned(),
            },
        );
    }

    let routing_identity_before = serde_json::to_string(&(
        &state.server_route_registry,
        &state.routing_rules,
        &state.device_routes,
    ))
    .unwrap_or_default();
    sync_server_route_registry(&mut state);
    for rule in &mut state.routing_rules {
        migrate_legacy_target(
            &state.profiles,
            &state.server_route_registry,
            &mut rule.target,
        );
    }
    for route in &mut state.device_routes {
        migrate_legacy_target(
            &state.profiles,
            &state.server_route_registry,
            &mut route.target,
        );
    }
    let routing_identity_changed = routing_identity_before
        != serde_json::to_string(&(
            &state.server_route_registry,
            &state.routing_rules,
            &state.device_routes,
        ))
        .unwrap_or_default();

    // The old generic-SOCKS probe obeyed routing rules and could cache a
    // false negative for 24h. Invalidate non-promoted timestamps exactly
    // once after switching to forced `proxy-active` EC probes.
    let dead_servers_changed = migrate_legacy_dead_server_refs(&mut state);
    let deep_bench_filter_changed = migrate_legacy_deep_bench_filter_refs(&mut state);
    let active_dead_membership_changed = reconcile_active_dead_server_membership(&mut state);
    let stale_profile_stats_changed = prune_stale_profile_stats(&mut state);
    let mut migration_changed = routing_identity_changed
        || auth_migration.changed()
        || dead_servers_changed
        || deep_bench_filter_changed
        || active_dead_membership_changed
        || stale_profile_stats_changed;
    if let AuthMigration::Disabled(error) = auth_migration {
        eprintln!("hincyray: failed to migrate Web UI password: {error}");
    }
    if state.split_routing.auto_vpn_probe_contract_version < AUTO_VPN_PROBE_CONTRACT_VERSION {
        let promoted: HashSet<String> = state
            .split_routing
            .auto_vpn_exceptions
            .iter()
            .filter_map(|domain| normalize_auto_vpn_domain(domain))
            .collect();
        state
            .split_routing
            .auto_vpn_last_checked_unix
            .retain(|domain, _| promoted.contains(domain));
        state.split_routing.auto_vpn_probe_contract_version = AUTO_VPN_PROBE_CONTRACT_VERSION;
        migration_changed = true;
    }
    if migration_changed && let Err(error) = persist_state(state_path, &state) {
        eprintln!("hincyray: failed to persist state migration: {error}");
    }

    state
}

fn migrate_legacy_target(
    profiles: &[Profile],
    registry: &[ServerRouteRegistryEntry],
    target: &mut String,
) {
    let Ok(RoutingTarget::LegacyProfile(id)) = RoutingTarget::parse(target) else {
        return;
    };
    let Some(profile) = profiles.iter().find(|profile| profile.id == id) else {
        return;
    };
    let canonical = canonical_profile_raw(profile);
    if let Some(entry) = registry
        .iter()
        .find(|entry| entry.canonical_raw == canonical)
    {
        *target = format!("server:{}", entry.server_ref);
    }
}

fn deserialize_persisted_state(text: &str) -> Result<HincyrayState, String> {
    deserialize_persisted_state_with_hasher(text, hash_password).map(|(state, _)| state)
}

fn deserialize_persisted_state_with_hasher(
    text: &str,
    hash: impl FnOnce(&str) -> Result<String, String>,
) -> Result<(HincyrayState, AuthMigration), String> {
    let mut value: Value = serde_json::from_str(text).map_err(|error| error.to_string())?;
    if let Some(split) = value
        .get_mut("split_routing")
        .and_then(Value::as_object_mut)
    {
        split
            .entry("auto_vpn_learning_enabled")
            .or_insert(Value::Bool(true));
        split
            .entry("ru_direct_mode")
            .or_insert_with(|| Value::String("geosite".to_owned()));
    }
    let mut state: HincyrayState =
        serde_json::from_value(value).map_err(|error| error.to_string())?;
    let auth_migration = state.web_ui_auth.migrate_legacy_password_with(hash);
    Ok((state, auth_migration))
}

fn compact_state_for_persist(state: &mut HincyrayState) {
    if state.metrics_history.len() > MAX_HISTORY_SAMPLES {
        let start = state
            .metrics_history
            .len()
            .saturating_sub(MAX_HISTORY_SAMPLES);
        state.metrics_history = state.metrics_history[start..].to_vec();
    }
    if state.connection_log.len() > MAX_CONNECTION_LOG {
        let start = state
            .connection_log
            .len()
            .saturating_sub(MAX_CONNECTION_LOG);
        state.connection_log = state.connection_log[start..].to_vec();
    }
    if state.undo_stack.len() > MAX_UNDO_STACK {
        let start = state.undo_stack.len().saturating_sub(MAX_UNDO_STACK);
        state.undo_stack = state.undo_stack[start..].to_vec();
    }
    if let Some(report) = state.last_subscription_refresh_report.as_mut()
        && report.entries.len() > MAX_REFRESH_REPORT_ENTRIES
    {
        report.entries.truncate(MAX_REFRESH_REPORT_ENTRIES);
    }
    state.split_routing.parovozik_direct_domains =
        normalize_parovozik_domains(&state.split_routing.parovozik_direct_domains);
    state.split_routing.parovozik_vpn_domains =
        normalize_parovozik_domains(&state.split_routing.parovozik_vpn_domains);
    state
        .split_routing
        .parovozik_server_refs
        .truncate(MAX_PAROVOZIK_SERVERS);
    if state.split_routing.parovozik_last_checked_unix.len() > MAX_PAROVOZIK_DOMAINS * 2 {
        let mut checked: Vec<(String, u64)> = state
            .split_routing
            .parovozik_last_checked_unix
            .iter()
            .map(|(domain, timestamp)| (domain.clone(), *timestamp))
            .collect();
        checked.sort_by_key(|(_, timestamp)| *timestamp);
        let remove_count = checked.len() - MAX_PAROVOZIK_DOMAINS * 2;
        for (domain, _) in checked.into_iter().take(remove_count) {
            state
                .split_routing
                .parovozik_last_checked_unix
                .remove(&domain);
        }
    }
}

fn prune_stale_profile_stats(state: &mut HincyrayState) -> bool {
    let current: HashSet<String> = state
        .profiles
        .iter()
        .map(|profile| profile.raw.clone())
        .collect();
    let mut stale: Vec<&ProfileStats> = state
        .stats
        .iter()
        .filter(|stat| !current.contains(&stat.profile_raw))
        .collect();
    if stale.len() <= MAX_STALE_PROFILE_STATS {
        return false;
    }
    stale.sort_unstable_by_key(|stat| std::cmp::Reverse(stat.last_checked_unix));
    let keep: HashSet<String> = stale
        .into_iter()
        .take(MAX_STALE_PROFILE_STATS)
        .map(|stat| stat.profile_raw.clone())
        .collect();
    let before = state.stats.len();
    state
        .stats
        .retain(|stat| current.contains(&stat.profile_raw) || keep.contains(&stat.profile_raw));
    state.stats.len() != before
}

fn persist_state(state_path: &Path, state: &HincyrayState) -> Result<(), String> {
    if let Some(parent) = state_path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let mut compacted = state.clone();
    compact_state_for_persist(&mut compacted);
    // Clear transient fields before serialization. They have #[serde(skip)]
    // so they won't appear in the output, but clearing them avoids holding
    // 3MB+ of undo_stack JSON strings in memory during serialization.
    compacted.undo_stack.clear();
    compacted.connection_log.clear();
    compacted.metrics_history.clear();
    compacted.web_ui_auth.password.clear();
    let text = serde_json::to_string_pretty(&compacted).map_err(|error| error.to_string())?;
    let tmp = state_path.with_extension("tmp");
    fs::write(&tmp, &text).map_err(|error| error.to_string())?;
    fs::rename(&tmp, state_path).map_err(|error| error.to_string())
}

/// v0.19.8: Flush state to disk only if the `dirty` flag is set.
/// Called once at the end of each watchdog tick and during graceful
/// shutdown. This is the "write-behind" flush point — multiple
/// `mark_dirty()` calls within a tick collapse into a single disk write.
fn flush_if_dirty(inner: &mut DaemonInner, state_path: &Path) {
    if inner.dirty {
        if let Err(error) = persist_state(state_path, &inner.state) {
            eprintln!("hincyray: watchdog persist failed: {error}");
        }
        inner.dirty = false;
    }
}

fn push_undo_snapshot(state: &mut HincyrayState, label: impl Into<String>) {
    let mut snapshot = state.clone();
    snapshot.undo_stack.clear();
    compact_state_for_persist(&mut snapshot);
    if let Ok(state_json) = serde_json::to_string(&snapshot) {
        state.undo_stack.push(UndoEntry {
            id: format!("undo-{}-{}", unix_now(), state.undo_stack.len()),
            label: label.into(),
            timestamp: unix_now(),
            state_json,
        });
        compact_state_for_persist(state);
    }
}

fn atomic_write_config(path: &Path, config_yaml: &[u8]) -> Result<(), String> {
    atomic_write_config_with(path, config_yaml, |temp, destination| {
        temp.persist(destination)
            .map(|_| ())
            .map_err(|error| error.error.to_string())
    })
}

fn atomic_write_config_with(
    path: &Path,
    config_yaml: &[u8],
    publish: impl FnOnce(NamedTempFile, &Path) -> Result<(), String>,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        let mut temp = NamedTempFile::new_in(parent).map_err(|error| error.to_string())?;
        temp.write_all(config_yaml)
            .map_err(|error| error.to_string())?;
        temp.as_file()
            .sync_all()
            .map_err(|error| error.to_string())?;
        publish(temp, path)?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| error.to_string())?;
        return Ok(());
    }
    Err(format!("config path {} has no parent", path.display()))
}

/// Build the single Mihomo config (YAML) for the current active profile.
/// Returns the YAML string so callers can write it to the daemon's
/// config path.
fn build_daemon_config(
    state: &HincyrayState,
    geobase_rule_providers: &[GeoBaseRuleProvider],
) -> Result<String, String> {
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

    let effective_features = effective_mihomo_features(state);
    if !state.split_routing.enabled {
        return build_mihomo_config(
            active_profile,
            &state.listen_host,
            state.socks_port,
            &effective_features,
        );
    }

    // Split routing: build the full router config.
    validate_routing_targets(state, &state.routing_rules, &state.device_routes)?;
    let mut managed_providers = geobase_rule_providers.to_vec();
    managed_providers.extend(parovozik_rule_providers(state)?);
    let (extra_profiles, mut pinned_routes, mut routes, active_block_quic, extra) =
        build_routing_context(
            state,
            active_profile,
            if state.safe_mode_enabled {
                &[]
            } else {
                &managed_providers
            },
        )?;

    // Prepend per-device routing rules (SRC-IP-CIDR) BEFORE general
    // routing rules so device-specific rules match first.
    let mut device_rules: Vec<XrayRouteRule> = Vec::new();
    for dr in &state.device_routes {
        if !dr.enabled || dr.ip.trim().is_empty() {
            continue;
        }
        let outbound_tag = resolve_target(state, active_profile, &dr.target, &mut pinned_routes)?.0;
        device_rules.push(XrayRouteRule {
            domains: vec![],
            ips: vec![format!("src-ip-cidr:{}/32", dr.ip.trim())],
            outbound_tag,
            block_quic: false,
            ports: vec![],
            network: None,
            port_mode: "include".to_owned(),
        });
    }
    // Device rules first, then general rules.
    routes.splice(0..0, device_rules);

    build_mihomo_router_config(
        active_profile,
        &extra_profiles,
        &pinned_routes,
        &routes,
        &state.listen_host,
        state.socks_port,
        Some(state.split_routing.redirect_port),
        state.split_routing.tproxy_available,
        state.split_routing.quic_mode.clone(),
        active_block_quic,
        &extra,
        &effective_features,
    )
}

fn effective_mihomo_features(state: &HincyrayState) -> MihomoFeatures {
    let mut features = state.mihomo_features.clone();
    if state.safe_mode_enabled {
        features.proxy_providers.clear();
        features.rule_providers.clear();
        features.sub_rules.clear();
        features.raw_rules.clear();
        features.typed_rules.clear();
        features.tunnels.clear();
        features.per_proxy.smux = None;
    }
    features
}

/// Build the routing context shared by the daemon's config generator.
/// Returns the list of extra profile/outbound-name pairs, the routing
/// rules, whether the active profile should block QUIC, and the extra
/// router options.
type RoutingContext<'a> = (
    Vec<(&'a Profile, String)>,
    Vec<PinnedServerRoute<'a>>,
    Vec<XrayRouteRule>,
    bool,
    RouterExtra,
);

fn build_routing_context<'a>(
    state: &'a HincyrayState,
    active_profile: &'a Profile,
    geobase_rule_providers: &[GeoBaseRuleProvider],
) -> Result<RoutingContext<'a>, String> {
    let extra_profiles: Vec<(&Profile, String)> = Vec::new();
    let mut pinned_routes = Vec::new();
    let mut routes: Vec<XrayRouteRule> = Vec::new();
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
        let ports = normalize_route_items(&rule.ports);
        let network = normalize_route_network(&rule.network);
        if domains.is_empty() && ips.is_empty() && ports.is_empty() && network.is_none() {
            continue;
        }

        let (outbound_tag, profile_for_quic) =
            resolve_target(state, active_profile, &rule.target, &mut pinned_routes)?;
        let profile_quic = profile_for_quic
            .map(|profile| profile.block_quic)
            .unwrap_or(false);

        routes.push(XrayRouteRule {
            domains,
            ips,
            outbound_tag,
            block_quic: state.split_routing.block_quic_global || profile_quic,
            ports,
            network,
            port_mode: rule.port_mode.clone(),
        });
    }

    // v0.16: block_quic_global is now handled by a migrated routing rule
    // ("QUIC Block"). active_block_quic only reflects per-profile QUIC
    // capability, which is a system-level automatic rule.
    let active_block_quic = active_profile.block_quic;
    let mut parovozik_vpn_outbounds = Vec::new();
    if state.split_routing.parovozik_enabled {
        let active_canonical = canonical_profile_raw(active_profile);
        for server_ref in state
            .split_routing
            .parovozik_server_refs
            .iter()
            .take(MAX_PAROVOZIK_SERVERS)
        {
            let is_active = state.server_route_registry.iter().any(|entry| {
                entry.server_ref == *server_ref && entry.canonical_raw == active_canonical
            });
            if is_active {
                continue;
            }
            let usable = state.server_route_registry.iter().any(|entry| {
                entry.server_ref == *server_ref
                    && state.profiles.iter().any(|profile| {
                        canonical_profile_raw(profile) == entry.canonical_raw
                            && !profile_is_dead(state, profile)
                    })
            });
            if !usable {
                continue;
            }
            let target = format!("server:{server_ref}");
            let (group, _) = resolve_target(state, active_profile, &target, &mut pinned_routes)?;
            if group != PROXY_ACTIVE_NAME && !parovozik_vpn_outbounds.contains(&group) {
                parovozik_vpn_outbounds.push(group);
            }
        }
    }
    let extra = RouterExtra {
        dns: Some(state.dns_settings.clone()),
        port_mode: state.split_routing.port_mode.clone(),
        proxy_ports: normalize_route_items(&state.split_routing.proxy_ports),
        bypass_ports: normalize_route_items(&state.split_routing.bypass_ports),
        geo_asset_path: if state.split_routing.geo_asset_path.is_empty() {
            None
        } else {
            Some(state.split_routing.geo_asset_path.clone())
        },
        ru_direct_mode: state.split_routing.ru_direct_mode.clone(),
        ru_direct_exceptions: normalize_route_items(&state.split_routing.ru_direct_exceptions),
        auto_vpn_exceptions: normalize_route_items(&state.split_routing.auto_vpn_exceptions),
        parovozik_direct_domains: if state.split_routing.parovozik_enabled {
            normalize_route_items(&state.split_routing.parovozik_direct_domains)
        } else {
            Vec::new()
        },
        parovozik_vpn_domains: if state.split_routing.parovozik_enabled {
            normalize_route_items(&state.split_routing.parovozik_vpn_domains)
        } else {
            Vec::new()
        },
        parovozik_vpn_target: if state.split_routing.parovozik_enabled {
            PAROVOZIK_PROXY_GROUP.to_owned()
        } else {
            String::new()
        },
        parovozik_vpn_outbounds,
        match_target: state.split_routing.match_target.clone(),
        mihomo_home: geo_dir_from_state(state),
        geobase_rule_providers: geobase_rule_providers.to_vec(),
    };
    Ok((
        extra_profiles,
        pinned_routes,
        routes,
        active_block_quic,
        extra,
    ))
}

fn resolve_target<'a>(
    state: &'a HincyrayState,
    active: &'a Profile,
    value: &str,
    routes: &mut Vec<PinnedServerRoute<'a>>,
) -> Result<(String, Option<&'a Profile>), String> {
    match RoutingTarget::parse(value)? {
        RoutingTarget::Direct => Ok((DIRECT_NAME.to_owned(), None)),
        RoutingTarget::Reject => Ok((REJECT_NAME.to_owned(), None)),
        RoutingTarget::Parovozik => Ok((PAROVOZIK_PROXY_GROUP.to_owned(), Some(active))),
        RoutingTarget::Active => Ok((PROXY_NAME.to_owned(), Some(active))),
        RoutingTarget::LegacyProfile(_) => Err(format!("unmigrated legacy target {value:?}")),
        RoutingTarget::Server(server_ref) => {
            let entry = state
                .server_route_registry
                .iter()
                .find(|e| e.server_ref == server_ref)
                .ok_or_else(|| format!("unknown server ref {server_ref}"))?;
            let profile = state
                .profiles
                .iter()
                .find(|p| canonical_profile_raw(p) == entry.canonical_raw)
                .ok_or_else(|| format!("server ref {server_ref} is stale"))?;
            if profile_is_dead(state, profile) {
                return Ok((PROXY_NAME.to_owned(), Some(active)));
            }
            if canonical_profile_raw(active) == entry.canonical_raw {
                return Ok((PROXY_ACTIVE_NAME.to_owned(), Some(profile)));
            }
            let suffix = &server_ref[7..];
            let outbound = format!("srv-out-{suffix}");
            let group = format!("srv-route-{suffix}");
            if !routes.iter().any(|route| route.group_name == group) {
                routes.push(PinnedServerRoute {
                    outbound_name: outbound,
                    group_name: group.clone(),
                    profile,
                });
            }
            Ok((group, Some(profile)))
        }
    }
}

fn validate_routing_targets(
    state: &HincyrayState,
    rules: &[RoutingRule],
    devices: &[DeviceRoute],
) -> Result<(), String> {
    let mut refs = HashSet::new();
    for target in rules
        .iter()
        .filter(|r| r.enabled)
        .map(|r| r.target.as_str())
        .chain(
            devices
                .iter()
                .filter(|r| r.enabled)
                .map(|r| r.target.as_str()),
        )
    {
        match RoutingTarget::parse(target)? {
            RoutingTarget::Server(server_ref) => {
                let entry = state
                    .server_route_registry
                    .iter()
                    .find(|e| e.server_ref == server_ref)
                    .ok_or_else(|| format!("unknown server ref {server_ref}"))?;
                let profile = state
                    .profiles
                    .iter()
                    .find(|profile| canonical_profile_raw(profile) == entry.canonical_raw);
                let Some(profile) = profile else {
                    return Err(format!("server ref {server_ref} is stale"));
                };
                if profile_is_dead(state, profile) {
                    continue;
                }
                refs.insert(server_ref);
            }
            RoutingTarget::LegacyProfile(_) => {
                return Err(format!("unmigrated legacy target {target:?}"));
            }
            _ => {}
        }
    }
    for server_ref in state
        .split_routing
        .parovozik_server_refs
        .iter()
        .take(MAX_PAROVOZIK_SERVERS)
    {
        let Some(entry) = state
            .server_route_registry
            .iter()
            .find(|entry| entry.server_ref == *server_ref)
        else {
            continue;
        };
        let Some(profile) = state
            .profiles
            .iter()
            .find(|profile| canonical_profile_raw(profile) == entry.canonical_raw)
        else {
            continue;
        };
        if profile_is_dead(state, profile) {
            continue;
        }
        refs.insert(server_ref.clone());
    }
    if state.split_routing.parovozik_server_refs.len() > MAX_PAROVOZIK_SERVERS {
        return Err(format!(
            "Паровозик поддерживает не более {MAX_PAROVOZIK_SERVERS} дополнительных серверов"
        ));
    }
    if refs.len() > MAX_PINNED_SERVERS {
        return Err(format!(
            "at most {MAX_PINNED_SERVERS} pinned servers may be enabled"
        ));
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum PinnedRouteTransition {
    Fallback,
    Recovery,
}

fn detect_pinned_route_transition(
    previous: Option<&str>,
    current: &str,
    pinned_outbound: &str,
) -> Option<PinnedRouteTransition> {
    match (previous, current) {
        (Some(old), PROXY_ACTIVE_NAME) if old == pinned_outbound => {
            Some(PinnedRouteTransition::Fallback)
        }
        (Some(PROXY_ACTIVE_NAME), now) if now == pinned_outbound => {
            Some(PinnedRouteTransition::Recovery)
        }
        _ => None,
    }
}

fn pinned_route_observer_catalog(state: &HincyrayState) -> Vec<(String, String, String, String)> {
    let Ok(active) = state
        .active_profile_id
        .and_then(|id| state.profiles.iter().find(|profile| profile.id == id))
        .ok_or(())
    else {
        return Vec::new();
    };
    let mut routes: Vec<(String, String, String, String)> = Vec::new();
    for target in state
        .routing_rules
        .iter()
        .filter(|rule| rule.enabled)
        .map(|rule| rule.target.as_str())
        .chain(
            state
                .device_routes
                .iter()
                .filter(|route| route.enabled)
                .map(|route| route.target.as_str()),
        )
    {
        let Ok(RoutingTarget::Server(server_ref)) = RoutingTarget::parse(target) else {
            continue;
        };
        let Some(entry) = state
            .server_route_registry
            .iter()
            .find(|entry| entry.server_ref == server_ref)
        else {
            continue;
        };
        let Some(profile) = state
            .profiles
            .iter()
            .find(|profile| canonical_profile_raw(profile) == entry.canonical_raw)
        else {
            continue;
        };
        if profile_is_dead(state, profile) {
            continue;
        }
        if canonical_profile_raw(active) == entry.canonical_raw {
            continue;
        }
        let suffix = &server_ref[7..];
        let item = (
            format!("srv-route-{suffix}"),
            format!("srv-out-{suffix}"),
            profile.name.clone(),
            active.name.clone(),
        );
        if !routes.iter().any(|existing| existing.0 == item.0) {
            routes.push(item);
        }
    }
    routes
}

fn observe_pinned_routes(daemon: &Daemon, ec_addr: &str, ec_secret: Option<&str>) {
    let catalog = {
        let inner = lock(&daemon.inner);
        pinned_route_observer_catalog(&inner.state)
    };
    let active_groups: HashSet<String> = catalog.iter().map(|item| item.0.clone()).collect();
    let mut observations = Vec::new();
    for (group, outbound, display, active_display) in catalog {
        let encoded = utf8_percent_encode(&group, NON_ALPHANUMERIC).to_string();
        if let Ok(value) = mihomo_api_get_json(ec_addr, ec_secret, &format!("/proxies/{encoded}"))
            && let Some(now) = value.get("now").and_then(Value::as_str)
        {
            observations.push((group, outbound, display, active_display, now.to_owned()));
        }
    }
    let mut inner = lock(&daemon.inner);
    inner
        .pinned_route_now
        .retain(|group, _| active_groups.contains(group));
    for (group, outbound, display, active_display, now) in observations {
        let transition = detect_pinned_route_transition(
            inner.pinned_route_now.get(&group).map(String::as_str),
            &now,
            &outbound,
        );
        inner.pinned_route_now.insert(group, now);
        match transition {
            Some(PinnedRouteTransition::Fallback) => eprintln!(
                "hincyray: pinned server {display} unavailable, switched to active server {active_display}"
            ),
            Some(PinnedRouteTransition::Recovery) => {
                eprintln!(
                    "hincyray: pinned server {display} recovered, restored preferred route from active server {active_display}"
                )
            }
            None => {}
        }
    }
}

/// Extract the parent directory of the configured geo asset path to pass
/// to Mihomo's `-d` home directory flag.
fn geo_dir_from_state(state: &HincyrayState) -> Option<String> {
    let path = state.split_routing.geo_asset_path.trim();
    if path.is_empty() {
        return None;
    }
    // `geo_asset_path` contains geosite.dat and geoip.metadb.
    // Mihomo's `-d` flag expects exactly this directory, not its
    // parent.  If the path points to a file (not a directory), fall
    // back to its parent.
    let p = Path::new(path);
    if p.is_dir() {
        Some(path.to_owned())
    } else {
        p.parent().map(|p| p.to_string_lossy().into_owned())
    }
}

fn parovozik_provider_paths(state: &HincyrayState) -> Result<(PathBuf, PathBuf), String> {
    let home = geo_dir_from_state(state)
        .map(PathBuf::from)
        .ok_or_else(|| "Mihomo home is required for Parovozik providers".to_owned())?;
    Ok((
        home.join(PAROVOZIK_DIRECT_FILE),
        home.join(PAROVOZIK_VPN_FILE),
    ))
}

fn parovozik_rule_providers(state: &HincyrayState) -> Result<Vec<GeoBaseRuleProvider>, String> {
    if !state.split_routing.parovozik_enabled {
        return Ok(Vec::new());
    }
    let (direct, vpn) = parovozik_provider_paths(state)?;
    Ok(vec![
        GeoBaseRuleProvider {
            enabled: true,
            name: PAROVOZIK_DIRECT_PROVIDER.to_owned(),
            path: direct.to_string_lossy().into_owned(),
            behavior: GeoBaseRuleBehavior::Domain,
            target: GeoBaseRuleTarget::ParovozikDirect,
        },
        GeoBaseRuleProvider {
            enabled: true,
            name: PAROVOZIK_VPN_PROVIDER.to_owned(),
            path: vpn.to_string_lossy().into_owned(),
            behavior: GeoBaseRuleBehavior::Domain,
            target: GeoBaseRuleTarget::ParovozikVpn,
        },
    ])
}

fn parovozik_provider_bytes(domains: &[String]) -> Vec<u8> {
    let domains = normalize_parovozik_domains(domains);
    if domains.is_empty() {
        b"# empty\n".to_vec()
    } else {
        format!("{}\n", domains.join("\n")).into_bytes()
    }
}

fn write_parovozik_provider_files(state: &HincyrayState) -> Result<(), String> {
    if !state.split_routing.parovozik_enabled {
        return Ok(());
    }
    let (direct_path, vpn_path) = parovozik_provider_paths(state)?;
    atomic_write_config(
        &direct_path,
        &parovozik_provider_bytes(&state.split_routing.parovozik_direct_domains),
    )?;
    atomic_write_config(
        &vpn_path,
        &parovozik_provider_bytes(&state.split_routing.parovozik_vpn_domains),
    )
}

fn hot_update_parovozik_providers(
    state: &HincyrayState,
    direct_changed: bool,
    vpn_changed: bool,
) -> Result<(), String> {
    write_parovozik_provider_files(state)?;
    let (addr, secret) = mihomo_controller(&state.mihomo_features).ok_or_else(|| {
        "Mihomo External Controller is required for Parovozik hot update".to_owned()
    })?;
    for provider in [
        direct_changed.then_some(PAROVOZIK_DIRECT_PROVIDER),
        vpn_changed.then_some(PAROVOZIK_VPN_PROVIDER),
    ]
    .into_iter()
    .flatten()
    {
        let path = format!(
            "/providers/rules/{}",
            utf8_percent_encode(provider, NON_ALPHANUMERIC)
        );
        mihomo_api_put(&addr, secret.as_deref(), &path, None)?;
    }
    Ok(())
}

fn normalize_route_items(items: &[String]) -> Vec<String> {
    items
        .iter()
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn normalize_auto_vpn_domain(input: &str) -> Option<String> {
    let mut host = input.trim().to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    if let Some(rest) = host.strip_prefix("http://") {
        host = rest.to_owned();
    } else if let Some(rest) = host.strip_prefix("https://") {
        host = rest.to_owned();
    }
    if let Some((before_path, _)) = host.split_once('/') {
        host = before_path.to_owned();
    }
    host = host
        .trim_start_matches("*.")
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_owned();

    if let Some(stripped) = host.strip_prefix('[').and_then(|v| v.strip_suffix(']'))
        && stripped.parse::<IpAddr>().is_ok()
    {
        return None;
    }
    if host.matches(':').count() == 1
        && let Some((candidate, port)) = host.rsplit_once(':')
        && !candidate.is_empty()
        && port.parse::<u16>().is_ok()
    {
        host = candidate.to_owned();
    }
    if host.parse::<IpAddr>().is_ok() || host.contains(':') {
        return None;
    }
    if host == "localhost"
        || host.ends_with(".local")
        || host.ends_with(".lan")
        || host.ends_with(".home")
    {
        return None;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    for label in &labels {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return None;
        }
    }
    Some(host)
}

fn dedup_limited_domains(items: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for item in items {
        let Some(domain) = normalize_auto_vpn_domain(&item) else {
            continue;
        };
        if seen.insert(domain.clone()) {
            out.push(domain);
        }
    }
    if out.len() > MAX_AUTO_VPN_EXCEPTIONS {
        out.drain(0..out.len() - MAX_AUTO_VPN_EXCEPTIONS);
    }
    out
}

fn prune_auto_vpn_metadata(split: &mut SplitRoutingSettings) {
    let domains: HashSet<String> = split.auto_vpn_exceptions.iter().cloned().collect();
    if split.auto_vpn_last_checked_unix.len() <= MAX_AUTO_VPN_EXCEPTIONS * 2 {
        return;
    }
    let mut candidates: Vec<(String, u64)> = split
        .auto_vpn_last_checked_unix
        .iter()
        .filter(|(domain, _)| !domains.contains(*domain))
        .map(|(domain, timestamp)| (domain.clone(), *timestamp))
        .collect();
    candidates.sort_by_key(|(_, timestamp)| *timestamp);
    let remove_count = split.auto_vpn_last_checked_unix.len() - MAX_AUTO_VPN_EXCEPTIONS * 2;
    for (domain, _) in candidates.into_iter().take(remove_count) {
        split.auto_vpn_last_checked_unix.remove(&domain);
    }
}

fn normalize_parovozik_domains(items: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    items
        .iter()
        .filter_map(|item| normalize_auto_vpn_domain(item))
        .filter(|domain| seen.insert(domain.clone()))
        .take(MAX_PAROVOZIK_DOMAINS)
        .collect()
}

fn normalize_parovozik_server_refs(
    state: &HincyrayState,
    values: &[String],
) -> Result<Vec<String>, String> {
    if values.len() > MAX_PAROVOZIK_SERVERS {
        return Err(format!(
            "Паровозик поддерживает не более {MAX_PAROVOZIK_SERVERS} дополнительных серверов"
        ));
    }
    let mut refs = Vec::new();
    for value in values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        let server_ref = value.strip_prefix("server:").unwrap_or(value);
        if !state
            .server_route_registry
            .iter()
            .any(|entry| entry.server_ref == server_ref)
        {
            return Err(format!("unknown Parovozik server ref {server_ref}"));
        }
        if state.profiles.iter().any(|profile| {
            state.server_route_registry.iter().any(|entry| {
                entry.server_ref == server_ref
                    && entry.canonical_raw == canonical_profile_raw(profile)
                    && profile_is_dead(state, profile)
            })
        }) {
            return Err(format!("Parovozik server ref {server_ref} is dead"));
        }
        if !refs.iter().any(|existing| existing == server_ref) {
            refs.push(server_ref.to_owned());
        }
    }
    Ok(refs)
}

fn normalize_route_network(network: &str) -> Option<String> {
    match network.trim().to_ascii_lowercase().as_str() {
        "" | "any" | "all" | "*" | "tcp,udp" | "udp,tcp" => None,
        "tcp" => Some("tcp".to_owned()),
        "udp" => Some("udp".to_owned()),
        _ => None,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

/// Cached SOCKS fallback info for the running core. Captured under a
/// short lock and then used by `load_subscription_for_daemon` outside
/// the mutex so network I/O does not block the API.
struct DaemonProxyInfo {
    /// `socks5h://host:port` — remote DNS (proxy server resolves hostname).
    socks5h_url: String,
    /// `socks5://host:port` — local DNS (router resolves hostname via
    /// Mihomo fake-ip, then connects to the IP through the proxy).
    socks5_url: String,
    /// `http://host:port` — HTTP CONNECT proxy (Mihomo mixed inbound).
    http_url: Option<String>,
    core_running: bool,
}

/// Result of `load_subscription_for_daemon`: either a successful
/// `SubscriptionLoadReport`, or a list of all attempted paths with
/// their errors. Each entry is `(label, error_message)` so callers
/// can show the user exactly what was tried and why each path failed.
enum SubscriptionLoadOutcome {
    Ok(crate::profiles::SubscriptionLoadReport),
    Failed { attempts: Vec<(String, String)> },
}

impl SubscriptionLoadOutcome {
    /// Format all attempt errors into a single string. When only one
    /// path was tried, returns the error as-is. When multiple paths
    /// failed, prefixes each with `[label]` and joins with `; `.
    fn format_error(attempts: &[(String, String)]) -> String {
        match attempts.len() {
            0 => String::new(),
            1 => attempts[0].1.clone(),
            _ => attempts
                .iter()
                .map(|(label, error)| format!("[{label}] {error}"))
                .collect::<Vec<_>>()
                .join("; "),
        }
    }
}

fn proxy_info_for_daemon(inner: &mut DaemonInner) -> DaemonProxyInfo {
    let core_running = inner.core.is_running();
    let host = &inner.state.listen_host;
    let socks_port = inner.state.socks_port;
    DaemonProxyInfo {
        socks5h_url: format!("socks5h://{host}:{socks_port}"),
        socks5_url: format!("socks5://{host}:{socks_port}"),
        http_url: inner.state.http_port.map(|p| format!("http://{host}:{p}")),
        core_running,
    }
}

/// Try every available fetch path in order and return the first success
/// or a collected list of all failures. The order is:
///
/// 1. **Direct** (no proxy) — works when the router can reach the URL
///    directly (e.g. non-RKN-blocked domains).
/// 2. **SOCKS5h** (remote DNS) — the proxy server resolves the hostname.
///    Works when the proxy can reach the URL and its DNS is functional.
/// 3. **SOCKS5** (local DNS) — the router resolves the hostname (via
///    Mihomo fake-ip DNS) and connects to the IP through the proxy.
///    Works when the proxy's DNS is broken but the router's Mihomo DNS
///    can resolve the domain.
/// 4. **HTTP** (CONNECT proxy) — uses the Mihomo HTTP/mixed inbound if
///    configured. A different transport that may succeed when SOCKS
///    fails (e.g. due to TLS interception on SOCKS).
///
/// Network I/O happens here, so the caller must NOT hold the daemon mutex.
fn load_subscription_for_daemon(
    source: &SubscriptionSource,
    proxy_info: &DaemonProxyInfo,
    hwid: &HwidConfig,
) -> SubscriptionLoadOutcome {
    let mut attempts: Vec<(String, String)> = Vec::new();

    // 1. Direct (no proxy)
    match load_subscription_detailed_via_proxy_with_hwid(source, None, hwid) {
        Ok(report) => return SubscriptionLoadOutcome::Ok(report),
        Err(err) => attempts.push(("direct".to_owned(), err)),
    }

    if !proxy_info.core_running {
        return SubscriptionLoadOutcome::Failed { attempts };
    }

    // 2. SOCKS5h (remote DNS)
    match load_subscription_detailed_via_proxy_with_hwid(
        source,
        Some(&proxy_info.socks5h_url),
        hwid,
    ) {
        Ok(report) => return SubscriptionLoadOutcome::Ok(report),
        Err(err) => attempts.push(("socks5h".to_owned(), err)),
    }

    // 3. SOCKS5 (local DNS — router resolves hostname via Mihomo fake-ip)
    match load_subscription_detailed_via_proxy_with_hwid(source, Some(&proxy_info.socks5_url), hwid)
    {
        Ok(report) => return SubscriptionLoadOutcome::Ok(report),
        Err(err) => attempts.push(("socks5".to_owned(), err)),
    }

    // 4. HTTP proxy (if configured — default port 10809)
    if let Some(http_url) = &proxy_info.http_url {
        match load_subscription_detailed_via_proxy_with_hwid(source, Some(http_url), hwid) {
            Ok(report) => return SubscriptionLoadOutcome::Ok(report),
            Err(err) => attempts.push(("http".to_owned(), err)),
        }
    }

    SubscriptionLoadOutcome::Failed { attempts }
}

/// v0.13: Check if a request is authorized. Returns true if:
/// - Auth is disabled, or
/// - The path is in the public allowlist, or
/// - The request carries a valid session token.
fn check_auth(daemon: &Daemon, auth_header: &Option<String>, path: &str, method: &str) -> bool {
    let mut inner = lock(&daemon.inner);
    if !inner.state.web_ui_auth.enabled {
        return true;
    }

    // Public endpoints — always accessible even when auth is on.
    if path == "/" || path == "/api/health" || path == "/api/auth/login" {
        return true;
    }
    // Auth settings GET is public so the login page can check if auth is enabled.
    if method == "GET" && path == "/api/auth-settings" {
        return true;
    }

    // Check Bearer token.
    if let Some(header) = auth_header
        && let Some(token) = header
            .strip_prefix("bearer ")
            .or_else(|| header.strip_prefix("Bearer "))
    {
        let now = unix_now();
        let valid = inner
            .sessions
            .get_mut(token)
            .is_some_and(|session| session.validate_and_touch(now));
        if !valid {
            inner.sessions.remove(token);
        }
        return valid;
    }
    false
}

fn handle_connection(mut stream: TcpStream, daemon: &Daemon) -> Result<(), String> {
    let peer_ip = stream
        .peer_addr()
        .map(|address| address.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let mut reader = BufReader::new(stream.try_clone().map_err(|error| error.to_string())?);

    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .map_err(|error| error.to_string())?;
    if request_line.is_empty() {
        return Ok(());
    }

    let mut content_length = None;
    let mut auth_header: Option<String> = None;
    let mut host_header: Option<String> = None;
    let mut origin_header: Option<String> = None;
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
        let Some((header_name, header_value)) = trimmed.split_once(':') else {
            continue;
        };
        let header_name = header_name.trim();
        let header_value = header_value.trim();
        if header_name.eq_ignore_ascii_case("content-length") {
            match header_value.parse::<usize>() {
                Ok(value) if content_length.is_none() => content_length = Some(value),
                _ => {
                    write_response(
                        &mut stream,
                        400,
                        "application/json",
                        &json!({"error": "invalid Content-Length"}).to_string(),
                    )?;
                    return Ok(());
                }
            }
        } else if header_name.eq_ignore_ascii_case("authorization") {
            auth_header = Some(header_value.to_owned());
        } else if header_name.eq_ignore_ascii_case("host") {
            host_header = Some(header_value.to_owned());
        } else if header_name.eq_ignore_ascii_case("origin") {
            origin_header = Some(header_value.to_owned());
        }
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
    if method == "OPTIONS" {
        write_response(
            &mut stream,
            403,
            "application/json",
            &json!({"error": "cross-origin preflight rejected"}).to_string(),
        )?;
        return Ok(());
    }
    let body_limit = request_body_limit(method, path);
    let content_length = content_length.unwrap_or(0);
    if content_length > body_limit {
        write_response(
            &mut stream,
            413,
            "application/json",
            &json!({"error": "request body too large", "limit": body_limit}).to_string(),
        )?;
        return Ok(());
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader
            .read_exact(&mut body)
            .map_err(|error| error.to_string())?;
    }
    let body_text = match String::from_utf8(body) {
        Ok(text) => text,
        Err(_) => {
            write_response(
                &mut stream,
                400,
                "application/json",
                &json!({"error": "request body must be valid UTF-8"}).to_string(),
            )?;
            return Ok(());
        }
    };

    if is_state_changing_method(method)
        && let Some(origin) = origin_header.as_deref()
        && !origin_matches_host(origin, host_header.as_deref())
    {
        write_response(
            &mut stream,
            403,
            "application/json",
            &json!({"error": "cross-origin state change rejected"}).to_string(),
        )?;
        return Ok(());
    }

    // v0.13: Web UI authentication middleware.
    if !check_auth(daemon, &auth_header, path, method) {
        let response_body = json!({"error": "unauthorized"}).to_string();
        write_response(&mut stream, 401, "application/json", &response_body)?;
        return Ok(());
    }

    let (status, content_type, response_body) =
        dispatch_from(method, path, &body_text, daemon, peer_ip);
    write_response(&mut stream, status, content_type, &response_body)
}

fn is_state_changing_method(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH" | "DELETE")
}

fn origin_matches_host(origin: &str, host: Option<&str>) -> bool {
    let Some(host) = host.map(str::trim).filter(|value| !value.is_empty()) else {
        return false;
    };
    let Ok(origin) = url::Url::parse(origin) else {
        return false;
    };
    matches!(origin.scheme(), "http" | "https")
        && origin.host_str().is_some()
        && origin
            .port_or_known_default()
            .map(|port| format!("{}:{port}", origin.host_str().unwrap_or_default()))
            .is_some_and(|origin_host| {
                origin_host.eq_ignore_ascii_case(host)
                    || (origin.port().is_none()
                        && origin
                            .host_str()
                            .is_some_and(|name| name.eq_ignore_ascii_case(host)))
            })
}

fn request_body_limit(method: &str, path: &str) -> usize {
    if method == "POST" && path == "/api/geobases/analyze" {
        MAX_GEOBASE_ANALYZE_BODY_BYTES
    } else {
        MAX_BODY_BYTES
    }
}

fn split_query(raw_path: &str) -> (&str, Option<&str>) {
    if let Some(idx) = raw_path.find('?') {
        (&raw_path[..idx], Some(&raw_path[idx + 1..]))
    } else {
        (raw_path, None)
    }
}

#[cfg(test)]
fn dispatch(method: &str, path: &str, body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    dispatch_from(method, path, body, daemon, IpAddr::V4(Ipv4Addr::LOCALHOST))
}

fn dispatch_from(
    method: &str,
    path: &str,
    body: &str,
    daemon: &Daemon,
    peer_ip: IpAddr,
) -> (u16, &'static str, String) {
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
                "active_profile_protocol": active.map(|p| p.protocol.to_string()),
                "profile_count": inner.state.profiles.len(),
                "auto_select": inner.state.auto_select,
                "auto_bench_interval_hours": inner.state.auto_bench_interval_hours,
                "last_auto_bench_unix": inner.state.last_auto_bench_unix,
                "auto_switch": inner.state.split_routing.auto_switch,
                "failover_fail_count": inner.failover_fail_count,
                "listen_host": inner.state.listen_host,
                "socks_port": inner.state.socks_port,
                "http_port": inner.state.http_port,
                "mihomo_config_path": daemon.mihomo_config_path.to_string_lossy(),
                "state_path": daemon.state_path.to_string_lossy(),
                "mihomo_path": inner.state.mihomo_path,
                "core_status": inner.core.status(),
                "mihomo_version": inner.state.mihomo_version,
                "update_available_version": inner.state.update_available_version,
                "split_routing": inner.state.split_routing,
                "dns_enabled": inner.state.dns_settings.enabled,
                "hwid": inner.state.hwid_config.hwid,
                "proxy_group_enabled": inner.state.mihomo_features.proxy_group.enabled,
                "ec_enabled": inner.state.mihomo_features.external_controller.enabled,
                "maintenance": inner.state.maintenance,
            });
            (200, "application/json", response.to_string())
        }
        ("GET", "/api/contracts") => handle_api_contracts(),
        ("GET", "/api/openapi.json") => json_response(&openapi_document()),
        ("GET", "/api/onboarding/status") => handle_onboarding_status(daemon),
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
                        "server_ref": profile_server_ref(profile),
                        "name": profile.name,
                        "protocol": profile.protocol.to_string(),
                        "transport": profile.transport(),
                        "address": profile.address,
                        "port": profile.port,
                        "active": active_id == Some(profile.id),
                        "group": profile.group,
                        "dead": profile_is_dead(&inner.state, profile),
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
        ("POST", "/api/profiles/add") => handle_profile_add(body, daemon),
        ("POST", "/api/profiles/delete") => handle_profile_delete(body, daemon),
        ("POST", "/api/profiles/update") => handle_profile_update(body, daemon),
        ("POST", "/api/profiles/share") => handle_profile_share(body, daemon),
        ("POST", "/api/profile-groups/share") => handle_profile_group_share(body, daemon),
        ("POST", "/api/profile-groups/delete") => handle_profile_group_delete(body, daemon),
        ("POST", "/api/profiles/block-quic") => handle_profile_block_quic(body, daemon),
        ("POST", "/api/active-profile") => handle_set_active(body, daemon),
        ("GET", "/api/mihomo-config") => handle_get_mihomo_config(daemon),
        ("GET", "/api/mihomo-config/preview") => handle_get_mihomo_config_preview(daemon),
        ("POST", "/api/mihomo-config/validate") => handle_mihomo_config_validate(daemon),
        ("POST", "/api/core/start") => handle_core_start(daemon),
        ("POST", "/api/core/stop") => handle_core_stop(daemon),
        ("POST", "/api/core/restart") => handle_core_restart(daemon),
        ("GET", "/api/bench/status") => handle_bench_status(daemon),
        ("POST", "/api/bench/start") => handle_bench_start(body, daemon),
        ("POST", "/api/bench/stop") => handle_bench_stop(daemon),
        ("GET", "/api/telegram-probe/status") => handle_telegram_probe_status(daemon),
        ("POST", "/api/telegram-probe/request-code") => {
            handle_telegram_probe_request_code(body, daemon)
        }
        ("POST", "/api/telegram-probe/confirm") => handle_telegram_probe_confirm(body, daemon),
        ("POST", "/api/telegram-probe/delete") => handle_telegram_probe_delete(daemon),
        ("GET", "/api/stats") => handle_stats(daemon),
        ("POST", "/api/favorites/toggle") => handle_favorites_toggle(body, daemon),
        ("GET", "/api/favorites") => handle_favorites_list(daemon),
        // v0.20: Deep Bench endpoints.
        ("GET", "/api/deep-bench/settings") => handle_deep_bench_settings_get(daemon),
        ("POST", "/api/deep-bench/settings") => handle_deep_bench_settings_set(body, daemon),
        ("POST", "/api/deep-bench/start") => handle_deep_bench_start(body, daemon),
        ("POST", "/api/deep-bench/cancel") => handle_deep_bench_cancel(daemon),
        ("GET", "/api/deep-bench/status") => handle_deep_bench_status(daemon),
        ("GET", "/api/deep-bench/history") => handle_deep_bench_history(daemon),
        // v0.20: Trash bin endpoints.
        ("GET", "/api/trash") => handle_trash_list(daemon),
        ("POST", "/api/trash/move") => handle_trash_move(body, daemon),
        ("POST", "/api/trash/restore") => handle_trash_restore(body, daemon),
        ("POST", "/api/trash/clear") => handle_trash_clear(daemon),
        ("POST", "/api/trash/purge-gone") => handle_trash_purge_gone(daemon),
        ("POST", "/api/subscriptions/refresh") => handle_subscriptions_refresh(daemon),
        ("GET", "/api/subscriptions/refresh-report") => handle_subscriptions_refresh_report(daemon),
        ("POST", "/api/subscriptions/refresh-one") => {
            handle_subscriptions_refresh_one(body, daemon)
        }
        ("GET", "/api/subscriptions") => handle_subscriptions_list(daemon),
        ("POST", "/api/subscriptions/delete") => handle_subscriptions_delete(body, daemon),
        ("GET", "/api/undo") => handle_undo_list(daemon),
        ("POST", "/api/undo/restore") => handle_undo_restore(body, daemon),
        ("GET", "/api/routing") => handle_routing_get(daemon),
        ("GET", "/api/routing/summary") => handle_routing_summary(daemon),
        ("GET", "/api/routing/connection-context") => handle_routing_connection_context(daemon),
        ("GET", "/api/routing/preview") => handle_routing_preview(daemon),
        ("POST", "/api/routing/explain") => handle_routing_explain(body, daemon),
        ("POST", "/api/routing/settings") => handle_routing_settings(body, daemon),
        ("POST", "/api/routing/rules") => handle_routing_rules(body, daemon),
        ("POST", "/api/routing/resource-route") => handle_routing_resource_route(body, daemon),
        ("POST", "/api/routing/catalog/refresh") => handle_routing_catalog_refresh(body, daemon),
        ("POST", "/api/routing/apply") => handle_routing_apply(daemon),
        ("POST", "/api/routing/reset") => handle_routing_reset(body, daemon),
        ("GET", "/api/routing-presets") => handle_routing_presets_list(),
        ("POST", "/api/routing-presets/apply") => handle_routing_preset_apply(body, daemon),
        ("GET", "/api/geo/providers") => handle_geo_providers(),
        ("POST", "/api/geo/download") => handle_geo_download(body, daemon),
        ("GET", "/api/geo/status") => handle_geo_status(daemon),
        ("GET", "/api/geobases") => handle_geobases_get(daemon),
        ("POST", "/api/geobases/analyze") => handle_geobases_analyze(body, daemon),
        ("POST", "/api/geobases/sync") => handle_geobases_sync(body, daemon),
        ("POST", "/api/geobases/details") => handle_geobases_details(body, daemon),
        ("POST", "/api/geobases/static") => handle_geobases_static(body, daemon),
        ("POST", "/api/geobases/cancel") => handle_geobases_cancel(daemon),
        ("POST", "/api/geobases/delete") => handle_geobases_delete(body, daemon),
        ("POST", "/api/geobases/enabled") => handle_geobases_enabled(body, daemon),
        ("POST", "/api/routing/trace") => handle_routing_trace(body, daemon),
        ("GET", "/api/routing/chain-check") => handle_routing_chain_check("", daemon),
        ("POST", "/api/routing/chain-check") => handle_routing_chain_check(body, daemon),
        ("GET", "/api/routing/firewall-status") => handle_firewall_status(daemon),
        ("POST", "/api/routing/firewall-start") => handle_firewall_start(daemon),
        ("POST", "/api/routing/firewall-stop") => handle_firewall_stop(daemon),
        ("GET", "/api/dns") => handle_dns_get(daemon),
        ("POST", "/api/dns") => handle_dns_set(body, daemon),
        ("GET", "/api/dns/leak-test") => handle_dns_leak_test(daemon),
        ("GET", "/api/dns/diagnostics") => handle_dns_diagnostics(daemon),
        ("GET", "/api/diagnostics/dns") => handle_dns_diagnostics_v2(daemon),
        ("GET", "/api/diagnostics/udp-quic") => handle_udp_quic_diagnostics(daemon),
        ("GET", "/api/memory-guard") => handle_memory_guard(daemon),
        ("GET", "/api/memory-estimate") => handle_memory_estimate(daemon),
        ("GET", "/api/safe-mode") => handle_safe_mode_get(daemon),
        ("POST", "/api/safe-mode") => handle_safe_mode_set(body, daemon),
        ("GET", "/metrics") => handle_prometheus_metrics(daemon),
        ("GET", "/api/logs") => handle_logs(daemon),
        ("GET", "/api/system") => handle_system(daemon),
        ("GET", "/api/auto-settings") => handle_auto_settings_get(daemon),
        ("POST", "/api/auto-settings") => handle_auto_settings_set(body, daemon),
        ("GET", "/api/hwid") => handle_hwid_get(daemon),
        ("POST", "/api/hwid") => handle_hwid_set(body, daemon),
        ("GET", "/api/update/status") => handle_update_status(daemon),
        ("POST", "/api/update/check") => handle_update_check(daemon),
        ("POST", "/api/update/apply") => handle_update_apply(daemon),
        ("POST", "/api/update/settings") => handle_update_settings(body, daemon),
        ("GET", "/api/mihomo-features") => handle_mihomo_features_get(daemon),
        ("POST", "/api/mihomo-features") => handle_mihomo_features_set(body, daemon),
        ("GET", "/api/mihomo-api/proxies") => handle_mihomo_api_proxies(daemon),
        ("GET", "/api/mihomo-api/connections") => handle_mihomo_api_connections(daemon),
        ("POST", "/api/mihomo-api/connections/page") => {
            handle_mihomo_api_connections_page(body, daemon)
        }
        ("POST", "/api/mihomo-api/connections/device-traffic") => {
            handle_mihomo_api_connections_device_traffic(body, daemon)
        }
        ("GET", "/api/mihomo-api/version") => handle_mihomo_api_forward_get("/version", daemon),
        ("GET", "/api/mihomo-api/configs") => handle_mihomo_api_forward_get("/configs", daemon),
        ("GET", "/api/mihomo-api/configs/geo") => {
            handle_mihomo_api_optional_forward_get("/configs/geo", daemon)
        }
        ("GET", "/api/mihomo-api/rules") => handle_mihomo_api_forward_get("/rules", daemon),
        ("GET", "/api/mihomo-api/providers/proxies") => {
            handle_mihomo_api_forward_get("/providers/proxies", daemon)
        }
        ("GET", "/api/mihomo-api/providers/rules") => {
            handle_mihomo_api_forward_get("/providers/rules", daemon)
        }
        ("POST", "/api/mihomo-api/cache/fakeip/flush") => {
            handle_mihomo_api_forward_post("/cache/fakeip/flush", "", daemon)
        }
        ("POST", "/api/mihomo-api/cache/dns/flush") => {
            handle_mihomo_api_forward_post("/cache/dns/flush", "", daemon)
        }
        ("POST", "/api/mihomo-api/rules/disable") => {
            handle_mihomo_api_optional_forward_post("/rules/disable", body, daemon)
        }
        ("POST", "/api/mihomo-api/connections/close") => {
            handle_mihomo_api_connections_close(body, daemon)
        }
        ("POST", "/api/mihomo-api/delay") => handle_mihomo_api_delay(body, daemon),
        ("GET", "/api/mihomo-api/traffic") => handle_mihomo_api_traffic(daemon),
        ("GET", "/api/mihomo-api/memory") => handle_mihomo_api_memory(daemon),
        ("GET", "/api/traffic") => handle_traffic_stats(daemon),
        ("GET", "/api/connection-log") => handle_connection_log(daemon),
        ("GET", "/api/device-routes") => handle_device_routes_list(daemon),
        ("POST", "/api/device-routes") => handle_device_routes_set(body, daemon),
        ("POST", "/api/device-routes/delete") => handle_device_routes_delete(body, daemon),
        ("GET", "/api/devices") => handle_devices_scan(daemon),
        ("POST", "/api/device-routes/apply") => handle_device_routes_apply(daemon),
        ("POST", "/api/mihomo-api/speed-test") => handle_speed_test(body, daemon),
        ("POST", "/api/unlock-check") => handle_unlock_check(body, daemon),
        ("GET", "/api/substore-lite") => handle_substore_lite_get(daemon),
        ("POST", "/api/substore-lite") => handle_substore_lite_set(body, daemon),
        ("POST", "/api/substore-lite/apply") => handle_substore_lite_apply(daemon),
        ("GET", "/api/backups") => handle_backups_list(daemon),
        ("POST", "/api/backups/create") => handle_backup_create(daemon),
        ("POST", "/api/backups/restore") => handle_backup_restore(body, daemon),
        ("POST", "/api/backups/delete") => handle_backup_delete(body, daemon),
        ("POST", "/api/backups/webdav-upload") => handle_backup_webdav_upload(body, daemon),
        ("POST", "/api/backups/webdav-download") => handle_backup_webdav_download(body, daemon),
        ("POST", "/api/auth/login") => handle_auth_login(body, daemon, peer_ip),
        ("POST", "/api/auth/logout") => handle_auth_logout(body, daemon),
        ("GET", "/api/auth-settings") => handle_auth_settings_get(daemon),
        ("POST", "/api/auth-settings") => handle_auth_settings_set(body, daemon),
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
    // Stored per-source outcome so we can update subscription metadata
    // after moving the profiles into `incoming`.
    enum StoredOutcome {
        Ok {
            count: usize,
            metadata: SubscriptionMetadata,
        },
        Failed {
            error: String,
        },
    }
    let mut loaded_subs: Vec<(SubscriptionSource, StoredOutcome)> = Vec::new();

    // Grab proxy fallback info under a short lock; network I/O below
    // runs without holding the mutex so the API stays responsive.
    let (proxy_info, hwid) = {
        let mut inner = lock(&daemon.inner);
        let hwid = inner.state.hwid_config.clone();
        (proxy_info_for_daemon(&mut inner), hwid)
    };

    for source in &parsed.subscriptions {
        let outcome = load_subscription_for_daemon(source, &proxy_info, &hwid);
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
                StoredOutcome::Ok {
                    count,
                    metadata: report.metadata,
                }
            }
            SubscriptionLoadOutcome::Failed { attempts } => {
                let error = SubscriptionLoadOutcome::format_error(&attempts);
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
                title: None,
                announcement: None,
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
            StoredOutcome::Ok { count, metadata } => {
                entry.last_loaded_unix = Some(now);
                entry.last_error = None;
                entry.profile_count = *count;
                apply_subscription_metadata(entry, metadata.clone());
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

    if let Err(error) = apply_active_profile(&mut inner, daemon, id) {
        return (
            error.http_status(),
            "application/json",
            json!({"error": error.message(), "profile_id": id}).to_string(),
        );
    }

    let response = json!({
        "active_profile_id": id,
        "active_profile_name": profile.name,
        "mihomo_config_path": daemon.mihomo_config_path.to_string_lossy(),
    });
    (200, "application/json", response.to_string())
}

fn handle_get_mihomo_config(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    let projection = GeoBaseProjection::Applied;
    match build_authoritative_daemon_config(&inner.state, daemon) {
        Ok(config_yaml) => redacted_config_response(projection, &config_yaml),
        Err(error) => (
            400,
            "application/json",
            json!({"error": error, "profile_id": inner.state.active_profile_id}).to_string(),
        ),
    }
}

fn handle_get_mihomo_config_preview(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    let projection = GeoBaseProjection::Desired;
    let providers = match project_geobase_rule_providers(
        daemon,
        projection,
        inner.state.split_routing.match_target.trim() == "direct",
    ) {
        Ok(providers) => providers,
        Err(error) => return json_error(400, &error),
    };
    match build_daemon_config(&inner.state, &providers) {
        Ok(config_yaml) => redacted_config_response(projection, &config_yaml),
        Err(error) => json_error(400, &error),
    }
}

fn redacted_config_response(
    projection: GeoBaseProjection,
    config_yaml: &str,
) -> (u16, &'static str, String) {
    match redact_config_yaml(config_yaml) {
        Ok(redacted) => (
            200,
            "text/yaml; charset=utf-8",
            format!(
                "# geobase-projection: {}\n# secrets: redacted\n{redacted}",
                projection.label()
            ),
        ),
        Err(error) => json_error(500, &format!("redact generated config: {error}")),
    }
}

fn redact_config_yaml(config_yaml: &str) -> Result<String, String> {
    let mut value: serde_yaml::Value =
        serde_yaml::from_str(config_yaml).map_err(|error| error.to_string())?;
    redact_mihomo_config(&mut value)?;
    serde_yaml::to_string(&value).map_err(|error| error.to_string())
}

fn redacted_yaml_value() -> serde_yaml::Value {
    serde_yaml::Value::String("<redacted>".to_owned())
}

fn redact_mihomo_config(value: &mut serde_yaml::Value) -> Result<(), String> {
    let mapping = value
        .as_mapping_mut()
        .ok_or_else(|| "generated Mihomo config root is not a mapping".to_owned())?;
    for (key, child) in mapping {
        let Some(key) = key.as_str() else {
            *child = redacted_yaml_value();
            continue;
        };
        match key.to_ascii_lowercase().as_str() {
            "proxies" => redact_yaml_sequence(child, redact_mihomo_proxy),
            "proxy-groups" => redact_yaml_sequence(child, redact_proxy_group),
            "proxy-providers" | "rule-providers" => redact_provider_map(child),
            "dns" => redact_dns_config(child),
            "tunnels" => redact_yaml_sequence(child, redact_tunnel),
            "ntp" => redact_mapping_fields(
                child,
                &[
                    "enable",
                    "write-to-system",
                    "port",
                    "interval",
                    "dialer-proxy",
                ],
            ),
            // These sections are generated from typed, non-credential settings.
            key if ROOT_DIAGNOSTIC_FIELDS.contains(&key) => {}
            // Unknown root fields are hidden until they are classified. This makes
            // newly generated credential fields fail closed rather than leak.
            _ => *child = redacted_yaml_value(),
        }
    }
    Ok(())
}

const ROOT_DIAGNOSTIC_FIELDS: &[&str] = &[
    "mode",
    "log-level",
    "allow-lan",
    "bind-address",
    "find-process-mode",
    "ipv6",
    "geo-auto-update",
    "socks-port",
    "listeners",
    "rules",
    "sub-rules",
    "sniffer",
    "geodata-loader",
    "unified-delay",
    "profile",
    "keep-alive-interval",
    "keep-alive-idle",
    "disable-keep-alive",
    "tcp-concurrent",
    "experimental",
    "skip-auth-prefixes",
    "hosts",
    "external-controller",
    "external-controller-cors",
];

fn redact_yaml_sequence(value: &mut serde_yaml::Value, redact_item: fn(&mut serde_yaml::Value)) {
    let Some(sequence) = value.as_sequence_mut() else {
        *value = redacted_yaml_value();
        return;
    };
    for item in sequence {
        redact_item(item);
    }
}

fn redact_mihomo_proxy(value: &mut serde_yaml::Value) {
    let Some(mapping) = value.as_mapping_mut() else {
        *value = redacted_yaml_value();
        return;
    };
    let proxy_type = mapping
        .get(serde_yaml::Value::String("type".to_owned()))
        .and_then(serde_yaml::Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    for (key, child) in mapping {
        let Some(key) = key.as_str() else {
            *child = redacted_yaml_value();
            continue;
        };
        let key = key.to_ascii_lowercase();
        match key.as_str() {
            "reality-opts" => {
                redact_mapping_fields(child, &["public-key", "support-x25519mlkem768"])
            }
            "xhttp-opts" => redact_xhttp_opts(child),
            "ws-opts" => redact_ws_opts(child),
            "grpc-opts" => redact_mapping_fields(
                child,
                &[
                    "grpc-service-name",
                    "grpc-user-agent",
                    "ping-interval",
                    "max-connections",
                    "min-streams",
                    "max-streams",
                ],
            ),
            "ech-opts" => redact_mapping_fields(child, &["enable", "config", "query-server-name"]),
            "smux" => redact_smux(child),
            "obfs-opts" => redact_mapping_fields(child, &["mode", "host"]),
            key if proxy_field_is_diagnostic(&proxy_type, key) => {}
            _ => *child = redacted_yaml_value(),
        }
    }
}

fn proxy_field_is_diagnostic(proxy_type: &str, key: &str) -> bool {
    const COMMON: &[&str] = &[
        "name",
        "type",
        "server",
        "port",
        "udp",
        "tfo",
        "mptcp",
        "ip-version",
        "dialer-proxy",
        "tls",
        "sni",
        "servername",
        "fingerprint",
        "client-fingerprint",
        "skip-cert-verify",
        "alpn",
        "network",
        "fast-open",
    ];
    if COMMON.contains(&key) {
        return true;
    }
    let protocol_fields: &[&str] = match proxy_type {
        "vless" => &["flow", "packet-encoding"],
        "vmess" => &["alterid", "cipher", "packet-encoding"],
        "trojan" => &[],
        "ss" => &["cipher"],
        "ssr" => &["cipher", "obfs", "protocol"],
        "snell" => &["version", "reuse"],
        "http" | "socks4" | "socks5" => &[],
        "anytls" => &[
            "idle-session-check-interval",
            "idle-session-timeout",
            "min-idle-session",
        ],
        // Hysteria v1 `obfs` is a shared secret, not merely a mode.
        "hysteria" => &[
            "ports",
            "protocol",
            "up",
            "down",
            "recv-window-conn",
            "recv-window",
            "disable_mtu_discovery",
        ],
        "hysteria2" => &["up", "down", "obfs", "ports", "hop-interval"],
        "wireguard" => &[
            "public-key",
            "ip",
            "ipv6",
            "allowed-ips",
            "reserved",
            "mtu",
            "persistent-keepalive",
        ],
        "tuic" => &[
            "ip",
            "disable-sni",
            "reduce-rtt",
            "request-timeout",
            "udp-relay-mode",
            "congestion-controller",
            "max-udp-relay-packet-size",
            "heartbeat-interval",
            "max-open-streams",
        ],
        "ssh" => &["host-key", "host-key-algorithms"],
        "masque" => &[
            "public-key",
            "ip",
            "ipv6",
            "mtu",
            "remote-dns-resolve",
            "dns",
            "congestion-controller",
            "bbr-profile",
        ],
        "openvpn" => &[
            "ca",
            "proto",
            "ping",
            "ping-restart",
            "dev",
            "cipher",
            "auth",
            "comp-lzo",
            "mtu",
            "remote-dns-resolve",
            "dns",
        ],
        "tailscale" => &[
            "hostname",
            "state-dir",
            "ephemeral",
            "accept-routes",
            "exit-node",
            "exit-node-allow-lan-access",
        ],
        _ => &[],
    };
    protocol_fields.contains(&key)
}

fn redact_xhttp_opts(value: &mut serde_yaml::Value) {
    let Some(mapping) = value.as_mapping_mut() else {
        *value = redacted_yaml_value();
        return;
    };
    for (key, child) in mapping {
        let key = key
            .as_str()
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();
        match key.as_str() {
            "reuse-settings" => redact_mapping_fields(
                child,
                &[
                    "max-concurrency",
                    "max-connections",
                    "c-max-reuse-times",
                    "h-max-request-times",
                    "h-max-reusable-secs",
                    "h-keep-alive-period",
                ],
            ),
            "host"
            | "mode"
            | "no-grpc-header"
            | "x-padding-bytes"
            | "x-padding-obfs-mode"
            | "x-padding-header"
            | "x-padding-placement"
            | "x-padding-method"
            | "uplink-http-method"
            | "session-placement"
            | "seq-placement"
            | "uplink-data-placement"
            | "uplink-chunk-size"
            | "sc-max-each-post-bytes"
            | "sc-min-posts-interval-ms" => {}
            _ => *child = redacted_yaml_value(),
        }
    }
}

fn redact_ws_opts(value: &mut serde_yaml::Value) {
    let Some(mapping) = value.as_mapping_mut() else {
        *value = redacted_yaml_value();
        return;
    };
    for (key, child) in mapping {
        let key = key
            .as_str()
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();
        match key.as_str() {
            "headers" => redact_mapping_fields(child, &["host"]),
            "max-early-data"
            | "early-data-header-name"
            | "v2ray-http-upgrade"
            | "v2ray-http-upgrade-fast-open" => {}
            _ => *child = redacted_yaml_value(),
        }
    }
}

fn redact_smux(value: &mut serde_yaml::Value) {
    let Some(mapping) = value.as_mapping_mut() else {
        *value = redacted_yaml_value();
        return;
    };
    for (key, child) in mapping {
        let key = key
            .as_str()
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();
        match key.as_str() {
            "brutal-opts" => redact_mapping_fields(child, &["enabled", "up", "down"]),
            "enabled" | "protocol" | "statistic" | "only-tcp" | "padding" | "max-connections"
            | "min-streams" | "max-streams" => {}
            _ => *child = redacted_yaml_value(),
        }
    }
}

fn redact_proxy_group(value: &mut serde_yaml::Value) {
    redact_mapping_fields(
        value,
        &[
            "name",
            "type",
            "proxies",
            "use",
            "interval",
            "timeout",
            "lazy",
            "max-failed-times",
            "tolerance",
            "strategy",
            "expected-status",
            "filter",
            "exclude-filter",
            "exclude-type",
            "include-all-providers",
            "include-all",
            "include-all-proxies",
        ],
    );
}

fn redact_provider_map(value: &mut serde_yaml::Value) {
    let Some(providers) = value.as_mapping_mut() else {
        *value = redacted_yaml_value();
        return;
    };
    for (_, provider) in providers {
        let Some(mapping) = provider.as_mapping_mut() else {
            *provider = redacted_yaml_value();
            continue;
        };
        for (key, child) in mapping {
            let key = key
                .as_str()
                .map(str::to_ascii_lowercase)
                .unwrap_or_default();
            match key.as_str() {
                "health-check" => redact_mapping_fields(
                    child,
                    &["enable", "interval", "timeout", "lazy", "expected-status"],
                ),
                "type" | "path" | "interval" | "proxy" | "filter" | "exclude-filter"
                | "exclude-type" | "behavior" | "format" | "path-in-bundle" | "size-limit" => {}
                // URL, age-secret-key, header, payload, and future provider fields
                // are credential-bearing by contract and therefore fail closed.
                _ => *child = redacted_yaml_value(),
            }
        }
    }
}

fn redact_tunnel(value: &mut serde_yaml::Value) {
    redact_mapping_fields(value, &["network", "address", "proxy"]);
}

fn redact_dns_config(value: &mut serde_yaml::Value) {
    let Some(mapping) = value.as_mapping_mut() else {
        *value = redacted_yaml_value();
        return;
    };
    for (key, child) in mapping {
        let key = key
            .as_str()
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();
        match key.as_str() {
            "nameserver"
            | "fallback"
            | "default-nameserver"
            | "proxy-server-nameserver"
            | "direct-nameserver" => redact_yaml_values(child),
            "nameserver-policy" | "proxy-server-nameserver-policy" => {
                let Some(policy) = child.as_mapping_mut() else {
                    *child = redacted_yaml_value();
                    continue;
                };
                for (_, servers) in policy {
                    redact_yaml_values(servers);
                }
            }
            "enable"
            | "listen"
            | "enhanced-mode"
            | "fake-ip-range"
            | "fake-ip-filter"
            | "cache-algorithm"
            | "ipv6"
            | "prefer-h3"
            | "fake-ip-filter-mode"
            | "fake-ip-ttl"
            | "use-hosts"
            | "use-system-hosts"
            | "respect-rules"
            | "direct-nameserver-follow-policy"
            | "ecs"
            | "ecs-override"
            | "disable-ipv4"
            | "disable-ipv6" => {}
            "fallback-filter" => redact_mapping_fields(
                child,
                &["geoip", "geoip-code", "geosite", "ipcidr", "domain"],
            ),
            key if key.starts_with("disable-qtype-") => {}
            _ => *child = redacted_yaml_value(),
        }
    }
}

fn redact_yaml_values(value: &mut serde_yaml::Value) {
    if let Some(sequence) = value.as_sequence_mut() {
        for item in sequence {
            *item = redacted_yaml_value();
        }
    } else {
        *value = redacted_yaml_value();
    }
}

fn redact_mapping_fields(value: &mut serde_yaml::Value, diagnostic_fields: &[&str]) {
    let Some(mapping) = value.as_mapping_mut() else {
        *value = redacted_yaml_value();
        return;
    };
    for (key, child) in mapping {
        let key = key
            .as_str()
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();
        if !diagnostic_fields.contains(&key.as_str()) {
            *child = redacted_yaml_value();
        }
    }
}

fn handle_mihomo_config_validate(daemon: &Daemon) -> (u16, &'static str, String) {
    let (config_result, mihomo_path, geo_dir) = {
        let inner = lock(&daemon.inner);
        (
            build_authoritative_daemon_config(&inner.state, daemon),
            inner.state.mihomo_path.clone(),
            geo_dir_from_state(&inner.state),
        )
    };
    match config_result {
        Ok(config_yaml) => {
            let result =
                validate_mihomo_config_yaml(&mihomo_path, &config_yaml, geo_dir.as_deref());
            (200, "application/json", result.to_string())
        }
        Err(error) => (
            400,
            "application/json",
            json!({"ok": false, "supported": true, "stage": "generate", "error": error})
                .to_string(),
        ),
    }
}

fn validate_mihomo_config_yaml(
    binary_path: &str,
    config_yaml: &str,
    geo_dir: Option<&str>,
) -> Value {
    validate_mihomo_config_yaml_with_timeout(
        binary_path,
        config_yaml,
        geo_dir,
        MIHOMO_VALIDATE_TIMEOUT,
    )
}

fn validate_mihomo_config_yaml_with_timeout(
    binary_path: &str,
    config_yaml: &str,
    geo_dir: Option<&str>,
    timeout: Duration,
) -> Value {
    let temp_path = unique_temp_path("hincyray-validate", "yaml");
    if let Err(error) = fs::write(&temp_path, config_yaml) {
        return json!({"ok": false, "supported": true, "stage": "write-temp", "error": error.to_string()});
    }
    let mut cmd = Command::new(binary_path);
    cmd.env("GOMEMLIMIT", MIHOMO_VALIDATE_MEMORY_LIMIT)
        .env("GOGC", MIHOMO_VALIDATE_GOGC)
        .arg("-t")
        .arg("-f")
        .arg(&temp_path);
    if let Some(dir) = geo_dir.filter(|d| !d.is_empty()) {
        cmd.arg("-d").arg(dir);
    }
    let output = run_bounded_command(cmd, timeout);
    let _ = fs::remove_file(&temp_path);
    match output {
        BoundedCommandResult::Completed {
            success,
            exit_code,
            stdout,
            stderr,
        } => {
            let text = format!("{stdout}\n{stderr}").to_ascii_lowercase();
            let unsupported = !success
                && (text.contains("unknown shorthand flag")
                    || text.contains("flag provided but not defined")
                    || text.contains("unknown command"));
            json!({
                "ok": success,
                "supported": !unsupported,
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
            })
        }
        BoundedCommandResult::TimedOut { stdout, stderr } => json!({
            "ok": false,
            "supported": true,
            "timeout": true,
            "timeout_secs": timeout.as_secs_f64(),
            "stdout": stdout,
            "stderr": stderr,
            "error": "mihomo config validation timed out and was terminated",
        }),
        BoundedCommandResult::SpawnError(error) if error.kind() == std::io::ErrorKind::NotFound => {
            json!({
                "ok": false,
                "supported": false,
                "error": format!("mihomo binary not found: {binary_path}"),
            })
        }
        BoundedCommandResult::SpawnError(error) => {
            json!({"ok": false, "supported": true, "error": error.to_string()})
        }
    }
}

enum BoundedCommandResult {
    Completed {
        success: bool,
        exit_code: Option<i32>,
        stdout: String,
        stderr: String,
    },
    TimedOut {
        stdout: String,
        stderr: String,
    },
    SpawnError(std::io::Error),
}

fn unique_temp_path(prefix: &str, extension: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let thread_id = format!("{:?}", thread::current().id())
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>();
    std::env::temp_dir().join(format!(
        "{prefix}-{}-{thread_id}-{nanos}.{extension}",
        std::process::id()
    ))
}

fn run_bounded_command(mut cmd: Command, timeout: Duration) -> BoundedCommandResult {
    let stdout_path = unique_temp_path("hincyray-command-stdout", "log");
    let stderr_path = unique_temp_path("hincyray-command-stderr", "log");
    let stdout_file = match fs::File::create(&stdout_path) {
        Ok(file) => file,
        Err(error) => return BoundedCommandResult::SpawnError(error),
    };
    let stderr_file = match fs::File::create(&stderr_path) {
        Ok(file) => file,
        Err(error) => {
            let _ = fs::remove_file(&stdout_path);
            return BoundedCommandResult::SpawnError(error);
        }
    };
    cmd.stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file));
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = fs::remove_file(&stdout_path);
            let _ = fs::remove_file(&stderr_path);
            return BoundedCommandResult::SpawnError(error);
        }
    };
    let started = SystemTime::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = read_limited_trimmed(&stdout_path);
                let stderr = read_limited_trimmed(&stderr_path);
                let _ = fs::remove_file(&stdout_path);
                let _ = fs::remove_file(&stderr_path);
                return BoundedCommandResult::Completed {
                    success: status.success(),
                    exit_code: status.code(),
                    stdout,
                    stderr,
                };
            }
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = fs::remove_file(&stdout_path);
                let _ = fs::remove_file(&stderr_path);
                return BoundedCommandResult::SpawnError(error);
            }
        }
        let elapsed = started.elapsed().unwrap_or_default();
        if elapsed >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            let stdout = read_limited_trimmed(&stdout_path);
            let stderr = read_limited_trimmed(&stderr_path);
            let _ = fs::remove_file(&stdout_path);
            let _ = fs::remove_file(&stderr_path);
            return BoundedCommandResult::TimedOut { stdout, stderr };
        }
        let remaining = timeout.saturating_sub(elapsed);
        thread::sleep(remaining.min(Duration::from_millis(20)));
    }
}

fn read_limited_trimmed(path: &Path) -> String {
    let mut output = Vec::new();
    if let Ok(file) = fs::File::open(path) {
        let _ = file
            .take(COMMAND_OUTPUT_LIMIT_BYTES)
            .read_to_end(&mut output);
    }
    String::from_utf8_lossy(&output).trim().to_owned()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GeoBaseProjection {
    Desired,
    Applied,
}

impl GeoBaseProjection {
    fn label(self) -> &'static str {
        match self {
            Self::Desired => "desired",
            Self::Applied => "applied",
        }
    }
}

fn project_geobase_rule_providers(
    daemon: &Daemon,
    projection: GeoBaseProjection,
    include_active: bool,
) -> Result<Vec<GeoBaseRuleProvider>, String> {
    let manifest = daemon
        .geobase_store()
        .load_manifest()
        .map_err(|error| format!("GeoBase manifest: {error}"))?;
    project_geobase_manifest(daemon, &manifest, projection, include_active)
}

fn project_geobase_manifest(
    daemon: &Daemon,
    manifest: &geobase::GeoBaseManifest,
    projection: GeoBaseProjection,
    include_active: bool,
) -> Result<Vec<GeoBaseRuleProvider>, String> {
    let bases = match projection {
        GeoBaseProjection::Desired => &manifest.bases,
        GeoBaseProjection::Applied => &manifest.applied_bases,
    };
    if !bases.iter().any(|record| record.enabled) {
        return Ok(Vec::new());
    }

    let canonical_root = fs::canonicalize(&daemon.geobase_store_root)
        .map_err(|error| format!("GeoBase store root: {error}"))?;
    let mut providers = Vec::new();
    for record in bases.iter().filter(|record| record.enabled) {
        if record.status != GeoBaseStatus::Ready {
            return Err(format!(
                "enabled GeoBase {} is not ready ({:?})",
                record.id, record.status
            ));
        }

        let active = resolve_geobase_artifact(
            &canonical_root,
            &daemon.geobase_store_root,
            &record.lists.active,
            GeoBaseArtifactKind::Domain,
        )?;
        let direct = resolve_geobase_artifact(
            &canonical_root,
            &daemon.geobase_store_root,
            &record.lists.direct,
            GeoBaseArtifactKind::Domain,
        )?;
        let _unresolved = resolve_geobase_artifact(
            &canonical_root,
            &daemon.geobase_store_root,
            &record.lists.unresolved,
            GeoBaseArtifactKind::Domain,
        )?;

        if include_active && record.lists.active.count > 0 {
            providers.push(GeoBaseRuleProvider {
                enabled: true,
                name: geobase_provider_name(&record.id, "a"),
                path: active,
                behavior: GeoBaseRuleBehavior::Domain,
                target: GeoBaseRuleTarget::Active,
            });
        }
        if record.lists.direct.count > 0 {
            providers.push(GeoBaseRuleProvider {
                enabled: true,
                name: geobase_provider_name(&record.id, "d"),
                path: direct,
                behavior: GeoBaseRuleBehavior::Domain,
                target: GeoBaseRuleTarget::Direct,
            });
        }
        for (metadata, suffix, target) in [
            (
                record.lists.static_active.as_ref(),
                "sa",
                GeoBaseRuleTarget::Active,
            ),
            (
                record.lists.static_direct.as_ref(),
                "sd",
                GeoBaseRuleTarget::Direct,
            ),
        ] {
            let Some(metadata) = metadata else {
                continue;
            };
            let path = resolve_geobase_artifact(
                &canonical_root,
                &daemon.geobase_store_root,
                metadata,
                GeoBaseArtifactKind::Ipcidr,
            )?;
            if metadata.count > 0 {
                providers.push(GeoBaseRuleProvider {
                    enabled: true,
                    name: geobase_provider_name(&record.id, suffix),
                    path,
                    behavior: GeoBaseRuleBehavior::Ipcidr,
                    target,
                });
            }
        }
    }
    Ok(providers)
}

fn geobase_provider_name(record_id: &str, suffix: &str) -> String {
    format!("{}-{suffix}", geobase::stable_id(record_id))
}

fn resolve_geobase_artifact(
    canonical_root: &Path,
    store_root: &Path,
    metadata: &GeoBaseListMetadata,
    kind: GeoBaseArtifactKind,
) -> Result<String, String> {
    let configured_path = store_root.join(&metadata.file);
    let canonical_path = fs::canonicalize(&configured_path).map_err(|error| {
        format!(
            "GeoBase artifact {} is missing or inaccessible: {error}",
            metadata.file
        )
    })?;
    if !canonical_path.starts_with(canonical_root) || !canonical_path.is_file() {
        return Err(format!(
            "GeoBase artifact {} resolves outside the store or is not a file",
            metadata.file
        ));
    }
    let content = fs::read(&canonical_path)
        .map_err(|error| format!("GeoBase artifact {}: {error}", metadata.file))?;
    if metadata.fingerprint.is_empty() {
        return Err(format!(
            "GeoBase artifact {} has no required fnv1a64 fingerprint",
            metadata.file
        ));
    }
    let actual_fingerprint = geobase::artifact_fingerprint(&content);
    if actual_fingerprint != metadata.fingerprint {
        return Err(format!(
            "GeoBase artifact {} fingerprint mismatch: got {actual_fingerprint}, expected {}",
            metadata.file, metadata.fingerprint
        ));
    }
    let actual_count = geobase::validate_artifact(&content, kind)
        .map_err(|error| format!("GeoBase artifact {} is invalid: {error}", metadata.file))?;
    if actual_count != metadata.count {
        return Err(format!(
            "GeoBase artifact {} has {actual_count} entries, manifest expects {}",
            metadata.file, metadata.count
        ));
    }
    canonical_path.to_str().map(str::to_owned).ok_or_else(|| {
        format!(
            "GeoBase artifact path is not valid UTF-8: {}",
            metadata.file
        )
    })
}

fn build_authoritative_daemon_config(
    state: &HincyrayState,
    daemon: &Daemon,
) -> Result<String, String> {
    let providers = project_geobase_rule_providers(
        daemon,
        GeoBaseProjection::Applied,
        state.split_routing.match_target.trim() == "direct",
    )?;
    build_daemon_config(state, &providers)
}

fn config_plan(
    state: &HincyrayState,
    daemon: &Daemon,
    projection: GeoBaseProjection,
) -> Result<(String, u64, Vec<geobase::GeoBaseRecord>), String> {
    let manifest = daemon
        .geobase_store()
        .load_manifest()
        .map_err(|error| format!("GeoBase manifest: {error}"))?;
    let (generation, bases) = match projection {
        GeoBaseProjection::Desired => (manifest.generation, manifest.bases.clone()),
        GeoBaseProjection::Applied => (manifest.applied_generation, manifest.applied_bases.clone()),
    };
    let providers = project_geobase_manifest(
        daemon,
        &manifest,
        projection,
        state.split_routing.match_target.trim() == "direct",
    )?;
    let config = build_daemon_config(state, &providers)?;
    Ok((config, generation, bases))
}

/// Regenerate the Mihomo config and write it to the daemon's config
/// path. Returns the binary path and config path so the caller can start
/// the core.
fn regenerate_config(state: &HincyrayState, daemon: &Daemon) -> Result<(String, PathBuf), String> {
    let config_yaml = build_authoritative_daemon_config(state, daemon)?;
    let config_path = daemon.mihomo_config_path.clone();
    atomic_write_config(&config_path, config_yaml.as_bytes())?;
    Ok((state.mihomo_path.clone(), config_path))
}

#[derive(Clone, Debug)]
struct ActivationResult {
    core_status: String,
    firewall_status: String,
    generation: u64,
    gc_warning: Option<String>,
}

fn validation_error(result: &Value) -> String {
    result
        .get("error")
        .and_then(Value::as_str)
        .or_else(|| result.get("stderr").and_then(Value::as_str))
        .filter(|message| !message.is_empty())
        .unwrap_or("mihomo rejected config")
        .to_owned()
}

fn wait_for_core_readiness(
    daemon: &Daemon,
    controller: Option<&(String, Option<String>)>,
) -> Result<(), String> {
    let started = Instant::now();
    let deadline = started + Duration::from_secs(6);
    let mut controller_ready = controller.is_none();
    loop {
        {
            let mut inner = lock(&daemon.inner);
            if !inner.core.is_running() {
                return Err("mihomo exited during readiness observation".to_owned());
            }
        }
        if !controller_ready
            && let Some((address, secret)) = controller
            && mihomo_api_get(address, secret.as_deref(), "/version").is_ok()
        {
            controller_ready = true;
        }
        if started.elapsed() >= Duration::from_secs(2) && controller_ready {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(if controller_ready {
                "mihomo did not remain running for 2 seconds".to_owned()
            } else {
                "mihomo external controller did not become ready".to_owned()
            });
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn hot_reload_mihomo_config(
    controller: &(String, Option<String>),
    config_path: &Path,
) -> Result<(), String> {
    let body = json!({"path": config_path.to_string_lossy()}).to_string();
    mihomo_api_put(
        &controller.0,
        controller.1.as_deref(),
        "/configs?force=true",
        Some(&body),
    )
}

fn restore_previous_activation(
    daemon: &Daemon,
    previous_config: Option<&[u8]>,
    previous_running: bool,
    state: &HincyrayState,
    firewall_was_running: bool,
) -> String {
    let config_result = match previous_config {
        Some(bytes) => atomic_write_config(&daemon.mihomo_config_path, bytes),
        None => match fs::remove_file(&daemon.mihomo_config_path) {
            Ok(()) => daemon
                .mihomo_config_path
                .parent()
                .ok_or_else(|| "config path has no parent".to_owned())
                .and_then(|parent| {
                    fs::File::open(parent)
                        .and_then(|directory| directory.sync_all())
                        .map_err(|error| error.to_string())
                }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.to_string()),
        },
    };
    let geo_dir = geo_dir_from_state(state);
    let core_result = {
        let mut inner = lock(&daemon.inner);
        if previous_running && previous_config.is_some() {
            let controller = mihomo_controller(&state.mihomo_features);
            if inner.core.is_running()
                && let Some(controller) = controller.as_ref()
            {
                hot_reload_mihomo_config(controller, &daemon.mihomo_config_path)
            } else {
                inner.core.restart(
                    &state.mihomo_path,
                    &daemon.mihomo_config_path,
                    geo_dir.as_deref(),
                )
            }
        } else {
            inner.core.stop()
        }
    };
    let firewall_result = {
        let mut inner = lock(&daemon.inner);
        let expected_running = firewall_was_running && state.split_routing.enabled;
        let contract_matches = inner.firewall.active == expected_running
            && (!expected_running
                || (inner.firewall.redirect_port == Some(state.split_routing.redirect_port)
                    && inner.firewall.vpn_subnet.as_deref()
                        == Some(state.split_routing.vpn_subnet.as_str())
                    && inner.firewall.policy_name.as_deref()
                        == Some(state.split_routing.policy_name.as_str())
                    && inner.firewall.policy_mark.as_deref()
                        == state.split_routing.policy_mark.as_deref()));
        if contract_matches {
            Ok(())
        } else if expected_running {
            let _ = inner.firewall.stop(&state.split_routing.vpn_subnet);
            inner.firewall.start(
                state.split_routing.redirect_port,
                &state.split_routing.vpn_subnet,
                &state.split_routing.policy_name,
                state.split_routing.policy_mark.as_deref(),
            )
        } else {
            let _ = inner.firewall.stop(&state.split_routing.vpn_subnet);
            Ok(())
        }
    };
    format!(
        "config={}, core={}, firewall={}",
        result_label(&config_result),
        result_label(&core_result),
        result_label(&firewall_result)
    )
}

fn result_label(result: &Result<(), String>) -> String {
    match result {
        Ok(()) => "restored".to_owned(),
        Err(error) => format!("failed ({error})"),
    }
}

fn acknowledge_activation(
    daemon: &Daemon,
    generation: u64,
    activated_bases: Vec<geobase::GeoBaseRecord>,
) -> Result<Option<String>, String> {
    daemon
        .geobase_store()
        .commit_applied_snapshot(generation, activated_bases)
        .map_err(|error| format!("mark GeoBase generation {generation} applied: {error}"))?;
    Ok(daemon
        .geobase_store()
        .garbage_collect()
        .err()
        .map(|error| format!("GeoBase garbage collection: {error}")))
}

fn activate_current_config(
    daemon: &Daemon,
    start_if_stopped: bool,
    configure_firewall: bool,
    projection: GeoBaseProjection,
) -> Result<ActivationResult, String> {
    let _apply = daemon
        .apply
        .lock()
        .map_err(|_| "config apply lock is poisoned".to_owned())?;
    activate_current_config_locked(daemon, start_if_stopped, configure_firewall, projection)
}

fn activate_current_config_locked(
    daemon: &Daemon,
    start_if_stopped: bool,
    configure_firewall: bool,
    projection: GeoBaseProjection,
) -> Result<ActivationResult, String> {
    let (state, previous_running, firewall_was_running) = {
        let mut inner = lock(&daemon.inner);
        (
            inner.state.clone(),
            inner.core.is_running(),
            inner.firewall.is_running(),
        )
    };
    let (mut config_yaml, generation, activated_bases) = config_plan(&state, daemon, projection)?;
    write_parovozik_provider_files(&state)?;
    let geo_dir = geo_dir_from_state(&state);
    let validation =
        validate_mihomo_config_yaml(&state.mihomo_path, &config_yaml, geo_dir.as_deref());
    if validation.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(format!(
            "config validation failed: {}",
            validation_error(&validation)
        ));
    }
    let previous_config = match fs::read(&daemon.mihomo_config_path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(format!("read previous config: {error}")),
    };
    atomic_write_config(&daemon.mihomo_config_path, config_yaml.as_bytes())?;

    let should_run = previous_running || start_if_stopped;
    let controller = mihomo_controller(&state.mihomo_features);
    let activation = (|| -> Result<(String, String), String> {
        if should_run {
            if previous_running && let Some(controller) = controller.as_ref() {
                hot_reload_mihomo_config(controller, &daemon.mihomo_config_path)?;
            } else {
                let mut inner = lock(&daemon.inner);
                inner.core.restart(
                    &state.mihomo_path,
                    &daemon.mihomo_config_path,
                    geo_dir.as_deref(),
                )?;
            }
            wait_for_core_readiness(daemon, controller.as_ref())?;
        }

        let firewall_status = if configure_firewall {
            let mut final_state = state.clone();
            let firewall_contract_changed = {
                let inner = lock(&daemon.inner);
                !inner.firewall.active
                    || inner.firewall.redirect_port != Some(state.split_routing.redirect_port)
                    || inner.firewall.vpn_subnet.as_deref()
                        != Some(state.split_routing.vpn_subnet.as_str())
                    || inner.firewall.policy_name.as_deref()
                        != Some(state.split_routing.policy_name.as_str())
                    || inner.firewall.policy_mark.as_deref()
                        != state.split_routing.policy_mark.as_deref()
                    || state.split_routing.tproxy_available != inner.firewall.tproxy_available
            };
            if state.split_routing.enabled && firewall_contract_changed {
                let mut inner = lock(&daemon.inner);
                let _ = inner.firewall.stop(&state.split_routing.vpn_subnet);
                inner.firewall.start(
                    state.split_routing.redirect_port,
                    &state.split_routing.vpn_subnet,
                    &state.split_routing.policy_name,
                    state.split_routing.policy_mark.as_deref(),
                )?;
                final_state.split_routing.policy_mark = inner.firewall.policy_mark.clone();
                final_state.split_routing.tproxy_available = inner.firewall.tproxy_available;
                inner.state.split_routing.policy_mark =
                    final_state.split_routing.policy_mark.clone();
                inner.state.split_routing.tproxy_available =
                    final_state.split_routing.tproxy_available;
                inner.dirty = true;
            } else if !state.split_routing.enabled {
                let mut inner = lock(&daemon.inner);
                if inner.firewall.active {
                    let _ = inner.firewall.stop(&state.split_routing.vpn_subnet);
                }
            }
            if final_state.split_routing.enabled
                && final_state.split_routing.tproxy_available
                    != state.split_routing.tproxy_available
            {
                let providers = project_geobase_rule_providers(
                    daemon,
                    projection,
                    final_state.split_routing.match_target.trim() == "direct",
                )?;
                config_yaml = build_daemon_config(&final_state, &providers)?;
                let validation = validate_mihomo_config_yaml(
                    &final_state.mihomo_path,
                    &config_yaml,
                    geo_dir.as_deref(),
                );
                if validation.get("ok").and_then(Value::as_bool) != Some(true) {
                    return Err(format!(
                        "final firewall config validation failed: {}",
                        validation_error(&validation)
                    ));
                }
                atomic_write_config(&daemon.mihomo_config_path, config_yaml.as_bytes())?;
                if should_run {
                    if previous_running && let Some(controller) = controller.as_ref() {
                        hot_reload_mihomo_config(controller, &daemon.mihomo_config_path)?;
                    } else {
                        let mut inner = lock(&daemon.inner);
                        inner.core.restart(
                            &final_state.mihomo_path,
                            &daemon.mihomo_config_path,
                            geo_dir.as_deref(),
                        )?;
                    }
                    wait_for_core_readiness(daemon, controller.as_ref())?;
                }
            }
            if state.split_routing.enabled {
                "running".to_owned()
            } else {
                "stopped".to_owned()
            }
        } else {
            let inner = lock(&daemon.inner);
            if inner.firewall.active {
                "running".to_owned()
            } else {
                "stopped".to_owned()
            }
        };
        let core_status = if should_run { "running" } else { "stopped" }.to_owned();
        Ok((core_status, firewall_status))
    })();

    let (core_status, firewall_status) = match activation {
        Ok(result) => result,
        Err(error) => {
            let rollback = restore_previous_activation(
                daemon,
                previous_config.as_deref(),
                previous_running,
                &state,
                firewall_was_running,
            );
            return Err(format!("{error}; rollback: {rollback}"));
        }
    };
    let gc_warning = if projection == GeoBaseProjection::Desired {
        match acknowledge_activation(daemon, generation, activated_bases) {
            Ok(warning) => warning,
            Err(error) => {
                let rollback = restore_previous_activation(
                    daemon,
                    previous_config.as_deref(),
                    previous_running,
                    &state,
                    firewall_was_running,
                );
                return Err(format!("{error}; rollback: {rollback}"));
            }
        }
    } else {
        None
    };
    Ok(ActivationResult {
        core_status,
        firewall_status,
        generation,
        gc_warning,
    })
}

fn handle_core_start(daemon: &Daemon) -> (u16, &'static str, String) {
    match activate_current_config(daemon, true, false, GeoBaseProjection::Applied) {
        Ok(result) => (
            200,
            "application/json",
            json!({"core_status": result.core_status, "generation": result.generation}).to_string(),
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
    match activate_current_config(daemon, true, false, GeoBaseProjection::Applied) {
        Ok(result) => (
            200,
            "application/json",
            json!({"core_status": result.core_status, "generation": result.generation}).to_string(),
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
                "supported": ["tcp", "head", "get", "quick"],
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
    let upload_url = value
        .get("upload_url")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(DEFAULT_UPLOAD_URL)
        .to_owned();
    let test_download = value
        .get("test_download")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let test_upload = value
        .get("test_upload")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    // Decide benchmark scope under the state lock. Subscription membership is
    // resolved by the daemon so browser filtering/collapse/reindexing cannot
    // widen or narrow the group test. Normal scopes exclude Dead Servers;
    // explicit ids remain available for deliberate single-server diagnostics.
    let subscription_url = value
        .get("subscription_url")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(str::to_owned);
    let requested_ids = match value.get("profile_ids") {
        None => None,
        Some(Value::Array(values)) => {
            let mut ids = Vec::with_capacity(values.len());
            for value in values {
                let Some(id) = value.as_u64().and_then(|id| usize::try_from(id).ok()) else {
                    return json_error(400, "profile_ids must contain only non-negative integers");
                };
                ids.push(id);
            }
            Some(ids)
        }
        Some(_) => return json_error(400, "profile_ids must be an array"),
    };
    if subscription_url.is_some() && requested_ids.is_some() {
        return json_error(
            400,
            "subscription_url and profile_ids are mutually exclusive",
        );
    }

    let (profiles, core_path) = {
        let inner = lock(&daemon.inner);
        if inner.bench.is_running() {
            return (
                409,
                "application/json",
                json!({"error": "benchmark already running; call /api/bench/stop first"})
                    .to_string(),
            );
        }
        let profiles = match select_profiles_for_quick_bench(
            &inner.state,
            subscription_url.as_deref(),
            requested_ids.as_deref(),
        ) {
            Ok(profiles) => profiles,
            Err((status, error)) => return json_error(status, &error),
        };
        let core_path = benchmark_mihomo_path(&inner.state.mihomo_path);
        (profiles, core_path)
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
    let quick_probe = (method == BenchMethod::Quick).then(|| QuickProbeConfig {
        telegram_session_path: telegram_session_path(&daemon.state_path)
            .to_string_lossy()
            .into_owned(),
        telegram: load_telegram_config(&telegram_config_path(&daemon.state_path)).ok(),
    });

    let handle = run_bench(
        profiles,
        method,
        probe_url,
        download_url,
        upload_url,
        core_path,
        quick_probe,
        test_download,
        test_upload,
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

fn select_profiles_for_quick_bench(
    state: &HincyrayState,
    subscription_url: Option<&str>,
    requested_ids: Option<&[usize]>,
) -> Result<Vec<Profile>, (u16, String)> {
    if subscription_url.is_some() && requested_ids.is_some() {
        return Err((
            400,
            "subscription_url and profile_ids are mutually exclusive".to_owned(),
        ));
    }
    if let Some(url) = subscription_url {
        if !state.subscriptions.iter().any(|source| source.url == url) {
            return Err((404, "subscription not found".to_owned()));
        }
        return Ok(state
            .profiles
            .iter()
            .filter(|profile| {
                profile.group.as_deref() == Some(url) && !profile_is_dead(state, profile)
            })
            .cloned()
            .collect());
    }
    if let Some(ids) = requested_ids {
        if ids.is_empty() {
            return Err((400, "profile_ids must not be empty".to_owned()));
        }
        let requested: HashSet<usize> = ids.iter().copied().collect();
        if let Some(missing) = requested
            .iter()
            .find(|id| !state.profiles.iter().any(|profile| profile.id == **id))
        {
            return Err((404, format!("profile not found: {missing}")));
        }
        return Ok(state
            .profiles
            .iter()
            .filter(|profile| requested.contains(&profile.id))
            .cloned()
            .collect());
    }
    Ok(state
        .profiles
        .iter()
        .filter(|profile| !profile_is_dead(state, profile))
        .cloned()
        .collect())
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

fn handle_telegram_probe_status(daemon: &Daemon) -> (u16, &'static str, String) {
    let config_path = telegram_config_path(&daemon.state_path);
    let session_path = telegram_session_path(&daemon.state_path);
    let config = load_telegram_config(&config_path).ok();
    let pending = {
        let inner = lock(&daemon.inner);
        inner.telegram_login.is_some()
    };
    let authorized =
        config.as_ref().is_some_and(|config| config.authorized) && session_path.is_file();
    json_response(&json!({
        "configured": config.is_some(),
        "session_exists": session_path.is_file(),
        "authorized": authorized,
        "login_pending": pending,
        "peer": config.as_ref().map(|config| config.peer.as_str()),
        "message_id": config.as_ref().map(|config| config.message_id),
    }))
}

fn handle_telegram_probe_request_code(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let Ok(mut config) = serde_json::from_str::<TelegramProbeConfig>(body) else {
        return json_error(400, "invalid Telegram probe configuration");
    };
    if config.api_hash.len() > 128 || config.phone.len() > 32 || config.peer.len() > 128 {
        return json_error(400, "Telegram probe fields are too long");
    }
    config.authorized = false;
    if let Err(error) = save_telegram_config(&telegram_config_path(&daemon.state_path), &config) {
        return json_error(400, &error);
    }
    let socks_port = lock(&daemon.inner).state.socks_port;
    match telegram_request_login_code(
        &telegram_session_path(&daemon.state_path),
        &config,
        socks_port,
    ) {
        Ok(login) => {
            lock(&daemon.inner).telegram_login = Some(login);
            json_response(&json!({"code_requested": true}))
        }
        Err(error) => json_error(502, &error),
    }
}

fn handle_telegram_probe_confirm(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return json_error(400, "invalid JSON body");
    };
    let code = value
        .get("code")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let password = value
        .get("password")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if code.len() > 32 || password.len() > 256 {
        return json_error(400, "Telegram confirmation fields are too long");
    }
    let config = match load_telegram_config(&telegram_config_path(&daemon.state_path)) {
        Ok(config) => config,
        Err(_) => return json_error(409, "request a Telegram login code first"),
    };
    let (state, socks_port) = {
        let mut inner = lock(&daemon.inner);
        let Some(state) = inner.telegram_login.take() else {
            return json_error(409, "request a Telegram login code first");
        };
        (state, inner.state.socks_port)
    };
    match telegram_confirm_login(
        &telegram_session_path(&daemon.state_path),
        config.api_id,
        socks_port,
        state,
        (!code.is_empty()).then_some(code),
        (!password.is_empty()).then_some(password),
    ) {
        Ok((ConfirmResult::Authorized, _)) => {
            let mut config = config;
            config.authorized = true;
            if let Err(error) =
                save_telegram_config(&telegram_config_path(&daemon.state_path), &config)
            {
                return json_error(500, &error);
            }
            json_response(&json!({"authorized": true}))
        }
        Ok((ConfirmResult::PasswordRequired { hint }, next_state)) => {
            lock(&daemon.inner).telegram_login = next_state;
            json_response(&json!({
                "authorized": false,
                "password_required": true,
                "hint": hint,
            }))
        }
        Err(error) => json_error(502, &error),
    }
}

fn handle_telegram_probe_delete(daemon: &Daemon) -> (u16, &'static str, String) {
    let config_path = telegram_config_path(&daemon.state_path);
    let session_path = telegram_session_path(&daemon.state_path);
    let config = load_telegram_config(&config_path).ok();
    let socks_port = {
        let mut inner = lock(&daemon.inner);
        inner.telegram_login = None;
        inner.state.socks_port
    };
    let revoked = telegram_revoke_and_delete(&session_path, config.as_ref(), socks_port);
    let _ = fs::remove_file(config_path);
    json_response(&json!({"deleted": true, "revoked": revoked}))
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
        if result.method == "quick" {
            stats_entry.resource_tests = result.resource_tests.clone();
        }
        if result.success {
            stats_entry.last_latency_ms = result.latency_ms;
            stats_entry.last_jitter_ms = result.jitter_ms;
            stats_entry.has_latency = true;
            stats_entry.has_jitter = true;
            if let Some(download_mbps) = result.download_mbps {
                stats_entry.last_download_mbps = download_mbps;
                stats_entry.has_download = true;
            }
            if let Some(upload_mbps) = result.upload_mbps {
                stats_entry.last_upload_mbps = upload_mbps;
                stats_entry.has_upload = true;
            }
            stats_entry.last_loss_percent = result.loss_percent;
            stats_entry.has_loss = true;
            stats_entry.last_error = result
                .download_error
                .clone()
                .or_else(|| result.upload_error.clone());
            stats_entry.success_count = stats_entry.success_count.saturating_add(1);
            stats_entry.consecutive_failures = 0;
            stats_entry.cooldown_until_unix = 0;
            update_smart_ewma(stats_entry, &result);
        } else {
            stats_entry.failure_count = stats_entry.failure_count.saturating_add(1);
            stats_entry.consecutive_failures = stats_entry.consecutive_failures.saturating_add(1);
            stats_entry.cooldown_until_unix = now.saturating_add(default_smart_cooldown_secs());
            stats_entry.last_error = result.error.clone();
        }
        stats_entry.last_checked_unix = now;
    }

    inner.state.metrics_history.push(MetricSample {
        timestamp: now,
        profile_id: result.profile_id,
        passed: result.success,
        latency_ms: result.latency_ms,
        download_mbps: result.download_mbps.unwrap_or(0.0),
    });
    if inner.state.metrics_history.len() > MAX_HISTORY_SAMPLES {
        let excess = inner.state.metrics_history.len() - MAX_HISTORY_SAMPLES;
        inner.state.metrics_history.drain(0..excess);
    }
    prune_stale_profile_stats(&mut inner.state);

    let _ = persist_state(&daemon.state_path, &inner.state);
}

fn handle_stats(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    let active_id = inner.state.active_profile_id;
    let favorites = &inner.state.favorites;
    let stats = &inner.state.stats;
    let profiles = &inner.state.profiles;

    let entries: Vec<Value> = profiles
        .iter()
        .map(|profile| {
            let stat = stats.iter().find(|s| s.profile_raw == profile.raw);
            let favorite = favorites.iter().any(|raw| raw == &profile.raw);
            json!({
                "profile_id": profile.id,
                "server_ref": profile_server_ref(profile),
                "name": profile.name,
                "protocol": profile.protocol.to_string(),
                "transport": profile.transport(),
                "address": profile.address,
                "port": profile.port,
                "active": active_id == Some(profile.id),
                "favorite": favorite,
                "group": profile.group,
                "dead": profile_is_dead(&inner.state, profile),
                "last_latency_ms": stat.filter(|s| s.has_latency).map(|s| s.last_latency_ms),
                "last_jitter_ms": stat.filter(|s| s.has_jitter).map(|s| s.last_jitter_ms),
                "last_download_mbps": stat.filter(|s| s.has_download).map(|s| s.last_download_mbps),
                "last_upload_mbps": stat.filter(|s| s.has_upload).map(|s| s.last_upload_mbps),
                "last_loss_percent": stat.filter(|s| s.has_loss).map(|s| s.last_loss_percent),
                "success_count": stat.map(|s| s.success_count).unwrap_or(0),
                "failure_count": stat.map(|s| s.failure_count).unwrap_or(0),
                "last_error": stat.and_then(|s| s.last_error.clone()),
                "last_checked": stat.map(|s| s.last_checked_unix).unwrap_or(0),
                "resource_tests": stat.map(|s| s.resource_tests.clone()).unwrap_or_default(),
                "ewma_latency_ms": stat.filter(|s| s.has_ewma).map(|s| s.ewma_latency_ms),
                "ewma_download_mbps": stat.filter(|s| s.has_download).map(|s| s.ewma_download_mbps),
                "consecutive_failures": stat.map(|s| s.consecutive_failures).unwrap_or(0),
                "cooldown_until_unix": stat.map(|s| s.cooldown_until_unix).unwrap_or(0),
            })
        })
        .collect();
    let response = json!({
        "stats": entries,
        "favorites_count": favorites.len(),
        "profiles_count": profiles.len(),
    });
    (200, "application/json", response.to_string())
}

fn update_smart_ewma(stats: &mut ProfileStats, result: &BenchResult) {
    const ALPHA: f32 = 0.35;
    stats.ewma_latency_ms = ewma(stats.ewma_latency_ms, result.latency_ms as f32, ALPHA);
    if let Some(download_mbps) = result.download_mbps {
        stats.ewma_download_mbps = ewma(stats.ewma_download_mbps, download_mbps, ALPHA);
    }
    stats.has_ewma = true;
}

fn ewma(previous: f32, sample: f32, alpha: f32) -> f32 {
    if previous <= 0.0 {
        sample
    } else {
        previous.mul_add(1.0 - alpha, sample * alpha)
    }
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

/// Add a single profile from a raw share link or subscription URL.
/// Body: `{"raw": "vless://...", "group": "optional"}`.
/// If `raw` is a share link → parse, dedup, assign new ID.
/// If `raw` is a subscription URL (http/https) → fetch, parse all profiles,
/// dedup, persist subscription source for later refresh.
fn handle_profile_add(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return (
            400,
            "application/json",
            json!({"error": "invalid JSON body"}).to_string(),
        );
    };
    let Some(raw) = value.get("raw").and_then(Value::as_str) else {
        return (
            400,
            "application/json",
            json!({"error": "missing \"raw\" field"}).to_string(),
        );
    };
    let group_param = value
        .get("group")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());

    let parsed = parse_input(raw);

    // ─── Path 1: single share link → one profile ───
    if !parsed.profiles.is_empty() {
        let mut inner = lock(&daemon.inner);
        let profile = parsed.profiles[0].clone();
        let raw_key = profile.raw.clone();

        // Dedup: check if a profile with the same raw link already exists.
        if inner.state.profiles.iter().any(|p| p.raw == raw_key) {
            return (
                409,
                "application/json",
                json!({"error": "profile already exists", "raw": raw_key}).to_string(),
            );
        }

        let new_id = inner.state.profiles.len();
        let mut profile = profile;
        profile.id = new_id;
        if profile.group.is_none() {
            profile.group = group_param.clone();
        }
        inner.state.profiles.push(profile);

        if let Err(error) = persist_state(&daemon.state_path, &inner.state) {
            return (
                500,
                "application/json",
                json!({"error": format!("persist state: {error}")}).to_string(),
            );
        }

        return (
            200,
            "application/json",
            json!({
                "profile_id": new_id,
                "profile_count": inner.state.profiles.len(),
            })
            .to_string(),
        );
    }

    // ─── Path 2: subscription URL → fetch and import all profiles ───
    if !parsed.subscriptions.is_empty() {
        // Grab proxy fallback info under a short lock; network I/O below
        // runs without holding the mutex so the API stays responsive.
        let (proxy_info, hwid) = {
            let mut inner = lock(&daemon.inner);
            let hwid = inner.state.hwid_config.clone();
            (proxy_info_for_daemon(&mut inner), hwid)
        };

        let mut all_profiles: Vec<Profile> = Vec::new();
        let mut errors: Vec<String> = Vec::new();
        let mut sub_outcomes: Vec<(
            SubscriptionSource,
            usize,
            Option<SubscriptionMetadata>,
            Option<String>,
        )> = Vec::new();

        for source in &parsed.subscriptions {
            let outcome = load_subscription_for_daemon(source, &proxy_info, &hwid);
            match outcome {
                SubscriptionLoadOutcome::Ok(report) => {
                    let count = report.profiles.len();
                    let metadata = report.metadata;
                    for mut profile in report.profiles {
                        if profile.group.is_none() {
                            profile.group = Some(source.url.clone());
                        }
                        all_profiles.push(profile);
                    }
                    sub_outcomes.push((source.clone(), count, Some(metadata), None));
                }
                SubscriptionLoadOutcome::Failed { attempts } => {
                    let error = SubscriptionLoadOutcome::format_error(&attempts);
                    errors.push(error.clone());
                    sub_outcomes.push((source.clone(), 0, None, Some(error)));
                }
            }
        }

        let mut inner = lock(&daemon.inner);
        let count_before = inner.state.profiles.len();
        let mut seen: HashSet<String> =
            inner.state.profiles.iter().map(|p| p.raw.clone()).collect();
        for mut profile in all_profiles {
            if seen.insert(profile.raw.clone()) {
                profile.id = inner.state.profiles.len();
                inner.state.profiles.push(profile);
            }
        }
        let count_after = inner.state.profiles.len();
        let added = count_after.saturating_sub(count_before);

        // Persist subscription sources for later refresh.
        let now = unix_now();
        for (source, count, metadata, error) in &sub_outcomes {
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
                    title: None,
                    announcement: None,
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
            if error.is_none() {
                entry.last_loaded_unix = Some(now);
                entry.last_error = None;
                entry.profile_count = *count;
                if let Some(metadata) = metadata {
                    apply_subscription_metadata(entry, metadata.clone());
                }
            } else {
                entry.last_error = error.clone();
            }
        }

        if let Err(error) = persist_state(&daemon.state_path, &inner.state) {
            errors.push(format!("persist: {error}"));
        }

        if !errors.is_empty() {
            return (
                502,
                "application/json",
                json!({
                    "error": errors.join("; "),
                    "profile_count": count_after,
                    "added": added,
                    "subscriptions": parsed.subscriptions.len(),
                })
                .to_string(),
            );
        }

        return (
            200,
            "application/json",
            json!({
                "profile_count": count_after,
                "added": added,
                "subscriptions": parsed.subscriptions.len(),
            })
            .to_string(),
        );
    }

    // ─── Path 3: neither share link nor subscription URL ───
    // parse_input already tried base64 decoding, so reaching here
    // means the input is truly unrecognisable. Give the user an
    // actionable hint.
    (
        400,
        "application/json",
        json!({
            "error": "could not parse share link or subscription URL",
            "candidate_count": parsed.candidates,
            "hint": "Paste a share link (vless://, vmess://, …), a subscription URL (https://…), or the raw base64 body of a subscription."
        })
            .to_string(),
    )
}

/// Delete a single profile by ID.
/// Body: `{"profile_id": N}`.
/// Re-indexes remaining profile IDs. If the active profile was deleted,
/// stops the core and clears `active_profile_id`.
fn handle_profile_delete(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
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

    // Check existence.
    if !inner.state.profiles.iter().any(|p| p.id == id) {
        return (
            404,
            "application/json",
            json!({"error": "profile not found", "profile_id": id}).to_string(),
        );
    }

    let was_active = inner.state.active_profile_id == Some(id);
    push_undo_snapshot(&mut inner.state, format!("Delete profile #{id}"));

    // Remove the profile.
    inner.state.profiles.retain(|p| p.id != id);
    prune_stale_profile_stats(&mut inner.state);

    // Re-index remaining profiles.
    for (i, p) in inner.state.profiles.iter_mut().enumerate() {
        p.id = i;
    }

    if was_active {
        inner.state.active_profile_id = None;
        // Stop the core since the active profile no longer exists.
        let _ = inner.core.stop();
    } else if let Some(active_id) = inner.state.active_profile_id {
        // Active profile ID may have shifted due to re-indexing.
        // Find the profile by its raw link to get the new ID.
        // Actually, since we re-index sequentially, the active profile
        // may have shifted. We need to find it by checking if the
        // active ID is still valid. If the deleted profile was before
        // the active one, the active ID needs to decrement by 1.
        if id < active_id {
            inner.state.active_profile_id = Some(active_id - 1);
        }
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
        json!({
            "deleted_profile_id": id,
            "profile_count": inner.state.profiles.len(),
            "was_active": was_active,
        })
        .to_string(),
    )
}

/// Update a profile's metadata (name and/or block_quic).
/// Body: `{"profile_id": N, "name": "...", "block_quic": true}`.
/// If `block_quic` changes on the active profile, regenerates config
/// and restarts the core.
fn handle_profile_update(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
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

    let new_name = value.get("name").and_then(Value::as_str);
    let new_block_quic = value.get("block_quic").and_then(Value::as_bool);

    if new_name.is_none() && new_block_quic.is_none() {
        return (
            400,
            "application/json",
            json!({"error": "nothing to update — provide \"name\" or \"block_quic\""}).to_string(),
        );
    }

    let mut inner = lock(&daemon.inner);
    let Some(profile) = inner.state.profiles.iter_mut().find(|p| p.id == id) else {
        return (
            404,
            "application/json",
            json!({"error": "profile not found", "profile_id": id}).to_string(),
        );
    };

    let mut changed_block_quic = false;
    if let Some(name) = new_name {
        profile.name = name.to_owned();
    }
    if let Some(block) = new_block_quic
        && profile.block_quic != block
    {
        profile.block_quic = block;
        changed_block_quic = true;
    }

    let is_active = inner.state.active_profile_id == Some(id);

    // If block_quic changed on the active profile, regenerate config
    // and restart the core so the change takes effect.
    if changed_block_quic && is_active {
        let geo_dir = geo_dir_from_state(&inner.state);
        if let Ok((binary_path, config_path)) = regenerate_config(&inner.state, daemon) {
            let _ = inner
                .core
                .restart(&binary_path, &config_path, geo_dir.as_deref());
        }
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
        json!({
            "profile_id": id,
            "name": inner.state.profiles.iter().find(|p| p.id == id).map(|p| p.name.clone()).unwrap_or_default(),
            "block_quic": inner.state.profiles.iter().find(|p| p.id == id).map(|p| p.block_quic).unwrap_or(false),
        })
        .to_string(),
    )
}

/// Return a profile's raw share link and QR SVG. The UI deliberately sends
/// only a local `profile_id`; the daemon resolves the sensitive raw link from
/// current persisted state so the browser does not need to cache it in the
/// profile table payload.
fn handle_profile_share(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
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

    let profile = {
        let inner = lock(&daemon.inner);
        inner.state.profiles.iter().find(|p| p.id == id).cloned()
    };
    let Some(profile) = profile else {
        return (
            404,
            "application/json",
            json!({"error": "profile not found", "profile_id": id}).to_string(),
        );
    };

    let code = match QrCode::new(profile.raw.as_bytes()) {
        Ok(code) => code,
        Err(error) => {
            return (
                500,
                "application/json",
                json!({"error": format!("QR generation failed: {error}")}).to_string(),
            );
        }
    };
    let qr_svg = code
        .render::<svg::Color<'_>>()
        .min_dimensions(256, 256)
        .dark_color(svg::Color("#111827"))
        .light_color(svg::Color("#ffffff"))
        .build();

    (
        200,
        "application/json",
        json!({
            "profile_id": profile.id,
            "name": profile.name,
            "protocol": profile.protocol.to_string(),
            "link": profile.raw,
            "qr_svg": qr_svg,
        })
        .to_string(),
    )
}

fn group_from_body(body: &str) -> Result<String, (u16, &'static str, String)> {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return Err((
            400,
            "application/json",
            json!({"error": "invalid JSON body"}).to_string(),
        ));
    };
    let Some(group) = value.get("group").and_then(Value::as_str).map(str::trim) else {
        return Err((
            400,
            "application/json",
            json!({"error": "missing group"}).to_string(),
        ));
    };
    if group.is_empty() {
        return Err((
            400,
            "application/json",
            json!({"error": "missing group"}).to_string(),
        ));
    }
    Ok(group.to_owned())
}

/// Return a UI-visible profile group as one shareable subscription bundle.
/// If the group is a saved subscription URL, that URL is the canonical shared
/// link. Otherwise the daemon returns a newline-separated raw-link bundle for
/// all profiles in the group.
fn handle_profile_group_share(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let group = match group_from_body(body) {
        Ok(group) => group,
        Err(response) => return response,
    };

    let (canonical_url, links, display_name) = {
        let inner = lock(&daemon.inner);
        let links: Vec<String> = inner
            .state
            .profiles
            .iter()
            .filter(|p| p.group.as_deref() == Some(group.as_str()))
            .map(|p| p.raw.clone())
            .collect();
        let canonical_url = inner
            .state
            .subscriptions
            .iter()
            .find(|s| s.url == group)
            .map(|s| s.url.clone());
        (canonical_url, links, group.clone())
    };

    if links.is_empty() {
        return (
            404,
            "application/json",
            json!({"error": "profile group not found", "group": group}).to_string(),
        );
    }

    let link = canonical_url.clone().unwrap_or_else(|| links.join("\n"));
    let qr_svg = match QrCode::new(link.as_bytes()) {
        Ok(code) => Some(
            code.render::<svg::Color<'_>>()
                .min_dimensions(256, 256)
                .dark_color(svg::Color("#111827"))
                .light_color(svg::Color("#ffffff"))
                .build(),
        ),
        Err(_) => None,
    };

    (
        200,
        "application/json",
        json!({
            "group": group,
            "name": display_name,
            "profile_count": links.len(),
            "subscription_url": canonical_url,
            "link": link,
            "links": links,
            "qr_svg": qr_svg,
        })
        .to_string(),
    )
}

/// Delete every server profile in a UI-visible group/subscription.
/// This is intentionally keyed by `group`, not by saved subscription URL, so
/// imported/named subscription groups such as "Tutnet online" are removable
/// through the same user-visible contract as URL-backed subscriptions.
fn handle_profile_group_delete(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let group = match group_from_body(body) {
        Ok(group) => group,
        Err(response) => return response,
    };

    let mut inner = lock(&daemon.inner);
    if !inner
        .state
        .profiles
        .iter()
        .any(|p| p.group.as_deref() == Some(group.as_str()))
    {
        return (
            404,
            "application/json",
            json!({"error": "profile group not found", "group": group}).to_string(),
        );
    }

    push_undo_snapshot(&mut inner.state, format!("Delete group {group}"));
    let (removed_profiles, removed_active) = purge_profile_group(&mut inner.state, &group);
    if removed_active {
        let _ = inner.core.stop();
        let _ = fs::remove_file(&daemon.mihomo_config_path);
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
        json!({
            "group": group,
            "removed_profiles": removed_profiles,
            "removed_active": removed_active,
            "profile_count": inner.state.profiles.len(),
        })
        .to_string(),
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

// =========================================================================
// v0.20: Deep Bench API handlers.
// =========================================================================

fn handle_deep_bench_settings_get(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    let settings = &inner.state.deep_bench;
    let eta = estimate_deep_bench_secs(inner.state.profiles.len(), settings.stability_minutes);
    (
        200,
        "application/json",
        json!({
            "settings": settings,
            "estimated_total_secs": eta,
            "profile_count": inner.state.profiles.len(),
        })
        .to_string(),
    )
}

fn handle_deep_bench_settings_set(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return json_error(400, "invalid JSON body");
    };
    let mut inner = lock(&daemon.inner);
    let s = &mut inner.state.deep_bench;
    if let Some(v) = value.get("enabled").and_then(Value::as_bool) {
        s.enabled = v;
    }
    if let Some(v) = value.get("weekdays").and_then(Value::as_u64) {
        s.weekdays = v as u8;
    }
    if let Some(v) = value.get("start_hour").and_then(Value::as_u64) {
        s.start_hour = (v as u8).min(23);
    }
    if let Some(v) = value.get("end_hour").and_then(Value::as_u64) {
        s.end_hour = (v as u8).min(23);
    }
    if let Some(v) = value.get("stability_minutes").and_then(Value::as_u64) {
        s.stability_minutes = v as u32;
    }
    if let Some(obj) = value.get("profile_filter").and_then(Value::as_object)
        && let Some(kind) = obj.get("kind").and_then(Value::as_str)
    {
        s.profile_filter = match kind {
            "all" => ProfileFilter::All,
            "subscription" => {
                let url = obj
                    .get("value")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                if url.is_empty() {
                    ProfileFilter::All
                } else {
                    ProfileFilter::Subscription(url)
                }
            }
            "explicit" => {
                let server_refs: Vec<String> = obj
                    .get("value")
                    .and_then(Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .filter_map(Value::as_str)
                            .filter(|server_ref| valid_lifecycle_ref(server_ref))
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default();
                if server_refs.is_empty() {
                    ProfileFilter::All
                } else {
                    ProfileFilter::Explicit(server_refs)
                }
            }
            _ => s.profile_filter.clone(),
        };
    }
    if let Err(error) = persist_state(&daemon.state_path, &inner.state) {
        return json_error(500, &format!("persist failed: {error}"));
    }
    (
        200,
        "application/json",
        json!({"ok": true, "settings": inner.state.deep_bench}).to_string(),
    )
}

fn handle_deep_bench_start(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    // Optional body overrides the persistent settings for this run only.
    let override_minutes: Option<u32> = serde_json::from_str::<Value>(body).ok().and_then(|v| {
        v.get("stability_minutes")
            .and_then(Value::as_u64)
            .map(|x| x as u32)
    });
    let mut inner = lock(&daemon.inner);
    if inner.deep_bench_active {
        return json_error(409, "deep bench already running");
    }
    if inner.bench.is_running() {
        return json_error(409, "a quick bench is running; cancel it first");
    }
    let profiles = select_profiles_for_deep_bench(&inner.state);
    if profiles.is_empty() {
        return json_error(400, "no profiles match the current filter");
    }
    let stability_minutes =
        override_minutes.unwrap_or(inner.state.deep_bench.stability_minutes.max(1));
    let mihomo_path = inner.state.mihomo_path.clone();
    let filter = inner.state.deep_bench.profile_filter.clone();
    let started_unix = unix_now();
    let cancel = Arc::new(AtomicBool::new(false));
    inner.deep_bench_active = true;
    inner.deep_bench_cancel = Some(cancel.clone());
    inner.deep_bench_status = DeepBenchStatus {
        state: "phase_a".to_owned(),
        phase_progress: 0,
        phase_detail: format!("0/{} profiles quick-benched", profiles.len()),
        started_unix,
        eta_secs: estimate_deep_bench_secs(profiles.len(), stability_minutes),
        last_error: String::new(),
    };
    inner.state.deep_bench.last_run_unix = started_unix;
    inner.dirty = true;
    drop(inner);

    let daemon_clone = daemon.clone();
    let cancel_clone = cancel.clone();
    let handle = std::thread::Builder::new()
        .name("hincyray-deep-bench".to_owned())
        .spawn(move || {
            run_deep_bench(
                daemon_clone,
                profiles,
                stability_minutes,
                filter,
                mihomo_path,
                cancel_clone,
                started_unix,
            );
        })
        .expect("spawn deep bench thread");
    let mut inner = lock(&daemon.inner);
    inner.deep_bench_handle = Some(handle);
    (
        200,
        "application/json",
        json!({"ok": true, "started_unix": started_unix}).to_string(),
    )
}

fn handle_deep_bench_cancel(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    let was_running = inner.deep_bench_active;
    if let Some(cancel) = &inner.deep_bench_cancel {
        cancel.store(true, Ordering::Relaxed);
    }
    (
        200,
        "application/json",
        json!({"ok": true, "was_running": was_running}).to_string(),
    )
}

fn handle_deep_bench_status(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    (
        200,
        "application/json",
        serde_json::to_string(&inner.deep_bench_status).unwrap_or_default(),
    )
}

fn handle_deep_bench_history(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    let history = if inner.state.quality_history.is_empty() {
        load_quality_history(&daemon.state_path, &inner.state.profiles)
    } else {
        inner.state.quality_history.clone()
    };
    let today = yyyymmdd_from_unix(unix_now());
    let cutoff_date = today.saturating_sub(30);
    let entries: Vec<&DailyQualitySnapshot> =
        history.iter().filter(|s| s.date >= cutoff_date).collect();
    (
        200,
        "application/json",
        json!({"history": entries, "days_kept": 30}).to_string(),
    )
}

// =========================================================================
// v0.20: Trash bin API handlers.
// =========================================================================

fn handle_trash_list(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    let entries: Vec<Value> = inner
        .state
        .dead_server_refs
        .iter()
        .map(|server_ref| {
            let promoted = inner
                .state
                .dead_promoted_at
                .get(server_ref)
                .copied()
                .unwrap_or(0);
            let profile = inner
                .state
                .profiles
                .iter()
                .find(|profile| profile_server_ref(profile) == *server_ref);
            json!({
                "server_ref": server_ref,
                "name": profile.map(|p| p.name.clone()).unwrap_or_else(|| "(gone)".to_owned()),
                "profile_id": profile.map(|p| p.id),
                "group": profile.and_then(|p| p.group.clone()),
                "promoted_at_unix": promoted,
                "still_in_profiles": profile.is_some(),
            })
        })
        .collect();
    (
        200,
        "application/json",
        json!({"trash": entries, "count": entries.len()}).to_string(),
    )
}

fn parse_server_refs(body: &str) -> Result<Vec<String>, String> {
    let value: Value = serde_json::from_str(body).map_err(|_| "invalid JSON body".to_owned())?;
    let refs = value
        .get("server_refs")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing 'server_refs' array".to_owned())?;
    let mut unique = HashSet::new();
    for server_ref in refs.iter().filter_map(Value::as_str) {
        if !valid_lifecycle_ref(server_ref) {
            return Err(format!("invalid server_ref: {server_ref}"));
        }
        unique.insert(server_ref.to_owned());
    }
    if unique.is_empty() {
        return Err("server_refs must not be empty".to_owned());
    }
    Ok(unique.into_iter().collect())
}

fn dead_membership_affects_running_dataplane(
    state: &HincyrayState,
    changed_refs: &HashSet<String>,
) -> bool {
    if !state.split_routing.enabled || state.active_profile_id.is_none() || changed_refs.is_empty()
    {
        return false;
    }
    state
        .routing_rules
        .iter()
        .filter(|rule| rule.enabled)
        .map(|rule| rule.target.as_str())
        .chain(
            state
                .device_routes
                .iter()
                .filter(|route| route.enabled)
                .map(|route| route.target.as_str()),
        )
        .filter_map(|target| match RoutingTarget::parse(target).ok()? {
            RoutingTarget::Server(server_ref) => {
                let entry = state
                    .server_route_registry
                    .iter()
                    .find(|entry| entry.server_ref == server_ref)?;
                state
                    .profiles
                    .iter()
                    .find(|profile| canonical_profile_raw(profile) == entry.canonical_raw)
                    .map(profile_server_ref)
            }
            _ => None,
        })
        .any(|server_ref| changed_refs.contains(&server_ref))
}

fn mutate_dead_server_membership<T>(
    daemon: &Daemon,
    mutate: impl FnOnce(&mut HincyrayState) -> Result<T, (u16, String)>,
) -> Result<T, (u16, String)> {
    let _apply = daemon
        .apply
        .lock()
        .map_err(|_| (500, "config apply lock is poisoned".to_owned()))?;
    let (result, previous_refs, previous_promoted, activate_dataplane) = {
        let mut inner = lock(&daemon.inner);
        let previous_refs = inner.state.dead_server_refs.clone();
        let previous_promoted = inner.state.dead_promoted_at.clone();
        let mut candidate = inner.state.clone();
        let result = mutate(&mut candidate)?;
        inner.state.dead_server_refs = candidate.dead_server_refs;
        inner.state.dead_promoted_at = candidate.dead_promoted_at;
        let changed_refs: HashSet<String> = previous_refs
            .symmetric_difference(&inner.state.dead_server_refs)
            .cloned()
            .collect();
        let membership_changed =
            !changed_refs.is_empty() || previous_promoted != inner.state.dead_promoted_at;
        if !membership_changed {
            return Ok(result);
        }
        let activate_dataplane = inner.core.is_running()
            && dead_membership_affects_running_dataplane(&inner.state, &changed_refs);
        if let Err(error) = persist_state(&daemon.state_path, &inner.state) {
            inner.state.dead_server_refs = previous_refs;
            inner.state.dead_promoted_at = previous_promoted;
            return Err((500, format!("persist failed: {error}")));
        }
        inner.dirty = false;
        (result, previous_refs, previous_promoted, activate_dataplane)
    };

    if activate_dataplane
        && let Err(error) =
            activate_current_config_locked(daemon, false, false, GeoBaseProjection::Applied)
    {
        let rollback = {
            let mut inner = lock(&daemon.inner);
            inner.state.dead_server_refs = previous_refs;
            inner.state.dead_promoted_at = previous_promoted;
            match persist_state(&daemon.state_path, &inner.state) {
                Ok(()) => {
                    inner.dirty = false;
                    "restored".to_owned()
                }
                Err(rollback_error) => {
                    inner.dirty = true;
                    format!("failed ({rollback_error})")
                }
            }
        };
        return Err((
            500,
            format!(
                "Dead Servers dataplane activation failed: {error}; state rollback: {rollback}"
            ),
        ));
    }

    Ok(result)
}

fn handle_trash_move(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let refs = match parse_server_refs(body) {
        Ok(refs) => refs,
        Err(error) => return json_error(400, &error),
    };
    let moved = match mutate_dead_server_membership(daemon, |state| {
        let active_ref = state
            .active_profile_id
            .and_then(|id| state.profiles.iter().find(|profile| profile.id == id))
            .map(profile_server_ref);
        for server_ref in &refs {
            if !state
                .profiles
                .iter()
                .any(|profile| profile_server_ref(profile) == *server_ref)
            {
                return Err((404, format!("server not found: {server_ref}")));
            }
            if active_ref.as_deref() == Some(server_ref) {
                return Err((
                    409,
                    "active profile cannot be moved to Dead Servers".to_owned(),
                ));
            }
        }
        let now = unix_now();
        for server_ref in &refs {
            state.dead_server_refs.insert(server_ref.clone());
            state
                .dead_promoted_at
                .entry(server_ref.clone())
                .or_insert(now);
        }
        Ok(refs.clone())
    }) {
        Ok(moved) => moved,
        Err((status, error)) => return json_error(status, &error),
    };
    (
        200,
        "application/json",
        json!({"ok": true, "moved": moved}).to_string(),
    )
}

fn handle_trash_restore(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let refs = match parse_server_refs(body) {
        Ok(refs) => refs,
        Err(error) => return json_error(400, &error),
    };
    let restored = match mutate_dead_server_membership(daemon, |state| {
        if let Some(missing) = refs
            .iter()
            .find(|server_ref| !state.dead_server_refs.contains(*server_ref))
        {
            return Err((404, format!("server not in Dead Servers: {missing}")));
        }
        for server_ref in &refs {
            state.dead_server_refs.remove(server_ref);
            state.dead_promoted_at.remove(server_ref);
        }
        Ok(refs.clone())
    }) {
        Ok(restored) => restored,
        Err((status, error)) => return json_error(status, &error),
    };
    (
        200,
        "application/json",
        json!({"ok": true, "restored": restored}).to_string(),
    )
}

fn handle_trash_clear(daemon: &Daemon) -> (u16, &'static str, String) {
    let _apply = match daemon.apply.lock() {
        Ok(guard) => guard,
        Err(_) => return json_error(500, "config apply lock is poisoned"),
    };
    let mut inner = lock(&daemon.inner);
    let mut candidate = inner.state.clone();
    let dead_refs = candidate.dead_server_refs.clone();
    let removed_raws: HashSet<String> = candidate
        .profiles
        .iter()
        .filter(|profile| dead_refs.contains(&profile_server_ref(profile)))
        .map(|profile| profile.raw.clone())
        .collect();
    let removed_profiles = removed_raws.len();
    let removed_entries = dead_refs.len();
    if removed_entries == 0 {
        return json_response(&json!({
            "ok": true,
            "removed_profiles": 0,
            "removed_entries": 0,
        }));
    }

    push_undo_snapshot(&mut candidate, "Clear Dead Servers".to_owned());
    let active_raw = candidate
        .active_profile_id
        .and_then(|id| candidate.profiles.iter().find(|profile| profile.id == id))
        .map(|profile| profile.raw.clone());
    candidate
        .profiles
        .retain(|profile| !removed_raws.contains(&profile.raw));
    reassign_profile_ids(&mut candidate.profiles);
    candidate.active_profile_id = active_raw.as_ref().and_then(|raw| {
        candidate
            .profiles
            .iter()
            .find(|profile| &profile.raw == raw)
            .map(|profile| profile.id)
    });
    candidate
        .favorites
        .retain(|raw| !removed_raws.contains(raw));
    candidate
        .stats
        .retain(|stat| !removed_raws.contains(&stat.profile_raw));
    candidate.dead_server_refs.clear();
    candidate.dead_promoted_at.clear();
    let group_counts: HashMap<String, usize> = candidate
        .profiles
        .iter()
        .filter_map(|profile| profile.group.clone())
        .fold(HashMap::new(), |mut counts, group| {
            *counts.entry(group).or_default() += 1;
            counts
        });
    for subscription in &mut candidate.subscriptions {
        subscription.profile_count = group_counts.get(&subscription.url).copied().unwrap_or(0);
    }
    sync_server_route_registry(&mut candidate);
    if let Err(error) = persist_state(&daemon.state_path, &candidate) {
        return json_error(500, &format!("persist failed: {error}"));
    }
    inner.state = candidate;
    inner.dirty = false;
    json_response(&json!({
        "ok": true,
        "removed_profiles": removed_profiles,
        "removed_entries": removed_entries,
        "profile_count": inner.state.profiles.len(),
    }))
}

fn handle_trash_purge_gone(daemon: &Daemon) -> (u16, &'static str, String) {
    let mut inner = lock(&daemon.inner);
    let purged = purge_stale_trash(&mut inner.state);
    if purged > 0
        && let Err(error) = persist_state(&daemon.state_path, &inner.state)
    {
        return json_error(500, &format!("persist failed: {error}"));
    }
    (
        200,
        "application/json",
        json!({"ok": true, "purged": purged}).to_string(),
    )
}

fn json_error(code: u16, msg: &str) -> (u16, &'static str, String) {
    (code, "application/json", json!({"error": msg}).to_string())
}

/// Replace all profiles belonging to subscription `url` with `fresh`.
/// Old profiles with `group == Some(url)` are removed; fresh profiles
/// are added (dedup by `raw` against profiles from other sources).
/// All profiles are re-indexed with sequential IDs and
/// `active_profile_id` is updated to point to the active profile by
/// its `raw` string. Returns the number of fresh profiles added.
///
/// An empty set is never a valid replacement: only the explicit delete API
/// may erase a subscription group. This remains an invariant even if a future
/// loader accidentally reports a transport-successful but empty response.
fn replace_subscription_profiles(
    state: &mut HincyrayState,
    url: &str,
    fresh: Vec<Profile>,
) -> Result<usize, String> {
    if fresh.is_empty() {
        return Err(format!(
            "refusing to replace subscription {url} with an empty profile set"
        ));
    }
    let active_raw = state
        .active_profile_id
        .and_then(|id| state.profiles.iter().find(|p| p.id == id))
        .map(|p| p.raw.clone());

    // Remove old profiles belonging to this subscription.
    state.profiles.retain(|p| p.group.as_deref() != Some(url));

    // Add fresh profiles, dedup by raw against all remaining.
    let mut seen: HashSet<String> = state.profiles.iter().map(|p| p.raw.clone()).collect();
    let mut added = 0;
    for mut profile in fresh {
        if profile.group.is_none() {
            profile.group = Some(url.to_owned());
        }
        if seen.insert(profile.raw.clone()) {
            state.profiles.push(profile);
            added += 1;
        }
    }

    // Re-assign sequential IDs after removal + insertion.
    for (i, p) in state.profiles.iter_mut().enumerate() {
        p.id = i;
    }

    // Restore active_profile_id by matching the raw string. If the
    // active profile was removed (no longer in the subscription),
    // active_profile_id becomes None — caller should handle this.
    state.active_profile_id = active_raw
        .as_ref()
        .and_then(|raw| state.profiles.iter().find(|p| &p.raw == raw))
        .map(|p| p.id);
    prune_stale_profile_stats(state);

    Ok(added)
}

/// Remove a subscription source and all its profiles from the state.
/// Re-indexes remaining profiles and updates `active_profile_id`.
/// Returns `true` if the active profile was removed (belonged to the
/// subscription) — caller should stop the core or switch to another.
fn purge_subscription(state: &mut HincyrayState, url: &str) -> bool {
    let active_raw = state
        .active_profile_id
        .and_then(|id| state.profiles.iter().find(|p| p.id == id))
        .map(|p| p.raw.clone());

    // Remove subscription source.
    state.subscriptions.retain(|s| s.url != url);

    // Remove all profiles belonging to this subscription.
    state.profiles.retain(|p| p.group.as_deref() != Some(url));

    // Re-assign sequential IDs.
    for (i, p) in state.profiles.iter_mut().enumerate() {
        p.id = i;
    }

    // Restore active_profile_id or detect removal.
    let new_active = active_raw
        .as_ref()
        .and_then(|raw| state.profiles.iter().find(|p| &p.raw == raw))
        .map(|p| p.id);
    let removed_active = new_active.is_none();
    state.active_profile_id = new_active;
    prune_stale_profile_stats(state);
    removed_active
}

/// Remove all profiles in a UI-visible profile group. If the group also
/// corresponds to a saved subscription URL, remove that subscription record as
/// well. Re-indexes remaining profiles and updates `active_profile_id`.
/// Returns `(removed_profiles, removed_active)`.
fn purge_profile_group(state: &mut HincyrayState, group: &str) -> (usize, bool) {
    let active_raw = state
        .active_profile_id
        .and_then(|id| state.profiles.iter().find(|p| p.id == id))
        .map(|p| p.raw.clone());

    state.subscriptions.retain(|s| s.url != group);

    let before = state.profiles.len();
    state.profiles.retain(|p| p.group.as_deref() != Some(group));
    let removed = before.saturating_sub(state.profiles.len());

    for (i, p) in state.profiles.iter_mut().enumerate() {
        p.id = i;
    }

    let new_active = active_raw
        .as_ref()
        .and_then(|raw| state.profiles.iter().find(|p| &p.raw == raw))
        .map(|p| p.id);
    let removed_active = active_raw.is_some() && new_active.is_none();
    state.active_profile_id = new_active;
    prune_stale_profile_stats(state);

    (removed, removed_active)
}

/// Result of refreshing all subscriptions.
struct RefreshResult {
    refreshed: usize,
    added: usize,
    errors: Vec<String>,
    report: SubscriptionRefreshReport,
}

/// Core logic for refreshing all saved subscriptions.
/// Used by both the HTTP handler and the watchdog auto-refresh.
/// Reads subscription sources, fetches each via network (with SOCKS
/// fallback), replaces profiles in state, and persists.
fn refresh_all_subscriptions(daemon: &Daemon) -> RefreshResult {
    let (subs, proxy_info, hwid) = {
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
        let hwid = inner.state.hwid_config.clone();
        (subs, proxy_info, hwid)
    };

    if subs.is_empty() {
        let report = SubscriptionRefreshReport {
            timestamp: unix_now(),
            ..SubscriptionRefreshReport::default()
        };
        let mut inner = lock(&daemon.inner);
        inner.state.last_subscription_refresh_report = Some(report.clone());
        let _ = persist_state(&daemon.state_path, &inner.state);
        return RefreshResult {
            refreshed: 0,
            added: 0,
            errors: Vec::new(),
            report,
        };
    }

    let mut errors: Vec<String> = Vec::new();
    let mut added_total = 0usize;
    let mut refreshed = 0usize;
    let now = unix_now();
    let mut entries: Vec<SubscriptionRefreshEntry> = Vec::new();

    for source in &subs {
        let outcome = load_subscription_for_daemon(source, &proxy_info, &hwid);
        let mut inner = lock(&daemon.inner);
        let previous_raw: HashSet<String> = inner
            .state
            .profiles
            .iter()
            .filter(|p| p.group.as_deref() == Some(&source.url))
            .map(|p| p.raw.clone())
            .collect();
        let previous_count = previous_raw.len();
        match outcome {
            SubscriptionLoadOutcome::Ok(report) => {
                let count = report.profiles.len();
                let metadata = report.metadata;
                let fresh_raw: HashSet<String> =
                    report.profiles.iter().map(|p| p.raw.clone()).collect();
                let added_for_source = fresh_raw.difference(&previous_raw).count();
                let removed_for_source = previous_raw.difference(&fresh_raw).count();
                match replace_subscription_profiles(&mut inner.state, &source.url, report.profiles)
                {
                    Ok(added) => {
                        if let Some(stored) = inner
                            .state
                            .subscriptions
                            .iter_mut()
                            .find(|s| s.url == source.url)
                        {
                            stored.last_loaded_unix = Some(now);
                            stored.last_error = None;
                            stored.profile_count = count;
                            apply_subscription_metadata(stored, metadata);
                        }
                        added_total += added;
                        refreshed += 1;
                        entries.push(SubscriptionRefreshEntry {
                            url: source.url.clone(),
                            status: "ok".to_owned(),
                            previous_count,
                            new_count: count,
                            added: added_for_source,
                            removed: removed_for_source,
                            changed: 0,
                            error: None,
                        });
                    }
                    Err(error) => {
                        if let Some(stored) = inner
                            .state
                            .subscriptions
                            .iter_mut()
                            .find(|s| s.url == source.url)
                        {
                            stored.last_error = Some(error.clone());
                        }
                        errors.push(error);
                        entries.push(SubscriptionRefreshEntry {
                            url: source.url.clone(),
                            status: "error".to_owned(),
                            previous_count,
                            new_count: previous_count,
                            added: 0,
                            removed: 0,
                            changed: 0,
                            error: errors.last().cloned(),
                        });
                    }
                }
            }
            SubscriptionLoadOutcome::Failed { attempts } => {
                let error = SubscriptionLoadOutcome::format_error(&attempts);
                if let Some(stored) = inner
                    .state
                    .subscriptions
                    .iter_mut()
                    .find(|s| s.url == source.url)
                {
                    stored.last_error = Some(error.clone());
                }
                errors.push(error);
                entries.push(SubscriptionRefreshEntry {
                    url: source.url.clone(),
                    status: "error".to_owned(),
                    previous_count,
                    new_count: previous_count,
                    added: 0,
                    removed: 0,
                    changed: 0,
                    error: errors.last().cloned(),
                });
            }
        }
        let failed = entries
            .iter()
            .filter(|entry| entry.status == "error")
            .count();
        let removed: usize = entries.iter().map(|entry| entry.removed).sum();
        let changed: usize = entries.iter().map(|entry| entry.changed).sum();
        inner.state.last_subscription_refresh_report = Some(SubscriptionRefreshReport {
            timestamp: now,
            refreshed,
            added: added_total,
            removed,
            changed,
            failed,
            entries: entries.clone(),
        });
        let _ = persist_state(&daemon.state_path, &inner.state);
    }

    let failed = entries
        .iter()
        .filter(|entry| entry.status == "error")
        .count();
    let removed: usize = entries.iter().map(|entry| entry.removed).sum();
    let changed: usize = entries.iter().map(|entry| entry.changed).sum();
    let report = SubscriptionRefreshReport {
        timestamp: now,
        refreshed,
        added: added_total,
        removed,
        changed,
        failed,
        entries,
    };

    RefreshResult {
        refreshed,
        added: added_total,
        errors,
        report,
    }
}

fn handle_subscriptions_refresh(daemon: &Daemon) -> (u16, &'static str, String) {
    let result = refresh_all_subscriptions(daemon);
    let mut response = json!({
        "refreshed": result.refreshed,
        "added": result.added,
        "errors": result.errors,
        "report": result.report,
    });
    if result.refreshed == 0 && result.errors.is_empty() {
        response["note"] = json!("no saved subscriptions; import a subscription URL first");
    }
    (200, "application/json", response.to_string())
}

fn handle_subscriptions_refresh_report(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    (
        200,
        "application/json",
        json!({"report": inner.state.last_subscription_refresh_report}).to_string(),
    )
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
    let (proxy_info, exists, hwid) = {
        let mut inner = lock(&daemon.inner);
        let exists = inner.state.subscriptions.iter().any(|s| s.url == url);
        let hwid = inner.state.hwid_config.clone();
        (proxy_info_for_daemon(&mut inner), exists, hwid)
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
    let outcome = load_subscription_for_daemon(&source, &proxy_info, &hwid);
    let now = unix_now();

    let mut inner = lock(&daemon.inner);
    let previous_raw: HashSet<String> = inner
        .state
        .profiles
        .iter()
        .filter(|p| p.group.as_deref() == Some(&source.url))
        .map(|p| p.raw.clone())
        .collect();
    let previous_count = previous_raw.len();
    match outcome {
        SubscriptionLoadOutcome::Ok(report) => {
            let count = report.profiles.len();
            let metadata = report.metadata;
            let fresh_raw: HashSet<String> =
                report.profiles.iter().map(|p| p.raw.clone()).collect();
            let added_for_source = fresh_raw.difference(&previous_raw).count();
            let removed_for_source = previous_raw.difference(&fresh_raw).count();
            match replace_subscription_profiles(&mut inner.state, &source.url, report.profiles) {
                Ok(added) => {
                    if let Some(stored) = inner
                        .state
                        .subscriptions
                        .iter_mut()
                        .find(|s| s.url == source.url)
                    {
                        stored.last_loaded_unix = Some(now);
                        stored.last_error = None;
                        stored.profile_count = count;
                        apply_subscription_metadata(stored, metadata);
                    }
                    let refresh_report = SubscriptionRefreshReport {
                        timestamp: now,
                        refreshed: 1,
                        added,
                        removed: removed_for_source,
                        changed: 0,
                        failed: 0,
                        entries: vec![SubscriptionRefreshEntry {
                            url: source.url.clone(),
                            status: "ok".to_owned(),
                            previous_count,
                            new_count: count,
                            added: added_for_source,
                            removed: removed_for_source,
                            changed: 0,
                            error: None,
                        }],
                    };
                    inner.state.last_subscription_refresh_report = Some(refresh_report.clone());
                    let _ = persist_state(&daemon.state_path, &inner.state);
                    let response = json!({
                        "url": source.url,
                        "refreshed": 1,
                        "added": added,
                        "profile_count": count,
                        "errors": Vec::<String>::new(),
                        "report": refresh_report,
                    });
                    (200, "application/json", response.to_string())
                }
                Err(error) => subscription_refresh_error_response(
                    &mut inner,
                    &daemon.state_path,
                    &source.url,
                    now,
                    previous_count,
                    error,
                ),
            }
        }
        SubscriptionLoadOutcome::Failed { attempts } => {
            let error = SubscriptionLoadOutcome::format_error(&attempts);
            subscription_refresh_error_response(
                &mut inner,
                &daemon.state_path,
                &source.url,
                now,
                previous_count,
                error,
            )
        }
    }
}

/// Record a failed single-subscription refresh without touching the existing
/// group. Both transport/parse failures and rejected state mutations use this
/// path, so their externally visible preservation semantics cannot diverge.
fn subscription_refresh_error_response(
    inner: &mut DaemonInner,
    state_path: &Path,
    url: &str,
    now: u64,
    previous_count: usize,
    error: String,
) -> (u16, &'static str, String) {
    if let Some(stored) = inner.state.subscriptions.iter_mut().find(|s| s.url == url) {
        stored.last_error = Some(error.clone());
    }
    let refresh_report = SubscriptionRefreshReport {
        timestamp: now,
        refreshed: 0,
        added: 0,
        removed: 0,
        changed: 0,
        failed: 1,
        entries: vec![SubscriptionRefreshEntry {
            url: url.to_owned(),
            status: "error".to_owned(),
            previous_count,
            new_count: previous_count,
            added: 0,
            removed: 0,
            changed: 0,
            error: Some(error.clone()),
        }],
    };
    inner.state.last_subscription_refresh_report = Some(refresh_report.clone());
    let _ = persist_state(state_path, &inner.state);
    (
        200,
        "application/json",
        json!({
            "url": url,
            "refreshed": 0,
            "added": 0,
            "errors": [error],
            "report": refresh_report,
        })
        .to_string(),
    )
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
                "title": s.title,
                "announcement": s.announcement,
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

/// Delete a saved subscription and all profiles that belong to it.
/// Body: `{"url": "..."}`. If the active profile was among the removed
/// profiles, the core is stopped and `active_profile_id` is cleared.
fn handle_subscriptions_delete(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
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

    let mut inner = lock(&daemon.inner);

    // Confirm the URL is a known saved subscription.
    let exists = inner.state.subscriptions.iter().any(|s| s.url == url);
    if !exists {
        return (
            404,
            "application/json",
            json!({"error": "subscription not found", "url": url}).to_string(),
        );
    }

    let removed_count = inner
        .state
        .profiles
        .iter()
        .filter(|p| p.group.as_deref() == Some(url))
        .count();

    push_undo_snapshot(&mut inner.state, format!("Delete subscription {url}"));
    let removed_active = purge_subscription(&mut inner.state, url);

    // If the active profile was removed, stop the core and clear the
    // config so we don't run with a stale outbound.
    if removed_active {
        let _ = inner.core.stop();
        let _ = fs::remove_file(&daemon.mihomo_config_path);
    }

    let _ = persist_state(&daemon.state_path, &inner.state);

    let response = json!({
        "url": url,
        "removed_profiles": removed_count,
        "removed_active": removed_active,
    });
    (200, "application/json", response.to_string())
}

fn handle_undo_list(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    let entries: Vec<Value> = inner
        .state
        .undo_stack
        .iter()
        .rev()
        .map(|entry| json!({"id": entry.id, "label": entry.label, "timestamp": entry.timestamp}))
        .collect();
    (
        200,
        "application/json",
        json!({"undo": entries, "count": entries.len()}).to_string(),
    )
}

fn handle_undo_restore(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return (
            400,
            "application/json",
            json!({"error": "invalid JSON body"}).to_string(),
        );
    };
    let Some(id) = value.get("id").and_then(Value::as_str) else {
        return (
            400,
            "application/json",
            json!({"error": "missing id"}).to_string(),
        );
    };

    let mut inner = lock(&daemon.inner);
    let Some(pos) = inner
        .state
        .undo_stack
        .iter()
        .position(|entry| entry.id == id)
    else {
        return (
            404,
            "application/json",
            json!({"error": "undo entry not found", "id": id}).to_string(),
        );
    };
    let entry = inner.state.undo_stack.remove(pos);
    let mut restored: HincyrayState = match deserialize_persisted_state(&entry.state_json) {
        Ok(state) => state,
        Err(error) => {
            return (
                500,
                "application/json",
                json!({"error": format!("restore snapshot: {error}")}).to_string(),
            );
        }
    };
    // Preserve newer undo entries except the consumed snapshot, so the user can
    // still recover from a mistaken restore if another snapshot existed.
    restored.undo_stack = inner.state.undo_stack.clone();
    inner.state = restored;
    inner.sessions.clear();
    let _ = inner.core.stop();
    let _ = fs::remove_file(&daemon.mihomo_config_path);
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
        json!({"restored": true, "id": entry.id, "label": entry.label}).to_string(),
    )
}

#[derive(Clone, Debug, Serialize)]
struct ManagedRoutingRule {
    id: String,
    source: &'static str,
    geobase_id: String,
    name: String,
    enabled: bool,
    applied: bool,
    target: &'static str,
    outbound: &'static str,
    domain_count: usize,
    network_count: usize,
    total_count: usize,
    revision: u64,
}

fn managed_geobase_routing_rules(
    manifest: &geobase::GeoBaseManifest,
    match_target: &str,
) -> Vec<ManagedRoutingRule> {
    manifest
        .applied_bases
        .iter()
        .flat_map(|base| {
            let applied = base.enabled && base.status == GeoBaseStatus::Ready;
            [
                (
                    "active",
                    "серый список",
                    "proxy-active",
                    if match_target == "direct" {
                        base.counts.active
                    } else {
                        0
                    },
                    base.counts.static_active,
                ),
                (
                    "direct",
                    "белый список",
                    "DIRECT",
                    base.counts.direct,
                    base.counts.static_direct,
                ),
            ]
            .into_iter()
            .filter(|(_, _, _, domain_count, network_count)| {
                *domain_count > 0 || *network_count > 0
            })
            .map(
                move |(target, label, outbound, domain_count, network_count)| ManagedRoutingRule {
                    id: format!("geobase:{}:{target}", base.id),
                    source: "geobase",
                    geobase_id: base.id.clone(),
                    name: format!("{} — {label}", base.name),
                    enabled: base.enabled,
                    applied,
                    target,
                    outbound,
                    domain_count,
                    network_count,
                    total_count: domain_count + network_count,
                    revision: base.revision,
                },
            )
        })
        .collect()
}

fn handle_routing_get(daemon: &Daemon) -> (u16, &'static str, String) {
    let (settings, rules, conflicts, servers) = {
        let mut inner = lock(&daemon.inner);
        sync_server_route_registry(&mut inner.state);
        let active_canonical = inner
            .state
            .active_profile_id
            .and_then(|id| inner.state.profiles.iter().find(|p| p.id == id))
            .map(canonical_profile_raw);
        let servers: Vec<Value> = inner
            .state
            .profiles
            .iter()
            .filter_map(|profile| {
                let canonical = canonical_profile_raw(profile);
                let entry = inner
                    .state
                    .server_route_registry
                    .iter()
                    .find(|entry| entry.canonical_raw == canonical)?;
                Some(json!({
                    "ref": entry.server_ref,
                    "id": profile.id,
                    "name": profile.name,
                    "protocol": profile.protocol.to_string(),
                    "address": profile.address,
                    "group": profile.group,
                    "active": active_canonical.as_deref() == Some(canonical.as_str()),
                    "dead": profile_is_dead(&inner.state, profile),
                }))
            })
            .collect();
        (
            inner.state.split_routing.clone(),
            inner.state.routing_rules.clone(),
            detect_routing_conflicts(&inner.state),
            servers,
        )
    };
    let mut rules = rules;
    rules.push(RoutingRule {
        enabled: settings.parovozik_enabled,
        name: "Паровозик Direct".to_owned(),
        target: "direct".to_owned(),
        domains: settings.parovozik_direct_domains.clone(),
        kind: "managed-parovozik".to_owned(),
        ..RoutingRule::default()
    });
    rules.push(RoutingRule {
        enabled: settings.parovozik_enabled,
        name: "Паровозик VPN".to_owned(),
        target: "parovozik".to_owned(),
        domains: settings.parovozik_vpn_domains.clone(),
        kind: "managed-parovozik".to_owned(),
        ..RoutingRule::default()
    });
    let manifest = match daemon.geobase_store().load_manifest() {
        Ok(manifest) => manifest,
        Err(error) => {
            return (
                500,
                "application/json",
                json!({"error": format!("GeoBase manifest: {error}")}).to_string(),
            );
        }
    };
    let response = json!({
        "settings": settings,
        "rules": rules,
        "catalog": popular_service_catalog(),
        "sources": rule_sources(),
        "conflicts": conflicts,
        "managed_rules": managed_geobase_routing_rules(&manifest, &settings.match_target),
        "servers": servers,
        "geobase_requires_apply": manifest.requires_apply(),
    });
    (200, "application/json", response.to_string())
}

fn handle_api_contracts() -> (u16, &'static str, String) {
    let response = ApiContractDescriptor {
        version: 1,
        bounded_endpoints: vec![
            "/api/onboarding/status",
            "/api/routing/summary",
            "/api/routing/connection-context",
            "/api/routing/preview",
            "/api/routing/explain",
            "/api/memory-estimate",
            "/api/mihomo-api/connections/page",
            "/api/mihomo-api/connections/device-traffic",
            "/api/safe-mode",
        ],
        schema_endpoint: "/api/openapi.json",
        endpoints: api_endpoint_contracts(),
        state_changing_requires_same_origin: true,
        authentication: "argon2id-password+cSPRNG-bearer-expiry",
    };
    json_response(&response)
}

fn handle_onboarding_status(daemon: &Daemon) -> (u16, &'static str, String) {
    let (state, core_running, firewall_active, tproxy_available, policy_mark_runtime) = {
        let mut inner = lock(&daemon.inner);
        (
            inner.state.clone(),
            inner.core.is_running(),
            inner.firewall.active,
            inner.firewall.tproxy_available,
            inner.firewall.policy_mark.clone(),
        )
    };
    let geo_dir = geo_dir_from_state(&state).map(PathBuf::from);
    let geoip_exists = geo_dir
        .as_ref()
        .is_some_and(|path| path.join("geoip.metadb").is_file());
    let mihomo_version = get_mihomo_version(&state.mihomo_path).ok();
    let active_profile_ok = state
        .active_profile_id
        .is_some_and(|id| state.profiles.iter().any(|profile| profile.id == id));
    let hook_required = Path::new("/opt/etc/ndm/netfilter.d").is_dir();
    let hook_exists = Path::new("/opt/etc/ndm/netfilter.d/hincyray.sh").is_file();
    let policy_mark = policy_mark_runtime
        .or_else(|| state.split_routing.policy_mark.clone())
        .or_else(|| query_policy_mark(&state.split_routing.policy_name));
    let proc_modules_available = Path::new("/proc/modules").is_file();
    let modules_ok = !state.split_routing.enabled
        || !proc_modules_available
        || (["xt_TPROXY", "xt_socket", "xt_comment"]
            .iter()
            .all(|name| kernel_module_loaded(name))
            || tproxy_available);
    let ec_check = mihomo_controller(&state.mihomo_features).map(|(addr, secret)| {
        mihomo_api_get_response(&addr, secret.as_deref(), "/version")
            .is_ok_and(|(status, _)| status < 500)
    });
    let dns_check = if core_running && state.split_routing.enabled {
        dns_query_tcp("127.0.0.1", 1053, "example.com")
            .get("ok")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    } else {
        true
    };
    let checks = vec![
        readiness_check(
            "mihomo",
            "Mihomo binary",
            mihomo_version.is_some(),
            mihomo_version.unwrap_or_else(|| format!("{} unavailable", state.mihomo_path)),
            "Install Mihomo or correct mihomo_path",
        ),
        readiness_check(
            "profile",
            "Active profile",
            active_profile_ok,
            format!(
                "{} profiles; active={:?}",
                state.profiles.len(),
                state.active_profile_id
            ),
            "Import and select a profile",
        ),
        readiness_check(
            "geoip",
            "GeoIP database",
            geoip_exists,
            geo_dir
                .map(|path| path.join("geoip.metadb").display().to_string())
                .unwrap_or_else(|| "geo directory is not configured".to_owned()),
            "Download geoip.metadb into the configured geo directory",
        ),
        readiness_check(
            "policy-mark",
            "Keenetic policy mark",
            !state.split_routing.enabled || policy_mark.is_some(),
            policy_mark.unwrap_or_else(|| {
                format!(
                    "policy {:?} has no connmark",
                    state.split_routing.policy_name
                )
            }),
            "Create/select the Keenetic traffic policy and apply routing",
        ),
        readiness_check(
            "kernel-modules",
            "Kernel modules",
            modules_ok,
            if proc_modules_available {
                format!(
                    "xt_TPROXY={} xt_socket={} xt_comment={} tproxy={}",
                    kernel_module_loaded("xt_TPROXY"),
                    kernel_module_loaded("xt_socket"),
                    kernel_module_loaded("xt_comment"),
                    tproxy_available
                )
            } else {
                "not a Linux router host".to_owned()
            },
            "Install/load xt_TPROXY, xt_socket, and xt_comment modules",
        ),
        readiness_check(
            "external-controller",
            "Mihomo External Controller",
            ec_check.unwrap_or(true),
            match ec_check {
                Some(true) => "reachable".to_owned(),
                Some(false) => "enabled but unreachable".to_owned(),
                None => "disabled by configuration".to_owned(),
            },
            "Enable EC or start Mihomo so the daemon can query runtime state",
        ),
        readiness_check(
            "dns",
            "DNS listener",
            dns_check,
            if state.split_routing.enabled {
                if core_running {
                    "127.0.0.1:1053 TCP query".to_owned()
                } else {
                    "core stopped; DNS runtime not checked".to_owned()
                }
            } else {
                "split routing disabled".to_owned()
            },
            "Start Mihomo and ensure DNS listener 1053 is generated",
        ),
        readiness_check(
            "core",
            "Mihomo core",
            core_running,
            if core_running { "running" } else { "stopped" }.to_owned(),
            "Start the core after profile/config checks pass",
        ),
        readiness_check(
            "firewall",
            "Transparent firewall",
            !state.split_routing.enabled || firewall_active,
            format!(
                "split={} firewall={} tproxy={}",
                state.split_routing.enabled, firewall_active, tproxy_available
            ),
            "Apply routing to install REDIRECT/TPROXY rules",
        ),
        readiness_check(
            "ndm-hook",
            "Keenetic firewall hook",
            !hook_required || hook_exists,
            if hook_required {
                format!("installed={hook_exists}")
            } else {
                "not a Keenetic/Entware host".to_owned()
            },
            "Apply routing once to install the ndm hook",
        ),
    ];
    let ready = checks.iter().all(|check| check.status == "ok");
    json_response(&OnboardingStatusResponse {
        ready,
        version: env!("CARGO_PKG_VERSION"),
        checks,
    })
}

fn readiness_check(
    id: &'static str,
    label: &'static str,
    ok: bool,
    detail: String,
    remediation: &'static str,
) -> ReadinessCheck {
    ReadinessCheck {
        id,
        label,
        status: if ok { "ok" } else { "error" },
        detail,
        remediation: (!ok).then_some(remediation),
    }
}

fn handle_routing_summary(daemon: &Daemon) -> (u16, &'static str, String) {
    let manifest = match daemon.geobase_store().load_manifest() {
        Ok(manifest) => manifest,
        Err(error) => return json_error(500, &format!("GeoBase manifest: {error}")),
    };
    let inner = lock(&daemon.inner);
    let conflicts = detect_routing_conflicts(&inner.state);
    json_response(&RoutingSummaryResponse {
        enabled: inner.state.split_routing.enabled,
        safe_mode_enabled: inner.state.safe_mode_enabled,
        match_target: inner.state.split_routing.match_target.clone(),
        user_rule_count: inner.state.routing_rules.len(),
        enabled_user_rule_count: inner
            .state
            .routing_rules
            .iter()
            .filter(|rule| rule.enabled)
            .count(),
        device_route_count: inner.state.device_routes.len(),
        managed_rule_count: managed_geobase_routing_rules(
            &manifest,
            &inner.state.split_routing.match_target,
        )
        .len(),
        server_count: inner.state.profiles.len(),
        conflict_count: conflicts.len(),
        geobase_requires_apply: manifest.requires_apply(),
    })
}

fn handle_routing_connection_context(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    let active_canonical = inner
        .state
        .active_profile_id
        .and_then(|id| inner.state.profiles.iter().find(|profile| profile.id == id))
        .map(canonical_profile_raw);
    let servers = inner
        .state
        .profiles
        .iter()
        .filter_map(|profile| {
            let canonical = canonical_profile_raw(profile);
            let entry = inner
                .state
                .server_route_registry
                .iter()
                .find(|entry| entry.canonical_raw == canonical)?;
            Some(RoutingServerSummary {
                reference: entry.server_ref.clone(),
                id: profile.id,
                name: profile.name.clone(),
                protocol: profile.protocol.to_string(),
                address: profile.address.clone(),
                group: profile.group.clone(),
                active: active_canonical.as_deref() == Some(canonical.as_str()),
            })
        })
        .collect();
    json_response(&RoutingConnectionContextResponse { servers })
}

fn handle_routing_preview(daemon: &Daemon) -> (u16, &'static str, String) {
    let (state, core_running, firewall_running, tproxy_available) = {
        let mut inner = lock(&daemon.inner);
        (
            inner.state.clone(),
            inner.core.is_running(),
            inner.firewall.is_running(),
            inner.firewall.tproxy_available,
        )
    };
    let firewall_rules_running = if firewall_running || !state.split_routing.enabled {
        firewall_rules_exist(tproxy_available)
    } else {
        false
    };
    let manifest = match daemon.geobase_store().load_manifest() {
        Ok(manifest) => manifest,
        Err(error) => return json_error(500, &format!("GeoBase manifest: {error}")),
    };
    let providers = match project_geobase_manifest(
        daemon,
        &manifest,
        GeoBaseProjection::Desired,
        state.split_routing.match_target.trim() == "direct",
    ) {
        Ok(providers) => providers,
        Err(error) => return json_error(400, &error),
    };
    let desired = match build_daemon_config(&state, &providers) {
        Ok(config) => config,
        Err(error) => return json_error(400, &error),
    };
    let desired_hash = sha256_hex(desired.as_bytes());
    let applied = fs::read(&daemon.mihomo_config_path).ok();
    let applied_hash = applied.as_deref().map(sha256_hex);
    let config_requires_apply = applied_hash.as_deref() != Some(desired_hash.as_str());
    let geobase_requires_apply = manifest.requires_apply();
    let core_requires_apply = state.active_profile_id.is_some() && !core_running;
    let firewall_requires_apply = firewall_runtime_requires_apply(
        state.split_routing.enabled,
        firewall_running,
        firewall_rules_running,
    );
    let requires_apply = config_requires_apply
        || geobase_requires_apply
        || core_requires_apply
        || firewall_requires_apply;
    let mut changes = Vec::new();
    if config_requires_apply {
        changes.push("generated Mihomo config differs from the applied file".to_owned());
    }
    if geobase_requires_apply {
        changes.push("desired GeoBase generation is not applied".to_owned());
    }
    if core_requires_apply {
        changes.push("Mihomo core is stopped but should be running".to_owned());
    }
    if state.split_routing.enabled && !firewall_running {
        changes.push("transparent firewall is stopped but split routing is enabled".to_owned());
    } else if state.split_routing.enabled && !firewall_rules_running {
        changes.push("transparent firewall runtime rules are missing".to_owned());
    } else if !state.split_routing.enabled && (firewall_running || firewall_rules_running) {
        changes
            .push("transparent firewall remains active while split routing is disabled".to_owned());
    }
    if state.safe_mode_enabled {
        changes.push("safe mode suppresses heavy optional rule sources".to_owned());
    }
    let core_restart = requires_apply && core_running;
    let firewall_reload = firewall_requires_apply
        || ((config_requires_apply || geobase_requires_apply) && state.split_routing.enabled);
    let diff = routing_preview_diff(
        &desired,
        applied
            .as_deref()
            .and_then(|bytes| std::str::from_utf8(bytes).ok()),
        config_requires_apply,
        geobase_requires_apply,
        core_restart,
        firewall_reload,
    );
    json_response(&RoutingPreviewResponse {
        requires_apply,
        core_restart,
        firewall_reload,
        desired_config_sha256: desired_hash,
        applied_config_sha256: applied_hash,
        changes,
        diff,
        warnings: detect_routing_conflicts(&state),
    })
}

#[derive(Default)]
struct ConfigPreviewSummary {
    rule_count: usize,
    match_target: Option<String>,
}

fn config_preview_summary(config_yaml: &str) -> ConfigPreviewSummary {
    let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(config_yaml) else {
        return ConfigPreviewSummary::default();
    };
    let Some(rules) = value.get("rules").and_then(serde_yaml::Value::as_sequence) else {
        return ConfigPreviewSummary::default();
    };
    let match_target = rules.iter().rev().find_map(|rule| {
        let raw = rule.as_str()?;
        let mut parts = raw.split(',').map(str::trim);
        (parts.next()?.eq_ignore_ascii_case("MATCH")).then(|| parts.next().unwrap_or("").to_owned())
    });
    ConfigPreviewSummary {
        rule_count: rules.len(),
        match_target,
    }
}

fn routing_preview_diff(
    desired_yaml: &str,
    applied_yaml: Option<&str>,
    config_requires_apply: bool,
    geobase_requires_apply: bool,
    core_restart: bool,
    firewall_reload: bool,
) -> Vec<RoutingPreviewDiff> {
    let desired = config_preview_summary(desired_yaml);
    let applied = applied_yaml.map(config_preview_summary).unwrap_or_default();
    let mut diff = Vec::new();
    if config_requires_apply {
        let delta = desired.rule_count as i64 - applied.rule_count as i64;
        diff.push(RoutingPreviewDiff {
            kind: "rules",
            title: if delta == 0 {
                "Mihomo rules will be regenerated".to_owned()
            } else if delta > 0 {
                format!("{} routing rules will be added", delta)
            } else {
                format!("{} routing rules will be removed", delta.abs())
            },
            before: Some(applied.rule_count.to_string()),
            after: Some(desired.rule_count.to_string()),
            delta: Some(delta),
        });
    }
    if desired.match_target != applied.match_target {
        diff.push(RoutingPreviewDiff {
            kind: "match-target",
            title: "MATCH target will change".to_owned(),
            before: applied.match_target,
            after: desired.match_target,
            delta: None,
        });
    }
    if geobase_requires_apply {
        diff.push(RoutingPreviewDiff {
            kind: "geobase",
            title: "Desired GeoBase generation will be applied".to_owned(),
            before: None,
            after: None,
            delta: None,
        });
    }
    if core_restart {
        diff.push(RoutingPreviewDiff {
            kind: "core",
            title: "Mihomo core will be restarted".to_owned(),
            before: Some("running".to_owned()),
            after: Some("restarted".to_owned()),
            delta: None,
        });
    }
    if firewall_reload {
        diff.push(RoutingPreviewDiff {
            kind: "firewall",
            title: "Transparent firewall rules will be reloaded".to_owned(),
            before: None,
            after: None,
            delta: None,
        });
    }
    diff
}

fn firewall_runtime_requires_apply(
    split_enabled: bool,
    firewall_running: bool,
    firewall_rules_running: bool,
) -> bool {
    if split_enabled {
        !firewall_running || !firewall_rules_running
    } else {
        firewall_running || firewall_rules_running
    }
}

fn handle_routing_explain(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return json_error(400, "invalid JSON body");
    };
    let raw = value
        .get("resource")
        .or_else(|| value.get("host"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let Some(resource) = normalize_routing_resource(raw) else {
        return json_error(400, "resource is not a routable host or IP");
    };
    let (host, ip) = match resource.kind {
        RoutingResourceKind::Domain => (resource.value.clone(), String::new()),
        RoutingResourceKind::Ip => (String::new(), resource.value.clone()),
    };
    let request = TraceRequest {
        host,
        ip,
        source_ip: value
            .get("source_ip")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_owned(),
        port: value
            .get("port")
            .and_then(Value::as_u64)
            .map(|port| port as u16),
        network: value
            .get("network")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase(),
    };
    let inner = lock(&daemon.inner);
    let mut trace = trace_routing_decision(&inner.state, &request);
    trace["resource"] = json!(resource.value);
    trace["resource_kind"] = json!(resource.kind.as_str());
    trace["safe_mode_enabled"] = json!(inner.state.safe_mode_enabled);
    (200, "application/json", trace.to_string())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = sha256(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn json_response<T: Serialize>(value: &T) -> (u16, &'static str, String) {
    match serde_json::to_string(value) {
        Ok(body) => (200, "application/json", body),
        Err(error) => json_error(500, &format!("serialize response: {error}")),
    }
}

/// Detect conflicts between per-rule ports and global PortMode.
/// Returns a list of warning strings (empty if no conflicts).
fn detect_routing_conflicts(state: &HincyrayState) -> Vec<String> {
    let mut warnings = Vec::new();
    let split = &state.split_routing;

    match split.port_mode {
        PortMode::AllowList if !split.proxy_ports.is_empty() => {
            let allowed: Vec<&str> = split
                .proxy_ports
                .iter()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();
            for rule in state.routing_rules.iter().filter(|r| r.enabled) {
                for port in rule
                    .ports
                    .iter()
                    .map(|p| p.trim())
                    .filter(|p| !p.is_empty())
                {
                    if !allowed.contains(&port) {
                        warnings.push(format!(
                            "правило «{}»: порт {} не входит в AllowList ({}) — \
                             глобальный PortMode может перехватить трафик раньше",
                            rule.name,
                            port,
                            allowed.join(",")
                        ));
                    }
                }
            }
        }
        PortMode::DenyList if !split.bypass_ports.is_empty() => {
            let bypassed: Vec<&str> = split
                .bypass_ports
                .iter()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();
            for rule in state.routing_rules.iter().filter(|r| r.enabled) {
                for port in rule
                    .ports
                    .iter()
                    .map(|p| p.trim())
                    .filter(|p| !p.is_empty())
                {
                    if bypassed.contains(&port) {
                        warnings.push(format!(
                            "правило «{}»: порт {} входит в DenyList bypass ({}) — \
                             глобальный PortMode направит его напрямую",
                            rule.name,
                            port,
                            bypassed.join(",")
                        ));
                    }
                }
            }
        }
        _ => {}
    }

    warnings
}

fn handle_routing_settings(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return (
            400,
            "application/json",
            json!({"error": "invalid JSON body"}).to_string(),
        );
    };
    let apply_requested = value.get("apply").and_then(Value::as_bool).unwrap_or(false);
    let (previous_state, settings) = {
        let mut inner = lock(&daemon.inner);
        let previous_state = inner.state.clone();
        if let Some(v) = value.get("enabled").and_then(Value::as_bool) {
            inner.state.split_routing.enabled = v;
            // Transparent proxy requires DNS — force enabled alongside
            // split routing so the state matches the firewall DNAT rules.
            if v {
                inner.state.dns_settings.enabled = true;
            }
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
        if let Some(v) = value.get("redirect_port").and_then(Value::as_u64) {
            inner.state.split_routing.redirect_port = v as u16;
        }
        if let Some(v) = value
            .get("policy_name")
            .and_then(Value::as_str)
            .filter(|v| !v.trim().is_empty())
        {
            inner.state.split_routing.policy_name = v.trim().to_owned();
        }
        if let Some(v) = value.get("quic_mode").and_then(Value::as_str) {
            inner.state.split_routing.quic_mode = match v {
                "proxy" => QuicMode::Proxy,
                _ => QuicMode::Block,
            };
        }
        if let Some(v) = value.get("port_mode").and_then(Value::as_str) {
            inner.state.split_routing.port_mode = match v {
                "allow_list" => PortMode::AllowList,
                "deny_list" => PortMode::DenyList,
                _ => PortMode::All,
            };
        }
        if let Some(v) = value.get("proxy_ports").and_then(Value::as_array) {
            inner.state.split_routing.proxy_ports = v
                .iter()
                .filter_map(|item| item.as_str().map(|s| s.trim().to_owned()))
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Some(v) = value.get("bypass_ports").and_then(Value::as_array) {
            inner.state.split_routing.bypass_ports = v
                .iter()
                .filter_map(|item| item.as_str().map(|s| s.trim().to_owned()))
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Some(v) = value.get("geo_asset_path").and_then(Value::as_str) {
            inner.state.split_routing.geo_asset_path = v.trim().to_owned();
        }
        if let Some(v) = value.get("ru_direct_mode").and_then(Value::as_str) {
            inner.state.split_routing.ru_direct_mode = v.trim().to_owned();
        }
        if let Some(v) = value.get("ru_direct_exceptions").and_then(Value::as_array) {
            inner.state.split_routing.ru_direct_exceptions = v
                .iter()
                .filter_map(|item| item.as_str().map(|s| s.trim().to_owned()))
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Some(v) = value
            .get("auto_vpn_learning_enabled")
            .and_then(Value::as_bool)
        {
            inner.state.split_routing.auto_vpn_learning_enabled = v;
        }
        if let Some(v) = value.get("auto_vpn_exceptions").and_then(Value::as_array) {
            let items: Vec<String> = v
                .iter()
                .filter_map(|item| normalize_auto_vpn_domain(item.as_str()?))
                .collect();
            inner.state.split_routing.auto_vpn_exceptions = dedup_limited_domains(items);
            prune_auto_vpn_metadata(&mut inner.state.split_routing);
        }
        if let Some(v) = value.get("parovozik_enabled").and_then(Value::as_bool) {
            inner.state.split_routing.parovozik_enabled = v;
        }
        if let Some(v) = value
            .get("parovozik_direct_domains")
            .and_then(Value::as_array)
        {
            let items: Vec<String> = v
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect();
            inner.state.split_routing.parovozik_direct_domains =
                normalize_parovozik_domains(&items);
        }
        if let Some(v) = value.get("parovozik_vpn_domains").and_then(Value::as_array) {
            let items: Vec<String> = v
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect();
            inner.state.split_routing.parovozik_vpn_domains = normalize_parovozik_domains(&items);
        }
        if let Some(v) = value.get("parovozik_server_refs").and_then(Value::as_array) {
            let items: Vec<String> = v
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect();
            let mut candidate = inner.state.clone();
            sync_server_route_registry(&mut candidate);
            let refs = match normalize_parovozik_server_refs(&candidate, &items) {
                Ok(refs) => refs,
                Err(error) => return json_error(400, &error),
            };
            inner.state.server_route_registry = candidate.server_route_registry;
            inner.state.split_routing.parovozik_server_refs = refs;
        }
        if let Some(v) = value.get("match_target").and_then(Value::as_str) {
            let target = v.trim().to_ascii_lowercase();
            // Validate: when no routing rules exist, can't set to "direct"
            // (would leave router with no VPN routing at all).
            if target == "direct" && inner.state.routing_rules.is_empty() {
                return (
                400,
                "application/json",
                json!({"error": "нельзя установить MATCH,direct когда нет правил маршрутизации — весь трафик пойдёт напрямую"}).to_string(),
            );
            }
            inner.state.split_routing.match_target = if target == "direct" {
                "direct".to_owned()
            } else {
                "proxy".to_owned()
            };
        }
        if let Err(error) = persist_state(&daemon.state_path, &inner.state) {
            return (
                500,
                "application/json",
                json!({"error": format!("persist state: {error}")}).to_string(),
            );
        }
        (previous_state, inner.state.split_routing.clone())
    };
    if apply_requested {
        return match activate_current_config(daemon, false, true, GeoBaseProjection::Desired) {
            Ok(result) => (
                200,
                "application/json",
                json!({
                    "settings": settings,
                    "applied": true,
                    "core_status": result.core_status,
                    "firewall_status": result.firewall_status,
                    "generation": result.generation,
                    "gc_warning": result.gc_warning,
                })
                .to_string(),
            ),
            Err(error) => {
                let rollback = restore_state_after_failed_policy_change(daemon, previous_state);
                json_error(500, &format!("{error}; state rollback: {rollback}"))
            }
        };
    }
    (
        200,
        "application/json",
        json!({"settings": settings, "applied": false, "requires_apply": true}).to_string(),
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
    let apply_requested = value.get("apply").and_then(Value::as_bool).unwrap_or(false);
    let rules_value = value.get("rules").cloned().unwrap_or(value);
    let Ok(mut rules) = serde_json::from_value::<Vec<RoutingRule>>(rules_value) else {
        return (
            400,
            "application/json",
            json!({"error": "expected rules array"}).to_string(),
        );
    };
    rules.retain(|rule| rule.kind != "managed-parovozik");
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
        rule.ports = normalize_route_items(&rule.ports);
        rule.network = rule.network.trim().to_owned();
    }
    if let Err(error) = validate_router_routing_rules(&rules) {
        return (400, "application/json", json!({"error": error}).to_string());
    }
    let (previous_state, saved_rules, removes_rules) = {
        let mut inner = lock(&daemon.inner);
        let mut candidate = inner.state.clone();
        sync_server_route_registry(&mut candidate);
        if let Err(error) = validate_routing_targets(&candidate, &rules, &candidate.device_routes) {
            return (400, "application/json", json!({"error": error}).to_string());
        }
        let previous_state = inner.state.clone();
        push_undo_snapshot(&mut inner.state, "Replace routing rules");
        inner.state.server_route_registry = candidate.server_route_registry;
        inner.state.routing_rules = rules;
        if let Err(error) = persist_state(&daemon.state_path, &inner.state) {
            return (
                500,
                "application/json",
                json!({"error": format!("persist state: {error}")}).to_string(),
            );
        }
        let removes_rules = routing_rules_are_strict_deletion(
            &previous_state.routing_rules,
            &inner.state.routing_rules,
        );
        (
            previous_state,
            inner.state.routing_rules.clone(),
            removes_rules,
        )
    };

    if apply_requested {
        return match activate_current_config(daemon, false, true, GeoBaseProjection::Desired) {
            Ok(result) => (
                200,
                "application/json",
                json!({
                    "rules": saved_rules,
                    "applied": true,
                    "core_status": result.core_status,
                    "firewall_status": result.firewall_status,
                    "generation": result.generation,
                    "gc_warning": result.gc_warning,
                })
                .to_string(),
            ),
            Err(error) if removes_rules => (
                200,
                "application/json",
                json!({
                    "rules": saved_rules,
                    "applied": false,
                    "requires_apply": true,
                    "activation_error": error,
                })
                .to_string(),
            ),
            Err(error) => {
                let rollback = restore_state_after_failed_policy_change(daemon, previous_state);
                json_error(500, &format!("{error}; state rollback: {rollback}"))
            }
        };
    }

    (
        200,
        "application/json",
        json!({"rules": saved_rules, "applied": false, "requires_apply": true}).to_string(),
    )
}

fn routing_rules_are_strict_deletion(previous: &[RoutingRule], next: &[RoutingRule]) -> bool {
    if next.len() >= previous.len() {
        return false;
    }
    let mut remaining = next.iter();
    let mut expected = remaining.next();
    for rule in previous {
        if expected == Some(rule) {
            expected = remaining.next();
        }
    }
    expected.is_none()
}

fn restore_state_after_failed_policy_change(
    daemon: &Daemon,
    previous_state: HincyrayState,
) -> String {
    let mut inner = lock(&daemon.inner);
    inner.state = previous_state;
    match persist_state(&daemon.state_path, &inner.state) {
        Ok(()) => "restored".to_owned(),
        Err(error) => format!("failed ({error})"),
    }
}

fn handle_routing_resource_route(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return (
            400,
            "application/json",
            json!({"error": "invalid JSON body"}).to_string(),
        );
    };
    let Some(raw_resource) = value
        .get("resource")
        .or_else(|| value.get("site"))
        .or_else(|| value.get("host"))
        .and_then(Value::as_str)
    else {
        return (
            400,
            "application/json",
            json!({"error": "missing resource"}).to_string(),
        );
    };
    let Some(resource) = normalize_routing_resource(raw_resource) else {
        return (
            400,
            "application/json",
            json!({"error": "resource is not a routable host or IP"}).to_string(),
        );
    };
    let target = value
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or("active")
        .trim()
        .to_owned();
    if let Err(error) = RoutingTarget::parse(&target) {
        return (400, "application/json", json!({"error": error}).to_string());
    }

    let source_ip = value.get("source_ip").and_then(Value::as_str);
    let close_connections = value
        .get("close_connections")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let rule_name = value
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("Resource route: {}", resource.value));

    let previous_state = {
        let mut inner = lock(&daemon.inner);
        let mut candidate = inner.state.clone();
        sync_server_route_registry(&mut candidate);
        push_undo_snapshot(&mut candidate, format!("Route resource {}", resource.value));
        upsert_resource_routing_rule(&mut candidate.routing_rules, &resource, &target, &rule_name);
        if let Err(error) = validate_router_routing_rules(&candidate.routing_rules) {
            return (400, "application/json", json!({"error": error}).to_string());
        }
        if let Err(error) = validate_routing_targets(
            &candidate,
            &candidate.routing_rules,
            &candidate.device_routes,
        ) {
            return (400, "application/json", json!({"error": error}).to_string());
        }
        let previous_state = inner.state.clone();
        inner.state = candidate;
        if let Err(error) = persist_state(&daemon.state_path, &inner.state) {
            return (
                500,
                "application/json",
                json!({"error": format!("persist state: {error}")}).to_string(),
            );
        }
        previous_state
    };

    let activation = match activate_current_config(daemon, false, true, GeoBaseProjection::Desired)
    {
        Ok(result) => result,
        Err(error) => {
            let rollback = restore_state_after_failed_policy_change(daemon, previous_state);
            return json_error(500, &format!("{error}; state rollback: {rollback}"));
        }
    };

    let close_result = if close_connections {
        close_resource_connections(daemon, &resource, source_ip)
    } else {
        ResourceCloseResult::default()
    };

    let close_ok = close_result.errors.is_empty();
    let status = if close_ok { 200 } else { 207 };
    let response = json!({
        "ok": close_ok,
        "resource": resource.value,
        "resource_kind": resource.kind.as_str(),
        "target": target,
        "rule_name": rule_name,
        "applied": true,
        "core_status": activation.core_status,
        "firewall_status": activation.firewall_status,
        "generation": activation.generation,
        "closed_connections": close_result.closed,
        "close_errors": close_result.errors,
        "gc_warning": activation.gc_warning,
    });
    (status, "application/json", response.to_string())
}

#[derive(Default)]
struct ResourceCloseResult {
    closed: usize,
    errors: Vec<String>,
}

fn upsert_resource_routing_rule(
    rules: &mut Vec<RoutingRule>,
    resource: &RoutingResource,
    target: &str,
    rule_name: &str,
) {
    let existing = rules.iter_mut().find(|rule| match resource.kind {
        RoutingResourceKind::Domain => rule.domains.iter().any(|domain| {
            normalize_routing_resource(domain).is_some_and(|normalized| {
                normalized.kind == resource.kind && normalized.value == resource.value
            })
        }),
        RoutingResourceKind::Ip => rule.ips.iter().any(|ip| {
            normalize_routing_resource(ip).is_some_and(|normalized| {
                normalized.kind == resource.kind && normalized.value == resource.value
            })
        }),
    });
    if let Some(rule) = existing {
        rule.enabled = true;
        rule.target = target.to_owned();
        rule.name = if rule.name.trim().is_empty() {
            rule_name.to_owned()
        } else {
            rule.name.trim().to_owned()
        };
        return;
    }

    let mut rule = RoutingRule {
        enabled: true,
        name: rule_name.to_owned(),
        target: target.to_owned(),
        network: "any".to_owned(),
        port_mode: "include".to_owned(),
        ..RoutingRule::default()
    };
    match resource.kind {
        RoutingResourceKind::Domain => rule.domains.push(resource.value.clone()),
        RoutingResourceKind::Ip => rule.ips.push(resource.value.clone()),
    }
    rules.push(rule);
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
        .then_some(proxy_info.socks5h_url.as_str());
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
    match activate_current_config(daemon, true, true, GeoBaseProjection::Desired) {
        Ok(result) => (
            200,
            "application/json",
            json!({
                "applied": true,
                "core_status": result.core_status,
                "firewall_status": result.firewall_status,
                "generation": result.generation,
                "gc_warning": result.gc_warning,
            })
            .to_string(),
        ),
        Err(error) => json_error(500, &error),
    }
}

/// v0.17: Reset routing policy to factory defaults.
///
/// Resets: ru_direct, match_target, port_mode, proxy_ports,
/// quic_mode, routing_rules, raw_rules. Infrastructure settings (enabled,
/// auto_switch, vpn_subnet, redirect_port, policy_name, geo_asset_path)
/// are preserved. Pass `{"apply":true}` to persist, regenerate the config,
/// restart the core, and roll state back if activation fails.
fn handle_routing_reset(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let value = if body.trim().is_empty() {
        json!({})
    } else {
        match serde_json::from_str::<Value>(body) {
            Ok(value) => value,
            Err(error) => return json_error(400, &format!("invalid JSON body: {error}")),
        }
    };
    let apply_requested = value.get("apply").and_then(Value::as_bool).unwrap_or(false);
    let previous_state = {
        let mut inner = lock(&daemon.inner);
        let previous_state = inner.state.clone();
        push_undo_snapshot(&mut inner.state, "Reset routing defaults");

        // Reset routing policy fields to factory defaults.
        let s = &mut inner.state.split_routing;
        s.ru_direct_mode = "off".to_owned();
        s.ru_direct_exceptions = Vec::new();
        s.auto_vpn_exceptions = Vec::new();
        s.auto_vpn_last_checked_unix.clear();
        s.auto_vpn_learning_enabled = false;
        s.parovozik_enabled = false;
        s.parovozik_direct_domains.clear();
        s.parovozik_vpn_domains.clear();
        s.parovozik_server_refs.clear();
        s.parovozik_last_checked_unix.clear();
        s.match_target = "proxy".to_owned();
        s.port_mode = PortMode::AllowList;
        s.proxy_ports = vec!["80".to_owned(), "443".to_owned()];
        s.bypass_ports = Vec::new();
        s.quic_mode = QuicMode::Block;
        s.block_quic_global = false;

        // Reset routing rules to just QUIC Block (system-level).
        inner.state.routing_rules = vec![RoutingRule {
            enabled: true,
            name: "QUIC Block".to_owned(),
            kind: String::new(),
            pattern: String::new(),
            target: "reject".to_owned(),
            domains: Vec::new(),
            ips: Vec::new(),
            services: Vec::new(),
            ports: vec!["443".to_owned()],
            network: "udp".to_owned(),
            port_mode: "include".to_owned(),
        }];

        // Clear user-defined raw Mihomo rules (RKN bypass injects its own).
        inner.state.mihomo_features.raw_rules = Vec::new();

        if let Err(error) = persist_state(&daemon.state_path, &inner.state) {
            return (
                500,
                "application/json",
                json!({"error": format!("persist state: {error}")}).to_string(),
            );
        }
        previous_state
    };

    if apply_requested {
        return match activate_current_config(daemon, false, true, GeoBaseProjection::Desired) {
            Ok(result) => (
                200,
                "application/json",
                json!({
                    "reset": true,
                    "applied": true,
                    "core_status": result.core_status,
                    "firewall_status": result.firewall_status,
                    "generation": result.generation,
                    "gc_warning": result.gc_warning,
                })
                .to_string(),
            ),
            Err(error) => {
                let rollback = restore_state_after_failed_policy_change(daemon, previous_state);
                json_error(500, &format!("{error}; state rollback: {rollback}"))
            }
        };
    }

    (
        200,
        "application/json",
        json!({
            "reset": true,
            "applied": false,
            "requires_apply": true,
            "message": "Настройки сброшены к заводским. Нажмите «Применить» для активации."
        })
        .to_string(),
    )
}

fn handle_routing_presets_list() -> (u16, &'static str, String) {
    let presets = routing_presets();
    (
        200,
        "application/json",
        json!({"presets": presets}).to_string(),
    )
}

fn handle_routing_preset_apply(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return (
            400,
            "application/json",
            json!({"error": "invalid JSON body"}).to_string(),
        );
    };
    let Some(preset_id) = value.get("preset").and_then(Value::as_str) else {
        return (
            400,
            "application/json",
            json!({"error": "missing \"preset\" field"}).to_string(),
        );
    };
    let Some(preset) = routing_presets().into_iter().find(|p| p.id == preset_id) else {
        return (
            400,
            "application/json",
            json!({"error": "unknown preset", "preset": preset_id}).to_string(),
        );
    };
    if let Err(error) = validate_router_routing_rules(&preset.rules) {
        return (
            400,
            "application/json",
            json!({"error": error, "preset": preset_id}).to_string(),
        );
    }

    let apply_requested = value.get("apply").and_then(Value::as_bool).unwrap_or(false);

    let target_override = value.get("target").and_then(Value::as_str).map(|s| {
        let t = s.trim().to_ascii_lowercase();
        match t.as_str() {
            "direct" | "reject" => t,
            _ => "active".to_owned(),
        }
    });

    let previous_state = {
        let mut inner = lock(&daemon.inner);
        let previous_state = inner.state.clone();
        push_undo_snapshot(&mut inner.state, format!("Apply preset {preset_id}"));

        // Add preset rules to existing rules, deduplicating by name. Some
        // presets intentionally reset the rule list first (for example
        // "All VPN", where an empty rule list is the actual desired state
        // before the final MATCH,proxy fallback).
        let mut existing = if preset.clear_existing {
            Vec::new()
        } else {
            inner.state.routing_rules.clone()
        };
        for rule in &preset.rules {
            if !existing.iter().any(|r| r.name == rule.name) {
                let mut rule = rule.clone();
                if let Some(ref target) = target_override {
                    rule.target = target.clone();
                }
                existing.push(rule);
            }
        }
        inner.state.routing_rules = existing;

        // Apply optional port mode change.
        if let Some(ref mode) = preset.port_mode {
            match mode.as_str() {
                "all" => inner.state.split_routing.port_mode = PortMode::All,
                "allow_list" => {
                    inner.state.split_routing.port_mode = PortMode::AllowList;
                    inner.state.split_routing.proxy_ports =
                        preset.proxy_ports.iter().map(|s| s.to_string()).collect();
                }
                "deny_list" => {
                    inner.state.split_routing.port_mode = PortMode::DenyList;
                }
                _ => {}
            }
        }

        if let Err(error) = persist_state(&daemon.state_path, &inner.state) {
            return (
                500,
                "application/json",
                json!({"error": format!("persist state: {error}")}).to_string(),
            );
        }
        previous_state
    };

    if apply_requested {
        return match activate_current_config(daemon, false, true, GeoBaseProjection::Desired) {
            Ok(result) => (
                200,
                "application/json",
                json!({
                    "saved": true,
                    "applied": true,
                    "preset": preset.id,
                    "rules_added": preset.rules.len(),
                    "rules_cleared": preset.clear_existing,
                    "port_mode": preset.port_mode,
                    "target_override": target_override,
                    "core_status": result.core_status,
                    "firewall_status": result.firewall_status,
                    "generation": result.generation,
                    "gc_warning": result.gc_warning,
                })
                .to_string(),
            ),
            Err(error) => {
                let rollback = restore_state_after_failed_policy_change(daemon, previous_state);
                json_error(500, &format!("{error}; state rollback: {rollback}"))
            }
        };
    }

    (
        200,
        "application/json",
        json!({
            "saved": true,
            "applied": false,
            "requires_apply": true,
            "preset": preset.id,
            "rules_added": preset.rules.len(),
            "rules_cleared": preset.clear_existing,
            "port_mode": preset.port_mode,
            "target_override": target_override,
        })
        .to_string(),
    )
}

/// Geo database providers for geosite.dat / geoip.metadb download.
fn geo_providers() -> Vec<Value> {
    vec![json!({
        "id": "metacubex-lite",
        "name": "MetaCubeX meta-rules-dat",
        "repo": "MetaCubeX/meta-rules-dat",
        "files": ["geosite.dat", "geoip.metadb"],
        "recommended": true,
    })]
}

fn handle_geo_providers() -> (u16, &'static str, String) {
    (
        200,
        "application/json",
        json!({"providers": geo_providers()}).to_string(),
    )
}

fn handle_geo_status(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    let geo_dir = Path::new(inner.state.split_routing.geo_asset_path.trim());
    let geoip_path = geo_dir.join("geoip.metadb");
    let geosite_path = geo_dir.join("geosite.dat");

    let geoip_info = if geoip_path.exists() {
        let size = fs::metadata(&geoip_path).map(|m| m.len()).unwrap_or(0);
        json!({"exists": true, "size": size, "path": geoip_path.display().to_string()})
    } else {
        json!({"exists": false, "path": geoip_path.display().to_string()})
    };

    let geosite_info = if geosite_path.exists() {
        let size = fs::metadata(&geosite_path).map(|m| m.len()).unwrap_or(0);
        json!({"exists": true, "size": size, "path": geosite_path.display().to_string()})
    } else {
        json!({"exists": false, "path": geosite_path.display().to_string()})
    };

    (
        200,
        "application/json",
        json!({
            "geoip": geoip_info,
            "geosite": geosite_info,
            "geo_asset_path": inner.state.split_routing.geo_asset_path,
        })
        .to_string(),
    )
}

fn handle_geo_download(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return (
            400,
            "application/json",
            json!({"error": "invalid JSON body"}).to_string(),
        );
    };
    let Some(provider_id) = value.get("provider").and_then(Value::as_str) else {
        return (
            400,
            "application/json",
            json!({"error": "missing \"provider\" field"}).to_string(),
        );
    };

    let providers = geo_providers();
    let Some(provider) = providers
        .iter()
        .find(|p| p.get("id").and_then(Value::as_str) == Some(provider_id))
    else {
        return (
            400,
            "application/json",
            json!({"error": "unknown provider", "provider": provider_id}).to_string(),
        );
    };

    let repo = provider.get("repo").and_then(Value::as_str).unwrap_or("");
    let files = provider
        .get("files")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let inner = lock(&daemon.inner);
    let geo_dir = Path::new(inner.state.split_routing.geo_asset_path.trim()).to_owned();
    let socks_port = inner.state.socks_port;

    // Ensure geo directory exists.
    if let Err(e) = fs::create_dir_all(&geo_dir) {
        return (
            500,
            "application/json",
            json!({"error": format!("create geo dir: {e}")}).to_string(),
        );
    }

    // Query GitHub API for latest release assets.
    let api_url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let curl_output = Command::new("curl")
        .args([
            "-s",
            "--max-time",
            "30",
            "--socks5-hostname",
            &format!("127.0.0.1:{socks_port}"),
            "-H",
            "User-Agent: hincyray",
            &api_url,
        ])
        .output();

    let Ok(curl_out) = curl_output else {
        return (
            502,
            "application/json",
            json!({"error": "curl spawn failed"}).to_string(),
        );
    };
    if !curl_out.status.success() {
        return (
            502,
            "application/json",
            json!({"error": format!("curl exited: {}", curl_out.status.code().unwrap_or(-1))})
                .to_string(),
        );
    }

    let api_text = String::from_utf8_lossy(&curl_out.stdout);
    let Ok(api_json) = serde_json::from_str::<Value>(&api_text) else {
        return (
            502,
            "application/json",
            json!({"error": "failed to parse GitHub API response"}).to_string(),
        );
    };

    let tag = api_json
        .get("tag_name")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let assets = api_json
        .get("assets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut downloaded = Vec::new();
    let mut errors = Vec::new();

    for file_val in &files {
        let Some(file_name) = file_val.as_str() else {
            continue;
        };
        // Find matching asset in the release.
        let asset = assets.iter().find(|a| {
            a.get("name")
                .and_then(Value::as_str)
                .is_some_and(|n| n == file_name)
        });
        let Some(asset) = asset else {
            errors.push(format!("{file_name}: asset not found in release {tag}"));
            continue;
        };
        let download_url = asset
            .get("browser_download_url")
            .and_then(Value::as_str)
            .unwrap_or("");
        if download_url.is_empty() {
            errors.push(format!("{file_name}: no download URL"));
            continue;
        }

        let dest = geo_dir.join(file_name);
        let backup = geo_dir.join(format!("{file_name}.bak"));

        // Back up existing file.
        if dest.exists() {
            let _ = fs::copy(&dest, &backup);
        }

        // Download through SOCKS proxy.
        let dl_output = Command::new("curl")
            .args([
                "-s",
                "-L",
                "--max-time",
                "120",
                "--socks5-hostname",
                &format!("127.0.0.1:{socks_port}"),
                "-H",
                "User-Agent: hincyray",
                "-o",
                &dest.display().to_string(),
                download_url,
            ])
            .output();

        match dl_output {
            Ok(out) if out.status.success() => {
                let size = fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
                if size < 1000 {
                    errors.push(format!(
                        "{file_name}: downloaded file too small ({size} bytes)"
                    ));
                    // Restore backup.
                    if backup.exists() {
                        let _ = fs::copy(&backup, &dest);
                    }
                } else {
                    downloaded.push(json!({
                        "file": file_name,
                        "size": size,
                        "tag": tag,
                    }));
                }
            }
            Ok(out) => {
                errors.push(format!(
                    "{file_name}: curl exited {}",
                    out.status.code().unwrap_or(-1)
                ));
                // Restore backup.
                if backup.exists() {
                    let _ = fs::copy(&backup, &dest);
                }
            }
            Err(e) => {
                errors.push(format!("{file_name}: curl spawn: {e}"));
            }
        }
    }

    // Drop the lock before regenerating config.
    drop(inner);

    // Regenerate config with new geo files.
    let inner = lock(&daemon.inner);
    if let Err(e) = regenerate_config(&inner.state, daemon) {
        eprintln!("hincyray: config regen after geo download: {e}");
    }
    drop(inner);

    if downloaded.is_empty() {
        return (
            500,
            "application/json",
            json!({
                "error": "no files downloaded",
                "errors": errors,
                "tag": tag,
            })
            .to_string(),
        );
    }

    (
        200,
        "application/json",
        json!({
            "downloaded": downloaded,
            "errors": errors,
            "tag": tag,
            "provider": provider_id,
        })
        .to_string(),
    )
}

fn handle_routing_trace(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return (
            400,
            "application/json",
            json!({"error": "invalid JSON body"}).to_string(),
        );
    };
    let request = TraceRequest {
        host: value
            .get("host")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase(),
        ip: value
            .get("ip")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_owned(),
        source_ip: value
            .get("source_ip")
            .or_else(|| value.get("src_ip"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_owned(),
        port: value.get("port").and_then(Value::as_u64).map(|p| p as u16),
        network: value
            .get("network")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase(),
    };
    let inner = lock(&daemon.inner);
    let trace = trace_routing_decision(&inner.state, &request);
    (200, "application/json", trace.to_string())
}

fn handle_routing_chain_check(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let source_ip = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("source_ip")
                .or_else(|| value.get("src_ip"))
                .or_else(|| value.get("ip"))
                .and_then(Value::as_str)
                .map(|s| s.trim().to_owned())
        })
        .filter(|s| !s.is_empty());

    let (
        split,
        core_running,
        firewall_active,
        tproxy_available,
        active_profile_name,
        active_profile_id,
        device_route,
        routing_rules,
        ec,
    ) = {
        let mut inner = lock(&daemon.inner);
        let source = source_ip.as_deref().unwrap_or("");
        let route = inner
            .state
            .device_routes
            .iter()
            .find(|route| route.enabled && route.ip.trim() == source)
            .cloned();
        let active_profile_id = inner.state.active_profile_id;
        let active_profile_name = active_profile_id
            .and_then(|id| inner.state.profiles.iter().find(|p| p.id == id))
            .map(|p| p.name.clone());
        (
            inner.state.split_routing.clone(),
            inner.core.is_running(),
            inner.firewall.is_running(),
            inner.firewall.tproxy_available,
            active_profile_name,
            active_profile_id,
            route,
            inner.state.routing_rules.clone(),
            mihomo_controller(&inner.state.mihomo_features),
        )
    };

    let nat_ok =
        shell_status("iptables -t nat -S PREROUTING 2>/dev/null | grep -q 'hincyray.*HINCYRAY'");
    let dns_ok =
        shell_status("iptables -t nat -S PREROUTING 2>/dev/null | grep -q 'hincyray.*DNAT'");
    let tproxy_ok = tproxy_available
        && shell_status(
            "iptables -t mangle -S PREROUTING 2>/dev/null | grep -q 'hincyray.*HINCYRAY_UDP'",
        );
    let route_ok = shell_status("ip rule show 2>/dev/null | grep -q 'fwmark 0x111'");
    let geo_dir = Path::new(split.geo_asset_path.trim());
    let geoip_metadb = geo_dir.join("geoip.metadb").exists();
    let geosite_dat = geo_dir.join("geosite.dat").exists();
    let uses_geo_assets = routing_rules.iter().any(rule_uses_runtime_geo_assets);
    let arp_device = source_ip.as_deref().and_then(find_arp_device);
    let source_seen = match (&ec, source_ip.as_deref()) {
        (Some((addr, secret)), Some(ip)) if core_running => {
            mihomo_source_seen(addr, secret.as_deref(), ip).ok()
        }
        _ => None,
    };

    let transparent_ready = split.enabled && firewall_active && nat_ok && core_running;
    let mut overall = Vec::new();
    overall.push(chain_node(
        "split",
        "Split Routing",
        if split.enabled { "ok" } else { "bad" },
        if split.enabled {
            "прозрачная маршрутизация включена".to_owned()
        } else {
            "выключено: трафик политики пойдёт напрямую через Keenetic".to_owned()
        },
    ));
    overall.push(chain_node(
        "policy",
        "Политика Keenetic",
        if split.policy_mark.as_deref().is_some_and(|m| !m.is_empty()) {
            "ok"
        } else if split.enabled {
            "warn"
        } else {
            "neutral"
        },
        format!(
            "политика={} mark={}",
            split.policy_name,
            split
                .policy_mark
                .as_deref()
                .unwrap_or("неизвестно до применения firewall")
        ),
    ));
    overall.push(chain_node(
        "firewall",
        "Правила firewall",
        if !split.enabled {
            "neutral"
        } else if firewall_active && nat_ok && dns_ok && (!tproxy_available || tproxy_ok) {
            "ok"
        } else {
            "bad"
        },
        format!(
            "состояние={} NAT={} DNS={} TPROXY={} route={}",
            if firewall_active {
                "работает"
            } else {
                "остановлен"
            },
            ok_fail(nat_ok),
            ok_fail(dns_ok),
            if tproxy_available {
                ok_fail(tproxy_ok)
            } else {
                "недоступен"
            },
            ok_fail(route_ok)
        ),
    ));
    overall.push(chain_node(
        "dns",
        "DNS redirect",
        if !split.enabled {
            "neutral"
        } else if dns_ok && core_running {
            "ok"
        } else {
            "bad"
        },
        format!(
            "DNAT={} ядро Mihomo={}",
            ok_fail(dns_ok),
            if core_running {
                "работает"
            } else {
                "остановлено"
            }
        ),
    ));
    overall.push(chain_node(
        "tcp",
        "TCP REDIRECT",
        if !split.enabled {
            "neutral"
        } else if nat_ok && core_running {
            "ok"
        } else {
            "bad"
        },
        format!(
            "NAT={} redirect-port={} ядро Mihomo={}",
            ok_fail(nat_ok),
            split.redirect_port,
            if core_running {
                "работает"
            } else {
                "остановлено"
            }
        ),
    ));
    overall.push(chain_node(
        "udp",
        "UDP TPROXY",
        if !split.enabled {
            "neutral"
        } else if tproxy_available && tproxy_ok && route_ok {
            "ok"
        } else if !tproxy_available {
            "warn"
        } else {
            "bad"
        },
        if tproxy_available {
            format!(
                "TPROXY={} policy-route={}",
                ok_fail(tproxy_ok),
                ok_fail(route_ok)
            )
        } else {
            "TPROXY недоступен: TCP-прозрачный VPN работает, UDP/QUIC ограничен или блокируется"
                .to_owned()
        },
    ));
    overall.push(chain_node(
        "mihomo",
        "Ядро Mihomo",
        if core_running { "ok" } else { "bad" },
        if core_running {
            "работает"
        } else {
            "остановлено"
        }
        .to_owned(),
    ));
    overall.push(chain_node(
        "proxy",
        "Активный proxy",
        if active_profile_id.is_some() {
            "ok"
        } else {
            "bad"
        },
        active_profile_name.unwrap_or_else(|| "активный профиль не выбран".to_owned()),
    ));
    overall.push(chain_node(
        "geo",
        "Geo assets",
        if !uses_geo_assets {
            "neutral"
        } else if geoip_metadb && geosite_dat {
            "ok"
        } else {
            "bad"
        },
        if uses_geo_assets {
            format!(
                "{} geoip.metadb={} geosite.dat={}",
                split.geo_asset_path,
                ok_fail(geoip_metadb),
                ok_fail(geosite_dat)
            )
        } else {
            "правила маршрутизации не требуют GEOIP/GEOSITE/RULE-SET assets".to_owned()
        },
    ));

    let mut device = Vec::new();
    if let Some(ip) = source_ip.as_deref() {
        let in_subnet = ip_matches_cidr_text(ip, &split.vpn_subnet);
        device.push(chain_node(
            "device",
            "Выбранное устройство",
            if arp_device.is_some() { "ok" } else { "warn" },
            arp_device.unwrap_or_else(|| format!("{ip}: сейчас нет в /proc/net/arp")),
        ));
        device.push(chain_node(
            "subnet",
            "VPN subnet",
            if in_subnet { "ok" } else { "warn" },
            format!(
                "{ip} {} {}",
                if in_subnet {
                    "входит в"
                } else {
                    "вне"
                },
                split.vpn_subnet
            ),
        ));
        device.push(chain_node(
            "override",
            "Override устройства",
            match device_route.as_ref().map(|r| r.target.as_str()) {
                Some("direct") | Some("reject") => "bad",
                Some(_) => "warn",
                None => "ok",
            },
            match device_route {
                Some(route) => format!(
                    "{} -> {} (имеет приоритет над всеми общими правилами)",
                    route.ip, route.target
                ),
                None => "нет: будут применены общие правила маршрутизации".to_owned(),
            },
        ));
        device.push(chain_node(
            "port_mode",
            "Режим портов",
            "ok",
            match split.port_mode {
                PortMode::All => "All: все порты продолжают обработку правилами".to_owned(),
                PortMode::AllowList => format!(
                    "AllowList: только {:?} продолжают обработку proxy-правилами",
                    split.proxy_ports
                ),
                PortMode::DenyList => {
                    format!("DenyList: {:?} обходят proxy-правила", split.bypass_ports)
                }
            },
        ));
        device.push(chain_node(
            "rules",
            "Правила маршрутизации",
            if routing_rules.is_empty() {
                "ok"
            } else if uses_geo_assets {
                "info"
            } else {
                "ok"
            },
            if routing_rules.is_empty() {
                "нет пользовательских правил: финальное MATCH,proxy отправит трафик в VPN".to_owned()
            } else if uses_geo_assets {
                format!(
                    "{} правил(а); GEOIP/GEOSITE/RULE-SET оцениваются внутри Mihomo во время соединения",
                    routing_rules.len()
                )
            } else {
                format!("{} правил(а) перед финальным MATCH,proxy", routing_rules.len())
            },
        ));
        device.push(chain_node(
            "observed",
            "Видимость в Mihomo",
            match source_seen {
                Some(true) => "ok",
                Some(false) => "info",
                None => "neutral",
            },
            match source_seen {
                Some(true) => format!("активное соединение от {ip} видно в Mihomo"),
                Some(false) => format!("сейчас нет активного соединения от {ip} в Mihomo"),
                None if !core_running => {
                    "ядро Mihomo остановлено, поэтому External Controller недоступен".to_owned()
                }
                None if ec.is_none() => {
                    "External Controller выключен в настройках Mihomo".to_owned()
                }
                None => "не удалось опросить External Controller Mihomo".to_owned(),
            },
        ));
        device.push(chain_node(
            "result",
            "Ожидаемый результат",
            if transparent_ready { "ok" } else { "bad" },
            expected_chain_result(transparent_ready, routing_rules.is_empty(), uses_geo_assets),
        ));
    }

    (
        200,
        "application/json",
        json!({
            "overall": overall,
            "device": device,
            "source_ip": source_ip,
            "summary": chain_summary(&overall, &device),
        })
        .to_string(),
    )
}

fn chain_node(id: &str, label: &str, status: &str, detail: String) -> Value {
    json!({"id": id, "label": label, "status": status, "detail": detail})
}

fn ok_fail(ok: bool) -> &'static str {
    if ok { "OK" } else { "FAIL" }
}

fn rule_uses_runtime_geo_assets(rule: &RoutingRule) -> bool {
    rule.enabled
        && rule
            .domains
            .iter()
            .chain(rule.ips.iter())
            .chain(rule.services.iter())
            .any(|item| {
                let low = item.trim().to_ascii_lowercase();
                low.starts_with("geoip:")
                    || low.starts_with("geosite:")
                    || low.starts_with("rule-set:")
                    || low.starts_with("src-geoip:")
                    || low.starts_with("ip-asn:")
            })
}

fn find_arp_device(ip: &str) -> Option<String> {
    let arp = fs::read_to_string("/proc/net/arp").ok()?;
    for line in arp.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 6 && fields[0] == ip && fields[3] != "00:00:00:00:00:00" {
            return Some(format!("{} on {} ({})", fields[0], fields[5], fields[3]));
        }
    }
    None
}

fn mihomo_source_seen(addr: &str, secret: Option<&str>, source_ip: &str) -> Result<bool, String> {
    let value = mihomo_api_get_json(addr, secret, "/connections")?;
    let Some(connections) = value.get("connections").and_then(Value::as_array) else {
        return Ok(false);
    };
    Ok(connections.iter().any(|conn| {
        conn.get("metadata")
            .and_then(|meta| meta.get("sourceIP"))
            .and_then(Value::as_str)
            == Some(source_ip)
    }))
}

fn expected_chain_result(
    transparent_ready: bool,
    rules_empty: bool,
    uses_geo_assets: bool,
) -> String {
    if !transparent_ready {
        return "прозрачная VPN-цепь нарушена; трафик пойдёт напрямую или соединение сломается на проблемном этапе".to_owned();
    }
    if rules_empty {
        "весь перехваченный трафик доходит до финального MATCH,proxy: VPN".to_owned()
    } else if uses_geo_assets {
        "правила содержат runtime GEOIP/GEOSITE/RULE-SET; решение принимает Mihomo, а несовпавший трафик уйдёт в финальный MATCH,proxy: VPN".to_owned()
    } else {
        "первое совпавшее правило побеждает; несовпавший трафик доходит до MATCH,proxy: VPN"
            .to_owned()
    }
}

fn chain_summary(overall: &[Value], device: &[Value]) -> Value {
    let mut bad = 0usize;
    let mut warn = 0usize;
    let mut info = 0usize;
    for node in overall.iter().chain(device.iter()) {
        match node.get("status").and_then(Value::as_str) {
            Some("bad") => bad += 1,
            Some("warn") => warn += 1,
            Some("info") => info += 1,
            _ => {}
        }
    }
    json!({
        "status": if bad > 0 { "bad" } else if warn > 0 { "warn" } else { "ok" },
        "bad": bad,
        "warn": warn,
        "info": info,
    })
}

#[derive(Clone, Debug)]
struct TraceRequest {
    host: String,
    ip: String,
    source_ip: String,
    port: Option<u16>,
    network: String,
}

fn trace_routing_decision(state: &HincyrayState, request: &TraceRequest) -> Value {
    let mut candidates: Vec<Value> = Vec::new();

    for route in state.device_routes.iter().filter(|route| route.enabled) {
        if !route.ip.trim().is_empty() && route.ip.trim() == request.source_ip {
            return json!({
                "decision": "matched",
                "source": "device_route",
                "name": route.name,
                "target": route.target,
                "reason": format!("source IP {} matches device route", request.source_ip),
                "candidates": candidates,
            });
        }
    }

    for (idx, rule) in state
        .routing_rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| rule.enabled)
    {
        let port_ok = trace_ports_match(rule, request.port);
        let network_ok = trace_network_matches(rule, &request.network);
        if !port_ok || !network_ok {
            continue;
        }

        let domain_match = trace_domain_match(rule, &request.host);
        let ip_match = trace_ip_match(rule, &request.ip, &request.source_ip);
        if domain_match.exact || ip_match.exact {
            return json!({
                "decision": "matched",
                "source": "routing_rule",
                "rule_index": idx,
                "name": rule.name,
                "target": rule.target,
                "reason": domain_match.reason.or(ip_match.reason).unwrap_or_else(|| "rule matched".to_owned()),
                "candidates": candidates,
            });
        }
        if domain_match.possible || ip_match.possible {
            candidates.push(json!({
                "rule_index": idx,
                "name": rule.name,
                "target": rule.target,
                "reason": domain_match.reason.or(ip_match.reason).unwrap_or_else(|| "requires Mihomo geo/rule-set evaluation".to_owned()),
            }));
        }
    }

    json!({
        "decision": if candidates.is_empty() { "default" } else { "requires_mihomo_geo_eval" },
        "target": "active",
        "reason": if candidates.is_empty() {
            "no exact local rule matched"
        } else {
            "candidate geosite/geoip/rule-set rules require Mihomo runtime assets"
        },
        "candidates": candidates,
    })
}

#[derive(Default)]
struct TraceMatch {
    exact: bool,
    possible: bool,
    reason: Option<String>,
}

fn trace_ports_match(rule: &RoutingRule, port: Option<u16>) -> bool {
    if rule.ports.is_empty() {
        return true;
    }
    let Some(port) = port else {
        return false;
    };
    rule.ports.iter().any(|spec| port_matches_spec(port, spec))
}

fn port_matches_spec(port: u16, spec: &str) -> bool {
    let spec = spec.trim();
    if let Some((start, end)) = spec.split_once('-') {
        let Ok(start) = start.trim().parse::<u16>() else {
            return false;
        };
        let Ok(end) = end.trim().parse::<u16>() else {
            return false;
        };
        return start <= port && port <= end;
    }
    spec.parse::<u16>().map(|p| p == port).unwrap_or(false)
}

fn trace_network_matches(rule: &RoutingRule, network: &str) -> bool {
    let wanted = rule.network.trim().to_ascii_lowercase();
    wanted.is_empty() || network.is_empty() || wanted == network
}

fn trace_domain_match(rule: &RoutingRule, host: &str) -> TraceMatch {
    let mut items = normalize_route_items(&rule.domains);
    for service in &rule.services {
        let service = service.trim().trim_start_matches("geosite:");
        if !service.is_empty() {
            items.push(format!("geosite:{service}"));
        }
    }
    if items.is_empty() && !rule.pattern.trim().is_empty() && rule.kind != "ip" {
        items.push(rule.pattern.trim().to_owned());
    }
    for item in items {
        let low = item.to_ascii_lowercase();
        if low.starts_with("geosite:") || low.starts_with("rule-set:") {
            return TraceMatch {
                possible: true,
                reason: Some(format!("{item} requires Mihomo runtime rule assets")),
                ..Default::default()
            };
        }
        let needle = low
            .trim_start_matches("domain:")
            .trim_start_matches("suffix:")
            .trim_start_matches("keyword:")
            .trim_start_matches("wildcard:")
            .trim_start_matches("regex:")
            .trim_start_matches('.')
            .to_owned();
        if host == needle || host.ends_with(&format!(".{needle}")) || host.contains(&needle) {
            return TraceMatch {
                exact: true,
                reason: Some(format!("host {host} matches {item}")),
                ..Default::default()
            };
        }
    }
    TraceMatch::default()
}

fn trace_ip_match(rule: &RoutingRule, ip: &str, source_ip: &str) -> TraceMatch {
    let mut items = normalize_route_items(&rule.ips);
    if items.is_empty()
        && !rule.pattern.trim().is_empty()
        && (rule.kind == "ip" || rule.kind == "geoip")
    {
        items.push(rule.pattern.trim().to_owned());
    }
    for item in items {
        let low = item.to_ascii_lowercase();
        if low.starts_with("geoip:") || low.starts_with("ip-asn:") || low.starts_with("src-geoip:")
        {
            return TraceMatch {
                possible: true,
                reason: Some(format!("{item} requires Mihomo geo database")),
                ..Default::default()
            };
        }
        let is_src = low.starts_with("src-ip-cidr:");
        let target_ip = if is_src { source_ip } else { ip };
        let cidr = low
            .trim_start_matches("src-ip-cidr:")
            .trim_start_matches("ip-cidr:")
            .trim_start_matches("ip:");
        if !target_ip.is_empty() && ip_matches_cidr_text(target_ip, cidr) {
            return TraceMatch {
                exact: true,
                reason: Some(format!("IP {target_ip} matches {item}")),
                ..Default::default()
            };
        }
    }
    TraceMatch::default()
}

fn ip_matches_cidr_text(ip: &str, cidr: &str) -> bool {
    if let Some((base, prefix)) = cidr.split_once('/') {
        let Ok(prefix) = prefix.parse::<u8>() else {
            return false;
        };
        return ipv4_in_cidr(ip, base, prefix);
    }
    ip == cidr
}

fn ipv4_in_cidr(ip: &str, base: &str, prefix: u8) -> bool {
    let Some(ip_num) = ipv4_to_u32(ip) else {
        return false;
    };
    let Some(base_num) = ipv4_to_u32(base) else {
        return false;
    };
    if prefix > 32 {
        return false;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (ip_num & mask) == (base_num & mask)
}

fn ipv4_to_u32(ip: &str) -> Option<u32> {
    let mut out = 0u32;
    let mut count = 0u8;
    for part in ip.split('.') {
        let octet = part.parse::<u8>().ok()?;
        out = (out << 8) | u32::from(octet);
        count += 1;
    }
    (count == 4).then_some(out)
}

fn handle_firewall_status(daemon: &Daemon) -> (u16, &'static str, String) {
    let mut inner = lock(&daemon.inner);
    let fw_active = inner.firewall.is_running();
    let tproxy_available = inner.firewall.tproxy_available;
    let core_running = inner.core.is_running();
    let redirect_port = inner.state.split_routing.redirect_port;
    let enabled = inner.state.split_routing.enabled;
    let policy_name = inner.state.split_routing.policy_name.clone();
    let policy_mark = inner
        .firewall
        .policy_mark
        .clone()
        .or_else(|| inner.state.split_routing.policy_mark.clone());
    let quic_mode = format!("{:?}", inner.state.split_routing.quic_mode);
    drop(inner);

    let nat_ok =
        shell_status("iptables -t nat -S PREROUTING 2>/dev/null | grep -q 'hincyray.*HINCYRAY'");
    let dns_ok =
        shell_status("iptables -t nat -S PREROUTING 2>/dev/null | grep -q 'hincyray.*DNAT'");
    let tproxy_ok = if tproxy_available {
        shell_status(
            "iptables -t mangle -S PREROUTING 2>/dev/null | grep -q 'hincyray.*HINCYRAY_UDP'",
        )
    } else {
        false
    };
    let route_ok = shell_status("ip rule show 2>/dev/null | grep -q 'fwmark 0x111'");
    let ndm_hook_exists = Path::new("/opt/etc/ndm/netfilter.d/hincyray.sh").exists()
        && fs::metadata("/opt/etc/ndm/netfilter.d/hincyray.sh")
            .map(|m| m.len() > 0)
            .unwrap_or(false);
    let ready_marker = Path::new("/tmp/hincyray_ready").exists();
    let redir_listening =
        std::net::TcpStream::connect(format!("127.0.0.1:{redirect_port}")).is_ok();

    (
        200,
        "application/json",
        json!({
            "enabled": enabled,
            "firewall_active": fw_active,
            "core_running": core_running,
            "tproxy_available": tproxy_available,
            "nat_redirect_ok": nat_ok,
            "dns_redirect_ok": dns_ok,
            "tproxy_ok": tproxy_ok,
            "route_ok": route_ok,
            "ndm_hook_installed": ndm_hook_exists,
            "ready_marker": ready_marker,
            "redir_listening": redir_listening,
            "redirect_port": redirect_port,
            "policy_name": policy_name,
            "policy_mark": policy_mark,
            "quic_mode": quic_mode,
        })
        .to_string(),
    )
}

fn handle_firewall_start(daemon: &Daemon) -> (u16, &'static str, String) {
    let mut inner = lock(&daemon.inner);
    let split = inner.state.split_routing.clone();
    if !split.enabled {
        return (
            400,
            "application/json",
            json!({"error": "split routing not enabled"}).to_string(),
        );
    }
    let vpn_subnet = split.vpn_subnet.clone();
    let _ = inner.firewall.stop(&vpn_subnet);
    match inner.firewall.start(
        split.redirect_port,
        &split.vpn_subnet,
        &split.policy_name,
        split.policy_mark.as_deref(),
    ) {
        Ok(()) => {
            // Persist discovered policy mark + tproxy availability.
            if let Some(ref mark) = inner.firewall.policy_mark {
                inner.state.split_routing.policy_mark = Some(mark.clone());
            }
            inner.state.split_routing.tproxy_available = inner.firewall.tproxy_available;
            let _ = persist_state(&daemon.state_path, &inner.state);
            (
                200,
                "application/json",
                json!({
                    "firewall_status": inner.firewall.status(),
                    "tproxy_available": inner.firewall.tproxy_available,
                    "policy_mark": inner.firewall.policy_mark,
                })
                .to_string(),
            )
        }
        Err(error) => (500, "application/json", json!({"error": error}).to_string()),
    }
}

fn handle_firewall_stop(daemon: &Daemon) -> (u16, &'static str, String) {
    let mut inner = lock(&daemon.inner);
    let vpn_subnet = inner.state.split_routing.vpn_subnet.clone();
    match inner.firewall.stop(&vpn_subnet) {
        Ok(()) => (
            200,
            "application/json",
            json!({"firewall_status": inner.firewall.status()}).to_string(),
        ),
        Err(error) => (500, "application/json", json!({"error": error}).to_string()),
    }
}

fn handle_dns_get(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    (
        200,
        "application/json",
        json!({
            "dns": inner.state.dns_settings,
            "sniffer_override_destination": inner.state.mihomo_features.sniffer_override_destination,
        })
        .to_string(),
    )
}

fn handle_dns_set(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return (
            400,
            "application/json",
            json!({"error": "invalid JSON body"}).to_string(),
        );
    };
    let mut inner = lock(&daemon.inner);
    if let Some(v) = value.get("enabled").and_then(Value::as_bool) {
        inner.state.dns_settings.enabled = v;
    }
    if let Some(v) = value.get("remote_servers").and_then(Value::as_array) {
        inner.state.dns_settings.remote_servers = v
            .iter()
            .filter_map(|item| item.as_str().map(|s| s.trim().to_owned()))
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Some(v) = value.get("local_servers").and_then(Value::as_array) {
        inner.state.dns_settings.local_servers = v
            .iter()
            .filter_map(|item| item.as_str().map(|s| s.trim().to_owned()))
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Some(v) = value.get("query_strategy").and_then(Value::as_str) {
        inner.state.dns_settings.query_strategy = v.trim().to_owned();
    }
    if let Some(v) = value
        .get("sniffer_override_destination")
        .and_then(Value::as_bool)
    {
        inner.state.mihomo_features.sniffer_override_destination = v;
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
        json!({
            "dns": inner.state.dns_settings,
            "sniffer_override_destination": inner.state.mihomo_features.sniffer_override_destination,
        })
        .to_string(),
    )
}

fn handle_dns_leak_test(daemon: &Daemon) -> (u16, &'static str, String) {
    let mut inner = lock(&daemon.inner);
    let core_running = inner.core.is_running();
    let split_enabled = inner.state.split_routing.enabled;
    let socks_port = inner.state.socks_port;
    drop(inner);

    if !core_running {
        return (
            400,
            "application/json",
            json!({"error": "Mihomo core is not running"}).to_string(),
        );
    }

    // Infrastructure checks: iptables rules + Mihomo DNS inbound.
    let dns_redirect_ok =
        shell_status("iptables -t nat -S PREROUTING 2>/dev/null | grep -q 'hincyray.*DNAT.*1053'");
    let nat_ok =
        shell_status("iptables -t nat -S PREROUTING 2>/dev/null | grep -q 'hincyray.*HINCYRAY'");
    let dns_in_listening = std::net::TcpStream::connect("127.0.0.1:1053").is_ok();

    // Proxy exit IP + location via Cloudflare trace through SOCKS.
    let trace_via_proxy = Command::new("curl")
        .args([
            "-s",
            "--max-time",
            "10",
            "--socks5-hostname",
            &format!("127.0.0.1:{socks_port}"),
            "https://1.1.1.1/cdn-cgi/trace",
        ])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();

    let proxy_exit_ip = trace_via_proxy
        .lines()
        .find(|l| l.starts_with("ip="))
        .and_then(|l| l.split('=').nth(1))
        .map(|s| s.to_owned())
        .unwrap_or_default();

    let proxy_loc = trace_via_proxy
        .lines()
        .find(|l| l.starts_with("loc="))
        .and_then(|l| l.split('=').nth(1))
        .map(|s| s.to_owned())
        .unwrap_or_default();

    // DNS via proxy: query DoH through the SOCKS proxy. The response
    // for whoami.akamai.net is the IP of the resolver that queried the
    // authoritative server. Through the proxy, this should be a
    // resolver near the proxy exit — NOT the ISP's DNS.
    let dns_via_proxy = Command::new("curl")
        .args([
            "-s",
            "--max-time",
            "10",
            "--socks5-hostname",
            &format!("127.0.0.1:{socks_port}"),
            "https://1.1.1.1/dns-query?name=whoami.akamai.net&type=A",
            "-H",
            "accept: application/dns-json",
        ])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();

    // Parse DoH JSON: {"Status":0,"Answer":[{"data":"1.2.3.4"}]}
    let dns_via_proxy_ip = serde_json::from_str::<Value>(&dns_via_proxy)
        .ok()
        .and_then(|v| {
            v.get("Answer")
                .and_then(|a| a.as_array())
                .and_then(|arr| arr.first())
                .and_then(|ans| ans.get("data"))
                .and_then(|d| d.as_str())
                .map(|s| s.to_owned())
        })
        .unwrap_or_default();

    // DNS direct: router's default resolver → ISP DNS proxy.
    // whoami.akamai.net returns the ISP's DNS resolver IP.
    let dns_direct = Command::new("sh")
        .arg("-c")
        .arg("nslookup whoami.akamai.net 2>/dev/null | grep -A1 'Name:' | grep 'Address' | awk '{print $NF}' | head -1")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default();

    // Leak detection logic:
    // - If proxy is unreachable → can't test
    // - If iptables rules or DNS inbound are missing → leak (VPN
    //   clients' DNS bypasses the tunnel)
    // - If dns_via_proxy IP == dns_direct IP → DNS is going to the
    //   same resolver (ISP), indicating a leak
    // - Otherwise → no leak
    let proxy_ok = !proxy_exit_ip.is_empty();

    let leaked = if !proxy_ok {
        false // can't determine
    } else if !dns_redirect_ok || !nat_ok || !dns_in_listening {
        true // infrastructure broken = DNS leak
    } else if !dns_via_proxy_ip.is_empty() && !dns_direct.is_empty() {
        // If both resolved, compare resolver IPs.
        // Through proxy: should be a resolver near the proxy exit.
        // Direct: should be the ISP's DNS resolver.
        // If they're the same, DNS is leaking to ISP.
        dns_via_proxy_ip == dns_direct
    } else {
        // Can't compare DNS IPs, but infrastructure is OK.
        false
    };

    let status = if !proxy_ok {
        "proxy_unreachable"
    } else if !dns_in_listening {
        "dns_inbound_down"
    } else if !dns_redirect_ok || !nat_ok {
        "rules_missing"
    } else if leaked {
        "leak_detected"
    } else {
        "ok"
    };

    (
        200,
        "application/json",
        json!({
            "status": status,
            "split_routing_enabled": split_enabled,
            "dns_redirect_ok": dns_redirect_ok,
            "nat_redirect_ok": nat_ok,
            "dns_inbound_listening": dns_in_listening,
            "proxy_exit_ip": proxy_exit_ip,
            "proxy_location": proxy_loc,
            "dns_via_proxy": dns_via_proxy_ip,
            "dns_direct": dns_direct,
            "leak_detected": leaked,
        })
        .to_string(),
    )
}

/// Return current auto-select / auto-benchmark / failover settings.
fn handle_auto_settings_get(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    (
        200,
        "application/json",
        json!({
            "auto_select": inner.state.auto_select,
            "auto_bench_interval_hours": inner.state.auto_bench_interval_hours,
            "last_auto_bench_unix": inner.state.last_auto_bench_unix,
            "auto_switch": inner.state.split_routing.auto_switch,
            "failover_fail_count": inner.failover_fail_count,
            "auto_refresh_enabled": inner.state.auto_refresh_enabled,
            "auto_refresh_interval_hours": inner.state.auto_refresh_interval_hours,
            "last_auto_refresh_unix": inner.state.last_auto_refresh_unix,
            "maintenance": inner.state.maintenance,
        })
        .to_string(),
    )
}

/// Update auto-select / auto-benchmark / failover settings.
fn handle_auto_settings_set(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return (
            400,
            "application/json",
            json!({"error": "invalid JSON body"}).to_string(),
        );
    };
    let mut inner = lock(&daemon.inner);
    if let Some(v) = value.get("auto_select").and_then(Value::as_bool) {
        inner.state.auto_select = v;
    }
    if let Some(v) = value
        .get("auto_bench_interval_hours")
        .and_then(Value::as_u64)
    {
        inner.state.auto_bench_interval_hours = v as u32;
    }
    if let Some(v) = value.get("auto_switch").and_then(Value::as_bool) {
        inner.state.split_routing.auto_switch = v;
    }
    if let Some(v) = value.get("auto_refresh_enabled").and_then(Value::as_bool) {
        inner.state.auto_refresh_enabled = v;
    }
    if let Some(v) = value
        .get("auto_refresh_interval_hours")
        .and_then(Value::as_u64)
    {
        inner.state.auto_refresh_interval_hours = v as u32;
    }
    if let Some(maintenance) = value.get("maintenance") {
        apply_maintenance_settings(&mut inner.state.maintenance, maintenance);
    }
    let _ = persist_state(&daemon.state_path, &inner.state);
    (
        200,
        "application/json",
        json!({
            "auto_select": inner.state.auto_select,
            "auto_bench_interval_hours": inner.state.auto_bench_interval_hours,
            "auto_switch": inner.state.split_routing.auto_switch,
            "auto_refresh_enabled": inner.state.auto_refresh_enabled,
            "auto_refresh_interval_hours": inner.state.auto_refresh_interval_hours,
            "maintenance": inner.state.maintenance,
        })
        .to_string(),
    )
}

fn apply_maintenance_settings(settings: &mut MaintenanceSettings, value: &Value) {
    if let Some(v) = value.get("enabled").and_then(Value::as_bool) {
        settings.enabled = v;
    }
    if let Some(v) = value.get("hour_utc").and_then(Value::as_u64) {
        settings.hour_utc = (v as u8).min(23);
    }
    if let Some(v) = value.get("minute_utc").and_then(Value::as_u64) {
        settings.minute_utc = (v as u8).min(59);
    }
    if let Some(v) = value.get("interval_days").and_then(Value::as_u64) {
        settings.interval_days = (v as u32).max(1);
    }
    if let Some(v) = value.get("create_backup").and_then(Value::as_bool) {
        settings.create_backup = v;
    }
    if let Some(v) = value.get("refresh_subscriptions").and_then(Value::as_bool) {
        settings.refresh_subscriptions = v;
    }
    if let Some(v) = value.get("restart_core").and_then(Value::as_bool) {
        settings.restart_core = v;
    }
    if let Some(v) = value.get("close_connections").and_then(Value::as_bool) {
        settings.close_connections = v;
    }
}

/// Return the current MihomoFeatures configuration.
fn handle_mihomo_features_get(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    (
        200,
        "application/json",
        serde_json::to_string(&inner.state.mihomo_features).unwrap_or_else(|_| "{}".to_owned()),
    )
}

/// Update the MihomoFeatures configuration. The body must be a complete
/// `MihomoFeatures` JSON object (obtainable via GET /api/mihomo-features).
/// All fields have serde defaults, so missing fields use their defaults.
fn handle_mihomo_features_set(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let features: MihomoFeatures = match serde_json::from_str(body) {
        Ok(f) => f,
        Err(e) => {
            return (
                400,
                "application/json",
                json!({"error": format!("invalid MihomoFeatures JSON: {e}")}).to_string(),
            );
        }
    };
    let mut inner = lock(&daemon.inner);
    inner.state.mihomo_features = features;
    let _ = persist_state(&daemon.state_path, &inner.state);
    (
        200,
        "application/json",
        serde_json::to_string(&inner.state.mihomo_features).unwrap_or_else(|_| "{}".to_owned()),
    )
}

// ---------------------------------------------------------------------------
// Mihomo external-controller API proxy endpoints
// ---------------------------------------------------------------------------

/// Forward `GET /proxies` to the Mihomo external controller.
/// Returns all proxies, proxy groups, and their current state (alive,
/// delay, selected node). Used by the Web UI to display proxy status.
fn handle_mihomo_api_proxies(daemon: &Daemon) -> (u16, &'static str, String) {
    let (addr, secret) = {
        let inner = lock(&daemon.inner);
        match mihomo_controller(&inner.state.mihomo_features) {
            Some(ec) => ec,
            None => {
                return (
                    400,
                    "application/json",
                    json!({"error": "external controller not enabled"}).to_string(),
                );
            }
        }
    };
    match mihomo_api_get(&addr, secret.as_deref(), "/proxies") {
        Ok(body) => (200, "application/json", body),
        Err(e) => (
            502,
            "application/json",
            json!({"error": format!("Mihomo API: {e}")}).to_string(),
        ),
    }
}

/// Forward `GET /connections` to the Mihomo external controller.
/// Returns real-time connection list with traffic stats. Used by the
/// Web UI to display active connections.
fn handle_mihomo_api_connections(daemon: &Daemon) -> (u16, &'static str, String) {
    let (addr, secret, geo_dir) = {
        let inner = lock(&daemon.inner);
        let ec = match mihomo_controller(&inner.state.mihomo_features) {
            Some(ec) => ec,
            None => {
                return (
                    400,
                    "application/json",
                    json!({"error": "external controller not enabled"}).to_string(),
                );
            }
        };
        (ec.0, ec.1, geo_dir_from_state(&inner.state))
    };
    match mihomo_api_get(&addr, secret.as_deref(), "/connections") {
        Ok(body) => (
            200,
            "application/json",
            enrich_connections_with_geoip(&body, geo_dir.as_deref().map(Path::new)).unwrap_or(body),
        ),
        Err(e) => (
            502,
            "application/json",
            json!({"error": format!("Mihomo API: {e}")}).to_string(),
        ),
    }
}

fn handle_mihomo_api_connections_page(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let request = match serde_json::from_str::<ConnectionQueryRequest>(body) {
        Ok(request) => request,
        Err(error) => return json_error(400, &format!("invalid request: {error}")),
    };
    let limit = request.limit.clamp(1, 500);
    let query_terms: Vec<String> = request
        .query
        .split_whitespace()
        .map(str::to_ascii_lowercase)
        .collect();
    let (addr, secret, geo_dir) = {
        let inner = lock(&daemon.inner);
        let Some((addr, secret)) = mihomo_controller(&inner.state.mihomo_features) else {
            return json_error(400, "external controller not enabled");
        };
        (addr, secret, geo_dir_from_state(&inner.state))
    };
    let body = match mihomo_api_get(&addr, secret.as_deref(), "/connections") {
        Ok(body) => {
            enrich_connections_with_geoip(&body, geo_dir.as_deref().map(Path::new)).unwrap_or(body)
        }
        Err(error) => return json_error(502, &format!("Mihomo API: {error}")),
    };
    let value: Value = match serde_json::from_str(&body) {
        Ok(value) => value,
        Err(error) => return json_error(502, &format!("Mihomo connections JSON: {error}")),
    };
    let all = value
        .get("connections")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let total = all.len();
    let filtered_rows: Vec<Value> = all
        .into_iter()
        .filter(|connection| {
            let search_text = connection_search_text(connection);
            query_terms.iter().all(|term| search_text.contains(term))
        })
        .collect();
    let filtered = filtered_rows.len();
    let connections = filtered_rows
        .into_iter()
        .skip(request.offset)
        .take(limit)
        .collect();
    json_response(&ConnectionPageResponse {
        total,
        filtered,
        offset: request.offset,
        limit,
        connections,
    })
}

fn handle_mihomo_api_connections_device_traffic(
    body: &str,
    daemon: &Daemon,
) -> (u16, &'static str, String) {
    const MAX_DEVICE_SOURCES: usize = 256;

    let request = match serde_json::from_str::<DeviceTrafficRequest>(body) {
        Ok(request) => request,
        Err(error) => return json_error(400, &format!("invalid request: {error}")),
    };
    if request.source_ips.len() > MAX_DEVICE_SOURCES {
        return json_error(
            400,
            &format!("source_ips exceeds maximum of {MAX_DEVICE_SOURCES}"),
        );
    }
    let source_ips: HashSet<String> = request
        .source_ips
        .into_iter()
        .map(|ip| ip.trim().to_owned())
        .filter(|ip| !ip.is_empty() && ip.len() <= 64)
        .collect();
    if source_ips.is_empty() {
        return json_response(&DeviceTrafficResponse {
            devices: HashMap::new(),
        });
    }
    let (addr, secret) = {
        let inner = lock(&daemon.inner);
        let Some((addr, secret)) = mihomo_controller(&inner.state.mihomo_features) else {
            return json_error(400, "external controller not enabled");
        };
        (addr, secret)
    };
    let body = match mihomo_api_get(&addr, secret.as_deref(), "/connections") {
        Ok(body) => body,
        Err(error) => return json_error(502, &format!("Mihomo API: {error}")),
    };
    let value: Value = match serde_json::from_str(&body) {
        Ok(value) => value,
        Err(error) => return json_error(502, &format!("Mihomo connections JSON: {error}")),
    };
    let devices = aggregate_device_traffic(
        value
            .get("connections")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default(),
        &source_ips,
    );
    json_response(&DeviceTrafficResponse { devices })
}

fn aggregate_device_traffic(
    connections: &[Value],
    source_ips: &HashSet<String>,
) -> HashMap<String, DeviceTrafficSummary> {
    let mut devices = HashMap::new();
    for connection in connections {
        let Some(source_ip) = connection
            .get("metadata")
            .and_then(|metadata| metadata.get("sourceIP"))
            .and_then(Value::as_str)
            .filter(|source_ip| source_ips.contains(*source_ip))
        else {
            continue;
        };
        let summary = devices
            .entry(source_ip.to_owned())
            .or_insert_with(DeviceTrafficSummary::default);
        summary.upload = summary.upload.saturating_add(
            connection
                .get("upload")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        );
        summary.download = summary.download.saturating_add(
            connection
                .get("download")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        );
        summary.connections = summary.connections.saturating_add(1);
    }
    devices
}

fn connection_search_text(connection: &Value) -> String {
    let metadata = connection.get("metadata").unwrap_or(&Value::Null);
    let mut fields = [
        metadata.get("host").and_then(Value::as_str).unwrap_or(""),
        metadata
            .get("sniffHost")
            .and_then(Value::as_str)
            .unwrap_or(""),
        metadata
            .get("destinationIP")
            .and_then(Value::as_str)
            .unwrap_or(""),
        metadata
            .get("remoteDestination")
            .and_then(Value::as_str)
            .unwrap_or(""),
        metadata
            .get("sourceIP")
            .and_then(Value::as_str)
            .unwrap_or(""),
        metadata
            .get("destinationPort")
            .and_then(Value::as_str)
            .unwrap_or(""),
        metadata
            .get("network")
            .and_then(Value::as_str)
            .unwrap_or(""),
        metadata
            .get("inboundName")
            .and_then(Value::as_str)
            .unwrap_or(""),
        metadata
            .get("destinationGeoIP")
            .and_then(Value::as_str)
            .unwrap_or(""),
        metadata
            .get("destinationCountry")
            .and_then(Value::as_str)
            .unwrap_or(""),
        connection.get("rule").and_then(Value::as_str).unwrap_or(""),
        connection
            .get("rulePayload")
            .and_then(Value::as_str)
            .unwrap_or(""),
    ]
    .join(" ");
    if let Some(chains) = connection.get("chains").and_then(Value::as_array) {
        for chain in chains.iter().filter_map(Value::as_str) {
            fields.push(' ');
            fields.push_str(chain);
        }
    }
    fields.to_ascii_lowercase()
}

fn enrich_connections_with_geoip(body: &str, geo_dir: Option<&Path>) -> Option<String> {
    let mut value = serde_json::from_str::<Value>(body).ok()?;
    let db_path = geo_dir?.join("geoip.metadb");
    let reader = maxminddb::Reader::open_readfile(db_path).ok()?;
    let connections = value.get_mut("connections")?.as_array_mut()?;
    for conn in connections {
        let Some(metadata) = conn.get_mut("metadata").and_then(Value::as_object_mut) else {
            continue;
        };
        if metadata
            .get("destinationCountry")
            .and_then(Value::as_str)
            .is_some_and(|country| iso_country_code(country).is_some())
        {
            continue;
        }
        let Some(ip) = ["destinationIP", "remoteDestination"]
            .into_iter()
            .filter_map(|key| metadata.get(key).and_then(Value::as_str))
            .find_map(|ip| ip.trim().parse::<IpAddr>().ok())
        else {
            continue;
        };
        if let Some(country) = geoip_country_code(&reader, ip) {
            metadata.insert("destinationCountry".to_owned(), json!(country));
        }
    }
    Some(value.to_string())
}

fn geoip_country_code(reader: &maxminddb::Reader<Vec<u8>>, ip: IpAddr) -> Option<String> {
    if let Some(code) = reader
        .lookup::<maxminddb::geoip2::Country<'_>>(ip)
        .ok()
        .flatten()
        .and_then(|country| country.country?.iso_code.map(str::to_owned))
    {
        return Some(code);
    }
    let raw = reader.lookup::<Value>(ip).ok()??;
    match raw {
        Value::String(code) => iso_country_code(&code),
        Value::Array(values) => values
            .iter()
            .filter_map(Value::as_str)
            .find_map(iso_country_code),
        Value::Object(map) => map
            .get("country")
            .and_then(|country| country.get("iso_code"))
            .or_else(|| map.get("iso_code"))
            .or_else(|| map.get("code"))
            .or_else(|| map.get("country_code"))
            .and_then(Value::as_str)
            .and_then(iso_country_code),
        _ => None,
    }
}

fn iso_country_code(value: &str) -> Option<String> {
    let code = value.trim();
    if code.len() == 2 && code.bytes().all(|b| b.is_ascii_alphabetic()) {
        Some(code.to_ascii_uppercase())
    } else {
        None
    }
}

fn handle_mihomo_api_forward_get(path: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let (addr, secret) = match mihomo_controller_for_daemon(daemon) {
        Ok(ec) => ec,
        Err(response) => return response,
    };
    match mihomo_api_get(&addr, secret.as_deref(), path) {
        Ok(body) => (200, "application/json", body),
        Err(error) => (
            502,
            "application/json",
            json!({"error": format!("Mihomo API: {error}")}).to_string(),
        ),
    }
}

fn optional_mihomo_unsupported(path: &str, method: &str, status: u16) -> String {
    json!({
        "ok": false,
        "supported": false,
        "path": path,
        "method": method,
        "mihomo_status": status,
        "reason": "the running Mihomo external-controller does not support this method/path",
    })
    .to_string()
}

fn handle_mihomo_api_optional_forward_get(
    path: &str,
    daemon: &Daemon,
) -> (u16, &'static str, String) {
    let (addr, secret) = match mihomo_controller_for_daemon(daemon) {
        Ok(ec) => ec,
        Err(response) => return response,
    };
    match mihomo_api_get_response(&addr, secret.as_deref(), path) {
        Ok((status, body)) if (200..300).contains(&status) => (200, "application/json", body),
        Ok((405, _)) => (
            200,
            "application/json",
            optional_mihomo_unsupported(path, "GET", 405),
        ),
        Ok((status, _)) => (
            502,
            "application/json",
            json!({"error": format!("Mihomo API {path}: HTTP {status}")}).to_string(),
        ),
        Err(error) => (
            502,
            "application/json",
            json!({"error": format!("Mihomo API: {error}")}).to_string(),
        ),
    }
}

fn handle_mihomo_api_forward_post(
    path: &str,
    body: &str,
    daemon: &Daemon,
) -> (u16, &'static str, String) {
    let (addr, secret) = match mihomo_controller_for_daemon(daemon) {
        Ok(ec) => ec,
        Err(response) => return response,
    };
    match mihomo_api_post(&addr, secret.as_deref(), path, body) {
        Ok(response) => {
            let body_out = if response.trim().is_empty() {
                json!({"ok": true}).to_string()
            } else {
                response
            };
            (200, "application/json", body_out)
        }
        Err(error) => (
            502,
            "application/json",
            json!({"error": format!("Mihomo API: {error}")}).to_string(),
        ),
    }
}

fn handle_mihomo_api_optional_forward_post(
    path: &str,
    body: &str,
    daemon: &Daemon,
) -> (u16, &'static str, String) {
    let (addr, secret) = match mihomo_controller_for_daemon(daemon) {
        Ok(ec) => ec,
        Err(response) => return response,
    };
    match mihomo_api_post_response(&addr, secret.as_deref(), path, body) {
        Ok((status, response)) if (200..300).contains(&status) => {
            let body_out = if response.trim().is_empty() {
                json!({"ok": true}).to_string()
            } else {
                response
            };
            (200, "application/json", body_out)
        }
        Ok((405, _)) => (
            200,
            "application/json",
            optional_mihomo_unsupported(path, "POST", 405),
        ),
        Ok((status, _)) => (
            502,
            "application/json",
            json!({"error": format!("Mihomo API {path}: HTTP {status}")}).to_string(),
        ),
        Err(error) => (
            502,
            "application/json",
            json!({"error": format!("Mihomo API: {error}")}).to_string(),
        ),
    }
}

/// Close Mihomo connections. Body:
/// - `{ "scope": "all" }` closes all connections via verified `DELETE /connections`.
/// - `{ "id": "..." }` closes one observed connection id.
/// - `{ "resource": "example.com" }`, `{ "host": "example.com" }`,
///   `{ "destination_ip": "1.2.3.4" }`, or `{ "source_ip": "192.168.2.35" }`
///   first reads `/connections`, filters by observed metadata, then closes
///   matching ids. The UI never has to predict connection ids for grouped
///   operations.
fn handle_mihomo_api_connections_close(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let value = if body.trim().is_empty() {
        json!({"scope":"all"})
    } else {
        match serde_json::from_str::<Value>(body) {
            Ok(value) => value,
            Err(error) => return json_error(400, &format!("invalid JSON body: {error}")),
        }
    };
    let (addr, secret) = match mihomo_controller_for_daemon(daemon) {
        Ok(ec) => ec,
        Err(response) => return response,
    };
    let scope = value.get("scope").and_then(Value::as_str).unwrap_or("");
    if scope == "all" || value == json!({}) {
        return match mihomo_api_delete(&addr, secret.as_deref(), "/connections") {
            Ok(status) => (
                200,
                "application/json",
                json!({"closed": "all", "mihomo_status": status}).to_string(),
            ),
            Err(error) => (
                502,
                "application/json",
                json!({"error": format!("Mihomo API: {error}")}).to_string(),
            ),
        };
    }

    let ids = if let Some(id) = value.get("id").and_then(Value::as_str) {
        vec![id.to_owned()]
    } else {
        let Ok(conns) = mihomo_api_get_json(&addr, secret.as_deref(), "/connections") else {
            return (
                502,
                "application/json",
                json!({"error": "could not read Mihomo connections"}).to_string(),
            );
        };
        let resource = value
            .get("resource")
            .or_else(|| value.get("site"))
            .and_then(Value::as_str)
            .and_then(normalize_routing_resource);
        let source_ip = value.get("source_ip").and_then(Value::as_str);
        let (host, destination_ip) = if let Some(resource) = resource.as_ref() {
            match resource.kind {
                RoutingResourceKind::Domain => (Some(resource.value.as_str()), None),
                RoutingResourceKind::Ip => (None, Some(resource.value.as_str())),
            }
        } else {
            (
                value.get("host").and_then(Value::as_str),
                value
                    .get("destination_ip")
                    .or_else(|| value.get("ip"))
                    .and_then(Value::as_str),
            )
        };
        let has_filter = host.is_some_and(|v| !v.trim().is_empty())
            || destination_ip.is_some_and(|v| !v.trim().is_empty())
            || source_ip.is_some_and(|v| !v.trim().is_empty());
        if !has_filter {
            return (
                400,
                "application/json",
                json!({"error": "missing connection filter or scope=all"}).to_string(),
            );
        }
        filter_connection_ids(&conns, host, destination_ip, source_ip)
    };

    let mut closed = 0usize;
    let mut errors: Vec<String> = Vec::new();
    for id in ids {
        let path = format!(
            "/connections/{}",
            utf8_percent_encode(&id, NON_ALPHANUMERIC)
        );
        match mihomo_api_delete(&addr, secret.as_deref(), &path) {
            Ok(_) => closed += 1,
            Err(error) => errors.push(format!("{id}: {error}")),
        }
    }
    (
        if errors.is_empty() { 200 } else { 207 },
        "application/json",
        json!({"closed": closed, "errors": errors}).to_string(),
    )
}

fn mihomo_controller_for_daemon(
    daemon: &Daemon,
) -> Result<(String, Option<String>), (u16, &'static str, String)> {
    let inner = lock(&daemon.inner);
    mihomo_controller(&inner.state.mihomo_features).ok_or_else(|| {
        (
            400,
            "application/json",
            json!({"error": "external controller not enabled"}).to_string(),
        )
    })
}

fn filter_connection_ids(
    conns: &Value,
    host: Option<&str>,
    destination_ip: Option<&str>,
    source_ip: Option<&str>,
) -> Vec<String> {
    let host = host.unwrap_or("").trim().to_ascii_lowercase();
    let destination_ip = destination_ip.unwrap_or("").trim();
    let source_ip = source_ip.unwrap_or("").trim();
    conns
        .get("connections")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|conn| {
            let metadata = conn.get("metadata")?;
            let conn_host = metadata
                .get("host")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_ascii_lowercase();
            let conn_source = metadata
                .get("sourceIP")
                .and_then(Value::as_str)
                .unwrap_or("");
            let conn_destination = metadata
                .get("destinationIP")
                .or_else(|| metadata.get("remoteDestination"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let host_ok =
                host.is_empty() || conn_host == host || conn_host.ends_with(&format!(".{host}"));
            let destination_ok = destination_ip.is_empty() || conn_destination == destination_ip;
            let source_ok = source_ip.is_empty() || conn_source == source_ip;
            (host_ok && destination_ok && source_ok)
                .then(|| conn.get("id").and_then(Value::as_str).map(str::to_owned))
                .flatten()
        })
        .collect()
}

fn close_resource_connections(
    daemon: &Daemon,
    resource: &RoutingResource,
    source_ip: Option<&str>,
) -> ResourceCloseResult {
    let (addr, secret) = match mihomo_controller_for_daemon(daemon) {
        Ok(ec) => ec,
        Err((_, _, body)) => {
            return ResourceCloseResult {
                closed: 0,
                errors: vec![body],
            };
        }
    };
    let conns = match mihomo_api_get_json(&addr, secret.as_deref(), "/connections") {
        Ok(value) => value,
        Err(error) => {
            return ResourceCloseResult {
                closed: 0,
                errors: vec![format!("could not read Mihomo connections: {error}")],
            };
        }
    };
    let ids = match resource.kind {
        RoutingResourceKind::Domain => {
            filter_connection_ids(&conns, Some(&resource.value), None, source_ip)
        }
        RoutingResourceKind::Ip => {
            filter_connection_ids(&conns, None, Some(&resource.value), source_ip)
        }
    };
    let mut result = ResourceCloseResult::default();
    for id in ids {
        let path = format!(
            "/connections/{}",
            utf8_percent_encode(&id, NON_ALPHANUMERIC)
        );
        match mihomo_api_delete(&addr, secret.as_deref(), &path) {
            Ok(_) => result.closed += 1,
            Err(error) => result.errors.push(format!("{id}: {error}")),
        }
    }
    result
}

/// Forward `GET /proxies/{name}/delay` to the Mihomo external controller.
/// Accepts JSON body `{"name": "proxy", "url": "https://...", "timeout": 5000}`.
/// Returns `{"delay": 107}` on success.
fn handle_mihomo_api_delay(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let (addr, secret) = {
        let inner = lock(&daemon.inner);
        match mihomo_controller(&inner.state.mihomo_features) {
            Some(ec) => ec,
            None => {
                return (
                    400,
                    "application/json",
                    json!({"error": "external controller not enabled"}).to_string(),
                );
            }
        }
    };
    // Empty body is treated as `{}` — use all defaults.
    // Invalid non-empty JSON is still a 400 error.
    let req: Value = if body.trim().is_empty() {
        json!({})
    } else {
        match serde_json::from_str(body) {
            Ok(v) => v,
            Err(e) => {
                return (
                    400,
                    "application/json",
                    json!({"error": format!("invalid JSON: {e}")}).to_string(),
                );
            }
        }
    };
    let name = req
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or(PROXY_NAME);
    let url = req
        .get("url")
        .and_then(Value::as_str)
        .unwrap_or("https://www.gstatic.com/generate_204");
    let timeout = req.get("timeout").and_then(Value::as_u64).unwrap_or(5000) as u32;
    match mihomo_api_delay(&addr, secret.as_deref(), name, url, timeout) {
        Ok(delay) => (200, "application/json", json!({"delay": delay}).to_string()),
        Err(e) => (
            502,
            "application/json",
            json!({"error": format!("delay test failed: {e}")}).to_string(),
        ),
    }
}

/// Forward `GET /traffic` to the Mihomo external controller.
/// Returns real-time upload/download speed in kbps.
fn handle_mihomo_api_traffic(daemon: &Daemon) -> (u16, &'static str, String) {
    let (addr, secret) = {
        let inner = lock(&daemon.inner);
        match mihomo_controller(&inner.state.mihomo_features) {
            Some(ec) => ec,
            None => {
                return (
                    400,
                    "application/json",
                    json!({"error": "external controller not enabled"}).to_string(),
                );
            }
        }
    };
    match mihomo_api_stream_get(&addr, secret.as_deref(), "/traffic") {
        Ok(body) => (200, "application/json", body),
        Err(e) => (
            502,
            "application/json",
            json!({"error": format!("Mihomo API: {e}")}).to_string(),
        ),
    }
}

/// Forward `GET /memory` to the Mihomo external controller.
/// Returns real-time memory usage in kb.
fn handle_mihomo_api_memory(daemon: &Daemon) -> (u16, &'static str, String) {
    let (addr, secret, pid) = {
        let inner = lock(&daemon.inner);
        let pid = inner.core.child.as_ref().map(Child::id);
        match mihomo_controller(&inner.state.mihomo_features) {
            Some((addr, secret)) => (Some(addr), secret, pid),
            None => {
                return match pid.and_then(read_process_rss_kb) {
                    Some(kb) => (
                        200,
                        "application/json",
                        json!({"inuse": kb, "oslimit": 0, "source": "procfs"}).to_string(),
                    ),
                    None => (
                        400,
                        "application/json",
                        json!({"error": "external controller not enabled"}).to_string(),
                    ),
                };
            }
        }
    };
    let Some(addr) = addr else {
        return (
            400,
            "application/json",
            json!({"error": "external controller not enabled"}).to_string(),
        );
    };
    match mihomo_api_stream_get(&addr, secret.as_deref(), "/memory") {
        Ok(body) => {
            let ec_inuse = serde_json::from_str::<Value>(&body)
                .ok()
                .and_then(|v| v.get("inuse").and_then(Value::as_u64))
                .unwrap_or(0);
            if ec_inuse == 0
                && let Some(kb) = pid.and_then(read_process_rss_kb)
            {
                return (
                    200,
                    "application/json",
                    json!({"inuse": kb, "oslimit": 0, "source": "procfs"}).to_string(),
                );
            }
            (200, "application/json", body)
        }
        Err(e) => (
            502,
            "application/json",
            json!({"error": format!("Mihomo API: {e}")}).to_string(),
        ),
    }
}

fn read_process_rss_kb(pid: u32) -> Option<u64> {
    let text = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest.split_whitespace().next()?.parse::<u64>().ok();
        }
    }
    None
}

fn read_process_status_field(pid: u32, field: &str) -> Option<u64> {
    let text = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let prefix = format!("{field}:");
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(&prefix) {
            return rest.split_whitespace().next()?.parse::<u64>().ok();
        }
    }
    None
}

fn read_process_comm(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|_| pid.to_string())
}

fn top_processes_by_rss(limit: usize) -> Vec<Value> {
    let mut rows: Vec<(u64, u32, String)> = Vec::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Ok(pid) = name.parse::<u32>() else {
                continue;
            };
            if let Some(rss_kb) = read_process_rss_kb(pid) {
                rows.push((rss_kb, pid, read_process_comm(pid)));
            }
        }
    }
    rows.sort_by_key(|row| std::cmp::Reverse(row.0));
    rows.into_iter()
        .take(limit)
        .map(|(rss_kb, pid, name)| json!({"pid": pid, "name": name, "rss_kb": rss_kb}))
        .collect()
}

fn memory_summary_from_proc() -> (u64, u64, f64) {
    let meminfo = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mut total = 0u64;
    let mut available = 0u64;
    for line in meminfo.lines() {
        let mut parts = line.split_whitespace();
        match (parts.next().map(|s| s.trim_end_matches(':')), parts.next()) {
            (Some("MemTotal"), Some(v)) => total = v.parse().unwrap_or(0),
            (Some("MemAvailable"), Some(v)) => available = v.parse().unwrap_or(0),
            _ => {}
        }
    }
    let usage_pct = if total > 0 {
        ((total.saturating_sub(available)) as f64 / total as f64) * 100.0
    } else {
        0.0
    };
    (total, available, (usage_pct * 10.0).round() / 10.0)
}

fn handle_memory_guard(daemon: &Daemon) -> (u16, &'static str, String) {
    let (settings, mihomo_pid) = {
        let mut inner = lock(&daemon.inner);
        (inner.state.memory_guard.clone(), inner.core.pid())
    };
    let (total_kb, available_kb, usage_pct) = memory_summary_from_proc();
    let mihomo = mihomo_pid.map(|pid| {
        json!({
            "pid": pid,
            "name": read_process_comm(pid),
            "rss_kb": read_process_rss_kb(pid).unwrap_or(0),
            "vm_size_kb": read_process_status_field(pid, "VmSize").unwrap_or(0),
            "vm_data_kb": read_process_status_field(pid, "VmData").unwrap_or(0),
            "vm_swap_kb": read_process_status_field(pid, "VmSwap").unwrap_or(0),
        })
    });
    let mihomo_rss = mihomo
        .as_ref()
        .and_then(|v| v.get("rss_kb"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let warnings = [
        (settings.enabled && usage_pct >= settings.system_usage_warn_pct).then(|| {
            format!(
                "system memory usage {usage_pct}% >= {}%",
                settings.system_usage_warn_pct
            )
        }),
        (settings.enabled && mihomo_rss >= settings.mihomo_rss_warn_kb).then(|| {
            format!(
                "mihomo RSS {mihomo_rss} KiB >= {} KiB",
                settings.mihomo_rss_warn_kb
            )
        }),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    (
        200,
        "application/json",
        json!({
            "ok": warnings.is_empty(),
            "enabled": settings.enabled,
            "thresholds": settings,
            "system": {"total_kb": total_kb, "available_kb": available_kb, "usage_pct": usage_pct},
            "mihomo": mihomo,
            "top_processes": top_processes_by_rss(10),
            "warnings": warnings,
        })
        .to_string(),
    )
}

const SAFE_MODE_SUPPRESSED: [&str; 8] = [
    "rkn-bypass",
    "managed-geobases",
    "proxy-providers",
    "rule-providers",
    "sub-rules",
    "raw-rules",
    "typed-rules",
    "tunnels-and-smux",
];

fn handle_safe_mode_get(daemon: &Daemon) -> (u16, &'static str, String) {
    let mut inner = lock(&daemon.inner);
    json_response(&json!({
        "enabled": inner.state.safe_mode_enabled,
        "suppressed": SAFE_MODE_SUPPRESSED,
        "core_status": inner.core.status(),
        "firewall_status": inner.firewall.status(),
    }))
}

fn handle_safe_mode_set(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let request = match serde_json::from_str::<SafeModeRequest>(body) {
        Ok(request) => request,
        Err(error) => return json_error(400, &format!("invalid request: {error}")),
    };
    let _apply = match daemon.apply.lock() {
        Ok(guard) => guard,
        Err(_) => return json_error(500, "config apply lock is poisoned"),
    };
    let (previous_enabled, undo_id) = {
        let mut inner = lock(&daemon.inner);
        let previous_enabled = inner.state.safe_mode_enabled;
        push_undo_snapshot(
            &mut inner.state,
            format!(
                "Safe mode {}",
                if request.enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            ),
        );
        let undo_id = inner.state.undo_stack.last().map(|entry| entry.id.clone());
        inner.state.safe_mode_enabled = request.enabled;
        if let Err(error) = persist_state(&daemon.state_path, &inner.state) {
            inner.state.safe_mode_enabled = previous_enabled;
            if let Some(undo_id) = undo_id.as_deref() {
                inner.state.undo_stack.retain(|entry| entry.id != undo_id);
            }
            return json_error(500, &format!("persist safe mode: {error}"));
        }
        (previous_enabled, undo_id)
    };
    if !request.apply {
        let mut inner = lock(&daemon.inner);
        return json_response(&SafeModeResponse {
            enabled: request.enabled,
            applied: false,
            core_status: inner.core.status().to_owned(),
            firewall_status: inner.firewall.status().to_owned(),
            suppressed: SAFE_MODE_SUPPRESSED.to_vec(),
        });
    }
    match activate_current_config_locked(daemon, true, true, GeoBaseProjection::Desired) {
        Ok(result) => json_response(&SafeModeResponse {
            enabled: request.enabled,
            applied: true,
            core_status: result.core_status,
            firewall_status: result.firewall_status,
            suppressed: SAFE_MODE_SUPPRESSED.to_vec(),
        }),
        Err(error) => {
            let rollback = restore_safe_mode_after_failed_activation(
                daemon,
                request.enabled,
                previous_enabled,
                undo_id.as_deref(),
            );
            json_error(500, &format!("{error}; state rollback: {rollback}"))
        }
    }
}

fn restore_safe_mode_after_failed_activation(
    daemon: &Daemon,
    attempted: bool,
    previous: bool,
    undo_id: Option<&str>,
) -> String {
    let mut inner = lock(&daemon.inner);
    if inner.state.safe_mode_enabled != attempted {
        return "skipped (safe mode changed concurrently)".to_owned();
    }
    inner.state.safe_mode_enabled = previous;
    if let Some(undo_id) = undo_id {
        inner.state.undo_stack.retain(|entry| entry.id != undo_id);
    }
    match persist_state(&daemon.state_path, &inner.state) {
        Ok(()) => "restored".to_owned(),
        Err(error) => format!("failed ({error})"),
    }
}

fn handle_memory_estimate(daemon: &Daemon) -> (u16, &'static str, String) {
    let manifest = match daemon.geobase_store().load_manifest() {
        Ok(manifest) => manifest,
        Err(error) => return json_error(500, &format!("GeoBase manifest: {error}")),
    };
    let (state, mihomo_pid) = {
        let mut inner = lock(&daemon.inner);
        (inner.state.clone(), inner.core.pid())
    };
    let (_, available_kb, usage_pct) = memory_summary_from_proc();
    let current_mihomo_rss_kb = mihomo_pid.and_then(read_process_rss_kb).unwrap_or(0);
    let mut source_paths = Vec::new();
    for provider in &state.mihomo_features.rule_providers {
        if provider.provider_type == "file"
            && let Some(path) = provider.path.as_deref()
        {
            source_paths.push(PathBuf::from(path));
        }
    }
    let geobase_entries = manifest
        .applied_bases
        .iter()
        .filter(|base| base.enabled)
        .map(|base| {
            base.counts.direct
                + base.counts.active
                + base.counts.static_direct
                + base.counts.static_active
        })
        .sum();
    let geobase_bytes = manifest
        .applied_bases
        .iter()
        .filter(|base| base.enabled)
        .flat_map(|base| {
            [
                Some(&base.lists.direct),
                Some(&base.lists.active),
                base.lists.static_direct.as_ref(),
                base.lists.static_active.as_ref(),
            ]
            .into_iter()
            .flatten()
        })
        .filter_map(|metadata| fs::metadata(daemon.geobase_store_root.join(&metadata.file)).ok())
        .map(|metadata| metadata.len())
        .sum::<u64>();
    let rule_source_bytes = source_paths
        .iter()
        .filter_map(|path| fs::metadata(path).ok())
        .map(|metadata| metadata.len())
        .sum::<u64>()
        .saturating_add(geobase_bytes);
    let mut reasons = Vec::new();
    if state.memory_guard.enabled && usage_pct >= state.memory_guard.system_usage_warn_pct {
        reasons.push(format!(
            "observed system usage {usage_pct}% exceeds configured {}% threshold",
            state.memory_guard.system_usage_warn_pct
        ));
    }
    if state.memory_guard.enabled && current_mihomo_rss_kb >= state.memory_guard.mihomo_rss_warn_kb
    {
        reasons.push(format!(
            "observed Mihomo RSS {current_mihomo_rss_kb} KiB exceeds configured {} KiB threshold",
            state.memory_guard.mihomo_rss_warn_kb
        ));
    }
    let risk = if reasons.is_empty() {
        "observed-ok"
    } else {
        "observed-warning"
    };
    json_response(&MemoryEstimateResponse {
        risk,
        rule_source_bytes,
        current_mihomo_rss_kb,
        available_memory_kb: available_kb,
        user_rules: state.routing_rules.len(),
        rule_provider_count: state.mihomo_features.rule_providers.len(),
        geobase_entries,
        safe_mode_enabled: state.safe_mode_enabled,
        reasons,
    })
}

/// Return cumulative traffic statistics (persisted totals) plus
/// real-time speed from Mihomo `/traffic` API (if EC enabled).
fn handle_traffic_stats(daemon: &Daemon) -> (u16, &'static str, String) {
    let (total_up, total_down, ec_addr, ec_secret) = {
        let inner = lock(&daemon.inner);
        let ec = mihomo_controller(&inner.state.mihomo_features);
        let (addr, secret) = match ec {
            Some((a, s)) => (Some(a), s),
            None => (None, None),
        };
        (
            inner.state.traffic_total_up_bytes,
            inner.state.traffic_total_down_bytes,
            addr,
            secret,
        )
    };

    let mut current_up_kbps: u64 = 0;
    let mut current_down_kbps: u64 = 0;
    if let Some(addr) = ec_addr
        && let Ok(traffic) = mihomo_api_stream_get_json(&addr, ec_secret.as_deref(), "/traffic")
    {
        current_up_kbps = traffic.get("up").and_then(Value::as_u64).unwrap_or(0);
        current_down_kbps = traffic.get("down").and_then(Value::as_u64).unwrap_or(0);
    }

    (
        200,
        "application/json",
        json!({
            "current_up_kbps": current_up_kbps,
            "current_down_kbps": current_down_kbps,
            "total_up_bytes": total_up,
            "total_down_bytes": total_down,
        })
        .to_string(),
    )
}

fn handle_prometheus_metrics(daemon: &Daemon) -> (u16, &'static str, String) {
    let (profiles, active, total_up, total_down, core_running, firewall_running, mihomo_pid) = {
        let mut inner = lock(&daemon.inner);
        (
            inner.state.profiles.len(),
            inner.state.active_profile_id,
            inner.state.traffic_total_up_bytes,
            inner.state.traffic_total_down_bytes,
            inner.core.is_running(),
            inner.firewall.is_running(),
            inner.core.pid(),
        )
    };
    let (mem_total, mem_available, mem_usage_pct) = memory_summary_from_proc();
    let mihomo_rss = mihomo_pid.and_then(read_process_rss_kb).unwrap_or(0);
    let mut out = String::new();
    out.push_str("# HELP hincyray_up HincyRay daemon metrics endpoint status\n# TYPE hincyray_up gauge\nhincyray_up 1\n");
    out.push_str("# HELP hincyray_core_running Mihomo core running state\n# TYPE hincyray_core_running gauge\n");
    out.push_str(&format!(
        "hincyray_core_running {}\n",
        if core_running { 1 } else { 0 }
    ));
    out.push_str("# HELP hincyray_firewall_running HincyRay firewall running state\n# TYPE hincyray_firewall_running gauge\n");
    out.push_str(&format!(
        "hincyray_firewall_running {}\n",
        if firewall_running { 1 } else { 0 }
    ));
    out.push_str("# HELP hincyray_profiles_total Number of loaded profiles\n# TYPE hincyray_profiles_total gauge\n");
    out.push_str(&format!("hincyray_profiles_total {profiles}\n"));
    out.push_str("# HELP hincyray_active_profile_id Active profile id, -1 when none\n# TYPE hincyray_active_profile_id gauge\n");
    out.push_str(&format!(
        "hincyray_active_profile_id {}\n",
        active.map(|v| v as i64).unwrap_or(-1)
    ));
    out.push_str("# HELP hincyray_traffic_total_bytes Persisted proxy traffic totals\n# TYPE hincyray_traffic_total_bytes counter\n");
    out.push_str(&format!(
        "hincyray_traffic_total_bytes{{direction=\"up\"}} {total_up}\n"
    ));
    out.push_str(&format!(
        "hincyray_traffic_total_bytes{{direction=\"down\"}} {total_down}\n"
    ));
    out.push_str(
        "# HELP hincyray_memory_kib System memory KiB\n# TYPE hincyray_memory_kib gauge\n",
    );
    out.push_str(&format!(
        "hincyray_memory_kib{{kind=\"total\"}} {mem_total}\n"
    ));
    out.push_str(&format!(
        "hincyray_memory_kib{{kind=\"available\"}} {mem_available}\n"
    ));
    out.push_str("# HELP hincyray_memory_usage_percent System memory usage percent\n# TYPE hincyray_memory_usage_percent gauge\n");
    out.push_str(&format!("hincyray_memory_usage_percent {mem_usage_pct}\n"));
    out.push_str("# HELP hincyray_mihomo_rss_kib Mihomo process RSS KiB\n# TYPE hincyray_mihomo_rss_kib gauge\n");
    out.push_str(&format!("hincyray_mihomo_rss_kib {mihomo_rss}\n"));
    (200, "text/plain; version=0.0.4; charset=utf-8", out)
}

/// Speed test: download a file through the SOCKS proxy and measure
/// throughput. Body: `{"url": "...", "timeout_secs": 30}`.
/// Default URL: Cloudflare 10MB download. Requires the core to be
/// running (SOCKS proxy must be active).
fn handle_speed_test(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let (socks_url, core_running) = {
        let mut inner = lock(&daemon.inner);
        (
            format!(
                "socks5h://{}:{}",
                inner.state.listen_host, inner.state.socks_port
            ),
            inner.core.is_running(),
        )
    };
    if !core_running {
        return (
            400,
            "application/json",
            json!({"error": "core is not running — start the proxy first"}).to_string(),
        );
    }

    let (url, timeout_secs) = match serde_json::from_str::<Value>(body) {
        Ok(v) => (
            v.get("url")
                .and_then(Value::as_str)
                .unwrap_or("https://speed.cloudflare.com/__down?bytes=10485760")
                .to_owned(),
            v.get("timeout_secs").and_then(Value::as_u64).unwrap_or(30),
        ),
        Err(_) => (
            "https://speed.cloudflare.com/__down?bytes=10485760".to_owned(),
            30,
        ),
    };

    let client = {
        let proxy = match reqwest::Proxy::all(&socks_url) {
            Ok(p) => p,
            Err(e) => {
                return (
                    500,
                    "application/json",
                    json!({"error": format!("proxy setup: {e}")}).to_string(),
                );
            }
        };
        match reqwest::blocking::Client::builder()
            .proxy(proxy)
            .timeout(Duration::from_secs(timeout_secs))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                return (
                    500,
                    "application/json",
                    json!({"error": format!("client build: {e}")}).to_string(),
                );
            }
        }
    };

    let start = std::time::Instant::now();
    match client.get(&url).send() {
        Ok(resp) => {
            let status = resp.status();
            if !status.is_success() {
                return (
                    502,
                    "application/json",
                    json!({"error": format!("HTTP {status}")}).to_string(),
                );
            }
            match resp.bytes() {
                Ok(bytes) => {
                    let elapsed_ms = start.elapsed().as_millis() as u64;
                    let bytes_len = bytes.len() as u64;
                    let mbps = if elapsed_ms > 0 {
                        (bytes_len as f64 * 8.0 / 1_000_000.0) / (elapsed_ms as f64 / 1000.0)
                    } else {
                        0.0
                    };
                    (
                        200,
                        "application/json",
                        json!({
                            "download_mbps": (mbps * 100.0).round() / 100.0,
                            "elapsed_ms": elapsed_ms,
                            "bytes": bytes_len,
                        })
                        .to_string(),
                    )
                }
                Err(e) => (
                    500,
                    "application/json",
                    json!({"error": format!("read body: {e}")}).to_string(),
                ),
            }
        }
        Err(e) => (
            502,
            "application/json",
            json!({"error": format!("request failed: {e}")}).to_string(),
        ),
    }
}

fn handle_unlock_check(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let (socks_url, core_running) = {
        let mut inner = lock(&daemon.inner);
        (
            format!(
                "socks5h://{}:{}",
                inner.state.listen_host, inner.state.socks_port
            ),
            inner.core.is_running(),
        )
    };
    if !core_running {
        return (
            400,
            "application/json",
            json!({"error": "core is not running — start the proxy first"}).to_string(),
        );
    }
    let requested: HashSet<String> = serde_json::from_str::<Value>(body)
        .ok()
        .map(|v| {
            if let Some(service) = v.get("service").and_then(Value::as_str) {
                [service.to_ascii_lowercase()].into_iter().collect()
            } else {
                v.get("services")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_ascii_lowercase()))
                    .collect()
            }
        })
        .unwrap_or_default();

    let proxy_client = match socks_client(&socks_url, Duration::from_secs(10)) {
        Ok(client) => client,
        Err(error) => {
            return (500, "application/json", json!({"error": error}).to_string());
        }
    };
    let direct_client = match direct_http_client(Duration::from_secs(10)) {
        Ok(client) => client,
        Err(error) => {
            return (500, "application/json", json!({"error": error}).to_string());
        }
    };
    let mut results = Vec::new();
    for probe in unlock_probes() {
        if !requested.is_empty() && !requested.contains(probe.id) {
            continue;
        }
        let direct = run_unlock_probe(&direct_client, &probe);
        let proxy = run_unlock_probe(&proxy_client, &probe);
        results.push(json!({
            "id": probe.id,
            "name": probe.name,
            "url": probe.url,
            "direct": direct,
            "proxy": proxy,
            "unlocked": proxy.get("reachable").and_then(Value::as_bool).unwrap_or(false),
        }));
    }
    (
        200,
        "application/json",
        json!({"results": results}).to_string(),
    )
}

struct UnlockProbe {
    id: &'static str,
    name: &'static str,
    url: &'static str,
    ok_statuses: &'static [u16],
}

fn unlock_probes() -> Vec<UnlockProbe> {
    vec![
        UnlockProbe {
            id: "cloudflare",
            name: "Cloudflare Trace",
            url: "https://www.cloudflare.com/cdn-cgi/trace",
            ok_statuses: &[200],
        },
        UnlockProbe {
            id: "youtube",
            name: "YouTube",
            url: "https://www.youtube.com/generate_204",
            ok_statuses: &[200, 204],
        },
        UnlockProbe {
            id: "netflix",
            name: "Netflix",
            url: "https://www.netflix.com/title/80018499",
            ok_statuses: &[200, 301, 302],
        },
        UnlockProbe {
            id: "openai",
            name: "OpenAI",
            url: "https://chat.openai.com/cdn-cgi/trace",
            ok_statuses: &[200, 403],
        },
        UnlockProbe {
            id: "spotify",
            name: "Spotify",
            url: "https://open.spotify.com/",
            ok_statuses: &[200, 301, 302],
        },
    ]
}

fn run_unlock_probe(client: &reqwest::blocking::Client, probe: &UnlockProbe) -> Value {
    let start = std::time::Instant::now();
    match client.get(probe.url).send() {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let ok = probe.ok_statuses.contains(&status);
            json!({
                "reachable": ok,
                "http_status": status,
                "elapsed_ms": start.elapsed().as_millis() as u64,
            })
        }
        Err(error) => json!({
            "reachable": false,
            "error": error.to_string(),
            "elapsed_ms": start.elapsed().as_millis() as u64,
        }),
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct AutoVpnCandidate {
    domain: String,
    port: Option<u16>,
}

fn auto_vpn_probe_urls(candidate: &AutoVpnCandidate) -> [String; 2] {
    let schemes = if candidate.port == Some(80) {
        ["http", "https"]
    } else {
        ["https", "http"]
    };
    let authority = match candidate.port {
        Some(port) => format!("{}:{port}", candidate.domain),
        None => candidate.domain.clone(),
    };
    [
        format!("{}://{authority}/", schemes[0]),
        format!("{}://{authority}/", schemes[1]),
    ]
}

fn probe_domain_reachable(
    client: &reqwest::blocking::Client,
    candidate: &AutoVpnCandidate,
) -> bool {
    for url in auto_vpn_probe_urls(candidate) {
        if let Ok(resp) = client.get(&url).send()
            && resp.status().as_u16() < 500
            && resp.status().as_u16() != 451
        {
            return true;
        }
    }
    false
}

fn proxy_domain_reachable_via_mihomo(
    addr: &str,
    secret: Option<&str>,
    candidate: &AutoVpnCandidate,
) -> bool {
    for url in auto_vpn_probe_urls(candidate) {
        if mihomo_api_delay(addr, secret, PROXY_ACTIVE_NAME, &url, 8000).is_ok() {
            return true;
        }
    }
    false
}

fn auto_vpn_candidate_from_mihomo_log_payload(payload: &str) -> Option<AutoVpnCandidate> {
    if !payload.contains("dial DIRECT") || !payload.contains(" error:") {
        return None;
    }
    let (_, after_arrow) = payload.split_once(" --> ")?;
    let (target, _) = after_arrow.split_once(" error:")?;
    let domain = normalize_auto_vpn_domain(target)?;
    let (_, port) = target.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    Some(AutoVpnCandidate {
        domain,
        port: Some(port),
    })
}

fn parovozik_candidate_from_mihomo_log_payload(payload: &str) -> Option<AutoVpnCandidate> {
    let (target, error) = payload.split_once(" error:")?;
    let direct_attempt = payload.contains("dial DIRECT")
        || payload.contains("dial tcp")
        || payload.contains("connect error");
    if !direct_attempt || error.trim().is_empty() {
        return None;
    }
    let target = target.rsplit(" --> ").next()?.trim();
    let domain = normalize_auto_vpn_domain(target)?;
    let port = target
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok());
    Some(AutoVpnCandidate { domain, port })
}

#[derive(Debug, Default)]
struct MihomoLogCursor {
    identity: Option<(u64, u64)>,
    offset: u64,
}

impl MihomoLogCursor {
    fn start_at_end(path: &Path) -> Self {
        match fs::metadata(path) {
            Ok(metadata) => Self {
                identity: Some(file_identity(&metadata)),
                offset: metadata.len(),
            },
            Err(_) => Self::default(),
        }
    }

    fn read_new_domains(
        &mut self,
        path: &Path,
        parovozik_enabled: bool,
    ) -> Result<Vec<AutoVpnCandidate>, String> {
        let mut file = fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
        let metadata = file
            .metadata()
            .map_err(|e| format!("metadata {}: {e}", path.display()))?;
        let identity = file_identity(&metadata);
        match self.identity {
            None => {
                self.identity = Some(identity);
                self.offset = 0;
            }
            Some(previous) if previous != identity => {
                self.identity = Some(identity);
                self.offset = 0;
            }
            Some(_) if metadata.len() < self.offset => {
                self.offset = 0;
            }
            Some(_) => {}
        }

        file.seek(SeekFrom::Start(self.offset))
            .map_err(|e| format!("seek {}: {e}", path.display()))?;
        let mut bytes = Vec::new();
        file.take(1_048_576)
            .read_to_end(&mut bytes)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        let Some(last_newline) = bytes.iter().rposition(|byte| *byte == b'\n') else {
            return Ok(Vec::new());
        };
        let complete_len = last_newline + 1;
        self.offset = self.offset.saturating_add(complete_len as u64);
        Ok(log_candidate_domains_from_text(
            &String::from_utf8_lossy(&bytes[..complete_len]),
            parovozik_enabled,
        ))
    }
}

#[cfg(unix)]
fn file_identity(metadata: &fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (metadata.dev(), metadata.ino())
}

#[cfg(not(unix))]
fn file_identity(metadata: &fs::Metadata) -> (u64, u64) {
    (metadata.len(), 0)
}

#[cfg(test)]
fn auto_vpn_log_candidate_domains_from_text(text: &str) -> Vec<AutoVpnCandidate> {
    log_candidate_domains_from_text(text, false)
}

fn log_candidate_domains_from_text(text: &str, parovozik_enabled: bool) -> Vec<AutoVpnCandidate> {
    let mut seen = HashSet::new();
    let mut domains = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let candidate = if parovozik_enabled {
            parovozik_candidate_from_mihomo_log_payload(line)
        } else {
            auto_vpn_candidate_from_mihomo_log_payload(line)
        };
        let Some(candidate) = candidate else {
            continue;
        };
        if seen.insert(candidate.clone()) {
            domains.push(candidate);
        }
    }
    domains
}

fn auto_vpn_candidate_domains(
    state: &HincyrayState,
    now: u64,
    observed_direct_failures: &[AutoVpnCandidate],
) -> Vec<AutoVpnCandidate> {
    let known_auto: HashSet<String> = state
        .split_routing
        .auto_vpn_exceptions
        .iter()
        .filter_map(|domain| normalize_auto_vpn_domain(domain))
        .collect();
    let mut seen = HashSet::new();
    let mut candidates = Vec::new();

    for observed in observed_direct_failures {
        let domain = &observed.domain;
        if known_auto.contains(domain) {
            continue;
        }
        let last_checked = state
            .split_routing
            .auto_vpn_last_checked_unix
            .get(domain)
            .copied()
            .unwrap_or(0);
        if now.saturating_sub(last_checked) < AUTO_VPN_RECHECK_INTERVAL_SECS {
            continue;
        }
        if seen.insert(domain.clone()) {
            candidates.push(observed.clone());
            if candidates.len() >= 3 {
                return candidates;
            }
        }
    }

    for entry in state.connection_log.iter().rev() {
        if !entry.chains.iter().any(|chain| chain == DIRECT_NAME) {
            continue;
        }
        let Some(domain) = normalize_auto_vpn_domain(&entry.host) else {
            continue;
        };
        if known_auto.contains(&domain) {
            continue;
        }
        let last_checked = state
            .split_routing
            .auto_vpn_last_checked_unix
            .get(&domain)
            .copied()
            .unwrap_or(0);
        if now.saturating_sub(last_checked) < AUTO_VPN_RECHECK_INTERVAL_SECS {
            continue;
        }
        if seen.insert(domain.clone()) {
            candidates.push(AutoVpnCandidate {
                domain,
                port: (entry.destination_port != 0).then_some(entry.destination_port),
            });
            if candidates.len() >= 3 {
                break;
            }
        }
    }

    for domain in &state.split_routing.auto_vpn_exceptions {
        let Some(domain) = normalize_auto_vpn_domain(domain) else {
            continue;
        };
        let last_checked = state
            .split_routing
            .auto_vpn_last_checked_unix
            .get(&domain)
            .copied()
            .unwrap_or(0);
        if now.saturating_sub(last_checked) >= AUTO_VPN_RECHECK_INTERVAL_SECS
            && seen.insert(domain.clone())
        {
            candidates.push(AutoVpnCandidate { domain, port: None });
            if candidates.len() >= 3 {
                break;
            }
        }
    }

    candidates
}

fn domain_matches_geobase_artifact(domain: &str, bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|text| {
        text.lines().any(|line| {
            let entry = line.trim().trim_start_matches("+.");
            !entry.is_empty() && (domain == entry || domain.ends_with(&format!(".{entry}")))
        })
    })
}

fn domain_is_in_applied_geobase(daemon: &Daemon, domain: &str) -> Result<bool, String> {
    let manifest = daemon
        .geobase_store()
        .load_manifest()
        .map_err(|error| format!("GeoBase manifest: {error}"))?;
    for base in manifest
        .applied_bases
        .iter()
        .filter(|base| base.enabled && base.status == GeoBaseStatus::Ready)
    {
        for metadata in [
            &base.lists.active,
            &base.lists.direct,
            &base.lists.unresolved,
        ] {
            let bytes = fs::read(daemon.geobase_store_root.join(&metadata.file))
                .map_err(|error| format!("GeoBase artifact {}: {error}", metadata.file))?;
            if domain_matches_geobase_artifact(domain, &bytes) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn parovozik_candidate_domains(
    state: &HincyrayState,
    now: u64,
    observed_direct_failures: &[AutoVpnCandidate],
) -> Vec<AutoVpnCandidate> {
    let known: HashSet<&str> = state
        .split_routing
        .parovozik_direct_domains
        .iter()
        .chain(state.split_routing.parovozik_vpn_domains.iter())
        .map(String::as_str)
        .collect();
    let manual_rule_match = |domain: &str| {
        state
            .routing_rules
            .iter()
            .filter(|rule| rule.enabled)
            .any(|rule| trace_domain_match(rule, domain).exact)
    };
    observed_direct_failures
        .iter()
        .filter(|candidate| !known.contains(candidate.domain.as_str()))
        .filter(|candidate| !manual_rule_match(&candidate.domain))
        .filter(|candidate| {
            now.saturating_sub(
                state
                    .split_routing
                    .parovozik_last_checked_unix
                    .get(&candidate.domain)
                    .copied()
                    .unwrap_or(0),
            ) >= AUTO_VPN_RECHECK_INTERVAL_SECS
        })
        .take(3)
        .cloned()
        .collect()
}

fn parovozik_probe_targets(state: &HincyrayState) -> Vec<String> {
    let mut targets = vec![PROXY_ACTIVE_NAME.to_owned()];
    for server_ref in state
        .split_routing
        .parovozik_server_refs
        .iter()
        .take(MAX_PAROVOZIK_SERVERS)
    {
        let usable = state.server_route_registry.iter().any(|entry| {
            entry.server_ref == *server_ref
                && state.profiles.iter().any(|profile| {
                    canonical_profile_raw(profile) == entry.canonical_raw
                        && !profile_is_dead(state, profile)
                })
        });
        if usable && server_ref.len() > 7 {
            targets.push(format!("srv-route-{}", &server_ref[7..]));
        }
    }
    targets
}

fn run_parovozik(
    daemon: &Daemon,
    ec_addr: Option<&str>,
    ec_secret: Option<&str>,
    observed_direct_failures: &[AutoVpnCandidate],
) -> bool {
    let Some(ec_addr) = ec_addr else {
        return false;
    };
    let now = unix_now();
    let (candidates, targets) = {
        let inner = lock(&daemon.inner);
        if !inner.state.split_routing.parovozik_enabled {
            return true;
        }
        (
            parovozik_candidate_domains(&inner.state, now, observed_direct_failures),
            parovozik_probe_targets(&inner.state),
        )
    };
    if candidates.is_empty() {
        return true;
    }
    let Ok(direct_client) = direct_http_client(Duration::from_secs(5)) else {
        return false;
    };
    let mut classified = Vec::new();
    for candidate in candidates {
        match domain_is_in_applied_geobase(daemon, &candidate.domain) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => {
                eprintln!("hincyray: Паровозик GeoBase lookup failed: {error}");
                return false;
            }
        }
        let target = if probe_domain_reachable(&direct_client, &candidate) {
            Some("direct")
        } else if targets.iter().any(|target| {
            auto_vpn_probe_urls(&candidate)
                .iter()
                .any(|url| mihomo_api_delay(ec_addr, ec_secret, target, url, 8000).is_ok())
        }) {
            Some("vpn")
        } else {
            None
        };
        classified.push((candidate.domain, target));
    }
    if classified.is_empty() {
        return true;
    }

    let previous_state = lock(&daemon.inner).state.clone();
    let (changed, direct_changed, vpn_changed, updated_state) = {
        let mut inner = lock(&daemon.inner);
        if !inner.state.split_routing.parovozik_enabled {
            return true;
        }
        let mut changed = false;
        let mut direct_changed = false;
        let mut vpn_changed = false;
        for (domain, target) in classified {
            inner
                .state
                .split_routing
                .parovozik_last_checked_unix
                .insert(domain.clone(), now);
            let list = match target {
                Some("direct") => Some(&mut inner.state.split_routing.parovozik_direct_domains),
                Some("vpn") => Some(&mut inner.state.split_routing.parovozik_vpn_domains),
                _ => None,
            };
            if let Some(list) = list
                && !list.contains(&domain)
            {
                eprintln!("hincyray: Паровозик classified {domain} as {target:?}");
                list.push(domain);
                changed = true;
                direct_changed |= target == Some("direct");
                vpn_changed |= target == Some("vpn");
            }
        }
        inner.state.split_routing.parovozik_direct_domains =
            normalize_parovozik_domains(&inner.state.split_routing.parovozik_direct_domains);
        inner.state.split_routing.parovozik_vpn_domains =
            normalize_parovozik_domains(&inner.state.split_routing.parovozik_vpn_domains);
        if changed && let Err(error) = persist_state(&daemon.state_path, &inner.state) {
            inner.state = previous_state.clone();
            eprintln!("hincyray: Паровозик persist failed: {error}");
            return false;
        }
        (changed, direct_changed, vpn_changed, inner.state.clone())
    };
    if changed {
        if let Err(error) =
            hot_update_parovozik_providers(&updated_state, direct_changed, vpn_changed)
        {
            let rollback = restore_state_after_failed_policy_change(daemon, previous_state.clone());
            let provider_rollback =
                hot_update_parovozik_providers(&previous_state, direct_changed, vpn_changed)
                    .map_or_else(
                        |error| format!("failed ({error})"),
                        |()| "restored".to_owned(),
                    );
            eprintln!(
                "hincyray: Паровозик hot update failed: {error}; state rollback: {rollback}; provider rollback: {provider_rollback}"
            );
            return false;
        }
        eprintln!("hincyray: Паровозик providers updated without core/firewall restart");
    }
    true
}

fn run_auto_vpn_learning(
    daemon: &Daemon,
    ec_addr: Option<&str>,
    ec_secret: Option<&str>,
    observed_direct_failures: &[AutoVpnCandidate],
) -> bool {
    let Some(ec_addr) = ec_addr else {
        return false;
    };
    let now = unix_now();
    let candidates = {
        let inner = lock(&daemon.inner);
        if !inner.state.split_routing.auto_vpn_learning_enabled {
            return true;
        }
        auto_vpn_candidate_domains(&inner.state, now, observed_direct_failures)
    };
    if candidates.is_empty() {
        return true;
    }

    let Ok(direct_client) = direct_http_client(Duration::from_secs(5)) else {
        return false;
    };
    let mut add = Vec::new();
    let mut remove = Vec::new();
    let mut checked = HashMap::new();
    for candidate in candidates {
        let direct_ok = probe_domain_reachable(&direct_client, &candidate);
        let proxy_ok = proxy_domain_reachable_via_mihomo(ec_addr, ec_secret, &candidate);
        let domain = candidate.domain;
        checked.insert(domain.clone(), now);
        if direct_ok {
            remove.push(domain);
        } else if proxy_ok {
            add.push(domain);
        }
    }

    if add.is_empty() && remove.is_empty() && checked.is_empty() {
        return true;
    }

    let mut inner = lock(&daemon.inner);
    let mut changed = false;
    for (domain, timestamp) in checked {
        inner
            .state
            .split_routing
            .auto_vpn_last_checked_unix
            .insert(domain, timestamp);
    }
    if !remove.is_empty() {
        let remove_set: HashSet<String> = remove.iter().cloned().collect();
        let before = inner.state.split_routing.auto_vpn_exceptions.len();
        inner
            .state
            .split_routing
            .auto_vpn_exceptions
            .retain(|domain| !remove_set.contains(domain));
        changed |= before != inner.state.split_routing.auto_vpn_exceptions.len();
    }
    for domain in add {
        if !inner
            .state
            .split_routing
            .auto_vpn_exceptions
            .iter()
            .any(|existing| existing == &domain)
        {
            eprintln!("hincyray: auto VPN exception learned: {domain}");
            inner.state.split_routing.auto_vpn_exceptions.push(domain);
            changed = true;
        }
    }
    let deduped = dedup_limited_domains(inner.state.split_routing.auto_vpn_exceptions.clone());
    if deduped != inner.state.split_routing.auto_vpn_exceptions {
        inner.state.split_routing.auto_vpn_exceptions = deduped;
        changed = true;
    }
    prune_auto_vpn_metadata(&mut inner.state.split_routing);
    inner.dirty = true;
    if changed {
        eprintln!(
            "hincyray: auto VPN exceptions changed; deferred until the next explicit routing apply"
        );
    }
    true
}

fn direct_http_client(timeout: Duration) -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| format!("client build: {e}"))
}

#[derive(Deserialize)]
struct GeoBaseAnalyzeRequest {
    #[serde(default)]
    id: Option<String>,
    name: String,
    source: GeoBaseSource,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    static_entries: Vec<StaticRouteEntry>,
}

#[derive(Deserialize)]
struct GeoBaseIdRequest {
    id: String,
}

#[derive(Deserialize)]
struct GeoBaseEnabledRequest {
    id: String,
    enabled: bool,
}

#[derive(Deserialize)]
struct GeoBaseStaticRequest {
    id: String,
    expected_revision: u64,
    static_entries: Vec<StaticRouteEntry>,
}

#[derive(Clone)]
struct GeoBaseJob {
    id: String,
    name: String,
    source: GeoBaseSource,
    content: Option<Vec<u8>>,
    static_entries: Vec<StaticRouteEntry>,
    expected_revision: Option<u64>,
    enabled: bool,
    sync_only: bool,
    controller: Option<(String, Option<String>)>,
    source_proxy_url: Option<String>,
    #[cfg(test)]
    analyzer: Option<GeoBaseAnalyzer>,
}

fn geobase_store(daemon: &Daemon) -> &GeoBaseStore {
    daemon.geobase_store()
}

fn geobase_error_status(error: &geobase::GeoBaseError) -> u16 {
    match error {
        geobase::GeoBaseError::NotFound(_) => 404,
        geobase::GeoBaseError::AlreadyExists(_) | geobase::GeoBaseError::Conflict(_) => 409,
        geobase::GeoBaseError::Io(_) | geobase::GeoBaseError::Json(_) => 500,
        _ => 400,
    }
}

fn handle_geobases_get(daemon: &Daemon) -> (u16, &'static str, String) {
    let status = lock(&daemon.inner).geobase.status.clone();
    match geobase_store(daemon).load_manifest() {
        Ok(manifest) => {
            let requires_apply = manifest.requires_apply();
            let bases = manifest.bases.clone();
            (
                200,
                "application/json",
                json!({
                    "manifest": manifest,
                    "bases": bases,
                    "runtime": status,
                    "requires_apply": requires_apply,
                })
                .to_string(),
            )
        }
        Err(error) => json_error(
            geobase_error_status(&error),
            &format!("GeoBase manifest: {error}"),
        ),
    }
}

fn handle_geobases_analyze(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let request: GeoBaseAnalyzeRequest = match serde_json::from_str(body) {
        Ok(request) => request,
        Err(error) => return json_error(400, &format!("invalid JSON body: {error}")),
    };
    let content = match request.source.kind {
        GeoBaseSourceKind::Url => {
            if request.content.is_some() {
                return json_error(400, "URL source must not include content");
            }
            None
        }
        GeoBaseSourceKind::Upload | GeoBaseSourceKind::Manual => {
            let Some(content) = request.content else {
                return json_error(400, "upload/manual source requires content");
            };
            if content.len() > geobase::MAX_SOURCE_BYTES {
                return json_error(413, "GeoBase source exceeds 8 MiB");
            }
            Some(content.into_bytes())
        }
    };
    let id = request.id.unwrap_or_else(|| {
        geobase::stable_id(&format!("{}\0{}", request.name, request.source.value))
    });
    start_geobase_job(
        daemon,
        id,
        request.name,
        request.source,
        content,
        request.static_entries,
        false,
    )
}

fn handle_geobases_sync(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let request: GeoBaseIdRequest = match serde_json::from_str(body) {
        Ok(request) => request,
        Err(error) => return json_error(400, &format!("invalid JSON body: {error}")),
    };
    if geobase_id_is_running(daemon, &request.id) {
        return json_error(409, "GeoBase is being analyzed");
    }
    let store = geobase_store(daemon);
    let manifest = match store.load_manifest() {
        Ok(manifest) => manifest,
        Err(error) => return json_error(geobase_error_status(&error), &error.to_string()),
    };
    let Some(record) = manifest
        .bases
        .into_iter()
        .find(|record| record.id == request.id)
    else {
        return json_error(404, "GeoBase not found");
    };
    if record.source.kind != GeoBaseSourceKind::Url {
        return json_error(400, "only stored URL sources can be synced");
    }
    let static_entries = match store.load_lists(&record.id) {
        Ok(generation) => generation.static_entries,
        Err(error) => return json_error(geobase_error_status(&error), &error.to_string()),
    };
    start_geobase_job(
        daemon,
        record.id,
        record.name,
        record.source,
        None,
        static_entries,
        true,
    )
}

fn handle_geobases_details(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let request: GeoBaseIdRequest = match serde_json::from_str(body) {
        Ok(request) => request,
        Err(error) => return json_error(400, &format!("invalid JSON body: {error}")),
    };
    let store = geobase_store(daemon);
    let manifest = match store.load_manifest() {
        Ok(manifest) => manifest,
        Err(error) => return json_error(geobase_error_status(&error), &error.to_string()),
    };
    let Some(record) = manifest
        .bases
        .into_iter()
        .find(|record| record.id == request.id)
    else {
        return json_error(404, "GeoBase not found");
    };
    let source = match store.load_source(&record.id) {
        Ok(source) => source,
        Err(error) => return json_error(geobase_error_status(&error), &error.to_string()),
    };
    let parsed = match geobase::parse_source(&source) {
        Ok(parsed) => parsed,
        Err(error) => return json_error(geobase_error_status(&error), &error.to_string()),
    };
    let lists = match store.load_lists(&record.id) {
        Ok(lists) => lists,
        Err(error) => return json_error(geobase_error_status(&error), &error.to_string()),
    };
    (
        200,
        "application/json",
        json!({"base": record, "source_networks": parsed.networks, "lists": lists}).to_string(),
    )
}

fn handle_geobases_static(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let request: GeoBaseStaticRequest = match serde_json::from_str(body) {
        Ok(request) => request,
        Err(error) => return json_error(400, &format!("invalid JSON body: {error}")),
    };
    if geobase_id_is_running(daemon, &request.id) {
        return json_error(409, "GeoBase is being analyzed");
    }
    let _apply = match daemon.apply.lock() {
        Ok(lock) => lock,
        Err(_) => return json_error(500, "config apply lock is poisoned"),
    };
    let store = geobase_store(daemon);
    let manifest = match store.load_manifest() {
        Ok(manifest) => manifest,
        Err(error) => return json_error(geobase_error_status(&error), &error.to_string()),
    };
    let Some(record) = manifest
        .bases
        .into_iter()
        .find(|record| record.id == request.id)
    else {
        return json_error(404, "GeoBase not found");
    };
    let source = match store.load_source(&record.id) {
        Ok(source) => source,
        Err(error) => return json_error(geobase_error_status(&error), &error.to_string()),
    };
    let mut generation = match store.load_lists(&record.id) {
        Ok(generation) => generation,
        Err(error) => return json_error(geobase_error_status(&error), &error.to_string()),
    };
    generation.static_entries = request.static_entries;
    let upsert = GeoBaseUpsertRequest {
        id: record.id,
        name: record.name,
        source: record.source,
        enabled: record.enabled,
    };
    match store.update(upsert, request.expected_revision, &source, generation) {
        Ok(record) => (
            200,
            "application/json",
            json!({"base": record, "requires_apply": true}).to_string(),
        ),
        Err(error) => json_error(geobase_error_status(&error), &error.to_string()),
    }
}

fn handle_geobases_cancel(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    let Some(cancel) = inner
        .geobase
        .cancel
        .as_ref()
        .filter(|_| inner.geobase.status.running)
    else {
        return json_error(409, "no GeoBase analysis is running");
    };
    cancel.store(true, Ordering::Release);
    (
        200,
        "application/json",
        json!({"runtime": inner.geobase.status}).to_string(),
    )
}

fn handle_geobases_delete(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let request: GeoBaseIdRequest = match serde_json::from_str(body) {
        Ok(request) => request,
        Err(error) => return json_error(400, &format!("invalid JSON body: {error}")),
    };
    if geobase_id_is_running(daemon, &request.id) {
        return json_error(409, "GeoBase is being analyzed");
    }
    let _apply = match daemon.apply.lock() {
        Ok(lock) => lock,
        Err(_) => return json_error(500, "config apply lock is poisoned"),
    };
    match geobase_store(daemon).delete(&request.id) {
        Ok(record) => (
            200,
            "application/json",
            json!({"deleted": record}).to_string(),
        ),
        Err(error) => json_error(geobase_error_status(&error), &error.to_string()),
    }
}

fn handle_geobases_enabled(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let request: GeoBaseEnabledRequest = match serde_json::from_str(body) {
        Ok(request) => request,
        Err(error) => return json_error(400, &format!("invalid JSON body: {error}")),
    };
    if geobase_id_is_running(daemon, &request.id) {
        return json_error(409, "GeoBase is being analyzed");
    }
    let _apply = match daemon.apply.lock() {
        Ok(lock) => lock,
        Err(_) => return json_error(500, "config apply lock is poisoned"),
    };
    match geobase_store(daemon).set_enabled(&request.id, request.enabled, None) {
        Ok(record) => (200, "application/json", json!({"base": record}).to_string()),
        Err(error) => json_error(geobase_error_status(&error), &error.to_string()),
    }
}

fn geobase_id_is_running(daemon: &Daemon, id: &str) -> bool {
    let inner = lock(&daemon.inner);
    inner.geobase.status.running && inner.geobase.status.id.as_deref() == Some(id)
}

fn start_geobase_job(
    daemon: &Daemon,
    id: String,
    name: String,
    source: GeoBaseSource,
    content: Option<Vec<u8>>,
    static_entries: Vec<StaticRouteEntry>,
    sync_only: bool,
) -> (u16, &'static str, String) {
    if let Err(error) = geobase::validate_id(&id) {
        return json_error(400, &error.to_string());
    }
    if name.trim().is_empty() || name.len() > 128 || source.value.len() > 2048 {
        return json_error(400, "invalid GeoBase name or source metadata");
    }
    if let Err(error) = validate_geobase_static_entries(&static_entries) {
        return json_error(400, &error);
    }

    let previous_handle = {
        let mut inner = lock(&daemon.inner);
        if inner.geobase.status.running {
            return json_error(409, "a GeoBase analysis is already running");
        }
        inner.geobase.handle.take()
    };
    if let Some(handle) = previous_handle {
        let _ = handle.join();
    }

    let store = geobase_store(daemon);
    let existing = match store.load_manifest() {
        Ok(manifest) => manifest.bases.into_iter().find(|record| record.id == id),
        Err(error) => return json_error(geobase_error_status(&error), &error.to_string()),
    };
    if sync_only && existing.is_none() {
        return json_error(404, "GeoBase not found");
    }
    let expected_revision = existing.as_ref().map(|record| record.revision);
    let enabled = existing.as_ref().is_none_or(|record| record.enabled);
    let (controller, source_proxy_url) = {
        let mut inner = lock(&daemon.inner);
        let controller = mihomo_controller(&inner.state.mihomo_features);
        let source_proxy_url = geobase_source_proxy_url(&mut inner);
        (controller, source_proxy_url)
    };
    #[cfg(test)]
    let analyzer = lock(&daemon.inner).geobase.analyzer.clone();
    let cancel = Arc::new(AtomicBool::new(false));
    let job = GeoBaseJob {
        id: id.clone(),
        name,
        source,
        content,
        static_entries,
        expected_revision,
        enabled,
        sync_only,
        controller,
        source_proxy_url,
        #[cfg(test)]
        analyzer,
    };
    let worker_daemon = daemon.clone();
    let worker_cancel = cancel.clone();
    {
        let mut inner = lock(&daemon.inner);
        if inner.geobase.status.running {
            return json_error(409, "a GeoBase analysis is already running");
        }
        let Some(next_job_id) = inner.geobase.next_job_id.checked_add(1) else {
            return json_error(500, "GeoBase job id space exhausted");
        };
        inner.geobase.next_job_id = next_job_id;
        let job_id = inner.geobase.next_job_id;
        inner.geobase.current_job_id = Some(job_id);
        inner.geobase.cancel = Some(cancel);
        inner.geobase.status = GeoBaseRuntimeStatus {
            job_id,
            phase: "loading".to_owned(),
            id: Some(id),
            running: true,
            ..GeoBaseRuntimeStatus::default()
        };
        inner.geobase.handle = Some(thread::spawn(move || {
            run_geobase_job(worker_daemon, worker_cancel, job_id, job)
        }));
        (
            202,
            "application/json",
            json!({"runtime": inner.geobase.status}).to_string(),
        )
    }
}

fn geobase_source_proxy_url(inner: &mut DaemonInner) -> Option<String> {
    inner.core.is_running().then(|| {
        format!(
            "socks5h://{}:{}",
            inner.state.listen_host, inner.state.socks_port
        )
    })
}

fn validate_geobase_static_entries(entries: &[StaticRouteEntry]) -> Result<(), String> {
    let mut targets = HashMap::new();
    for entry in entries {
        if entry.target == Classification::Unresolved {
            return Err("static route target must be direct or active".to_owned());
        }
        let parsed = geobase::parse_source(entry.network.as_bytes()).map_err(|e| e.to_string())?;
        if parsed.networks.len() != 1 || !parsed.domains.is_empty() {
            return Err(format!("invalid static network: {}", entry.network));
        }
        if let Some(previous) = targets.insert(parsed.networks[0].clone(), entry.target)
            && previous != entry.target
        {
            return Err(format!(
                "static route has conflicting targets: {}",
                entry.network
            ));
        }
    }
    Ok(())
}

fn run_geobase_job(daemon: Daemon, cancel: Arc<AtomicBool>, job_id: u64, job: GeoBaseJob) {
    let mut completion = GeoBaseJobCompletion::new(daemon.clone(), job_id);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_geobase_job_inner(
            &daemon,
            &cancel,
            job_id,
            Instant::now() + GEOBASE_JOB_TIMEOUT,
            &job,
        )
    }));
    let outcome = match result {
        Ok(Ok(())) => ("complete", None),
        Ok(Err(_)) if cancel.load(Ordering::Acquire) => ("cancelled", None),
        Ok(Err(error)) => ("error", Some(error)),
        Err(payload) => ("panic", Some(panic_message(payload))),
    };
    completion.finish(outcome.0, outcome.1);
}

struct GeoBaseJobCompletion {
    daemon: Daemon,
    job_id: u64,
    finished: bool,
}

impl GeoBaseJobCompletion {
    fn new(daemon: Daemon, job_id: u64) -> Self {
        Self {
            daemon,
            job_id,
            finished: false,
        }
    }

    fn finish(&mut self, phase: &str, error: Option<String>) {
        let mut inner = lock(&self.daemon.inner);
        if inner.geobase.current_job_id == Some(self.job_id) {
            inner.geobase.cancel = None;
            inner.geobase.current_job_id = None;
            inner.geobase.status.running = false;
            inner.geobase.status.phase = phase.to_owned();
            inner.geobase.status.error = error;
        }
        self.finished = true;
    }
}

impl Drop for GeoBaseJobCompletion {
    fn drop(&mut self) {
        if !self.finished {
            self.finish(
                "panic",
                Some("GeoBase worker terminated without completion".to_owned()),
            );
        }
    }
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|message| (*message).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .map_or_else(
            || "GeoBase worker panicked".to_owned(),
            |message| format!("GeoBase worker panicked: {message}"),
        )
}

fn run_geobase_job_inner(
    daemon: &Daemon,
    cancel: &Arc<AtomicBool>,
    job_id: u64,
    deadline: Instant,
    job: &GeoBaseJob,
) -> Result<(), String> {
    check_geobase_job(cancel, deadline)?;
    let source = match job.source.kind {
        GeoBaseSourceKind::Url => download_geobase_url(
            &job.source.value,
            job.source_proxy_url.as_deref(),
            cancel,
            deadline,
        )?,
        GeoBaseSourceKind::Upload | GeoBaseSourceKind::Manual => job
            .content
            .clone()
            .ok_or_else(|| "source content is missing".to_owned())?,
    };
    check_geobase_job(cancel, deadline)?;
    let parsed = geobase::parse_source(&source).map_err(|error| error.to_string())?;
    let source_diff = if job.sync_only {
        Some(
            geobase_store(daemon)
                .diff_with_stored(&job.id, &source)
                .map_err(|error| error.to_string())?,
        )
    } else {
        None
    };
    let source_networks: HashSet<&str> = parsed.networks.iter().map(String::as_str).collect();
    let static_entries: Vec<_> = job
        .static_entries
        .iter()
        .filter(|entry| source_networks.contains(entry.network.as_str()))
        .cloned()
        .collect();
    let removed_static_entries = job
        .static_entries
        .len()
        .saturating_sub(static_entries.len());
    update_geobase_status(daemon, job_id, |status| {
        status.phase = "analyzing".to_owned();
        status.total = parsed.domains.len();
        status.source_diff = source_diff.clone();
        status.removed_static_entries = removed_static_entries;
    });
    let classifications =
        classify_geobase_domains(daemon, cancel, job_id, deadline, job, parsed.domains)?;
    check_geobase_job(cancel, deadline)?;
    update_geobase_status(daemon, job_id, |status| status.phase = "saving".to_owned());
    let request = GeoBaseUpsertRequest {
        id: job.id.clone(),
        name: job.name.clone(),
        source: job.source.clone(),
        enabled: job.enabled,
    };
    let generation = GeoBaseGenerationInput {
        classifications,
        static_entries,
    };
    let _apply = daemon
        .apply
        .lock()
        .map_err(|_| "config apply lock is poisoned".to_owned())?;
    let store = geobase_store(daemon);
    match job.expected_revision {
        Some(revision) => store.update(request, revision, &source, generation),
        None => store.create(request, &source, generation),
    }
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn update_geobase_status(
    daemon: &Daemon,
    job_id: u64,
    update: impl FnOnce(&mut GeoBaseRuntimeStatus),
) {
    let mut inner = lock(&daemon.inner);
    if inner.geobase.current_job_id == Some(job_id) {
        update(&mut inner.geobase.status);
    }
}

fn classify_geobase_domains(
    daemon: &Daemon,
    cancel: &Arc<AtomicBool>,
    job_id: u64,
    deadline: Instant,
    job: &GeoBaseJob,
    domains: Vec<String>,
) -> Result<Vec<DomainClassification>, String> {
    let total = domains.len();
    let domains = Arc::new(domains);
    let index = Arc::new(AtomicUsize::new(0));
    let results = Arc::new(Mutex::new(Vec::with_capacity(total)));
    let worker_count = total.min(4);
    let mut handles = Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        let domains = domains.clone();
        let index = index.clone();
        let results = results.clone();
        let cancel = cancel.clone();
        let daemon = daemon.clone();
        let controller = job.controller.clone();
        #[cfg(test)]
        let analyzer = job.analyzer.clone();
        handles.push(thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                loop {
                    check_geobase_job(&cancel, deadline)?;
                    let current = index.fetch_add(1, Ordering::Relaxed);
                    let Some(domain) = domains.get(current) else {
                        break;
                    };
                    #[cfg(test)]
                    let classification = if let Some(analyzer) = &analyzer {
                        analyzer(domain)
                    } else {
                        classify_geobase_domain(&cancel, deadline, controller.as_ref(), domain)?
                    };
                    #[cfg(not(test))]
                    let classification =
                        classify_geobase_domain(&cancel, deadline, controller.as_ref(), domain)?;
                    lock(&results).push(DomainClassification {
                        domain: domain.clone(),
                        classification,
                    });
                    update_geobase_status(&daemon, job_id, |status| {
                        status.completed += 1;
                        status.progress_percent = status
                            .completed
                            .saturating_mul(100)
                            .checked_div(status.total)
                            .map_or(100, |percent| percent.min(100) as u8);
                        match classification {
                            Classification::Direct => status.direct += 1,
                            Classification::Active => status.active += 1,
                            Classification::Unresolved => status.unresolved += 1,
                        }
                    });
                }
                Ok::<(), String>(())
            }));
            match result {
                Ok(result) => result,
                Err(payload) => Err(panic_message(payload)),
            }
        }));
    }
    let mut errors = Vec::new();
    for handle in handles {
        match handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => errors.push(error),
            Err(payload) => errors.push(panic_message(payload)),
        }
    }
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    check_geobase_job(cancel, deadline)?;
    let mut output = lock(&results).clone();
    output.sort_by(|left, right| left.domain.cmp(&right.domain));
    Ok(output)
}

fn classify_geobase_domain(
    cancel: &AtomicBool,
    deadline: Instant,
    controller: Option<&(String, Option<String>)>,
    domain: &str,
) -> Result<Classification, String> {
    let candidate = AutoVpnCandidate {
        domain: domain.to_owned(),
        port: None,
    };
    if probe_geobase_domain_direct(domain, cancel, deadline)? {
        return Ok(Classification::Direct);
    }
    check_geobase_job(cancel, deadline)?;
    if match controller {
        Some((addr, secret)) => {
            proxy_geobase_domain_reachable(addr, secret.as_deref(), &candidate, cancel, deadline)?
        }
        None => false,
    } {
        Ok(Classification::Active)
    } else {
        Ok(Classification::Unresolved)
    }
}

fn probe_geobase_domain_direct(
    domain: &str,
    cancel: &AtomicBool,
    deadline: Instant,
) -> Result<bool, String> {
    let addresses = match resolve_public_addrs_bounded(domain, 443, cancel, deadline) {
        Ok(addresses) => addresses,
        Err(error) if is_systemic_geobase_probe_error(&error) => return Err(error),
        Err(_) => return Ok(false),
    };
    if addresses.is_empty() || addresses.iter().any(|address| !is_public_ip(address.ip())) {
        return Ok(false);
    }
    for attempt in 0..2 {
        check_geobase_job(cancel, deadline)?;
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .connect_timeout(GEOBASE_PROBE_TIMEOUT)
            .timeout(GEOBASE_PROBE_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(domain, &addresses)
            .build()
            .map_err(|error| format!("GeoBase probe client: {error}"))?;
        if let Ok(response) = client.get(format!("https://{domain}/")).send() {
            let status = response.status().as_u16();
            if status < 500 && status != 451 {
                return Ok(true);
            }
        }
        if attempt == 0 {
            check_geobase_job(cancel, deadline)?;
            thread::sleep(Duration::from_millis(150));
        }
    }
    Ok(false)
}

fn is_systemic_geobase_probe_error(error: &str) -> bool {
    error == "cancelled"
        || error == "GeoBase job exceeded 30 minute deadline"
        || error.starts_with("GeoBase probe client:")
}

fn proxy_geobase_domain_reachable(
    addr: &str,
    secret: Option<&str>,
    candidate: &AutoVpnCandidate,
    cancel: &AtomicBool,
    deadline: Instant,
) -> Result<bool, String> {
    for url in auto_vpn_probe_urls(candidate) {
        check_geobase_job(cancel, deadline)?;
        if mihomo_api_delay(addr, secret, PROXY_ACTIVE_NAME, &url, 4000).is_ok() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn check_geobase_job(cancel: &AtomicBool, deadline: Instant) -> Result<(), String> {
    if cancel.load(Ordering::Acquire) {
        Err("cancelled".to_owned())
    } else if Instant::now() >= deadline {
        Err("GeoBase job exceeded 30 minute deadline".to_owned())
    } else {
        Ok(())
    }
}

fn download_geobase_url(
    url: &str,
    source_proxy_url: Option<&str>,
    cancel: &AtomicBool,
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let mut current = url::Url::parse(url).map_err(|error| format!("invalid URL: {error}"))?;
    for redirects in 0..=5 {
        check_geobase_job(cancel, deadline)?;
        let (host, addresses) = resolve_geobase_url(&current, cancel, deadline)?;
        // Pin this request to the validated DNS answers. This closes the
        // validation/request DNS-rebinding window while preserving TLS SNI.
        let direct_client = reqwest::blocking::Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(&host, &addresses)
            .build()
            .map_err(|error| format!("client build: {error}"))?;
        check_geobase_job(cancel, deadline)?;
        let mut response = request_geobase_hop(source_proxy_url, |transport| match transport {
            GeoBaseTransport::Direct => direct_client
                .get(current.clone())
                .send()
                .map_err(|error| format!("download {}: {error}", current)),
            GeoBaseTransport::Socks5h(proxy_url) => geobase_proxy_client(proxy_url)?
                .get(current.clone())
                .send()
                .map_err(|error| format!("download {}: {error}", current)),
        })?;
        if response.status().is_redirection() {
            if redirects == 5 {
                return Err("GeoBase URL exceeds 5 redirects".to_owned());
            }
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .ok_or_else(|| "redirect has no Location header".to_owned())?
                .to_str()
                .map_err(|_| "redirect Location is not valid text".to_owned())?;
            let next = current
                .join(location)
                .map_err(|error| format!("invalid redirect URL: {error}"))?;
            resolve_geobase_url(&next, cancel, deadline)?;
            current = next;
            continue;
        }
        if !response.status().is_success() {
            return Err(format!(
                "GeoBase download returned HTTP {}",
                response.status()
            ));
        }
        if response
            .content_length()
            .is_some_and(|length| length > geobase::MAX_SOURCE_BYTES as u64)
        {
            return Err("GeoBase source exceeds 8 MiB".to_owned());
        }
        let mut body = Vec::new();
        let mut chunk = [0u8; 16 * 1024];
        loop {
            check_geobase_job(cancel, deadline)?;
            let read = response
                .read(&mut chunk)
                .map_err(|error| error.to_string())?;
            if read == 0 {
                std::str::from_utf8(&body)
                    .map_err(|_| "GeoBase HTTP body must be valid UTF-8".to_owned())?;
                return Ok(body);
            }
            if body.len() + read > geobase::MAX_SOURCE_BYTES {
                return Err("GeoBase source exceeds 8 MiB".to_owned());
            }
            body.extend_from_slice(&chunk[..read]);
        }
    }
    unreachable!()
}

fn geobase_proxy_client(proxy_url: &str) -> Result<reqwest::blocking::Client, String> {
    let proxy = reqwest::Proxy::all(proxy_url).map_err(|error| format!("proxy setup: {error}"))?;
    reqwest::blocking::Client::builder()
        .proxy(proxy)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| format!("proxy client build: {error}"))
}

#[derive(Clone, Copy)]
enum GeoBaseTransport<'a> {
    Direct,
    Socks5h(&'a str),
}

fn request_geobase_hop<T>(
    source_proxy_url: Option<&str>,
    mut request: impl FnMut(GeoBaseTransport<'_>) -> Result<T, String>,
) -> Result<T, String> {
    match request(GeoBaseTransport::Direct) {
        Ok(response) => Ok(response),
        Err(direct_error) => {
            let Some(proxy_url) = source_proxy_url else {
                return Err(direct_error);
            };
            request(GeoBaseTransport::Socks5h(proxy_url))
                .map_err(|proxy_error| format!("[direct] {direct_error}; [socks5h] {proxy_error}"))
        }
    }
}

#[cfg(test)]
fn validate_geobase_url(url: &url::Url) -> Result<(), String> {
    let cancel = AtomicBool::new(false);
    resolve_geobase_url(url, &cancel, Instant::now() + GEOBASE_DNS_TIMEOUT).map(|_| ())
}

fn resolve_geobase_url(
    url: &url::Url,
    cancel: &AtomicBool,
    deadline: Instant,
) -> Result<(String, Vec<std::net::SocketAddr>), String> {
    if url.scheme() != "https" {
        return Err("GeoBase URL must use HTTPS".to_owned());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("GeoBase URL must not contain credentials".to_owned());
    }
    let host = url
        .host_str()
        .ok_or_else(|| "GeoBase URL has no host".to_owned())?;
    let port = url.port_or_known_default().unwrap_or(443);
    let addresses = resolve_public_addrs_bounded(host, port, cancel, deadline)?;
    if addresses.is_empty() || addresses.iter().any(|address| !is_public_ip(address.ip())) {
        return Err(format!(
            "GeoBase URL host {host} resolves to a non-public address"
        ));
    }
    Ok((host.to_owned(), addresses))
}

fn resolve_public_addrs_bounded(
    host: &str,
    port: u16,
    cancel: &AtomicBool,
    deadline: Instant,
) -> Result<Vec<std::net::SocketAddr>, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![std::net::SocketAddr::new(ip, port)]);
    }
    let host_owned = host.to_owned();
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let result = (host_owned.as_str(), port)
            .to_socket_addrs()
            .map(|addresses| addresses.collect::<Vec<_>>())
            .map_err(|error| error.to_string());
        let _ = sender.send(result);
    });
    let dns_deadline = deadline.min(Instant::now() + GEOBASE_DNS_TIMEOUT);
    loop {
        check_geobase_job(cancel, deadline)?;
        let remaining = dns_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(format!("DNS lookup timed out for {host}"));
        }
        let wait = remaining.min(Duration::from_millis(50));
        match receiver.recv_timeout(wait) {
            Ok(result) => {
                return result.map_err(|error| format!("DNS lookup failed for {host}: {error}"));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(format!("DNS lookup worker failed for {host}"));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
}

fn cancel_and_join_geobase(daemon: &Daemon) {
    let handle = {
        let mut inner = lock(&daemon.inner);
        if let Some(cancel) = inner.geobase.cancel.as_ref() {
            cancel.store(true, Ordering::Release);
        }
        inner.geobase.handle.take()
    };
    if let Some(handle) = handle
        && let Err(payload) = handle.join()
    {
        eprintln!("hincyray: {}", panic_message(payload));
    }
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let value = u32::from(ip);
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && !ip.is_unspecified()
                && !ip.is_broadcast()
                && ip.octets()[0] < 224
                && value & 0xff00_0000 != u32::from(Ipv4Addr::new(0, 0, 0, 0))
                && value & 0xffc0_0000 != u32::from(Ipv4Addr::new(100, 64, 0, 0))
                && value & 0xffff_ff00 != u32::from(Ipv4Addr::new(192, 0, 0, 0))
                && value & 0xffff_ff00 != u32::from(Ipv4Addr::new(192, 0, 2, 0))
                && value & 0xfffe_0000 != u32::from(Ipv4Addr::new(198, 18, 0, 0))
                && value & 0xffff_ff00 != u32::from(Ipv4Addr::new(198, 51, 100, 0))
                && value & 0xffff_ff00 != u32::from(Ipv4Addr::new(203, 0, 113, 0))
        }
        IpAddr::V6(ip) => {
            let global_unicast = ip.segments()[0] & 0xe000 == 0x2000;
            global_unicast
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !ip.is_unspecified()
                && !ip.is_unique_local()
                && !ip.is_unicast_link_local()
                && !is_ipv6_documentation(ip)
                && ip
                    .to_ipv4_mapped()
                    .is_none_or(|mapped| is_public_ip(IpAddr::V4(mapped)))
        }
    }
}

fn is_ipv6_documentation(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] == 0x2001 && segments[1] == 0x0db8
}

fn socks_client(socks_url: &str, timeout: Duration) -> Result<reqwest::blocking::Client, String> {
    let proxy = reqwest::Proxy::all(socks_url).map_err(|e| format!("proxy setup: {e}"))?;
    reqwest::blocking::Client::builder()
        .proxy(proxy)
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| format!("client build: {e}"))
}

fn handle_substore_lite_get(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    (
        200,
        "application/json",
        json!({"settings": inner.state.sub_store_lite}).to_string(),
    )
}

fn handle_substore_lite_set(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let Ok(settings) = serde_json::from_str::<SubStoreLiteSettings>(body) else {
        return (
            400,
            "application/json",
            json!({"error": "invalid SubStoreLiteSettings JSON"}).to_string(),
        );
    };
    let mut inner = lock(&daemon.inner);
    inner.state.sub_store_lite = settings;
    let _ = persist_state(&daemon.state_path, &inner.state);
    (
        200,
        "application/json",
        json!({"settings": inner.state.sub_store_lite}).to_string(),
    )
}

fn handle_substore_lite_apply(daemon: &Daemon) -> (u16, &'static str, String) {
    let mut inner = lock(&daemon.inner);
    let _ = create_state_backup(&daemon.state_path, &inner.state, "pre-substore");
    let before = inner.state.profiles.len();
    let report = apply_substore_lite(&mut inner.state);
    reassign_profile_ids(&mut inner.state.profiles);
    let after = inner.state.profiles.len();
    inner.state.sub_store_lite.last_applied_unix = unix_now();
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
        json!({"before": before, "after": after, "report": report}).to_string(),
    )
}

fn apply_substore_lite(state: &mut HincyrayState) -> Value {
    let settings = state.sub_store_lite.clone();
    let mut renamed = 0usize;
    let mut filtered = 0usize;
    let mut deduped = 0usize;

    for profile in &mut state.profiles {
        for rule in &settings.rename_rules {
            if !rule.from.is_empty() && profile.name.contains(&rule.from) {
                profile.name = profile.name.replace(&rule.from, &rule.to);
                renamed += 1;
            }
        }
    }

    let include_filter = settings.include_filter.clone();
    let exclude_filter = settings.exclude_filter.clone();
    state.profiles.retain(|profile| {
        let text = profile_search_text(profile);
        let include_ok =
            filter_is_empty(&include_filter) || text_matches_filter(&text, &include_filter);
        let exclude_ok =
            filter_is_empty(&exclude_filter) || !text_matches_filter(&text, &exclude_filter);
        let keep = include_ok && exclude_ok;
        if !keep {
            filtered += 1;
        }
        keep
    });

    if settings.deduplicate {
        let mut seen = HashSet::new();
        state.profiles.retain(|profile| {
            let key = profile_identity(profile);
            let keep = seen.insert(key);
            if !keep {
                deduped += 1;
            }
            keep
        });
    }

    prune_stale_profile_stats(state);
    sort_profiles_for_substore(&mut state.profiles, &state.stats, &settings.sort_by);
    json!({"renamed": renamed, "filtered": filtered, "deduplicated": deduped, "sort_by": settings.sort_by})
}

fn profile_search_text(profile: &Profile) -> String {
    format!(
        "{} {} {} {} {}",
        profile.name,
        profile.protocol,
        profile.address,
        profile.port.map(|p| p.to_string()).unwrap_or_default(),
        profile.group.clone().unwrap_or_default()
    )
    .to_ascii_lowercase()
}

fn filter_is_empty(filter: &str) -> bool {
    filter.split('|').all(|part| part.trim().is_empty())
}

fn text_matches_filter(text: &str, filter: &str) -> bool {
    let low = text.to_ascii_lowercase();
    filter
        .split('|')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .any(|part| low.contains(&part.to_ascii_lowercase()))
}

fn profile_identity(profile: &Profile) -> String {
    format!(
        "{}|{}|{}",
        profile.protocol,
        profile.address,
        profile.port.unwrap_or(0)
    )
}

fn sort_profiles_for_substore(profiles: &mut [Profile], stats: &[ProfileStats], sort_by: &str) {
    let stat_map: HashMap<String, ProfileStats> = stats
        .iter()
        .map(|stat| (stat.profile_raw.clone(), stat.clone()))
        .collect();
    match sort_by {
        "latency" => profiles.sort_by(|a, b| {
            let la = stat_map
                .get(&a.raw)
                .map(|s| s.last_latency_ms)
                .unwrap_or(u32::MAX);
            let lb = stat_map
                .get(&b.raw)
                .map(|s| s.last_latency_ms)
                .unwrap_or(u32::MAX);
            la.cmp(&lb).then_with(|| a.name.cmp(&b.name))
        }),
        "group" => profiles.sort_by(|a, b| a.group.cmp(&b.group).then_with(|| a.name.cmp(&b.name))),
        "protocol" => profiles.sort_by(|a, b| {
            a.protocol
                .to_string()
                .cmp(&b.protocol.to_string())
                .then_with(|| a.name.cmp(&b.name))
        }),
        "address" => {
            profiles.sort_by(|a, b| a.address.cmp(&b.address).then_with(|| a.name.cmp(&b.name)))
        }
        _ => profiles.sort_by(|a, b| a.name.cmp(&b.name)),
    }
}

fn reassign_profile_ids(profiles: &mut [Profile]) {
    for (idx, profile) in profiles.iter_mut().enumerate() {
        profile.id = idx;
    }
}

fn handle_dns_diagnostics(daemon: &Daemon) -> (u16, &'static str, String) {
    let (split_enabled, dns_port, ec, socks_port, core_running) = {
        let mut inner = lock(&daemon.inner);
        (
            inner.state.split_routing.enabled,
            1053u16,
            mihomo_controller(&inner.state.mihomo_features),
            inner.state.socks_port,
            inner.core.is_running(),
        )
    };
    let local_dns = dns_query_tcp("127.0.0.1", dns_port, "example.com");
    let direct_dns = run_nslookup("example.com", None);
    let mihomo_query = ec.as_ref().map(|(addr, secret)| {
        mihomo_api_get_json(
            addr,
            secret.as_deref(),
            "/dns/query?name=example.com&type=A",
        )
    });
    let proxy_trace = if core_running {
        Command::new("curl")
            .args([
                "-s",
                "--max-time",
                "8",
                "--socks5-hostname",
                &format!("127.0.0.1:{socks_port}"),
                "https://1.1.1.1/cdn-cgi/trace",
            ])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default()
    } else {
        String::new()
    };
    (
        200,
        "application/json",
        json!({
            "split_routing_enabled": split_enabled,
            "dns_listener_port": dns_port,
            "local_dns": local_dns,
            "direct_dns": direct_dns,
            "mihomo_dns_query": match mihomo_query {
                Some(Ok(v)) => json!({"ok": true, "response": v}),
                Some(Err(e)) => json!({"ok": false, "error": e}),
                None => json!({"ok": false, "error": "external controller disabled"}),
            },
            "proxy_trace_sample": proxy_trace.lines().take(12).collect::<Vec<_>>(),
        })
        .to_string(),
    )
}

fn handle_dns_diagnostics_v2(daemon: &Daemon) -> (u16, &'static str, String) {
    let (split_enabled, dns_port, ec, core_running, remote_servers, local_servers) = {
        let mut inner = lock(&daemon.inner);
        (
            inner.state.split_routing.enabled,
            1053u16,
            mihomo_controller(&inner.state.mihomo_features),
            inner.core.is_running(),
            inner.state.dns_settings.remote_servers.clone(),
            inner.state.dns_settings.local_servers.clone(),
        )
    };
    let local_tcp = dns_query_tcp("127.0.0.1", dns_port, "example.com");
    let local_google = dns_query_tcp("127.0.0.1", dns_port, "google.com");
    let mihomo_query = ec.as_ref().map(|(addr, secret)| {
        mihomo_api_get_json(
            addr,
            secret.as_deref(),
            "/dns/query?name=example.com&type=A",
        )
    });
    let verdict_ok = local_tcp
        .get("ok")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    (
        200,
        "application/json",
        json!({
            "ok": verdict_ok,
            "summary": if verdict_ok { "Mihomo DNS TCP listener answered" } else { "Mihomo DNS TCP listener did not answer" },
            "split_routing_enabled": split_enabled,
            "core_running": core_running,
            "dns_listener": {"host": "127.0.0.1", "port": dns_port, "tcp_example": local_tcp, "tcp_google": local_google},
            "configured_servers": {"remote": remote_servers, "local": local_servers},
            "mihomo_dns_query": match mihomo_query {
                Some(Ok(v)) => json!({"ok": true, "response": v}),
                Some(Err(e)) => json!({"ok": false, "error": e}),
                None => json!({"ok": false, "error": "external controller disabled"}),
            },
            "hints": [
                "DNS is always enabled in router mode because firewall DNATs DNS to 127.0.0.1:1053",
                "If local TCP DNS fails, validate Mihomo config and core logs before changing rules"
            ],
        })
        .to_string(),
    )
}

fn handle_udp_quic_diagnostics(daemon: &Daemon) -> (u16, &'static str, String) {
    let (split, firewall_active, tproxy_available, core_running) = {
        let mut inner = lock(&daemon.inner);
        (
            inner.state.split_routing.clone(),
            inner.firewall.is_running(),
            inner.firewall.tproxy_available,
            inner.core.is_running(),
        )
    };
    let modules = ["xt_TPROXY", "xt_socket", "xt_comment"]
        .into_iter()
        .map(|name| json!({"name": name, "loaded": kernel_module_loaded(name)}))
        .collect::<Vec<_>>();
    let nat_rules = command_json("iptables", &["-t", "nat", "-S"]);
    let mangle_rules = command_json("iptables", &["-t", "mangle", "-S"]);
    let ip_rules = command_json("ip", &["rule", "show"]);
    let verdict_ok = split.enabled
        && firewall_active
        && (tproxy_available || split.quic_mode == QuicMode::Block);
    (
        200,
        "application/json",
        json!({
            "ok": verdict_ok,
            "summary": if verdict_ok { "UDP/QUIC path is consistent with current routing mode" } else { "UDP/QUIC path needs attention" },
            "split_routing_enabled": split.enabled,
            "core_running": core_running,
            "firewall_active": firewall_active,
            "redirect_port_tcp": split.redirect_port,
            "tproxy_port_udp": split.redirect_port + 1,
            "tproxy_available": tproxy_available,
            "quic_mode": format!("{:?}", split.quic_mode),
            "modules": modules,
            "iptables": {"nat": nat_rules, "mangle": mangle_rules},
            "policy_routing": ip_rules,
        })
        .to_string(),
    )
}

fn command_json(program: &str, args: &[&str]) -> Value {
    match Command::new(program).args(args).output() {
        Ok(output) => json!({
            "ok": output.status.success(),
            "exit_code": output.status.code(),
            "stdout": String::from_utf8_lossy(&output.stdout).trim(),
            "stderr": String::from_utf8_lossy(&output.stderr).trim(),
        }),
        Err(error) => json!({"ok": false, "error": error.to_string()}),
    }
}

fn run_nslookup(host: &str, server: Option<(&str, u16)>) -> Value {
    let mut cmd = Command::new("nslookup");
    cmd.arg(host);
    if let Some((addr, port)) = server {
        cmd.arg(format!("{addr}#{port}"));
    }
    match cmd.output() {
        Ok(output) => json!({
            "ok": output.status.success(),
            "stdout": String::from_utf8_lossy(&output.stdout).trim(),
            "stderr": String::from_utf8_lossy(&output.stderr).trim(),
        }),
        Err(error) => json!({"ok": false, "error": error.to_string()}),
    }
}

/// Build a minimal DNS A-record query message (RFC 1035 §4.1).
fn build_dns_a_query(name: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(32);
    // Header: id=1, flags=0x0100 (RD), qdcount=1, others=0
    q.extend_from_slice(&[
        0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    // Question: encode domain name as labels
    for label in name.split('.') {
        let l = label.len();
        if l > 63 {
            break;
        }
        q.push(l as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0); // root label
    q.extend_from_slice(&[0x00, 0x01]); // Type A
    q.extend_from_slice(&[0x00, 0x01]); // Class IN
    q
}

/// Parse a DNS response message, extracting A-record IPs and status.
fn parse_dns_a_response(resp: &[u8]) -> Value {
    if resp.len() < 12 {
        return json!({"ok": false, "error": "response too short"});
    }
    let rcode = u16::from_be_bytes([resp[2], resp[3]]) & 0x000f;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    // Skip question section
    let mut pos = 12;
    while pos < resp.len() {
        let b = resp[pos];
        if b == 0 {
            pos += 1;
            break;
        }
        if b & 0xc0 == 0xc0 {
            pos += 2; // compressed pointer
            break;
        }
        pos += b as usize + 1;
    }
    pos += 4; // Type + Class of question
    // Parse answer RRs
    let mut ips: Vec<String> = Vec::new();
    for _ in 0..ancount {
        if pos >= resp.len() {
            break;
        }
        // Skip name (possibly compressed)
        if resp[pos] & 0xc0 == 0xc0 {
            pos += 2;
        } else {
            while pos < resp.len() && resp[pos] != 0 {
                pos += resp[pos] as usize + 1;
            }
            pos += 1;
        }
        if pos + 10 > resp.len() {
            break;
        }
        let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        pos += 8; // Type(2) + Class(2) + TTL(4)
        let rdlen = u16::from_be_bytes([resp[pos], resp[pos + 1]]) as usize;
        pos += 2;
        if rtype == 1 && rdlen == 4 && pos + 4 <= resp.len() {
            ips.push(format!(
                "{}.{}.{}.{}",
                resp[pos],
                resp[pos + 1],
                resp[pos + 2],
                resp[pos + 3]
            ));
        }
        pos += rdlen;
    }
    json!({
        "ok": rcode == 0,
        "rcode": rcode,
        "answer_count": ancount,
        "ips": ips,
    })
}

/// Send a DNS A-record query over TCP (RFC 7766) and parse the response.
/// Works on any platform — no external tools needed.
fn dns_query_tcp(host: &str, port: u16, name: &str) -> Value {
    let query = build_dns_a_query(name);
    // TCP DNS: 2-byte big-endian length prefix
    let len = query.len() as u16;
    let mut packet = Vec::with_capacity(query.len() + 2);
    packet.extend_from_slice(&len.to_be_bytes());
    packet.extend_from_slice(&query);

    use std::io::{Read, Write};
    let addr: std::net::Ipv4Addr = match host.parse() {
        Ok(a) => a,
        Err(_) => std::net::Ipv4Addr::UNSPECIFIED,
    };
    let mut stream = match std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from((std::net::IpAddr::V4(addr), port)),
        std::time::Duration::from_secs(3),
    ) {
        Ok(s) => s,
        Err(e) => {
            return json!({"ok": false, "error": format!("connect: {e}")});
        }
    };
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
    if let Err(e) = stream.write_all(&packet) {
        return json!({"ok": false, "error": format!("write: {e}")});
    }
    let mut len_buf = [0u8; 2];
    if let Err(e) = stream.read_exact(&mut len_buf) {
        return json!({"ok": false, "error": format!("read length: {e}")});
    }
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if resp_len > 4096 {
        return json!({"ok": false, "error": "response too large"});
    }
    let mut resp = vec![0u8; resp_len];
    if let Err(e) = stream.read_exact(&mut resp) {
        return json!({"ok": false, "error": format!("read body: {e}")});
    }
    parse_dns_a_response(&resp)
}

fn handle_backups_list(daemon: &Daemon) -> (u16, &'static str, String) {
    match list_state_backups(&daemon.state_path) {
        Ok(backups) => (
            200,
            "application/json",
            json!({"backups": backups}).to_string(),
        ),
        Err(error) => (500, "application/json", json!({"error": error}).to_string()),
    }
}

fn handle_backup_create(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    match create_state_backup(&daemon.state_path, &inner.state, "manual") {
        Ok(path) => (
            200,
            "application/json",
            json!({"created": path.file_name().and_then(|s| s.to_str()).unwrap_or("")}).to_string(),
        ),
        Err(error) => (500, "application/json", json!({"error": error}).to_string()),
    }
}

fn handle_backup_restore(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return (
            400,
            "application/json",
            json!({"error": "invalid JSON body"}).to_string(),
        );
    };
    let Some(file) = value.get("file").and_then(Value::as_str) else {
        return (
            400,
            "application/json",
            json!({"error": "missing file"}).to_string(),
        );
    };
    let backup = match backup_path_by_name(&daemon.state_path, file) {
        Ok(path) => path,
        Err(error) => return (400, "application/json", json!({"error": error}).to_string()),
    };
    let text = match fs::read_to_string(&backup) {
        Ok(text) => text,
        Err(error) => {
            return (
                500,
                "application/json",
                json!({"error": format!("read backup: {error}")}).to_string(),
            );
        }
    };
    let mut restored: HincyrayState = match deserialize_persisted_state(&text) {
        Ok(state) => state,
        Err(error) => {
            return (
                400,
                "application/json",
                json!({"error": format!("invalid backup state: {error}")}).to_string(),
            );
        }
    };
    if restored.split_routing.enabled {
        restored.dns_settings.enabled = true;
    }
    let mut inner = lock(&daemon.inner);
    let was_running = inner.core.is_running();
    let _ = create_state_backup(&daemon.state_path, &inner.state, "pre-restore");
    inner.state = restored;
    inner.sessions.clear();
    if let Err(error) = persist_state(&daemon.state_path, &inner.state) {
        return (
            500,
            "application/json",
            json!({"error": format!("persist restored state: {error}")}).to_string(),
        );
    }
    let restart = if was_running {
        restart_core_locked(&mut inner, daemon).map(|()| inner.core.status().to_owned())
    } else {
        regenerate_config(&inner.state, daemon).map(|_| inner.core.status().to_owned())
    };
    match restart {
        Ok(core_status) => (
            200,
            "application/json",
            json!({"restored": file, "core_status": core_status}).to_string(),
        ),
        Err(error) => (
            500,
            "application/json",
            json!({"restored": file, "error": error}).to_string(),
        ),
    }
}

fn handle_backup_delete(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let file = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v.get("file").and_then(Value::as_str).map(str::to_owned));
    let Some(file) = file else {
        return (
            400,
            "application/json",
            json!({"error": "missing file"}).to_string(),
        );
    };
    let path = match backup_path_by_name(&daemon.state_path, &file) {
        Ok(path) => path,
        Err(error) => return (400, "application/json", json!({"error": error}).to_string()),
    };
    match fs::remove_file(&path) {
        Ok(()) => (
            200,
            "application/json",
            json!({"deleted": file}).to_string(),
        ),
        Err(error) => (
            500,
            "application/json",
            json!({"error": error.to_string()}).to_string(),
        ),
    }
}

fn handle_backup_webdav_upload(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
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
    let inner = lock(&daemon.inner);
    let state_json = match serde_json::to_string_pretty(&inner.state) {
        Ok(text) => text,
        Err(error) => {
            return (
                500,
                "application/json",
                json!({"error": error.to_string()}).to_string(),
            );
        }
    };
    drop(inner);
    match webdav_put(
        url,
        value.get("username").and_then(Value::as_str),
        value.get("password").and_then(Value::as_str),
        state_json,
    ) {
        Ok(status) => (
            200,
            "application/json",
            json!({"uploaded": true, "status": status}).to_string(),
        ),
        Err(error) => (502, "application/json", json!({"error": error}).to_string()),
    }
}

fn handle_backup_webdav_download(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
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
    match webdav_get(
        url,
        value.get("username").and_then(Value::as_str),
        value.get("password").and_then(Value::as_str),
    ) {
        Ok(text) => {
            let mut restored: HincyrayState = match deserialize_persisted_state(&text) {
                Ok(state) => state,
                Err(error) => {
                    return (
                        400,
                        "application/json",
                        json!({"error": format!("invalid downloaded state: {error}")}).to_string(),
                    );
                }
            };
            if restored.split_routing.enabled {
                restored.dns_settings.enabled = true;
            }
            let mut inner = lock(&daemon.inner);
            let was_running = inner.core.is_running();
            let _ = create_state_backup(&daemon.state_path, &inner.state, "pre-webdav-restore");
            inner.state = restored;
            inner.sessions.clear();
            let _ = persist_state(&daemon.state_path, &inner.state);
            if was_running {
                let _ = restart_core_locked(&mut inner, daemon);
            } else {
                let _ = regenerate_config(&inner.state, daemon);
            }
            (
                200,
                "application/json",
                json!({"downloaded": true}).to_string(),
            )
        }
        Err(error) => (502, "application/json", json!({"error": error}).to_string()),
    }
}

fn backup_dir(state_path: &Path) -> PathBuf {
    state_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("backups")
}

fn create_state_backup(
    state_path: &Path,
    state: &HincyrayState,
    reason: &str,
) -> Result<PathBuf, String> {
    let dir = backup_dir(state_path);
    fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    let safe_reason: String = reason
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let path = dir.join(format!("state-{}-{safe_reason}.json", unix_now()));
    let text = serde_json::to_string_pretty(state).map_err(|e| e.to_string())?;
    fs::write(&path, text).map_err(|e| format!("write {}: {e}", path.display()))?;
    prune_state_backups(state_path, MAX_BACKUPS)?;
    Ok(path)
}

fn list_state_backups(state_path: &Path) -> Result<Vec<Value>, String> {
    let dir = backup_dir(state_path);
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for entry in fs::read_dir(&dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let meta = entry.metadata().map_err(|e| e.to_string())?;
        entries.push(json!({
            "file": path.file_name().and_then(|s| s.to_str()).unwrap_or(""),
            "bytes": meta.len(),
            "modified_unix": meta.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0),
        }));
    }
    entries.sort_by(|a, b| {
        b.get("modified_unix")
            .and_then(Value::as_u64)
            .cmp(&a.get("modified_unix").and_then(Value::as_u64))
    });
    Ok(entries)
}

fn prune_state_backups(state_path: &Path, keep: usize) -> Result<(), String> {
    let backups = list_state_backups(state_path)?;
    for backup in backups.into_iter().skip(keep) {
        if let Some(file) = backup.get("file").and_then(Value::as_str)
            && let Ok(path) = backup_path_by_name(state_path, file)
        {
            let _ = fs::remove_file(path);
        }
    }
    Ok(())
}

fn backup_path_by_name(state_path: &Path, file: &str) -> Result<PathBuf, String> {
    if file.contains('/') || file.contains('\\') || file == "." || file == ".." {
        return Err("invalid backup file name".to_owned());
    }
    let path = backup_dir(state_path).join(file);
    if path.extension().and_then(|s| s.to_str()) != Some("json") {
        return Err("backup file must be .json".to_owned());
    }
    Ok(path)
}

fn webdav_put(
    url: &str,
    username: Option<&str>,
    password: Option<&str>,
    body: String,
) -> Result<u16, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;
    let mut req = client.put(url).body(body);
    if let Some(user) = username
        && !user.is_empty()
    {
        req = req.basic_auth(user, password.map(str::to_owned));
    }
    let resp = req.send().map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    if resp.status().is_success() {
        Ok(status)
    } else {
        Err(format!("WebDAV PUT HTTP {status}"))
    }
}

fn webdav_get(url: &str, username: Option<&str>, password: Option<&str>) -> Result<String, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;
    let mut req = client.get(url);
    if let Some(user) = username
        && !user.is_empty()
    {
        req = req.basic_auth(user, password.map(str::to_owned));
    }
    let resp = req.send().map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("WebDAV GET HTTP {}", resp.status()));
    }
    resp.text().map_err(|e| e.to_string())
}

fn restart_core_locked(inner: &mut MutexGuard<DaemonInner>, daemon: &Daemon) -> Result<(), String> {
    let geo_dir = geo_dir_from_state(&inner.state);
    let (binary_path, config_path) = regenerate_config(&inner.state, daemon)?;
    inner
        .core
        .restart(&binary_path, &config_path, geo_dir.as_deref())
}

/// Authenticate a user and return a bounded-lifetime cryptographic session.
fn handle_auth_login(body: &str, daemon: &Daemon, peer_ip: IpAddr) -> (u16, &'static str, String) {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return (
            400,
            "application/json",
            json!({"error": "invalid JSON body"}).to_string(),
        );
    };
    let username = value.get("username").and_then(Value::as_str).unwrap_or("");
    let password = value.get("password").and_then(Value::as_str).unwrap_or("");

    let now = unix_now();
    let password_permit = match daemon.password_work.try_acquire() {
        Some(permit) => permit,
        None => {
            return (
                503,
                "application/json",
                json!({"error": "password verification capacity exhausted", "retry_after_seconds": 1})
                    .to_string(),
            );
        }
    };
    let (expected_username, password_hash, reservation) = {
        let mut inner = lock(&daemon.inner);
        if !inner.state.web_ui_auth.enabled {
            return (
                200,
                "application/json",
                json!({"token": null, "auth_enabled": false}).to_string(),
            );
        }
        let reservation = match inner.login_limiter.reserve_attempt(peer_ip, now) {
            Ok(reservation) => reservation,
            Err(retry_after) => {
                return (
                    429,
                    "application/json",
                    json!({"error": "too many login attempts", "retry_after_seconds": retry_after})
                        .to_string(),
                );
            }
        };
        (
            inner.state.web_ui_auth.username.clone(),
            inner.state.web_ui_auth.password_hash.clone(),
            reservation,
        )
    };

    let password_valid =
        verify_password_with_permit(password, &password_hash, password_permit).unwrap_or(false);
    let credentials_valid = username == expected_username && password_valid;
    if !credentials_valid {
        return (
            401,
            "application/json",
            json!({
                "error": "invalid credentials",
                "retry_after_seconds": reservation.retry_after_on_failure()
            })
            .to_string(),
        );
    }

    let token = match generate_session_token() {
        Ok(token) => token,
        Err(error) => return json_error(500, &error),
    };
    let mut inner = lock(&daemon.inner);
    inner.login_limiter.record_success(peer_ip);
    inner.sessions.retain(|_, session| !session.is_expired(now));
    if inner.sessions.len() >= MAX_WEB_SESSIONS
        && let Some(oldest) = inner
            .sessions
            .iter()
            .min_by_key(|(_, session)| session.created_at_unix)
            .map(|(token, _)| token.clone())
    {
        inner.sessions.remove(&oldest);
    }
    let session = WebSession::new(now);
    let expires_at = session.expires_at_unix;
    inner.sessions.insert(token.clone(), session);
    (
        200,
        "application/json",
        json!({
            "token": token,
            "auth_enabled": true,
            "expires_at_unix": expires_at,
        })
        .to_string(),
    )
}

/// v0.13: Invalidate a session token.
fn handle_auth_logout(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let token = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v.get("token").and_then(Value::as_str).map(str::to_owned));
    if let Some(token) = token {
        let mut inner = lock(&daemon.inner);
        inner.sessions.remove(&token);
    }
    (200, "application/json", json!({"ok": true}).to_string())
}

/// v0.13: Get current auth settings (password is never returned).
fn handle_auth_settings_get(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    let auth = &inner.state.web_ui_auth;
    (
        200,
        "application/json",
        json!({
            "enabled": auth.enabled,
            "username": auth.username,
            "password_set": auth.has_password(),
        })
        .to_string(),
    )
}

/// v0.13: Update auth settings (enable/disable, change username/password).
fn handle_auth_settings_set(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return (
            400,
            "application/json",
            json!({"error": "invalid JSON body"}).to_string(),
        );
    };
    let requested_password = value
        .get("password")
        .and_then(Value::as_str)
        .filter(|password| !password.is_empty());
    let password_hash = if let Some(password) = requested_password {
        let permit = match daemon.password_work.try_acquire() {
            Some(permit) => permit,
            None => {
                return (
                    503,
                    "application/json",
                    json!({"error": "password hashing capacity exhausted", "retry_after_seconds": 1})
                        .to_string(),
                );
            }
        };
        match hash_password_with_permit(password, permit) {
            Ok(hash) => Some(hash),
            Err(error) => return json_error(400, &error),
        }
    } else {
        None
    };
    let mut inner = lock(&daemon.inner);
    let mut invalidate_sessions = false;
    let requested_enabled = value.get("enabled").and_then(Value::as_bool);
    if let Some(username) = value.get("username").and_then(Value::as_str) {
        let username = username.trim();
        if !username.is_empty() {
            invalidate_sessions |= inner.state.web_ui_auth.username != username;
            inner.state.web_ui_auth.username = username.to_owned();
        }
    }
    if let Some(password_hash) = password_hash {
        inner.state.web_ui_auth.password_hash = password_hash;
        inner.state.web_ui_auth.password.clear();
        invalidate_sessions = true;
    }
    if requested_enabled == Some(true) && !inner.state.web_ui_auth.has_password() {
        return json_error(400, "cannot enable authentication without a password");
    }
    if let Some(enabled) = requested_enabled {
        invalidate_sessions |= inner.state.web_ui_auth.enabled != enabled;
        inner.state.web_ui_auth.enabled = enabled;
    }
    if invalidate_sessions {
        inner.sessions.clear();
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
        json!({
            "enabled": inner.state.web_ui_auth.enabled,
            "username": inner.state.web_ui_auth.username,
            "password_set": inner.state.web_ui_auth.has_password(),
        })
        .to_string(),
    )
}

/// Return the persisted connection log (most recent first).
fn handle_connection_log(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    let entries: Vec<Value> = inner
        .state
        .connection_log
        .iter()
        .rev()
        .map(|e| {
            json!({
                "timestamp": e.timestamp,
                "host": e.host,
                "source_ip": e.source_ip,
                "destination_ip": e.destination_ip,
                "network": e.network,
                "chains": e.chains,
                "rule": e.rule,
                "upload": e.upload,
                "download": e.download,
            })
        })
        .collect();
    (
        200,
        "application/json",
        json!({"entries": entries, "count": entries.len()}).to_string(),
    )
}

/// List all per-device routing rules.
fn handle_device_routes_list(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    let routes: Vec<Value> = inner
        .state
        .device_routes
        .iter()
        .map(|dr| {
            json!({
                "enabled": dr.enabled,
                "name": dr.name,
                "ip": dr.ip,
                "mac": dr.mac,
                "target": dr.target,
            })
        })
        .collect();
    (
        200,
        "application/json",
        json!({"routes": routes, "count": routes.len()}).to_string(),
    )
}

/// Add or update a per-device routing rule (upsert by IP).
/// Body: `{"enabled": true, "name": "Pixel 6a", "ip": "192.168.2.35", "mac": "aa:bb:cc:dd:ee:ff", "target": "direct"}`.
fn handle_device_routes_set(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return (
            400,
            "application/json",
            json!({"error": "invalid JSON body"}).to_string(),
        );
    };
    let Some(ip) = value.get("ip").and_then(Value::as_str) else {
        return (
            400,
            "application/json",
            json!({"error": "missing ip"}).to_string(),
        );
    };
    let ip = ip.trim().to_owned();
    if ip.is_empty() {
        return (
            400,
            "application/json",
            json!({"error": "ip cannot be empty"}).to_string(),
        );
    }

    let name = value
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let target = value
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or("active")
        .to_owned();
    let mac = value
        .get("mac")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let enabled = value
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    let mut inner = lock(&daemon.inner);
    let mut candidate = inner.state.clone();
    sync_server_route_registry(&mut candidate);
    // Upsert: find existing by IP, or push new.
    if let Some(existing) = candidate.device_routes.iter_mut().find(|dr| dr.ip == ip) {
        existing.enabled = enabled;
        existing.name = name.clone();
        existing.mac = mac.clone();
        existing.target = target.clone();
    } else {
        candidate.device_routes.push(DeviceRoute {
            enabled,
            name,
            ip,
            mac,
            target,
        });
    }

    if let Err(error) = validate_routing_targets(
        &candidate,
        &candidate.routing_rules,
        &candidate.device_routes,
    ) {
        return (400, "application/json", json!({"error": error}).to_string());
    }
    inner.state = candidate;

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
        json!({
            "routes": inner.state.device_routes.iter().map(|dr| {
                json!({
                    "enabled": dr.enabled,
                    "name": dr.name,
                    "ip": dr.ip,
                    "mac": dr.mac,
                    "target": dr.target,
                })
            }).collect::<Vec<_>>(),
            "count": inner.state.device_routes.len(),
        })
        .to_string(),
    )
}

/// Delete a per-device routing rule by IP.
/// Body: `{"ip": "192.168.2.35"}`.
fn handle_device_routes_delete(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return (
            400,
            "application/json",
            json!({"error": "invalid JSON body"}).to_string(),
        );
    };
    let Some(ip) = value.get("ip").and_then(Value::as_str) else {
        return (
            400,
            "application/json",
            json!({"error": "missing ip"}).to_string(),
        );
    };
    let ip = ip.trim();

    let mut inner = lock(&daemon.inner);
    let before = inner.state.device_routes.len();
    inner.state.device_routes.retain(|dr| dr.ip != ip);
    let after = inner.state.device_routes.len();

    if before == after {
        return (
            404,
            "application/json",
            json!({"error": "device route not found", "ip": ip}).to_string(),
        );
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
        json!({"deleted_ip": ip, "remaining": after}).to_string(),
    )
}

/// Scan for devices on the LAN by reading `/proc/net/arp`.
/// Returns a list of `{"ip", "mac", "iface"}` for all reachable devices.
fn handle_devices_scan(_daemon: &Daemon) -> (u16, &'static str, String) {
    let arp_content = fs::read_to_string("/proc/net/arp").unwrap_or_default();
    let mut devices: Vec<Value> = Vec::new();

    for line in arp_content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 6 {
            let ip = fields[0];
            let mac = fields[3];
            let iface = fields[5];
            // Skip entries with no MAC (incomplete ARP entries).
            if mac != "00:00:00:00:00:00" && !mac.is_empty() {
                devices.push(json!({
                    "ip": ip,
                    "mac": mac,
                    "iface": iface,
                }));
            }
        }
    }

    (
        200,
        "application/json",
        json!({"devices": devices, "count": devices.len()}).to_string(),
    )
}

/// Apply device routing changes: regenerate Mihomo config and restart core.
fn handle_device_routes_apply(daemon: &Daemon) -> (u16, &'static str, String) {
    let mut inner = lock(&daemon.inner);
    let geo_dir = geo_dir_from_state(&inner.state);
    match regenerate_config(&inner.state, daemon) {
        Ok((binary_path, config_path)) => {
            match inner
                .core
                .restart(&binary_path, &config_path, geo_dir.as_deref())
            {
                Ok(()) => (
                    200,
                    "application/json",
                    json!({"status": "applied", "core_status": inner.core.status()}).to_string(),
                ),
                Err(e) => (
                    500,
                    "application/json",
                    json!({"error": format!("core restart: {e}")}).to_string(),
                ),
            }
        }
        Err(e) => (
            500,
            "application/json",
            json!({"error": format!("config regeneration: {e}")}).to_string(),
        ),
    }
}

/// Return the last N lines of the Mihomo log file so the user can
/// diagnose start failures from the web panel without SSH.
fn handle_logs(_daemon: &Daemon) -> (u16, &'static str, String) {
    let dir = resolve_log_dir();
    let mihomo_log = dir.join("mihomo.log");

    let read_tail = |path: &Path| -> String {
        let Ok(text) = fs::read_to_string(path) else {
            return String::new();
        };
        let lines: Vec<&str> = text.lines().collect();
        let start = lines.len().saturating_sub(200);
        redact_log_text(&lines[start..].join("\n"))
    };

    (
        200,
        "application/json",
        json!({
            "mihomo": read_tail(&mihomo_log),
            "mihomo_log_path": mihomo_log.to_string_lossy(),
        })
        .to_string(),
    )
}

fn redact_log_text(text: &str) -> String {
    text.lines()
        .map(|line| {
            if log_line_may_contain_secret(line) {
                "[redacted log line: possible secret]".to_owned()
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn log_line_may_contain_secret(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    const SECRET_MARKERS: &[&str] = &[
        "password",
        "passwd",
        "private-key",
        "private_key",
        "preshared-key",
        "pre-shared-key",
        "token",
        "secret",
        "authorization",
        "bearer ",
        "set-cookie",
        "uuid",
        "alterid",
        "client-fingerprint",
    ];
    if SECRET_MARKERS.iter().any(|marker| lower.contains(marker)) {
        return true;
    }
    (lower.contains("://") && lower.contains('@'))
        || (lower.contains("://")
            && ["?key=", "&key=", "?auth=", "&auth=", "?token=", "&token="]
                .iter()
                .any(|marker| lower.contains(marker)))
}

/// Collect and return system resource information: CPU (architecture,
/// cores, model, features, frequency, temperature, usage), memory
/// (total/free/available/cached/swap), load average, and uptime.
///
/// CPU usage is computed as a delta between the current and previous
/// `/proc/stat` samples stored in `DaemonInner`. The first call
/// returns 0% and stores the baseline; subsequent calls return the
/// real usage percentage since the last call.
fn handle_system(daemon: &Daemon) -> (u16, &'static str, String) {
    // ── /proc/stat: CPU usage ──
    let (cpu_usage, cpu_usage_per_core) = {
        let mut inner = lock(&daemon.inner);
        let stat_text = fs::read_to_string("/proc/stat").unwrap_or_default();
        let mut agg: Option<CpuTimes> = None;
        let mut per_core: Vec<CpuTimes> = Vec::new();
        for line in stat_text.lines() {
            if line.starts_with("cpu ") {
                agg = CpuTimes::parse_line(line);
            } else if line.starts_with("cpu")
                && line[3..].chars().next().is_some_and(|c| c.is_ascii_digit())
                && let Some(t) = CpuTimes::parse_line(line)
            {
                per_core.push(t);
            }
        }
        // Compute deltas against previous samples.
        let usage = match (&inner.prev_cpu, &agg) {
            (Some(prev), Some(cur)) => CpuTimes::usage_pct(prev, cur),
            _ => 0.0,
        };
        let mut per_core_usage: Vec<f64> = Vec::new();
        if !inner.prev_cpu_per_core.is_empty() && inner.prev_cpu_per_core.len() == per_core.len() {
            for (prev, cur) in inner.prev_cpu_per_core.iter().zip(per_core.iter()) {
                per_core_usage.push(CpuTimes::usage_pct(prev, cur));
            }
        } else {
            per_core_usage = vec![0.0; per_core.len()];
        }
        // Store current samples for next call.
        inner.prev_cpu = agg;
        inner.prev_cpu_per_core = per_core;
        (usage, per_core_usage)
    };

    // ── /proc/cpuinfo: architecture, model, features ──
    let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let mut cpu_model = String::new();
    let mut cpu_cores: u32 = 0;
    let mut cpu_features = String::new();
    let mut cpu_bogomips: f64 = 0.0;
    let mut cpu_part = String::new();
    for line in cpuinfo.lines() {
        if let Some(val) = line.strip_prefix("model name")
            && let Some(val) = val.split(':').nth(1)
            && cpu_model.is_empty()
        {
            cpu_model = val.trim().to_owned();
        }
        if line.starts_with("processor") {
            cpu_cores += 1;
        }
        if let Some(val) = line.strip_prefix("Features")
            && let Some(val) = val.split(':').nth(1)
            && cpu_features.is_empty()
        {
            cpu_features = val.trim().to_owned();
        }
        if let Some(val) = line.strip_prefix("BogoMIPS")
            && let Some(val) = val.split(':').nth(1)
        {
            cpu_bogomips = val.trim().parse().unwrap_or(0.0);
        }
        if let Some(val) = line.strip_prefix("CPU part")
            && let Some(val) = val.split(':').nth(1)
        {
            cpu_part = val.trim().to_owned();
        }
    }
    let cpu_part_name = arm_cpu_part_name(&cpu_part);

    // ── /sys/class/thermal: temperature ──
    let cpu_temp: Option<f64> = (|| {
        let entries = fs::read_dir("/sys/class/thermal").ok()?;
        for entry in entries.flatten() {
            let path = entry.path().join("temp");
            if let Ok(text) = fs::read_to_string(&path)
                && let Ok(millideg) = text.trim().parse::<f64>()
            {
                return Some(millideg / 1000.0);
            }
        }
        None
    })();

    // ── /proc/meminfo: memory ──
    let meminfo = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mut mem_total_kb: u64 = 0;
    let mut mem_free_kb: u64 = 0;
    let mut mem_available_kb: u64 = 0;
    let mut mem_buffers_kb: u64 = 0;
    let mut mem_cached_kb: u64 = 0;
    let mut swap_total_kb: u64 = 0;
    let mut swap_free_kb: u64 = 0;
    for line in meminfo.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let key = parts[0].trim_end_matches(':');
        let val: u64 = parts[1].parse().unwrap_or(0);
        match key {
            "MemTotal" => mem_total_kb = val,
            "MemFree" => mem_free_kb = val,
            "MemAvailable" => mem_available_kb = val,
            "Buffers" => mem_buffers_kb = val,
            "Cached" => mem_cached_kb = val,
            "SwapTotal" => swap_total_kb = val,
            "SwapFree" => swap_free_kb = val,
            _ => {}
        }
    }
    let mem_usage_pct = if mem_total_kb > 0 {
        let used = mem_total_kb.saturating_sub(mem_available_kb);
        (used as f64 / mem_total_kb as f64) * 100.0
    } else {
        0.0
    };

    // ── /proc/loadavg ──
    let loadavg = fs::read_to_string("/proc/loadavg").unwrap_or_default();
    let load_parts: Vec<&str> = loadavg.split_whitespace().collect();
    let load_1: f64 = load_parts
        .first()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);
    let load_5: f64 = load_parts
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);
    let load_15: f64 = load_parts
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);

    // ── /proc/uptime ──
    let uptime_text = fs::read_to_string("/proc/uptime").unwrap_or_default();
    let uptime_secs: f64 = uptime_text
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);

    // ── uname / hostname / model ──
    let kernel = Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default();
    let hostname = Command::new("uname")
        .arg("-n")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default();
    let model = fs::read_to_string("/proc/device-tree/model")
        .ok()
        .map(|s| s.trim_end_matches('\0').trim().to_owned())
        .unwrap_or_default();

    (
        200,
        "application/json",
        json!({
            "cpu": {
                "model": cpu_model,
                "cores": cpu_cores,
                "part": cpu_part,
                "part_name": cpu_part_name,
                "features": cpu_features,
                "bogomips": cpu_bogomips,
                "usage_pct": (cpu_usage * 10.0).round() / 10.0,
                "usage_per_core": cpu_usage_per_core.iter().map(|v| (v * 10.0).round() / 10.0).collect::<Vec<_>>(),
                "temp_c": cpu_temp.map(|t| (t * 10.0).round() / 10.0),
            },
            "memory": {
                "total_kb": mem_total_kb,
                "free_kb": mem_free_kb,
                "available_kb": mem_available_kb,
                "buffers_kb": mem_buffers_kb,
                "cached_kb": mem_cached_kb,
                "usage_pct": (mem_usage_pct * 10.0).round() / 10.0,
                "swap_total_kb": swap_total_kb,
                "swap_free_kb": swap_free_kb,
            },
            "load": {
                "1": load_1,
                "5": load_5,
                "15": load_15,
            },
            "uptime_secs": uptime_secs,
            "kernel": kernel,
            "hostname": hostname,
            "model": model,
        })
        .to_string(),
    )
}

fn handle_hwid_get(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    (
        200,
        "application/json",
        json!({"hwid": inner.state.hwid_config}).to_string(),
    )
}

fn handle_hwid_set(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return (
            400,
            "application/json",
            json!({"error": "invalid JSON body"}).to_string(),
        );
    };
    let mut inner = lock(&daemon.inner);
    if let Some(v) = value.get("hwid").and_then(Value::as_str) {
        inner.state.hwid_config.hwid = v.trim().to_owned();
    }
    if let Some(v) = value.get("os_version").and_then(Value::as_str) {
        inner.state.hwid_config.os_version = v.trim().to_owned();
    }
    if let Some(v) = value.get("device_model").and_then(Value::as_str) {
        inner.state.hwid_config.device_model = v.trim().to_owned();
    }
    if let Some(v) = value.get("device_os").and_then(Value::as_str) {
        inner.state.hwid_config.device_os = v.trim().to_owned();
    }
    if let Some(v) = value.get("app_version").and_then(Value::as_str) {
        inner.state.hwid_config.app_version = v.trim().to_owned();
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
        json!({"hwid": inner.state.hwid_config}).to_string(),
    )
}

// ─── Mihomo update API handlers ───────────────────────────────────

/// Return cached update state: current version, available version,
/// auto-update settings, last check time. Does NOT spawn `mihomo -v`
/// — the cached version is refreshed only by check/apply/startup.
fn handle_update_status(daemon: &Daemon) -> (u16, &'static str, String) {
    let inner = lock(&daemon.inner);
    let response = json!({
        "current_version": inner.state.mihomo_version,
        "update_available_version": inner.state.update_available_version,
        "auto_update_enabled": inner.state.auto_update_enabled,
        "auto_update_interval_hours": inner.state.auto_update_interval_hours,
        "last_update_check_unix": inner.state.last_update_check_unix,
        "mihomo_path": inner.state.mihomo_path,
    });
    (200, "application/json", response.to_string())
}

/// Manually check GitHub for the latest Mihomo release through the
/// local SOCKS proxy. Requires the core to be running (GitHub is
/// blocked from the router's direct connection).
fn handle_update_check(daemon: &Daemon) -> (u16, &'static str, String) {
    let (socks_port, core_running, mihomo_path) = {
        let mut inner = lock(&daemon.inner);
        (
            inner.state.socks_port,
            inner.core.is_running(),
            inner.state.mihomo_path.clone(),
        )
    };
    if !core_running {
        return (
            400,
            "application/json",
            json!({"error": "Mihomo core is not running; cannot check for updates through proxy"})
                .to_string(),
        );
    }
    match check_latest_mihomo_release(socks_port) {
        Ok(release) => {
            // Refresh the cached current version by running `mihomo -v`.
            let current_version = get_mihomo_version(&mihomo_path).ok();
            let is_newer = current_version
                .as_ref()
                .map(|cv| is_newer_version(cv, &release.tag_name))
                .unwrap_or(true);
            let now = unix_now();
            {
                let mut inner = lock(&daemon.inner);
                inner.state.last_update_check_unix = now;
                inner.state.mihomo_version = current_version.clone();
                if is_newer {
                    inner.state.update_available_version = Some(release.tag_name.clone());
                } else {
                    inner.state.update_available_version = None;
                }
                let _ = persist_state(&daemon.state_path, &inner.state);
            }
            let response = json!({
                "current_version": current_version,
                "latest_version": release.tag_name,
                "update_available": is_newer,
                "asset_name": release.asset_name,
            });
            (200, "application/json", response.to_string())
        }
        Err(error) => {
            let mut inner = lock(&daemon.inner);
            inner.state.last_update_check_unix = unix_now();
            let _ = persist_state(&daemon.state_path, &inner.state);
            (500, "application/json", json!({"error": error}).to_string())
        }
    }
}

/// Download and install the latest Mihomo release. Replaces the
/// binary, restarts the core, and verifies the new process is alive.
/// On failure, rolls back to the previous binary.
fn handle_update_apply(daemon: &Daemon) -> (u16, &'static str, String) {
    let (socks_port, core_running, mihomo_path, config_path, geo_dir) = {
        let mut inner = lock(&daemon.inner);
        (
            inner.state.socks_port,
            inner.core.is_running(),
            inner.state.mihomo_path.clone(),
            daemon.mihomo_config_path.clone(),
            geo_dir_from_state(&inner.state),
        )
    };
    if !core_running {
        return (
            400,
            "application/json",
            json!({"error": "Mihomo core is not running; cannot download update through proxy"})
                .to_string(),
        );
    }

    // Check for the latest release (network I/O, no lock).
    let release = match check_latest_mihomo_release(socks_port) {
        Ok(r) => r,
        Err(e) => {
            return (
                500,
                "application/json",
                json!({"error": format!("check failed: {e}")}).to_string(),
            );
        }
    };
    let current_version = get_mihomo_version(&mihomo_path).unwrap_or_default();
    if !current_version.is_empty() && !is_newer_version(&current_version, &release.tag_name) {
        return (
            200,
            "application/json",
            json!({"message": "already up to date", "current_version": current_version})
                .to_string(),
        );
    }

    // Download and install (network I/O + file ops, no lock).
    let new_version = match download_and_install_mihomo(&release, &mihomo_path, socks_port) {
        Ok(v) => v,
        Err(e) => return (500, "application/json", json!({"error": e}).to_string()),
    };

    // Restart core with new binary (needs lock).
    let mut inner = lock(&daemon.inner);
    if let Err(e) = inner
        .core
        .restart(&mihomo_path, &config_path, geo_dir.as_deref())
    {
        // Core restart failed — attempt rollback.
        eprintln!("hincyray: core restart after update failed ({e}), rolling back");
        let backup_path = format!("{mihomo_path}.bak");
        let _ = fs::copy(&backup_path, &mihomo_path);
        let _ = inner
            .core
            .restart(&mihomo_path, &config_path, geo_dir.as_deref());
        return (
            500,
            "application/json",
            json!({"error": format!("core restart failed after update, rolled back: {e}")})
                .to_string(),
        );
    }

    // Wait and verify the new core is alive.
    drop(inner);
    thread::sleep(Duration::from_secs(3));
    let mut inner = lock(&daemon.inner);
    if !inner.core.is_running() {
        eprintln!("hincyray: core died after update, rolling back");
        let backup_path = format!("{mihomo_path}.bak");
        let _ = fs::copy(&backup_path, &mihomo_path);
        let _ = inner
            .core
            .restart(&mihomo_path, &config_path, geo_dir.as_deref());
        return (
            500,
            "application/json",
            json!({"error": "core died after update, rolled back to previous version"}).to_string(),
        );
    }

    // Success — update state.
    inner.state.mihomo_version = Some(new_version.clone());
    inner.state.update_available_version = None;
    let _ = persist_state(&daemon.state_path, &inner.state);
    let response = json!({
        "updated": true,
        "previous_version": current_version,
        "new_version": new_version,
    });
    (200, "application/json", response.to_string())
}

/// Toggle auto-update and set the check interval.
fn handle_update_settings(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return (
            400,
            "application/json",
            json!({"error": "invalid JSON body"}).to_string(),
        );
    };
    let mut inner = lock(&daemon.inner);
    if let Some(v) = value.get("auto_update_enabled").and_then(Value::as_bool) {
        inner.state.auto_update_enabled = v;
    }
    if let Some(v) = value
        .get("auto_update_interval_hours")
        .and_then(Value::as_u64)
    {
        inner.state.auto_update_interval_hours = v as u32;
    }
    let _ = persist_state(&daemon.state_path, &inner.state);
    let response = json!({
        "auto_update_enabled": inner.state.auto_update_enabled,
        "auto_update_interval_hours": inner.state.auto_update_interval_hours,
    });
    (200, "application/json", response.to_string())
}

fn shell_status(command: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(command)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Quick SOCKS health check: try a tiny HTTP request through the
/// proxy with a 5-second timeout. Returns true if the tunnel is
/// forwarding traffic.
fn socks_health_check(socks_port: u16) -> bool {
    Command::new("curl")
        .args([
            "-s",
            "--max-time",
            "5",
            "--socks5-hostname",
            &format!("127.0.0.1:{socks_port}"),
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "https://1.1.1.1/cdn-cgi/trace",
        ])
        .output()
        .map(|o| {
            let code = String::from_utf8_lossy(&o.stdout).trim().to_owned();
            o.status.success() && code.starts_with('2')
        })
        .unwrap_or(false)
}

/// Find the lowest-latency eligible profile with a successful probe.
fn find_best_profile(state: &HincyrayState, excluded_profiles: &HashSet<usize>) -> Option<usize> {
    let now = unix_now();
    let mut best: Option<(usize, u32)> = None;
    for profile in &state.profiles {
        if excluded_profiles.contains(&profile.id) || profile_is_dead(state, profile) {
            continue;
        }
        let Some(stat) = state.stats.iter().find(|s| s.profile_raw == profile.raw) else {
            continue;
        };
        if stat.success_count == 0 || stat.cooldown_until_unix > now || !stat.has_latency {
            continue;
        }
        if best
            .map(|(_, latency)| stat.last_latency_ms < latency)
            .unwrap_or(true)
        {
            best = Some((profile.id, stat.last_latency_ms));
        }
    }
    best.map(|(id, _)| id)
}

/// Rank failover candidates by historical quality while keeping identity and
/// eligibility tied to the immutable raw profile descriptor. Historical data
/// only determines probe order; every candidate is protocol-verified before a
/// switch.
fn ranked_failover_candidates(
    state: &HincyrayState,
    excluded_raws: &HashSet<String>,
) -> Vec<Profile> {
    let now = unix_now();
    let mut ranked: Vec<(Profile, u32)> = state
        .profiles
        .iter()
        .filter(|profile| !excluded_raws.contains(&profile.raw) && !profile_is_dead(state, profile))
        .filter_map(|profile| {
            let stat = state
                .stats
                .iter()
                .find(|stat| stat.profile_raw == profile.raw)?;
            if stat.success_count == 0 || stat.cooldown_until_unix > now {
                return None;
            }
            stat.has_latency
                .then_some((profile.clone(), stat.last_latency_ms))
        })
        .collect();
    ranked.sort_by_key(|(_, latency)| *latency);
    ranked.into_iter().map(|(profile, _)| profile).collect()
}

const MAX_VERIFIED_FAILOVER_CANDIDATES: usize = 8;

/// Verify candidates outside the daemon mutex, then resolve the winning raw
/// descriptor against current state immediately before the transactional
/// switch. A concurrent user switch or subscription refresh aborts this
/// failover attempt instead of applying a stale numeric id.
fn attempt_verified_failover(
    daemon: &Daemon,
    failed_active_raw: &str,
    rejected_raws: &mut HashSet<String>,
) -> bool {
    rejected_raws.insert(failed_active_raw.to_owned());
    let (candidates, mihomo_path) = {
        let inner = lock(&daemon.inner);
        (
            ranked_failover_candidates(&inner.state, rejected_raws),
            inner.state.mihomo_path.clone(),
        )
    };

    for candidate in candidates
        .into_iter()
        .take(MAX_VERIFIED_FAILOVER_CANDIDATES)
    {
        eprintln!(
            "hincyray: protocol-verifying failover candidate {}",
            candidate.id
        );
        let result = crate::benchmark::verify_profile_for_failover(&candidate, &mihomo_path);
        let accepted = result.success;
        let candidate_raw = candidate.raw.clone();
        let candidate_name = candidate.name.clone();
        apply_bench_result(daemon, result);
        if !accepted {
            rejected_raws.insert(candidate_raw);
            continue;
        }

        let mut inner = lock(&daemon.inner);
        let current_raw = inner
            .state
            .active_profile_id
            .and_then(|id| inner.state.profiles.iter().find(|profile| profile.id == id))
            .map(|profile| profile.raw.as_str());
        if current_raw != Some(failed_active_raw) {
            eprintln!(
                "hincyray: verified failover aborted because active profile changed concurrently"
            );
            return false;
        }
        let Some(candidate_id) = inner
            .state
            .profiles
            .iter()
            .find(|profile| profile.raw == candidate_raw)
            .map(|profile| profile.id)
        else {
            eprintln!(
                "hincyray: verified candidate disappeared during subscription refresh: {candidate_name}"
            );
            rejected_raws.insert(candidate_raw);
            continue;
        };
        eprintln!("hincyray: verified failover to profile {candidate_id} ({candidate_name})");
        if apply_active_profile(&mut inner, daemon, candidate_id).is_ok() {
            return true;
        }
        record_profile_health_failure(&mut inner.state, &candidate_raw, unix_now());
        inner.dirty = true;
        rejected_raws.insert(candidate_raw);
        eprintln!("hincyray: verified candidate could not be applied; trying the next candidate");
    }

    eprintln!("hincyray: no protocol-verified alternative profile for failover");
    false
}

fn record_profile_health_failure(state: &mut HincyrayState, profile_raw: &str, now: u64) {
    let stats_idx = match state
        .stats
        .iter()
        .position(|stat| stat.profile_raw == profile_raw)
    {
        Some(index) => index,
        None => {
            state.stats.push(ProfileStats {
                profile_raw: profile_raw.to_owned(),
                ..ProfileStats::default()
            });
            state.stats.len() - 1
        }
    };
    let stat = &mut state.stats[stats_idx];
    stat.failure_count = stat.failure_count.saturating_add(1);
    stat.consecutive_failures = stat.consecutive_failures.saturating_add(1);
    stat.cooldown_until_unix = now.saturating_add(default_smart_cooldown_secs());
    stat.last_checked_unix = now;
    stat.last_error = Some("active profile failed Mihomo fallback health threshold".to_owned());
}

// ─── Mihomo auto-update ───────────────────────────────────────────

/// GitHub release info parsed from the latest release API response.
struct MihomoRelease {
    tag_name: String,
    asset_url: String,
    asset_name: String,
}

/// Run `mihomo -v` and parse the version string from stdout.
/// The output looks like:
/// `Mihomo Meta v1.19.27 linux arm64 with go1.26.4 Sat Jun  6 ...`
/// The version (e.g. "v1.19.27") is the 3rd whitespace-separated token.
fn get_mihomo_version(binary_path: &str) -> Result<String, String> {
    let output = Command::new(binary_path)
        .arg("-v")
        .output()
        .map_err(|e| format!("mihomo -v spawn: {e}"))?;
    let text = String::from_utf8_lossy(&output.stdout);
    text.split_whitespace()
        .nth(2)
        .map(|s| s.to_owned())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "could not parse version from mihomo -v output".to_owned())
}

/// Compare two version strings like "v1.19.27" and "v1.19.28".
/// Returns true if `latest` is strictly newer than `current`.
fn is_newer_version(current: &str, latest: &str) -> bool {
    let parse_parts = |s: &str| -> Vec<u32> {
        s.trim_start_matches('v')
            .split('.')
            .filter_map(|p| p.parse::<u32>().ok())
            .collect()
    };
    let cur = parse_parts(current);
    let new = parse_parts(latest);
    for (c, n) in cur.iter().zip(new.iter()) {
        if n > c {
            return true;
        }
        if n < c {
            return false;
        }
    }
    new.len() > cur.len()
}

/// Fetch the latest Mihomo release from the GitHub API through the
/// local SOCKS proxy. GitHub is blocked from the router's direct
/// connection, so the proxy is mandatory — the caller must verify
/// that the core is running before calling this function.
fn check_latest_mihomo_release(socks_port: u16) -> Result<MihomoRelease, String> {
    let output = Command::new("curl")
        .args([
            "-s",
            "--max-time",
            "30",
            "--socks5-hostname",
            &format!("127.0.0.1:{socks_port}"),
            "-H",
            "User-Agent: hincyray",
            "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest",
        ])
        .output()
        .map_err(|e| format!("curl spawn: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "curl exited with status {}",
            output.status.code().unwrap_or(-1)
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&text).map_err(|e| format!("parse GitHub JSON: {e}"))?;
    let tag_name = json
        .get("tag_name")
        .and_then(Value::as_str)
        .ok_or("missing tag_name in GitHub response")?
        .to_owned();
    let asset = json
        .get("assets")
        .and_then(Value::as_array)
        .and_then(|assets| {
            assets.iter().find(|a| {
                a.get("name").and_then(Value::as_str).is_some_and(|name| {
                    name.starts_with("mihomo-linux-arm64-")
                        && name.ends_with(".gz")
                        && !name.contains("compatible")
                })
            })
        })
        .ok_or("no mihomo-linux-arm64-*.gz asset found in release")?;
    let asset_url = asset
        .get("browser_download_url")
        .and_then(Value::as_str)
        .ok_or("missing browser_download_url")?
        .to_owned();
    let asset_name = asset
        .get("name")
        .and_then(Value::as_str)
        .ok_or("missing asset name")?
        .to_owned();
    Ok(MihomoRelease {
        tag_name,
        asset_url,
        asset_name,
    })
}

/// Download, decompress, verify, back up, and replace the Mihomo
/// binary. The caller is responsible for restarting the core after
/// this function returns successfully.
///
/// Flow:
/// 1. Download `.gz` through the SOCKS proxy to `/tmp/mihomo-update.gz`.
/// 2. Decompress with `gunzip -c` → `/tmp/mihomo-update`.
/// 3. `chmod +x` the new binary.
/// 4. Verify the new binary runs (`/tmp/mihomo-update -v`).
/// 5. Back up the current binary to `<path>.bak`.
/// 6. Replace the current binary (fs::copy, cross-device safe).
/// 7. `chmod +x` the replaced binary.
/// 8. Clean up temp files.
fn download_and_install_mihomo(
    release: &MihomoRelease,
    current_binary: &str,
    socks_port: u16,
) -> Result<String, String> {
    let tmp_gz = "/tmp/mihomo-update.gz";
    let tmp_bin = "/tmp/mihomo-update";

    // 1. Download
    let dl_status = Command::new("curl")
        .args([
            "-sL",
            "--max-time",
            "300",
            "--socks5-hostname",
            &format!("127.0.0.1:{socks_port}"),
            "-H",
            "User-Agent: hincyray",
            "-o",
            tmp_gz,
            &release.asset_url,
        ])
        .status()
        .map_err(|e| format!("curl download spawn: {e}"))?;
    if !dl_status.success() {
        let _ = fs::remove_file(tmp_gz);
        return Err("download failed (curl exited with non-zero status)".to_owned());
    }

    // 2. Decompress
    let gz_output = Command::new("gunzip")
        .args(["-c", tmp_gz])
        .output()
        .map_err(|e| {
            let _ = fs::remove_file(tmp_gz);
            format!("gunzip spawn: {e}")
        })?;
    if !gz_output.status.success() {
        let _ = fs::remove_file(tmp_gz);
        let stderr = String::from_utf8_lossy(&gz_output.stderr);
        return Err(format!("gunzip failed: {stderr}"));
    }
    fs::write(tmp_bin, &gz_output.stdout).map_err(|e| {
        let _ = fs::remove_file(tmp_gz);
        format!("write decompressed binary: {e}")
    })?;

    // 3. Make executable
    let _ = fs::remove_file(tmp_gz);
    Command::new("chmod")
        .arg("+x")
        .arg(tmp_bin)
        .status()
        .map_err(|e| {
            let _ = fs::remove_file(tmp_bin);
            format!("chmod: {e}")
        })?;

    // 4. Verify the new binary runs
    let new_version = get_mihomo_version(tmp_bin).map_err(|e| {
        let _ = fs::remove_file(tmp_bin);
        format!("new binary verification failed: {e}")
    })?;

    // 5. Back up current binary
    let backup_path = format!("{current_binary}.bak");
    fs::copy(current_binary, &backup_path).map_err(|e| {
        let _ = fs::remove_file(tmp_bin);
        format!("backup current binary: {e}")
    })?;

    // 6. Replace: unlink first to avoid ETXTBSY on kernels that block
    //    writes to executing binaries. The running Mihomo process keeps
    //    its inode, so it continues running until the caller restarts it.
    let _ = fs::remove_file(current_binary);
    fs::copy(tmp_bin, current_binary).map_err(|e| {
        // Attempt rollback on failure
        let _ = fs::copy(&backup_path, current_binary);
        let _ = fs::remove_file(tmp_bin);
        format!("replace binary: {e}")
    })?;

    // 7. Ensure executable bit
    let _ = Command::new("chmod").arg("+x").arg(current_binary).status();

    // 8. Clean up
    let _ = fs::remove_file(tmp_bin);

    Ok(new_version)
}

/// Start a TCP benchmark on all profiles from the watchdog. This is
/// the same mechanism as `handle_bench_start` but uses the TCP method
/// (lightweight, no temp Xray processes) and covers all profiles.
fn start_auto_benchmark(daemon: &Daemon) {
    let profiles: Vec<Profile> = {
        let inner = lock(&daemon.inner);
        if inner.bench.is_running() {
            return;
        }
        inner
            .state
            .profiles
            .iter()
            .filter(|profile| !profile_is_dead(&inner.state, profile))
            .cloned()
            .collect()
    };
    if profiles.is_empty() {
        return;
    }
    let job = Arc::new(Mutex::new(BenchJob::default()));
    let cancel = Arc::new(AtomicBool::new(false));
    let daemon_for_callback = daemon.clone();
    let on_result = Box::new(move |result: BenchResult| {
        apply_bench_result(&daemon_for_callback, result);
    });
    let handle = run_bench(
        profiles,
        BenchMethod::Tcp,
        DEFAULT_PROBE_URL.to_owned(),
        DEFAULT_DOWNLOAD_URL.to_owned(),
        DEFAULT_UPLOAD_URL.to_owned(),
        "xray".to_owned(),
        None,
        false,
        false,
        Arc::clone(&job),
        Arc::clone(&cancel),
        on_result,
    );
    let mut inner = lock(&daemon.inner);
    if let Some(prev) = inner.bench.handle.take() {
        let _ = prev.join();
    }
    inner.bench.job = Some(job);
    inner.bench.cancel = Some(cancel);
    inner.bench.handle = Some(handle);
}

enum ActiveProfileApplyError {
    Ineligible(String),
    InvalidConfig(String),
    Runtime(String),
}

impl ActiveProfileApplyError {
    fn http_status(&self) -> u16 {
        match self {
            Self::Ineligible(_) => 409,
            Self::InvalidConfig(_) => 400,
            Self::Runtime(_) => 500,
        }
    }

    fn message(&self) -> &str {
        match self {
            Self::Ineligible(message) | Self::InvalidConfig(message) | Self::Runtime(message) => {
                message
            }
        }
    }
}

/// Apply a new active profile to every layer that observes it: in-memory
/// state, generated Mihomo config, running Mihomo process, and persisted state.
///
/// Keep all profile-switching entrypoints behind this helper so that the
/// persisted profile and Mihomo's live configuration change together.
fn apply_active_profile(
    inner: &mut MutexGuard<DaemonInner>,
    daemon: &Daemon,
    profile_id: usize,
) -> Result<(), ActiveProfileApplyError> {
    let Some(profile) = inner
        .state
        .profiles
        .iter()
        .find(|profile| profile.id == profile_id)
    else {
        return Err(ActiveProfileApplyError::Ineligible(format!(
            "profile not found: {profile_id}"
        )));
    };
    if profile_is_dead(&inner.state, profile) {
        return Err(ActiveProfileApplyError::Ineligible(
            "profile in Dead Servers cannot be activated; restore it first".to_owned(),
        ));
    }
    let previous_profile_id = inner.state.active_profile_id;
    let geo_dir = geo_dir_from_state(&inner.state);

    inner.state.active_profile_id = Some(profile_id);
    let config_yaml = match build_authoritative_daemon_config(&inner.state, daemon) {
        Ok(yaml) => yaml,
        Err(error) => {
            inner.state.active_profile_id = previous_profile_id;
            return Err(ActiveProfileApplyError::InvalidConfig(error));
        }
    };

    let config_path = daemon.mihomo_config_path.clone();
    let binary_path = inner.state.mihomo_path.clone();
    let controller = mihomo_controller(&inner.state.mihomo_features);
    let core_running = inner.core.is_running();

    let apply_result = atomic_write_config(&config_path, config_yaml.as_bytes())
        .and_then(|()| {
            if core_running && let Some(controller) = controller.as_ref() {
                hot_reload_mihomo_config(controller, &config_path)
            } else {
                inner
                    .core
                    .restart(&binary_path, &config_path, geo_dir.as_deref())
            }
        })
        .and_then(|()| persist_state(&daemon.state_path, &inner.state).map_err(|e| e.to_string()));

    if let Err(error) = apply_result {
        inner.state.active_profile_id = previous_profile_id;
        if previous_profile_id.is_some() {
            let (rollback_binary, rollback_path) = match regenerate_config(&inner.state, daemon) {
                Ok(pair) => pair,
                Err(e) => {
                    eprintln!("hincyray: rollback config regeneration failed: {e}");
                    return Err(ActiveProfileApplyError::Runtime(error));
                }
            };
            let rollback_result = if core_running && let Some(controller) = controller.as_ref() {
                hot_reload_mihomo_config(controller, &rollback_path)
            } else {
                inner
                    .core
                    .restart(&rollback_binary, &rollback_path, geo_dir.as_deref())
            };
            if let Err(rollback_error) = rollback_result {
                eprintln!(
                    "hincyray: rollback after active profile switch failure failed: {rollback_error}"
                );
            }
        }
        return Err(ActiveProfileApplyError::Runtime(error));
    }

    Ok(())
}

/// Switch the active profile, regenerate Mihomo config, and restart the
/// core. Caller must hold the lock.
fn switch_active_profile(inner: &mut MutexGuard<DaemonInner>, daemon: &Daemon, profile_id: usize) {
    if let Err(error) = apply_active_profile(inner, daemon, profile_id) {
        eprintln!(
            "hincyray: active profile switch failed: {}",
            error.message()
        );
    }
}

/// Background watchdog thread. Runs every 10 seconds and handles:
///
/// 1. **Core monitoring (always)** — if the Mihomo core has crashed,
///    regenerate config and restart it with exponential backoff.
/// 2. **Firewall/iptables monitoring (split routing only)** — restart
///    tun2socks if dead, reinstall iptables rules wiped by ndm.
/// 3. **Health check + failover (auto_switch)** — probe the SOCKS
///    tunnel with a short curl request. After 3 consecutive failures,
///    switch to the lowest-latency recently successful profile.
/// 4. **Auto-benchmark (auto_bench_interval_hours > 0)** — trigger a
///    TCP benchmark on all profiles on a schedule.
/// 5. **Auto-select (auto_select)** — when a benchmark finishes,
///    switch to the lowest-latency recently successful profile.
fn start_watchdog(
    daemon: Daemon,
    mihomo_log_path: PathBuf,
    mut mihomo_log_cursor: MihomoLogCursor,
) {
    thread::spawn(move || {
        let mut bench_was_running = false;
        let mut restart_backoff_secs: u64 = 0;
        let mut failover_rejected_profiles: HashSet<String> = HashSet::new();
        let mut watchdog_tick: u64 = 0;
        let mut pending_auto_vpn_domains: VecDeque<AutoVpnCandidate> = VecDeque::new();

        loop {
            thread::sleep(Duration::from_secs(10));
            watchdog_tick += 1;

            // --- Read state snapshot (short lock) ---
            let (
                core_running,
                split_enabled,
                firewall_active,
                redirect_port,
                vpn_subnet,
                policy_name,
                cached_mark,
                socks_port,
                auto_switch,
                auto_select,
                auto_bench_hours,
                last_auto_bench,
                bench_running,
                active_profile_id,
                auto_update_enabled,
                auto_update_interval_hours,
                last_update_check,
                mihomo_path,
                proxy_group_enabled,
                ec_addr,
                ec_secret,
                auto_refresh_enabled,
                auto_refresh_interval_hours,
                last_auto_refresh,
                maintenance,
                auto_vpn_learning_enabled,
                parovozik_enabled,
                deep_bench_running,
                deep_bench_due_now,
            ) = {
                let mut inner = lock(&daemon.inner);
                let ec = mihomo_controller(&inner.state.mihomo_features);
                let (ec_addr, ec_secret) = match ec {
                    Some((a, s)) => (Some(a), s),
                    None => (None, None),
                };
                (
                    inner.core.is_running(),
                    inner.state.split_routing.enabled,
                    inner.firewall.is_running(),
                    inner.state.split_routing.redirect_port,
                    inner.state.split_routing.vpn_subnet.clone(),
                    inner.state.split_routing.policy_name.clone(),
                    inner.state.split_routing.policy_mark.clone(),
                    inner.state.socks_port,
                    inner.state.split_routing.auto_switch,
                    inner.state.auto_select,
                    inner.state.auto_bench_interval_hours,
                    inner.state.last_auto_bench_unix,
                    inner.bench.is_running(),
                    inner.state.active_profile_id,
                    inner.state.auto_update_enabled,
                    inner.state.auto_update_interval_hours,
                    inner.state.last_update_check_unix,
                    inner.state.mihomo_path.clone(),
                    inner.state.mihomo_features.proxy_group.enabled,
                    ec_addr,
                    ec_secret,
                    inner.state.auto_refresh_enabled,
                    inner.state.auto_refresh_interval_hours,
                    inner.state.last_auto_refresh_unix,
                    inner.state.maintenance.clone(),
                    inner.state.split_routing.auto_vpn_learning_enabled,
                    inner.state.split_routing.parovozik_enabled,
                    inner.deep_bench_active,
                    deep_bench_due(&inner.state.deep_bench, unix_now()),
                )
            };

            // --- Phase 1: Core restart (always) ---
            if !core_running {
                if restart_backoff_secs > 0 {
                    eprintln!(
                        "hincyray: core restart backoff ({}s remaining)",
                        restart_backoff_secs
                    );
                    restart_backoff_secs = restart_backoff_secs.saturating_sub(10);
                    // Still process auto-switch / bench state below.
                } else {
                    eprintln!("hincyray: core not running, restarting...");
                    match activate_current_config(&daemon, true, false, GeoBaseProjection::Applied)
                    {
                        Ok(_) => {
                            restart_backoff_secs = 0;
                            eprintln!("hincyray: core restarted by watchdog");
                        }
                        Err(error) => {
                            eprintln!("hincyray: watchdog core restart failed: {error}");
                            restart_backoff_secs = restart_backoff_secs.clamp(10, 150) * 2;
                        }
                    }
                    continue;
                }
            }

            // --- Phase 2: Firewall rules (split routing only) ---
            if split_enabled {
                if !firewall_active {
                    eprintln!("hincyray: firewall not active, starting...");
                    let mut inner = lock(&daemon.inner);
                    let vpn_subnet_clone = vpn_subnet.clone();
                    let _ = inner.firewall.stop(&vpn_subnet_clone);
                    if let Err(error) = inner.firewall.start(
                        redirect_port,
                        &vpn_subnet,
                        &policy_name,
                        cached_mark.as_deref(),
                    ) {
                        eprintln!("hincyray: firewall start failed: {error}");
                    } else {
                        // Persist discovered policy mark + tproxy availability.
                        if let Some(ref mark) = inner.firewall.policy_mark {
                            inner.state.split_routing.policy_mark = Some(mark.clone());
                        }
                        inner.state.split_routing.tproxy_available =
                            inner.firewall.tproxy_available;
                        inner.dirty = true;
                        eprintln!("hincyray: firewall started by watchdog");
                    }
                } else {
                    // Check and reinstall iptables rules wiped by ndm.
                    let tproxy_avail = {
                        let inner = lock(&daemon.inner);
                        inner.firewall.tproxy_available
                    };
                    if !firewall_rules_exist(tproxy_avail) {
                        eprintln!("hincyray: iptables rules missing, reinstalling via ndm hook...");
                        // Run the ndm hook script to reinstall rules.
                        let _ = Command::new("sh")
                            .arg("/opt/etc/ndm/netfilter.d/hincyray.sh")
                            .status();
                        // Also reinstall directly in case the hook script is missing.
                        let mark = cached_mark.unwrap_or_default();
                        if !mark.is_empty() {
                            let _ = install_firewall_rules(
                                &mark,
                                redirect_port,
                                &vpn_subnet,
                                tproxy_avail,
                            );
                            if tproxy_avail {
                                install_tproxy_route();
                            }
                        }
                        eprintln!("hincyray: iptables rules reinstalled");
                    }
                }
            }

            // Observe pinned fallback groups through cheap EC state reads only.
            // This is independent of Phase 3 and never triggers an upstream probe.
            if core_running && let Some(ref addr) = ec_addr {
                observe_pinned_routes(&daemon, addr, ec_secret.as_deref());
            }

            // --- Phase 3: Health check (always) + failover (auto_switch) ---
            // Health check runs on every tick when the core is running and
            // no benchmark is in progress. The `auto_switch` flag controls
            // *what happens on failure*: when enabled, the watchdog switches
            // to the next-best profile; when disabled, it just logs — the
            // Mihomo direct-fallback proxy group already routes traffic to
            // DIRECT when the upstream proxy is unreachable, preventing
            // connection storms.
            if !bench_running && !deep_bench_running && core_running {
                // When proxy groups are enabled, Mihomo handles failover
                // natively via url-test / fallback / load-balance groups.
                // The daemon must NOT restart the core or switch profiles —
                // that would destroy the group's internal state (latency
                // history, selected node, sticky sessions) and cause a
                // traffic blip. Instead, we just log and skip.
                if proxy_group_enabled {
                    // Optionally query the API for group health display.
                    // No action needed — Mihomo url-test runs on its own
                    // interval and switches nodes automatically.
                    if let Some(ref addr) = ec_addr
                        && let Ok(proxies) =
                            mihomo_api_get_json(addr, ec_secret.as_deref(), "/proxies/proxy")
                    {
                        let alive = proxies
                            .get("alive")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        let now_name = proxies.get("now").and_then(Value::as_str).unwrap_or("?");
                        if !alive {
                            eprintln!("hincyray: proxy group not alive (Mihomo handling failover)");
                        } else {
                            // Reset fail counter — group is healthy.
                            let mut inner = lock(&daemon.inner);
                            if inner.failover_fail_count > 0 {
                                eprintln!("hincyray: proxy group healthy (now={now_name})");
                            }
                            inner.failover_fail_count = 0;
                            failover_rejected_profiles.clear();
                        }
                    }
                } else if let Some(ref addr) = ec_addr {
                    // v0.19.9: External controller enabled — read Mihomo
                    // fallback group state instead of triggering our own
                    // delay test. Rationale: the auto-generated fallback
                    // group `proxy` already runs a delay test every
                    // `interval` seconds (default 10s) and switches to
                    // DIRECT when proxy-active is unreachable. Triggering
                    // a second delay test from the daemon doubles upstream
                    // load (two `https://www.gstatic.com/generate_204`
                    // requests every 10s) and can worsen upstream
                    // flapping. Instead, we read `now` and `alive` from
                    // `/proxies/proxy` — a cheap loopback EC query. The
                    // fallback group is our source of truth: it knows
                    // better than we do whether proxy-active is healthy.
                    //
                    // Health is `true` only when the fallback group is
                    // `alive` AND currently routing through `proxy-active`
                    // (not DIRECT). When mihomo switches to DIRECT, we
                    // detect that as a proxy failure.
                    let group_state =
                        mihomo_api_get_json(addr, ec_secret.as_deref(), "/proxies/proxy");
                    let active_state =
                        mihomo_api_get_json(addr, ec_secret.as_deref(), "/proxies/proxy-active");
                    let healthy = group_state
                        .as_ref()
                        .ok()
                        .zip(active_state.as_ref().ok())
                        .is_some_and(|(group, active)| {
                            fallback_routes_through_live_active(group, active)
                        });
                    // Read the last known latency from proxy-active history
                    // for logging purposes. This does not trigger a new
                    // upstream request — `history` is populated by the
                    // fallback group's own delay test.
                    let latency_ms: Option<u64> = if healthy {
                        active_state.as_ref().ok().and_then(|v| {
                            v.get("history")
                                .and_then(Value::as_array)
                                .and_then(|h| h.last())
                                .and_then(|last| last.get("delay"))
                                .and_then(Value::as_u64)
                        })
                    } else {
                        None
                    };
                    let failed_active_raw = {
                        let mut inner = lock(&daemon.inner);
                        if healthy {
                            if inner.failover_fail_count > 0 {
                                match latency_ms {
                                    Some(ms) => {
                                        eprintln!("hincyray: health check recovered ({ms}ms)");
                                    }
                                    None => {
                                        eprintln!("hincyray: health check recovered");
                                    }
                                }
                            }
                            inner.failover_fail_count = 0;
                            failover_rejected_profiles.clear();
                            None
                        } else {
                            let prev_count = inner.failover_fail_count;
                            inner.failover_fail_count += 1;
                            const FAILOVER_THRESHOLD: u32 = 3;
                            if prev_count == 0 {
                                let reason = match group_state.as_ref() {
                                    Ok(v) => {
                                        let now =
                                            v.get("now").and_then(Value::as_str).unwrap_or("?");
                                        let alive = v
                                            .get("alive")
                                            .and_then(Value::as_bool)
                                            .unwrap_or(false);
                                        let active_alive = active_state
                                            .as_ref()
                                            .ok()
                                            .and_then(|value| value.get("alive"))
                                            .and_then(Value::as_bool)
                                            .unwrap_or(false);
                                        format!(
                                            "now={now} alive={alive} active_alive={active_alive}"
                                        )
                                    }
                                    Err(error) => error.to_string(),
                                };
                                eprintln!(
                                    "hincyray: health check failed (1/{FAILOVER_THRESHOLD}) — fallback group: {reason}"
                                );
                            }
                            if inner.failover_fail_count >= FAILOVER_THRESHOLD {
                                if auto_switch {
                                    let active_raw = active_profile_id.and_then(|id| {
                                        inner
                                            .state
                                            .profiles
                                            .iter()
                                            .find(|profile| profile.id == id)
                                            .map(|profile| profile.raw.clone())
                                    });
                                    if let Some(ref raw) = active_raw {
                                        record_profile_health_failure(
                                            &mut inner.state,
                                            raw,
                                            unix_now(),
                                        );
                                        inner.dirty = true;
                                    }
                                    inner.failover_fail_count = 0;
                                    active_raw
                                } else {
                                    if prev_count < FAILOVER_THRESHOLD {
                                        eprintln!(
                                            "hincyray: proxy unreachable, \
                                             mihomo fallback to DIRECT (auto-switch disabled)"
                                        );
                                    }
                                    inner.failover_fail_count = FAILOVER_THRESHOLD;
                                    None
                                }
                            } else {
                                None
                            }
                        }
                    };
                    if let Some(failed_raw) = failed_active_raw {
                        let _ = attempt_verified_failover(
                            &daemon,
                            &failed_raw,
                            &mut failover_rejected_profiles,
                        );
                    }
                } else {
                    // Fallback: no external controller, use SOCKS curl.
                    // Note: when the mihomo direct-fallback group switches
                    // to DIRECT, SOCKS health check will pass (through
                    // DIRECT). Enable EC for accurate proxy health monitoring.
                    let healthy = socks_health_check(socks_port);
                    let failed_active_raw = {
                        let mut inner = lock(&daemon.inner);
                        if healthy {
                            if inner.failover_fail_count > 0 {
                                eprintln!("hincyray: health check recovered");
                            }
                            inner.failover_fail_count = 0;
                            failover_rejected_profiles.clear();
                            None
                        } else {
                            let prev_count = inner.failover_fail_count;
                            inner.failover_fail_count += 1;
                            const FAILOVER_THRESHOLD: u32 = 3;
                            if prev_count == 0 {
                                eprintln!("hincyray: health check failed (1/{FAILOVER_THRESHOLD})");
                            }
                            if inner.failover_fail_count >= FAILOVER_THRESHOLD {
                                if auto_switch {
                                    let active_raw = active_profile_id.and_then(|id| {
                                        inner
                                            .state
                                            .profiles
                                            .iter()
                                            .find(|profile| profile.id == id)
                                            .map(|profile| profile.raw.clone())
                                    });
                                    if let Some(ref raw) = active_raw {
                                        record_profile_health_failure(
                                            &mut inner.state,
                                            raw,
                                            unix_now(),
                                        );
                                        inner.dirty = true;
                                    }
                                    inner.failover_fail_count = 0;
                                    active_raw
                                } else {
                                    if prev_count < FAILOVER_THRESHOLD {
                                        eprintln!(
                                            "hincyray: proxy unreachable, \
                                             mihomo fallback to DIRECT (auto-switch disabled)"
                                        );
                                    }
                                    inner.failover_fail_count = FAILOVER_THRESHOLD;
                                    None
                                }
                            } else {
                                None
                            }
                        }
                    };
                    if let Some(failed_raw) = failed_active_raw {
                        let _ = attempt_verified_failover(
                            &daemon,
                            &failed_raw,
                            &mut failover_rejected_profiles,
                        );
                    }
                }
            }

            // --- Phase 4: Auto-benchmark ---
            if auto_bench_hours > 0 && !bench_running {
                let now = unix_now();
                let interval_secs = u64::from(auto_bench_hours) * 3600;
                if now.saturating_sub(last_auto_bench) >= interval_secs {
                    eprintln!("hincyray: auto-benchmark triggered");
                    start_auto_benchmark(&daemon);
                    let mut inner = lock(&daemon.inner);
                    inner.state.last_auto_bench_unix = now;
                    inner.dirty = true;
                }
            }

            // --- Phase 5: Auto-select after benchmark ---
            if bench_was_running && !bench_running && auto_select {
                eprintln!("hincyray: benchmark finished, auto-selecting lowest-latency profile");
                let mut inner = lock(&daemon.inner);
                if let Some(best_id) = find_best_profile(&inner.state, &HashSet::new())
                    && Some(best_id) != inner.state.active_profile_id
                {
                    eprintln!("hincyray: auto-switching to profile {best_id}");
                    switch_active_profile(&mut inner, &daemon, best_id);
                }
            }

            // --- Phase 6: Auto-update check ---
            if auto_update_enabled && core_running && !bench_running {
                let now = unix_now();
                let interval_secs = u64::from(auto_update_interval_hours) * 3600;
                if now.saturating_sub(last_update_check) >= interval_secs {
                    eprintln!("hincyray: auto-update check triggered");
                    match check_latest_mihomo_release(socks_port) {
                        Ok(release) => {
                            let current_version =
                                get_mihomo_version(&mihomo_path).unwrap_or_default();
                            if !current_version.is_empty()
                                && is_newer_version(&current_version, &release.tag_name)
                            {
                                eprintln!(
                                    "hincyray: new Mihomo {} available, auto-installing...",
                                    release.tag_name
                                );
                                match download_and_install_mihomo(
                                    &release,
                                    &mihomo_path,
                                    socks_port,
                                ) {
                                    Ok(new_version) => {
                                        let mut inner = lock(&daemon.inner);
                                        let geo_dir = geo_dir_from_state(&inner.state);
                                        if let Err(e) = inner.core.restart(
                                            &mihomo_path,
                                            &daemon.mihomo_config_path,
                                            geo_dir.as_deref(),
                                        ) {
                                            eprintln!(
                                                "hincyray: core restart after auto-update failed: {e}"
                                            );
                                        }
                                        inner.state.mihomo_version = Some(new_version.clone());
                                        inner.state.update_available_version = None;
                                        inner.state.last_update_check_unix = now;
                                        inner.dirty = true;
                                        eprintln!("hincyray: Mihomo auto-updated to {new_version}");
                                    }
                                    Err(e) => {
                                        eprintln!("hincyray: auto-update install failed: {e}");
                                        let mut inner = lock(&daemon.inner);
                                        inner.state.last_update_check_unix = now;
                                        inner.dirty = true;
                                    }
                                }
                            } else {
                                eprintln!("hincyray: Mihomo is up to date ({current_version})");
                                let mut inner = lock(&daemon.inner);
                                inner.state.last_update_check_unix = now;
                                inner.state.update_available_version = None;
                                if !current_version.is_empty() {
                                    inner.state.mihomo_version = Some(current_version);
                                }
                                inner.dirty = true;
                            }
                        }
                        Err(e) => {
                            eprintln!("hincyray: auto-update check failed: {e}");
                            let mut inner = lock(&daemon.inner);
                            inner.state.last_update_check_unix = now;
                            inner.dirty = true;
                        }
                    }
                }
            }

            // --- Phase 7: Auto-refresh subscriptions ---
            if auto_refresh_enabled
                && auto_refresh_interval_hours > 0
                && !bench_running
                && core_running
            {
                let now = unix_now();
                let interval_secs = u64::from(auto_refresh_interval_hours) * 3600;
                if now.saturating_sub(last_auto_refresh) >= interval_secs {
                    eprintln!("hincyray: auto-refresh subscriptions triggered");
                    let _result = refresh_all_subscriptions(&daemon);

                    // After refresh, check if the active profile was
                    // removed (its raw link no longer exists). If so,
                    // auto-select the best available profile.
                    let mut inner = lock(&daemon.inner);
                    let active_removed = inner
                        .state
                        .active_profile_id
                        .is_some_and(|id| !inner.state.profiles.iter().any(|p| p.id == id));

                    if active_removed || inner.state.active_profile_id.is_none() {
                        if let Some(best_id) = find_best_profile(&inner.state, &HashSet::new()) {
                            eprintln!(
                                "hincyray: auto-refresh: active profile removed, switching to best #{best_id}"
                            );
                            switch_active_profile(&mut inner, &daemon, best_id);
                        } else if let Some(first) = inner.state.profiles.first() {
                            let first_id = first.id;
                            eprintln!(
                                "hincyray: auto-refresh: no tested profiles, switching to first #{first_id}"
                            );
                            switch_active_profile(&mut inner, &daemon, first_id);
                        } else {
                            eprintln!(
                                "hincyray: auto-refresh: no profiles available after refresh"
                            );
                            inner.state.active_profile_id = None;
                        }
                    }

                    inner.state.last_auto_refresh_unix = now;
                    inner.dirty = true;
                }
            }

            // --- Phase 8: Traffic statistics ---
            // Poll Mihomo /traffic every tick (10s) and accumulate
            // cumulative byte counters. Persist every 6 ticks (60s)
            // to avoid writing state.json every 10 seconds.
            if core_running
                && let Some(ref addr) = ec_addr
                && let Ok(traffic) =
                    mihomo_api_stream_get_json(addr, ec_secret.as_deref(), "/traffic")
            {
                let up_kbps = traffic.get("up").and_then(Value::as_u64).unwrap_or(0);
                let down_kbps = traffic.get("down").and_then(Value::as_u64).unwrap_or(0);
                // kbps * 10s = kb during this interval.
                // * 1024 = bytes.
                let up_bytes = up_kbps * 10 * 1024;
                let down_bytes = down_kbps * 10 * 1024;
                let mut inner = lock(&daemon.inner);
                inner.state.traffic_total_up_bytes =
                    inner.state.traffic_total_up_bytes.saturating_add(up_bytes);
                inner.state.traffic_total_down_bytes = inner
                    .state
                    .traffic_total_down_bytes
                    .saturating_add(down_bytes);
                // Mark dirty every 6 ticks (60s) — traffic counters are
                // cumulative, no need to persist every 10s. The flush at
                // the end of the tick will coalesce with any other dirty
                // phase into a single write.
                if watchdog_tick.is_multiple_of(6) {
                    inner.dirty = true;
                }
            }

            // --- Phase 9: Connection log ---
            // Poll Mihomo /connections every 30s for the UI connection log.
            // Auto-VPN learning has its own lossless incremental file source.
            if core_running
                && watchdog_tick.is_multiple_of(3)
                && let Some(ref addr) = ec_addr
                && let Ok(conns) = mihomo_api_get_json(addr, ec_secret.as_deref(), "/connections")
            {
                let now = unix_now();
                let mut new_entries: Vec<ConnectionLogEntry> = Vec::new();
                let mut current_ids: HashSet<String> = HashSet::new();

                if let Some(connections) = conns.get("connections").and_then(Value::as_array) {
                    for conn in connections {
                        let id = conn
                            .get("id")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_owned();
                        if id.is_empty() {
                            continue;
                        }
                        current_ids.insert(id.clone());

                        // Only log connections not already in the
                        // persisted log (check last 50 entries by
                        // host+source_ip to avoid duplicates).
                        let metadata = conn.get("metadata");
                        let host = metadata
                            .and_then(|m| m.get("host"))
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_owned();
                        let source_ip = metadata
                            .and_then(|m| m.get("sourceIP"))
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_owned();
                        let destination_ip = metadata
                            .and_then(|m| m.get("destinationIP"))
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_owned();
                        let destination_port = metadata
                            .and_then(|m| m.get("destinationPort"))
                            .and_then(Value::as_str)
                            .and_then(|port| port.parse::<u16>().ok())
                            .unwrap_or(0);
                        let network = metadata
                            .and_then(|m| m.get("network"))
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_owned();

                        let chains: Vec<String> = conn
                            .get("chains")
                            .and_then(Value::as_array)
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|c| c.as_str().map(str::to_owned))
                                    .collect()
                            })
                            .unwrap_or_default();

                        let rule = conn
                            .get("rule")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_owned();

                        let upload = conn.get("upload").and_then(Value::as_u64).unwrap_or(0);
                        let download = conn.get("download").and_then(Value::as_u64).unwrap_or(0);

                        // Skip connections with no host (likely
                        // internal or DNS traffic).
                        if host.is_empty() {
                            continue;
                        }

                        new_entries.push(ConnectionLogEntry {
                            timestamp: now,
                            host,
                            source_ip,
                            destination_ip,
                            destination_port,
                            network,
                            chains,
                            rule,
                            upload,
                            download,
                        });
                    }
                }

                if !new_entries.is_empty() {
                    let mut inner = lock(&daemon.inner);
                    // Dedup against the last 50 entries by
                    // host+source_ip to avoid logging the same
                    // persistent connection every 30s.
                    let recent: HashSet<(String, String)> = inner
                        .state
                        .connection_log
                        .iter()
                        .rev()
                        .take(50)
                        .map(|e| (e.host.clone(), e.source_ip.clone()))
                        .collect();
                    for entry in new_entries {
                        let key = (entry.host.clone(), entry.source_ip.clone());
                        if !recent.contains(&key) {
                            inner.state.connection_log.push(entry);
                        }
                    }
                    // Trim to cap.
                    if inner.state.connection_log.len() > MAX_CONNECTION_LOG {
                        let excess = inner.state.connection_log.len() - MAX_CONNECTION_LOG;
                        inner.state.connection_log.drain(0..excess);
                    }
                    // connection_log is #[serde(skip)] — not persisted to
                    // state.json. Mark dirty in case other fields changed
                    // in the same tick; the flush is a no-op for the log
                    // itself but coalesces with traffic counter dirty.
                    inner.dirty = true;
                }
            }

            // --- Phase 10: Scheduled maintenance ---
            if maintenance_due(&maintenance, unix_now()) && !bench_running {
                eprintln!("hincyray: scheduled maintenance triggered");
                run_scheduled_maintenance(
                    &daemon,
                    &maintenance,
                    ec_addr.as_deref(),
                    ec_secret.as_deref(),
                );
            }

            // --- Auto VPN exceptions ---
            // Mihomo's EC /logs endpoint is live-only, so periodic stream
            // sampling loses events. Consume every completed line appended
            // to Mihomo's local log instead; the cursor handles rotation and
            // truncation, while the bounded queue bridges 10s reads to 30s
            // probe cycles.
            if core_running && split_enabled && (auto_vpn_learning_enabled || parovozik_enabled) {
                match mihomo_log_cursor.read_new_domains(&mihomo_log_path, parovozik_enabled) {
                    Ok(domains) => {
                        for candidate in domains {
                            if !pending_auto_vpn_domains
                                .iter()
                                .any(|pending| pending.domain == candidate.domain)
                            {
                                if pending_auto_vpn_domains.len() >= MAX_AUTO_VPN_PENDING_DOMAINS {
                                    pending_auto_vpn_domains.pop_front();
                                }
                                pending_auto_vpn_domains.push_back(candidate);
                            }
                        }
                    }
                    Err(error) => eprintln!("hincyray: auto VPN log read failed: {error}"),
                }
            } else {
                pending_auto_vpn_domains.clear();
                mihomo_log_cursor = MihomoLogCursor::start_at_end(&mihomo_log_path);
            }

            if core_running
                && split_enabled
                && (auto_vpn_learning_enabled || parovozik_enabled)
                && watchdog_tick.is_multiple_of(AUTO_VPN_PROBE_INTERVAL_TICKS)
            {
                let batch: Vec<AutoVpnCandidate> =
                    pending_auto_vpn_domains.iter().take(3).cloned().collect();
                let parovozik_ok = !parovozik_enabled
                    || run_parovozik(&daemon, ec_addr.as_deref(), ec_secret.as_deref(), &batch);
                let auto_vpn_ok = !auto_vpn_learning_enabled
                    || run_auto_vpn_learning(
                        &daemon,
                        ec_addr.as_deref(),
                        ec_secret.as_deref(),
                        &batch,
                    );
                if parovozik_ok && auto_vpn_ok {
                    pending_auto_vpn_domains.drain(..batch.len());
                }
            }

            // --- Phase 13: Deep Bench (v0.20) ---
            // Two-phase quality testing on a schedule. Phase A reuses
            // `run_bench()` for the quick scan, Phase B observes each
            // passing server for `stability_minutes` to collect drop
            // rate, latency variance, and unlock capability. Results
            // land in `quality-history.json` for 30-day trend display.
            //
            // The actual work runs on a background thread so the
            // watchdog keeps ticking. Memory gate (mihomo_rss +
            // MemAvailable) is checked before launch; per-step memory
            // checks happen inside Phase B.
            if deep_bench_due_now && !deep_bench_running && !bench_running {
                let mihomo_pid = read_mihomo_pid();
                let mem_ok = memory_gate_allows_bench(mihomo_pid);
                if !mem_ok {
                    eprintln!("hincyray: deep bench due but memory gate closed, skipping");
                } else {
                    // Snapshot inputs under a short lock, then spawn.
                    let (profiles, stability_minutes, profile_filter, mihomo_path) = {
                        let inner = lock(&daemon.inner);
                        (
                            select_profiles_for_deep_bench(&inner.state),
                            inner.state.deep_bench.stability_minutes.max(1),
                            inner.state.deep_bench.profile_filter.clone(),
                            inner.state.mihomo_path.clone(),
                        )
                    };
                    if profiles.is_empty() {
                        eprintln!(
                            "hincyray: deep bench due but no profiles match filter, skipping"
                        );
                    } else {
                        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
                        let started_unix = unix_now();
                        // Mark active + record start in state.
                        {
                            let mut inner = lock(&daemon.inner);
                            inner.deep_bench_active = true;
                            inner.deep_bench_cancel = Some(cancel.clone());
                            inner.deep_bench_status = DeepBenchStatus {
                                state: "phase_a".to_owned(),
                                phase_progress: 0,
                                phase_detail: format!(
                                    "0/{} profiles quick-benched",
                                    profiles.len()
                                ),
                                started_unix,
                                eta_secs: estimate_deep_bench_secs(
                                    profiles.len(),
                                    stability_minutes,
                                ),
                                last_error: String::new(),
                            };
                            inner.state.deep_bench.last_run_unix = started_unix;
                            inner.dirty = true;
                        }
                        let daemon_clone = daemon.clone();
                        let cancel_clone = cancel.clone();
                        let handle = std::thread::Builder::new()
                            .name("hincyray-deep-bench".to_owned())
                            .spawn(move || {
                                run_deep_bench(
                                    daemon_clone,
                                    profiles,
                                    stability_minutes,
                                    profile_filter,
                                    mihomo_path,
                                    cancel_clone,
                                    started_unix,
                                );
                            })
                            .expect("spawn deep bench thread");
                        let mut inner = lock(&daemon.inner);
                        inner.deep_bench_handle = Some(handle);
                    }
                }
            }

            // Reap finished deep bench handle so memory is freed.
            if deep_bench_running {
                let finished = lock(&daemon.inner)
                    .deep_bench_handle
                    .as_ref()
                    .map(|h| h.is_finished())
                    .unwrap_or(true);
                if finished {
                    let mut inner = lock(&daemon.inner);
                    if let Some(h) = inner.deep_bench_handle.take() {
                        let _ = h.join();
                    }
                    inner.deep_bench_cancel = None;
                    inner.deep_bench_active = false;
                }
            }

            // --- End of tick: write-behind flush ---
            // Coalesce all dirty-marked mutations from this tick into a
            // single state.json write. This is the core of write-behind:
            // instead of up to 6 persist_state() calls per tick
            // (6 × 660KB = 3.96MB), we do at most 1 write per tick.
            // If nothing was dirty, zero writes.
            {
                let mut inner = lock(&daemon.inner);
                flush_if_dirty(&mut inner, &daemon.state_path);
            }

            bench_was_running = bench_running;
        }
    });
}

fn fallback_routes_through_live_active(group: &Value, active: &Value) -> bool {
    group.get("alive").and_then(Value::as_bool) == Some(true)
        && group.get("now").and_then(Value::as_str) == Some(PROXY_ACTIVE_NAME)
        && active.get("alive").and_then(Value::as_bool) == Some(true)
}

fn maintenance_due(settings: &MaintenanceSettings, now: u64) -> bool {
    if !settings.enabled {
        return false;
    }
    let interval = u64::from(settings.interval_days.max(1)) * 86_400;
    if settings.last_run_unix > 0 && now.saturating_sub(settings.last_run_unix) < interval {
        return false;
    }
    let target =
        u64::from(settings.hour_utc.min(23)) * 3600 + u64::from(settings.minute_utc.min(59)) * 60;
    let seconds_today = now % 86_400;
    seconds_today >= target && seconds_today < target + 600
}

// =========================================================================
// v0.20: Date/time helpers for Deep Bench scheduling.
//
// We avoid pulling in `chrono` for these few calls — Howard Hinnant's
// civil_from_days algorithm gives us y/m/d from days-since-epoch in
// ~10 lines, and day_of_week falls out for free (1970-01-01 = Thursday
// ⇒ `(days + 4) % 7` with Sunday = 0).
// =========================================================================

/// Day of week from Unix timestamp. Returns 0=Sunday, 1=Monday, …, 6=Saturday.
/// Matches `chrono::Weekday::num_days_from_sunday()`.
fn day_of_week_from_unix(unix: u64) -> u8 {
    let days = unix.div_euclid(86_400);
    // 1970-01-01 was Thursday ⇒ day_of_week(0) == 4.
    ((days + 4) % 7) as u8
}

/// Hour of day (0..=23) in UTC from Unix timestamp.
fn hour_from_unix(unix: u64) -> u8 {
    ((unix % 86_400) / 3600) as u8
}

/// YYYYMMDD packing (e.g. 20260707 for 2026-07-07) from Unix timestamp.
/// Used as the unique-per-day key in `DeepBenchSettings.last_completed_date`.
fn yyyymmdd_from_unix(unix: u64) -> u32 {
    let days = unix.div_euclid(86_400) as i64;
    // Howard Hinnant's civil_from_days:
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y_final = if m <= 2 { y + 1 } else { y };
    (y_final as u32) * 10_000 + (m as u32) * 100 + d as u32
}

/// v0.20: Returns true if a deep bench should start on this tick.
///
/// Conditions (all must hold):
/// 1. `enabled` is true.
/// 2. Current weekday is in the `weekdays` bitmask.
/// 3. Current hour is within `[start_hour, end_hour)` window.
/// 4. `last_completed_date` != today (one-shot per day).
/// 5. Not already running this tick — caller checks `bench_running`
///    and `deep_bench_running` separately to keep this function pure.
fn deep_bench_due(settings: &DeepBenchSettings, now: u64) -> bool {
    if !settings.enabled {
        return false;
    }
    if settings.end_hour <= settings.start_hour {
        return false; // invalid window
    }
    let dow = day_of_week_from_unix(now);
    if settings.weekdays & (1 << dow) == 0 {
        return false;
    }
    let hour = hour_from_unix(now);
    if hour < settings.start_hour || hour >= settings.end_hour {
        return false;
    }
    let today = yyyymmdd_from_unix(now);
    if settings.last_completed_date == today {
        return false;
    }
    // If we started a run today but didn't complete it yet, let it
    // continue (caller decides). But if `last_run_unix` is within
    // the last hour, we treat it as "still possibly running" and
    // don't kick off another — protects against double-spawn if the
    // watchdog thread somehow races.
    if settings.last_run_unix > 0 && now.saturating_sub(settings.last_run_unix) < 3600 {
        return false;
    }
    true
}

/// v0.20: Get the running mihomo PID (0 if not running / not found).
/// Used by memory gate.
fn read_mihomo_pid() -> u32 {
    // pgrep-style scan of /proc — avoids depending on the `pgrep`
    // binary which may not be in PATH on Entware.
    let entries = match std::fs::read_dir("/proc") {
        Ok(e) => e.flatten().collect::<Vec<_>>(),
        Err(_) => return 0,
    };
    for entry in entries {
        let name = entry.file_name();
        let pid: u32 = match name.to_str().and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue,
        };
        let cmdline_path = entry.path().join("cmdline");
        if let Ok(cmdline) = std::fs::read(&cmdline_path)
            && let Some(cmd) = cmdline
                .split(|b| *b == 0)
                .next()
                .and_then(|s| std::str::from_utf8(s).ok())
            && (cmd.ends_with("/mihomo") || cmd == "mihomo")
        {
            return pid;
        }
    }
    0
}

/// v0.20: Memory gate — checks whether it's safe to launch a new
/// bench right now. Returns false if:
/// - mihomo RSS exceeds 200 MB (we'd be competing with a fat core)
/// - MemAvailable is below 80 MB (almost OOM territory on 512 MB)
fn memory_gate_allows_bench(mihomo_pid: u32) -> bool {
    if mihomo_pid > 0
        && let Ok(status) = std::fs::read_to_string(format!("/proc/{mihomo_pid}/status"))
        && let Some(kb) = first_kv_kb(&status, "VmRSS:")
        && kb > 200 * 1024
    {
        return false;
    }
    if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo")
        && let Some(kb) = first_kv_kb(&meminfo, "MemAvailable:")
        && kb < 80 * 1024
    {
        return false;
    }
    true
}

/// v0.20: helper — read the integer after `prefix:` (kB) from a
/// /proc-style `Key:\tVALUE kB` line. Returns `None` on miss.
fn first_kv_kb(text: &str, prefix: &str) -> Option<u64> {
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(prefix)
            && let Some(s) = rest.split_whitespace().next()
            && let Ok(kb) = s.parse::<u64>()
        {
            return Some(kb);
        }
    }
    None
}

/// v0.20: Filter the profile list according to the Deep Bench selector.
/// Normal All/Subscription scopes exclude Dead Servers. Explicit raw scope is
/// deliberate diagnostics/recovery and may include dead profiles.
fn select_profiles_for_deep_bench(state: &HincyrayState) -> Vec<Profile> {
    match &state.deep_bench.profile_filter {
        ProfileFilter::All => state
            .profiles
            .iter()
            .filter(|profile| !profile_is_dead(state, profile))
            .cloned()
            .collect(),
        ProfileFilter::Subscription(url) => state
            .profiles
            .iter()
            .filter(|profile| {
                profile.group.as_deref() == Some(url.as_str()) && !profile_is_dead(state, profile)
            })
            .cloned()
            .collect(),
        ProfileFilter::Explicit(server_refs) => {
            let set: std::collections::HashSet<&String> = server_refs.iter().collect();
            state
                .profiles
                .iter()
                .filter(|profile| set.contains(&profile_server_ref(profile)))
                .cloned()
                .collect()
        }
    }
}

/// v0.20: Rough ETA for the full deep bench (Phase A + Phase B).
/// Phase A: ~30 seconds per profile (parallel x2 on router).
/// Phase B: stability_minutes × 60 seconds per profile (sequential).
/// Returned in seconds; UI formats as `~3h 35m`.
fn estimate_deep_bench_secs(profile_count: usize, stability_minutes: u32) -> u64 {
    let phase_a = (profile_count as u64) * 30 / 2; // parallel x2
    let phase_b = (profile_count as u64) * u64::from(stability_minutes) * 60;
    phase_a + phase_b
}

/// v0.20: Deep Bench orchestrator. Runs Phase A (quick bench on all
/// selected profiles via `run_bench`) and Phase B (stability + unlock
/// test sequentially on each passing profile via `run_stability_and_unlock`),
/// then writes the results to `quality-history.json`.
///
/// The function blocks the worker thread but never the watchdog — the
/// watchdog launched us on a dedicated thread. `cancel` is honoured at
/// every step so `/api/deep-bench/cancel` or graceful shutdown stops
/// us promptly.
fn run_deep_bench(
    daemon: Daemon,
    profiles: Vec<Profile>,
    stability_minutes: u32,
    _filter: ProfileFilter,
    _mihomo_path: String,
    cancel: Arc<std::sync::atomic::AtomicBool>,
    started_unix: u64,
) {
    eprintln!(
        "hincyray: deep bench started ({} profiles, {}m stability)",
        profiles.len(),
        stability_minutes
    );
    let total_profiles = profiles.len();
    let today = yyyymmdd_from_unix(started_unix);

    // ===== Phase A: quick bench via run_bench =====
    let probe_url = crate::benchmark::DEFAULT_PROBE_URL.to_owned();
    let download_url = crate::benchmark::DEFAULT_DOWNLOAD_URL.to_owned();
    let upload_url = crate::benchmark::DEFAULT_UPLOAD_URL.to_owned();
    let job: SharedJob = Arc::new(Mutex::new(BenchJob {
        running: true,
        method: Some(BenchMethod::Tcp),
        total: total_profiles,
        completed: 0,
        current_profile_id: None,
        current_profile_name: None,
        last_updated: started_unix,
        cancel_requested: false,
        results: Vec::new(),
    }));
    let on_result: Box<dyn Fn(crate::benchmark::BenchResult) + Send> = Box::new(|_| {});
    // Update status to Phase A.
    {
        let mut inner = lock(&daemon.inner);
        inner.deep_bench_status = DeepBenchStatus {
            state: "phase_a".to_owned(),
            phase_progress: 0,
            phase_detail: format!("0/{total_profiles} profiles quick-benched"),
            started_unix,
            eta_secs: estimate_deep_bench_secs(total_profiles, stability_minutes),
            last_error: String::new(),
        };
    }
    let handle = crate::benchmark::run_bench(
        profiles.clone(),
        BenchMethod::Tcp,
        probe_url,
        download_url,
        upload_url,
        "mihomo".to_owned(),
        None,
        /* test_download */ true,
        /* test_upload */ false,
        job.clone(),
        cancel.clone(),
        on_result,
    );
    if let Err(error) = handle.join() {
        eprintln!("hincyray: deep bench phase A worker panicked: {error:?}");
    }
    let phase_a_results = job.lock().map(|v| v.results.clone()).unwrap_or_default();
    eprintln!(
        "hincyray: deep bench phase A complete ({} results)",
        phase_a_results.len()
    );

    if cancel.load(std::sync::atomic::Ordering::Relaxed) {
        finish_deep_bench_cancelled(&daemon, started_unix);
        return;
    }

    // Filter: keep profiles that passed Phase A.
    let passed: Vec<&Profile> = profiles
        .iter()
        .filter(|p| {
            phase_a_results
                .iter()
                .find(|r| r.profile_raw == p.raw)
                .map(|r| r.success)
                .unwrap_or(false)
        })
        .collect();
    eprintln!(
        "hincyray: deep bench phase B starts ({} of {} passed)",
        passed.len(),
        total_profiles
    );

    // ===== Phase B: stability + unlock sequentially =====
    let mut snapshots: Vec<DailyQualitySnapshot> = Vec::with_capacity(passed.len());
    for (idx, profile) in passed.iter().enumerate() {
        if cancel.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        // Memory gate before each step.
        if !memory_gate_allows_bench(read_mihomo_pid()) {
            eprintln!(
                "hincyray: deep bench phase B paused (memory gate), retrying in 60s [{}/{}]",
                idx + 1,
                passed.len()
            );
            for _ in 0..60 {
                if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
            if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            if !memory_gate_allows_bench(read_mihomo_pid()) {
                eprintln!("hincyray: deep bench phase B aborted (memory gate still closed)");
                break;
            }
        }
        // Update status.
        {
            let mut inner = lock(&daemon.inner);
            let progress = ((idx + 1) * 100 / passed.len().max(1)).min(100) as u32;
            inner.deep_bench_status = DeepBenchStatus {
                state: "phase_b".to_owned(),
                phase_progress: progress,
                phase_detail: format!("{}/{} stability: {}", idx + 1, passed.len(), profile.name),
                started_unix,
                eta_secs: estimate_deep_bench_secs_remaining(
                    idx + 1,
                    passed.len(),
                    stability_minutes,
                ),
                last_error: String::new(),
            };
        }
        let phase_a_success = phase_a_results
            .iter()
            .find(|r| r.profile_raw == profile.raw)
            .is_some_and(|r| r.success);
        match crate::benchmark::run_stability_and_unlock(profile, stability_minutes, &cancel) {
            Some((stability, unlock)) => {
                snapshots.push(DailyQualitySnapshot {
                    date: today,
                    server_ref: profile_server_ref(profile),
                    profile_name: profile.name.clone(),
                    phase_a_success,
                    stability: Some(stability),
                    unlock: Some(unlock),
                });
            }
            None => {
                // Profile passed Phase A but failed Phase B spawn —
                // Record the failed Phase B attempt without synthesizing a score.
                snapshots.push(DailyQualitySnapshot {
                    date: today,
                    server_ref: profile_server_ref(profile),
                    profile_name: profile.name.clone(),
                    phase_a_success,
                    stability: None,
                    unlock: None,
                });
            }
        }
    }

    if cancel.load(std::sync::atomic::Ordering::Relaxed) {
        // Still persist partial results — better than losing them.
        eprintln!(
            "hincyray: deep bench cancelled, persisting {}/{} phase B snapshots",
            snapshots.len(),
            passed.len()
        );
    } else {
        eprintln!(
            "hincyray: deep bench phase B complete ({} snapshots)",
            snapshots.len()
        );
    }

    // ===== Persist raw quality history =====
    {
        let mut inner = lock(&daemon.inner);
        if inner.state.quality_history.is_empty() {
            inner.state.quality_history =
                load_quality_history(&daemon.state_path, &inner.state.profiles);
        }
        // Append to in-memory quality_history.
        inner.state.quality_history.extend(snapshots.clone());
        cap_quality_history(&mut inner.state, today);
        // Persist to dedicated file (state.json would bloat).
        let history_path = quality_history_path(&daemon.state_path);
        if let Err(error) = persist_quality_history(&history_path, &inner.state.quality_history) {
            eprintln!("hincyray: quality history persist failed: {error}");
            inner.deep_bench_status.last_error = format!("quality history persist failed: {error}");
        }
        // Mark deep bench completed.
        inner.state.deep_bench.last_completed_date = today;
        let final_state = if cancel.load(std::sync::atomic::Ordering::Relaxed) {
            "cancelled"
        } else {
            "completed"
        };
        inner.deep_bench_status = DeepBenchStatus {
            state: final_state.to_owned(),
            phase_progress: 100,
            phase_detail: format!(
                "{} snapshots written to quality-history.json",
                snapshots.len()
            ),
            started_unix,
            eta_secs: 0,
            last_error: inner.deep_bench_status.last_error.clone(),
        };
        inner.dirty = true;
    }
}

/// v0.20: Abort handler — marks deep bench as cancelled without
/// touching history (no partial results on hard-cancel before any
/// Phase A output).
fn finish_deep_bench_cancelled(daemon: &Daemon, started_unix: u64) {
    let mut inner = lock(&daemon.inner);
    inner.state.deep_bench.last_completed_date = yyyymmdd_from_unix(started_unix);
    inner.deep_bench_status = DeepBenchStatus {
        state: "cancelled".to_owned(),
        phase_progress: 0,
        phase_detail: "cancelled during phase A".to_owned(),
        started_unix,
        eta_secs: 0,
        last_error: String::new(),
    };
    inner.dirty = true;
}

/// v0.20: Compute remaining ETA for Phase B at step `idx` of `total`.
fn estimate_deep_bench_secs_remaining(idx: usize, total: usize, stability_minutes: u32) -> u64 {
    let remaining = total.saturating_sub(idx) as u64;
    remaining * u64::from(stability_minutes) * 60
}

/// v0.20: Path to the quality-history file (sibling of state.json).
fn quality_history_path(state_path: &Path) -> PathBuf {
    let mut p = state_path.to_path_buf();
    p.set_file_name("quality-history.json");
    p
}

/// v0.20: Write quality history to a dedicated JSON file. Atomic
/// (write to .tmp + rename) so a partial write never corrupts history.
fn persist_quality_history(path: &Path, history: &[DailyQualitySnapshot]) -> Result<(), String> {
    let json = serde_json::to_string(history).map_err(|e| format!("serialize: {e}"))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir: {e}"))?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, &json).map_err(|e| format!("write: {e}"))?;
    fs::rename(&tmp, path).map_err(|e| format!("rename: {e}"))
}

/// v0.20: Lazy-load quality history from disk into state on first
/// access. Called by `/api/deep-bench/history` if empty.
fn load_quality_history(state_path: &Path, profiles: &[Profile]) -> Vec<DailyQualitySnapshot> {
    let path = quality_history_path(state_path);
    match std::fs::read_to_string(&path) {
        Ok(s) => {
            let mut history: Vec<DailyQualitySnapshot> =
                serde_json::from_str(&s).unwrap_or_default();
            let mut changed = false;
            for snapshot in &mut history {
                let (server_ref, migrated) = migrate_lifecycle_ref(&snapshot.server_ref, profiles);
                if migrated {
                    snapshot.server_ref = server_ref;
                    changed = true;
                }
            }
            if changed && let Err(error) = persist_quality_history(&path, &history) {
                eprintln!(
                    "hincyray: failed to persist quality history identity migration: {error}"
                );
            }
            history
        }
        Err(_) => Vec::new(),
    }
}

/// v0.20: Cap quality history at 30 days × (current profile count + 100)
/// to bound file growth on USB flash. Drops oldest entries first.
fn cap_quality_history(state: &mut HincyrayState, today: u32) {
    let keep_days = 30u32;
    let cutoff = today.saturating_sub(keep_days);
    state.quality_history.retain(|s| s.date >= cutoff);
    // Hard cap on total entries as a safety net.
    let max_entries = (state.profiles.len() + 100) * 30;
    if state.quality_history.len() > max_entries {
        let excess = state.quality_history.len() - max_entries;
        state.quality_history.drain(0..excess);
    }
}

/// v0.20: Garbage-collect trash entries for raws that no longer appear
/// in any profile AND were promoted more than 90 days ago. Returns
/// the number of purged entries.
fn purge_stale_trash(state: &mut HincyrayState) -> usize {
    let now = unix_now();
    let cutoff = now.saturating_sub(90 * 86_400);
    let live_refs: HashSet<String> = state.profiles.iter().map(profile_server_ref).collect();
    let before = state.dead_server_refs.len();
    state.dead_server_refs.retain(|server_ref| {
        // Keep if still in profiles OR promoted recently.
        if live_refs.contains(server_ref) {
            return true;
        }
        state
            .dead_promoted_at
            .get(server_ref)
            .copied()
            .map(|t| t > cutoff)
            .unwrap_or(false)
    });
    state
        .dead_promoted_at
        .retain(|server_ref, _| state.dead_server_refs.contains(server_ref));
    before.saturating_sub(state.dead_server_refs.len())
}

fn run_scheduled_maintenance(
    daemon: &Daemon,
    settings: &MaintenanceSettings,
    ec_addr: Option<&str>,
    ec_secret: Option<&str>,
) {
    if settings.create_backup {
        let inner = lock(&daemon.inner);
        if let Err(error) = create_state_backup(&daemon.state_path, &inner.state, "maintenance") {
            eprintln!("hincyray: maintenance backup failed: {error}");
        }
    }
    if settings.refresh_subscriptions {
        let _ = refresh_all_subscriptions(daemon);
    }
    if settings.close_connections
        && let Some(addr) = ec_addr
        && let Err(error) = mihomo_api_delete(addr, ec_secret, "/connections")
    {
        eprintln!("hincyray: maintenance connection close failed: {error}");
    }
    {
        let mut inner = lock(&daemon.inner);
        if settings.restart_core
            && inner.core.is_running()
            && let Err(error) = restart_core_locked(&mut inner, daemon)
        {
            eprintln!("hincyray: maintenance core restart failed: {error}");
        }
        inner.state.maintenance.last_run_unix = unix_now();
        // Mark dirty — the watchdog tick will flush this along with any
        // other pending changes in the same tick.
        inner.dirty = true;
    }
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
    let services: &[(&str, &str, &[&str], &str)] = &[
        // ── Services (geosite: prefix) ──
        (
            "youtube",
            "YouTube",
            &["youtube", "googlevideo", "ytimg"],
            "service",
        ),
        ("netflix", "Netflix", &["netflix"], "service"),
        ("twitch", "Twitch", &["twitch"], "service"),
        ("spotify", "Spotify", &["spotify"], "service"),
        ("telegram", "Telegram", &["telegram"], "service"),
        ("discord", "Discord", &["discord"], "service"),
        ("openai", "OpenAI", &["openai"], "service"),
        ("google", "Google", &["google"], "service"),
        ("apple", "Apple", &["apple"], "service"),
        ("microsoft", "Microsoft", &["microsoft"], "service"),
        ("steam", "Steam", &["steam"], "service"),
        ("reddit", "Reddit", &["reddit"], "service"),
        ("twitter", "Twitter/X", &["twitter"], "service"),
        ("facebook", "Facebook", &["facebook"], "service"),
        ("instagram", "Instagram", &["instagram"], "service"),
        ("tiktok", "TikTok", &["tiktok"], "service"),
        ("disney", "Disney+", &["disney"], "service"),
        ("hbo", "HBO Max", &["hbo"], "service"),
        ("amazon", "Amazon", &["amazon"], "service"),
        ("github", "GitHub", &["github"], "service"),
        ("cloudflare", "Cloudflare", &["cloudflare"], "service"),
        ("vk", "VK", &["vk"], "service"),
        ("yandex", "Yandex", &["yandex"], "service"),
        // ── Domain zones (bare suffix, no geosite: prefix) ──
        ("ru", ".ru", &["ru"], "zone"),
        ("rf", ".рф", &["xn--p1ai"], "zone"),
        (
            "category-ru",
            "RU все (GEOSITE)",
            &["category-ru"],
            "geosite-zone",
        ),
    ];
    services
        .iter()
        .map(|&(id, name, geosite, group)| {
            json!({"id": id, "name": name, "geosite": geosite, "group": group})
        })
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
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: {content_type}\r\nContent-Length: {len}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'\r\nConnection: close\r\n\r\n",
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
        204 => "No Content",
        202 => "Accepted",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        409 => "Conflict",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn test_daemon() -> (TempDir, Daemon) {
        let dir = TempDir::new().expect("temp dir");
        let state_path = dir.path().join("state.json");
        let mihomo_config_path = dir.path().join("mihomo-config.yaml");
        // Point the daemon at a no-op executable so tests that restart the
        // core (e.g. profile activation) don't fail just because `mihomo` is
        // not installed in the test environment.
        let state = HincyrayState {
            mihomo_path: "/usr/bin/true".to_owned(),
            ..HincyrayState::default()
        };
        let daemon = Daemon::new(state, state_path, mihomo_config_path);
        (dir, daemon)
    }

    fn wait_for_geobase(daemon: &Daemon) -> GeoBaseRuntimeStatus {
        for _ in 0..200 {
            let status = lock(&daemon.inner).geobase.status.clone();
            if !status.running {
                return status;
            }
            thread::sleep(Duration::from_millis(5));
        }
        panic!("GeoBase job did not finish");
    }

    fn set_geobase_analyzer(
        daemon: &Daemon,
        analyzer: impl Fn(&str) -> Classification + Send + Sync + 'static,
    ) {
        lock(&daemon.inner).geobase.analyzer = Some(Arc::new(analyzer));
    }

    fn http_request(daemon: Daemon, request: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            handle_connection(stream, &daemon).expect("handle request");
        });
        let mut client = TcpStream::connect(address).expect("connect");
        client.write_all(request.as_bytes()).expect("write request");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("shutdown write");
        let mut response = String::new();
        client.read_to_string(&mut response).expect("read response");
        worker.join().expect("server thread");
        response
    }

    #[test]
    fn split_routing_new_defaults_are_conservative() {
        let defaults = SplitRoutingSettings::default();
        assert!(!defaults.auto_vpn_learning_enabled);
        assert_eq!(defaults.ru_direct_mode, "off");

        let absent: SplitRoutingSettings = serde_json::from_str("{}").expect("deserialize");
        assert!(!absent.auto_vpn_learning_enabled);
        let explicit: SplitRoutingSettings =
            serde_json::from_str(r#"{"auto_vpn_learning_enabled":true}"#)
                .expect("deserialize explicit values");
        assert!(explicit.auto_vpn_learning_enabled);
    }

    #[test]
    fn persisted_legacy_split_routing_missing_experimental_fields_keeps_old_true_defaults() {
        let mut value = serde_json::to_value(HincyrayState::default()).expect("state JSON");
        {
            let split = value["split_routing"]
                .as_object_mut()
                .expect("split routing object");
            split.remove("auto_vpn_learning_enabled");
            split.remove("ru_direct_mode");
        }
        let state = deserialize_persisted_state(&value.to_string()).expect("legacy state");
        assert!(state.split_routing.auto_vpn_learning_enabled);
        assert_eq!(state.split_routing.ru_direct_mode, "geosite");

        let split = value["split_routing"]
            .as_object_mut()
            .expect("split routing object");
        split.insert("auto_vpn_learning_enabled".to_owned(), Value::Bool(false));
        split.insert("ru_direct_mode".to_owned(), Value::String("off".to_owned()));
        let explicit = deserialize_persisted_state(&value.to_string()).expect("explicit state");
        assert!(!explicit.split_routing.auto_vpn_learning_enabled);
        assert_eq!(explicit.split_routing.ru_direct_mode, "off");
    }

    #[test]
    fn geobase_probe_error_classification_only_aborts_systemic_failures() {
        assert!(is_systemic_geobase_probe_error("cancelled"));
        assert!(is_systemic_geobase_probe_error(
            "GeoBase job exceeded 30 minute deadline"
        ));
        assert!(is_systemic_geobase_probe_error(
            "GeoBase probe client: TLS backend unavailable"
        ));
        assert!(!is_systemic_geobase_probe_error(
            "DNS lookup failed for blocked.example: not found"
        ));
        assert!(!is_systemic_geobase_probe_error(
            "DNS lookup timed out for blocked.example"
        ));
    }

    #[test]
    fn geobase_manual_analysis_reports_coherent_status_and_persists() {
        let (_dir, daemon) = test_daemon();
        set_geobase_analyzer(&daemon, |domain| {
            if domain.starts_with("direct") {
                Classification::Direct
            } else {
                Classification::Active
            }
        });
        let (code, _, body) = handle_geobases_analyze(
            r#"{"id":"regional","name":"Regional","source":{"kind":"manual","value":"test list"},"content":"direct.example\nactive.example\n"}"#,
            &daemon,
        );
        assert_eq!(code, 202);
        let started: Value = serde_json::from_str(&body).expect("start JSON");
        assert_eq!(started["runtime"]["running"], true);
        assert_eq!(started["runtime"]["id"], "regional");
        assert!(started["runtime"]["job_id"].as_u64().unwrap_or(0) > 0);

        let status = wait_for_geobase(&daemon);
        assert_eq!(status.phase, "complete");
        assert_eq!(status.total, 2);
        assert_eq!(status.completed, 2);
        assert_eq!(status.direct, 1);
        assert_eq!(status.active, 1);
        assert_eq!(status.unresolved, 0);
        assert_eq!(status.progress_percent, 100);
        let (code, _, body) = handle_geobases_get(&daemon);
        assert_eq!(code, 200);
        let response: Value = serde_json::from_str(&body).expect("GET JSON");
        assert_eq!(response["manifest"]["bases"][0]["id"], "regional");
        assert_eq!(response["bases"][0]["id"], "regional");
        assert_eq!(response["requires_apply"], true);
        assert_eq!(response["runtime"]["running"], false);
    }

    #[test]
    fn geobase_source_wire_contract_matches_ui_payloads() {
        let (_dir, daemon) = test_daemon();
        set_geobase_analyzer(&daemon, |_| Classification::Direct);
        let upload = r#"{"id":"upload","name":"Upload","source":{"kind":"upload","value":"routes.txt"},"content":"upload.example\n"}"#;
        assert_eq!(handle_geobases_analyze(upload, &daemon).0, 202);
        assert_eq!(wait_for_geobase(&daemon).phase, "complete");
        let manual = r#"{"id":"manual","name":"Manual","source":{"kind":"manual","value":"editor"},"content":"manual.example\n"}"#;
        assert_eq!(handle_geobases_analyze(manual, &daemon).0, 202);
        assert_eq!(wait_for_geobase(&daemon).phase, "complete");
        let url_with_content = r#"{"name":"URL","source":{"kind":"url","value":"https://127.0.0.1/routes.txt"},"content":"forbidden.example\n"}"#;
        assert_eq!(handle_geobases_analyze(url_with_content, &daemon).0, 400);
        let missing_content = r#"{"name":"Manual","source":{"kind":"manual","value":"editor"}}"#;
        assert_eq!(handle_geobases_analyze(missing_content, &daemon).0, 400);
        let ssrf =
            r#"{"name":"URL","source":{"kind":"url","value":"https://127.0.0.1/routes.txt"}}"#;
        assert_eq!(handle_geobases_analyze(ssrf, &daemon).0, 202);
        let status = wait_for_geobase(&daemon);
        assert_eq!(status.phase, "error");
        assert!(
            status
                .error
                .as_deref()
                .is_some_and(|error| error.contains("non-public"))
        );
    }

    #[test]
    fn geobase_panicking_analyzer_cleans_up_after_joining_all_workers() {
        let (_dir, daemon) = test_daemon();
        let finished = Arc::new(AtomicUsize::new(0));
        let observed = finished.clone();
        set_geobase_analyzer(&daemon, move |domain| {
            if domain == "panic.example" {
                panic!("analyzer boom");
            }
            thread::sleep(Duration::from_millis(20));
            observed.fetch_add(1, Ordering::SeqCst);
            Classification::Direct
        });
        let request = r#"{"id":"panic-base","name":"Panic","source":{"kind":"manual","value":"test"},"content":"a.example\nb.example\nc.example\npanic.example\n"}"#;
        assert_eq!(handle_geobases_analyze(request, &daemon).0, 202);
        let status = wait_for_geobase(&daemon);
        assert_eq!(status.phase, "error");
        assert!(
            status
                .error
                .as_deref()
                .is_some_and(|error| error.contains("analyzer boom"))
        );
        assert_eq!(finished.load(Ordering::SeqCst), 3);
        let inner = lock(&daemon.inner);
        assert!(inner.geobase.cancel.is_none());
        assert!(inner.geobase.current_job_id.is_none());
    }

    #[test]
    fn geobase_shutdown_requests_cancel_and_joins_worker() {
        let (_dir, daemon) = test_daemon();
        set_geobase_analyzer(&daemon, |_| {
            thread::sleep(Duration::from_millis(25));
            Classification::Direct
        });
        let request = r#"{"id":"shutdown","name":"Shutdown","source":{"kind":"manual","value":"test"},"content":"a.example\nb.example\nc.example\nd.example\ne.example\n"}"#;
        assert_eq!(handle_geobases_analyze(request, &daemon).0, 202);
        cancel_and_join_geobase(&daemon);
        let inner = lock(&daemon.inner);
        assert!(!inner.geobase.status.running);
        assert_eq!(inner.geobase.status.phase, "cancelled");
        assert!(inner.geobase.handle.is_none());
        assert!(inner.geobase.cancel.is_none());
    }

    #[test]
    fn geobase_allows_only_one_job_and_cancel_is_observable() {
        let (_dir, daemon) = test_daemon();
        set_geobase_analyzer(&daemon, |_| {
            thread::sleep(Duration::from_millis(100));
            Classification::Direct
        });
        let request = r#"{"id":"slow","name":"Slow","source":{"kind":"manual","value":"test"},"content":"one.example\ntwo.example\nthree.example\nfour.example\nfive.example\n"}"#;
        assert_eq!(handle_geobases_analyze(request, &daemon).0, 202);
        assert_eq!(handle_geobases_analyze(request, &daemon).0, 409);
        assert_eq!(handle_geobases_cancel(&daemon).0, 200);
        let status = wait_for_geobase(&daemon);
        assert_eq!(status.phase, "cancelled");
        assert!(
            geobase_store(&daemon)
                .load_manifest()
                .expect("manifest")
                .bases
                .is_empty()
        );
    }

    #[test]
    fn geobase_enable_and_delete_update_manifest() {
        let (_dir, daemon) = test_daemon();
        set_geobase_analyzer(&daemon, |_| Classification::Direct);
        let request = r#"{"id":"managed","name":"Managed","source":{"kind":"manual","value":"test"},"content":"one.example\n"}"#;
        assert_eq!(handle_geobases_analyze(request, &daemon).0, 202);
        assert_eq!(wait_for_geobase(&daemon).phase, "complete");
        assert_eq!(
            handle_geobases_enabled(r#"{"id":"managed","enabled":false}"#, &daemon).0,
            200
        );
        let manifest = geobase_store(&daemon).load_manifest().expect("manifest");
        assert!(!manifest.bases[0].enabled);
        assert_eq!(manifest.bases[0].status, GeoBaseStatus::Disabled);
        assert_eq!(
            handle_geobases_delete(r#"{"id":"managed"}"#, &daemon).0,
            200
        );
        assert!(
            geobase_store(&daemon)
                .load_manifest()
                .expect("manifest")
                .bases
                .is_empty()
        );
    }

    fn geobase_config_state() -> HincyrayState {
        let mut state = HincyrayState {
            profiles: vec![Profile {
                id: 0,
                name: "active".to_owned(),
                protocol: crate::profiles::Protocol::Vless,
                address: "proxy.example".to_owned(),
                port: Some(443),
                raw: "vless://11111111-1111-1111-1111-111111111111@proxy.example:443#active"
                    .to_owned(),
                selected: true,
                block_quic: false,
                group: None,
            }],
            active_profile_id: Some(0),
            ..HincyrayState::default()
        };
        state.split_routing.enabled = true;
        state.routing_rules = vec![RoutingRule {
            enabled: true,
            name: "user-first".to_owned(),
            target: "direct".to_owned(),
            domains: vec!["user.example".to_owned()],
            port_mode: "include".to_owned(),
            ..RoutingRule::default()
        }];
        state
    }

    fn geobase_config_state_for(daemon: &Daemon) -> HincyrayState {
        let mut state = geobase_config_state();
        state.split_routing.geo_asset_path = daemon
            .state_path
            .parent()
            .expect("state parent")
            .to_string_lossy()
            .into_owned();
        state
    }

    fn create_geobase_config_generation(daemon: &Daemon, id: &str, enabled: bool) {
        geobase_store(daemon)
            .create(
                GeoBaseUpsertRequest {
                    id: id.to_owned(),
                    name: id.to_owned(),
                    source: GeoBaseSource {
                        kind: GeoBaseSourceKind::Manual,
                        value: "integration test".to_owned(),
                    },
                    enabled,
                },
                b"active.example\ndirect.example\n1.1.1.0/24\n8.8.8.0/24\n",
                GeoBaseGenerationInput {
                    classifications: vec![
                        DomainClassification {
                            domain: "active.example".to_owned(),
                            classification: Classification::Active,
                        },
                        DomainClassification {
                            domain: "direct.example".to_owned(),
                            classification: Classification::Direct,
                        },
                    ],
                    static_entries: vec![
                        StaticRouteEntry {
                            network: "1.1.1.0/24".to_owned(),
                            target: Classification::Active,
                        },
                        StaticRouteEntry {
                            network: "8.8.8.0/24".to_owned(),
                            target: Classification::Direct,
                        },
                    ],
                },
            )
            .expect("create GeoBase generation");
    }

    #[test]
    fn geobase_generation_projects_into_authoritative_daemon_config() {
        let (_dir, daemon) = test_daemon();
        create_geobase_config_generation(&daemon, "regional", true);
        create_geobase_config_generation(&daemon, "disabled", false);

        let providers = project_geobase_rule_providers(&daemon, GeoBaseProjection::Desired, false)
            .expect("project providers");
        let base = geobase::stable_id("regional");
        assert_eq!(
            providers
                .iter()
                .map(|provider| provider.name.clone())
                .collect::<Vec<_>>(),
            vec![
                format!("{base}-d"),
                format!("{base}-sa"),
                format!("{base}-sd"),
            ]
        );
        let canonical_store_root =
            fs::canonicalize(&daemon.geobase_store_root).expect("store root");
        assert!(providers.iter().all(|provider| {
            Path::new(&provider.path).is_absolute()
                && Path::new(&provider.path).starts_with(&canonical_store_root)
        }));
        assert!(
            providers
                .iter()
                .all(|provider| !provider.name.starts_with("disabled"))
        );

        let state = geobase_config_state_for(&daemon);
        let desired_yaml = build_daemon_config(&state, &providers).expect("desired config");
        for provider in &providers {
            assert!(desired_yaml.contains(&format!("{}:", provider.name)));
            assert!(desired_yaml.contains(&provider.path));
        }
        assert!(desired_yaml.contains("behavior: domain"));
        assert!(desired_yaml.contains("behavior: ipcidr"));
        assert!(!desired_yaml.contains(&format!("RULE-SET,{base}-a,proxy")));
        assert!(desired_yaml.contains(&format!("RULE-SET,{base}-d,DIRECT")));
        assert!(desired_yaml.contains(&format!("RULE-SET,{base}-sa,proxy")));
        assert!(desired_yaml.contains(&format!("RULE-SET,{base}-sd,DIRECT")));
        let user_rule = desired_yaml
            .find("DOMAIN-SUFFIX,user.example,DIRECT")
            .expect("user rule");
        let managed_rule = desired_yaml
            .find(&format!("RULE-SET,{base}-d,DIRECT"))
            .expect("managed rule");
        assert!(
            user_rule < managed_rule,
            "ordinary user rule must remain first"
        );
    }

    #[test]
    fn geobase_projection_uses_explicit_match_mode_without_locking_daemon_state() {
        let (_dir, daemon) = test_daemon();
        create_geobase_config_generation(&daemon, "regional", true);
        let _inner = lock(&daemon.inner);

        let providers = project_geobase_rule_providers(&daemon, GeoBaseProjection::Desired, false)
            .expect("project providers while daemon state is locked");

        assert!(providers.iter().all(|provider| {
            provider.target != GeoBaseRuleTarget::Active
                || provider.behavior == GeoBaseRuleBehavior::Ipcidr
        }));
    }

    #[test]
    fn pending_geobase_mutations_do_not_change_applied_restart_projection() {
        let (_dir, daemon) = test_daemon();
        create_geobase_config_generation(&daemon, "regional", true);
        let store = geobase_store(&daemon);
        let desired = store.load_manifest().expect("desired manifest");
        assert!(desired.requires_apply());
        assert!(
            project_geobase_rule_providers(&daemon, GeoBaseProjection::Applied, false)
                .expect("applied projection")
                .is_empty()
        );

        store
            .mark_applied(desired.generation)
            .expect("explicit apply snapshot");
        assert!(
            !project_geobase_rule_providers(&daemon, GeoBaseProjection::Applied, false)
                .expect("applied projection")
                .is_empty()
        );
        store.delete("regional").expect("pending delete");
        assert!(
            store
                .load_manifest()
                .expect("pending manifest")
                .requires_apply()
        );
        assert!(
            !project_geobase_rule_providers(&daemon, GeoBaseProjection::Applied, false)
                .expect("deleted base remains applied")
                .is_empty()
        );
        assert!(
            project_geobase_rule_providers(&daemon, GeoBaseProjection::Desired, false)
                .expect("desired projection")
                .is_empty()
        );
    }

    #[test]
    fn geobase_provider_names_are_bounded_and_collision_safe() {
        let first = geobase_provider_name(&format!("a{}", "x".repeat(62)), "sa");
        let second = geobase_provider_name(&format!("a{}", "x".repeat(61)), "sa");
        assert_ne!(first, second);
        assert!(first.len() <= 64);
        assert_ne!(
            geobase_provider_name("base-static", "a"),
            geobase_provider_name("base", "sa")
        );
    }

    #[test]
    fn geobase_projection_uses_actual_mihomo_home() {
        let (_dir, daemon) = test_daemon();
        create_geobase_config_generation(&daemon, "regional", true);
        let mut outside = geobase_config_state();
        outside.split_routing.geo_asset_path = "/definitely/not/the/geobase/store".to_owned();
        let desired = project_geobase_rule_providers(&daemon, GeoBaseProjection::Desired, false)
            .expect("desired providers");
        let error = build_daemon_config(&outside, &desired)
            .expect_err("provider outside actual -d home must fail");
        assert!(error.contains("outside Mihomo home"), "{error}");

        build_daemon_config(&geobase_config_state_for(&daemon), &desired)
            .expect("store below actual home should work");
    }

    #[test]
    fn geobase_tamper_with_same_line_count_is_rejected() {
        let (_dir, daemon) = test_daemon();
        create_geobase_config_generation(&daemon, "regional", true);
        let manifest = geobase_store(&daemon).load_manifest().expect("manifest");
        let path = daemon
            .geobase_store_root
            .join(&manifest.bases[0].lists.active.file);
        fs::write(path, b"other.example\n").expect("tamper artifact");
        let error = project_geobase_rule_providers(&daemon, GeoBaseProjection::Desired, false)
            .expect_err("same-count tamper must fail fingerprint verification");
        assert!(error.contains("fingerprint mismatch"), "{error}");
    }

    #[test]
    fn failed_atomic_publish_preserves_previous_config() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("config.yaml");
        fs::write(&path, b"old bytes").expect("old config");
        let error = atomic_write_config_with(&path, b"new bytes", |_temp, _destination| {
            Err("injected publish failure".to_owned())
        })
        .expect_err("publish must fail");
        assert!(error.contains("injected"));
        assert_eq!(fs::read(path).expect("preserved config"), b"old bytes");
    }

    #[cfg(unix)]
    #[test]
    fn failed_readiness_rolls_back_exact_config_and_generation() {
        let dir = TempDir::new().expect("temp dir");
        let script = dir.path().join("fake-mihomo.sh");
        fs::write(
            &script,
            b"#!/bin/sh\nif [ \"$1\" = \"-t\" ]; then exit 0; fi\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-f\" ]; then shift; cfg=$1; fi; shift; done\nif grep -q OLD \"$cfg\"; then sleep 30; else exit 1; fi\n",
        )
        .expect("fake mihomo");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod");
        let mut state = geobase_config_state();
        state.split_routing.enabled = false;
        state.mihomo_path = script.to_string_lossy().into_owned();
        let daemon = Daemon::new(
            state,
            dir.path().join("state.json"),
            dir.path().join("mihomo-config.yaml"),
        );
        create_geobase_config_generation(&daemon, "rollback", false);
        atomic_write_config(&daemon.mihomo_config_path, b"OLD exact bytes\n").expect("old config");
        {
            let mut inner = lock(&daemon.inner);
            inner
                .core
                .start(
                    script.to_str().expect("script path"),
                    &daemon.mihomo_config_path,
                    None,
                )
                .expect("old core");
        }
        let error = activate_current_config(&daemon, false, false, GeoBaseProjection::Desired)
            .expect_err("new runtime config exits immediately");
        assert!(error.contains("rollback:"), "{error}");
        assert_eq!(
            fs::read(&daemon.mihomo_config_path).expect("rolled back config"),
            b"OLD exact bytes\n"
        );
        assert!(lock(&daemon.inner).core.is_running());
        let manifest = geobase_store(&daemon).load_manifest().expect("manifest");
        assert_ne!(manifest.applied_generation, manifest.generation);
        let _ = lock(&daemon.inner).core.stop();
    }

    #[test]
    fn enabled_geobase_with_missing_artifact_fails_config_generation() {
        let (_dir, daemon) = test_daemon();
        create_geobase_config_generation(&daemon, "regional", true);
        let manifest = geobase_store(&daemon).load_manifest().expect("manifest");
        let active_path = daemon
            .geobase_store_root
            .join(&manifest.bases[0].lists.active.file);
        fs::remove_file(active_path).expect("remove active artifact");

        let error = project_geobase_rule_providers(&daemon, GeoBaseProjection::Desired, false)
            .expect_err("missing enabled artifact must fail");
        assert!(error.contains("missing or inaccessible"), "{error}");
    }

    #[test]
    fn http_parser_rejects_invalid_and_oversized_content_length() {
        let (_dir, daemon) = test_daemon();
        let invalid = http_request(
            daemon.clone(),
            "POST /api/profiles/import HTTP/1.1\r\nContent-Length: nope\r\n\r\n",
        );
        assert!(invalid.starts_with("HTTP/1.1 400"));
        let oversized = http_request(
            daemon,
            &format!(
                "POST /api/profiles/import HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
                MAX_BODY_BYTES + 1
            ),
        );
        assert!(oversized.starts_with("HTTP/1.1 413"));
        assert_eq!(
            request_body_limit("POST", "/api/geobases/analyze"),
            MAX_GEOBASE_ANALYZE_BODY_BYTES
        );
    }

    #[test]
    fn http_parser_rejects_invalid_utf8_body() {
        let (_dir, daemon) = test_daemon();
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            handle_connection(stream, &daemon).expect("handle request");
        });
        let mut client = TcpStream::connect(address).expect("connect");
        client
            .write_all(b"POST /api/geobases/analyze HTTP/1.1\r\nContent-Length: 1\r\n\r\n\xff")
            .expect("write request");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("shutdown write");
        let mut response = String::new();
        client.read_to_string(&mut response).expect("response");
        worker.join().expect("server thread");
        assert!(response.starts_with("HTTP/1.1 400"));
        assert!(response.contains("valid UTF-8"));
    }

    #[test]
    fn geobase_generations_advance_transactionally_and_require_apply() {
        let (_dir, daemon) = test_daemon();
        create_geobase_config_generation(&daemon, "generation", true);
        let store = geobase_store(&daemon);
        let desired = store.load_manifest().expect("manifest");
        assert!(desired.requires_apply());
        let before_failed_apply = desired.applied_generation;
        let (code, _, _) = handle_routing_apply(&daemon);
        assert_ne!(code, 200, "default test state has no active profile");
        assert_eq!(
            store
                .load_manifest()
                .expect("failed apply manifest")
                .applied_generation,
            before_failed_apply
        );
        store
            .mark_applied(desired.generation)
            .expect("authoritative generation acknowledgement");
        assert!(
            !store
                .load_manifest()
                .expect("applied manifest")
                .requires_apply()
        );

        let revision = store.load_manifest().expect("manifest").bases[0].revision;
        store
            .set_enabled("generation", false, Some(revision))
            .expect("transactional disable");
        assert!(
            store
                .load_manifest()
                .expect("disabled manifest")
                .requires_apply()
        );
    }

    #[test]
    #[cfg(unix)]
    fn stopped_core_successful_apply_marks_authoritative_generation() {
        let dir = TempDir::new().expect("temp dir");
        let script = dir.path().join("fake-mihomo.sh");
        fs::write(
            &script,
            b"#!/bin/sh\nif [ \"$1\" = \"-t\" ]; then exit 0; fi\nsleep 30\n",
        )
        .expect("fake mihomo");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod");
        let mut state = geobase_config_state();
        state.mihomo_path = script.to_string_lossy().into_owned();
        state.split_routing.enabled = false;
        let daemon = Daemon::new(
            state,
            dir.path().join("state.json"),
            dir.path().join("mihomo-config.yaml"),
        );
        create_geobase_config_generation(&daemon, "authoritative", true);
        let desired = geobase_store(&daemon)
            .load_manifest()
            .expect("desired manifest")
            .generation;
        assert_eq!(handle_routing_apply(&daemon).0, 200);
        let applied = geobase_store(&daemon)
            .load_manifest()
            .expect("applied manifest");
        assert_eq!(applied.applied_generation, desired);
        assert!(!applied.requires_apply());
        assert!(lock(&daemon.inner).core.is_running());
        let _ = lock(&daemon.inner).core.stop();
    }

    #[test]
    fn routing_preview_requires_apply_for_pending_geobase_with_identical_yaml() {
        let (_dir, daemon) = test_daemon();
        create_geobase_config_generation(&daemon, "pending", true);
        let mut state = geobase_config_state_for(&daemon);
        state.safe_mode_enabled = true;
        let desired = config_plan(&state, &daemon, GeoBaseProjection::Desired)
            .expect("desired config")
            .0;
        atomic_write_config(&daemon.mihomo_config_path, desired.as_bytes()).expect("config");
        {
            let mut inner = lock(&daemon.inner);
            inner.state = state;
            inner.core.child = Some(Command::new("sleep").arg("30").spawn().expect("sleep"));
            inner.firewall.active = true;
        }

        let (status, _, body) = handle_routing_preview(&daemon);
        assert_eq!(status, 200);
        let preview: Value = serde_json::from_str(&body).expect("preview JSON");
        assert_eq!(
            preview["desired_config_sha256"],
            preview["applied_config_sha256"]
        );
        assert_eq!(preview["requires_apply"], true);
        assert!(
            preview["changes"]
                .as_array()
                .expect("changes")
                .iter()
                .any(|change| change
                    .as_str()
                    .is_some_and(|change| change.contains("GeoBase")))
        );
        let mut inner = lock(&daemon.inner);
        let _ = inner.core.stop();
        inner.firewall.active = false;
    }

    #[test]
    fn routing_preview_requires_apply_for_stopped_core_with_identical_config() {
        let (_dir, daemon) = test_daemon();
        let mut state = geobase_config_state_for(&daemon);
        state.split_routing.enabled = false;
        let desired = config_plan(&state, &daemon, GeoBaseProjection::Desired)
            .expect("desired config")
            .0;
        atomic_write_config(&daemon.mihomo_config_path, desired.as_bytes()).expect("config");
        {
            let mut inner = lock(&daemon.inner);
            inner.state = state;
            inner.core.child = Some(Command::new("sleep").arg("30").spawn().expect("sleep"));
        }
        let (_, _, body) = handle_routing_preview(&daemon);
        let applied: Value = serde_json::from_str(&body).expect("applied preview");
        assert_eq!(applied["requires_apply"], false);

        let _ = lock(&daemon.inner).core.stop();
        let (_, _, body) = handle_routing_preview(&daemon);
        let stopped_core: Value = serde_json::from_str(&body).expect("core preview");
        assert_eq!(stopped_core["requires_apply"], true);
        assert!(
            stopped_core["changes"]
                .as_array()
                .expect("changes")
                .iter()
                .any(|change| change
                    .as_str()
                    .is_some_and(|change| change.contains("core is stopped")))
        );
    }

    #[test]
    fn routing_preview_firewall_runtime_matrix_requires_repairs() {
        assert!(!firewall_runtime_requires_apply(true, true, true));
        assert!(firewall_runtime_requires_apply(true, false, false));
        assert!(firewall_runtime_requires_apply(true, true, false));
        assert!(!firewall_runtime_requires_apply(false, false, false));
        assert!(firewall_runtime_requires_apply(false, true, false));
        assert!(firewall_runtime_requires_apply(false, false, true));
    }

    #[test]
    fn routing_preview_requires_apply_to_remove_unwanted_firewall_runtime() {
        let (_dir, daemon) = test_daemon();
        let mut state = geobase_config_state_for(&daemon);
        state.split_routing.enabled = false;
        let desired = config_plan(&state, &daemon, GeoBaseProjection::Desired)
            .expect("desired config")
            .0;
        atomic_write_config(&daemon.mihomo_config_path, desired.as_bytes()).expect("config");
        {
            let mut inner = lock(&daemon.inner);
            inner.state = state;
            inner.core.child = Some(Command::new("sleep").arg("30").spawn().expect("sleep"));
            inner.firewall.active = true;
        }

        let (status, _, body) = handle_routing_preview(&daemon);
        assert_eq!(status, 200);
        let preview: Value = serde_json::from_str(&body).expect("preview JSON");
        assert_eq!(preview["requires_apply"], true);
        assert_eq!(preview["firewall_reload"], true);
        let mut inner = lock(&daemon.inner);
        let _ = inner.core.stop();
        inner.firewall.active = false;
    }

    #[test]
    fn geobase_url_validation_rejects_ssrf_targets() {
        for raw in [
            "http://example.com/list.txt",
            "https://user:pass@example.com/list.txt",
            "https://127.0.0.1/list.txt",
            "https://[::1]/list.txt",
        ] {
            let url = url::Url::parse(raw).expect("URL");
            assert!(validate_geobase_url(&url).is_err(), "accepted {raw}");
        }
        for ip in [
            "10.0.0.1",
            "100.64.0.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "2001:db8::1",
            "ff02::1",
        ] {
            assert!(!is_public_ip(ip.parse().expect("IP")), "accepted {ip}");
        }
        assert!(is_public_ip("1.1.1.1".parse().expect("IP")));
        assert!(is_public_ip("2606:4700:4700::1111".parse().expect("IP")));
    }

    #[test]
    fn geobase_transport_falls_back_and_aggregates_errors() {
        let mut attempts = Vec::new();
        let error = request_geobase_hop(Some("not a proxy URL"), |transport| {
            attempts.push(match transport {
                GeoBaseTransport::Direct => "direct".to_owned(),
                GeoBaseTransport::Socks5h(url) => url.to_owned(),
            });
            Err::<(), _>(match transport {
                GeoBaseTransport::Direct => "send failed".to_owned(),
                GeoBaseTransport::Socks5h(_) => "proxy setup failed".to_owned(),
            })
        })
        .expect_err("both transports must fail");
        assert_eq!(attempts, ["direct", "not a proxy URL"]);
        assert_eq!(error, "[direct] send failed; [socks5h] proxy setup failed");
    }

    #[test]
    fn geobase_malformed_proxy_fails_after_direct_transport_failure() {
        let error = request_geobase_hop(Some("://malformed"), |transport| match transport {
            GeoBaseTransport::Direct => Err("send failed".to_owned()),
            GeoBaseTransport::Socks5h(url) => geobase_proxy_client(url).map(|_| ()),
        })
        .expect_err("malformed proxy must fail");
        assert!(error.starts_with("[direct] send failed; [socks5h] proxy setup:"));
    }

    #[test]
    fn geobase_job_proxy_is_captured_only_while_core_runs() {
        let (_dir, daemon) = test_daemon();
        let mut inner = lock(&daemon.inner);
        assert_eq!(geobase_source_proxy_url(&mut inner), None);

        inner.core.child = Some(
            Command::new("/bin/sleep")
                .arg("10")
                .spawn()
                .expect("spawn test core"),
        );
        assert_eq!(
            geobase_source_proxy_url(&mut inner).as_deref(),
            Some("socks5h://127.0.0.1:10808")
        );
        let _ = inner.core.stop();
        assert_eq!(geobase_source_proxy_url(&mut inner), None);
    }

    #[test]
    fn geobase_http_response_does_not_try_proxy() {
        let mut attempts = 0;
        let status = request_geobase_hop(Some("socks5h://127.0.0.1:10808"), |_| {
            attempts += 1;
            Ok(503)
        })
        .expect("HTTP response is a completed transport request");
        assert_eq!(status, 503);
        assert_eq!(attempts, 1);
    }

    #[test]
    fn geobase_redirect_target_is_revalidated() {
        let current = url::Url::parse("https://example.com/list.txt").expect("URL");
        let next = current.join("https://127.0.0.1/private").expect("redirect");
        assert!(validate_geobase_url(&next).is_err());
    }

    fn auto_candidate(domain: &str, port: Option<u16>) -> AutoVpnCandidate {
        AutoVpnCandidate {
            domain: domain.to_owned(),
            port,
        }
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
        assert_eq!(proxy_info.socks5h_url, "socks5h://127.0.0.1:10808");
        assert_eq!(proxy_info.socks5_url, "socks5://127.0.0.1:10808");
        assert_eq!(
            proxy_info.http_url.as_deref(),
            Some("http://127.0.0.1:10809")
        );
    }

    #[test]
    fn iso_country_code_accepts_only_two_letter_codes() {
        assert_eq!(iso_country_code("ru"), Some("RU".to_owned()));
        assert_eq!(iso_country_code(" NL "), Some("NL".to_owned()));
        assert_eq!(iso_country_code("telegram"), None);
        assert_eq!(iso_country_code("r1"), None);
    }

    #[test]
    fn format_error_combines_multiple_attempt_messages() {
        // Single attempt → error returned as-is.
        let single = SubscriptionLoadOutcome::format_error(&[(
            "direct".to_owned(),
            "https://provider.example/sub/x: connection refused".to_owned(),
        )]);
        assert_eq!(single, "https://provider.example/sub/x: connection refused");

        // Multiple attempts → each prefixed with [label], joined with "; ".
        let attempts = vec![
            (
                "direct".to_owned(),
                "https://v.example/sub: таймаут (30с): ...".to_owned(),
            ),
            (
                "socks5h".to_owned(),
                "https://v.example/sub: TLS handshake failed: ...".to_owned(),
            ),
            (
                "socks5".to_owned(),
                "https://v.example/sub: TLS handshake failed: ...".to_owned(),
            ),
        ];
        let combined = SubscriptionLoadOutcome::format_error(&attempts);
        assert!(combined.contains("[direct]"));
        assert!(combined.contains("[socks5h]"));
        assert!(combined.contains("[socks5]"));
        assert!(combined.contains("таймаут"));
        assert!(combined.contains("TLS handshake failed"));

        // Empty → empty string.
        assert_eq!(SubscriptionLoadOutcome::format_error(&[]), "");
    }

    #[test]
    fn load_subscription_for_daemon_core_stopped_only_direct_attempt() {
        // When the core is NOT running, load_subscription_for_daemon
        // should try only the "direct" path and return a single
        // attempt in the Failed variant.
        let (_dir, daemon) = test_daemon();
        let mut inner = lock(&daemon.inner);
        let proxy_info = proxy_info_for_daemon(&mut inner);
        let hwid = inner.state.hwid_config.clone();
        drop(inner);

        let source = SubscriptionSource {
            url: "http://127.0.0.1:1/sub/never".to_owned(),
        };
        let outcome = load_subscription_for_daemon(&source, &proxy_info, &hwid);
        match outcome {
            SubscriptionLoadOutcome::Failed { attempts } => {
                assert_eq!(
                    attempts.len(),
                    1,
                    "core stopped → only direct attempt, got {attempts:?}"
                );
                assert_eq!(attempts[0].0, "direct");
            }
            SubscriptionLoadOutcome::Ok(_) => {
                panic!("expected failure, got success");
            }
        }
    }

    #[test]
    fn load_subscription_for_daemon_core_running_tries_all_paths() {
        // When the core IS running (simulated by constructing
        // DaemonProxyInfo manually), load_subscription_for_daemon
        // should try all 4 paths: direct, socks5h, socks5, http.
        // Since nothing is listening on the test ports, all will fail.
        let proxy_info = DaemonProxyInfo {
            socks5h_url: "socks5h://127.0.0.1:1".to_owned(),
            socks5_url: "socks5://127.0.0.1:1".to_owned(),
            http_url: Some("http://127.0.0.1:1".to_owned()),
            core_running: true,
        };
        let hwid = crate::profiles::HwidConfig::default();
        let source = SubscriptionSource {
            url: "http://127.0.0.1:1/sub/never".to_owned(),
        };
        let outcome = load_subscription_for_daemon(&source, &proxy_info, &hwid);
        match outcome {
            SubscriptionLoadOutcome::Failed { attempts } => {
                assert_eq!(
                    attempts.len(),
                    4,
                    "core running → 4 attempts (direct+socks5h+socks5+http), got {attempts:?}"
                );
                let labels: Vec<&str> = attempts.iter().map(|(l, _)| l.as_str()).collect();
                assert_eq!(labels, vec!["direct", "socks5h", "socks5", "http"]);
            }
            SubscriptionLoadOutcome::Ok(_) => {
                panic!("expected all paths to fail, got success");
            }
        }
    }

    #[test]
    fn load_subscription_for_daemon_no_http_port_tries_three_paths() {
        // When http_port is None, only 3 paths are tried:
        // direct, socks5h, socks5.
        let proxy_info = DaemonProxyInfo {
            socks5h_url: "socks5h://127.0.0.1:1".to_owned(),
            socks5_url: "socks5://127.0.0.1:1".to_owned(),
            http_url: None,
            core_running: true,
        };
        let hwid = crate::profiles::HwidConfig::default();
        let source = SubscriptionSource {
            url: "http://127.0.0.1:1/sub/never".to_owned(),
        };
        let outcome = load_subscription_for_daemon(&source, &proxy_info, &hwid);
        match outcome {
            SubscriptionLoadOutcome::Failed { attempts } => {
                assert_eq!(
                    attempts.len(),
                    3,
                    "no http port → 3 attempts, got {attempts:?}"
                );
                let labels: Vec<&str> = attempts.iter().map(|(l, _)| l.as_str()).collect();
                assert_eq!(labels, vec!["direct", "socks5h", "socks5"]);
            }
            SubscriptionLoadOutcome::Ok(_) => {
                panic!("expected all paths to fail, got success");
            }
        }
    }

    #[test]
    fn best_profile_selector_requires_a_successful_latency_probe() {
        let mut state = HincyrayState::default();
        state.profiles = vec![
            Profile {
                id: 1,
                name: "failed".to_owned(),
                protocol: crate::profiles::Protocol::Vless,
                address: "failed.example".to_owned(),
                port: Some(443),
                raw: "vless://11111111-1111-1111-1111-111111111111@failed.example:443#failed"
                    .to_owned(),
                selected: true,
                block_quic: false,
                group: None,
            },
            Profile {
                id: 2,
                name: "latency-only".to_owned(),
                protocol: crate::profiles::Protocol::Vless,
                address: "fallback.example".to_owned(),
                port: Some(443),
                raw: "vless://11111111-1111-1111-1111-111111111111@fallback.example:443#fallback"
                    .to_owned(),
                selected: true,
                block_quic: false,
                group: None,
            },
        ];
        state.stats = vec![
            ProfileStats {
                profile_raw: state.profiles[0].raw.clone(),
                last_latency_ms: 10,
                has_latency: true,
                success_count: 0,
                failure_count: 3,
                ..ProfileStats::default()
            },
            ProfileStats {
                profile_raw: state.profiles[1].raw.clone(),
                last_latency_ms: 80,
                has_latency: true,
                success_count: 5,
                ..ProfileStats::default()
            },
        ];

        assert_eq!(find_best_profile(&state, &HashSet::new()), Some(2));
    }

    #[test]
    fn best_profile_selector_skips_rejected_profiles() {
        let mut state = HincyrayState::default();
        state.profiles = vec![
            Profile {
                id: 1,
                name: "stale-best".to_owned(),
                protocol: crate::profiles::Protocol::Vless,
                address: "stale.example".to_owned(),
                port: Some(443),
                raw: "vless://11111111-1111-1111-1111-111111111111@stale.example:443#stale"
                    .to_owned(),
                selected: true,
                block_quic: false,
                group: None,
            },
            Profile {
                id: 2,
                name: "next-best".to_owned(),
                protocol: crate::profiles::Protocol::Vless,
                address: "next.example".to_owned(),
                port: Some(443),
                raw: "vless://11111111-1111-1111-1111-111111111111@next.example:443#next"
                    .to_owned(),
                selected: true,
                block_quic: false,
                group: None,
            },
        ];
        state.stats = vec![
            ProfileStats {
                profile_raw: state.profiles[0].raw.clone(),
                last_latency_ms: 10,
                has_latency: true,
                success_count: 1,
                ..ProfileStats::default()
            },
            ProfileStats {
                profile_raw: state.profiles[1].raw.clone(),
                last_latency_ms: 50,
                has_latency: true,
                success_count: 1,
                ..ProfileStats::default()
            },
        ];

        let rejected = HashSet::from([1]);
        assert_eq!(find_best_profile(&state, &rejected), Some(2));
    }

    #[test]
    fn failover_ranking_uses_raw_identity_and_excludes_trash_and_cooldown() {
        let mut state = HincyrayState {
            profiles: vec![
                make_profile(40, "current", "raw-current", None),
                make_profile(2, "trashed-best", "raw-trash", None),
                make_profile(99, "cooldown", "raw-cooldown", None),
                make_profile(7, "verified-next", "raw-next", None),
            ],
            ..Default::default()
        };
        state
            .dead_server_refs
            .insert(profile_server_ref(&state.profiles[1]));
        state.stats = vec![
            ProfileStats {
                profile_raw: "raw-current".to_owned(),
                success_count: 10,
                last_latency_ms: 20,
                has_latency: true,
                ..ProfileStats::default()
            },
            ProfileStats {
                profile_raw: "raw-trash".to_owned(),
                success_count: 10,
                last_latency_ms: 1,
                has_latency: true,
                ..ProfileStats::default()
            },
            ProfileStats {
                profile_raw: "raw-cooldown".to_owned(),
                success_count: 10,
                last_latency_ms: 2,
                has_latency: true,
                cooldown_until_unix: unix_now() + 60,
                ..ProfileStats::default()
            },
            ProfileStats {
                profile_raw: "raw-next".to_owned(),
                success_count: 3,
                last_latency_ms: 30,
                has_latency: true,
                ..ProfileStats::default()
            },
        ];

        let excluded = HashSet::from(["raw-current".to_owned()]);
        let candidates = ranked_failover_candidates(&state, &excluded);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].raw, "raw-next");
        assert_eq!(candidates[0].id, 7);
    }

    #[test]
    fn profile_health_failure_creates_raw_keyed_cooldown() {
        let mut state = HincyrayState::default();
        state.stats.push(ProfileStats {
            profile_raw: "raw-failed".to_owned(),
            ..ProfileStats::default()
        });

        record_profile_health_failure(&mut state, "raw-failed", 1_000);

        let stat = state
            .stats
            .iter()
            .find(|stat| stat.profile_raw == "raw-failed")
            .expect("failed profile stats");
        assert_eq!(stat.failure_count, 1);
        assert_eq!(stat.consecutive_failures, 1);
        assert_eq!(stat.cooldown_until_unix, 1_300);
        assert_eq!(stat.last_checked_unix, 1_000);
        assert!(
            stat.last_error
                .as_deref()
                .is_some_and(|error| error.contains("fallback health threshold"))
        );
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
        assert_eq!(loaded.mihomo_path, "mihomo");
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
    fn auto_vpn_probe_contract_migration_clears_stale_metadata_once() {
        let dir = TempDir::new().expect("temp dir");
        let state_path = dir.path().join("state.json");
        let mut state = HincyrayState::default();
        state.split_routing.auto_vpn_probe_contract_version = 0;
        state.split_routing.auto_vpn_exceptions = vec!["promoted.example".to_owned()];
        state
            .split_routing
            .auto_vpn_last_checked_unix
            .insert("promoted.example".to_owned(), 10);
        state
            .split_routing
            .auto_vpn_last_checked_unix
            .insert("stale.example".to_owned(), 20);
        persist_state(&state_path, &state).expect("persist old contract");

        let migrated = load_state(&state_path);
        assert_eq!(
            migrated.split_routing.auto_vpn_probe_contract_version,
            AUTO_VPN_PROBE_CONTRACT_VERSION
        );
        assert_eq!(
            migrated
                .split_routing
                .auto_vpn_last_checked_unix
                .get("promoted.example"),
            Some(&10)
        );
        assert!(
            !migrated
                .split_routing
                .auto_vpn_last_checked_unix
                .contains_key("stale.example")
        );

        let mut persisted = migrated;
        persisted
            .split_routing
            .auto_vpn_last_checked_unix
            .insert("fresh.example".to_owned(), 30);
        persist_state(&state_path, &persisted).expect("persist new contract");
        let reloaded = load_state(&state_path);
        assert_eq!(
            reloaded
                .split_routing
                .auto_vpn_last_checked_unix
                .get("fresh.example"),
            Some(&30)
        );
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
    fn set_active_profile_writes_mihomo_config() {
        let (_dir, daemon) = test_daemon();
        let body = "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=xhttp&security=reality&sni=www.example.com&fp=chrome&pbk=0123456789abcdef0123456789abcdef0123456789a&sid=abcd#XHTTP";
        handle_import(body, &daemon);

        let (status, _, response_text) = handle_set_active(r#"{"profile_id":0}"#, &daemon);
        assert_eq!(status, 200);
        let response: Value = serde_json::from_str(&response_text).expect("parse response");
        assert_eq!(response["active_profile_id"], 0);
        assert_eq!(response["active_profile_name"], "XHTTP");

        let config_text = fs::read_to_string(&daemon.mihomo_config_path).expect("read config");
        let config: Value = serde_yaml::from_str(&config_text).expect("parse config");
        assert_eq!(config["socks-port"], 10808);
        assert_eq!(config["proxies"][0]["type"], "vless");
        assert_eq!(config["proxies"][0]["network"], "xhttp");
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
            sync_server_route_registry(&mut inner.state);
            let pinned_canonical = canonical_profile_raw(&inner.state.profiles[1]);
            let pinned_ref = inner
                .state
                .server_route_registry
                .iter()
                .find(|entry| entry.canonical_raw == pinned_canonical)
                .expect("pinned ref")
                .server_ref
                .clone();
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
                target: format!("server:{pinned_ref}"),
                services: vec!["youtube".to_owned()],
                ..Default::default()
            });
        }

        let (status, _, body) = handle_get_mihomo_config(&daemon);
        assert_eq!(status, 200);
        let config: Value = serde_yaml::from_str(&body).expect("parse config");
        assert!(
            config["listeners"]
                .as_array()
                .expect("listeners array")
                .iter()
                .any(|listener| listener["name"] == "redir-in" && listener["type"] == "redir")
        );
        assert!(
            config["proxies"]
                .as_array()
                .expect("proxies array")
                .iter()
                .any(|proxy| proxy["name"]
                    .as_str()
                    .is_some_and(|name| name.starts_with("srv-out-"))
                    && proxy["type"] == "vless")
        );
        let rules = config["rules"].as_array().expect("routing rules");
        assert!(rules.iter().any(|rule| {
            rule.as_str()
                .is_some_and(|s| s.contains("GEOSITE,ru") && s.contains("DIRECT"))
        }));
        assert!(rules.iter().any(|rule| {
            rule.as_str()
                .is_some_and(|s| s == "AND,((NETWORK,udp),(DST-PORT,443)),REJECT")
        }));
        assert_eq!(rules.last().expect("fallback rule"), "MATCH,proxy");
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
    fn parovozik_settings_are_disabled_by_default_and_project_two_managed_rules() {
        let (_dir, daemon) = test_daemon();
        assert!(!lock(&daemon.inner).state.split_routing.parovozik_enabled);
        let (status, _, body) = handle_routing_get(&daemon);
        assert_eq!(status, 200);
        let response: Value = serde_json::from_str(&body).expect("routing response");
        let rules = response["rules"].as_array().expect("rules");
        let parovozik: Vec<&Value> = rules
            .iter()
            .filter(|rule| rule["kind"] == "managed-parovozik")
            .collect();
        assert_eq!(parovozik.len(), 2);
        assert!(parovozik.iter().all(|rule| rule["enabled"] == false));
        assert!(
            parovozik
                .iter()
                .any(|rule| rule["name"] == "Паровозик Direct")
        );
        assert!(parovozik.iter().any(|rule| rule["name"] == "Паровозик VPN"));
    }

    #[test]
    fn parovozik_provider_files_are_bounded_normalized_and_atomic() {
        let (dir, daemon) = test_daemon();
        let mut state = lock(&daemon.inner).state.clone();
        state.split_routing.geo_asset_path = dir.path().to_string_lossy().into_owned();
        state.split_routing.parovozik_enabled = true;
        state.split_routing.parovozik_direct_domains =
            vec![" Example.COM ".to_owned(), "example.com".to_owned()];
        state.split_routing.parovozik_vpn_domains = vec!["vpn.example".to_owned()];

        write_parovozik_provider_files(&state).expect("provider files");
        let (direct, vpn) = parovozik_provider_paths(&state).expect("paths");
        assert_eq!(fs::read_to_string(direct).expect("direct"), "example.com\n");
        assert_eq!(fs::read_to_string(vpn).expect("vpn"), "vpn.example\n");

        state.split_routing.parovozik_direct_domains.clear();
        write_parovozik_provider_files(&state).expect("empty provider");
        let (direct, _) = parovozik_provider_paths(&state).expect("paths");
        assert_eq!(fs::read_to_string(direct).expect("direct"), "# empty\n");
    }

    #[test]
    fn parovozik_config_uses_hot_update_rule_providers() {
        let (dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#Active",
            &daemon,
        );
        let state = {
            let mut inner = lock(&daemon.inner);
            inner.state.active_profile_id = Some(0);
            inner.state.split_routing.enabled = true;
            inner.state.split_routing.parovozik_enabled = true;
            inner.state.split_routing.geo_asset_path = dir.path().to_string_lossy().into_owned();
            inner.state.clone()
        };
        write_parovozik_provider_files(&state).expect("provider files");
        let yaml = build_daemon_config(&state, &[]).expect("config");
        assert!(yaml.contains("RULE-SET,parovozik-direct,DIRECT"));
        assert!(yaml.contains("RULE-SET,parovozik-vpn-rules,parovozik-vpn"));
        assert!(!yaml.contains("DOMAIN-SUFFIX,example.com,parovozik-vpn"));
    }

    #[test]
    fn stale_parovozik_refs_do_not_block_profile_switch_config() {
        let (dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@one.example:443?security=tls#One\n\
             vless://22222222-2222-2222-2222-222222222222@two.example:443?security=tls#Two",
            &daemon,
        );
        let mut state = lock(&daemon.inner).state.clone();
        state.active_profile_id = Some(1);
        state.split_routing.enabled = true;
        state.split_routing.parovozik_enabled = true;
        state.split_routing.geo_asset_path = dir.path().to_string_lossy().into_owned();
        sync_server_route_registry(&mut state);
        let stale_ref = "srv-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        state
            .split_routing
            .parovozik_server_refs
            .push(stale_ref.to_owned());
        state.server_route_registry.push(ServerRouteRegistryEntry {
            server_ref: stale_ref.to_owned(),
            canonical_raw: "missing-profile".to_owned(),
        });

        build_daemon_config(&state, &[]).expect("stale Parovozik ref must be ignored");
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
            sync_server_route_registry(&mut inner.state);
            let pinned_canonical = canonical_profile_raw(&inner.state.profiles[1]);
            let pinned_ref = inner
                .state
                .server_route_registry
                .iter()
                .find(|entry| entry.canonical_raw == pinned_canonical)
                .expect("pinned ref")
                .server_ref
                .clone();
            inner.state.routing_rules.push(RoutingRule {
                enabled: true,
                name: "YouTube".to_owned(),
                target: format!("server:{pinned_ref}"),
                services: vec!["youtube".to_owned()],
                ..Default::default()
            });
        }

        // Toggle block_quic on the active profile (id=0) and the fixed target
        // profile (id=1). Mihomo emits a single global QUIC reject rule when
        // the active profile blocks QUIC, while the per-profile flag is
        // persisted in state for future active selections.
        let (status, _, _) =
            handle_profile_block_quic(r#"{"profile_id":0,"block_quic":true}"#, &daemon);
        assert_eq!(status, 200);
        let (status, _, _) =
            handle_profile_block_quic(r#"{"profile_id":1,"block_quic":true}"#, &daemon);
        assert_eq!(status, 200);

        let (status, _, body) = handle_get_mihomo_config(&daemon);
        assert_eq!(status, 200);
        let config: Value = serde_yaml::from_str(&body).expect("parse config");
        let rules = config["rules"].as_array().expect("routing rules");
        assert!(rules.iter().any(|rule| {
            rule.as_str()
                .is_some_and(|s| s == "AND,((NETWORK,udp),(DST-PORT,443)),REJECT")
        }));

        let inner = lock(&daemon.inner);
        assert!(inner.state.profiles[0].block_quic);
        assert!(inner.state.profiles[1].block_quic);
    }

    #[test]
    fn profile_add_parses_share_link() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443#First",
            &daemon,
        );

        // Add a second profile via the CRUD endpoint.
        let (status, _, body) = handle_profile_add(
            r#"{"raw":"vless://22222222-2222-2222-2222-222222222222@example.org:443#Second"}"#,
            &daemon,
        );
        assert_eq!(status, 200);
        let resp: Value = serde_json::from_str(&body).expect("parse response");
        assert_eq!(resp["profile_id"], 1);

        let inner = lock(&daemon.inner);
        assert_eq!(inner.state.profiles.len(), 2);
        assert_eq!(inner.state.profiles[1].name, "Second");
    }

    #[test]
    fn profile_add_rejects_duplicate() {
        let (_dir, daemon) = test_daemon();
        let raw = "vless://11111111-1111-1111-1111-111111111111@example.com:443#First";
        handle_import(raw, &daemon);

        let (status, _, _) = handle_profile_add(&format!(r#"{{"raw":"{raw}"}}"#), &daemon);
        assert_eq!(status, 409);
    }

    #[test]
    fn profile_add_subscription_url_attempts_fetch_not_parse_error() {
        let (_dir, daemon) = test_daemon();
        // A subscription URL should NOT return a parse error. It should
        // attempt a network fetch and return a fetch error (502).
        let (status, _, body) =
            handle_profile_add(r#"{"raw":"http://127.0.0.1:1/sub/never"}"#, &daemon);
        // 502 = fetch was attempted (correct); 400 with "could not parse" = regression.
        assert_ne!(status, 400);
        let resp: Value = serde_json::from_str(&body).expect("parse response");
        assert!(
            !body.contains("could not parse"),
            "subscription URL must not return parse error"
        );
        // The response should mention the URL in the error.
        if let Some(error) = resp.get("error").and_then(Value::as_str) {
            assert!(error.contains("127.0.0.1:1"));
        }
    }

    #[test]
    fn profile_add_garbage_still_returns_parse_error() {
        let (_dir, daemon) = test_daemon();
        let (status, _, body) = handle_profile_add(r#"{"raw":"not-a-link"}"#, &daemon);
        assert_eq!(status, 400);
        assert!(body.contains("could not parse"));
        // Should include a hint about acceptable input formats.
        assert!(body.contains("hint"));
    }

    #[test]
    fn profile_delete_removes_and_reindexes() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@a.com:443#A\n\
             vless://22222222-2222-2222-2222-222222222222@b.com:443#B\n\
             vless://33333333-3333-3333-3333-333333333333@c.com:443#C",
            &daemon,
        );

        // Delete profile id=1 (B). Remaining: A(0), C(1).
        let (status, _, body) = handle_profile_delete(r#"{"profile_id":1}"#, &daemon);
        assert_eq!(status, 200);
        let resp: Value = serde_json::from_str(&body).expect("parse response");
        assert_eq!(resp["profile_count"], 2);

        let inner = lock(&daemon.inner);
        assert_eq!(inner.state.profiles.len(), 2);
        assert_eq!(inner.state.profiles[0].name, "A");
        assert_eq!(inner.state.profiles[1].name, "C");
        // IDs re-indexed.
        assert_eq!(inner.state.profiles[0].id, 0);
        assert_eq!(inner.state.profiles[1].id, 1);
    }

    #[test]
    fn profile_update_changes_name() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443#OldName",
            &daemon,
        );

        let (status, _, body) =
            handle_profile_update(r#"{"profile_id":0,"name":"NewName"}"#, &daemon);
        assert_eq!(status, 200);
        let resp: Value = serde_json::from_str(&body).expect("parse response");
        assert_eq!(resp["name"], "NewName");

        let inner = lock(&daemon.inner);
        assert_eq!(inner.state.profiles[0].name, "NewName");
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
    fn set_active_accepts_hysteria2_via_mihomo() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "hysteria2://secret@example.com:443?sni=example.com#Hy2",
            &daemon,
        );
        let (status, _, response_text) = handle_set_active(r#"{"profile_id":0}"#, &daemon);
        // Hysteria2 is supported natively by Mihomo. The config build
        // succeeds, so we should NOT see a 400 "Hysteria2" rejection. The
        // core restart may fail in the test environment (no mihomo binary),
        // but that's a runtime error (500), not a config error (400).
        assert_ne!(status, 400);
        assert!(!response_text.contains("Hysteria2"));
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
    fn get_mihomo_config_returns_400_without_active() {
        let (_dir, daemon) = test_daemon();
        let (status, _, _) = handle_get_mihomo_config(&daemon);
        assert_eq!(status, 400);
    }

    #[test]
    fn get_mihomo_config_returns_config_after_activation() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#Demo",
            &daemon,
        );
        handle_set_active(r#"{"profile_id":0}"#, &daemon);
        let (status, content_type, body) = handle_get_mihomo_config(&daemon);
        assert_eq!(status, 200);
        assert_eq!(content_type, "text/yaml; charset=utf-8");
        assert!(body.contains("socks-port: 10808"));
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
        let dir = TempDir::new().expect("temp dir");
        let state_path = dir.path().join("state.json");
        let mihomo_config_path = dir.path().join("mihomo-config.yaml");
        let daemon = Daemon::new(HincyrayState::default(), state_path, mihomo_config_path);
        let (status, _, body) = dispatch("GET", "/api/status", "", &daemon);
        assert_eq!(status, 200);
        assert!(body.contains("\"socks_port\":10808"));
        assert!(body.contains("\"core_status\":\"stopped\""));
        assert!(body.contains("\"mihomo_path\":\"mihomo\""));
        assert!(body.contains("\"mihomo_config_path\":\""));
        assert!(!body.contains("core_engine"));
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
        assert!(body.contains("HincyRay — Панель управления Mihomo"));
    }

    #[test]
    fn stream_parser_uses_first_json_snapshot() {
        let body = "{\"up\":1,\"down\":2}\n{\"up\":3,\"down\":4}\n";
        assert_eq!(
            first_stream_json(body).as_deref(),
            Some("{\"up\":1,\"down\":2}")
        );
    }

    #[test]
    fn stream_parser_rejects_empty_or_invalid_stream() {
        assert!(first_stream_json("").is_none());
        assert!(first_stream_json("not-json\n{\"later\":true}").is_none());
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
    fn benchmark_empty_mihomo_path_uses_path_lookup() {
        assert_eq!(benchmark_mihomo_path(""), "mihomo");
        assert_eq!(benchmark_mihomo_path("  "), "mihomo");
        assert_eq!(
            benchmark_mihomo_path("/opt/sbin/mihomo"),
            "/opt/sbin/mihomo"
        );
    }

    #[test]
    fn telegram_probe_status_never_exposes_credentials() {
        let (_dir, daemon) = test_daemon();
        save_telegram_config(
            &telegram_config_path(&daemon.state_path),
            &TelegramProbeConfig {
                api_id: 12345,
                api_hash: "sensitive-api-hash".to_owned(),
                phone: "+10000000000".to_owned(),
                peer: "fixture_channel".to_owned(),
                message_id: 42,
                authorized: false,
            },
        )
        .expect("save Telegram config");

        let (status, _, body) = dispatch("GET", "/api/telegram-probe/status", "", &daemon);
        assert_eq!(status, 200);
        assert!(body.contains("fixture_channel"));
        assert!(!body.contains("sensitive-api-hash"));
        assert!(!body.contains("+10000000000"));
        assert!(!body.contains("api_id"));
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
    fn stats_endpoint_marks_never_measured_metrics_as_null() {
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
        for field in [
            "last_latency_ms",
            "last_jitter_ms",
            "last_download_mbps",
            "last_upload_mbps",
            "last_loss_percent",
        ] {
            assert!(stats[0][field].is_null(), "{field} must be null");
        }
        assert!(stats[0].get("score").is_none());
        assert!(stats[0].get("ewma_score").is_none());
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
    fn profile_share_returns_raw_link_and_qr_svg_by_id() {
        let (_dir, daemon) = test_daemon();
        let raw = "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#Demo";
        handle_import(raw, &daemon);

        let (status, content_type, body) = dispatch(
            "POST",
            "/api/profiles/share",
            r#"{"profile_id":0}"#,
            &daemon,
        );

        assert_eq!(status, 200);
        assert_eq!(content_type, "application/json");
        let response: Value = serde_json::from_str(&body).expect("parse profile share response");
        assert_eq!(response["profile_id"], 0);
        assert_eq!(response["name"], "Demo");
        assert_eq!(response["link"], raw);
        let qr_svg = response["qr_svg"].as_str().expect("qr svg string");
        assert!(qr_svg.contains("<svg"));
        assert!(qr_svg.contains("</svg>"));
    }

    #[test]
    fn profile_share_rejects_unknown_or_missing_profile_id() {
        let (_dir, daemon) = test_daemon();

        let (missing_status, _, _) = dispatch("POST", "/api/profiles/share", r#"{}"#, &daemon);
        assert_eq!(missing_status, 400);

        let (unknown_status, _, body) = dispatch(
            "POST",
            "/api/profiles/share",
            r#"{"profile_id":99}"#,
            &daemon,
        );
        assert_eq!(unknown_status, 404);
        let response: Value = serde_json::from_str(&body).expect("parse profile share error");
        assert_eq!(response["profile_id"], 99);
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
            method: "quick".to_owned(),
            latency_ms: 80,
            jitter_ms: 4,
            download_mbps: Some(25.0),
            upload_mbps: Some(8.0),
            download_error: None,
            upload_error: None,
            loss_percent: 0.0,
            success: true,
            error: None,
            resource_tests: vec![ResourceTestResult {
                contract_version: 4,
                id: "youtube".to_owned(),
                name: "YouTube".to_owned(),
                attempts: 2,
                successes: 2,
                reachable: true,
                stable: true,
                avg_ttfb_ms: 120,
                max_ttfb_ms: 140,
                avg_download_kbps: 800.0,
                error: None,
            }],
            timestamp: 1_700_000_000,
        };
        apply_bench_result(&daemon, success);

        let inner = lock(&daemon.inner);
        assert_eq!(inner.state.stats.len(), 1);
        let stat = &inner.state.stats[0];
        assert_eq!(stat.profile_raw, raw);
        assert_eq!(stat.last_latency_ms, 80);
        assert_eq!(stat.last_download_mbps, 25.0);
        assert_eq!(stat.last_upload_mbps, 8.0);
        assert!(stat.has_download);
        assert!(stat.has_upload);
        assert_eq!(stat.resource_tests.len(), 1);
        assert_eq!(stat.resource_tests[0].id, "youtube");
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
            download_mbps: None,
            upload_mbps: None,
            download_error: None,
            upload_error: None,
            loss_percent: 100.0,
            success: false,
            error: Some("tcp connect failed".to_owned()),
            resource_tests: Vec::new(),
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
    fn latency_only_bench_preserves_previous_speed_measurements() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#Demo",
            &daemon,
        );
        let raw = lock(&daemon.inner).state.profiles[0].raw.clone();
        let result = |download_mbps, upload_mbps, timestamp| BenchResult {
            profile_id: 0,
            profile_name: "Demo".to_owned(),
            profile_raw: raw.clone(),
            method: "tcp".to_owned(),
            latency_ms: 50,
            jitter_ms: 2,
            download_mbps,
            upload_mbps,
            download_error: None,
            upload_error: None,
            loss_percent: 0.0,
            success: true,
            error: None,
            resource_tests: Vec::new(),
            timestamp,
        };
        apply_bench_result(&daemon, result(Some(40.0), Some(12.0), 1));
        apply_bench_result(&daemon, result(None, None, 2));

        let inner = lock(&daemon.inner);
        let stat = &inner.state.stats[0];
        assert_eq!(stat.last_download_mbps, 40.0);
        assert_eq!(stat.last_upload_mbps, 12.0);
        assert!(stat.has_download);
        assert!(stat.has_upload);
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
                    download_mbps: None,
                    upload_mbps: None,
                    download_error: None,
                    upload_error: None,
                    loss_percent: 0.0,
                    success: true,
                    error: None,
                    resource_tests: Vec::new(),
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

    #[test]
    fn dns_api_get_returns_defaults() {
        let (_dir, daemon) = test_daemon();
        let (status, _, body) = dispatch("GET", "/api/dns", "", &daemon);
        assert_eq!(status, 200);
        assert!(body.contains("\"enabled\":false"));
    }

    #[test]
    fn dns_api_set_persists_enabled_and_servers() {
        let (_dir, daemon) = test_daemon();
        let body = r#"{"enabled":true,"remote_servers":["https://1.1.1.1/dns-query","8.8.8.8"],"local_servers":["223.5.5.5"],"query_strategy":"UseIPv4"}"#;
        let (status, _, response) = dispatch("POST", "/api/dns", body, &daemon);
        assert_eq!(status, 200);
        assert!(response.contains("\"enabled\":true"));
        let inner = lock(&daemon.inner);
        assert!(inner.state.dns_settings.enabled);
        assert_eq!(inner.state.dns_settings.remote_servers.len(), 2);
        assert_eq!(inner.state.dns_settings.local_servers.len(), 1);
    }

    #[test]
    fn dns_api_get_includes_sniffer_override_default_true() {
        let (_dir, daemon) = test_daemon();
        let (status, _, body) = dispatch("GET", "/api/dns", "", &daemon);
        assert_eq!(status, 200);
        assert!(body.contains("\"sniffer_override_destination\":true"));
    }

    #[test]
    fn dns_api_set_sniffer_override_false_persists() {
        let (_dir, daemon) = test_daemon();
        let body = r#"{"sniffer_override_destination":false}"#;
        let (status, _, response) = dispatch("POST", "/api/dns", body, &daemon);
        assert_eq!(status, 200);
        assert!(response.contains("\"sniffer_override_destination\":false"));
        let inner = lock(&daemon.inner);
        assert!(!inner.state.mihomo_features.sniffer_override_destination);
    }

    #[test]
    fn dns_a_query_builds_valid_packet() {
        let q = build_dns_a_query("example.com");
        // Header (12) + 7+example + 3+com + root(1) + type(2) + class(2) = 12+8+4+1+2+2 = 29
        assert_eq!(q.len(), 29);
        // Transaction ID = 1
        assert_eq!(&q[0..2], &[0x00, 0x01]);
        // Flags: RD=1
        assert_eq!(&q[2..4], &[0x01, 0x00]);
        // QDCOUNT = 1
        assert_eq!(&q[4..6], &[0x00, 0x01]);
        // First label length = 7 ("example")
        assert_eq!(q[12], 7);
        // Type A
        assert_eq!(&q[25..27], &[0x00, 0x01]);
        // Class IN
        assert_eq!(&q[27..29], &[0x00, 0x01]);
    }

    #[test]
    fn dns_a_query_single_label() {
        let q = build_dns_a_query("localhost");
        // 12 + 1+9 + 1 + 2 + 2 = 27
        assert_eq!(q.len(), 27);
        assert_eq!(q[12], 9);
    }

    #[test]
    fn dns_a_response_parse_ok() {
        // Craft a minimal DNS response: 1 answer, A record = 1.2.3.4
        let mut resp = Vec::new();
        // Header: id=1, flags=0x8180 (response, RD, RA), qd=1, an=1, ns=0, ar=0
        resp.extend_from_slice(&[
            0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ]);
        // Question: example.com type A class IN
        resp.extend_from_slice(&[
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, 0x00, 0x01,
        ]);
        // Answer: compressed name ptr (0xc00c), type A, class IN, TTL 60, rdlen 4, data 1.2.3.4
        resp.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 1, 2, 3, 4,
        ]);
        let v = parse_dns_a_response(&resp);
        assert_eq!(v["ok"], json!(true));
        assert_eq!(v["rcode"], json!(0));
        assert_eq!(v["answer_count"], json!(1));
        assert_eq!(v["ips"][0], json!("1.2.3.4"));
    }

    #[test]
    fn dns_a_response_parse_nxdomain() {
        // NXDOMAIN: rcode=3, 0 answers
        let mut resp = Vec::new();
        resp.extend_from_slice(&[
            0x00, 0x01, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        resp.extend_from_slice(&[
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, 0x00, 0x01,
        ]);
        let v = parse_dns_a_response(&resp);
        assert_eq!(v["ok"], json!(false));
        assert_eq!(v["rcode"], json!(3));
        assert_eq!(v["answer_count"], json!(0));
    }

    #[test]
    fn dns_a_response_parse_too_short() {
        let v = parse_dns_a_response(&[0x00, 0x01]);
        assert_eq!(v["ok"], json!(false));
        assert!(v["error"].as_str().is_some());
    }

    #[test]
    fn dns_query_tcp_connection_refused() {
        // Port 1 is almost certainly not listening
        let v = dns_query_tcp("127.0.0.1", 1, "example.com");
        assert_eq!(v["ok"], json!(false));
        assert!(v["error"].as_str().is_some());
    }

    #[test]
    fn hwid_api_get_returns_defaults() {
        let (_dir, daemon) = test_daemon();
        let (status, _, body) = dispatch("GET", "/api/hwid", "", &daemon);
        assert_eq!(status, 200);
        assert!(body.contains("a3f7e10d5c9b2486"));
        assert!(body.contains("Poco X3 Pro"));
    }

    #[test]
    fn hwid_api_set_persists_custom_values() {
        let (_dir, daemon) = test_daemon();
        let body = r#"{"hwid":"abcdef0123456789","os_version":"14","device_model":"Pixel 7","device_os":"Android"}"#;
        let (status, _, response) = dispatch("POST", "/api/hwid", body, &daemon);
        assert_eq!(status, 200);
        assert!(response.contains("abcdef0123456789"));
        let inner = lock(&daemon.inner);
        assert_eq!(inner.state.hwid_config.hwid, "abcdef0123456789");
        assert_eq!(inner.state.hwid_config.device_model, "Pixel 7");
    }

    #[test]
    fn routing_settings_with_port_mode_persists() {
        let (_dir, daemon) = test_daemon();
        let body = r#"{"port_mode":"allow_list","proxy_ports":["80","443"],"geo_asset_path":"/opt/etc/hincyray"}"#;
        let (status, _, _) = handle_routing_settings(body, &daemon);
        assert_eq!(status, 200);
        let inner = lock(&daemon.inner);
        assert_eq!(inner.state.split_routing.port_mode, PortMode::AllowList);
        assert_eq!(inner.state.split_routing.proxy_ports, vec!["80", "443"]);
        assert_eq!(
            inner.state.split_routing.geo_asset_path,
            "/opt/etc/hincyray"
        );
    }

    #[test]
    fn routing_rule_with_ports_and_network_generates_mihomo_rule() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#Active",
            &daemon,
        );
        {
            let mut inner = lock(&daemon.inner);
            inner.state.active_profile_id = Some(0);
            inner.state.split_routing.enabled = true;
            inner.state.routing_rules.push(RoutingRule {
                enabled: true,
                name: "Gaming UDP".to_owned(),
                target: "direct".to_owned(),
                ports: vec!["27000-27050".to_owned()],
                network: "udp".to_owned(),
                ..Default::default()
            });
        }
        let (status, _, body) = handle_get_mihomo_config(&daemon);
        assert_eq!(status, 200);
        let config: Value = serde_yaml::from_str(&body).expect("parse config");
        let rules = config["rules"].as_array().expect("rules");
        // v0.16: ports + network without domains are ANDed together:
        // "UDP traffic on ports 27000-27050 → DIRECT"
        assert!(
            rules.iter().any(|r| {
                r.as_str() == Some("AND,((NETWORK,udp),(DST-PORT,27000-27050)),DIRECT")
            })
        );
    }

    #[test]
    fn routing_rule_with_network_any_does_not_emit_mihomo_network_rule() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#Active",
            &daemon,
        );
        {
            let mut inner = lock(&daemon.inner);
            inner.state.active_profile_id = Some(0);
            inner.state.split_routing.enabled = true;
            inner.state.routing_rules.push(RoutingRule {
                enabled: true,
                name: "YouTube any".to_owned(),
                target: "active".to_owned(),
                services: vec!["youtube".to_owned()],
                network: "any".to_owned(),
                ..Default::default()
            });
        }
        let (status, _, body) = handle_get_mihomo_config(&daemon);
        assert_eq!(status, 200);
        let config: Value = serde_yaml::from_str(&body).expect("parse config");
        let rules = config["rules"].as_array().expect("rules");
        // GEOSITE,youtube,proxy should be present
        assert!(
            rules
                .iter()
                .any(|r| { r.as_str() == Some("GEOSITE,youtube,proxy") })
        );
        // NETWORK,any must never appear — it crashes Mihomo
        assert!(
            !rules
                .iter()
                .any(|r| { r.as_str().unwrap_or("").starts_with("NETWORK,") })
        );
    }

    #[test]
    fn split_routing_config_with_dns_enabled_includes_dns_section() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#Active",
            &daemon,
        );
        {
            let mut inner = lock(&daemon.inner);
            inner.state.active_profile_id = Some(0);
            inner.state.split_routing.enabled = true;
            inner.state.dns_settings.enabled = true;
            inner.state.dns_settings.remote_servers = vec!["https://1.1.1.1/dns-query".to_owned()];
        }
        let (status, _, body) = handle_get_mihomo_config(&daemon);
        assert_eq!(status, 200);
        let config: Value = serde_yaml::from_str(&body).expect("parse config");
        assert!(config.get("dns").is_some());
    }

    #[test]
    fn split_routing_config_always_includes_dns_even_when_disabled() {
        // The transparent proxy requires DNS — the firewall DNATs DNS
        // to port 1053 unconditionally, so the Mihomo config must always
        // include the DNS listener, regardless of `dns.enabled`.
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#Active",
            &daemon,
        );
        {
            let mut inner = lock(&daemon.inner);
            inner.state.active_profile_id = Some(0);
            inner.state.split_routing.enabled = true;
            inner.state.dns_settings.enabled = false; // explicitly disabled
        }
        let (status, _, body) = handle_get_mihomo_config(&daemon);
        assert_eq!(status, 200);
        let config: Value = serde_yaml::from_str(&body).expect("parse config");
        let dns = config
            .get("dns")
            .expect("dns section must always be present in router config");
        assert_eq!(
            dns.get("enable").and_then(Value::as_bool),
            Some(true),
            "dns.enable must be true in generated config"
        );
        assert_eq!(
            dns.get("listen").and_then(Value::as_str),
            Some("0.0.0.0:1053"),
            "dns listener must be on port 1053 to match firewall DNAT"
        );
    }

    #[test]
    fn load_state_forces_dns_enabled_when_split_routing_on() {
        let dir = TempDir::new().expect("temp dir");
        let state_path = dir.path().join("state.json");
        let state = HincyrayState {
            split_routing: SplitRoutingSettings {
                enabled: true,
                ..Default::default()
            },
            dns_settings: DnsSettings {
                enabled: false, // explicitly disabled
                ..Default::default()
            },
            ..Default::default()
        };
        fs::write(
            &state_path,
            serde_json::to_string(&state).expect("serialize"),
        )
        .expect("write");
        let loaded = load_state(&state_path);
        assert!(
            loaded.dns_settings.enabled,
            "load_state must force dns_settings.enabled=true when split routing is on"
        );
    }

    #[test]
    fn compact_state_for_persist_caps_unbounded_collections() {
        let mut state = HincyrayState {
            connection_log: (0..(MAX_CONNECTION_LOG + 5))
                .map(|i| ConnectionLogEntry {
                    timestamp: i as u64,
                    ..Default::default()
                })
                .collect(),
            undo_stack: (0..(MAX_UNDO_STACK + 3))
                .map(|i| UndoEntry {
                    id: i.to_string(),
                    label: "x".to_owned(),
                    timestamp: i as u64,
                    state_json: "{}".to_owned(),
                })
                .collect(),
            ..Default::default()
        };
        compact_state_for_persist(&mut state);
        assert_eq!(state.connection_log.len(), MAX_CONNECTION_LOG);
        assert_eq!(state.undo_stack.len(), MAX_UNDO_STACK);
        assert_eq!(
            state
                .connection_log
                .first()
                .expect("compacted connection log keeps newest entries")
                .timestamp,
            5
        );
    }

    #[test]
    fn stale_profile_stats_are_bounded_by_recency() {
        let live_raw = "vless://live@example.com";
        let mut state = HincyrayState {
            profiles: vec![make_profile(0, "Live", live_raw, None)],
            stats: (0..(MAX_STALE_PROFILE_STATS + 5))
                .map(|index| ProfileStats {
                    profile_raw: format!("vless://stale-{index}@example.com"),
                    last_checked_unix: index as u64,
                    ..Default::default()
                })
                .chain(std::iter::once(ProfileStats {
                    profile_raw: live_raw.to_owned(),
                    last_checked_unix: 0,
                    ..Default::default()
                }))
                .collect(),
            ..Default::default()
        };

        assert!(prune_stale_profile_stats(&mut state));
        assert_eq!(state.stats.len(), MAX_STALE_PROFILE_STATS + 1);
        assert!(state.stats.iter().any(|stat| stat.profile_raw == live_raw));
        assert!(
            !state.stats.iter().any(|stat| stat.last_checked_unix == 0
                && stat.profile_raw.starts_with("vless://stale-"))
        );
        assert!(!prune_stale_profile_stats(&mut state));
    }

    #[test]
    fn json_error_does_not_require_static_message() {
        let message = format!("dynamic error {}", 42);
        let (_, _, body) = json_error(400, &message);
        assert_eq!(
            serde_json::from_str::<Value>(&body).expect("error JSON")["error"],
            message
        );
    }

    #[test]
    fn undo_restore_restores_previous_state() {
        let (_dir, daemon) = test_daemon();
        {
            let mut inner = lock(&daemon.inner);
            inner
                .state
                .profiles
                .push(make_profile(0, "A", "raw-a", None));
            push_undo_snapshot(&mut inner.state, "before delete");
            inner.state.profiles.clear();
        }
        let id = {
            let inner = lock(&daemon.inner);
            inner.state.undo_stack[0].id.clone()
        };
        let (status, _, _) = handle_undo_restore(&format!(r#"{{"id":"{id}"}}"#), &daemon);
        assert_eq!(status, 200);
        let inner = lock(&daemon.inner);
        assert_eq!(inner.state.profiles.len(), 1);
        assert_eq!(inner.state.profiles[0].name, "A");
    }

    #[test]
    fn prometheus_metrics_exposes_core_series() {
        let (_dir, daemon) = test_daemon();
        let (status, content_type, body) = handle_prometheus_metrics(&daemon);
        assert_eq!(status, 200);
        assert!(content_type.starts_with("text/plain"));
        assert!(body.contains("hincyray_up 1"));
        assert!(body.contains("hincyray_profiles_total"));
    }

    #[test]
    fn mihomo_validator_reports_missing_binary_as_unsupported() {
        let result = validate_mihomo_config_yaml(
            "/definitely/missing/hincyray-mihomo",
            "mixed-port: 10809\n",
            None,
        );
        assert_eq!(result["ok"], json!(false));
        assert_eq!(result["supported"], json!(false));
    }

    #[test]
    fn mihomo_validator_times_out_and_terminates_hung_process() {
        let dir = TempDir::new().expect("temp dir");
        let script_path = dir.path().join("hung-mihomo.sh");
        fs::write(
            &script_path,
            "#!/bin/sh\necho validator-started\nsleep 10\necho validator-finished\n",
        )
        .expect("write script");
        let chmod = Command::new("chmod")
            .arg("+x")
            .arg(&script_path)
            .status()
            .expect("chmod script");
        assert!(chmod.success());

        let started = SystemTime::now();
        let result = validate_mihomo_config_yaml_with_timeout(
            script_path.to_str().expect("utf-8 path"),
            "mixed-port: 10809\n",
            None,
            Duration::from_millis(100),
        );
        let elapsed = started.elapsed().unwrap_or_default();

        assert_eq!(result["ok"], json!(false));
        assert_eq!(result["supported"], json!(true));
        assert_eq!(result["timeout"], json!(true));
        assert!(
            elapsed < Duration::from_secs(2),
            "validator timeout must bound handler lifetime, elapsed={elapsed:?}"
        );
        assert!(
            result["stdout"]
                .as_str()
                .unwrap_or_default()
                .contains("validator-started")
        );
    }

    #[test]
    fn mihomo_validator_preserves_unsupported_flag_detection() {
        let dir = TempDir::new().expect("temp dir");
        let script_path = dir.path().join("unsupported-mihomo.sh");
        fs::write(
            &script_path,
            "#!/bin/sh\necho 'unknown shorthand flag: t' >&2\nexit 2\n",
        )
        .expect("write script");
        let chmod = Command::new("chmod")
            .arg("+x")
            .arg(&script_path)
            .status()
            .expect("chmod script");
        assert!(chmod.success());

        let result = validate_mihomo_config_yaml_with_timeout(
            script_path.to_str().expect("utf-8 path"),
            "mixed-port: 10809\n",
            None,
            Duration::from_secs(2),
        );

        assert_eq!(result["ok"], json!(false));
        assert_eq!(result["supported"], json!(false));
        assert_eq!(result["exit_code"], json!(2));
    }

    #[cfg(unix)]
    #[test]
    fn mihomo_validator_bounds_go_runtime_memory() {
        let dir = TempDir::new().expect("temp dir");
        let script_path = dir.path().join("environment-mihomo.sh");
        fs::write(
            &script_path,
            "#!/bin/sh\n[ \"$GOMEMLIMIT\" = \"64MiB\" ] && [ \"$GOGC\" = \"20\" ]\n",
        )
        .expect("write script");
        fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755)).expect("chmod");

        let result = validate_mihomo_config_yaml_with_timeout(
            script_path.to_str().expect("utf-8 path"),
            "mixed-port: 10809\n",
            None,
            Duration::from_secs(2),
        );

        assert_eq!(result["ok"], json!(true));
    }

    // ── Subscription replace / delete tests ───────────────────────────

    fn make_profile(id: usize, name: &str, raw: &str, group: Option<&str>) -> Profile {
        Profile {
            id,
            name: name.to_owned(),
            protocol: crate::profiles::Protocol::Vless,
            address: "example.com".to_owned(),
            port: Some(443),
            raw: raw.to_owned(),
            selected: false,
            block_quic: false,
            group: group.map(|s| s.to_owned()),
        }
    }

    #[test]
    fn replace_subscription_profiles_removes_old_adds_fresh() {
        let mut state = HincyrayState::default();
        let url = "https://provider.example/sub";

        state
            .profiles
            .push(make_profile(0, "Sub1", "raw1", Some(url)));
        state
            .profiles
            .push(make_profile(1, "Sub2", "raw2", Some(url)));
        state
            .profiles
            .push(make_profile(2, "Sub3", "raw3", Some(url)));
        state.profiles.push(make_profile(3, "Direct", "raw4", None));
        state.active_profile_id = Some(1); // Sub2

        // Fresh set: raw1 (same), raw5 (new). raw2 and raw3 are gone.
        let fresh = vec![
            make_profile(0, "Sub1-updated", "raw1", None),
            make_profile(1, "SubNew", "raw5", None),
        ];

        let added = replace_subscription_profiles(&mut state, url, fresh)
            .expect("non-empty subscription replacement should succeed");

        // Both fresh profiles are added (old subscription profiles were
        // removed, so no dedup collision except with Direct/raw4).
        assert_eq!(added, 2);
        // Direct (raw4) + 2 fresh = 3 total.
        assert_eq!(state.profiles.len(), 3);
        // Sub2 (raw2) was the active profile and is gone.
        assert_eq!(state.active_profile_id, None);
        // IDs re-indexed sequentially.
        assert_eq!(state.profiles[0].id, 0);
        assert_eq!(state.profiles[1].id, 1);
        assert_eq!(state.profiles[2].id, 2);
        // Groups assigned correctly.
        assert_eq!(state.profiles[1].group.as_deref(), Some(url));
        assert_eq!(state.profiles[2].group.as_deref(), Some(url));
    }

    #[test]
    fn replace_subscription_profiles_preserves_active_by_raw() {
        let mut state = HincyrayState::default();
        let url = "https://provider.example/sub";

        state
            .profiles
            .push(make_profile(0, "Sub1", "raw1", Some(url)));
        state
            .profiles
            .push(make_profile(1, "Sub2", "raw2", Some(url)));
        state.active_profile_id = Some(0); // Sub1 (raw1)

        // Fresh set includes raw1 — active should be preserved by raw.
        let fresh = vec![
            make_profile(0, "Sub1-updated", "raw1", None),
            make_profile(1, "Sub2", "raw2", None),
        ];

        let _added = replace_subscription_profiles(&mut state, url, fresh)
            .expect("non-empty subscription replacement should succeed");

        assert_eq!(state.profiles.len(), 2);
        // Active should point to the profile with raw1 (now at index 0).
        assert_eq!(state.active_profile_id, Some(0));
        assert_eq!(state.profiles[0].raw, "raw1");
        assert_eq!(state.profiles[0].name, "Sub1-updated");
    }

    #[test]
    fn dead_server_membership_survives_subscription_refresh_and_display_rename() {
        let mut state = HincyrayState::default();
        let url = "https://provider.example/sub";
        let old_raw = "vless://11111111-1111-1111-1111-111111111111@one.example:443#Old%20Name";
        let refreshed_raw =
            "vless://11111111-1111-1111-1111-111111111111@one.example:443#New%20Name";
        state
            .profiles
            .push(make_profile(9, "Old Name", old_raw, Some(url)));
        let server_ref = profile_server_ref(&state.profiles[0]);
        state.dead_server_refs.insert(server_ref.clone());

        replace_subscription_profiles(
            &mut state,
            url,
            vec![make_profile(0, "New Name", refreshed_raw, None)],
        )
        .expect("refresh replacement");

        assert_eq!(profile_server_ref(&state.profiles[0]), server_ref);
        assert!(profile_is_dead(&state, &state.profiles[0]));
        assert_eq!(state.profiles[0].group.as_deref(), Some(url));
    }

    #[test]
    fn lifecycle_v2_identity_normalizes_url_syntax_without_losing_repeated_values() {
        let first = "VLESS://11111111-1111-1111-1111-111111111111@EXAMPLE.COM:443?type=ws&alpn=h2&alpn=http%2F1.1&security=tls&host=cdn.example#First";
        let reordered = "vless://11111111-1111-1111-1111-111111111111@example.com:443?host=cdn.example&security=tls&alpn=h2&alpn=http%2F1.1&type=ws#Renamed";
        let changed = "vless://11111111-1111-1111-1111-111111111111@example.com:443?host=other.example&security=tls&alpn=h2&alpn=http%2F1.1&type=ws#Renamed";

        let canonical = canonical_lifecycle_identity_from_raw(first);
        assert_eq!(canonical, canonical_lifecycle_identity_from_raw(reordered));
        assert_eq!(
            url::Url::parse(&canonical)
                .expect("canonical lifecycle URL")
                .query_pairs()
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect::<Vec<_>>(),
            vec![
                ("alpn".to_owned(), "h2".to_owned()),
                ("alpn".to_owned(), "http/1.1".to_owned()),
                ("host".to_owned(), "cdn.example".to_owned()),
                ("security".to_owned(), "tls".to_owned()),
                ("type".to_owned(), "ws".to_owned()),
            ]
        );
        assert_ne!(
            lifecycle_ref_for_canonical(&canonical),
            lifecycle_ref_for_canonical(&canonical_lifecycle_identity_from_raw(changed))
        );
    }

    #[test]
    fn replace_subscription_profiles_no_duplicates_on_refresh() {
        let mut state = HincyrayState::default();
        let url = "https://provider.example/sub";

        // Simulate two consecutive refreshes with the same profiles.
        let fresh = vec![
            make_profile(0, "Sub1", "raw1", None),
            make_profile(1, "Sub2", "raw2", None),
        ];

        let added1 = replace_subscription_profiles(&mut state, url, fresh.clone())
            .expect("non-empty subscription replacement should succeed");
        assert_eq!(added1, 2);
        assert_eq!(state.profiles.len(), 2);

        // Second refresh with the same profiles: old ones removed, new
        // ones added — total should still be 2, not 4.
        let added2 = replace_subscription_profiles(&mut state, url, fresh)
            .expect("non-empty subscription replacement should succeed");
        assert_eq!(added2, 2);
        assert_eq!(state.profiles.len(), 2);
    }

    #[test]
    fn replace_subscription_profiles_rejects_empty_set_without_mutating_state() {
        let mut state = HincyrayState::default();
        let url = "https://provider.example/sub";
        state
            .profiles
            .push(make_profile(0, "Sub1", "raw1", Some(url)));
        state
            .profiles
            .push(make_profile(1, "Sub2", "raw2", Some(url)));
        state.profiles.push(make_profile(2, "Direct", "raw3", None));
        state.active_profile_id = Some(1);

        let before: Vec<(usize, String, Option<String>)> = state
            .profiles
            .iter()
            .map(|profile| (profile.id, profile.raw.clone(), profile.group.clone()))
            .collect();
        let error = replace_subscription_profiles(&mut state, url, Vec::new())
            .expect_err("empty refresh must be rejected before state mutation");

        assert!(error.contains("refusing to replace subscription"));
        let after: Vec<(usize, String, Option<String>)> = state
            .profiles
            .iter()
            .map(|profile| (profile.id, profile.raw.clone(), profile.group.clone()))
            .collect();
        assert_eq!(after, before);
        assert_eq!(state.active_profile_id, Some(1));
    }

    #[test]
    fn dead_server_legacy_state_and_history_migrate_without_raw_api_identity() {
        let dir = TempDir::new().expect("temp dir");
        let state_path = dir.path().join("state.json");
        let raw = "vless://11111111-1111-1111-1111-111111111111@legacy.example:443#Legacy";
        let expected_ref = lifecycle_ref_for_canonical(&canonical_lifecycle_identity_from_raw(raw));
        let mut state = HincyrayState::default();
        state.dead_server_refs.insert(raw.to_owned());
        state.dead_promoted_at.insert(raw.to_owned(), 123);
        state.deep_bench.profile_filter = ProfileFilter::Explicit(vec![raw.to_owned()]);
        persist_state(&state_path, &state).expect("persist legacy-compatible state");

        let migrated = load_state(&state_path);
        assert_eq!(
            migrated.dead_server_refs,
            HashSet::from([expected_ref.clone()])
        );
        assert_eq!(migrated.dead_promoted_at.get(&expected_ref), Some(&123));
        assert_eq!(
            migrated.deep_bench.profile_filter,
            ProfileFilter::Explicit(vec![expected_ref.clone()])
        );
        let persisted: Value =
            serde_json::from_str(&fs::read_to_string(&state_path).expect("read migrated state"))
                .expect("parse migrated state");
        assert_eq!(persisted["dead_server_refs"], json!([expected_ref.clone()]));
        assert_eq!(
            persisted["deep_bench"]["profile_filter"]["value"],
            json!([expected_ref.clone()])
        );

        let history_path = quality_history_path(&state_path);
        fs::write(
            &history_path,
            json!([{
                "date": 20260716,
                "profile_raw": raw,
                "profile_name": "Legacy",
                "quick_score": 10,
                "composite_score": 9
            }])
            .to_string(),
        )
        .expect("write legacy history");
        let history = load_quality_history(&state_path, &[]);
        assert_eq!(history[0].server_ref, expected_ref);
        let api_json = serde_json::to_string(&history).expect("serialize history API");
        assert!(api_json.contains("server_ref"));
        assert!(!api_json.contains("profile_raw"));
        assert!(!api_json.contains("vless://"));
        assert!(!api_json.contains("quick_score"));
        assert!(!api_json.contains("composite_score"));
    }

    #[test]
    fn dead_server_batch_handlers_are_atomic_and_reject_active_profile() {
        let (_dir, daemon) = test_daemon();
        let (active_ref, first_ref, second_ref) = {
            let mut inner = lock(&daemon.inner);
            inner.state.profiles = vec![
                make_profile(0, "Active", "raw-active", None),
                make_profile(1, "First", "raw-first", Some("group-a")),
                make_profile(2, "Second", "raw-second", Some("group-b")),
            ];
            inner.state.active_profile_id = Some(0);
            (
                profile_server_ref(&inner.state.profiles[0]),
                profile_server_ref(&inner.state.profiles[1]),
                profile_server_ref(&inner.state.profiles[2]),
            )
        };

        let (status, _, _) = handle_trash_move(
            &json!({"server_refs": [first_ref.clone(), active_ref]}).to_string(),
            &daemon,
        );
        assert_eq!(status, 409);
        assert!(lock(&daemon.inner).state.dead_server_refs.is_empty());

        let unknown_ref = server_ref_for_canonical("unknown-server");
        let (status, _, _) = handle_trash_move(
            &json!({"server_refs": [first_ref.clone(), unknown_ref.clone()]}).to_string(),
            &daemon,
        );
        assert_eq!(status, 404);
        assert!(lock(&daemon.inner).state.dead_server_refs.is_empty());

        let (status, _, _) = handle_trash_move(
            &json!({"server_refs": [first_ref.clone(), second_ref.clone()]}).to_string(),
            &daemon,
        );
        assert_eq!(status, 200);
        assert_eq!(
            lock(&daemon.inner).state.dead_server_refs,
            HashSet::from([first_ref.clone(), second_ref.clone()])
        );

        let (_, _, list_body) = handle_trash_list(&daemon);
        assert!(!list_body.contains("raw-first"));
        assert!(!list_body.contains("raw-second"));

        let (status, _, _) = handle_trash_restore(
            &json!({"server_refs": [first_ref.clone(), unknown_ref]}).to_string(),
            &daemon,
        );
        assert_eq!(status, 404);
        assert_eq!(
            lock(&daemon.inner).state.dead_server_refs,
            HashSet::from([first_ref.clone(), second_ref.clone()])
        );

        let (status, _, _) = handle_trash_restore(
            &json!({"server_refs": [first_ref, second_ref]}).to_string(),
            &daemon,
        );
        assert_eq!(status, 200);
        assert!(lock(&daemon.inner).state.dead_server_refs.is_empty());
    }

    #[test]
    fn dead_server_clear_removes_profiles_and_related_state() {
        let (_dir, daemon) = test_daemon();
        let subscription = "https://provider.example/sub/fixture";
        let dead_ref = {
            let mut inner = lock(&daemon.inner);
            inner.state.profiles = vec![
                make_profile(0, "Dead", "raw-dead", Some(subscription)),
                make_profile(1, "Active", "raw-active", Some(subscription)),
            ];
            inner.state.active_profile_id = Some(1);
            inner.state.subscriptions.push(StoredSubscription {
                url: subscription.to_owned(),
                profile_count: 2,
                ..Default::default()
            });
            inner.state.favorites.push("raw-dead".to_owned());
            inner.state.stats.push(ProfileStats {
                profile_raw: "raw-dead".to_owned(),
                success_count: 1,
                ..Default::default()
            });
            let dead_ref = profile_server_ref(&inner.state.profiles[0]);
            inner
                .state
                .dead_server_refs
                .extend([dead_ref.clone(), server_ref_for_canonical("legacy-orphan")]);
            inner.state.dead_promoted_at.insert(dead_ref.clone(), 123);
            dead_ref
        };

        let (status, _, body) = handle_trash_clear(&daemon);

        assert_eq!(status, 200, "{body}");
        let response: Value = serde_json::from_str(&body).expect("clear response");
        assert_eq!(response["removed_profiles"], 1);
        assert_eq!(response["removed_entries"], 2);
        let inner = lock(&daemon.inner);
        assert_eq!(inner.state.profiles.len(), 1);
        assert_eq!(inner.state.profiles[0].id, 0);
        assert_eq!(inner.state.profiles[0].raw, "raw-active");
        assert_eq!(inner.state.active_profile_id, Some(0));
        assert_eq!(inner.state.subscriptions[0].profile_count, 1);
        assert!(inner.state.favorites.is_empty());
        assert!(inner.state.stats.is_empty());
        assert!(inner.state.dead_server_refs.is_empty());
        assert!(!inner.state.dead_promoted_at.contains_key(&dead_ref));
    }

    #[test]
    fn lifecycle_v1_is_rejected_for_current_move_but_restores_legacy_orphan() {
        let (_dir, daemon) = test_daemon();
        let (legacy_current_ref, orphan_ref) = {
            let mut inner = lock(&daemon.inner);
            inner.state.profiles.push(make_profile(
                0,
                "Current",
                "vless://11111111-1111-1111-1111-111111111111@current.example:443#Current",
                None,
            ));
            let legacy_current_ref =
                server_ref_for_canonical(&canonical_profile_raw(&inner.state.profiles[0]));
            let orphan_ref = server_ref_for_canonical("legacy-orphan");
            inner.state.dead_server_refs.insert(orphan_ref.clone());
            (legacy_current_ref, orphan_ref)
        };

        let (status, _, body) = handle_trash_move(
            &json!({"server_refs": [legacy_current_ref]}).to_string(),
            &daemon,
        );
        assert_eq!(status, 404, "{body}");

        let (status, _, body) = handle_trash_restore(
            &json!({"server_refs": [orphan_ref.clone()]}).to_string(),
            &daemon,
        );
        assert_eq!(status, 200, "{body}");
        assert!(
            !lock(&daemon.inner)
                .state
                .dead_server_refs
                .contains(&orphan_ref)
        );
    }

    #[test]
    fn dead_membership_dataplane_scope_is_only_enabled_pinned_routes() {
        let mut state = HincyrayState {
            profiles: vec![
                sample_profile(0, "Active", "active.example"),
                sample_profile(1, "Pinned", "pinned.example"),
            ],
            active_profile_id: Some(0),
            ..Default::default()
        };
        state.split_routing.enabled = true;
        sync_server_route_registry(&mut state);
        let pinned_ref = state
            .server_route_registry
            .iter()
            .find(|entry| entry.canonical_raw == canonical_profile_raw(&state.profiles[1]))
            .expect("pinned routing ref")
            .server_ref
            .clone();
        let changed = HashSet::from([profile_server_ref(&state.profiles[1])]);
        assert!(!dead_membership_affects_running_dataplane(&state, &changed));

        state.routing_rules.push(RoutingRule {
            enabled: false,
            target: format!("server:{pinned_ref}"),
            domains: vec!["disabled.example".to_owned()],
            ..Default::default()
        });
        assert!(!dead_membership_affects_running_dataplane(&state, &changed));
        state.routing_rules[0].enabled = true;
        assert!(dead_membership_affects_running_dataplane(&state, &changed));

        state.routing_rules.clear();
        state.device_routes.push(DeviceRoute {
            enabled: true,
            target: format!("server:{pinned_ref}"),
            ..Default::default()
        });
        assert!(dead_membership_affects_running_dataplane(&state, &changed));
        state.split_routing.enabled = false;
        assert!(!dead_membership_affects_running_dataplane(&state, &changed));
    }

    #[test]
    fn dead_membership_candidate_error_cannot_partially_mutate_live_state() {
        let (_dir, daemon) = test_daemon();
        let server_ref = server_ref_for_canonical("candidate-error");
        let error =
            mutate_dead_server_membership(&daemon, |candidate| -> Result<(), (u16, String)> {
                candidate.dead_server_refs.insert(server_ref.clone());
                candidate.dead_promoted_at.insert(server_ref.clone(), 123);
                Err((409, "injected candidate rejection".to_owned()))
            })
            .expect_err("candidate mutation must reject");
        assert_eq!(error.0, 409);
        let inner = lock(&daemon.inner);
        assert!(inner.state.dead_server_refs.is_empty());
        assert!(inner.state.dead_promoted_at.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn dead_membership_activation_failure_rolls_back_only_lifecycle_fields() {
        let dir = TempDir::new().expect("temp dir");
        let script = dir.path().join("fake-mihomo.sh");
        let marker = dir.path().join("new-config-started");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\nif [ \"$1\" = \"-t\" ]; then exit 0; fi\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-f\" ]; then shift; cfg=$1; fi; shift; done\nif grep -q OLD \"$cfg\"; then sleep 30; else touch '{}'; sleep 1; exit 1; fi\n",
                marker.display()
            ),
        )
        .expect("fake mihomo");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod");
        let mut state = HincyrayState {
            profiles: vec![
                sample_profile(0, "Active", "active.example"),
                sample_profile(1, "Pinned", "pinned.example"),
            ],
            active_profile_id: Some(0),
            mihomo_path: script.to_string_lossy().into_owned(),
            ..Default::default()
        };
        state.split_routing.enabled = true;
        sync_server_route_registry(&mut state);
        let pinned_ref = state
            .server_route_registry
            .iter()
            .find(|entry| entry.canonical_raw == canonical_profile_raw(&state.profiles[1]))
            .expect("pinned routing ref")
            .server_ref
            .clone();
        let pinned_lifecycle_ref = profile_server_ref(&state.profiles[1]);
        state.routing_rules.push(RoutingRule {
            enabled: true,
            target: format!("server:{pinned_ref}"),
            domains: vec!["pinned.example".to_owned()],
            ..Default::default()
        });
        let daemon = Daemon::new(
            state,
            dir.path().join("state.json"),
            dir.path().join("mihomo-config.yaml"),
        );
        atomic_write_config(&daemon.mihomo_config_path, b"OLD exact bytes\n").expect("old config");
        {
            let mut inner = lock(&daemon.inner);
            inner
                .core
                .start(
                    script.to_str().expect("script path"),
                    &daemon.mihomo_config_path,
                    None,
                )
                .expect("old core");
        }

        let request_daemon = daemon.clone();
        let request_ref = pinned_lifecycle_ref.clone();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let request = thread::spawn(move || {
            let result = handle_trash_move(
                &json!({"server_refs": [request_ref]}).to_string(),
                &request_daemon,
            );
            result_tx.send(result).expect("send request result");
        });
        let mut early_result = None;
        for _ in 0..100 {
            if marker.exists() {
                break;
            }
            if let Ok(result) = result_rx.try_recv() {
                early_result = Some(result);
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert!(
            marker.exists(),
            "new runtime config was not started; early result: {early_result:?}"
        );
        {
            let mut inner = lock(&daemon.inner);
            inner.state.traffic_total_up_bytes = 777;
            persist_state(&daemon.state_path, &inner.state).expect("persist concurrent update");
        }
        let (status, _, body) = match early_result {
            Some(result) => result,
            None => result_rx.recv().expect("receive request result"),
        };
        request.join().expect("request thread");
        assert_eq!(status, 500, "{body}");
        assert!(body.contains("state rollback: restored"), "{body}");
        assert_eq!(
            fs::read(&daemon.mihomo_config_path).expect("rolled back config"),
            b"OLD exact bytes\n"
        );
        {
            let mut inner = lock(&daemon.inner);
            assert!(!inner.state.dead_server_refs.contains(&pinned_lifecycle_ref));
            assert_eq!(inner.state.traffic_total_up_bytes, 777);
            assert!(inner.core.is_running());
            let _ = inner.core.stop();
        }
        let persisted = load_state(&daemon.state_path);
        assert!(!persisted.dead_server_refs.contains(&pinned_lifecycle_ref));
        assert_eq!(persisted.traffic_total_up_bytes, 777);
    }

    #[test]
    fn dead_server_cannot_be_activated_until_restored() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@dead.example:443#Dead",
            &daemon,
        );
        {
            let mut inner = lock(&daemon.inner);
            let server_ref = profile_server_ref(&inner.state.profiles[0]);
            inner.state.dead_server_refs.insert(server_ref);
        }

        let (status, _, body) = handle_set_active(r#"{"profile_id":0}"#, &daemon);
        assert_eq!(status, 409, "{body}");
        assert!(body.contains("restore it first"));
        assert_eq!(lock(&daemon.inner).state.active_profile_id, None);
    }

    #[test]
    fn startup_reconciles_legacy_active_dead_membership() {
        let dir = TempDir::new().expect("temp dir");
        let state_path = dir.path().join("state.json");
        let mut state = HincyrayState::default();
        state
            .profiles
            .push(make_profile(0, "Active", "raw-active", None));
        state.active_profile_id = Some(0);
        let active_ref = profile_server_ref(&state.profiles[0]);
        state.dead_server_refs.insert(active_ref.clone());
        state.dead_promoted_at.insert(active_ref.clone(), 123);
        persist_state(&state_path, &state).expect("persist contradictory legacy state");

        let loaded = load_state(&state_path);
        assert_eq!(loaded.active_profile_id, Some(0));
        assert!(!loaded.dead_server_refs.contains(&active_ref));
        assert!(!loaded.dead_promoted_at.contains_key(&active_ref));
        let persisted: Value =
            serde_json::from_str(&fs::read_to_string(&state_path).expect("read reconciled state"))
                .expect("parse reconciled state");
        assert_eq!(persisted["dead_server_refs"], json!([]));
        assert_eq!(persisted["dead_promoted_at"], json!({}));
    }

    #[test]
    fn benchmark_scopes_exclude_dead_unless_explicitly_requested() {
        let subscription = "https://provider.example/sub";
        let mut state = HincyrayState::default();
        state.subscriptions.push(StoredSubscription {
            url: subscription.to_owned(),
            ..Default::default()
        });
        state.profiles = vec![
            make_profile(10, "Dead", "raw-dead", Some(subscription)),
            make_profile(20, "Live subscription", "raw-live-sub", Some(subscription)),
            make_profile(30, "Live manual", "raw-live-manual", None),
        ];
        let dead_ref = profile_server_ref(&state.profiles[0]);
        state.dead_server_refs.insert(dead_ref.clone());

        let all_ids: HashSet<usize> = select_profiles_for_quick_bench(&state, None, None)
            .expect("all quick scope")
            .into_iter()
            .map(|profile| profile.id)
            .collect();
        assert_eq!(all_ids, HashSet::from([20, 30]));
        let subscription_ids: Vec<usize> =
            select_profiles_for_quick_bench(&state, Some(subscription), None)
                .expect("subscription quick scope")
                .into_iter()
                .map(|profile| profile.id)
                .collect();
        assert_eq!(subscription_ids, vec![20]);
        let explicit_ids: Vec<usize> = select_profiles_for_quick_bench(&state, None, Some(&[10]))
            .expect("explicit diagnostic scope")
            .into_iter()
            .map(|profile| profile.id)
            .collect();
        assert_eq!(explicit_ids, vec![10]);
        assert_eq!(
            select_profiles_for_quick_bench(&state, None, Some(&[999]))
                .expect_err("unknown explicit id must reject whole scope")
                .0,
            404
        );

        state.deep_bench.profile_filter = ProfileFilter::All;
        let deep_all: HashSet<usize> = select_profiles_for_deep_bench(&state)
            .into_iter()
            .map(|profile| profile.id)
            .collect();
        assert_eq!(deep_all, HashSet::from([20, 30]));
        state.deep_bench.profile_filter = ProfileFilter::Subscription(subscription.to_owned());
        assert_eq!(select_profiles_for_deep_bench(&state)[0].id, 20);
        state.deep_bench.profile_filter = ProfileFilter::Explicit(vec![dead_ref]);
        assert_eq!(select_profiles_for_deep_bench(&state)[0].id, 10);
    }

    #[test]
    fn purge_subscription_removes_source_and_profiles() {
        let mut state = HincyrayState::default();
        let url = "https://provider.example/sub";

        state
            .profiles
            .push(make_profile(0, "Sub1", "raw1", Some(url)));
        state
            .profiles
            .push(make_profile(1, "Sub2", "raw2", Some(url)));
        state.profiles.push(make_profile(2, "Direct", "raw3", None));
        state.active_profile_id = Some(0); // Sub1 — will be removed
        state.subscriptions.push(StoredSubscription {
            url: url.to_owned(),
            ..Default::default()
        });

        let removed_active = purge_subscription(&mut state, url);

        assert!(removed_active);
        assert_eq!(state.profiles.len(), 1);
        assert_eq!(state.profiles[0].raw, "raw3");
        assert_eq!(state.profiles[0].id, 0);
        assert_eq!(state.active_profile_id, None);
        assert!(state.subscriptions.is_empty());
    }

    #[test]
    fn purge_subscription_preserves_active_from_other_group() {
        let mut state = HincyrayState::default();
        let url = "https://provider.example/sub";

        state
            .profiles
            .push(make_profile(0, "Sub1", "raw1", Some(url)));
        state.profiles.push(make_profile(1, "Direct", "raw2", None));
        state.active_profile_id = Some(1); // Direct — not in subscription
        state.subscriptions.push(StoredSubscription {
            url: url.to_owned(),
            ..Default::default()
        });

        let removed_active = purge_subscription(&mut state, url);

        assert!(!removed_active);
        assert_eq!(state.profiles.len(), 1);
        assert_eq!(state.profiles[0].raw, "raw2");
        assert_eq!(state.profiles[0].id, 0);
        assert_eq!(state.active_profile_id, Some(0));
    }

    #[test]
    fn purge_profile_group_removes_named_group_without_subscription_record() {
        let mut state = HincyrayState::default();
        let group = "Tutnet online";

        state
            .profiles
            .push(make_profile(0, "Sub1", "raw1", Some(group)));
        state
            .profiles
            .push(make_profile(1, "Sub2", "raw2", Some(group)));
        state
            .profiles
            .push(make_profile(2, "Other", "raw3", Some("Other group")));
        state.active_profile_id = Some(0);

        let (removed, removed_active) = purge_profile_group(&mut state, group);

        assert_eq!(removed, 2);
        assert!(removed_active);
        assert_eq!(state.profiles.len(), 1);
        assert_eq!(state.profiles[0].id, 0);
        assert_eq!(state.profiles[0].raw, "raw3");
        assert_eq!(state.active_profile_id, None);
    }

    #[test]
    fn profile_group_share_returns_all_links_for_named_group() {
        let (_dir, daemon) = test_daemon();
        let group = "Named subscription";
        {
            let mut inner = lock(&daemon.inner);
            inner
                .state
                .profiles
                .push(make_profile(0, "Sub1", "raw1", Some(group)));
            inner
                .state
                .profiles
                .push(make_profile(1, "Sub2", "raw2", Some(group)));
        }

        let (status, _, body) = dispatch(
            "POST",
            "/api/profile-groups/share",
            &json!({"group": group}).to_string(),
            &daemon,
        );

        assert_eq!(status, 200);
        let response: Value = serde_json::from_str(&body).expect("parse");
        assert_eq!(response["group"], group);
        assert_eq!(response["profile_count"], 2);
        assert_eq!(response["link"], "raw1\nraw2");
        assert_eq!(response["links"].as_array().expect("links").len(), 2);
    }

    #[test]
    fn profile_group_delete_removes_named_group() {
        let (_dir, daemon) = test_daemon();
        let group = "Named subscription";
        {
            let mut inner = lock(&daemon.inner);
            inner
                .state
                .profiles
                .push(make_profile(0, "Sub1", "raw1", Some(group)));
            inner
                .state
                .profiles
                .push(make_profile(1, "Other", "raw2", Some("Other")));
        }

        let (status, _, body) = dispatch(
            "POST",
            "/api/profile-groups/delete",
            &json!({"group": group}).to_string(),
            &daemon,
        );

        assert_eq!(status, 200);
        let response: Value = serde_json::from_str(&body).expect("parse");
        assert_eq!(response["removed_profiles"], 1);
        let inner = lock(&daemon.inner);
        assert_eq!(inner.state.profiles.len(), 1);
        assert_eq!(inner.state.profiles[0].group.as_deref(), Some("Other"));
    }

    #[test]
    fn subscriptions_delete_removes_subscription_and_profiles() {
        let (_dir, daemon) = test_daemon();
        let url = "https://provider.example/sub";
        {
            let mut inner = lock(&daemon.inner);
            inner
                .state
                .profiles
                .push(make_profile(0, "Sub1", "raw1", Some(url)));
            inner
                .state
                .profiles
                .push(make_profile(1, "Sub2", "raw2", Some(url)));
            inner
                .state
                .profiles
                .push(make_profile(2, "Direct", "raw3", None));
            inner.state.subscriptions.push(StoredSubscription {
                url: url.to_owned(),
                ..Default::default()
            });
        }

        let (status, _, body) = dispatch(
            "POST",
            "/api/subscriptions/delete",
            &json!({"url": url}).to_string(),
            &daemon,
        );

        assert_eq!(status, 200);
        let response: Value = serde_json::from_str(&body).expect("parse");
        assert_eq!(response["removed_profiles"], 2);

        let inner = lock(&daemon.inner);
        assert_eq!(inner.state.profiles.len(), 1);
        assert_eq!(inner.state.profiles[0].raw, "raw3");
        assert!(inner.state.subscriptions.is_empty());
    }

    #[test]
    fn subscriptions_delete_rejects_unknown_url() {
        let (_dir, daemon) = test_daemon();
        let (status, _, _) = dispatch(
            "POST",
            "/api/subscriptions/delete",
            r#"{"url":"https://provider.example/sub/never-saved"}"#,
            &daemon,
        );
        assert_eq!(status, 404);
    }

    #[test]
    fn subscriptions_delete_rejects_missing_url() {
        let (_dir, daemon) = test_daemon();
        let (status, _, body) = dispatch("POST", "/api/subscriptions/delete", r#"{}"#, &daemon);
        assert_eq!(status, 400);
        assert!(body.contains("missing url"));
    }

    // ── Mihomo update tests ─────────────────────────────────────────

    #[test]
    fn is_newer_version_compares_correctly() {
        assert!(is_newer_version("v1.19.27", "v1.19.28"));
        assert!(is_newer_version("v1.19.27", "v1.20.0"));
        assert!(is_newer_version("v1.19.27", "v2.0.0"));
        assert!(!is_newer_version("v1.19.27", "v1.19.27"));
        assert!(!is_newer_version("v1.19.28", "v1.19.27"));
        assert!(!is_newer_version("v2.0.0", "v1.19.27"));
        // Without 'v' prefix
        assert!(is_newer_version("1.19.27", "1.19.28"));
        // Different number of parts
        assert!(is_newer_version("v1.19", "v1.19.1"));
        assert!(!is_newer_version("v1.19.1", "v1.19"));
    }

    #[test]
    fn update_status_endpoint_returns_defaults() {
        let (_dir, daemon) = test_daemon();
        let (status, _, body) = dispatch("GET", "/api/update/status", "", &daemon);
        assert_eq!(status, 200);
        let response: Value = serde_json::from_str(&body).expect("parse");
        assert_eq!(response["auto_update_enabled"], false);
        assert_eq!(response["auto_update_interval_hours"], 24);
        assert_eq!(response["last_update_check_unix"], 0);
        assert!(response["current_version"].is_null());
        assert!(response["update_available_version"].is_null());
    }

    #[test]
    fn update_settings_endpoint_persists() {
        let (_dir, daemon) = test_daemon();
        let body = r#"{"auto_update_enabled":true,"auto_update_interval_hours":12}"#;
        let (status, _, response) = dispatch("POST", "/api/update/settings", body, &daemon);
        assert_eq!(status, 200);
        assert!(response.contains("\"auto_update_enabled\":true"));
        assert!(response.contains("\"auto_update_interval_hours\":12"));
        let inner = lock(&daemon.inner);
        assert!(inner.state.auto_update_enabled);
        assert_eq!(inner.state.auto_update_interval_hours, 12);
    }

    #[test]
    fn update_check_returns_400_when_core_stopped() {
        let (_dir, daemon) = test_daemon();
        let (status, _, body) = dispatch("POST", "/api/update/check", "", &daemon);
        assert_eq!(status, 400);
        assert!(body.contains("not running"));
    }

    #[test]
    fn update_apply_returns_400_when_core_stopped() {
        let (_dir, daemon) = test_daemon();
        let (status, _, body) = dispatch("POST", "/api/update/apply", "", &daemon);
        assert_eq!(status, 400);
        assert!(body.contains("not running"));
    }

    #[test]
    fn status_endpoint_includes_update_fields() {
        let (_dir, daemon) = test_daemon();
        let (status, _, body) = dispatch("GET", "/api/status", "", &daemon);
        assert_eq!(status, 200);
        assert!(body.contains("\"mihomo_version\""));
        assert!(body.contains("\"update_available_version\""));
    }

    #[test]
    fn update_settings_rejects_invalid_json() {
        let (_dir, daemon) = test_daemon();
        let (status, _, _) = dispatch("POST", "/api/update/settings", "not json", &daemon);
        assert_eq!(status, 400);
    }

    #[test]
    fn legacy_state_without_update_fields_loads_with_defaults() {
        let dir = TempDir::new().expect("temp dir");
        let state_path = dir.path().join("state.json");
        let legacy = r#"{
            "profiles": [],
            "active_profile_id": null,
            "auto_select": false,
            "listen_host": "127.0.0.1",
            "socks_port": 10808,
            "mihomo_path": "mihomo",
            "metrics_history": [],
            "routing_rules": []
        }"#;
        fs::write(&state_path, legacy).expect("write legacy state");
        let loaded = load_state(&state_path);
        assert!(!loaded.auto_update_enabled);
        assert_eq!(loaded.auto_update_interval_hours, 24);
        assert_eq!(loaded.last_update_check_unix, 0);
        assert!(loaded.update_available_version.is_none());
        assert!(loaded.mihomo_version.is_none());
    }

    // ── Mihomo external-controller API proxy tests ─────────────────

    #[test]
    fn mihomo_controller_returns_none_when_disabled() {
        let features = MihomoFeatures::default();
        assert!(mihomo_controller(&features).is_none());
    }

    #[test]
    fn mihomo_controller_returns_some_when_enabled() {
        let mut features = MihomoFeatures::default();
        features.external_controller.enabled = true;
        features.external_controller.address = "127.0.0.1:9090".to_owned();
        let ec = mihomo_controller(&features).expect("ec");
        assert_eq!(ec.0, "127.0.0.1:9090");
    }

    #[test]
    fn api_proxies_returns_400_when_ec_disabled() {
        let (_dir, daemon) = test_daemon();
        let (code, _, body) = handle_mihomo_api_proxies(&daemon);
        assert_eq!(code, 400);
        assert!(body.contains("not enabled"));
    }

    #[test]
    fn api_connections_returns_400_when_ec_disabled() {
        let (_dir, daemon) = test_daemon();
        let (code, _, body) = handle_mihomo_api_connections(&daemon);
        assert_eq!(code, 400);
        assert!(body.contains("not enabled"));
    }

    #[test]
    fn api_delay_returns_400_when_ec_disabled() {
        let (_dir, daemon) = test_daemon();
        let (code, _, body) = handle_mihomo_api_delay(r#"{"name":"proxy"}"#, &daemon);
        assert_eq!(code, 400);
        assert!(body.contains("not enabled"));
    }

    #[test]
    fn api_delay_returns_400_on_invalid_json() {
        let (_dir, daemon) = test_daemon();
        // Enable EC so we pass the first check, then test JSON parsing.
        {
            let mut inner = lock(&daemon.inner);
            inner.state.mihomo_features.external_controller.enabled = true;
            inner.state.mihomo_features.external_controller.address = "127.0.0.1:9090".to_owned();
        }
        let (code, _, body) = handle_mihomo_api_delay("not json", &daemon);
        assert_eq!(code, 400);
        assert!(body.contains("invalid JSON"));
    }

    #[test]
    fn api_delay_empty_body_uses_defaults() {
        let (_dir, daemon) = test_daemon();
        {
            let mut inner = lock(&daemon.inner);
            inner.state.mihomo_features.external_controller.enabled = true;
            inner.state.mihomo_features.external_controller.address = "127.0.0.1:9090".to_owned();
        }
        // Empty body should not return 400 "invalid JSON" — it should
        // fall through to the delay test (which will fail because no
        // Mihomo is running, but the error is a connection error, not
        // a parse error).
        let (code, _, body) = handle_mihomo_api_delay("", &daemon);
        assert_ne!(code, 400);
        assert!(!body.contains("invalid JSON"));
    }

    #[test]
    fn status_includes_proxy_group_and_ec_flags() {
        let (_dir, daemon) = test_daemon();
        let (code, _, body) = dispatch("GET", "/api/status", "", &daemon);
        assert_eq!(code, 200);
        let json: Value = serde_json::from_str(&body).expect("parse status");
        assert!(json.get("proxy_group_enabled").is_some());
        assert!(json.get("ec_enabled").is_some());
    }

    #[test]
    fn auto_settings_include_refresh_fields() {
        let (_dir, daemon) = test_daemon();
        let (status, _, body) = handle_auto_settings_get(&daemon);
        assert_eq!(status, 200);
        let resp: Value = serde_json::from_str(&body).expect("parse response");
        assert_eq!(resp["auto_refresh_enabled"], false);
        assert_eq!(resp["auto_refresh_interval_hours"], 0);
    }

    #[test]
    fn auto_settings_set_refresh_persists() {
        let (_dir, daemon) = test_daemon();
        let body = r#"{"auto_refresh_enabled":true,"auto_refresh_interval_hours":6}"#;
        let (status, _, resp) = handle_auto_settings_set(body, &daemon);
        assert_eq!(status, 200);
        assert!(resp.contains("\"auto_refresh_enabled\":true"));
        assert!(resp.contains("\"auto_refresh_interval_hours\":6"));
        let inner = lock(&daemon.inner);
        assert!(inner.state.auto_refresh_enabled);
        assert_eq!(inner.state.auto_refresh_interval_hours, 6);
    }

    #[test]
    fn traffic_stats_returns_defaults() {
        let (_dir, daemon) = test_daemon();
        let (status, _, body) = handle_traffic_stats(&daemon);
        assert_eq!(status, 200);
        let resp: Value = serde_json::from_str(&body).expect("parse response");
        assert_eq!(resp["total_up_bytes"], 0);
        assert_eq!(resp["total_down_bytes"], 0);
    }

    #[test]
    fn traffic_stats_accumulate_persists() {
        let (_dir, daemon) = test_daemon();
        {
            let mut inner = lock(&daemon.inner);
            inner.state.traffic_total_up_bytes = 1_000_000;
            inner.state.traffic_total_down_bytes = 5_000_000;
        }
        let (_, _, body) = handle_traffic_stats(&daemon);
        let resp: Value = serde_json::from_str(&body).expect("parse response");
        assert_eq!(resp["total_up_bytes"], 1_000_000);
        assert_eq!(resp["total_down_bytes"], 5_000_000);
    }

    #[test]
    fn speed_test_returns_400_when_core_stopped() {
        let (_dir, daemon) = test_daemon();
        let (status, _, body) = handle_speed_test("{}", &daemon);
        assert_eq!(status, 400);
        assert!(body.contains("core is not running"));
    }

    #[test]
    fn connection_log_returns_empty_by_default() {
        let (_dir, daemon) = test_daemon();
        let (status, _, body) = handle_connection_log(&daemon);
        assert_eq!(status, 200);
        let resp: Value = serde_json::from_str(&body).expect("parse response");
        assert_eq!(resp["count"], 0);
    }

    #[test]
    fn connection_log_returns_entries() {
        let (_dir, daemon) = test_daemon();
        {
            let mut inner = lock(&daemon.inner);
            inner.state.connection_log.push(ConnectionLogEntry {
                timestamp: 1234567890,
                host: "example.com".to_owned(),
                source_ip: "192.168.2.35".to_owned(),
                destination_ip: "1.2.3.4".to_owned(),
                destination_port: 443,
                network: "tcp".to_owned(),
                chains: vec!["proxy-active".to_owned()],
                rule: "DOMAIN-SUFFIX".to_owned(),
                upload: 1024,
                download: 4096,
            });
        }
        let (_, _, body) = handle_connection_log(&daemon);
        let resp: Value = serde_json::from_str(&body).expect("parse response");
        assert_eq!(resp["count"], 1);
        let entries = resp["entries"].as_array().expect("entries array");
        assert_eq!(entries[0]["host"], "example.com");
        assert_eq!(entries[0]["source_ip"], "192.168.2.35");
    }

    #[test]
    fn device_routes_add_and_list() {
        let (_dir, daemon) = test_daemon();
        let body = r#"{"enabled":true,"name":"Pixel 6a","ip":"192.168.2.35","mac":"aa:bb:cc:dd:ee:ff","target":"direct"}"#;
        let (status, _, resp) = handle_device_routes_set(body, &daemon);
        assert_eq!(status, 200);
        let resp: Value = serde_json::from_str(&resp).expect("parse response");
        assert_eq!(resp["count"], 1);

        let (status, _, body) = handle_device_routes_list(&daemon);
        assert_eq!(status, 200);
        let resp: Value = serde_json::from_str(&body).expect("parse response");
        assert_eq!(resp["count"], 1);
        let routes = resp["routes"].as_array().expect("routes array");
        assert_eq!(routes[0]["ip"], "192.168.2.35");
        assert_eq!(routes[0]["target"], "direct");
    }

    #[test]
    fn device_routes_delete() {
        let (_dir, daemon) = test_daemon();
        handle_device_routes_set(
            r#"{"ip":"192.168.2.35","target":"direct","name":"Test"}"#,
            &daemon,
        );
        let (status, _, body) = handle_device_routes_delete(r#"{"ip":"192.168.2.35"}"#, &daemon);
        assert_eq!(status, 200);
        let resp: Value = serde_json::from_str(&body).expect("parse response");
        assert_eq!(resp["remaining"], 0);
    }

    #[test]
    fn device_routes_appear_in_config() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443#Active",
            &daemon,
        );
        {
            let mut inner = lock(&daemon.inner);
            inner.state.active_profile_id = Some(0);
            inner.state.split_routing.enabled = true;
            inner.state.device_routes.push(DeviceRoute {
                enabled: true,
                name: "Pixel".to_owned(),
                ip: "192.168.2.35".to_owned(),
                target: "direct".to_owned(),
                ..Default::default()
            });
        }
        let (status, _, body) = handle_get_mihomo_config(&daemon);
        assert_eq!(status, 200);
        let config: Value = serde_yaml::from_str(&body).expect("parse config");
        let rules = config["rules"].as_array().expect("rules array");
        assert!(
            rules.iter().any(|r| {
                r.as_str().is_some_and(|s| {
                    s.contains("SRC-IP-CIDR") && s.contains("192.168.2.35") && s.contains("DIRECT")
                })
            }),
            "device route SRC-IP-CIDR rule not found in config"
        );
    }

    #[test]
    fn routing_rule_reject_target_in_config() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443#Active",
            &daemon,
        );
        {
            let mut inner = lock(&daemon.inner);
            inner.state.active_profile_id = Some(0);
            inner.state.split_routing.enabled = true;
            inner.state.routing_rules.push(RoutingRule {
                enabled: true,
                name: "Block ads".to_owned(),
                target: "reject".to_owned(),
                domains: vec!["geosite:category-ads-all".to_owned()],
                ..Default::default()
            });
        }
        let (status, _, body) = handle_get_mihomo_config(&daemon);
        assert_eq!(status, 200);
        let config: Value = serde_yaml::from_str(&body).expect("parse config");
        let rules = config["rules"].as_array().expect("rules array");
        assert!(
            rules.iter().any(|r| {
                r.as_str()
                    .is_some_and(|s| s.contains("GEOSITE,category-ads-all") && s.contains("REJECT"))
            }),
            "REJECT rule not found in config, rules: {rules:?}"
        );
    }

    #[test]
    fn device_route_reject_target_in_config() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443#Active",
            &daemon,
        );
        {
            let mut inner = lock(&daemon.inner);
            inner.state.active_profile_id = Some(0);
            inner.state.split_routing.enabled = true;
            inner.state.device_routes.push(DeviceRoute {
                enabled: true,
                name: "Blocked device".to_owned(),
                ip: "192.168.2.99".to_owned(),
                target: "reject".to_owned(),
                ..Default::default()
            });
        }
        let (status, _, body) = handle_get_mihomo_config(&daemon);
        assert_eq!(status, 200);
        let config: Value = serde_yaml::from_str(&body).expect("parse config");
        let rules = config["rules"].as_array().expect("rules array");
        assert!(
            rules.iter().any(|r| {
                r.as_str().is_some_and(|s| {
                    s.contains("SRC-IP-CIDR,192.168.2.99/32") && s.contains("REJECT")
                })
            }),
            "device route REJECT rule not found in config, rules: {rules:?}"
        );
    }

    #[test]
    fn routing_presets_list_returns_presets() {
        let (status, _, body) = handle_routing_presets_list();
        assert_eq!(status, 200);
        let value: Value = serde_json::from_str(&body).expect("parse json");
        let presets = value["presets"].as_array().expect("presets array");
        assert!(!presets.is_empty(), "presets should not be empty");
        let ids: Vec<&str> = presets.iter().filter_map(|p| p["id"].as_str()).collect();
        assert!(ids.contains(&"ru-ip-direct"), "ru-ip-direct preset missing");
        assert!(ids.contains(&"all-vpn"), "all-vpn preset missing");
        assert!(ids.contains(&"ad-block"), "ad-block preset missing");
        assert!(ids.contains(&"only-web-vpn"), "only-web-vpn preset missing");
        assert!(ids.contains(&"block-social"), "block-social preset missing");
        assert!(
            ids.contains(&"ru-ip-direct-ad-block"),
            "ru-ip-direct-ad-block preset missing"
        );
    }

    #[test]
    fn routing_preset_ad_block_is_rejected_as_router_unsafe() {
        let (_dir, daemon) = test_daemon();
        let (status, _, body) = handle_routing_preset_apply(r#"{"preset":"ad-block"}"#, &daemon);
        assert_eq!(status, 400);
        let result: Value = serde_json::from_str(&body).expect("parse json");
        assert!(result["error"].as_str().expect("error").contains("unsafe"));
    }

    #[test]
    fn routing_preset_apply_ru_ip_direct_adds_geoip_rule() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443#Active",
            &daemon,
        );
        lock(&daemon.inner).state.active_profile_id = Some(0);
        let (status, _, body) =
            handle_routing_preset_apply(r#"{"preset":"ru-ip-direct"}"#, &daemon);
        assert_eq!(status, 200);
        let result: Value = serde_json::from_str(&body).expect("parse json");
        assert_eq!(result["rules_added"], json!(1));

        let inner = lock(&daemon.inner);
        assert_eq!(inner.state.routing_rules.len(), 1);
        assert_eq!(inner.state.routing_rules[0].target, "direct");
        assert_eq!(inner.state.routing_rules[0].ips, vec!["geoip:RU"]);
    }

    #[test]
    fn routing_preset_apply_deduplicates_by_name() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443#Active",
            &daemon,
        );
        {
            let mut inner = lock(&daemon.inner);
            inner.state.active_profile_id = Some(0);
            inner.state.split_routing.enabled = true;
            inner.state.routing_rules.push(RoutingRule {
                enabled: true,
                name: "Block ads".to_owned(),
                target: "reject".to_owned(),
                domains: vec!["geosite:category-ads-all".to_owned()],
                ..Default::default()
            });
        }
        // Apply ad-block preset — should be rejected before it can duplicate
        // or persist a known router-OOM GEOSITE rule.
        let (status, _, body) = handle_routing_preset_apply(r#"{"preset":"ad-block"}"#, &daemon);
        assert_eq!(status, 400);
        let result: Value = serde_json::from_str(&body).expect("parse json");
        assert!(result["error"].as_str().expect("error").contains("unsafe"));

        let inner = lock(&daemon.inner);
        assert_eq!(
            inner.state.routing_rules.len(),
            1,
            "should not duplicate rule with same name"
        );
    }

    #[test]
    fn routing_preset_apply_only_web_vpn_changes_port_mode() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443#Active",
            &daemon,
        );
        {
            let mut inner = lock(&daemon.inner);
            inner.state.active_profile_id = Some(0);
            inner.state.split_routing.enabled = true;
        }
        let (status, _, body) =
            handle_routing_preset_apply(r#"{"preset":"only-web-vpn"}"#, &daemon);
        assert_eq!(status, 200);
        let result: Value = serde_json::from_str(&body).expect("parse json");
        assert_eq!(result["port_mode"], json!("allow_list"));

        let inner = lock(&daemon.inner);
        assert!(matches!(
            inner.state.split_routing.port_mode,
            PortMode::AllowList
        ));
        assert_eq!(inner.state.split_routing.proxy_ports, vec!["80", "443"]);
    }

    #[test]
    fn routing_preset_all_vpn_clears_rules_and_sets_all_ports() {
        let (_dir, daemon) = test_daemon();
        {
            let mut inner = lock(&daemon.inner);
            inner.state.routing_rules.push(RoutingRule {
                enabled: true,
                name: "RU direct".to_owned(),
                target: "direct".to_owned(),
                ips: vec!["geoip:RU".to_owned()],
                ..Default::default()
            });
            inner.state.split_routing.port_mode = PortMode::AllowList;
            inner.state.split_routing.proxy_ports = vec!["80".to_owned(), "443".to_owned()];
        }

        let (status, _, body) = handle_routing_preset_apply(r#"{"preset":"all-vpn"}"#, &daemon);
        assert_eq!(status, 200);
        let result: Value = serde_json::from_str(&body).expect("parse json");
        assert_eq!(result["rules_cleared"], json!(true));

        let inner = lock(&daemon.inner);
        assert!(inner.state.routing_rules.is_empty());
        assert!(matches!(inner.state.split_routing.port_mode, PortMode::All));
    }

    #[test]
    fn routing_preset_apply_unknown_returns_400() {
        let (_dir, daemon) = test_daemon();
        let (status, _, body) = handle_routing_preset_apply(r#"{"preset":"nonexistent"}"#, &daemon);
        assert_eq!(status, 400);
        let result: Value = serde_json::from_str(&body).expect("parse json");
        assert_eq!(result["error"], json!("unknown preset"));
    }

    #[test]
    fn routing_rules_reject_known_oom_geosite() {
        let (_dir, daemon) = test_daemon();
        let body = r#"{"rules":[{"enabled":true,"name":"Ads","target":"reject","domains":["geosite:category-ads-all"]}]}"#;
        let (status, _, response) = handle_routing_rules(body, &daemon);
        assert_eq!(status, 400);
        assert!(response.contains("unsafe"));

        let inner = lock(&daemon.inner);
        assert!(inner.state.routing_rules.is_empty());
    }

    #[test]
    fn routing_rule_deletion_survives_apply_validation_failure() {
        let (_dir, daemon) = test_daemon();
        {
            let mut inner = lock(&daemon.inner);
            inner.state.routing_rules.push(RoutingRule {
                enabled: true,
                name: "Remove me".to_owned(),
                target: "active".to_owned(),
                domains: vec!["remove.example".to_owned()],
                ..Default::default()
            });
            inner.state.mihomo_path = "/definitely/missing/mihomo".to_owned();
            persist_state(&daemon.state_path, &inner.state).expect("persist initial state");
        }

        let (status, _, body) = handle_routing_rules(r#"{"rules":[],"apply":true}"#, &daemon);
        assert_eq!(status, 200, "{body}");
        let response: Value = serde_json::from_str(&body).expect("response");
        assert_eq!(response["applied"], false);
        assert_eq!(response["requires_apply"], true);
        assert!(response["activation_error"].as_str().is_some());
        assert!(lock(&daemon.inner).state.routing_rules.is_empty());
        assert!(
            load_state(&daemon.state_path)
                .routing_rules
                .iter()
                .all(|rule| rule.name != "Remove me")
        );
    }

    #[test]
    fn routing_rule_deletion_classifier_rejects_mixed_edits() {
        let first = RoutingRule {
            name: "First".to_owned(),
            ..Default::default()
        };
        let second = RoutingRule {
            name: "Second".to_owned(),
            ..Default::default()
        };
        let edited = RoutingRule {
            name: "Edited".to_owned(),
            ..Default::default()
        };

        assert!(routing_rules_are_strict_deletion(
            &[first.clone(), second.clone()],
            std::slice::from_ref(&second)
        ));
        assert!(!routing_rules_are_strict_deletion(
            &[first, second],
            &[edited]
        ));
    }

    #[test]
    fn routing_rule_addition_rolls_back_on_apply_validation_failure() {
        let (_dir, daemon) = test_daemon();
        lock(&daemon.inner).state.mihomo_path = "/definitely/missing/mihomo".to_owned();
        let body = r#"{"rules":[{"enabled":true,"name":"New","target":"active","domains":["new.example"]}],"apply":true}"#;

        let (status, _, response) = handle_routing_rules(body, &daemon);
        assert_eq!(status, 500, "{response}");
        assert!(response.contains("state rollback: restored"), "{response}");
        assert!(lock(&daemon.inner).state.routing_rules.is_empty());
    }

    #[test]
    fn check_auth_disabled_allows_all() {
        let (_dir, daemon) = test_daemon();
        assert!(check_auth(&daemon, &None, "/api/status", "GET"));
        assert!(check_auth(&daemon, &None, "/api/profiles", "GET"));
    }

    #[test]
    fn check_auth_enabled_blocks_without_token() {
        let (_dir, daemon) = test_daemon();
        {
            let mut inner = lock(&daemon.inner);
            inner.state.web_ui_auth.enabled = true;
            inner.state.web_ui_auth.username = "admin".to_owned();
            inner
                .state
                .web_ui_auth
                .set_password("secret")
                .expect("hash");
        }
        assert!(!check_auth(&daemon, &None, "/api/status", "GET"));
        assert!(!check_auth(&daemon, &None, "/api/profiles", "GET"));
    }

    #[test]
    fn check_auth_allows_public_paths_when_enabled() {
        let (_dir, daemon) = test_daemon();
        {
            let mut inner = lock(&daemon.inner);
            inner.state.web_ui_auth.enabled = true;
        }
        assert!(check_auth(&daemon, &None, "/", "GET"));
        assert!(check_auth(&daemon, &None, "/api/health", "GET"));
        assert!(check_auth(&daemon, &None, "/api/auth/login", "POST"));
        assert!(check_auth(&daemon, &None, "/api/auth-settings", "GET"));
    }

    #[test]
    fn check_auth_allows_with_valid_token() {
        let (_dir, daemon) = test_daemon();
        let token = {
            let mut inner = lock(&daemon.inner);
            inner.state.web_ui_auth.enabled = true;
            let t = generate_session_token().expect("token");
            inner
                .sessions
                .insert(t.clone(), WebSession::new(unix_now()));
            t
        };
        let auth_header = Some(format!("Bearer {token}"));
        assert!(check_auth(&daemon, &auth_header, "/api/status", "GET"));
        assert!(check_auth(&daemon, &auth_header, "/api/profiles", "GET"));
    }

    #[test]
    fn check_auth_rejects_invalid_token() {
        let (_dir, daemon) = test_daemon();
        {
            let mut inner = lock(&daemon.inner);
            inner.state.web_ui_auth.enabled = true;
        }
        let auth_header = Some("Bearer invalidtoken123".to_owned());
        assert!(!check_auth(&daemon, &auth_header, "/api/status", "GET"));
    }

    #[test]
    fn auth_login_returns_token() {
        let (_dir, daemon) = test_daemon();
        {
            let mut inner = lock(&daemon.inner);
            inner.state.web_ui_auth.enabled = true;
            inner.state.web_ui_auth.username = "admin".to_owned();
            inner
                .state
                .web_ui_auth
                .set_password("pass123")
                .expect("hash");
        }
        let (status, _, body) = handle_auth_login(
            r#"{"username":"admin","password":"pass123"}"#,
            &daemon,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        );
        assert_eq!(status, 200);
        let result: Value = serde_json::from_str(&body).expect("parse json");
        assert_eq!(result["auth_enabled"], json!(true));
        assert!(result["token"].as_str().is_some_and(|t| !t.is_empty()));
    }

    #[test]
    fn auth_login_rejects_wrong_credentials() {
        let (_dir, daemon) = test_daemon();
        {
            let mut inner = lock(&daemon.inner);
            inner.state.web_ui_auth.enabled = true;
            inner.state.web_ui_auth.username = "admin".to_owned();
            inner
                .state
                .web_ui_auth
                .set_password("correct")
                .expect("hash");
        }
        let (status, _, body) = handle_auth_login(
            r#"{"username":"admin","password":"wrong"}"#,
            &daemon,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        );
        assert_eq!(status, 401);
        let result: Value = serde_json::from_str(&body).expect("parse json");
        assert_eq!(result["error"], json!("invalid credentials"));
    }

    #[test]
    fn auth_settings_get_does_not_leak_password() {
        let (_dir, daemon) = test_daemon();
        {
            let mut inner = lock(&daemon.inner);
            inner.state.web_ui_auth.enabled = true;
            inner
                .state
                .web_ui_auth
                .set_password("sensitive")
                .expect("hash");
        }
        let (status, _, body) = handle_auth_settings_get(&daemon);
        assert_eq!(status, 200);
        let result: Value = serde_json::from_str(&body).expect("parse json");
        assert_eq!(result["enabled"], json!(true));
        assert_eq!(result["password_set"], json!(true));
        // Password must NOT appear in the response.
        assert!(
            body.as_str()
                .bytes()
                .position(|b| b == b's')
                .map(|pos| { !body.as_str()[pos..].starts_with("sensitive") })
                .unwrap_or(true)
        );
        assert!(!body.contains("sensitive"));
    }

    #[test]
    fn auth_settings_set_enables_and_persists() {
        let (_dir, daemon) = test_daemon();
        let body = r#"{"enabled":true,"username":"root","password":"hunter2"}"#;
        let (status, _, response) = handle_auth_settings_set(body, &daemon);
        assert_eq!(status, 200);
        let result: Value = serde_json::from_str(&response).expect("parse json");
        assert_eq!(result["enabled"], json!(true));
        assert_eq!(result["username"], json!("root"));
        assert_eq!(result["password_set"], json!(true));

        // Verify state was persisted.
        let inner = lock(&daemon.inner);
        assert!(inner.state.web_ui_auth.enabled);
        assert_eq!(inner.state.web_ui_auth.username, "root");
        assert!(inner.state.web_ui_auth.password.is_empty());
        assert!(
            verify_password("hunter2", &inner.state.web_ui_auth.password_hash).expect("verify")
        );
        let persisted = fs::read_to_string(&daemon.state_path).expect("persisted state");
        assert!(!persisted.contains("hunter2"));
        assert!(!persisted.contains("\"password\""));
    }

    #[test]
    fn auth_settings_set_empty_password_keeps_existing() {
        let (_dir, daemon) = test_daemon();
        {
            let mut inner = lock(&daemon.inner);
            inner
                .state
                .web_ui_auth
                .set_password("existingpass")
                .expect("hash");
        }
        // Send only enabled=true, no password field.
        let body = r#"{"enabled":true}"#;
        let (status, _, _) = handle_auth_settings_set(body, &daemon);
        assert_eq!(status, 200);
        let inner = lock(&daemon.inner);
        assert!(
            verify_password("existingpass", &inner.state.web_ui_auth.password_hash)
                .expect("verify")
        );
    }

    #[test]
    fn auth_logout_clears_session() {
        let (_dir, daemon) = test_daemon();
        let token = {
            let mut inner = lock(&daemon.inner);
            inner.state.web_ui_auth.enabled = true;
            let t = generate_session_token().expect("token");
            inner
                .sessions
                .insert(t.clone(), WebSession::new(unix_now()));
            t
        };
        let body = format!(r#"{{"token":"{token}"}}"#);
        let (status, _, _) = handle_auth_logout(&body, &daemon);
        assert_eq!(status, 200);
        let inner = lock(&daemon.inner);
        assert!(!inner.sessions.contains_key(&token));
    }

    #[test]
    fn legacy_plaintext_auth_migrates_to_hash_without_reserializing_secret() {
        let mut value = serde_json::to_value(HincyrayState::default()).expect("state");
        value["web_ui_auth"] = json!({
            "enabled": true,
            "username": "admin",
            "password": "legacy-secret"
        });
        let state = deserialize_persisted_state(&value.to_string()).expect("migrate");
        assert!(state.web_ui_auth.password.is_empty());
        assert!(
            verify_password("legacy-secret", &state.web_ui_auth.password_hash).expect("verify")
        );
        let serialized = serde_json::to_string(&state).expect("serialize");
        assert!(!serialized.contains("legacy-secret"));
        assert!(!serialized.contains("\"password\""));
    }

    #[test]
    fn failed_auth_migration_preserves_state_disables_auth_and_is_not_corruption() {
        let dir = TempDir::new().expect("temp dir");
        let state_path = dir.path().join("state.json");
        let mut original = HincyrayState::default();
        original
            .profiles
            .push(sample_profile(7, "Preserved", "preserved.example"));
        original.routing_rules.push(RoutingRule {
            enabled: true,
            name: "Preserved rule".to_owned(),
            target: "direct".to_owned(),
            domains: vec!["preserved.example".to_owned()],
            ..RoutingRule::default()
        });
        let mut value = serde_json::to_value(original).expect("state");
        value["web_ui_auth"] = json!({
            "enabled": true,
            "username": "admin",
            "password": "legacy-secret"
        });
        fs::write(&state_path, value.to_string()).expect("write state");

        let loaded =
            load_state_with_hasher(&state_path, |_| Err("simulated Argon2 failure".to_owned()));

        assert_eq!(loaded.profiles.len(), 1);
        assert_eq!(loaded.profiles[0].name, "Preserved");
        assert!(
            loaded
                .routing_rules
                .iter()
                .any(|rule| rule.name == "Preserved rule")
        );
        assert!(!loaded.web_ui_auth.enabled);
        assert!(loaded.web_ui_auth.password.is_empty());
        assert!(loaded.web_ui_auth.password_hash.is_empty());
        assert!(!state_path.with_extension("json.corrupt").exists());

        let persisted = fs::read_to_string(&state_path).expect("persisted state");
        assert!(!persisted.contains("legacy-secret"));
        assert!(!persisted.contains("\"password\""));
        let persisted: HincyrayState = serde_json::from_str(&persisted).expect("valid state");
        assert!(!persisted.web_ui_auth.enabled);
        assert_eq!(persisted.profiles.len(), 1);
        assert!(
            persisted
                .routing_rules
                .iter()
                .any(|rule| rule.name == "Preserved rule")
        );
    }

    #[test]
    fn expired_session_is_rejected_and_removed() {
        let (_dir, daemon) = test_daemon();
        let token = generate_session_token().expect("token");
        {
            let mut inner = lock(&daemon.inner);
            inner.state.web_ui_auth.enabled = true;
            inner.sessions.insert(
                token.clone(),
                WebSession {
                    created_at_unix: 0,
                    last_seen_unix: 0,
                    expires_at_unix: 1,
                },
            );
        }
        assert!(!check_auth(
            &daemon,
            &Some(format!("Bearer {token}")),
            "/api/status",
            "GET"
        ));
        assert!(!lock(&daemon.inner).sessions.contains_key(&token));
    }

    #[test]
    fn origin_contract_accepts_same_host_and_rejects_cross_origin() {
        assert!(origin_matches_host(
            "http://192.168.1.1:8088",
            Some("192.168.1.1:8088")
        ));
        assert!(origin_matches_host(
            "https://router.example",
            Some("router.example")
        ));
        assert!(!origin_matches_host(
            "https://evil.example",
            Some("192.168.1.1:8088")
        ));
    }

    #[test]
    fn cross_origin_preflight_is_rejected() {
        let (_dir, daemon) = test_daemon();
        let rejected = http_request(
            daemon,
            "OPTIONS /api/routing/rules HTTP/1.1\r\nHost: 192.168.1.1:8088\r\nOrigin: https://evil.example\r\n\r\n",
        );
        assert!(rejected.starts_with("HTTP/1.1 403 Forbidden"));
        assert!(!rejected.contains("Access-Control-Allow-Origin"));
    }

    #[test]
    fn fallback_health_requires_the_active_outbound_itself_to_be_alive() {
        let group = json!({"alive": true, "now": "proxy-active"});
        assert!(fallback_routes_through_live_active(
            &group,
            &json!({"alive": true})
        ));
        assert!(!fallback_routes_through_live_active(
            &group,
            &json!({"alive": false})
        ));
        assert!(!fallback_routes_through_live_active(
            &json!({"alive": true, "now": "DIRECT"}),
            &json!({"alive": true})
        ));
    }

    #[test]
    fn ndm_hook_bypasses_dhcp_broadcast_and_local_networks_before_tproxy() {
        let script = generate_ndm_hook_script("0xffffaaa", 10810, "192.168.2.0/24", true);
        for cidr in FIREWALL_BYPASS_CIDRS {
            let nat_rule = format!("iptables -t nat -A HINCYRAY -d {cidr}");
            let udp_rule = format!("iptables -t mangle -A HINCYRAY_UDP -d {cidr}");
            assert!(script.contains(&nat_rule), "missing NAT bypass for {cidr}");
            assert!(script.contains(&udp_rule), "missing UDP bypass for {cidr}");
            assert_eq!(script.matches(&nat_rule).count(), 1);
            assert_eq!(script.matches(&udp_rule).count(), 1);
        }
        let broadcast = script
            .find("iptables -t mangle -A HINCYRAY_UDP -d 255.255.255.255/32")
            .expect("DHCP broadcast bypass");
        let tproxy = script
            .find("iptables -t mangle -A HINCYRAY_UDP -p udp -m comment")
            .expect("TPROXY rule");
        assert!(broadcast < tproxy, "broadcast bypass must precede TPROXY");
    }

    #[test]
    fn config_redaction_covers_every_generated_credential_family() {
        let yaml = r#"
authentication:
  - SECRET_LOCAL_AUTH
secret: SECRET_CONTROLLER
proxies:
  - name: VLESS diagnostic
    type: vless
    server: vless.example
    port: 443
    uuid: SECRET_VLESS_UUID
    certificate: SECRET_VLESS_CERT
    private-key: SECRET_VLESS_KEY
    reality-opts:
      public-key: SAFE_REALITY_PUBLIC_KEY
      short-id: SECRET_REALITY_SHORT_ID
    xhttp-opts:
      path: /diagnostic
      x-padding-key: SECRET_X_PADDING_KEY
      session-key: SECRET_SESSION_KEY
      seq-key: SECRET_SEQ_KEY
      uplink-data-key: SECRET_UPLINK_DATA_KEY
  - name: VMess diagnostic
    type: vmess
    server: vmess.example
    port: 443
    uuid: SECRET_VMESS_UUID
    certificate: SECRET_VMESS_CERT
    private-key: SECRET_VMESS_KEY
  - name: Trojan diagnostic
    type: trojan
    server: trojan.example
    port: 443
    password: SECRET_TROJAN_PASSWORD
  - name: Shadowsocks diagnostic
    type: ss
    server: ss.example
    port: 8388
    cipher: aes-256-gcm
    password: SECRET_SS_PASSWORD
  - name: SSR diagnostic
    type: ssr
    server: ssr.example
    port: 443
    cipher: aes-256-cfb
    password: SECRET_SSR_PASSWORD
    obfs-param: SECRET_SSR_OBFS_PARAM
    protocol-param: SECRET_SSR_PROTOCOL_PARAM
  - name: Snell diagnostic
    type: snell
    server: snell.example
    port: 44046
    psk: SECRET_SNELL_PSK
  - name: HTTP diagnostic
    type: http
    server: http.example
    port: 8080
    username: SECRET_HTTP_USERNAME
    password: SECRET_HTTP_PASSWORD
  - name: SOCKS diagnostic
    type: socks5
    server: socks.example
    port: 1080
    username: SECRET_SOCKS_USERNAME
    password: SECRET_SOCKS_PASSWORD
  - name: AnyTLS diagnostic
    type: anytls
    server: anytls.example
    port: 443
    password: SECRET_ANYTLS_PASSWORD
  - name: Hysteria diagnostic
    type: hysteria
    server: hysteria.example
    port: 443
    auth-str: SECRET_HYSTERIA_AUTH
    obfs: SECRET_HYSTERIA_OBFS
  - name: Hysteria2 diagnostic
    type: hysteria2
    server: hysteria2.example
    port: 443
    password: SECRET_HYSTERIA2_PASSWORD
    obfs: salamander
    obfs-password: SECRET_HYSTERIA2_OBFS_PASSWORD
  - name: WireGuard diagnostic
    type: wireguard
    server: wireguard.example
    port: 51820
    private-key: SECRET_WIREGUARD_PRIVATE_KEY
    public-key: SAFE_WIREGUARD_PUBLIC_KEY
    pre-shared-key: SECRET_WIREGUARD_PSK
    allowed-ips: [0.0.0.0/0]
  - name: TUIC diagnostic
    type: tuic
    server: tuic.example
    port: 443
    uuid: SECRET_TUIC_UUID
    password: SECRET_TUIC_PASSWORD
  - name: SSH diagnostic
    type: ssh
    server: ssh.example
    port: 22
    username: SECRET_SSH_USERNAME
    password: SECRET_SSH_PASSWORD
    private-key: SECRET_SSH_PRIVATE_KEY
    private-key-passphrase: SECRET_SSH_PASSPHRASE
  - name: MASQUE diagnostic
    type: masque
    server: masque.example
    port: 443
    private-key: SECRET_MASQUE_PRIVATE_KEY
    public-key: SAFE_MASQUE_PUBLIC_KEY
  - name: OpenVPN diagnostic
    type: openvpn
    server: openvpn.example
    port: 1194
    ca: SAFE_OPENVPN_CA
    cert: SECRET_OPENVPN_CLIENT_CERT
    key: SECRET_OPENVPN_KEY
    tls-crypt: SECRET_OPENVPN_TLS_CRYPT
    username: SECRET_OPENVPN_USERNAME
    password: SECRET_OPENVPN_PASSWORD
  - name: Tailscale diagnostic
    type: tailscale
    hostname: tailscale-diagnostic
    auth-key: SECRET_TAILSCALE_AUTH_KEY
rules:
  - MATCH,proxy
"#;
        let redacted = redact_config_yaml(yaml).expect("redact");
        for secret in yaml
            .split(|ch: char| ch.is_whitespace() || matches!(ch, ':' | '[' | ']' | ','))
            .filter(|value| value.starts_with("SECRET_"))
        {
            assert!(!redacted.contains(secret), "leaked {secret}: {redacted}");
        }
        for diagnostic in [
            "VLESS diagnostic",
            "vless.example",
            "SAFE_REALITY_PUBLIC_KEY",
            "aes-256-gcm",
            "salamander",
            "SAFE_WIREGUARD_PUBLIC_KEY",
            "0.0.0.0/0",
            "SAFE_MASQUE_PUBLIC_KEY",
            "SAFE_OPENVPN_CA",
            "tailscale-diagnostic",
            "MATCH,proxy",
        ] {
            assert!(
                redacted.contains(diagnostic),
                "missing diagnostic {diagnostic}: {redacted}"
            );
        }
        assert!(redacted.matches("<redacted>").count() >= 35);
    }

    #[test]
    fn config_redaction_collapses_provider_credentials_and_arbitrary_payloads() {
        let yaml = r#"
proxy-providers:
  subscription-diagnostic:
    type: inline
    interval: 3600
    proxy: proxy
    url: https://provider.example/sub/SECRET_PROVIDER_URL
    age-secret-key: SECRET_AGE_KEY
    header:
      X-Arbitrary-Credential: [SECRET_PROXY_HEADER]
      Harmless-Looking-Name: [SECRET_PROXY_HEADER_UNKNOWN]
    payload:
      - "type: vless, uuid: SECRET_INLINE_PROXY"
    future-provider-credential:
      nested: SECRET_FUTURE_PROVIDER_FIELD
rule-providers:
  rules-diagnostic:
    type: inline
    behavior: domain
    format: yaml
    interval: 7200
    header:
      Authorization: [SECRET_RULE_HEADER]
    payload:
      - DOMAIN,SECRET_INLINE_RULE,DIRECT
    future-inline-data: SECRET_FUTURE_RULE_FIELD
"#;
        let redacted = redact_config_yaml(yaml).expect("redact");
        for secret in yaml
            .split(|ch: char| ch.is_whitespace() || matches!(ch, ':' | '[' | ']' | ',' | '/'))
            .filter(|value| value.starts_with("SECRET_"))
        {
            assert!(!redacted.contains(secret), "leaked {secret}: {redacted}");
        }
        for diagnostic in [
            "subscription-diagnostic",
            "rules-diagnostic",
            "type: inline",
            "interval: 3600",
            "behavior: domain",
            "format: yaml",
        ] {
            assert!(
                redacted.contains(diagnostic),
                "missing {diagnostic}: {redacted}"
            );
        }
    }

    #[test]
    fn config_redaction_fails_closed_for_unknown_schema_and_dns_credentials() {
        let yaml = r#"
mode: rule
future-root-credential: SECRET_FUTURE_ROOT
dns:
  enable: true
  listen: 0.0.0.0:1053
  nameserver:
    - https://SECRET_DNS_USER:SECRET_DNS_PASSWORD@dns.example/dns-query
  nameserver-policy:
    "+.example.com":
      - tls://SECRET_POLICY_TOKEN@dns.example
proxies:
  - name: Future protocol diagnostic
    type: future-protocol
    server: future.example
    port: 443
    harmless-looking-new-field: SECRET_FUTURE_PROXY_FIELD
proxy-groups:
  - name: proxy
    type: fallback
    proxies: [Future protocol diagnostic, DIRECT]
    url: https://www.gstatic.com/generate_204
    future-group-secret: SECRET_FUTURE_GROUP
"#;
        let redacted = redact_config_yaml(yaml).expect("redact");
        for secret in yaml
            .split(|ch: char| ch.is_whitespace() || matches!(ch, ':' | '[' | ']' | ',' | '/' | '@'))
            .filter(|value| value.starts_with("SECRET_"))
        {
            assert!(!redacted.contains(secret), "leaked {secret}: {redacted}");
        }
        for diagnostic in [
            "mode: rule",
            "listen: 0.0.0.0:1053",
            "+.example.com",
            "Future protocol diagnostic",
            "future.example",
            "type: fallback",
        ] {
            assert!(
                redacted.contains(diagnostic),
                "missing {diagnostic}: {redacted}"
            );
        }
        assert!(!redacted.contains("https://www.gstatic.com/generate_204"));
    }

    #[test]
    fn config_redaction_hides_opaque_diagnostic_urls_and_targets() {
        let yaml = r#"
proxies:
  - name: opaque paths
    type: vless
    server: proxy.example
    port: 443
    xhttp-opts:
      path: /SECRET_XHTTP_PATH
    ws-opts:
      path: /SECRET_WS_PATH
proxy-groups:
  - name: proxy
    type: fallback
    proxies: [opaque paths, DIRECT]
    url: https://health.example/SECRET_GROUP_URL
proxy-providers:
  remote:
    type: http
    health-check:
      enable: true
      url: https://health.example/SECRET_PROVIDER_HEALTH
tunnels:
  - network: [tcp]
    address: 127.0.0.1:9000
    target: SECRET_TUNNEL_TARGET
ntp:
  enable: true
  server: SECRET_NTP_SERVER
  port: 123
"#;
        let redacted = redact_config_yaml(yaml).expect("redact");
        for secret in [
            "SECRET_XHTTP_PATH",
            "SECRET_WS_PATH",
            "SECRET_GROUP_URL",
            "SECRET_PROVIDER_HEALTH",
            "SECRET_TUNNEL_TARGET",
            "SECRET_NTP_SERVER",
        ] {
            assert!(!redacted.contains(secret), "leaked {secret}: {redacted}");
        }
        for diagnostic in [
            "opaque paths",
            "proxy.example",
            "type: fallback",
            "address: 127.0.0.1:9000",
            "port: 123",
        ] {
            assert!(
                redacted.contains(diagnostic),
                "missing {diagnostic}: {redacted}"
            );
        }
    }

    #[test]
    fn safe_mode_projection_suppresses_heavy_features_without_mutating_state() {
        let mut state = HincyrayState {
            safe_mode_enabled: true,
            ..HincyrayState::default()
        };
        state.mihomo_features.raw_rules = vec!["DOMAIN,example.com,DIRECT".to_owned()];
        state.mihomo_features.typed_rules = vec![crate::mihomo_config::MihomoRuleConfig {
            rule_type: "DOMAIN".to_owned(),
            value: "example.net".to_owned(),
            target: "DIRECT".to_owned(),
            options: Vec::new(),
        }];
        state
            .mihomo_features
            .tunnels
            .push(crate::mihomo_config::TunnelConfig {
                network: vec!["tcp".to_owned()],
                address: "127.0.0.1:1".to_owned(),
                target: "example.com:443".to_owned(),
                proxy: None,
            });
        let effective = effective_mihomo_features(&state);
        assert!(effective.raw_rules.is_empty());
        assert!(effective.typed_rules.is_empty());
        assert!(effective.tunnels.is_empty());
        assert_eq!(state.mihomo_features.raw_rules.len(), 1);
        assert_eq!(state.mihomo_features.typed_rules.len(), 1);
        assert_eq!(state.mihomo_features.tunnels.len(), 1);
    }

    #[test]
    fn safe_mode_rollback_preserves_unrelated_concurrent_state() {
        let (_dir, daemon) = test_daemon();
        let undo_id = {
            let mut inner = lock(&daemon.inner);
            push_undo_snapshot(&mut inner.state, "Safe mode enabled");
            inner.state.safe_mode_enabled = true;
            inner.state.auto_select = true;
            persist_state(&daemon.state_path, &inner.state).expect("persist concurrent state");
            inner
                .state
                .undo_stack
                .last()
                .expect("safe mode undo")
                .id
                .clone()
        };

        assert_eq!(
            restore_safe_mode_after_failed_activation(&daemon, true, false, Some(&undo_id),),
            "restored"
        );
        let inner = lock(&daemon.inner);
        assert!(!inner.state.safe_mode_enabled);
        assert!(inner.state.auto_select);
        assert!(
            !inner
                .state
                .undo_stack
                .iter()
                .any(|entry| entry.id == undo_id)
        );
        let persisted = load_state(&daemon.state_path);
        assert!(!persisted.safe_mode_enabled);
        assert!(persisted.auto_select);
    }

    #[test]
    #[cfg(unix)]
    fn safe_mode_handler_failure_does_not_erase_concurrent_state_update() {
        let dir = TempDir::new().expect("temp dir");
        let marker = dir.path().join("validation-started");
        let script = dir.path().join("fake-mihomo.sh");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\nif [ \"$1\" = \"-t\" ]; then touch '{}'; sleep 1; exit 1; fi\nexit 1\n",
                marker.display()
            ),
        )
        .expect("fake mihomo");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod");
        let mut state = geobase_config_state();
        state.split_routing.enabled = false;
        state.mihomo_path = script.to_string_lossy().into_owned();
        let daemon = Daemon::new(
            state,
            dir.path().join("state.json"),
            dir.path().join("mihomo-config.yaml"),
        );
        let worker_daemon = daemon.clone();
        let worker = thread::spawn(move || {
            handle_safe_mode_set(r#"{"enabled":true,"apply":true}"#, &worker_daemon)
        });
        for _ in 0..100 {
            if marker.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(marker.exists(), "validation did not start");
        {
            let mut inner = lock(&daemon.inner);
            inner.state.auto_select = true;
        }

        let (status, _, body) = worker.join().expect("safe mode worker");
        assert_eq!(status, 500, "{body}");
        let inner = lock(&daemon.inner);
        assert!(!inner.state.safe_mode_enabled);
        assert!(inner.state.auto_select);
        drop(inner);
        let persisted = load_state(&daemon.state_path);
        assert!(!persisted.safe_mode_enabled);
        assert!(persisted.auto_select);
    }

    #[test]
    fn connection_search_contract_covers_canonical_metadata_and_chain() {
        let connection = json!({
            "metadata": {
                "host": "chatgpt.com",
                "destinationIP": "203.0.113.5",
                "sourceIP": "192.168.2.35",
                "destinationCountry": "RU"
            },
            "chains": ["proxy-active", "proxy"],
            "rule": "DomainSuffix",
            "rulePayload": "chatgpt.com"
        });
        let text = connection_search_text(&connection);
        for expected in [
            "chatgpt.com",
            "203.0.113.5",
            "192.168.2.35",
            "ru",
            "proxy-active",
            "domainsuffix",
        ] {
            assert!(text.contains(expected), "missing {expected}: {text}");
        }
        let terms = ["ru", "chatgpt.com"];
        assert!(terms.iter().all(|term| text.contains(term)));
    }

    #[test]
    fn device_traffic_projection_aggregates_only_requested_sources() {
        let connections = vec![
            json!({"metadata":{"sourceIP":"192.168.2.2"},"upload":10,"download":20}),
            json!({"metadata":{"sourceIP":"192.168.2.2"},"upload":5,"download":7}),
            json!({"metadata":{"sourceIP":"192.168.2.3"},"upload":100,"download":200}),
        ];
        let source_ips = HashSet::from(["192.168.2.2".to_owned()]);
        let projected = aggregate_device_traffic(&connections, &source_ips);
        assert_eq!(projected.len(), 1);
        assert_eq!(projected["192.168.2.2"].upload, 15);
        assert_eq!(projected["192.168.2.2"].download, 27);
        assert_eq!(projected["192.168.2.2"].connections, 2);
    }

    #[test]
    fn typed_contract_and_routing_summary_endpoints_are_bounded() {
        let (_dir, daemon) = test_daemon();
        let (status, _, contracts) = handle_api_contracts();
        assert_eq!(status, 200);
        assert!(contracts.contains("/api/routing/summary"));
        let (status, _, summary) = handle_routing_summary(&daemon);
        assert_eq!(status, 200);
        let value: Value = serde_json::from_str(&summary).expect("summary");
        assert_eq!(value["user_rule_count"], 0);
        assert!(value.get("catalog").is_none());
        assert!(value.get("servers").is_none());
    }

    fn sample_profile(id: usize, name: &str, address: &str) -> Profile {
        Profile {
            id,
            name: name.to_owned(),
            protocol: crate::profiles::Protocol::Vless,
            address: address.to_owned(),
            port: Some(443),
            raw: format!("vless://11111111-1111-1111-1111-111111111111@{address}:443#{name}"),
            selected: true,
            block_quic: false,
            group: Some("sub".to_owned()),
        }
    }

    #[test]
    fn routing_trace_matches_device_route_before_general_rules() {
        let mut state = HincyrayState::default();
        state.device_routes.push(DeviceRoute {
            enabled: true,
            name: "TV".to_owned(),
            ip: "192.168.2.10".to_owned(),
            mac: None,
            target: "reject".to_owned(),
        });
        state.routing_rules.push(RoutingRule {
            enabled: true,
            name: "All domains direct".to_owned(),
            domains: vec!["example.com".to_owned()],
            target: "direct".to_owned(),
            ..Default::default()
        });
        let trace = trace_routing_decision(
            &state,
            &TraceRequest {
                host: "www.example.com".to_owned(),
                ip: "93.184.216.34".to_owned(),
                source_ip: "192.168.2.10".to_owned(),
                port: Some(443),
                network: "tcp".to_owned(),
            },
        );
        assert_eq!(trace["source"], json!("device_route"));
        assert_eq!(trace["target"], json!("reject"));
    }

    #[test]
    fn routing_trace_marks_geosite_as_runtime_candidate() {
        let mut state = HincyrayState::default();
        state.routing_rules.push(RoutingRule {
            enabled: true,
            name: "RU direct".to_owned(),
            domains: vec!["geosite:ru".to_owned()],
            target: "direct".to_owned(),
            ..Default::default()
        });
        let trace = trace_routing_decision(
            &state,
            &TraceRequest {
                host: "ya.ru".to_owned(),
                ip: String::new(),
                source_ip: String::new(),
                port: Some(443),
                network: "tcp".to_owned(),
            },
        );
        assert_eq!(trace["decision"], json!("requires_mihomo_geo_eval"));
        assert_eq!(trace["candidates"].as_array().expect("candidates").len(), 1);
    }

    #[test]
    fn routing_chain_check_reports_split_routing_disabled_as_bad() {
        let (_dir, daemon) = test_daemon();
        let (status, _, body) = dispatch("GET", "/api/routing/chain-check", "", &daemon);
        assert_eq!(status, 200);
        let response: Value = serde_json::from_str(&body).expect("json");
        let split = response["overall"]
            .as_array()
            .expect("overall")
            .iter()
            .find(|node| node["id"] == json!("split"))
            .expect("split node");
        assert_eq!(split["status"], json!("bad"));
        assert!(
            split["detail"]
                .as_str()
                .expect("detail")
                .contains("напрямую")
        );
    }

    #[test]
    fn routing_chain_check_accepts_device_source_ip() {
        let (_dir, daemon) = test_daemon();
        {
            let mut inner = lock(&daemon.inner);
            inner.state.split_routing.enabled = true;
            inner.state.split_routing.vpn_subnet = "192.168.2.0/24".to_owned();
            inner.state.device_routes.push(DeviceRoute {
                enabled: true,
                name: "Pixel".to_owned(),
                ip: "192.168.2.35".to_owned(),
                mac: None,
                target: "direct".to_owned(),
            });
        }
        let (status, _, body) = dispatch(
            "POST",
            "/api/routing/chain-check",
            r#"{"source_ip":"192.168.2.35"}"#,
            &daemon,
        );
        assert_eq!(status, 200);
        let response: Value = serde_json::from_str(&body).expect("json");
        assert_eq!(response["source_ip"], json!("192.168.2.35"));
        let override_node = response["device"]
            .as_array()
            .expect("device")
            .iter()
            .find(|node| node["id"] == json!("override"))
            .expect("override node");
        assert_eq!(override_node["status"], json!("bad"));
        assert!(
            override_node["detail"]
                .as_str()
                .expect("detail")
                .contains("имеет приоритет над всеми общими правилами")
        );
    }

    #[test]
    fn routing_chain_check_geo_rules_are_info_not_warn() {
        let (_dir, daemon) = test_daemon();
        {
            let mut inner = lock(&daemon.inner);
            inner.state.split_routing.enabled = true;
            inner.state.split_routing.vpn_subnet = "192.168.2.0/24".to_owned();
            inner.state.routing_rules.push(RoutingRule {
                enabled: true,
                name: "CN direct".to_owned(),
                target: "direct".to_owned(),
                domains: vec!["geoip:CN".to_owned()],
                ..Default::default()
            });
        }
        let (status, _, body) = dispatch(
            "POST",
            "/api/routing/chain-check",
            r#"{"source_ip":"192.168.2.99"}"#,
            &daemon,
        );
        assert_eq!(status, 200);
        let response: Value = serde_json::from_str(&body).expect("json");

        // The "rules" node must be "info" (informational), not "warn".
        let rules_node = response["device"]
            .as_array()
            .expect("device")
            .iter()
            .find(|node| node["id"] == json!("rules"))
            .expect("rules node");
        assert_eq!(
            rules_node["status"],
            json!("info"),
            "geo-asset rules should be 'info', not 'warn'"
        );

        // The summary must count info nodes separately.
        let summary = &response["summary"];
        assert!(
            summary["info"].as_u64().unwrap_or(0) > 0,
            "info count must be > 0"
        );

        // info must not inflate the warn count: compare with a daemon that
        // has no geo-asset rules — the warn count should be identical.
        let (_dir2, daemon2) = test_daemon();
        {
            let mut inner = lock(&daemon2.inner);
            inner.state.split_routing.enabled = true;
            inner.state.split_routing.vpn_subnet = "192.168.2.0/24".to_owned();
            // No routing rules → no geo assets → rules node will be "ok".
        }
        let (_, _, body2) = dispatch(
            "POST",
            "/api/routing/chain-check",
            r#"{"source_ip":"192.168.2.99"}"#,
            &daemon2,
        );
        let response2: Value = serde_json::from_str(&body2).expect("json");
        let warn_with_info = summary["warn"].as_u64().unwrap_or(0);
        let warn_without_info = response2["summary"]["warn"].as_u64().unwrap_or(0);
        assert_eq!(
            warn_with_info, warn_without_info,
            "info nodes must not inflate warn count"
        );
    }

    #[test]
    fn substore_lite_filters_renames_deduplicates_and_sorts() {
        let mut state = HincyrayState {
            profiles: vec![
                sample_profile(0, "HK 01", "hk.example"),
                sample_profile(1, "US 01", "us.example"),
                sample_profile(2, "HK 01 dup", "hk.example"),
            ],
            sub_store_lite: SubStoreLiteSettings {
                include_filter: "hk".to_owned(),
                rename_rules: vec![SubStoreRenameRule {
                    from: "HK".to_owned(),
                    to: "Hong Kong".to_owned(),
                }],
                deduplicate: true,
                sort_by: "name".to_owned(),
                ..Default::default()
            },
            ..Default::default()
        };
        let report = apply_substore_lite(&mut state);
        assert_eq!(state.profiles.len(), 1);
        assert_eq!(state.profiles[0].name, "Hong Kong 01");
        assert_eq!(report["filtered"], json!(1));
        assert_eq!(report["deduplicated"], json!(1));
    }

    #[test]
    fn maintenance_due_respects_window_and_interval() {
        let settings = MaintenanceSettings {
            enabled: true,
            hour_utc: 1,
            minute_utc: 0,
            interval_days: 1,
            last_run_unix: 0,
            ..Default::default()
        };
        assert!(maintenance_due(&settings, 3600));
        assert!(!maintenance_due(&settings, 7200));
        let recently_run = MaintenanceSettings {
            last_run_unix: 3500,
            ..settings
        };
        assert!(!maintenance_due(&recently_run, 3600));
    }

    #[test]
    fn backup_path_rejects_traversal() {
        let dir = TempDir::new().expect("temp dir");
        let state_path = dir.path().join("state.json");
        assert!(backup_path_by_name(&state_path, "../state.json").is_err());
        assert!(backup_path_by_name(&state_path, "state-1-manual.json").is_ok());
    }

    #[test]
    fn filter_connection_ids_matches_host_and_source() {
        let conns = json!({
            "connections": [
                {"id":"a", "metadata":{"host":"api.example.com", "sourceIP":"192.168.2.2"}},
                {"id":"b", "metadata":{"host":"other.test", "sourceIP":"192.168.2.3"}}
            ]
        });
        assert_eq!(
            filter_connection_ids(&conns, Some("example.com"), None, None),
            vec!["a"]
        );
        assert_eq!(
            filter_connection_ids(&conns, None, None, Some("192.168.2.3")),
            vec!["b"]
        );
    }

    #[test]
    fn filter_connection_ids_matches_remote_destination_ip_and_source() {
        let conns = json!({
            "connections": [
                {"id":"a", "metadata":{"host":"", "remoteDestination":"1.2.3.4", "sourceIP":"192.168.2.2"}},
                {"id":"b", "metadata":{"host":"", "destinationIP":"1.2.3.4", "sourceIP":"192.168.2.3"}},
                {"id":"c", "metadata":{"host":"", "remoteDestination":"5.6.7.8", "sourceIP":"192.168.2.2"}}
            ]
        });
        assert_eq!(
            filter_connection_ids(&conns, None, Some("1.2.3.4"), Some("192.168.2.2")),
            vec!["a"]
        );
        assert_eq!(
            filter_connection_ids(&conns, None, Some("1.2.3.4"), None),
            vec!["a", "b"]
        );
    }

    #[test]
    fn normalize_routing_resource_classifies_urls_hosts_and_ips() {
        let url = normalize_routing_resource("https://Api.Example.COM:443/path").expect("url");
        assert_eq!(url.kind, RoutingResourceKind::Domain);
        assert_eq!(url.value, "api.example.com");

        let ip = normalize_routing_resource("212.193.155.88:443").expect("ip");
        assert_eq!(ip.kind, RoutingResourceKind::Ip);
        assert_eq!(ip.value, "212.193.155.88");

        let ipv6 = normalize_routing_resource("[2001:db8::1]:443").expect("ipv6");
        assert_eq!(ipv6.kind, RoutingResourceKind::Ip);
        assert_eq!(ipv6.value, "2001:db8::1");
    }

    #[test]
    fn close_connections_rejects_invalid_json_before_external_controller_lookup() {
        let (_dir, daemon) = test_daemon();
        let (status, _, body) = handle_mihomo_api_connections_close("{", &daemon);
        assert_eq!(status, 400);
        assert!(body.contains("invalid JSON body"), "body: {body}");
    }

    #[test]
    fn controller_dial_address_maps_wildcard_bind_to_loopback() {
        assert_eq!(controller_dial_address("0.0.0.0:9090"), "127.0.0.1:9090");
        assert_eq!(controller_dial_address("[::]:9090"), "127.0.0.1:9090");
        assert_eq!(controller_dial_address(":9090"), "127.0.0.1:9090");
        assert_eq!(controller_dial_address("127.0.0.1:9090"), "127.0.0.1:9090");
    }

    #[test]
    fn match_target_proxy_generates_match_proxy() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443#Active",
            &daemon,
        );
        {
            let mut inner = lock(&daemon.inner);
            inner.state.active_profile_id = Some(0);
            inner.state.split_routing.enabled = true;
            inner.state.split_routing.match_target = "proxy".to_owned();
            inner.state.routing_rules.push(RoutingRule {
                enabled: true,
                name: "YT".to_owned(),
                target: "active".to_owned(),
                domains: vec!["geosite:youtube".to_owned()],
                ..Default::default()
            });
        }
        let (status, _, body) = handle_get_mihomo_config(&daemon);
        assert_eq!(status, 200);
        let config: Value = serde_yaml::from_str(&body).expect("parse config");
        let rules = config["rules"].as_array().expect("rules");
        let last = rules.last().and_then(Value::as_str).expect("last rule");
        assert_eq!(last, "MATCH,proxy");
    }

    #[test]
    fn match_target_direct_generates_match_direct() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443#Active",
            &daemon,
        );
        {
            let mut inner = lock(&daemon.inner);
            inner.state.active_profile_id = Some(0);
            inner.state.split_routing.enabled = true;
            inner.state.split_routing.match_target = "direct".to_owned();
            inner.state.routing_rules.push(RoutingRule {
                enabled: true,
                name: "YT".to_owned(),
                target: "active".to_owned(),
                domains: vec!["geosite:youtube".to_owned()],
                ..Default::default()
            });
        }
        let (status, _, body) = handle_get_mihomo_config(&daemon);
        assert_eq!(status, 200);
        let config: Value = serde_yaml::from_str(&body).expect("parse config");
        let rules = config["rules"].as_array().expect("rules");
        let last = rules.last().and_then(Value::as_str).expect("last rule");
        assert_eq!(last, "MATCH,DIRECT");
    }

    #[test]
    fn match_target_direct_rejected_when_no_rules() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443#Active",
            &daemon,
        );
        {
            let mut inner = lock(&daemon.inner);
            inner.state.active_profile_id = Some(0);
            inner.state.split_routing.enabled = true;
        }
        let (status, _, _body) = handle_routing_settings(r#"{"match_target":"direct"}"#, &daemon);
        assert_eq!(status, 400);
    }

    #[test]
    fn preset_apply_with_target_override() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443#Active",
            &daemon,
        );
        {
            let mut inner = lock(&daemon.inner);
            inner.state.active_profile_id = Some(0);
            inner.state.split_routing.enabled = true;
        }
        let (status, _, body) =
            handle_routing_preset_apply(r#"{"preset":"ru-ip-direct","target":"active"}"#, &daemon);
        assert_eq!(status, 200);
        let result: Value = serde_json::from_str(&body).expect("parse json");
        assert_eq!(result["target_override"], json!("active"));

        let inner = lock(&daemon.inner);
        let ru_rule = inner
            .state
            .routing_rules
            .iter()
            .find(|r| r.name == "RU IPs direct")
            .expect("ru-ip-direct rule");
        assert_eq!(ru_rule.target, "active");
    }

    #[test]
    fn geo_providers_list_returns_providers() {
        let (status, _, body) = handle_geo_providers();
        assert_eq!(status, 200);
        let result: Value = serde_json::from_str(&body).expect("parse json");
        let providers = result["providers"].as_array().expect("providers");
        assert!(!providers.is_empty());
        assert!(
            providers
                .iter()
                .any(|p| { p.get("id").and_then(Value::as_str) == Some("metacubex-lite") })
        );
    }

    #[test]
    fn conflict_detection_allowlist() {
        let (_dir, daemon) = test_daemon();
        {
            let mut inner = lock(&daemon.inner);
            inner.state.split_routing.port_mode = PortMode::AllowList;
            inner.state.split_routing.proxy_ports = vec!["80".to_owned(), "443".to_owned()];
            inner.state.routing_rules.push(RoutingRule {
                enabled: true,
                name: "SSH".to_owned(),
                target: "active".to_owned(),
                ports: vec!["22".to_owned()],
                ..Default::default()
            });
        }
        let (status, _, body) = handle_routing_get(&daemon);
        assert_eq!(status, 200);
        let result: Value = serde_json::from_str(&body).expect("parse json");
        let conflicts = result["conflicts"].as_array().expect("conflicts");
        assert_eq!(conflicts.len(), 1);
        let msg = conflicts[0].as_str().expect("conflict msg");
        assert!(msg.contains("22"));
        assert!(msg.contains("SSH"));
    }

    #[test]
    fn conflict_detection_no_conflicts_when_all_mode() {
        let (_dir, daemon) = test_daemon();
        {
            let mut inner = lock(&daemon.inner);
            inner.state.split_routing.port_mode = PortMode::All;
            inner.state.routing_rules.push(RoutingRule {
                enabled: true,
                name: "SSH".to_owned(),
                target: "active".to_owned(),
                ports: vec!["22".to_owned()],
                ..Default::default()
            });
        }
        let (status, _, body) = handle_routing_get(&daemon);
        assert_eq!(status, 200);
        let result: Value = serde_json::from_str(&body).expect("parse json");
        let conflicts = result["conflicts"].as_array().expect("conflicts");
        assert!(conflicts.is_empty());
    }

    #[test]
    fn routing_get_omits_redundant_active_domains_but_keeps_static_active() {
        let (_dir, daemon) = test_daemon();
        create_geobase_config_generation(&daemon, "regional", true);
        let store = geobase_store(&daemon);
        let desired = store.load_manifest().expect("desired manifest");
        store
            .mark_applied(desired.generation)
            .expect("apply GeoBase snapshot");

        let (status, _, body) = handle_routing_get(&daemon);
        assert_eq!(status, 200);
        let response: Value = serde_json::from_str(&body).expect("routing response");
        let rows = response["managed_rules"].as_array().expect("managed rules");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["source"], "geobase");
        assert_eq!(rows[0]["geobase_id"], "regional");
        assert_eq!(rows[0]["name"], "regional — серый список");
        assert_eq!(rows[0]["target"], "active");
        assert_eq!(rows[0]["outbound"], "proxy-active");
        assert_eq!(rows[0]["domain_count"], 0);
        assert_eq!(rows[0]["network_count"], 1);
        assert_eq!(rows[0]["total_count"], 1);
        assert_eq!(rows[1]["name"], "regional — белый список");
        assert_eq!(rows[1]["target"], "direct");
        assert_eq!(rows[1]["outbound"], "DIRECT");
        assert_eq!(rows[1]["domain_count"], 1);
        assert_eq!(rows[1]["network_count"], 1);
        assert_eq!(rows[1]["total_count"], 2);
        assert!(rows.iter().all(|row| row["enabled"] == true));
        assert!(rows.iter().all(|row| row["applied"] == true));
        assert_eq!(response["geobase_requires_apply"], false);

        store.delete("regional").expect("pending desired delete");
        let (status, _, pending_body) = handle_routing_get(&daemon);
        assert_eq!(status, 200);
        let pending: Value = serde_json::from_str(&pending_body).expect("pending response");
        assert_eq!(pending["managed_rules"], response["managed_rules"]);
        assert_eq!(pending["geobase_requires_apply"], true);
    }

    #[test]
    fn routing_settings_accepts_auto_vpn_exceptions() {
        let (_dir, daemon) = test_daemon();
        let (status, _, _body) = handle_routing_settings(
            r#"{"auto_vpn_learning_enabled":false,"auto_vpn_exceptions":["HTTPS://Blocked.Example/path","192.168.1.1","*.ok.example."]}"#,
            &daemon,
        );
        assert_eq!(status, 200);
        let inner = lock(&daemon.inner);
        assert!(!inner.state.split_routing.auto_vpn_learning_enabled);
        assert_eq!(
            inner.state.split_routing.auto_vpn_exceptions,
            vec!["blocked.example".to_owned(), "ok.example".to_owned()]
        );
    }

    #[test]
    fn auto_vpn_candidate_domains_use_direct_connections_only() {
        let mut state = HincyrayState::default();
        state.connection_log.push(ConnectionLogEntry {
            timestamp: 1,
            host: "proxied.example".to_owned(),
            chains: vec![PROXY_NAME.to_owned()],
            ..Default::default()
        });
        state.connection_log.push(ConnectionLogEntry {
            timestamp: 2,
            host: "Direct.Example:443".to_owned(),
            destination_port: 443,
            chains: vec![DIRECT_NAME.to_owned()],
            ..Default::default()
        });
        assert_eq!(
            auto_vpn_candidate_domains(&state, AUTO_VPN_RECHECK_INTERVAL_SECS + 1, &[]),
            vec![auto_candidate("direct.example", Some(443))]
        );
    }

    #[test]
    fn auto_vpn_log_payload_extracts_direct_failure_endpoint_only() {
        assert_eq!(
            auto_vpn_candidate_from_mihomo_log_payload(
                "[TCP] dial DIRECT (match GeoSite/category-ru) 192.168.2.100:45542 --> Rutube.Ru:8443 error: connect failed"
            ),
            Some(auto_candidate("rutube.ru", Some(8443)))
        );
        assert_eq!(
            auto_vpn_candidate_from_mihomo_log_payload(
                "[TCP] dial proxy-active 192.168.2.100:1 --> blocked.example:443 error: upstream failed"
            ),
            None
        );
        assert_eq!(
            auto_vpn_candidate_from_mihomo_log_payload(
                "[TCP] dial DIRECT 192.168.2.100:1 --> 192.0.2.1:443 error: failed"
            ),
            None
        );
    }

    #[test]
    fn auto_vpn_log_text_extracts_unique_direct_failure_domains() {
        let body = r#"time="2026-07-10T13:39:02Z" level=warning msg="[TCP] dial DIRECT (match GeoSite/category-ru) 192.168.2.100:45542 --> rutube.ru:8443 error: connect failed"
time="2026-07-10T13:39:03Z" level=warning msg="[TCP] dial DIRECT 192.168.2.100:45543 --> Rutube.Ru:443 error: connect failed"
time="2026-07-10T13:39:04Z" level=warning msg="[TCP] dial DIRECT 192.168.2.100:45544 --> seller.ozon.ru:443 error: connect failed"
time="2026-07-10T13:39:05Z" level=warning msg="[TCP] dial proxy-active 192.168.2.100:45545 --> ignored.example:443 error: upstream failed""#;
        assert_eq!(
            auto_vpn_log_candidate_domains_from_text(body),
            vec![
                auto_candidate("rutube.ru", Some(8443)),
                auto_candidate("rutube.ru", Some(443)),
                auto_candidate("seller.ozon.ru", Some(443))
            ]
        );
    }

    #[test]
    fn parovozik_log_parser_accepts_unmatched_direct_dial_failures() {
        assert_eq!(
            parovozik_candidate_from_mihomo_log_payload(
                "[TCP] dial tcp (match Match/) 192.168.2.100:45542 --> New.Example:443 error: i/o timeout"
            ),
            Some(auto_candidate("new.example", Some(443)))
        );
        assert_eq!(
            parovozik_candidate_from_mihomo_log_payload(
                "[TCP] dial proxy-active 192.168.2.100:1 --> ignored.example:443 error: failed"
            ),
            None
        );
    }

    #[test]
    fn auto_vpn_probe_urls_preserve_observed_port() {
        assert_eq!(
            auto_vpn_probe_urls(&auto_candidate("rutube.ru", Some(8443))),
            [
                "https://rutube.ru:8443/".to_owned(),
                "http://rutube.ru:8443/".to_owned()
            ]
        );
    }

    #[test]
    fn parovozik_candidates_exclude_known_domains_and_are_disabled_by_default() {
        let mut state = HincyrayState::default();
        assert!(!state.split_routing.parovozik_enabled);
        state
            .split_routing
            .parovozik_direct_domains
            .push("known.example".to_owned());
        let candidates = parovozik_candidate_domains(
            &state,
            AUTO_VPN_RECHECK_INTERVAL_SECS + 1,
            &[
                auto_candidate("known.example", Some(443)),
                auto_candidate("new.example", Some(443)),
            ],
        );
        assert_eq!(candidates, vec![auto_candidate("new.example", Some(443))]);
    }

    #[test]
    fn parovozik_geobase_match_supports_exact_and_suffix_entries() {
        let bytes = b"exact.example\n+.suffix.example\n";
        assert!(domain_matches_geobase_artifact("exact.example", bytes));
        assert!(domain_matches_geobase_artifact("cdn.suffix.example", bytes));
        assert!(!domain_matches_geobase_artifact("unknown.example", bytes));
    }

    #[test]
    fn parovozik_settings_accept_at_most_five_stable_server_refs() {
        let mut state = HincyrayState::default();
        for index in 0..6 {
            state.profiles.push(sample_profile(
                index,
                &format!("Server {index}"),
                &format!("server-{index}.example"),
            ));
        }
        sync_server_route_registry(&mut state);
        let refs: Vec<String> = state
            .server_route_registry
            .iter()
            .map(|entry| entry.server_ref.clone())
            .collect();
        assert_eq!(
            normalize_parovozik_server_refs(&state, &refs[..5]).expect("five refs"),
            refs[..5]
        );
        assert!(normalize_parovozik_server_refs(&state, &refs).is_err());
    }

    #[test]
    fn mihomo_log_cursor_reads_appends_without_replaying_or_losing_partial_lines() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("mihomo.log");
        fs::write(
            &path,
            "old dial DIRECT --> old.example:443 error: ignored\n",
        )
        .expect("old log");
        let mut cursor = MihomoLogCursor::start_at_end(&path);

        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("append log");
        write!(
            file,
            "new dial DIRECT --> first.example:443 error: failed\npartial dial DIRECT --> second.example:443 error: failed"
        )
        .expect("append records");
        file.flush().expect("flush records");

        assert_eq!(
            cursor.read_new_domains(&path, false).expect("read append"),
            vec![auto_candidate("first.example", Some(443))]
        );
        writeln!(file).expect("complete partial record");
        file.flush().expect("flush completed record");
        assert_eq!(
            cursor
                .read_new_domains(&path, false)
                .expect("read completed line"),
            vec![auto_candidate("second.example", Some(443))]
        );
        assert!(
            cursor
                .read_new_domains(&path, false)
                .expect("read no append")
                .is_empty()
        );
    }

    #[test]
    fn mihomo_log_cursor_reads_new_file_after_rotation() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("mihomo.log");
        fs::write(&path, "old\n").expect("old log");
        let mut cursor = MihomoLogCursor::start_at_end(&path);
        fs::rename(&path, dir.path().join("mihomo.log.1")).expect("rotate");
        fs::write(
            &path,
            "new dial DIRECT --> rotated.example:443 error: failed\n",
        )
        .expect("new log");
        assert_eq!(
            cursor
                .read_new_domains(&path, false)
                .expect("read rotated log"),
            vec![auto_candidate("rotated.example", Some(443))]
        );
    }

    #[test]
    fn mihomo_log_cursor_reads_first_file_created_after_startup() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("mihomo.log");
        let mut cursor = MihomoLogCursor::start_at_end(&path);
        fs::write(
            &path,
            "new dial DIRECT --> created.example:8443 error: failed\n",
        )
        .expect("created log");
        assert_eq!(
            cursor
                .read_new_domains(&path, false)
                .expect("read created log"),
            vec![auto_candidate("created.example", Some(8443))]
        );
    }

    #[test]
    fn auto_vpn_candidate_domains_prioritize_log_failures_and_throttle_all_sources() {
        let mut state = HincyrayState::default();
        state
            .split_routing
            .auto_vpn_last_checked_unix
            .insert("fresh.example".to_owned(), AUTO_VPN_RECHECK_INTERVAL_SECS);
        state.connection_log.push(ConnectionLogEntry {
            timestamp: 1,
            host: "connection.example".to_owned(),
            destination_port: 443,
            chains: vec![DIRECT_NAME.to_owned()],
            ..Default::default()
        });
        let candidates = auto_vpn_candidate_domains(
            &state,
            AUTO_VPN_RECHECK_INTERVAL_SECS + 10,
            &[
                auto_candidate("log.example", Some(8443)),
                auto_candidate("fresh.example", Some(443)),
            ],
        );
        assert_eq!(
            candidates,
            vec![
                auto_candidate("log.example", Some(8443)),
                auto_candidate("connection.example", Some(443))
            ]
        );
    }

    #[test]
    fn routing_reset_restores_factory_defaults() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443#Active",
            &daemon,
        );
        {
            let mut inner = lock(&daemon.inner);
            inner.state.active_profile_id = Some(0);
            inner.state.split_routing.enabled = true;
            inner.state.split_routing.ru_direct_mode = "off".to_owned();
            inner.state.split_routing.match_target = "direct".to_owned();
            inner.state.split_routing.port_mode = PortMode::All;
            inner.state.split_routing.proxy_ports = Vec::new();
            inner.state.split_routing.ru_direct_exceptions = vec!["example.ru".to_owned()];
            inner.state.split_routing.auto_vpn_exceptions = vec!["blocked.example".to_owned()];
            inner
                .state
                .split_routing
                .auto_vpn_last_checked_unix
                .insert("blocked.example".to_owned(), 123);
            inner.state.split_routing.auto_vpn_learning_enabled = false;
            inner.state.routing_rules.push(RoutingRule {
                enabled: true,
                name: "Custom".to_owned(),
                target: "active".to_owned(),
                domains: vec!["custom.com".to_owned()],
                ..Default::default()
            });
            inner.state.mihomo_features.raw_rules = vec!["DOMAIN-SUFFIX,test.com,proxy".to_owned()];
        }
        let (status, _, _body) = handle_routing_reset("{}", &daemon);
        assert_eq!(status, 200);
        {
            let inner = lock(&daemon.inner);
            let s = &inner.state.split_routing;
            assert_eq!(s.ru_direct_mode, "off", "ru_direct_mode should be off");
            assert_eq!(s.match_target, "proxy", "match_target should be proxy");
            assert_eq!(
                s.port_mode,
                PortMode::AllowList,
                "port_mode should preserve the previous reset default"
            );
            assert_eq!(
                s.proxy_ports,
                vec!["80".to_owned(), "443".to_owned()],
                "proxy_ports should preserve the previous reset default"
            );
            assert!(
                s.ru_direct_exceptions.is_empty(),
                "ru_direct_exceptions should be cleared"
            );
            assert!(
                s.auto_vpn_exceptions.is_empty(),
                "auto_vpn_exceptions should be cleared"
            );
            assert!(
                s.auto_vpn_last_checked_unix.is_empty(),
                "auto_vpn metadata should be cleared"
            );
            assert!(!s.auto_vpn_learning_enabled);
            // Routing rules should be just QUIC Block.
            assert_eq!(
                inner.state.routing_rules.len(),
                1,
                "should have exactly 1 rule (QUIC Block)"
            );
            assert_eq!(inner.state.routing_rules[0].name, "QUIC Block");
            // Raw rules should be cleared.
            assert!(
                inner.state.mihomo_features.raw_rules.is_empty(),
                "raw_rules should be cleared"
            );
        }
    }

    #[test]
    fn server_routing_sha256_matches_known_vector() {
        let digest = sha256(b"abc");
        let actual = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            actual,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn server_ref_ignores_display_name_but_not_connection_config() {
        let first = sample_profile(0, "First", "one.example");
        let renamed = sample_profile(0, "Renamed", "one.example");
        let changed = sample_profile(0, "First", "two.example");
        assert_eq!(
            server_ref_for_canonical(&canonical_profile_raw(&first)),
            server_ref_for_canonical(&canonical_profile_raw(&renamed))
        );
        assert_ne!(
            server_ref_for_canonical(&canonical_profile_raw(&first)),
            server_ref_for_canonical(&canonical_profile_raw(&changed))
        );
    }

    #[test]
    fn lifecycle_v2_ref_cannot_cross_into_routing_target_contract() {
        let lifecycle_ref = profile_server_ref(&sample_profile(0, "Lifecycle", "one.example"));
        assert!(valid_lifecycle_ref(&lifecycle_ref));
        assert!(!valid_routing_server_ref(&lifecycle_ref));
        assert!(RoutingTarget::parse(&format!("server:{lifecycle_ref}")).is_err());
    }

    #[test]
    fn server_routing_legacy_target_migrates_before_reindex() {
        let mut state = HincyrayState {
            profiles: vec![
                sample_profile(7, "Pinned", "pinned.example"),
                sample_profile(9, "Other", "other.example"),
            ],
            ..Default::default()
        };
        state.routing_rules.push(RoutingRule {
            enabled: true,
            name: "Pinned".to_owned(),
            domains: vec!["example.com".to_owned()],
            target: "profile:7".to_owned(),
            ..Default::default()
        });
        sync_server_route_registry(&mut state);
        migrate_legacy_target(
            &state.profiles,
            &state.server_route_registry,
            &mut state.routing_rules[0].target,
        );
        let migrated = state.routing_rules[0].target.clone();
        assert!(migrated.starts_with("server:srv-v1-"));
        state.profiles.swap(0, 1);
        reassign_profile_ids(&mut state.profiles);
        assert!(validate_routing_targets(&state, &state.routing_rules, &[]).is_ok());
        let RoutingTarget::Server(reference) = RoutingTarget::parse(&migrated).expect("target")
        else {
            panic!("expected server target");
        };
        let entry = state
            .server_route_registry
            .iter()
            .find(|entry| entry.server_ref == reference)
            .expect("registry entry");
        assert!(entry.canonical_raw.contains("pinned.example"));
    }

    #[test]
    fn server_routing_rejects_stale_target_without_mutating_rules() {
        let (_dir, daemon) = test_daemon();
        let before = {
            let inner = lock(&daemon.inner);
            inner.state.routing_rules.clone()
        };
        let body = json!({"rules": [{
            "enabled": true,
            "name": "Stale",
            "target": "server:srv-v1-00000000000000000000000000000000",
            "domains": ["example.com"]
        }]})
        .to_string();
        let (status, _, response) = handle_routing_rules(&body, &daemon);
        assert_eq!(status, 400, "{response}");
        let inner = lock(&daemon.inner);
        assert_eq!(inner.state.routing_rules.len(), before.len());
        assert_eq!(inner.state.undo_stack.len(), 0);
    }

    #[test]
    fn server_routing_limits_unique_enabled_servers() {
        let mut state = HincyrayState::default();
        for id in 0..=MAX_PINNED_SERVERS {
            state.profiles.push(sample_profile(
                id,
                &format!("Server {id}"),
                &format!("server-{id}.example"),
            ));
        }
        sync_server_route_registry(&mut state);
        let rules: Vec<RoutingRule> = state
            .server_route_registry
            .iter()
            .map(|entry| RoutingRule {
                enabled: true,
                name: entry.server_ref.clone(),
                target: format!("server:{}", entry.server_ref),
                domains: vec!["example.com".to_owned()],
                ..Default::default()
            })
            .collect();
        let error = validate_routing_targets(&state, &rules, &[]).expect_err("limit");
        assert!(error.contains("at most 16"), "{error}");
    }

    #[test]
    fn server_routing_api_exposes_metadata_without_secrets() {
        let (_dir, daemon) = test_daemon();
        handle_import(
            "vless://11111111-1111-1111-1111-111111111111@safe.example:443#Safe",
            &daemon,
        );
        {
            let mut inner = lock(&daemon.inner);
            inner.state.active_profile_id = Some(0);
            sync_server_route_registry(&mut inner.state);
        }
        let (status, _, body) = handle_routing_get(&daemon);
        assert_eq!(status, 200);
        let response: Value = serde_json::from_str(&body).expect("routing response");
        let server = &response["servers"][0];
        assert_eq!(server["name"], "Safe");
        assert!(server["ref"].as_str().is_some_and(valid_routing_server_ref));
        assert!(server.get("raw").is_none());
        assert!(server.get("canonical_raw").is_none());
        assert!(!body.contains("11111111-1111-1111-1111-111111111111"));
    }

    #[test]
    fn server_routing_config_deduplicates_group_and_falls_back_only_to_active() {
        let mut state = HincyrayState {
            profiles: vec![
                sample_profile(0, "Active", "active.example"),
                sample_profile(1, "Pinned", "pinned.example"),
            ],
            active_profile_id: Some(0),
            ..Default::default()
        };
        state.split_routing.enabled = true;
        sync_server_route_registry(&mut state);
        let pinned_ref = state
            .server_route_registry
            .iter()
            .find(|entry| entry.canonical_raw.contains("pinned.example"))
            .expect("pinned ref")
            .server_ref
            .clone();
        for domain in ["one.example", "two.example"] {
            state.routing_rules.push(RoutingRule {
                enabled: true,
                name: domain.to_owned(),
                target: format!("server:{pinned_ref}"),
                domains: vec![domain.to_owned()],
                ..Default::default()
            });
        }
        let yaml = build_daemon_config(&state, &[]).expect("config");
        let config: Value = serde_yaml::from_str(&yaml).expect("yaml");
        let suffix = &pinned_ref[7..];
        let group_name = format!("srv-route-{suffix}");
        let groups = config["proxy-groups"].as_array().expect("groups");
        let matching: Vec<&Value> = groups
            .iter()
            .filter(|group| group["name"] == group_name)
            .collect();
        assert_eq!(matching.len(), 1);
        assert_eq!(
            matching[0]["proxies"],
            json!([format!("srv-out-{suffix}"), PROXY_ACTIVE_NAME])
        );
        assert!(
            !matching[0]["proxies"]
                .as_array()
                .expect("members")
                .iter()
                .any(|member| member == DIRECT_NAME || member == PROXY_NAME)
        );
    }

    #[test]
    fn dead_pinned_server_falls_back_to_active_without_destroying_route_intent() {
        let mut state = HincyrayState {
            profiles: vec![
                sample_profile(0, "Active", "active.example"),
                sample_profile(1, "Pinned", "pinned.example"),
            ],
            active_profile_id: Some(0),
            ..Default::default()
        };
        state.split_routing.enabled = true;
        sync_server_route_registry(&mut state);
        let pinned_ref = state
            .server_route_registry
            .iter()
            .find(|entry| entry.canonical_raw.contains("pinned.example"))
            .expect("pinned ref")
            .server_ref
            .clone();
        let target = format!("server:{pinned_ref}");
        state.routing_rules.push(RoutingRule {
            enabled: true,
            name: "Pinned".to_owned(),
            target: target.clone(),
            domains: vec!["pinned.example".to_owned()],
            ..Default::default()
        });
        let pinned_lifecycle_ref = profile_server_ref(&state.profiles[1]);
        state.dead_server_refs.insert(pinned_lifecycle_ref.clone());

        assert!(validate_routing_targets(&state, &state.routing_rules, &[]).is_ok());
        let yaml = build_daemon_config(&state, &[]).expect("dead target falls back");
        let config: Value = serde_yaml::from_str(&yaml).expect("yaml");
        assert_eq!(state.routing_rules[0].target, target);
        assert!(
            config["rules"]
                .as_array()
                .expect("rules")
                .iter()
                .any(|rule| rule == "DOMAIN-SUFFIX,pinned.example,proxy")
        );
        assert!(
            !config["proxies"]
                .as_array()
                .expect("proxies")
                .iter()
                .any(|proxy| proxy["name"] == format!("srv-out-{}", &pinned_ref[7..]))
        );
        assert!(pinned_route_observer_catalog(&state).is_empty());

        state.dead_server_refs.remove(&pinned_lifecycle_ref);
        let restored_yaml = build_daemon_config(&state, &[]).expect("restored target");
        let restored: Value = serde_yaml::from_str(&restored_yaml).expect("restored yaml");
        assert!(
            restored["rules"]
                .as_array()
                .expect("rules")
                .iter()
                .any(|rule| rule.as_str()
                    == Some(&format!(
                        "DOMAIN-SUFFIX,pinned.example,srv-route-{}",
                        &pinned_ref[7..]
                    )))
        );
    }

    #[test]
    fn server_routing_active_target_uses_proxy_active_without_extra_group() {
        let mut state = HincyrayState {
            profiles: vec![sample_profile(0, "Active", "active.example")],
            active_profile_id: Some(0),
            ..Default::default()
        };
        state.split_routing.enabled = true;
        sync_server_route_registry(&mut state);
        let server_ref = state.server_route_registry[0].server_ref.clone();
        state.routing_rules.push(RoutingRule {
            enabled: true,
            name: "Same server".to_owned(),
            target: format!("server:{server_ref}"),
            domains: vec!["same.example".to_owned()],
            ..Default::default()
        });
        let yaml = build_daemon_config(&state, &[]).expect("config");
        let config: Value = serde_yaml::from_str(&yaml).expect("yaml");
        assert!(
            config["rules"]
                .as_array()
                .expect("rules")
                .iter()
                .any(|rule| rule == "DOMAIN-SUFFIX,same.example,proxy-active")
        );
        assert!(
            !config["proxy-groups"]
                .as_array()
                .expect("groups")
                .iter()
                .any(|group| group["name"]
                    .as_str()
                    .is_some_and(|name| name.starts_with("srv-route-")))
        );
    }

    #[test]
    fn server_routing_device_route_rejects_stale_target_atomically() {
        let (_dir, daemon) = test_daemon();
        let body = json!({
            "enabled": true,
            "name": "TV",
            "ip": "192.168.2.20",
            "target": "server:srv-v1-00000000000000000000000000000000"
        })
        .to_string();
        let (status, _, response) = handle_device_routes_set(&body, &daemon);
        assert_eq!(status, 400, "{response}");
        let inner = lock(&daemon.inner);
        assert!(inner.state.device_routes.is_empty());
    }

    #[test]
    fn server_routing_transition_logs_only_real_switches() {
        let pinned = "srv-out-deadbeef";
        assert_eq!(detect_pinned_route_transition(None, pinned, pinned), None);
        assert_eq!(
            detect_pinned_route_transition(Some(pinned), pinned, pinned),
            None
        );
        assert_eq!(
            detect_pinned_route_transition(Some(pinned), PROXY_ACTIVE_NAME, pinned),
            Some(PinnedRouteTransition::Fallback)
        );
        assert_eq!(
            detect_pinned_route_transition(Some(PROXY_ACTIVE_NAME), PROXY_ACTIVE_NAME, pinned),
            None
        );
        assert_eq!(
            detect_pinned_route_transition(Some(PROXY_ACTIVE_NAME), pinned, pinned),
            Some(PinnedRouteTransition::Recovery)
        );
    }
}
