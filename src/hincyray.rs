//! HincyRay router daemon.
//!
//! Lightweight sync HTTP server on `std::net::TcpListener`, no async
//! runtime, no web framework. Shares `profiles`, `xray_config`, and
//! `scoring` with the desktop app so parser/scoring logic is not
//! duplicated.
//!
//! Default bind: `0.0.0.0:8088`. Override with `HINCYRAY_LISTEN`.
//! State path: see `resolve_state_path`. Override with `HINCYRAY_STATE`.
//! Mihomo config path: alongside state. Override with `HINCYRAY_MIHOMO_CONFIG`.

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
use crate::mihomo_config::{
    DIRECT_NAME, PROXY_NAME, build_mihomo_config, build_mihomo_router_config,
};
use crate::profiles::{
    HwidConfig, Profile, SubscriptionSource, load_subscription_detailed_via_proxy_with_hwid,
    parse_input,
};
use crate::xray_config::{DnsSettings, PortMode, QuicMode, RouterExtra, XrayRouteRule};

const DEFAULT_LISTEN: &str = "0.0.0.0:8088";
const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_HISTORY_SAMPLES: usize = 1000;

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

    // Regenerate config from state on startup so the transparent proxy
    // inbounds are included when split routing is enabled.
    {
        let mut inner = lock(&daemon.inner);
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

    // Start watchdog on router targets.
    start_watchdog(daemon.clone());

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

    // Graceful shutdown: stop child processes and clean up kernel state.
    eprintln!("hincyray: shutting down...");
    {
        let mut inner = lock(&daemon.inner);
        let _ = inner.core.stop();
        let vpn_subnet = inner.state.split_routing.vpn_subnet.clone();
        let _ = inner.firewall.stop(&vpn_subnet);
        let _ = persist_state(&daemon.state_path, &inner.state);
        eprintln!("hincyray: state persisted, children stopped, iptables cleaned");
    }
    Ok(())
}

/// Top-level daemon state plus on-disk paths. Cloning is cheap: only
/// the `Arc` is duplicated.
#[derive(Clone)]
pub struct Daemon {
    inner: Arc<Mutex<DaemonInner>>,
    state_path: PathBuf,
    mihomo_config_path: PathBuf,
}

struct DaemonInner {
    state: HincyrayState,
    core: CoreManager,
    firewall: FirewallManager,
    bench: BenchRuntime,
    /// v0.6: consecutive health-check failures for the active profile.
    /// Reset to 0 on success. When it reaches the threshold (3), the
    /// watchdog triggers a failover to the next-best profile.
    failover_fail_count: u32,
    /// v0.6.1: previous `/proc/stat` aggregate sample for CPU usage
    /// delta computation. `None` on first call → usage returns 0%.
    prev_cpu: Option<CpuTimes>,
    /// v0.6.1: per-core previous samples for per-core usage.
    prev_cpu_per_core: Vec<CpuTimes>,
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
    /// v0.5: DNS anti-leak settings for the router core config.
    #[serde(default)]
    pub dns_settings: DnsSettings,
    /// v0.5: Hardcoded HWID fingerprint for Happ subscription fetches.
    #[serde(default)]
    pub hwid_config: HwidConfig,
    /// v0.6: Auto-benchmark interval in hours (0 = disabled). When > 0,
    /// the watchdog triggers a TCP benchmark on all profiles every N
    /// hours. If `auto_select` is true, switches to the best-scoring
    /// profile after the benchmark completes.
    #[serde(default)]
    pub auto_bench_interval_hours: u32,
    /// v0.6: Unix timestamp of the last auto-triggered benchmark.
    #[serde(default)]
    pub last_auto_bench_unix: u64,
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
            split_routing: SplitRoutingSettings::default(),
            subscriptions: Vec::new(),
            favorites: Vec::new(),
            stats: Vec::new(),
            dns_settings: DnsSettings::default(),
            hwid_config: HwidConfig::default(),
            auto_bench_interval_hours: 0,
            last_auto_bench_unix: 0,
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
    /// v0.5: Port specifications for port-based routing (e.g. "80", "443", "1000-2000").
    #[serde(default)]
    pub ports: Vec<String>,
    /// v0.5: Network type filter: "tcp", "udp", or empty for both.
    #[serde(default)]
    pub network: String,
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

fn default_mihomo_path() -> String {
    "mihomo".to_owned()
}

impl Daemon {
    fn new(state: HincyrayState, state_path: PathBuf, mihomo_config_path: PathBuf) -> Self {
        Self {
            inner: Arc::new(Mutex::new(DaemonInner {
                state,
                core: CoreManager::new(),
                firewall: FirewallManager::new(),
                bench: BenchRuntime::new(),
                failover_fail_count: 0,
                prev_cpu: None,
                prev_cpu_per_core: Vec::new(),
            })),
            state_path,
            mihomo_config_path,
        }
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
        cmd.stdout(Stdio::null()).stderr(stderr);
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
}

impl FirewallManager {
    fn new() -> Self {
        Self {
            active: false,
            tproxy_available: false,
            policy_mark: None,
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

        // 1. Detect TPROXY capability.
        self.tproxy_available = detect_tproxy();
        if !self.tproxy_available {
            eprintln!(
                "hincyray: TPROXY unavailable, using TCP-only REDIRECT (UDP will be blocked)"
            );
        }

        // 1b. Load xt_comment kernel module (needed for iptables -m comment
        // used in rule tagging/cleanup). Not auto-loaded on Keenetic 4.9.
        load_kernel_module("xt_comment");
        // Also ensure TPROXY modules are loaded (they may already be).
        if self.tproxy_available {
            load_kernel_module("xt_TPROXY");
            load_kernel_module("xt_socket");
        }

        // 2. Query or create Keenetic policy and get connmark.
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

        // 3. Install iptables rules.
        install_firewall_rules(&mark, redirect_port, vpn_subnet, self.tproxy_available)?;

        // 4. Install TPROXY policy routing (ip rule + ip route).
        if self.tproxy_available {
            install_tproxy_route();
        }

        // 5. Generate and install ndm hook script.
        install_ndm_hook(&mark, redirect_port, vpn_subnet, self.tproxy_available);

        // 6. Create ready marker.
        let _ = fs::write("/tmp/hincyray_ready", b"1");

        self.active = true;
        eprintln!(
            "hincyray: firewall started (mark={mark}, tproxy={}, port={redirect_port})",
            self.tproxy_available
        );
        Ok(())
    }

    fn stop(&mut self, _vpn_subnet: &str) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }

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
        eprintln!("hincyray: firewall stopped, iptables rules cleaned");
        Ok(())
    }
}

/// Load a kernel module by name. Tries `/lib/modules/$(uname -r)/<name>.ko`
/// then `/opt/lib/modules/<name>.ko` via `insmod`. Silently succeeds if
/// the module is already loaded.
fn load_kernel_module(name: &str) {
    let module_path = format!("/lib/modules/{}/{}.ko", unsafe_kernver(), name);
    let alt_path = format!("/opt/lib/modules/{}.ko", name);
    let _ = Command::new("insmod").arg(&module_path).status();
    let _ = Command::new("insmod").arg(&alt_path).status();
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
    // Try creating a TPROXY rule in a test chain.
    let ok = Command::new("iptables")
        .args(["-t", "mangle", "-N", "HINCYRAY_TEST_TP"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        return false;
    }
    let tproxy_ok = Command::new("iptables")
        .args([
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
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let socket_ok = Command::new("iptables")
        .args([
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
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    // Cleanup test chain.
    let _ = Command::new("iptables")
        .args(["-t", "mangle", "-F", "HINCYRAY_TEST_TP"])
        .status();
    let _ = Command::new("iptables")
        .args(["-t", "mangle", "-X", "HINCYRAY_TEST_TP"])
        .status();
    tproxy_ok && socket_ok
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
    // bypass private LAN and multicast.
    let _ = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "iptables -t nat -A HINCYRAY -m conntrack --ctstate DNAT {comment} -j RETURN"
        ))
        .status();
    let _ = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-A",
            "HINCYRAY",
            "-d",
            "192.168.0.0/16",
            "-m",
            "comment",
            "--comment",
            "hincyray",
            "-j",
            "RETURN",
        ])
        .status();
    let _ = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-A",
            "HINCYRAY",
            "-d",
            "224.0.0.0/4",
            "-m",
            "comment",
            "--comment",
            "hincyray",
            "-j",
            "RETURN",
        ])
        .status();

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
        let _ = Command::new("iptables")
            .args([
                "-t",
                "mangle",
                "-A",
                "HINCYRAY_UDP",
                "-d",
                "192.168.0.0/16",
                "-m",
                "comment",
                "--comment",
                "hincyray",
                "-j",
                "RETURN",
            ])
            .status();
        let _ = Command::new("iptables")
            .args([
                "-t",
                "mangle",
                "-A",
                "HINCYRAY_UDP",
                "-d",
                "224.0.0.0/4",
                "-m",
                "comment",
                "--comment",
                "hincyray",
                "-j",
                "RETURN",
            ])
            .status();

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
                &port_str,
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
    let tproxy_section = if tproxy_available {
        format!(
            r##"# ── mangle table: UDP TPROXY ──
iptables -t mangle -N HINCYRAY_UDP 2>/dev/null
iptables -t mangle -F HINCYRAY_UDP
iptables -t mangle -A HINCYRAY_UDP -m conntrack --ctstate DNAT -m comment --comment hincyray -j RETURN
iptables -t mangle -A HINCYRAY_UDP -d 192.168.0.0/16 -m comment --comment hincyray -j RETURN
iptables -t mangle -A HINCYRAY_UDP -d 224.0.0.0/4 -m comment --comment hincyray -j RETURN
iptables -t mangle -A HINCYRAY_UDP -p udp -m socket --transparent -m comment --comment hincyray -j MARK --set-mark 0x111
iptables -t mangle -A HINCYRAY_UDP -p udp -m comment --comment hincyray -j TPROXY --on-ip 127.0.0.1 --on-port {port} --tproxy-mark 0x111
iptables -t mangle -D PREROUTING -m connmark --mark {mark} -p udp -m comment --comment hincyray -j HINCYRAY_UDP 2>/dev/null
iptables -t mangle -A PREROUTING -m connmark --mark {mark} -p udp -m comment --comment hincyray -j HINCYRAY_UDP
"##,
            port = port_str,
            mark = mark
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
iptables -t nat -A HINCYRAY -d 192.168.0.0/16 -m comment --comment hincyray -j RETURN
iptables -t nat -A HINCYRAY -d 224.0.0.0/4 -m comment --comment hincyray -j RETURN
iptables -t nat -A HINCYRAY -p tcp -m comment --comment hincyray -j REDIRECT --to-ports $PORT
iptables -t nat -D PREROUTING -m connmark --mark $MARK -p tcp -m comment --comment hincyray -j HINCYRAY 2>/dev/null
iptables -t nat -A PREROUTING -m connmark --mark $MARK -p tcp -m comment --comment hincyray -j HINCYRAY

# ── nat table: DNS DNAT (connmark-matched) ──
iptables -t nat -D PREROUTING -m connmark --mark $MARK -p udp --dport 53 -m comment --comment hincyray -j DNAT --to-destination $DNS_DST 2>/dev/null
iptables -t nat -D PREROUTING -m connmark --mark $MARK -p tcp --dport 53 -m comment --comment hincyray -j DNAT --to-destination $DNS_DST 2>/dev/null
iptables -t nat -I PREROUTING 1 -m connmark --mark $MARK -p udp --dport 53 -m comment --comment hincyray -j DNAT --to-destination $DNS_DST
iptables -t nat -I PREROUTING 2 -m connmark --mark $MARK -p tcp --dport 53 -m comment --comment hincyray -j DNAT --to-destination $DNS_DST

{tproxy}

# ── TPROXY policy routing ──
ip rule del fwmark 0x111 lookup 111 2>/dev/null
ip rule add fwmark 0x111 lookup 111 2>/dev/null
ip route flush table 111 2>/dev/null
ip route add local default dev lo table 111 2>/dev/null
"##,
        mark = mark,
        port = port_str,
        tproxy = tproxy_section,
    )
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

/// Open a log file in the daemon log directory, truncating if the
/// existing file exceeds 1 MB to prevent unbounded growth on the
/// router's limited flash/tmpfs. Returns a `Stdio` for passing to
/// `Command::stderr()`.
fn open_log_file(name: &str) -> Result<Stdio, String> {
    let dir = resolve_log_dir();
    fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    let path = dir.join(name);
    // Truncate if file is too large (> 1 MB).
    if let Ok(meta) = fs::metadata(&path)
        && meta.len() > 1_048_576
    {
        let _ = fs::write(&path, b"");
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

fn load_state(state_path: &Path) -> HincyrayState {
    let Ok(text) = fs::read_to_string(state_path) else {
        return HincyrayState::default();
    };
    match serde_json::from_str(&text) {
        Ok(state) => state,
        Err(error) => {
            eprintln!(
                "hincyray: state file {} is corrupted ({}), backing up and starting fresh",
                state_path.display(),
                error
            );
            let backup = state_path.with_extension("json.corrupt");
            let _ = fs::write(&backup, &text);
            eprintln!("hincyray: corrupted state saved to {}", backup.display());
            HincyrayState::default()
        }
    }
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

fn write_config_file(path: &Path, config_yaml: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::write(path, config_yaml).map_err(|error| error.to_string())
}

/// Build the single Mihomo config (YAML) for the current active profile.
/// Returns the YAML string so callers can write it to the daemon's
/// config path.
fn build_daemon_config(state: &HincyrayState) -> Result<String, String> {
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
        return build_mihomo_config(active_profile, &state.listen_host, state.socks_port);
    }

    // Split routing: build the full router config.
    let (extra_profiles, routes, active_block_quic, extra) =
        build_routing_context(state, active_id, active_profile);

    build_mihomo_router_config(
        active_profile,
        &extra_profiles,
        &routes,
        &state.listen_host,
        state.socks_port,
        Some(state.split_routing.redirect_port),
        state.split_routing.tproxy_available,
        state.split_routing.quic_mode.clone(),
        active_block_quic,
        &extra,
    )
}

/// Build the routing context shared by the daemon's config generator.
/// Returns the list of extra profile/outbound-name pairs, the routing
/// rules, whether the active profile should block QUIC, and the extra
/// router options.
fn build_routing_context<'a>(
    state: &'a HincyrayState,
    active_id: usize,
    active_profile: &'a Profile,
) -> (
    Vec<(&'a Profile, String)>,
    Vec<XrayRouteRule>,
    bool,
    RouterExtra,
) {
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
        let ports = normalize_route_items(&rule.ports);
        let network = if rule.network.trim().is_empty() {
            None
        } else {
            Some(rule.network.trim().to_owned())
        };
        if domains.is_empty() && ips.is_empty() && ports.is_empty() && network.is_none() {
            continue;
        }

        let outbound_tag = match rule.target.as_str() {
            "direct" => DIRECT_NAME.to_owned(),
            "active" | "best" | "" => PROXY_NAME.to_owned(),
            target if target.starts_with("profile:") => {
                let id = target.trim_start_matches("profile:").parse::<usize>().ok();
                if let Some(id) = id {
                    if id == active_id {
                        PROXY_NAME.to_owned()
                    } else if let Some(profile) = state.profiles.iter().find(|p| p.id == id) {
                        let tag = format!("profile-{id}");
                        if !extra_profiles.iter().any(|(_, existing)| existing == &tag) {
                            extra_profiles.push((profile, tag.clone()));
                        }
                        tag
                    } else {
                        PROXY_NAME.to_owned()
                    }
                } else {
                    PROXY_NAME.to_owned()
                }
            }
            _ => PROXY_NAME.to_owned(),
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
            ports,
            network,
        });
    }

    let active_block_quic = state.split_routing.block_quic_global || active_profile.block_quic;
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
    };
    (extra_profiles, routes, active_block_quic, extra)
}

/// Extract the parent directory of the configured geo asset path to pass
/// to Mihomo's `-d` home directory flag.
fn geo_dir_from_state(state: &HincyrayState) -> Option<String> {
    let path = state.split_routing.geo_asset_path.trim();
    if path.is_empty() {
        return None;
    }
    let p = Path::new(path);
    p.parent().map(|p| p.to_string_lossy().into_owned())
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

/// Try direct fetch first; on failure, fall back to the local core
/// SOCKS inbound (`socks5h://127.0.0.1:<socks_port>`) iff the active
/// core is running. Network I/O happens here, so the caller must NOT
/// hold the daemon mutex.
fn load_subscription_for_daemon(
    source: &SubscriptionSource,
    proxy_info: &DaemonProxyInfo,
    hwid: &HwidConfig,
) -> SubscriptionLoadOutcome {
    match load_subscription_detailed_via_proxy_with_hwid(source, None, hwid) {
        Ok(report) => SubscriptionLoadOutcome::Ok(report),
        Err(direct_err) => {
            if !proxy_info.core_running {
                return SubscriptionLoadOutcome::Failed {
                    direct: direct_err,
                    proxy: None,
                };
            }
            match load_subscription_detailed_via_proxy_with_hwid(
                source,
                Some(&proxy_info.socks_url),
                hwid,
            ) {
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
                "split_routing": inner.state.split_routing,
                "dns_enabled": inner.state.dns_settings.enabled,
                "hwid": inner.state.hwid_config.hwid,
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
        ("GET", "/api/mihomo-config") => handle_get_mihomo_config(daemon),
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
        ("POST", "/api/subscriptions/delete") => handle_subscriptions_delete(body, daemon),
        ("GET", "/api/routing") => handle_routing_get(daemon),
        ("POST", "/api/routing/settings") => handle_routing_settings(body, daemon),
        ("POST", "/api/routing/rules") => handle_routing_rules(body, daemon),
        ("POST", "/api/routing/catalog/refresh") => handle_routing_catalog_refresh(body, daemon),
        ("POST", "/api/routing/apply") => handle_routing_apply(daemon),
        ("GET", "/api/routing/firewall-status") => handle_firewall_status(daemon),
        ("POST", "/api/routing/firewall-start") => handle_firewall_start(daemon),
        ("POST", "/api/routing/firewall-stop") => handle_firewall_stop(daemon),
        ("GET", "/api/dns") => handle_dns_get(daemon),
        ("POST", "/api/dns") => handle_dns_set(body, daemon),
        ("GET", "/api/dns/leak-test") => handle_dns_leak_test(daemon),
        ("GET", "/api/logs") => handle_logs(daemon),
        ("GET", "/api/system") => handle_system(daemon),
        ("GET", "/api/auto-settings") => handle_auto_settings_get(daemon),
        ("POST", "/api/auto-settings") => handle_auto_settings_set(body, daemon),
        ("GET", "/api/hwid") => handle_hwid_get(daemon),
        ("POST", "/api/hwid") => handle_hwid_set(body, daemon),
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
    match build_daemon_config(&inner.state) {
        Ok(config_yaml) => (200, "text/yaml; charset=utf-8", config_yaml),
        Err(error) => (
            400,
            "application/json",
            json!({"error": error, "profile_id": inner.state.active_profile_id}).to_string(),
        ),
    }
}

/// Regenerate the Mihomo config and write it to the daemon's config
/// path. Returns the binary path and config path so the caller can start
/// the core.
fn regenerate_config(state: &HincyrayState, daemon: &Daemon) -> Result<(String, PathBuf), String> {
    let config_yaml = build_daemon_config(state)?;
    let config_path = daemon.mihomo_config_path.clone();
    write_config_file(&config_path, &config_yaml)?;
    Ok((state.mihomo_path.clone(), config_path))
}

fn handle_core_start(daemon: &Daemon) -> (u16, &'static str, String) {
    let mut inner = lock(&daemon.inner);
    let geo_dir = geo_dir_from_state(&inner.state);
    let (binary_path, config_path) = match regenerate_config(&inner.state, daemon) {
        Ok(pair) => pair,
        Err(error) => {
            return (
                500,
                "application/json",
                json!({"error": format!("config regeneration: {error}")}).to_string(),
            );
        }
    };
    match inner
        .core
        .start(&binary_path, &config_path, geo_dir.as_deref())
    {
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
    let geo_dir = geo_dir_from_state(&inner.state);
    let (binary_path, config_path) = match regenerate_config(&inner.state, daemon) {
        Ok(pair) => pair,
        Err(error) => {
            return (
                500,
                "application/json",
                json!({"error": format!("config regeneration: {error}")}).to_string(),
            );
        }
    };
    match inner
        .core
        .restart(&binary_path, &config_path, geo_dir.as_deref())
    {
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

    let profiles = {
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
        profiles
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
        "xray".to_owned(),
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

/// Replace all profiles belonging to subscription `url` with `fresh`.
/// Old profiles with `group == Some(url)` are removed; fresh profiles
/// are added (dedup by `raw` against profiles from other sources).
/// All profiles are re-indexed with sequential IDs and
/// `active_profile_id` is updated to point to the active profile by
/// its `raw` string. Returns the number of fresh profiles added.
fn replace_subscription_profiles(
    state: &mut HincyrayState,
    url: &str,
    fresh: Vec<Profile>,
) -> usize {
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

    added
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
    removed_active
}

fn handle_subscriptions_refresh(daemon: &Daemon) -> (u16, &'static str, String) {
    // Read saved subscription sources plus the SOCKS fallback info
    // under a single short lock; network I/O happens below without
    // holding the mutex so the API stays responsive.
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
        let outcome = load_subscription_for_daemon(source, &proxy_info, &hwid);
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
                // Replace all profiles belonging to this subscription
                // with the fresh set. This removes stale profiles that
                // are no longer in the subscription and prevents
                // duplicates from accumulating across refreshes.
                let added =
                    replace_subscription_profiles(&mut inner.state, &source.url, report.profiles);
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
            // Replace all profiles belonging to this subscription with
            // the fresh set — removes stale entries, prevents duplicates.
            let added =
                replace_subscription_profiles(&mut inner.state, &source.url, report.profiles);
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
        rule.ports = normalize_route_items(&rule.ports);
        rule.network = rule.network.trim().to_owned();
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
    let config_yaml = match build_daemon_config(&inner.state) {
        Ok(yaml) => yaml,
        Err(error) => return (400, "application/json", json!({"error": error}).to_string()),
    };
    let config_path = daemon.mihomo_config_path.clone();
    let binary_path = inner.state.mihomo_path.clone();
    if let Err(error) = write_config_file(&config_path, &config_yaml) {
        return (
            500,
            "application/json",
            json!({"error": format!("write config: {error}")}).to_string(),
        );
    }
    let was_running = inner.core.is_running();
    let split = inner.state.split_routing.clone();
    let geo_dir = geo_dir_from_state(&inner.state);
    let core_status = if was_running {
        match inner
            .core
            .restart(&binary_path, &config_path, geo_dir.as_deref())
        {
            Ok(()) => inner.core.status().to_owned(),
            Err(error) => return (500, "application/json", json!({"error": error}).to_string()),
        }
    } else {
        inner.core.status().to_owned()
    };

    let firewall_status = if split.enabled {
        // Restart firewall with current settings.
        let vpn_subnet = split.vpn_subnet.clone();
        let _ = inner.firewall.stop(&vpn_subnet);
        let redirect_port = split.redirect_port;
        let policy_name = split.policy_name.clone();
        let cached_mark = split.policy_mark.clone();
        match inner.firewall.start(
            redirect_port,
            &vpn_subnet,
            &policy_name,
            cached_mark.as_deref(),
        ) {
            Ok(()) => {
                // Persist discovered policy mark + tproxy availability.
                if let Some(ref mark) = inner.firewall.policy_mark {
                    inner.state.split_routing.policy_mark = Some(mark.clone());
                }
                inner.state.split_routing.tproxy_available = inner.firewall.tproxy_available;
                let _ = persist_state(&daemon.state_path, &inner.state);
                // Regenerate config with correct tproxy_available flag.
                if let Err(e) = regenerate_config(&inner.state, daemon) {
                    eprintln!("hincyray: config regen after firewall start: {e}");
                }
                "running".to_owned()
            }
            Err(error) => {
                return (
                    500,
                    "application/json",
                    json!({"applied": true, "core_status": core_status, "firewall_error": error})
                        .to_string(),
                );
            }
        }
    } else {
        let vpn_subnet = split.vpn_subnet.clone();
        let _ = inner.firewall.stop(&vpn_subnet);
        "stopped".to_owned()
    };

    (
        200,
        "application/json",
        json!({"applied": true, "core_status": core_status, "firewall_status": firewall_status})
            .to_string(),
    )
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
        json!({"dns": inner.state.dns_settings}).to_string(),
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
        json!({"dns": inner.state.dns_settings}).to_string(),
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
    let _ = persist_state(&daemon.state_path, &inner.state);
    (
        200,
        "application/json",
        json!({
            "auto_select": inner.state.auto_select,
            "auto_bench_interval_hours": inner.state.auto_bench_interval_hours,
            "auto_switch": inner.state.split_routing.auto_switch,
        })
        .to_string(),
    )
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
        lines[start..].join("\n")
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

/// Find the profile with the highest `last_score` from `ProfileStats`
/// that is not in `excluded_profiles` and has at least one successful
/// probe. A zero score is still a valid low-priority fallback: some
/// endpoints pass latency/health probes but score zero because the short
/// download test produced no measurable throughput on the router.
/// Returns the profile id, or None if no candidate exists.
fn find_best_profile_by_score(
    state: &HincyrayState,
    excluded_profiles: &HashSet<usize>,
) -> Option<usize> {
    let mut best: Option<(usize, u32)> = None;
    for profile in &state.profiles {
        if excluded_profiles.contains(&profile.id) {
            continue;
        }
        let Some(stat) = state.stats.iter().find(|s| s.profile_raw == profile.raw) else {
            continue;
        };
        if stat.success_count == 0 {
            continue;
        }
        if best
            .map(|(_, score)| stat.last_score > score)
            .unwrap_or(true)
        {
            best = Some((profile.id, stat.last_score));
        }
    }
    best.map(|(id, _)| id)
}

/// Start a TCP benchmark on all profiles from the watchdog. This is
/// the same mechanism as `handle_bench_start` but uses the TCP method
/// (lightweight, no temp Xray processes) and covers all profiles.
fn start_auto_benchmark(daemon: &Daemon) {
    let profiles = {
        let inner = lock(&daemon.inner);
        if inner.bench.is_running() {
            return;
        }
        inner.state.profiles.clone()
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
        "xray".to_owned(),
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
    InvalidConfig(String),
    Runtime(String),
}

impl ActiveProfileApplyError {
    fn http_status(&self) -> u16 {
        match self {
            Self::InvalidConfig(_) => 400,
            Self::Runtime(_) => 500,
        }
    }

    fn message(&self) -> &str {
        match self {
            Self::InvalidConfig(message) | Self::Runtime(message) => message,
        }
    }
}

/// Apply a new active profile to every layer that observes it: in-memory
/// state, generated Mihomo config, running Mihomo process, and persisted state.
///
/// Mihomo does not hot-reload its config, so writing the file without
/// restarting the core creates a split-brain state where the API reports one
/// active profile while the SOCKS/transparent proxy still uses the old
/// outbound. Keep all profile-switching entrypoints behind this helper so that
/// "active profile" has one system-wide meaning.
fn apply_active_profile(
    inner: &mut MutexGuard<DaemonInner>,
    daemon: &Daemon,
    profile_id: usize,
) -> Result<(), ActiveProfileApplyError> {
    let previous_profile_id = inner.state.active_profile_id;
    let geo_dir = geo_dir_from_state(&inner.state);

    inner.state.active_profile_id = Some(profile_id);
    let config_yaml = match build_daemon_config(&inner.state) {
        Ok(yaml) => yaml,
        Err(error) => {
            inner.state.active_profile_id = previous_profile_id;
            return Err(ActiveProfileApplyError::InvalidConfig(error));
        }
    };

    let config_path = daemon.mihomo_config_path.clone();
    let binary_path = inner.state.mihomo_path.clone();

    let apply_result = write_config_file(&config_path, &config_yaml)
        .and_then(|()| {
            inner
                .core
                .restart(&binary_path, &config_path, geo_dir.as_deref())
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
            if let Err(rollback_error) =
                inner
                    .core
                    .restart(&rollback_binary, &rollback_path, geo_dir.as_deref())
            {
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
///    switch to the next-best profile by benchmark score.
/// 4. **Auto-benchmark (auto_bench_interval_hours > 0)** — trigger a
///    TCP benchmark on all profiles on a schedule.
/// 5. **Auto-select (auto_select)** — when a benchmark finishes,
///    switch to the highest-scoring profile.
fn start_watchdog(daemon: Daemon) {
    thread::spawn(move || {
        let mut bench_was_running = false;
        let mut restart_backoff_secs: u64 = 0;
        let mut failover_rejected_profiles = HashSet::new();

        loop {
            thread::sleep(Duration::from_secs(10));

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
            ) = {
                let mut inner = lock(&daemon.inner);
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
                    let mut inner = lock(&daemon.inner);
                    match regenerate_config(&inner.state, &daemon) {
                        Ok((binary_path, config_path)) => {
                            let geo_dir = geo_dir_from_state(&inner.state);
                            if let Err(error) =
                                inner
                                    .core
                                    .start(&binary_path, &config_path, geo_dir.as_deref())
                            {
                                eprintln!("hincyray: watchdog core restart failed: {error}");
                                restart_backoff_secs = restart_backoff_secs.clamp(10, 150) * 2;
                            } else {
                                restart_backoff_secs = 0;
                                eprintln!("hincyray: core restarted by watchdog");
                            }
                        }
                        Err(error) => {
                            eprintln!("hincyray: watchdog config regeneration failed: {error}");
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
                        let _ = persist_state(&daemon.state_path, &inner.state);
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

            // --- Phase 3: Health check + failover (auto_switch) ---
            if auto_switch && !bench_running && core_running {
                let healthy = socks_health_check(socks_port);
                let mut inner = lock(&daemon.inner);
                if healthy {
                    if inner.failover_fail_count > 0 {
                        eprintln!("hincyray: health check recovered");
                    }
                    inner.failover_fail_count = 0;
                    failover_rejected_profiles.clear();
                } else {
                    inner.failover_fail_count += 1;
                    const FAILOVER_THRESHOLD: u32 = 3;
                    eprintln!(
                        "hincyray: health check failed ({}/{})",
                        inner.failover_fail_count, FAILOVER_THRESHOLD
                    );
                    if inner.failover_fail_count >= FAILOVER_THRESHOLD {
                        if let Some(id) = active_profile_id {
                            failover_rejected_profiles.insert(id);
                        }
                        if let Some(next_id) =
                            find_best_profile_by_score(&inner.state, &failover_rejected_profiles)
                        {
                            eprintln!("hincyray: failover to profile {next_id}");
                            switch_active_profile(&mut inner, &daemon, next_id);
                        } else {
                            eprintln!("hincyray: no alternative profile for failover");
                        }
                        inner.failover_fail_count = 0;
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
                    let _ = persist_state(&daemon.state_path, &inner.state);
                }
            }

            // --- Phase 5: Auto-select after benchmark ---
            if bench_was_running && !bench_running && auto_select {
                eprintln!("hincyray: benchmark finished, auto-selecting best profile");
                let mut inner = lock(&daemon.inner);
                if let Some(best_id) = find_best_profile_by_score(&inner.state, &HashSet::new())
                    && Some(best_id) != inner.state.active_profile_id
                {
                    eprintln!("hincyray: auto-switching to profile {best_id}");
                    switch_active_profile(&mut inner, &daemon, best_id);
                }
            }
            bench_was_running = bench_running;
        }
    });
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
.log-box{background:#1a1a2e;color:#c0c0c0;padding:.5em;max-height:300px;overflow:auto;font-size:12px;white-space:pre-wrap;border-radius:4px}
.bar-wrap{background:#eaeef2;border-radius:3px;height:8px;overflow:hidden;margin-top:.2em}
.bar-fill{height:100%;border-radius:3px;transition:width .4s ease}
.bar-fill.cpu{background:linear-gradient(90deg,#4ac26b,#2da44e)}
.bar-fill.mem{background:linear-gradient(90deg,#58a6ff,#1f6feb)}
.bar-fill.hot{background:linear-gradient(90deg,#ff8182,#cf222e)}
.card .bar-wrap{margin-top:.25em}
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
<p class="subtle">Lightweight Keenetic VPN/proxy panel &middot; v0.7 &middot; NAT REDIRECT + TPROXY transparent proxy, Keenetic policy integration, ndm hooks, QUIC toggle, ping, stats, favorites, subscription refresh, port routing, DNS anti-leak, HWID fingerprint, VMess/Trojan/Shadowsocks. Talks to the local JSON API over fetch.</p>

<div id="msg" class="msg" role="status" aria-live="polite"></div>

<h2>Status</h2>
<div class="cards">
  <div class="card"><div class="label">Core</div><div class="value" id="card-core">&mdash;</div></div>
  <div class="card"><div class="label">Active profile</div><div class="value" id="card-active">&mdash;</div></div>
  <div class="card"><div class="label">Profiles</div><div class="value" id="card-count">&mdash;</div></div>
  <div class="card"><div class="label">SOCKS listen</div><div class="value" id="card-socks">&mdash;</div></div>
  <div class="card"><div class="label">State path</div><div class="value" id="card-state">&mdash;</div></div>
  <div class="card"><div class="label">Config path</div><div class="value" id="card-config-path">&mdash;</div></div>
</div>

<div class="row">
  <button class="primary" id="btn-refresh">Refresh</button>
  <button id="btn-start">Start core</button>
  <button id="btn-stop">Stop core</button>
  <button id="btn-restart">Restart core</button>
</div>

<h2>Benchmark / ping</h2>
<p class="subtle">TCP probes <code>address:port</code> directly (no core). HEAD/GET spin up a temporary Xray SOCKS per VLESS/VMess/Trojan/SS profile, run curl, then tear it down &mdash; the active core is never touched. Hysteria2 profiles use TCP only (Mihomo benchmark not yet implemented).</p>
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
    <thead><tr><th>URL</th><th>Profiles</th><th>Last loaded</th><th>Last error</th><th></th></tr></thead>
    <tbody id="subs-body"><tr><td colspan="5" class="subtle">No saved subscriptions.</td></tr></tbody>
  </table>
</div>

<h2>HWID Fingerprint <span id="hwid-toggle" class="toggle">show</span></h2>
<div id="hwid-panel" class="collapsible">
  <p class="subtle">Hardcoded device fingerprint for Happ subscription fetches. Replaces the real device ID with a fixed, consistent identity so the server's cross-check passes. All fields must be mutually consistent (model/OS/HWID).</p>
  <div class="grid2">
    <div class="field"><label for="hwid-value">HWID (16 hex chars)</label><input type="text" id="hwid-value" placeholder="a3f7e10d5c9b2486"></div>
    <div class="field"><label for="hwid-os">OS version</label><input type="text" id="hwid-os" placeholder="13"></div>
    <div class="field"><label for="hwid-model">Device model</label><input type="text" id="hwid-model" placeholder="Poco X3 Pro"></div>
    <div class="field"><label for="hwid-device-os">Device OS</label><input type="text" id="hwid-device-os" placeholder="Android"></div>
    <div class="field"><label for="hwid-app-ver">App version</label><input type="text" id="hwid-app-ver" placeholder="3.22.1"></div>
  </div>
  <div class="row"><button id="btn-hwid-save">Save HWID</button><span class="subtle" id="hwid-status"></span></div>
</div>

<h2>DNS Anti-Leak <span id="dns-toggle" class="toggle">show</span></h2>
<div id="dns-panel" class="collapsible">
  <p class="subtle">When enabled, Mihomo uses configured DNS servers instead of the system resolver, preventing DNS leaks. Remote DNS queries go through the proxy; local DNS handles direct domains (e.g. CN).</p>
  <div class="row" style="margin:.3em 0">
    <label class="chip"><input type="checkbox" id="dns-enabled"> Enable DNS anti-leak</label>
    <div class="field"><label for="dns-strategy">Query strategy</label><select id="dns-strategy"><option value="UseIPv4">UseIPv4</option><option value="UseIPv6">UseIPv6</option><option value="UseIP">UseIP (v4+v6)</option></select></div>
  </div>
  <div class="grid2">
    <div class="field"><label for="dns-remote">Remote DNS servers (one per line)</label><textarea id="dns-remote" placeholder="https://1.1.1.1/dns-query&#10;8.8.8.8"></textarea></div>
    <div class="field"><label for="dns-local">Local DNS servers (one per line, for direct domains)</label><textarea id="dns-local" placeholder="223.5.5.5&#10;223.6.6.6"></textarea></div>
  </div>
  <div class="row"><button id="btn-dns-save">Save DNS</button><span class="subtle" id="dns-status"></span></div>
</div>

<h2>DNS Leak Test <span id="leak-toggle" class="toggle">show</span></h2>
<div id="leak-panel" class="collapsible">
  <p class="subtle">Checks whether DNS queries from the VPN WiFi segment are routed through the proxy (no leak) or exposed to the ISP (leak). Click "Run test" to check.</p>
  <div class="row" style="margin:.3em 0">
    <button class="primary" id="btn-dns-leak-test">Run test</button>
    <span class="subtle" id="leak-test-status"></span>
  </div>
  <div id="leak-test-results" style="display:none">
    <table>
      <tbody>
        <tr><td class="subtle">Status</td><td id="leak-status"></td></tr>
        <tr><td class="subtle">DNS redirect (iptables)</td><td id="leak-dns-redirect"></td></tr>
        <tr><td class="subtle">Mangle MARK (iptables)</td><td id="leak-mangle"></td></tr>
        <tr><td class="subtle">Mihomo DNS inbound (port 1053)</td><td id="leak-dns-inbound"></td></tr>
        <tr><td class="subtle">Proxy exit IP</td><td id="leak-proxy-ip"></td></tr>
        <tr><td class="subtle">Proxy location</td><td id="leak-proxy-loc"></td></tr>
        <tr><td class="subtle">DNS via proxy (whoami.akamai.net)</td><td id="leak-dns-proxy"></td></tr>
        <tr><td class="subtle">DNS direct (ISP resolver)</td><td id="leak-dns-direct"></td></tr>
        <tr><td class="subtle">Leak detected?</td><td id="leak-detected"></td></tr>
      </tbody>
    </table>
  </div>
</div>

<h2>System <span id="sys-toggle" class="toggle">hide</span></h2>
<div id="sys-panel" class="collapsible" style="display:block">
  <div class="cards">
    <div class="card"><div class="label">CPU</div><div class="value" id="sys-cpu-model">&mdash;</div></div>
    <div class="card"><div class="label">Cores</div><div class="value" id="sys-cpu-cores">&mdash;</div></div>
    <div class="card"><div class="label">CPU usage</div><div class="value" id="sys-cpu-usage">&mdash;</div><div class="bar-wrap"><div class="bar-fill cpu" id="sys-cpu-bar" style="width:0%"></div></div></div>
    <div class="card"><div class="label">Temperature</div><div class="value" id="sys-cpu-temp">&mdash;</div><div class="bar-wrap"><div class="bar-fill" id="sys-temp-bar" style="width:0%"></div></div></div>
    <div class="card"><div class="label">RAM usage</div><div class="value" id="sys-mem-usage">&mdash;</div><div class="bar-wrap"><div class="bar-fill mem" id="sys-mem-bar" style="width:0%"></div></div></div>
    <div class="card"><div class="label">RAM total</div><div class="value" id="sys-mem-total">&mdash;</div></div>
    <div class="card"><div class="label">Load average</div><div class="value" id="sys-load">&mdash;</div></div>
    <div class="card"><div class="label">Uptime</div><div class="value" id="sys-uptime">&mdash;</div></div>
    <div class="card"><div class="label">Kernel</div><div class="value" id="sys-kernel">&mdash;</div></div>
  </div>
  <div class="row" style="margin:.4em 0">
    <span class="subtle" id="sys-hostname"></span>
    <span class="subtle" id="sys-model"></span>
    <span class="subtle" id="sys-features"></span>
  </div>
</div>

<h2>Auto Settings <span id="auto-toggle" class="toggle">show</span></h2>
<div id="auto-panel" class="collapsible">
  <div class="grid2">
    <label class="chip"><input type="checkbox" id="auto-select-chk"> Auto-select best profile after benchmark</label>
    <label class="chip"><input type="checkbox" id="auto-switch-chk"> Auto-switch (failover) on health check failure</label>
    <div class="field"><label for="auto-bench-hours">Auto-benchmark interval (hours, 0 = disabled)</label><input type="number" id="auto-bench-hours" min="0" max="168" value="0"></div>
  </div>
  <div class="row" style="margin:.45em 0">
    <button id="btn-auto-save">Save auto settings</button>
    <span class="subtle">Failover failures: <span id="auto-failover-count">0</span>/3</span>
    <span class="subtle" id="auto-last-bench"></span>
  </div>
</div>

<h2>Logs <span id="logs-toggle" class="toggle">show</span></h2>
<div id="logs-panel" class="collapsible">
  <div class="row" style="margin:.45em 0">
    <button id="btn-logs-refresh">Refresh logs</button>
  </div>
  <h3 class="subtle">Core (Mihomo)</h3>
  <pre id="mihomo-log" class="log-box"></pre>
</div>

<h2>WiFi Traffic Split <span id="routing-toggle" class="toggle">show</span></h2>
<div id="routing-panel" class="collapsible">
  <p class="subtle">Rules apply to devices assigned to the Keenetic <code>HincyRay</code> traffic policy via NAT REDIRECT (TCP) + TPROXY (UDP). Direct SOCKS clients keep using the active server. First matching rule wins; unmatched traffic falls back to the active server.</p>
  <div class="grid2">
    <label class="chip"><input type="checkbox" id="route-enabled"> Enable WiFi split routing</label>
    <label class="chip"><input type="checkbox" id="route-auto-switch"> Auto switch servers</label>
    <label class="chip"><input type="checkbox" id="route-block-quic"> Block QUIC / UDP 443 globally</label>
    <div class="field"><label for="route-source">Rule source project</label><select id="route-source"></select></div>
    <div class="field"><label for="route-quic-mode">QUIC (UDP/443) mode</label><select id="route-quic-mode"><option value="block">Block (force TCP fallback)</option><option value="proxy">Proxy via TPROXY</option></select></div>
    <div class="field"><label for="route-port-mode">Port routing mode</label><select id="route-port-mode"><option value="all">All ports (proxy everything)</option><option value="allow_list">Allow-list (only proxy listed ports)</option><option value="deny_list">Deny-list (proxy all except listed)</option></select></div>
    <div class="field"><label for="route-geo-path">GeoIP/GeoSite asset path</label><input type="text" id="route-geo-path" placeholder="/opt/etc/hincyray"></div>
  </div>
  <div class="grid2" id="port-lists-section" style="display:none">
    <div class="field"><label for="route-proxy-ports">Proxy ports (allow-list mode, comma-separated)</label><input type="text" id="route-proxy-ports" placeholder="80,443,8080"></div>
    <div class="field"><label for="route-bypass-ports">Bypass ports (deny-list mode, comma-separated)</label><input type="text" id="route-bypass-ports" placeholder="25,53,110,143"></div>
  </div>
  <div class="row" style="margin:.45em 0">
    <button id="btn-routing-save">Save settings</button>
    <button id="btn-catalog-refresh">Refresh service catalog</button>
    <button class="primary" id="btn-routing-apply">Apply Mihomo config</button>
    <button id="btn-firewall-status">Firewall status</button>
    <button id="btn-firewall-start">Start firewall</button>
    <button class="danger" id="btn-firewall-stop">Stop firewall</button>
    <span class="subtle" id="routing-status"></span>
  </div>
  <h3 style="font-size:.95em;margin:.8em 0 .35em">Add rule</h3>
  <div class="grid2">
    <div class="field"><label for="rule-name">Rule name</label><input type="text" id="rule-name" placeholder="YouTube via server A"></div>
    <div class="field"><label for="rule-target">Target</label><select id="rule-target"></select></div>
    <div class="field"><label for="rule-ports">Ports (comma-separated, e.g. 80,443,1000-2000)</label><input type="text" id="rule-ports" placeholder="80,443"></div>
    <div class="field"><label for="rule-network">Network</label><select id="rule-network"><option value="">Any (TCP+UDP)</option><option value="tcp">TCP only</option><option value="udp">UDP only</option></select></div>
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

<h2>Generated Mihomo config</h2>
<div class="row">
  <button id="btn-load-config">Load / show</button>
  <span class="subtle">Fetches <code>GET /api/mihomo-config</code> for the active profile.</span>
</div>
<pre id="mihomo-config">&mdash;</pre>

<hr class="subtle">
<p class="subtle">HincyRay daemon &middot; API: <code>/api/health</code>, <code>/api/status</code>, <code>/api/profiles</code>, <code>/api/bench/*</code>, <code>/api/stats</code>, <code>/api/favorites/*</code>, <code>/api/subscriptions/*</code>, <code>/api/mihomo-config</code>, <code>/api/core/*</code>, <code>/api/routing/*</code>, <code>/api/routing/firewall-*</code>, <code>/api/dns</code>, <code>/api/hwid</code>.</p>

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
  document.getElementById("card-config-path").textContent = s.mihomo_config_path;
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
          showOk("Profile " + id + " selected. Mihomo config regenerated.");
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
    tbody.innerHTML = '<tr><td colspan="5" class="subtle">No saved subscriptions. Import a subscription URL to save it here.</td></tr>';
    return;
  }
  var rows = subs.map(function(s){
    var err = s.last_error ? esc(s.last_error).slice(0, 80) : "&mdash;";
    return '<tr>'
      + '<td><code>' + esc(s.url) + '</code></td>'
      + '<td>' + (s.profile_count || 0) + '</td>'
      + '<td>' + fmtTime(s.last_loaded_unix) + '</td>'
      + '<td>' + err + '</td>'
      + '<td><button class="mini danger" data-sub-delete="' + esc(s.url) + '">Delete</button></td>'
      + '</tr>';
  });
  tbody.innerHTML = rows.join("");
  Array.prototype.forEach.call(tbody.querySelectorAll("[data-sub-delete]"), function(btn){
    btn.addEventListener("click", function(){
      var url = btn.getAttribute("data-sub-delete");
      if(!confirm("Delete this subscription and all its profiles?\n" + url)){ return; }
      api("POST", "/api/subscriptions/delete", JSON.stringify({url: url})).then(function(data){
        showOk("Deleted " + (data.removed_profiles || 0) + " profile(s).");
        return refreshAll();
      }).catch(function(err){ setMsg("Delete failed: " + err.message); });
    });
  });
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

  var portMode = document.getElementById("route-port-mode");
  if(portMode){ portMode.value = settings.port_mode || "all"; }
  var geoPath = document.getElementById("route-geo-path");
  if(geoPath){ geoPath.value = settings.geo_asset_path || ""; }
  var proxyPorts = document.getElementById("route-proxy-ports");
  if(proxyPorts){ proxyPorts.value = (settings.proxy_ports || []).join(","); }
  var bypassPorts = document.getElementById("route-bypass-ports");
  if(bypassPorts){ bypassPorts.value = (settings.bypass_ports || []).join(","); }
  updatePortListsVisibility();

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

function updatePortListsVisibility(){
  var mode = document.getElementById("route-port-mode");
  var section = document.getElementById("port-lists-section");
  if(!mode || !section){ return; }
  var v = mode.value;
  section.style.display = (v === "allow_list" || v === "deny_list") ? "grid" : "none";
}

function routingMatchSummary(rule){
  var parts = [];
  if(rule.services && rule.services.length){ parts.push("services: " + rule.services.join(", ")); }
  if(rule.domains && rule.domains.length){ parts.push("domains: " + rule.domains.slice(0,4).join(", ") + (rule.domains.length > 4 ? "…" : "")); }
  if(rule.ips && rule.ips.length){ parts.push("ip: " + rule.ips.slice(0,4).join(", ") + (rule.ips.length > 4 ? "…" : "")); }
  if(rule.ports && rule.ports.length){ parts.push("ports: " + rule.ports.join(",")); }
  if(rule.network){ parts.push("net: " + rule.network); }
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
  var portsRaw = (document.getElementById("rule-ports").value || "").trim();
  var ports = portsRaw ? portsRaw.split(",").map(function(s){ return s.trim(); }).filter(Boolean) : [];
  var networkVal = (document.getElementById("rule-network").value || "").trim();
  var rule = {
    enabled: true,
    name: (document.getElementById("rule-name").value || "").trim() || "Routing rule",
    kind: "custom",
    pattern: "",
    target: document.getElementById("rule-target").value,
    domains: domains,
    ips: linesFrom("rule-ips"),
    services: services,
    ports: ports,
    network: networkVal
  };
  routingState.rules = routingState.rules || [];
  routingState.rules.push(rule);
  document.getElementById("rule-name").value = "";
  document.getElementById("rule-domains").value = "";
  document.getElementById("rule-ips").value = "";
  document.getElementById("rule-ports").value = "";
  document.getElementById("rule-network").value = "";
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
  api("GET", "/api/mihomo-config").then(function(data){
    document.getElementById("mihomo-config").textContent = data;
  }).catch(function(err){ setMsg("Load config failed: " + err.message); });
});

function routingSettingsBody(){
  var portMode = document.getElementById("route-port-mode");
  var proxyPorts = (document.getElementById("route-proxy-ports").value || "").split(",").map(function(s){return s.trim();}).filter(Boolean);
  var bypassPorts = (document.getElementById("route-bypass-ports").value || "").split(",").map(function(s){return s.trim();}).filter(Boolean);
  var quicMode = document.getElementById("route-quic-mode");
  return JSON.stringify({
    enabled: document.getElementById("route-enabled").checked,
    auto_switch: document.getElementById("route-auto-switch").checked,
    block_quic_global: document.getElementById("route-block-quic").checked,
    rule_source: document.getElementById("route-source").value,
    quic_mode: quicMode ? quicMode.value : "block",
    port_mode: portMode ? portMode.value : "all",
    proxy_ports: proxyPorts,
    bypass_ports: bypassPorts,
    geo_asset_path: (document.getElementById("route-geo-path").value || "").trim()
  });
}

document.getElementById("btn-routing-save").addEventListener("click", function(){
  api("POST", "/api/routing/settings", routingSettingsBody()).then(function(data){
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
  api("POST", "/api/routing/settings", routingSettingsBody()).then(function(){
    return api("POST", "/api/routing/rules", JSON.stringify({rules: routingState.rules || []}));
  }).then(function(){
    return api("POST", "/api/routing/apply");
  }).then(function(data){
    showOk("Routing applied. Core: " + (data.core_status || "ok"));
    return refreshAll();
  }).catch(function(err){ setMsg("Apply routing failed: " + err.message); });
});

document.getElementById("route-port-mode").addEventListener("change", updatePortListsVisibility);

document.getElementById("btn-hwid-save").addEventListener("click", function(){
  var body = JSON.stringify({
    hwid: (document.getElementById("hwid-value").value || "").trim(),
    os_version: (document.getElementById("hwid-os").value || "").trim(),
    device_model: (document.getElementById("hwid-model").value || "").trim(),
    device_os: (document.getElementById("hwid-device-os").value || "").trim(),
    app_version: (document.getElementById("hwid-app-ver").value || "").trim()
  });
  api("POST", "/api/hwid", body).then(function(data){
    showOk("HWID saved.");
    document.getElementById("hwid-status").textContent = "";
  }).catch(function(err){ setMsg("HWID save failed: " + err.message); });
});

document.getElementById("btn-dns-save").addEventListener("click", function(){
  var remote = (document.getElementById("dns-remote").value || "").split(/\r?\n/).map(function(s){return s.trim();}).filter(Boolean);
  var local = (document.getElementById("dns-local").value || "").split(/\r?\n/).map(function(s){return s.trim();}).filter(Boolean);
  var body = JSON.stringify({
    enabled: document.getElementById("dns-enabled").checked,
    remote_servers: remote,
    local_servers: local,
    query_strategy: document.getElementById("dns-strategy").value
  });
  api("POST", "/api/dns", body).then(function(data){
    showOk("DNS settings saved.");
    document.getElementById("dns-status").textContent = "";
  }).catch(function(err){ setMsg("DNS save failed: " + err.message); });
});

document.getElementById("leak-toggle").addEventListener("click", function(){
  toggleCollapsible("leak-toggle", "leak-panel");
});
document.getElementById("btn-dns-leak-test").addEventListener("click", function(){
  var btn = document.getElementById("btn-dns-leak-test");
  var status = document.getElementById("leak-test-status");
  var results = document.getElementById("leak-test-results");
  btn.disabled = true;
  status.textContent = "Running test… (up to 20s)";
  results.style.display = "none";
  api("GET", "/api/dns/leak-test").then(function(d){
    btn.disabled = false;
    status.textContent = "";
    results.style.display = "block";
    function setCell(id, val, okClass){
      var el = document.getElementById(id);
      el.textContent = val;
      el.style.color = okClass === true ? "#4caf50" : okClass === false ? "#f44336" : "";
    }
    var statusMap = {
      "ok": "No leak detected",
      "leak_detected": "LEAK DETECTED",
      "proxy_unreachable": "Proxy unreachable",
                "dns_inbound_down": "Mihomo DNS inbound not listening",
      "rules_missing": "iptables rules missing"
    };
    setCell("leak-status", statusMap[d.status] || d.status, d.status === "ok");
    setCell("leak-dns-redirect", d.dns_redirect_ok ? "OK" : "MISSING", d.dns_redirect_ok);
    setCell("leak-mangle", d.nat_redirect_ok ? "OK" : "MISSING", d.nat_redirect_ok);
    setCell("leak-dns-inbound", d.dns_inbound_listening ? "listening" : "not listening", d.dns_inbound_listening);
    setCell("leak-proxy-ip", d.proxy_exit_ip || "—");
    setCell("leak-proxy-loc", d.proxy_location || "—");
    setCell("leak-dns-proxy", d.dns_via_proxy || "—");
    setCell("leak-dns-direct", d.dns_direct || "—");
    setCell("leak-detected", d.leak_detected ? "YES — DNS is leaking to ISP" : "NO — DNS goes through proxy", !d.leak_detected);
  }).catch(function(err){
    btn.disabled = false;
    status.textContent = "";
    setMsg("DNS leak test failed: " + err.message);
  });
});

document.getElementById("btn-firewall-status").addEventListener("click", function(){
  api("GET", "/api/routing/firewall-status").then(function(data){
    var parts = [
      "firewall=" + (data.firewall_active ? "active" : "inactive"),
      "nat=" + (data.nat_redirect_ok ? "ok" : "missing"),
      "dns=" + (data.dns_redirect_ok ? "ok" : "missing"),
      "tproxy=" + (data.tproxy_available ? (data.tproxy_ok ? "ok" : "missing") : "n/a"),
      "route=" + (data.route_ok ? "ok" : "missing"),
      "ndm_hook=" + (data.ndm_hook_installed ? "installed" : "missing"),
      "redir=" + (data.redir_listening ? "listening" : "not listening"),
      "core=" + (data.core_running ? "running" : "stopped")
    ];
    if(data.policy_mark){ parts.push("mark=" + data.policy_mark); }
    parts.push("quic=" + data.quic_mode);
    document.getElementById("routing-status").textContent = parts.join(", ");
  }).catch(function(err){ setMsg("Firewall status failed: " + err.message); });
});
document.getElementById("btn-firewall-start").addEventListener("click", function(){
  api("POST", "/api/routing/firewall-start").then(function(data){
    showOk("Firewall started. TPROXY: " + (data.tproxy_available ? "available" : "unavailable") + ".");
  }).catch(function(err){ setMsg("Firewall start failed: " + err.message); });
});
document.getElementById("btn-firewall-stop").addEventListener("click", function(){
  api("POST", "/api/routing/firewall-stop").then(function(){ showOk("Firewall stopped."); }).catch(function(err){ setMsg("Firewall stop failed: " + err.message); });
});

document.getElementById("subs-toggle").addEventListener("click", function(){
  toggleCollapsible("subs-toggle", "subs-panel");
});
document.getElementById("fav-toggle").addEventListener("click", function(){
  toggleCollapsible("fav-toggle", "fav-panel");
});
document.getElementById("hwid-toggle").addEventListener("click", function(){
  toggleCollapsible("hwid-toggle", "hwid-panel");
});
document.getElementById("dns-toggle").addEventListener("click", function(){
  toggleCollapsible("dns-toggle", "dns-panel");
});
document.getElementById("routing-toggle").addEventListener("click", function(){
  toggleCollapsible("routing-toggle", "routing-panel");
});

// Load HWID and DNS settings on page load.
api("GET","/api/hwid").then(function(data){
  var h = data.hwid || {};
  document.getElementById("hwid-value").value = h.hwid || "";
  document.getElementById("hwid-os").value = h.os_version || "";
  document.getElementById("hwid-model").value = h.device_model || "";
  document.getElementById("hwid-device-os").value = h.device_os || "";
  document.getElementById("hwid-app-ver").value = h.app_version || "";
}).catch(function(){ /* ignore */ });
api("GET","/api/dns").then(function(data){
  var d = data.dns || {};
  document.getElementById("dns-enabled").checked = !!d.enabled;
  document.getElementById("dns-remote").value = (d.remote_servers || []).join("\n");
  document.getElementById("dns-local").value = (d.local_servers || []).join("\n");
  var strat = document.getElementById("dns-strategy");
  if(strat && d.query_strategy){ strat.value = d.query_strategy; }
}).catch(function(){ /* ignore */ });

// Auto-settings: load, save, and display.
// dirty flag prevents the 5-second status refresh from overwriting
// the user's unsaved changes to the checkboxes and interval field.
var autoSettingsDirty = false;

function loadAutoSettings(){
  api("GET", "/api/auto-settings").then(function(data){
    autoSettingsDirty = false;
    document.getElementById("auto-select-chk").checked = !!data.auto_select;
    document.getElementById("auto-switch-chk").checked = !!data.auto_switch;
    document.getElementById("auto-bench-hours").value = data.auto_bench_interval_hours || 0;
    document.getElementById("auto-failover-count").textContent = data.failover_fail_count || 0;
    if(data.last_auto_bench_unix){
      var ago = Math.round((Date.now()/1000 - data.last_auto_bench_unix) / 3600);
      document.getElementById("auto-last-bench").textContent = "Last auto-bench: " + ago + "h ago";
    }
  }).catch(function(){ /* ignore */ });
}

// Sync auto-settings checkboxes from the /api/status response (which
// includes auto_select, auto_switch, auto_bench_interval_hours) during
// the 5-second refresh, but only if the user hasn't made local changes.
function syncAutoSettingsFromStatus(s){
  if(autoSettingsDirty){ return; }
  document.getElementById("auto-select-chk").checked = !!s.auto_select;
  document.getElementById("auto-switch-chk").checked = !!s.auto_switch;
  document.getElementById("auto-bench-hours").value = s.auto_bench_interval_hours || 0;
}

["auto-select-chk", "auto-switch-chk"].forEach(function(id){
  document.getElementById(id).addEventListener("change", function(){ autoSettingsDirty = true; });
});
document.getElementById("auto-bench-hours").addEventListener("input", function(){ autoSettingsDirty = true; });

document.getElementById("btn-auto-save").addEventListener("click", function(){
  var body = JSON.stringify({
    auto_select: document.getElementById("auto-select-chk").checked,
    auto_switch: document.getElementById("auto-switch-chk").checked,
    auto_bench_interval_hours: Number(document.getElementById("auto-bench-hours").value) || 0,
  });
  api("POST", "/api/auto-settings", body).then(function(){
    autoSettingsDirty = false;
    showOk("Auto settings saved.");
  }).catch(function(err){ setMsg("Save failed: " + err.message); });
});

// Logs: load and display.
function loadLogs(){
  api("GET", "/api/logs").then(function(data){
    document.getElementById("mihomo-log").textContent = data.mihomo || "(empty)";
  }).catch(function(err){ setMsg("Logs load failed: " + err.message); });
}

document.getElementById("btn-logs-refresh").addEventListener("click", loadLogs);

document.getElementById("auto-toggle").addEventListener("click", function(){
  toggleCollapsible("auto-toggle", "auto-panel");
});
document.getElementById("logs-toggle").addEventListener("click", function(){
  toggleCollapsible("logs-toggle", "logs-panel");
});
document.getElementById("sys-toggle").addEventListener("click", function(){
  toggleCollapsible("sys-toggle", "sys-panel");
});

// ── System info rendering ───────────────────────────────────────────

function formatUptime(secs){
  if(!secs || secs <= 0){ return "—"; }
  var d = Math.floor(secs / 86400);
  var h = Math.floor((secs % 86400) / 3600);
  var m = Math.floor((secs % 3600) / 60);
  var s = Math.floor(secs % 60);
  var parts = [];
  if(d > 0){ parts.push(d + "d"); }
  if(h > 0 || d > 0){ parts.push(h + "h"); }
  if(m > 0 || h > 0 || d > 0){ parts.push(m + "m"); }
  parts.push(s + "s");
  return parts.join(" ");
}

function formatKb(kb){
  if(!kb || kb <= 0){ return "0 MB"; }
  if(kb >= 1048576){ return (kb / 1048576).toFixed(1) + " GB"; }
  if(kb >= 1024){ return Math.round(kb / 1024) + " MB"; }
  return kb + " kB";
}

function setBar(id, pct, hotThreshold){
  var bar = document.getElementById(id);
  if(!bar){ return; }
  var clamped = Math.min(100, Math.max(0, pct));
  bar.style.width = clamped + "%";
  if(hotThreshold && pct > hotThreshold){
    bar.className = "bar-fill hot";
  } else {
    bar.className = bar.className.replace(" hot", "");
  }
}

function renderSystem(s){
  if(!s){ return; }
  var cpu = s.cpu || {};
  var mem = s.memory || {};
  var load = s.load || {};

  // CPU model
  var modelEl = document.getElementById("sys-cpu-model");
  if(modelEl){
    var modelText = cpu.model || "—";
    if(cpu.part_name){ modelText += " (" + cpu.part_name + ")"; }
    modelEl.textContent = modelText;
  }

  // Cores
  var coresEl = document.getElementById("sys-cpu-cores");
  if(coresEl){
    var perCore = cpu.usage_per_core || [];
    if(perCore.length > 0){
      var parts = perCore.map(function(v){ return v.toFixed(1) + "%"; });
      coresEl.textContent = cpu.cores + " cores  [" + parts.join(", ") + "]";
    } else {
      coresEl.textContent = (cpu.cores || "—") + " cores";
    }
  }

  // CPU usage
  var usageEl = document.getElementById("sys-cpu-usage");
  if(usageEl){
    usageEl.textContent = (cpu.usage_pct != null ? cpu.usage_pct.toFixed(1) + "%" : "—");
  }
  setBar("sys-cpu-bar", cpu.usage_pct || 0, 90);

  // Temperature
  var tempEl = document.getElementById("sys-cpu-temp");
  if(tempEl){
    tempEl.textContent = (cpu.temp_c != null ? cpu.temp_c.toFixed(1) + "°C" : "n/a");
  }
  // Temperature bar: 0-100°C scale, hot above 75°C.
  if(cpu.temp_c != null){
    setBar("sys-temp-bar", cpu.temp_c, 75);
    var tempBar = document.getElementById("sys-temp-bar");
    if(tempBar){
      tempBar.style.width = Math.min(100, (cpu.temp_c / 100) * 100) + "%";
    }
  }

  // RAM usage
  var memUsageEl = document.getElementById("sys-mem-usage");
  if(memUsageEl){
    memUsageEl.textContent = (mem.usage_pct != null ? mem.usage_pct.toFixed(1) + "%" : "—");
  }
  setBar("sys-mem-bar", mem.usage_pct || 0, 90);

  // RAM total
  var memTotalEl = document.getElementById("sys-mem-total");
  if(memTotalEl){
    var memText = formatKb(mem.total_kb);
    if(mem.available_kb){
      memText += "  (free: " + formatKb(mem.available_kb) + ")";
    }
    if(mem.swap_total_kb && mem.swap_total_kb > 0){
      memText += "  swap: " + formatKb(mem.swap_free_kb) + "/" + formatKb(mem.swap_total_kb);
    }
    memTotalEl.textContent = memText;
  }

  // Load average
  var loadEl = document.getElementById("sys-load");
  if(loadEl){
    loadEl.textContent = load["1"].toFixed(2) + " / " + load["5"].toFixed(2) + " / " + load["15"].toFixed(2);
  }

  // Uptime
  var upEl = document.getElementById("sys-uptime");
  if(upEl){
    upEl.textContent = formatUptime(s.uptime_secs);
  }

  // Kernel
  var kernEl = document.getElementById("sys-kernel");
  if(kernEl){
    kernEl.textContent = s.kernel || "—";
  }

  // Hostname + model + features (subtle line)
  var hostEl = document.getElementById("sys-hostname");
  if(hostEl){ hostEl.textContent = s.hostname ? "Host: " + s.hostname : ""; }
  var modelEl2 = document.getElementById("sys-model");
  if(modelEl2){ modelEl2.textContent = s.model ? "Model: " + s.model : ""; }
  var featEl = document.getElementById("sys-features");
  if(featEl){ featEl.textContent = cpu.features ? "Features: " + cpu.features : ""; }
}

// Load initial data.
loadAutoSettings();

// Auto-refresh status every 5 seconds (lightweight: only /api/status).
// Does not reload profiles or input fields, so user input is preserved.
setInterval(function(){
  api("GET", "/api/status").then(function(s){
    renderStatus(s);
    var el = document.getElementById("auto-failover-count");
    if(el){ el.textContent = s.failover_fail_count || 0; }
    syncAutoSettingsFromStatus(s);
  }).catch(function(){ /* transient, keep last known state */ });
  // System info also refreshes every 5s (CPU usage delta, temp, etc.)
  api("GET", "/api/system").then(function(sys){
    renderSystem(sys);
  }).catch(function(){ /* transient */ });
}, 5000);

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
    fn best_profile_selector_uses_zero_score_success_as_fallback() {
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
                last_score: 90,
                success_count: 0,
                failure_count: 3,
                ..ProfileStats::default()
            },
            ProfileStats {
                profile_raw: state.profiles[1].raw.clone(),
                last_score: 0,
                success_count: 5,
                ..ProfileStats::default()
            },
        ];

        assert_eq!(find_best_profile_by_score(&state, &HashSet::new()), Some(2));
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
                last_score: 90,
                success_count: 1,
                ..ProfileStats::default()
            },
            ProfileStats {
                profile_raw: state.profiles[1].raw.clone(),
                last_score: 10,
                success_count: 1,
                ..ProfileStats::default()
            },
        ];

        let rejected = HashSet::from([1]);
        assert_eq!(find_best_profile_by_score(&state, &rejected), Some(2));
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
                .any(|proxy| proxy["name"] == "profile-1" && proxy["type"] == "vless")
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
        assert!(
            rules
                .iter()
                .any(|r| { r.as_str() == Some("DST-PORT,27000-27050,DIRECT") })
        );
        assert!(
            rules
                .iter()
                .any(|r| { r.as_str() == Some("NETWORK,udp,DIRECT") })
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

        let added = replace_subscription_profiles(&mut state, url, fresh);

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

        let _added = replace_subscription_profiles(&mut state, url, fresh);

        assert_eq!(state.profiles.len(), 2);
        // Active should point to the profile with raw1 (now at index 0).
        assert_eq!(state.active_profile_id, Some(0));
        assert_eq!(state.profiles[0].raw, "raw1");
        assert_eq!(state.profiles[0].name, "Sub1-updated");
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

        let added1 = replace_subscription_profiles(&mut state, url, fresh.clone());
        assert_eq!(added1, 2);
        assert_eq!(state.profiles.len(), 2);

        // Second refresh with the same profiles: old ones removed, new
        // ones added — total should still be 2, not 4.
        let added2 = replace_subscription_profiles(&mut state, url, fresh);
        assert_eq!(added2, 2);
        assert_eq!(state.profiles.len(), 2);
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
}
