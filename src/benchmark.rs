//! HincyRay benchmark runner.
//!
//! Background ping/benchmark job that does NOT touch the active Xray
//! core. The TCP method probes `address:port` directly. The HEAD/GET
//! methods spawn a temporary Xray child per VLESS profile on a random
//! local SOCKS port, run `curl` through it, then kill the child. Child
//! processes are cleaned up even on cancel/error via a `Drop` guard so
//! the router is never left with stray benchmark cores.
//!
//! No async runtime, no extra dependencies: `std::thread`,
//! `std::process::Command`, `std::net::TcpStream`, and the already
//! declared `tempfile` crate. `curl` is invoked as an external binary
//! because Entware ships it; if `curl` is missing the HEAD/GET methods
//! return a clear error.

use std::io::Write;
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::profiles::{Profile, Protocol};
use crate::scoring::quality_score;
use crate::xray_config::build_xray_config;

pub const DEFAULT_PROBE_URL: &str = "https://www.gstatic.com/generate_204";
pub const DEFAULT_DOWNLOAD_URL: &str = "https://proof.ovh.net/files/100Mb.dat";

const PROBE_ATTEMPTS: usize = 3;
const PROBE_TIMEOUT_SECS: u64 = 6;
const DOWNLOAD_MAX_SECS: u64 = 3;
const XRAY_READY_TIMEOUT: Duration = Duration::from_secs(8);
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Benchmark method requested by the API or web UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BenchMethod {
    Tcp,
    Head,
    Get,
}

impl BenchMethod {
    pub fn parse_method(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "tcp" => Some(Self::Tcp),
            "head" => Some(Self::Head),
            "get" => Some(Self::Get),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Head => "head",
            Self::Get => "get",
        }
    }
}

/// One profile's benchmark outcome. Persisted into `HincyrayState::stats`
/// by the daemon thread callback; also surfaced live in the job state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BenchResult {
    pub profile_id: usize,
    pub profile_name: String,
    pub profile_raw: String,
    pub method: String,
    pub latency_ms: u32,
    pub jitter_ms: u32,
    pub download_mbps: f32,
    pub loss_percent: f32,
    pub score: u32,
    pub success: bool,
    pub error: Option<String>,
    pub timestamp: u64,
}

/// Live, in-progress job state shared between the worker thread and the
/// HTTP status endpoint. The worker mutates it under the mutex; the API
/// reads a snapshot.
#[derive(Clone, Debug, Default)]
pub struct BenchJob {
    pub running: bool,
    pub method: Option<BenchMethod>,
    pub total: usize,
    pub completed: usize,
    pub current_profile_id: Option<usize>,
    pub current_profile_name: Option<String>,
    pub last_updated: u64,
    pub cancel_requested: bool,
    pub results: Vec<BenchResult>,
}

pub type SharedJob = Arc<Mutex<BenchJob>>;

/// Spawn the benchmark worker thread. Returns immediately; the caller
/// keeps the `SharedJob` for status reads and the `AtomicBool` to
/// request cancellation. `on_result` is invoked once per finished
/// profile (success or failure) so the daemon can persist stats without
/// the benchmark module depending on `hincyray`.
#[allow(clippy::too_many_arguments)]
pub fn run_bench(
    profiles: Vec<Profile>,
    method: BenchMethod,
    probe_url: String,
    download_url: String,
    xray_path: String,
    job: SharedJob,
    cancel: Arc<AtomicBool>,
    on_result: Box<dyn Fn(BenchResult) + Send + 'static>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        {
            let mut state = job.lock().unwrap_or_else(|poison| poison.into_inner());
            state.running = true;
            state.method = Some(method);
            state.total = profiles.len();
            state.completed = 0;
            state.cancel_requested = false;
            state.results.clear();
            state.last_updated = unix_now();
        }

        for profile in &profiles {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            {
                let mut state = job.lock().unwrap_or_else(|poison| poison.into_inner());
                state.current_profile_id = Some(profile.id);
                state.current_profile_name = Some(profile.name.clone());
                state.last_updated = unix_now();
            }

            let result = benchmark_profile(profile, method, &probe_url, &download_url, &xray_path);

            on_result(result.clone());
            {
                let mut state = job.lock().unwrap_or_else(|poison| poison.into_inner());
                state.results.push(result);
                state.completed += 1;
                state.last_updated = unix_now();
            }
        }

        {
            let mut state = job.lock().unwrap_or_else(|poison| poison.into_inner());
            state.running = false;
            state.current_profile_id = None;
            state.current_profile_name = None;
            state.last_updated = unix_now();
        }
    })
}

fn benchmark_profile(
    profile: &Profile,
    method: BenchMethod,
    probe_url: &str,
    download_url: &str,
    xray_path: &str,
) -> BenchResult {
    let timestamp = unix_now();
    let base = || BenchResult {
        profile_id: profile.id,
        profile_name: profile.name.clone(),
        profile_raw: profile.raw.clone(),
        method: method.as_str().to_owned(),
        latency_ms: 0,
        jitter_ms: 0,
        download_mbps: 0.0,
        loss_percent: 100.0,
        score: 0,
        success: false,
        error: None,
        timestamp,
    };

    let outcome = match method {
        BenchMethod::Tcp => run_tcp(profile),
        BenchMethod::Head | BenchMethod::Get => {
            if !matches!(profile.protocol, Protocol::Vless) {
                Err(format!(
                    "unsupported by xray benchmark: protocol {}",
                    profile.protocol
                ))
            } else {
                run_via_temp_xray(profile, method, probe_url, download_url, xray_path)
            }
        }
    };

    match outcome {
        Ok(metrics) => BenchResult {
            latency_ms: metrics.latency_ms,
            jitter_ms: metrics.jitter_ms,
            download_mbps: metrics.download_mbps,
            loss_percent: metrics.loss_percent,
            score: quality_score(
                metrics.latency_ms,
                metrics.jitter_ms,
                metrics.download_mbps,
                metrics.loss_percent,
            ),
            success: true,
            error: None,
            ..base()
        },
        Err(error) => BenchResult {
            error: Some(error),
            ..base()
        },
    }
}

struct Metrics {
    latency_ms: u32,
    jitter_ms: u32,
    download_mbps: f32,
    loss_percent: f32,
}

fn run_tcp(profile: &Profile) -> Result<Metrics, String> {
    let port = profile.port.unwrap_or(443);
    if profile.address.is_empty() {
        return Err("profile has empty address".to_owned());
    }
    let (latencies, failures) = tcp_probe(&profile.address, port, PROBE_ATTEMPTS);
    if latencies.is_empty() {
        return Err(format!(
            "tcp connect {addr}:{port} failed {failures}/{attempts}",
            addr = profile.address,
            port = port,
            attempts = PROBE_ATTEMPTS,
            failures = failures
        ));
    }
    let latency_ms = average_ms(&latencies);
    let jitter_ms = jitter_ms(&latencies);
    let loss_percent = failures as f32 / PROBE_ATTEMPTS as f32 * 100.0;
    Ok(Metrics {
        latency_ms,
        jitter_ms,
        download_mbps: 0.0,
        loss_percent,
    })
}

pub(crate) fn tcp_probe(host: &str, port: u16, attempts: usize) -> (Vec<Duration>, usize) {
    let mut latencies = Vec::new();
    let mut failures = 0usize;
    let target = (host, port).to_socket_addrs();
    let addrs: Vec<std::net::SocketAddr> = match target {
        Ok(iter) => iter.collect(),
        Err(_) => {
            // DNS / address resolution failed: count all attempts as
            // failures; no latencies.
            return (Vec::new(), attempts);
        }
    };
    if addrs.is_empty() {
        return (Vec::new(), attempts);
    }
    for _ in 0..attempts {
        let started = Instant::now();
        // Try each resolved address; succeed on the first that connects.
        let mut ok = false;
        for addr in &addrs {
            if TcpStream::connect_timeout(addr, TCP_CONNECT_TIMEOUT).is_ok() {
                ok = true;
                break;
            }
        }
        if ok {
            latencies.push(started.elapsed());
        } else {
            failures += 1;
        }
    }
    (latencies, failures)
}

fn run_via_temp_xray(
    profile: &Profile,
    method: BenchMethod,
    probe_url: &str,
    download_url: &str,
    xray_path: &str,
) -> Result<Metrics, String> {
    let port = reserve_local_port()?;
    let config = build_xray_config(profile, "127.0.0.1", port)?;
    let mut config_file = NamedTempFile::new().map_err(|error| format!("temp config: {error}"))?;
    serde_json::to_writer_pretty(&mut config_file, &config).map_err(|e| e.to_string())?;
    config_file.flush().map_err(|e| e.to_string())?;

    let stderr_file = NamedTempFile::new().map_err(|e| format!("temp stderr: {e}"))?;
    let stderr_writer = stderr_file.reopen().map_err(|e| e.to_string())?;

    let child = Command::new(xray_path)
        .arg("run")
        .arg("-format")
        .arg("json")
        .arg("-c")
        .arg(config_file.path())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr_writer))
        .spawn()
        .map_err(|error| format!("xray spawn ({xray_path}): {error}"))?;
    let mut guard = ChildGuard { child: Some(child) };

    wait_until_socks_ready(port, guard.as_mut(), stderr_file.path())?;

    let mut latencies = Vec::new();
    let mut failures = 0usize;
    for _ in 0..PROBE_ATTEMPTS {
        match curl_probe(port, probe_url, method) {
            Ok(d) => latencies.push(d),
            Err(_) => failures += 1,
        }
        thread::sleep(Duration::from_millis(120));
    }

    if latencies.is_empty() {
        return Err(format!(
            "all {attempts} probe requests via SOCKS failed (url {probe_url})",
            attempts = PROBE_ATTEMPTS
        ));
    }

    let download_mbps = if method == BenchMethod::Get && !download_url.trim().is_empty() {
        curl_download(port, download_url).unwrap_or(0.0)
    } else {
        0.0
    };

    let latency_ms = average_ms(&latencies);
    let jitter_ms = jitter_ms(&latencies);
    let loss_percent = failures as f32 / PROBE_ATTEMPTS as f32 * 100.0;

    Ok(Metrics {
        latency_ms,
        jitter_ms,
        download_mbps,
        loss_percent,
    })
}

fn reserve_local_port() -> Result<u16, String> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    drop(listener);
    Ok(port)
}

fn wait_until_socks_ready(port: u16, child: &mut Child, stderr_path: &Path) -> Result<(), String> {
    let started = Instant::now();
    while started.elapsed() < XRAY_READY_TIMEOUT {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            let stderr_tail = read_tail(stderr_path, 500);
            return Err(format!(
                "xray exited early: {status}{tail}",
                tail = if stderr_tail.is_empty() {
                    String::new()
                } else {
                    format!("; {stderr_tail}")
                }
            ));
        }
        if TcpStream::connect(("127.0.0.1", port)).is_err() {
            thread::sleep(Duration::from_millis(100));
            continue;
        }
        // Port is accepting; give xray a brief moment to finish SOCKS
        // handshake wiring before we throw requests at it.
        thread::sleep(Duration::from_millis(80));
        return Ok(());
    }
    Err(format!(
        "xray did not open SOCKS port {port} within timeout"
    ))
}

fn curl_probe(port: u16, url: &str, method: BenchMethod) -> Result<Duration, String> {
    if url.trim().is_empty() {
        return Err("probe url is empty".to_owned());
    }
    let started = Instant::now();
    let mut cmd = Command::new("curl");
    cmd.arg("--socks5-hostname")
        .arg(format!("127.0.0.1:{port}"))
        .arg("-L")
        .arg("--max-time")
        .arg(PROBE_TIMEOUT_SECS.to_string())
        .arg("--silent")
        .arg("--show-error")
        .arg("--output")
        .arg("/dev/null")
        .arg("--write-out")
        .arg("%{http_code}");
    if method == BenchMethod::Head {
        cmd.arg("--head");
    }
    cmd.arg(url);
    let output = cmd.output().map_err(|e| format!("curl spawn: {e}"))?;
    let http_code = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let ok = output.status.success() && http_code.starts_with('2');
    if ok {
        Ok(started.elapsed())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "curl rc={rc}, http={http_code}, {stderr}",
            rc = output
                .status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".to_owned())
        ))
    }
}

fn curl_download(port: u16, url: &str) -> Result<f32, String> {
    let output = Command::new("curl")
        .arg("--socks5-hostname")
        .arg(format!("127.0.0.1:{port}"))
        .arg("-L")
        .arg("--max-time")
        .arg(DOWNLOAD_MAX_SECS.to_string())
        .arg("--range")
        .arg("0-10485759")
        .arg("--silent")
        .arg("--show-error")
        .arg("--output")
        .arg("/dev/null")
        .arg("--write-out")
        .arg("%{http_code} %{size_download} %{time_total}")
        .arg(url)
        .output()
        .map_err(|e| format!("curl spawn: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parts: Vec<&str> = stdout.split_whitespace().collect();
    if parts.len() != 3 {
        return Err(format!("unexpected curl download output: {stdout}"));
    }
    let http_code = parts[0];
    let bytes: f32 = parts[1].parse::<f32>().map_err(|e| e.to_string())?;
    let seconds: f32 = parts[2].parse::<f32>().map_err(|e| e.to_string())?;
    let http_ok = http_code.starts_with('2') || http_code == "000";
    let timed_out_with_data = output.status.code() == Some(28) && bytes > 0.0 && http_ok;
    if (!output.status.success() && !timed_out_with_data) || !http_ok || bytes <= 0.0 {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "curl download rc={rc}, http={http_code}, bytes={bytes}, {stderr}",
            rc = output
                .status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".to_owned())
        ));
    }
    Ok(bytes * 8.0 / seconds.max(0.1) / 1_000_000.0)
}

fn average_ms(values: &[Duration]) -> u32 {
    if values.is_empty() {
        return 0;
    }
    let total = values.iter().map(Duration::as_millis).sum::<u128>();
    (total / values.len() as u128) as u32
}

fn jitter_ms(values: &[Duration]) -> u32 {
    if values.len() < 2 {
        return 0;
    }
    let average = average_ms(values) as i64;
    let total_deviation = values
        .iter()
        .map(|value| (value.as_millis() as i64 - average).unsigned_abs())
        .sum::<u64>();
    (total_deviation / values.len() as u64) as u32
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn read_tail(path: &Path, limit: usize) -> String {
    let Ok(text) = std::fs::read_to_string(path) else {
        return String::new();
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let chars: Vec<char> = trimmed.chars().collect();
    let start = chars.len().saturating_sub(limit);
    chars[start..].iter().collect()
}

/// RAII guard that kills and reaps the temporary Xray child on drop,
/// even when the benchmark returns early or is cancelled.
struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn as_mut(&mut self) -> &mut Child {
        self.child
            .as_mut()
            .expect("ChildGuard holds a child until drop")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bench_method_parses_case_insensitive() {
        assert_eq!(BenchMethod::parse_method("TCP"), Some(BenchMethod::Tcp));
        assert_eq!(BenchMethod::parse_method("Head"), Some(BenchMethod::Head));
        assert_eq!(BenchMethod::parse_method("get"), Some(BenchMethod::Get));
        assert_eq!(BenchMethod::parse_method("quic"), None);
    }

    #[test]
    fn tcp_probe_to_local_unused_port_records_failures() {
        // Port 1 is privileged and not listening on a normal dev box;
        // connect fails fast with ECONNREFUSED. Three attempts, all
        // failures, no latencies.
        let (latencies, failures) = tcp_probe("127.0.0.1", 1, 3);
        assert!(latencies.is_empty(), "no successes expected");
        assert_eq!(failures, 3);
    }

    #[test]
    fn jitter_is_zero_for_single_value() {
        let one = vec![Duration::from_millis(50)];
        assert_eq!(jitter_ms(&one), 0);
    }

    #[test]
    fn jitter_is_mean_absolute_deviation() {
        let values = vec![
            Duration::from_millis(10),
            Duration::from_millis(20),
            Duration::from_millis(30),
        ];
        // mean = 20, deviations = 10, 0, 10 -> mean abs dev = 6 (20/3).
        assert_eq!(jitter_ms(&values), 6);
    }

    #[test]
    fn average_ms_handles_empty() {
        assert_eq!(average_ms(&[]), 0);
    }

    #[test]
    fn benchmark_profile_hysteria2_unsupported_for_head() {
        let profile = Profile {
            id: 0,
            name: "Hy2".to_owned(),
            protocol: Protocol::Hysteria2,
            address: "example.com".to_owned(),
            port: Some(443),
            raw: "hysteria2://secret@example.com:443?sni=example.com#Hy2".to_owned(),
            selected: false,
            block_quic: false,
            group: None,
        };
        let result = benchmark_profile(
            &profile,
            BenchMethod::Head,
            DEFAULT_PROBE_URL,
            DEFAULT_DOWNLOAD_URL,
            "xray",
        );
        assert!(!result.success);
        let err = result.error.expect("error message");
        assert!(err.contains("unsupported by xray benchmark"), "got: {err}");
    }

    #[test]
    fn benchmark_profile_tcp_records_failure_for_unreachable_host() {
        let profile = Profile {
            id: 7,
            name: "dead".to_owned(),
            protocol: Protocol::Vless,
            address: "127.0.0.1".to_owned(),
            port: Some(1),
            raw: "vless://11111111-1111-1111-1111-111111111111@127.0.0.1:1#dead".to_owned(),
            selected: false,
            block_quic: false,
            group: None,
        };
        let result = benchmark_profile(
            &profile,
            BenchMethod::Tcp,
            DEFAULT_PROBE_URL,
            DEFAULT_DOWNLOAD_URL,
            "xray",
        );
        assert!(!result.success);
        assert!(result.error.is_some());
        assert_eq!(result.profile_id, 7);
    }

    #[test]
    fn run_bench_marks_running_and_completes_for_empty_input() {
        let job: SharedJob = Arc::new(Mutex::new(BenchJob::default()));
        let cancel = Arc::new(AtomicBool::new(false));
        let collected: Arc<Mutex<Vec<BenchResult>>> = Arc::new(Mutex::new(Vec::new()));
        let collected_for_closure = Arc::clone(&collected);
        let on_result = Box::new(move |result: BenchResult| {
            collected_for_closure
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(result);
        });

        let handle = run_bench(
            Vec::new(),
            BenchMethod::Tcp,
            DEFAULT_PROBE_URL.to_owned(),
            DEFAULT_DOWNLOAD_URL.to_owned(),
            "xray".to_owned(),
            Arc::clone(&job),
            cancel,
            on_result,
        );
        handle.join().expect("bench thread exits cleanly");

        let state = job.lock().unwrap_or_else(|p| p.into_inner());
        assert!(!state.running);
        assert_eq!(state.total, 0);
        assert_eq!(state.completed, 0);
        assert!(state.results.is_empty());
        assert!(
            collected
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .is_empty()
        );
    }
}
