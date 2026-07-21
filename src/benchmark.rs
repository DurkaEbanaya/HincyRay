//! HincyRay benchmark runner.
//!
//! Background ping/benchmark job that does NOT touch the active Mihomo
//! core. The TCP method probes `address:port` directly. The HEAD/GET
//! methods spawn a temporary Mihomo child per profile on a random
//! local SOCKS port, run `curl` through it, then kill the child. Child
//! processes are cleaned up even on cancel/error via a `Drop` guard so
//! the router is never left with stray benchmark cores.
//!
//! No async runtime, no extra dependencies: `std::thread`,
//! `std::process::Command`, `std::net::TcpStream`, and the already
//! declared `tempfile` crate. `curl` is invoked as an external binary
//! because Entware ships it; if `curl` is missing the HEAD/GET methods
//! return a clear error.

use std::collections::VecDeque;
use std::io::Write;
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::mihomo_config::build_mihomo_bench_config;
use crate::profiles::Profile;
#[cfg(test)]
use crate::profiles::Protocol;
use crate::scoring::quality_score;

pub const DEFAULT_PROBE_URL: &str = "https://www.gstatic.com/generate_204";
pub const DEFAULT_DOWNLOAD_URL: &str = "https://proof.ovh.net/files/100Mb.dat";
pub const DEFAULT_UPLOAD_URL: &str = "https://speed.cloudflare.com/__up";

const PROBE_ATTEMPTS: usize = 3;
const PROBE_TIMEOUT_SECS: u64 = 6;
const DOWNLOAD_MAX_SECS: u64 = 3;
const SUSTAINED_DOWNLOAD_MAX_SECS: u64 = 15;
const XRAY_READY_TIMEOUT: Duration = Duration::from_secs(8);
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const QUICK_TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const QUICK_BENCH_WORKERS: usize = 8;

/// Benchmark method requested by the API or web UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BenchMethod {
    Tcp,
    Head,
    Get,
    Quick,
}

impl BenchMethod {
    pub fn parse_method(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "tcp" => Some(Self::Tcp),
            "head" => Some(Self::Head),
            "get" => Some(Self::Get),
            "quick" => Some(Self::Quick),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Head => "head",
            Self::Get => "get",
            Self::Quick => "quick",
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
    pub download_mbps: Option<f32>,
    pub upload_mbps: Option<f32>,
    pub download_error: Option<String>,
    pub upload_error: Option<String>,
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
    upload_url: String,
    core_path: String,
    test_download: bool,
    test_upload: bool,
    job: SharedJob,
    cancel: Arc<AtomicBool>,
    on_result: Box<dyn Fn(BenchResult) + Send + 'static>,
) -> thread::JoinHandle<()> {
    {
        let mut state = job.lock().unwrap_or_else(|poison| poison.into_inner());
        *state = BenchJob {
            running: true,
            method: Some(method),
            total: profiles.len(),
            last_updated: unix_now(),
            ..BenchJob::default()
        };
    }

    thread::spawn(move || {
        if method == BenchMethod::Quick {
            let queue = Arc::new(Mutex::new(VecDeque::from(profiles)));
            let (sender, receiver) = mpsc::channel();
            let worker_count = QUICK_BENCH_WORKERS.min(
                queue
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .len(),
            );
            let mut workers = Vec::with_capacity(worker_count);
            for _ in 0..worker_count {
                let queue = Arc::clone(&queue);
                let sender = sender.clone();
                let cancel = Arc::clone(&cancel);
                let job = Arc::clone(&job);
                workers.push(thread::spawn(move || {
                    loop {
                        if cancel.load(Ordering::Relaxed) {
                            break;
                        }
                        let profile = queue
                            .lock()
                            .unwrap_or_else(|poison| poison.into_inner())
                            .pop_front();
                        let Some(profile) = profile else { break };
                        {
                            let mut state = job.lock().unwrap_or_else(|poison| poison.into_inner());
                            state.current_profile_id = Some(profile.id);
                            state.current_profile_name = Some(profile.name.clone());
                            state.last_updated = unix_now();
                        }
                        if sender
                            .send(benchmark_profile(
                                &profile,
                                BenchMethod::Quick,
                                "",
                                "",
                                "",
                                "",
                                false,
                                false,
                            ))
                            .is_err()
                        {
                            break;
                        }
                    }
                }));
            }
            drop(sender);
            for result in receiver {
                on_result(result.clone());
                let mut state = job.lock().unwrap_or_else(|poison| poison.into_inner());
                state.results.push(result);
                state.completed += 1;
                state.last_updated = unix_now();
            }
            for worker in workers {
                let _ = worker.join();
            }
        } else {
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

                let result = benchmark_profile(
                    profile,
                    method,
                    &probe_url,
                    &download_url,
                    &upload_url,
                    &core_path,
                    test_download,
                    test_upload,
                );

                on_result(result.clone());
                {
                    let mut state = job.lock().unwrap_or_else(|poison| poison.into_inner());
                    state.results.push(result);
                    state.completed += 1;
                    state.last_updated = unix_now();
                }
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

#[allow(clippy::too_many_arguments)]
fn benchmark_profile(
    profile: &Profile,
    method: BenchMethod,
    probe_url: &str,
    download_url: &str,
    upload_url: &str,
    core_path: &str,
    test_download: bool,
    test_upload: bool,
) -> BenchResult {
    let timestamp = unix_now();
    let base = || BenchResult {
        profile_id: profile.id,
        profile_name: profile.name.clone(),
        profile_raw: profile.raw.clone(),
        method: method.as_str().to_owned(),
        latency_ms: 0,
        jitter_ms: 0,
        download_mbps: None,
        upload_mbps: None,
        download_error: None,
        upload_error: None,
        loss_percent: 100.0,
        score: 0,
        success: false,
        error: None,
        timestamp,
    };

    // Step 1: Latency probe — TCP (direct) or HEAD/GET (via temp xray).
    let latency_outcome = match method {
        BenchMethod::Tcp => run_tcp(profile),
        BenchMethod::Quick => run_quick_tcp(profile),
        BenchMethod::Head | BenchMethod::Get => {
            run_via_temp_mihomo(profile, method, probe_url, core_path)
        }
    };

    // Step 2: Speed metrics are independent of the selected latency method.
    // Always execute every requested speed stage through a temporary Mihomo
    // instance; GET must not silently skip upload or bypass request flags.
    let need_speed = method != BenchMethod::Quick && (test_download || test_upload);

    let speed_metrics = if need_speed {
        run_speed_via_mihomo(
            profile,
            download_url,
            upload_url,
            test_download,
            test_upload,
            core_path,
        )
    } else {
        SpeedMetrics::not_requested()
    };

    // Merge latency + speed results.
    match latency_outcome {
        Ok(metrics) => {
            // If speed test ran separately, merge its results.
            let download_mbps = speed_metrics
                .download
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .copied();
            let upload_mbps = speed_metrics
                .upload
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .copied();
            BenchResult {
                latency_ms: metrics.latency_ms,
                jitter_ms: metrics.jitter_ms,
                download_mbps,
                upload_mbps,
                download_error: speed_metrics.download.and_then(Result::err),
                upload_error: speed_metrics.upload.and_then(Result::err),
                loss_percent: metrics.loss_percent,
                score: quality_score(
                    metrics.latency_ms,
                    metrics.jitter_ms,
                    download_mbps.unwrap_or(0.0),
                    metrics.loss_percent,
                ),
                success: true,
                error: None,
                ..base()
            }
        }
        Err(error) => {
            // Latency failed — but speed might still work (e.g. server
            // blocks direct TCP but works through proxy). If speed test
            // succeeded, report partial success.
            BenchResult {
                download_mbps: speed_metrics
                    .download
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .copied(),
                upload_mbps: speed_metrics
                    .upload
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .copied(),
                download_error: speed_metrics.download.and_then(Result::err),
                upload_error: speed_metrics.upload.and_then(Result::err),
                error: Some(error),
                ..base()
            }
        }
    }
}

/// Verify a failover candidate through its real proxy protocol, not merely by
/// opening the server's TCP port. Failover is accepted only when every HTTPS
/// sample succeeds; a partially working profile would recreate user-visible
/// flapping immediately after the switch.
pub fn verify_profile_for_failover(profile: &Profile, mihomo_path: &str) -> BenchResult {
    let result = benchmark_profile(
        profile,
        BenchMethod::Head,
        DEFAULT_PROBE_URL,
        DEFAULT_DOWNLOAD_URL,
        DEFAULT_UPLOAD_URL,
        mihomo_path,
        false,
        false,
    );
    strict_failover_result(result)
}

fn strict_failover_result(mut result: BenchResult) -> BenchResult {
    if result.success && result.loss_percent > 0.0 {
        result.success = false;
        result.score = 0;
        result.error = Some(format!(
            "failover verification rejected partial availability ({:.1}% loss)",
            result.loss_percent
        ));
    }
    result
}

struct Metrics {
    latency_ms: u32,
    jitter_ms: u32,
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
        loss_percent,
    })
}

fn run_quick_tcp(profile: &Profile) -> Result<Metrics, String> {
    let port = profile.port.unwrap_or(443);
    if profile.address.is_empty() {
        return Err("profile has empty address".to_owned());
    }
    let (latencies, failures) =
        tcp_probe_with_timeout(&profile.address, port, 1, QUICK_TCP_CONNECT_TIMEOUT);
    let Some(latency) = latencies.first() else {
        return Err(format!(
            "quick tcp connect {}:{} failed {failures}/1",
            profile.address, port
        ));
    };
    Ok(Metrics {
        latency_ms: latency.as_millis().min(u128::from(u32::MAX)) as u32,
        jitter_ms: 0,
        loss_percent: 0.0,
    })
}

pub(crate) fn tcp_probe(host: &str, port: u16, attempts: usize) -> (Vec<Duration>, usize) {
    tcp_probe_with_timeout(host, port, attempts, TCP_CONNECT_TIMEOUT)
}

fn tcp_probe_with_timeout(
    host: &str,
    port: u16,
    attempts: usize,
    connect_timeout: Duration,
) -> (Vec<Duration>, usize) {
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
            if TcpStream::connect_timeout(addr, connect_timeout).is_ok() {
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

fn run_via_temp_mihomo(
    profile: &Profile,
    method: BenchMethod,
    probe_url: &str,
    mihomo_path: &str,
) -> Result<Metrics, String> {
    let port = reserve_local_port()?;
    let config = build_mihomo_bench_config(profile, "127.0.0.1", port)?;
    let mut config_file = NamedTempFile::with_suffix(".yaml")
        .map_err(|error| format!("temp Mihomo config: {error}"))?;
    config_file
        .write_all(config.as_bytes())
        .map_err(|e| format!("write Mihomo config: {e}"))?;
    config_file
        .flush()
        .map_err(|e| format!("flush Mihomo config: {e}"))?;

    let process_log = NamedTempFile::new().map_err(|e| format!("temp Mihomo log: {e}"))?;

    let child = spawn_mihomo_with_combined_log(mihomo_path, config_file.path(), &process_log)
        .map_err(|error| format!("Mihomo spawn ({mihomo_path}): {error}"))?;
    let mut guard = ChildGuard { child: Some(child) };

    wait_until_socks_ready(port, guard.as_mut(), process_log.path())?;

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

    let latency_ms = average_ms(&latencies);
    let jitter_ms = jitter_ms(&latencies);
    let loss_percent = failures as f32 / PROBE_ATTEMPTS as f32 * 100.0;

    Ok(Metrics {
        latency_ms,
        jitter_ms,
        loss_percent,
    })
}

/// Spawn a temporary mihomo instance with a single profile to run
/// download and/or upload speed tests through its SOCKS port. Used when
/// the latency method is TCP or HEAD (which don't measure speed) but
/// the user has enabled speed testing.
struct SpeedMetrics {
    download: Option<Result<f32, String>>,
    upload: Option<Result<f32, String>>,
}

impl SpeedMetrics {
    fn not_requested() -> Self {
        Self {
            download: None,
            upload: None,
        }
    }
}

fn run_speed_via_mihomo(
    profile: &Profile,
    download_url: &str,
    upload_url: &str,
    test_download: bool,
    test_upload: bool,
    mihomo_path: &str,
) -> SpeedMetrics {
    let setup = || -> Result<(u16, NamedTempFile, NamedTempFile, ChildGuard), String> {
        let port = reserve_local_port()?;
        let config_yaml = build_mihomo_bench_config(profile, "127.0.0.1", port)?;
        let mut config_file =
            NamedTempFile::with_suffix(".yaml").map_err(|e| format!("temp Mihomo config: {e}"))?;
        config_file
            .write_all(config_yaml.as_bytes())
            .map_err(|e| format!("write Mihomo config: {e}"))?;
        config_file
            .flush()
            .map_err(|e| format!("flush Mihomo config: {e}"))?;

        let process_log = NamedTempFile::new().map_err(|e| format!("temp Mihomo log: {e}"))?;

        let child = spawn_mihomo_with_combined_log(mihomo_path, config_file.path(), &process_log)
            .map_err(|e| format!("spawn Mihomo at {mihomo_path}: {e}"))?;
        let mut guard = ChildGuard { child: Some(child) };

        wait_until_socks_ready(port, guard.as_mut(), process_log.path())?;
        Ok((port, config_file, process_log, guard))
    };

    let (port, _config_file, _stderr_file, _guard) = match setup() {
        Ok(runtime) => runtime,
        Err(error) => {
            return SpeedMetrics {
                download: test_download.then(|| Err(error.clone())),
                upload: test_upload.then_some(Err(error)),
            };
        }
    };

    let download = if test_download {
        Some(if download_url.trim().is_empty() {
            Err("download URL is empty".to_owned())
        } else {
            curl_download(port, download_url)
        })
    } else {
        None
    };

    let upload = if test_upload {
        Some(if upload_url.trim().is_empty() {
            Err("upload URL is empty".to_owned())
        } else {
            curl_upload(port, upload_url)
        })
    } else {
        None
    };

    SpeedMetrics { download, upload }
}

fn reserve_local_port() -> Result<u16, String> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    drop(listener);
    Ok(port)
}

/// Spawn a temporary Mihomo process while preserving both output streams in a
/// single ordered log. Mihomo writes startup diagnostics to stdout on some
/// platforms and stderr on others; dropping either stream turns an actionable
/// configuration/runtime error into an opaque exit status.
fn spawn_mihomo_with_combined_log(
    mihomo_path: &str,
    config_path: &Path,
    process_log: &NamedTempFile,
) -> std::io::Result<Child> {
    let (stdout, stderr) = combined_process_log_files(process_log)?;
    Command::new(mihomo_path)
        .arg("-f")
        .arg(config_path)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
}

fn combined_process_log_files(
    process_log: &NamedTempFile,
) -> std::io::Result<(std::fs::File, std::fs::File)> {
    let stdout = process_log.reopen()?;
    let stderr = stdout.try_clone()?;
    Ok((stdout, stderr))
}

fn wait_until_socks_ready(
    port: u16,
    child: &mut Child,
    process_log_path: &Path,
) -> Result<(), String> {
    let started = Instant::now();
    while started.elapsed() < XRAY_READY_TIMEOUT {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            let process_log_tail = read_tail(process_log_path, 500);
            return Err(format!(
                "benchmark core exited early: {status}{tail}",
                tail = if process_log_tail.is_empty() {
                    String::new()
                } else {
                    format!("; {process_log_tail}")
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
        "benchmark core did not open SOCKS port {port} within timeout"
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
    curl_download_with_timeout(port, url, DOWNLOAD_MAX_SECS)
}

fn curl_download_with_timeout(port: u16, url: &str, max_secs: u64) -> Result<f32, String> {
    let output = Command::new("curl")
        .arg("--socks5-hostname")
        .arg(format!("127.0.0.1:{port}"))
        .arg("-L")
        .arg("--max-time")
        .arg(max_secs.to_string())
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

/// Upload a 5MB chunk of data through the SOCKS proxy and measure
/// upload speed in Mbps. Pipes data through curl's stdin to avoid
/// temp-file filesystem quirks on Entware. Uses POST (Cloudflare __up
/// expects POST).
///
/// HTTP `100 Continue` is accepted as a valid response: it means the
/// server received the upload body. When curl times out (rc=28) after
/// the body was fully sent, we still compute speed from `size_upload`
/// and `time_total` — the upload itself succeeded, only the final
/// `200 OK` response didn't arrive within the deadline.
fn curl_upload(port: u16, url: &str) -> Result<f32, String> {
    let chunk = vec![0xAAu8; 5_000_000];

    let mut child = Command::new("curl")
        .arg("--socks5-hostname")
        .arg(format!("127.0.0.1:{port}"))
        .arg("-L")
        .arg("--max-time")
        .arg("30")
        .arg("-X")
        .arg("POST")
        .arg("--data-binary")
        .arg("@-")
        .arg("-H")
        .arg("Content-Type: application/octet-stream")
        .arg("--silent")
        .arg("--show-error")
        .arg("--output")
        .arg("/dev/null")
        .arg("--write-out")
        .arg("%{http_code} %{size_upload} %{time_total}")
        .arg(url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("curl spawn: {e}"))?;

    // Write the upload data to curl's stdin.
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(&chunk);
        // stdin drops here, closing the pipe → EOF signals end of body.
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("curl wait: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parts: Vec<&str> = stdout.split_whitespace().collect();
    if parts.len() != 3 {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "unexpected curl upload output: {stdout} ({stderr})"
        ));
    }
    let http_code = parts[0];
    let bytes: f32 = parts[1].parse::<f32>().map_err(|e| e.to_string())?;
    let seconds: f32 = parts[2].parse::<f32>().map_err(|e| e.to_string())?;
    // `1xx` = Continue (intermediate, upload accepted), `2xx` = final OK,
    // `000` = no response received (proxy connect may have succeeded but
    // server didn't reply — still count if data was sent).
    let http_ok = http_code.starts_with('1') || http_code.starts_with('2') || http_code == "000";
    let timed_out_with_data = output.status.code() == Some(28) && bytes > 0.0 && http_ok;
    if (!output.status.success() && !timed_out_with_data) || !http_ok || bytes <= 0.0 {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "curl upload rc={rc}, http={http_code}, bytes={bytes}, {stderr}",
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

// =========================================================================
// v0.20: Deep Bench — stability-over-time + unlock-test.
//
// Stability test observes one profile's SOCKS proxy for N minutes,
// sampling latency every 10 seconds via `curl HEAD` to gstatic. This
// gives a realistic drop/loss rate and latency variance over time, not
// just a snapshot. Unlock test probes four commonly-blocked services
// (github, cloudflare, google, telegram) with 2 retries each to avoid
// false negatives from transient failures.
//
// Both tests reuse the temp mihomo instance spawned by the caller —
// they take an already-bound `port` argument.
// =========================================================================

use crate::hincyray::{StabilityMetrics, UnlockStatus, UnlockTestResult};

/// Number of retry attempts for each unlock-test probe. 2 was chosen
/// to absorb transient blips without doubling the test time on
/// genuinely-blocked servers (each retry is up to 8s timeout).
const UNLOCK_RETRIES: u32 = 2;

/// Sustained download URL — Cloudflare's 100 MB speed endpoint. Used
/// for the 30-second sustained throughput test in Phase B.
const SUSTAINED_DOWNLOAD_URL: &str = "https://speed.cloudflare.com/__down?bytes=100000000";

const SUSTAINED_DOWNLOAD_CANDIDATES: &[&str] = &[
    DEFAULT_DOWNLOAD_URL,
    SUSTAINED_DOWNLOAD_URL,
    "http://cachefly.cachefly.net/100mb.test",
];

struct StabilityAggregationInput {
    observation_secs: u32,
    latency_samples: Vec<u32>,
    drop_count: u32,
    total_attempts: u32,
    warmup_ok: bool,
    sustained_download_mbps: f32,
    sustained_download_source: String,
    sustained_download_error: String,
    sustained_upload_mbps: f32,
}

/// Spawn a temp mihomo for `profile`, wait for SOCKS ready, return the
/// bound port and the ChildGuard. Caller is responsible for keeping
/// the guard alive for the duration of the tests. Returns `None` if
/// mihomo cannot be started (config error, port exhaustion, etc.).
fn spawn_bench_mihomo(profile: &Profile) -> Option<(u16, ChildGuard)> {
    let port = reserve_local_port().ok()?;
    let config_yaml = build_mihomo_bench_config(profile, "127.0.0.1", port).ok()?;
    let mut config_file = NamedTempFile::with_suffix(".yaml").ok()?;
    config_file.write_all(config_yaml.as_bytes()).ok()?;
    config_file.flush().ok()?;
    let process_log = NamedTempFile::new().ok()?;
    let child = spawn_mihomo_with_combined_log("mihomo", config_file.path(), &process_log).ok()?;
    let mut guard = ChildGuard { child: Some(child) };
    wait_until_socks_ready(port, guard.as_mut(), process_log.path()).ok()?;
    Some((port, guard))
}

/// v0.20: Run the full Phase B observation on `profile` for `minutes`
/// minutes. Spawns a single temp mihomo, runs the stability latency
/// loop (10-sec samples to gstatic), then runs the unlock-test
/// (4 services × 2 retries) on the same SOCKS port, then drops the
/// temp mihomo. Returns `(stability, unlock)` or `None` if the temp
/// mihomo couldn't be spawned.
///
/// `cancel` is checked at every sample; if set, the loop exits early
/// and partial metrics are returned. The unlock-test always runs
/// (even on early cancel) so we don't lose that data point.
pub fn run_stability_and_unlock(
    profile: &Profile,
    minutes: u32,
    cancel: &AtomicBool,
) -> Option<(StabilityMetrics, UnlockTestResult)> {
    let (port, _guard) = spawn_bench_mihomo(profile)?;
    let observation_secs = minutes.max(1) * 60;
    let sample_period = 10u64;
    let expected_samples = observation_secs / sample_period as u32;
    let mut latency_samples: Vec<u32> = Vec::with_capacity(expected_samples as usize);
    let mut drop_count = 0u32;

    let warmup_ok = warmup_bench_proxy(port, cancel);

    let started = Instant::now();
    loop {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let elapsed = started.elapsed().as_secs();
        if elapsed >= u64::from(observation_secs) {
            break;
        }
        match curl_probe(port, DEFAULT_PROBE_URL, BenchMethod::Head) {
            Ok(dur) => latency_samples.push(dur.as_millis().min(u32::MAX as u128) as u32),
            Err(_) => drop_count += 1,
        }
        // Sleep until next 10s tick, but keep checking cancel frequently.
        let next_tick = started.elapsed().as_secs() / sample_period * sample_period + sample_period;
        while started.elapsed().as_secs() < next_tick
            && started.elapsed().as_secs() < u64::from(observation_secs)
        {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            thread::sleep(Duration::from_millis(200));
        }
    }

    let total_attempts = latency_samples.len() as u32 + drop_count;
    let (sustained_download_mbps, sustained_download_source, sustained_download_error) =
        sustained_download_probe(port);
    // Skip upload for stability — it doubles test time and download
    // is the dominant signal for streaming/browsing quality.
    let sustained_upload_mbps = 0.0;
    let metrics = aggregate_stability(StabilityAggregationInput {
        observation_secs,
        latency_samples,
        drop_count,
        total_attempts,
        warmup_ok,
        sustained_download_mbps,
        sustained_download_source,
        sustained_download_error,
        sustained_upload_mbps,
    });
    let unlock = run_unlock_test(port);
    Some((metrics, unlock))
}

fn warmup_bench_proxy(port: u16, cancel: &AtomicBool) -> bool {
    for attempt in 0..3 {
        if cancel.load(Ordering::Relaxed) {
            return false;
        }
        if curl_probe(port, DEFAULT_PROBE_URL, BenchMethod::Head).is_ok() {
            return true;
        }
        if attempt < 2 {
            thread::sleep(Duration::from_millis(500));
        }
    }
    false
}

fn sustained_download_probe(port: u16) -> (f32, String, String) {
    let mut errors = Vec::new();
    for url in SUSTAINED_DOWNLOAD_CANDIDATES {
        match curl_download_with_timeout(port, url, SUSTAINED_DOWNLOAD_MAX_SECS) {
            Ok(mbps) if mbps > 0.0 => return (mbps, (*url).to_owned(), String::new()),
            Ok(_) => errors.push(format!("{url}: zero bytes/speed")),
            Err(error) => errors.push(format!("{url}: {error}")),
        }
    }
    (0.0, String::new(), errors.join("; "))
}

/// v0.20: Precompute min/avg/p95/stddev from raw latency samples.
fn aggregate_stability(input: StabilityAggregationInput) -> StabilityMetrics {
    let StabilityAggregationInput {
        observation_secs,
        latency_samples: mut samples,
        drop_count,
        total_attempts,
        warmup_ok,
        sustained_download_mbps,
        sustained_download_source,
        sustained_download_error,
        sustained_upload_mbps,
    } = input;
    let total = total_attempts.max(1);
    let loss_percent = drop_count as f32 * 100.0 / total as f32;
    if samples.is_empty() {
        return StabilityMetrics {
            observation_secs,
            latency_samples: samples,
            latency_min: 0,
            latency_avg: 0,
            latency_p95: 0,
            latency_stddev: 0,
            drop_count,
            loss_percent,
            warmup_ok,
            sustained_download_mbps,
            sustained_download_source,
            sustained_download_error,
            sustained_upload_mbps,
        };
    }
    samples.sort_unstable();
    let min = samples[0];
    let max = samples[samples.len() - 1];
    let sum = samples.iter().map(|&x| x as u64).sum::<u64>();
    let avg = (sum / samples.len() as u64).min(u32::MAX as u64) as u32;
    let p95_idx = ((samples.len() as f64) * 0.95).ceil() as usize;
    let p95 = samples
        .get(p95_idx.saturating_sub(1))
        .copied()
        .unwrap_or(max);
    let variance = samples
        .iter()
        .map(|&s| {
            let d = s as f64 - avg as f64;
            d * d
        })
        .sum::<f64>()
        / samples.len() as f64;
    let stddev = variance.sqrt() as u32;
    StabilityMetrics {
        observation_secs,
        latency_samples: samples,
        latency_min: min,
        latency_avg: avg,
        latency_p95: p95,
        latency_stddev: stddev,
        drop_count,
        loss_percent,
        warmup_ok,
        sustained_download_mbps,
        sustained_download_source,
        sustained_download_error,
        sustained_upload_mbps,
    }
}

/// v0.20: Probe a single URL via SOCKS for the unlock-test. Retries
/// up to `UNLOCK_RETRIES` times. Records HTTP status + TTFB. Returns
/// the best (most-reachable) result observed.
fn probe_unlock(port: u16, url: &str) -> UnlockStatus {
    let mut best = UnlockStatus::default();
    for _ in 0..UNLOCK_RETRIES {
        let output = Command::new("curl")
            .arg("--socks5-hostname")
            .arg(format!("127.0.0.1:{port}"))
            .arg("-L")
            .arg("--max-time")
            .arg("8")
            .arg("--silent")
            .arg("--show-error")
            .arg("--output")
            .arg("/dev/null")
            .arg("--write-out")
            .arg("%{http_code} %{time_starttransfer}")
            .arg(url)
            .output();
        let Ok(out) = output else { continue };
        let raw = String::from_utf8_lossy(&out.stdout);
        let parts: Vec<&str> = raw.split_whitespace().collect();
        if parts.len() >= 2
            && let Ok(code) = parts[0].parse::<u16>()
        {
            let ttfb_secs: f64 = parts[1].parse().unwrap_or(0.0);
            let ttfb_ms = (ttfb_secs * 1000.0).round() as u32;
            let reachable = (200..400).contains(&code);
            if reachable || !best.reachable {
                best = UnlockStatus {
                    reachable,
                    http_status: code,
                    ttfb_ms: ttfb_ms.max(best.ttfb_ms),
                };
            }
            if reachable {
                break;
            }
        }
    }
    best
}

/// v0.20: Run the unlock-test against a pre-spawned SOCKS port.
/// Probes github, cloudflare, google, telegram. Each probe does up to
/// `UNLOCK_RETRIES` attempts to avoid false negatives.
pub fn run_unlock_test(port: u16) -> UnlockTestResult {
    UnlockTestResult {
        github: probe_unlock(port, "https://github.com"),
        cloudflare: probe_unlock(port, "https://www.cloudflare.com"),
        google: probe_unlock(port, "https://www.google.com"),
        telegram: probe_unlock(port, "https://web.telegram.org"),
    }
}

/// v0.20: Compute the composite quality score (0-100) from the
/// available inputs. Weights:
///   25% latency (avg ms)        — ≤50ms → 100, ≥500ms → 0, linear
///   15% jitter (stddev)         — ≤5ms → 100, ≥100ms → 0, linear
///   20% stability (drop rate)   — 0% → 100, ≥30% → 0, linear
///   15% speed (sustained Mbps)  — ≥50 → 100, 0 → 0, linear
///   25% unlock (4 services)     — 4/4 → 100, 0/4 → 0
pub fn composite_quality_score(
    latency_avg_ms: u32,
    latency_stddev: u32,
    loss_percent: f32,
    sustained_mbps: f32,
    unlock_count: u32,
) -> u32 {
    let latency_score = if latency_avg_ms == 0 {
        0.0
    } else if latency_avg_ms <= 50 {
        100.0
    } else if latency_avg_ms >= 500 {
        0.0
    } else {
        100.0 - (latency_avg_ms as f64 - 50.0) * 100.0 / 450.0
    };
    let jitter_score = if latency_stddev <= 5 {
        100.0
    } else if latency_stddev >= 100 {
        0.0
    } else {
        100.0 - (latency_stddev as f64 - 5.0) * 100.0 / 95.0
    };
    let stability_score = if loss_percent <= 0.0 {
        100.0
    } else if loss_percent >= 30.0 {
        0.0
    } else {
        100.0 - loss_percent as f64 * 100.0 / 30.0
    };
    let speed_score = if sustained_mbps >= 50.0 {
        100.0
    } else {
        sustained_mbps as f64 * 100.0 / 50.0
    };
    let unlock_score = (unlock_score_pct(unlock_count)) as f64;
    let composite = 0.25 * latency_score
        + 0.15 * jitter_score
        + 0.20 * stability_score
        + 0.15 * speed_score
        + 0.25 * unlock_score;
    composite.round().clamp(0.0, 100.0) as u32
}

/// Unlock-test contribution to composite (0-100). 4/4 → 100.
fn unlock_score_pct(unlock_count: u32) -> u32 {
    (unlock_count.min(4) * 25).min(100)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combined_process_log_preserves_stdout_and_stderr_streams() {
        let process_log = NamedTempFile::new().expect("process log");
        let (mut stdout, mut stderr) =
            combined_process_log_files(&process_log).expect("combined log handles");

        writeln!(stdout, "stdout diagnostic").expect("write stdout");
        writeln!(stderr, "stderr diagnostic").expect("write stderr");
        stdout.flush().expect("flush stdout");
        stderr.flush().expect("flush stderr");

        let output = std::fs::read_to_string(process_log.path()).expect("read process log");
        assert!(output.contains("stdout diagnostic"));
        assert!(output.contains("stderr diagnostic"));
    }

    #[test]
    fn failover_verification_rejects_partial_protocol_availability() {
        let result = BenchResult {
            profile_id: 7,
            profile_name: "flapping".to_owned(),
            profile_raw: "vless://flapping".to_owned(),
            method: "head".to_owned(),
            latency_ms: 200,
            jitter_ms: 100,
            download_mbps: None,
            upload_mbps: None,
            download_error: None,
            upload_error: None,
            loss_percent: 33.333,
            score: 42,
            success: true,
            error: None,
            timestamp: 1,
        };

        let strict = strict_failover_result(result);
        assert!(!strict.success);
        assert_eq!(strict.score, 0);
        assert!(
            strict
                .error
                .as_deref()
                .is_some_and(|error| error.contains("partial availability"))
        );
    }

    #[test]
    fn bench_method_parses_case_insensitive() {
        assert_eq!(BenchMethod::parse_method("TCP"), Some(BenchMethod::Tcp));
        assert_eq!(BenchMethod::parse_method("Head"), Some(BenchMethod::Head));
        assert_eq!(BenchMethod::parse_method("get"), Some(BenchMethod::Get));
        assert_eq!(BenchMethod::parse_method("QUICK"), Some(BenchMethod::Quick));
        assert_eq!(BenchMethod::parse_method("quic"), None);
    }

    #[test]
    fn quick_benchmark_uses_one_tcp_probe_without_speed_stages() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("local listener");
        let port = listener.local_addr().expect("listener address").port();
        let profile = Profile {
            id: 9,
            name: "quick".to_owned(),
            protocol: Protocol::Vless,
            address: "127.0.0.1".to_owned(),
            port: Some(port),
            raw: format!("vless://11111111-1111-1111-1111-111111111111@127.0.0.1:{port}#quick"),
            selected: false,
            block_quic: false,
            group: None,
        };

        let result = benchmark_profile(
            &profile,
            BenchMethod::Quick,
            "",
            "",
            "",
            "/definitely/missing/mihomo",
            true,
            true,
        );

        assert!(result.success);
        assert_eq!(result.method, "quick");
        assert_eq!(result.jitter_ms, 0);
        assert_eq!(result.loss_percent, 0.0);
        assert_eq!(result.download_mbps, None);
        assert_eq!(result.upload_mbps, None);
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
    fn benchmark_profile_hysteria2_head_uses_mihomo_backend() {
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
            DEFAULT_UPLOAD_URL,
            "/definitely/missing/mihomo",
            false,
            false,
        );
        assert!(!result.success);
        let err = result.error.expect("error message");
        assert!(
            err.contains("Mihomo spawn") && !err.contains("не поддерживает"),
            "got: {err}"
        );
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
            DEFAULT_UPLOAD_URL,
            "xray",
            false,
            false,
        );
        assert!(!result.success);
        assert!(result.error.is_some());
        assert_eq!(result.profile_id, 7);
    }

    #[test]
    fn requested_speed_setup_failure_is_explicit_not_zero() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("local listener");
        let port = listener.local_addr().expect("listener address").port();
        let profile = Profile {
            id: 8,
            name: "local".to_owned(),
            protocol: Protocol::Vless,
            address: "127.0.0.1".to_owned(),
            port: Some(port),
            raw: format!("vless://11111111-1111-1111-1111-111111111111@127.0.0.1:{port}#local"),
            selected: false,
            block_quic: false,
            group: None,
        };
        let result = benchmark_profile(
            &profile,
            BenchMethod::Tcp,
            DEFAULT_PROBE_URL,
            DEFAULT_DOWNLOAD_URL,
            DEFAULT_UPLOAD_URL,
            "/definitely/missing/mihomo",
            true,
            true,
        );
        assert!(result.success, "TCP latency should succeed");
        assert_eq!(result.download_mbps, None);
        assert_eq!(result.upload_mbps, None);
        assert!(
            result
                .download_error
                .as_deref()
                .is_some_and(|e| e.contains("spawn Mihomo"))
        );
        assert!(
            result
                .upload_error
                .as_deref()
                .is_some_and(|e| e.contains("spawn Mihomo"))
        );
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
            DEFAULT_UPLOAD_URL.to_owned(),
            "xray".to_owned(),
            false,
            false,
            Arc::clone(&job),
            cancel,
            on_result,
        );
        {
            let state = job.lock().unwrap_or_else(|p| p.into_inner());
            assert_eq!(state.total, 0);
            assert_eq!(state.method, Some(BenchMethod::Tcp));
        }
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
