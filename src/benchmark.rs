//! HincyRay benchmark runner.
//!
//! Background ping/benchmark job that does NOT touch the active Mihomo
//! core. The TCP method probes `address:port` directly. The HEAD/GET
//! methods spawn a temporary Mihomo child per profile on a random
//! local SOCKS port, run `curl` through it, then kill the child. Child
//! processes are cleaned up even on cancel/error via a `Drop` guard so
//! the router is never left with stray benchmark cores.
//!
//! `curl` is invoked for the generic HTTP probes. Quick Test uses a narrow
//! YouTube Innertube flow, an authorized Telegram session, and an ipregion-style
//! Google region lookup for AI Studio availability through each tested profile.

use std::collections::VecDeque;
use std::io::Write;
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::mihomo_config::build_mihomo_bench_config;
use crate::profiles::Profile;
#[cfg(test)]
use crate::profiles::Protocol;
use crate::telegram_probe::{TelegramProbeConfig, probe_media};

pub const DEFAULT_PROBE_URL: &str = "https://www.gstatic.com/generate_204";
pub const DEFAULT_DOWNLOAD_URL: &str = "https://proof.ovh.net/files/100Mb.dat";
pub const DEFAULT_UPLOAD_URL: &str = "https://speed.cloudflare.com/__up";

const PROBE_ATTEMPTS: usize = 3;
const PROBE_TIMEOUT_SECS: u64 = 6;
const DOWNLOAD_MAX_SECS: u64 = 3;
const SUSTAINED_DOWNLOAD_MAX_SECS: u64 = 15;
const XRAY_READY_TIMEOUT: Duration = Duration::from_secs(8);
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const QUICK_RESOURCE_CONTRACT_VERSION: u8 = 6;
const YOUTUBE_VIDEO_ID: &str = "aqz-KE-bpKQ";
const YOUTUBE_WATCH_URL: &str = "https://www.youtube.com/watch?v=aqz-KE-bpKQ&hl=en";
const YOUTUBE_PLAYER_URL: &str = "https://www.youtube.com/youtubei/v1/player?prettyPrint=false";
const YOUTUBE_WEB_USER_AGENT: &str =
    "Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 Chrome/131 Safari/537.36";
const YOUTUBE_VR_USER_AGENT: &str = "com.google.android.apps.youtube.vr.oculus/1.65.10 (Linux; U; Android 12L; eureka-user Build/SQ3A.220605.009.A1) gzip";
const YOUTUBE_SIGNATURE_TIMESTAMP: u64 = 20653;
const YOUTUBE_PAGE_MAX_BYTES: u64 = 3 * 1024 * 1024;
const YOUTUBE_PLAYER_MAX_BYTES: u64 = 2 * 1024 * 1024;
const YOUTUBE_SEGMENT_BYTES: u64 = 512 * 1024;
const YOUTUBE_CONNECT_TIMEOUT_SECS: u64 = 10;
const YOUTUBE_ATTEMPTS: u32 = 2;
const AI_STUDIO_URL: &str = "https://aistudio.google.com/prompts/new_chat";
const AI_STUDIO_UNAVAILABLE_URL: &str = "https://ai.google.dev/gemini-api/docs/available-regions";
const AI_STUDIO_SIGN_IN_URL: &str = "https://accounts.google.com/";
const AI_STUDIO_PAGE_MAX_BYTES: u64 = 2 * 1024 * 1024;
const IPREGION_GOOGLE_URL: &str =
    "https://accounts.google.com/v3/signin/identifier?flowName=GlifSetupAndroid";
const IPREGION_USER_AGENT: &str =
    "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0";
const IPREGION_COUNTRY_URL: &str = "https://www.apicountries.com/alpha/";
const IPREGION_GEMINI_REGIONS_URL: &str =
    "https://ai.google.dev/gemini-api/docs/available-regions.md.txt";
const IPREGION_GOOGLE_MAX_BYTES: u64 = 2 * 1024 * 1024;
const IPREGION_RESPONSE_MAX_BYTES: u64 = 512 * 1024;

#[derive(Clone, Debug)]
pub struct QuickProbeConfig {
    pub telegram_session_path: String,
    pub telegram: Option<TelegramProbeConfig>,
}

/// Benchmark method requested by the API or web UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BenchMethod {
    Tcp,
    Head,
    Get,
    Quick,
    Full,
}

impl BenchMethod {
    pub fn parse_method(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "tcp" => Some(Self::Tcp),
            "head" => Some(Self::Head),
            "get" => Some(Self::Get),
            "quick" => Some(Self::Quick),
            "full" => Some(Self::Full),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Head => "head",
            Self::Get => "get",
            Self::Quick => "quick",
            Self::Full => "full",
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
    pub success: bool,
    pub error: Option<String>,
    #[serde(default)]
    pub resource_tests: Vec<ResourceTestResult>,
    pub timestamp: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceTestResult {
    #[serde(default)]
    pub contract_version: u8,
    pub id: String,
    pub name: String,
    pub attempts: u32,
    pub successes: u32,
    pub reachable: bool,
    pub stable: bool,
    pub avg_ttfb_ms: u32,
    pub max_ttfb_ms: u32,
    pub avg_download_kbps: f32,
    pub error: Option<String>,
}

struct QuickResourceAttempt {
    ttfb_ms: u32,
    total_ms: u32,
    bytes: u64,
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
    pub active_profiles: Vec<ActiveBenchProfile>,
    pub last_updated: u64,
    pub cancel_requested: bool,
    pub results: Vec<BenchResult>,
    pub(crate) worker_count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct ActiveBenchProfile {
    pub id: usize,
    pub name: String,
}

pub type SharedJob = Arc<Mutex<BenchJob>>;

pub fn new_bench_job(method: BenchMethod, total: usize, concurrency: usize) -> SharedJob {
    Arc::new(Mutex::new(BenchJob {
        running: true,
        method: Some(method),
        total,
        last_updated: unix_now(),
        worker_count: benchmark_worker_count(concurrency, total),
        ..BenchJob::default()
    }))
}

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
    quick_probe: Option<QuickProbeConfig>,
    test_download: bool,
    test_upload: bool,
    job: SharedJob,
    cancel: Arc<AtomicBool>,
    on_result: Box<dyn Fn(BenchResult) + Send + Sync + 'static>,
) -> Result<thread::JoinHandle<()>, String> {
    thread::Builder::new()
        .name("hincyray-benchmark".to_owned())
        .spawn(move || {
            let queue = Arc::new(Mutex::new(VecDeque::from(profiles)));
            let on_result: Arc<dyn Fn(BenchResult) + Send + Sync> = Arc::from(on_result);
            let worker_count = job
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .worker_count;

            thread::scope(|scope| {
                for _ in 0..worker_count {
                    let queue = Arc::clone(&queue);
                    let job = Arc::clone(&job);
                    let cancel = Arc::clone(&cancel);
                    let on_result = Arc::clone(&on_result);
                    let quick_probe = quick_probe.clone();
                    let probe_url = &probe_url;
                    let download_url = &download_url;
                    let upload_url = &upload_url;
                    let core_path = &core_path;
                    scope.spawn(move || {
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
                                let mut state =
                                    job.lock().unwrap_or_else(|poison| poison.into_inner());
                                state.current_profile_id = Some(profile.id);
                                state.current_profile_name = Some(profile.name.clone());
                                if state.active_profiles.len() < 6 {
                                    state.active_profiles.push(ActiveBenchProfile {
                                        id: profile.id,
                                        name: profile.name.clone(),
                                    });
                                }
                                state.last_updated = unix_now();
                            }

                            let result = benchmark_profile(
                                &profile,
                                method,
                                probe_url,
                                download_url,
                                upload_url,
                                core_path,
                                quick_probe.as_ref(),
                                test_download,
                                test_upload,
                                &cancel,
                            );

                            if cancel.load(Ordering::Relaxed) {
                                let mut state =
                                    job.lock().unwrap_or_else(|poison| poison.into_inner());
                                state
                                    .active_profiles
                                    .retain(|active| active.id != profile.id);
                                continue;
                            }

                            on_result(result.clone());
                            let mut state = job.lock().unwrap_or_else(|poison| poison.into_inner());
                            state
                                .active_profiles
                                .retain(|active| active.id != profile.id);
                            if let Some((id, name)) = state
                                .active_profiles
                                .last()
                                .map(|active| (active.id, active.name.clone()))
                            {
                                state.current_profile_id = Some(id);
                                state.current_profile_name = Some(name);
                            } else {
                                state.current_profile_id = None;
                                state.current_profile_name = None;
                            }
                            state.results.push(result);
                            state.completed += 1;
                            state.last_updated = unix_now();
                        }
                    });
                }
            });

            {
                let mut state = job.lock().unwrap_or_else(|poison| poison.into_inner());
                state.running = false;
                state.current_profile_id = None;
                state.current_profile_name = None;
                state.active_profiles.clear();
                state.last_updated = unix_now();
            }
        })
        .map_err(|error| format!("spawn benchmark worker: {error}"))
}

fn benchmark_worker_count(concurrency: usize, profile_count: usize) -> usize {
    concurrency.clamp(1, 6).min(profile_count.max(1))
}

#[allow(clippy::too_many_arguments)]
fn benchmark_profile(
    profile: &Profile,
    method: BenchMethod,
    probe_url: &str,
    download_url: &str,
    upload_url: &str,
    core_path: &str,
    quick_probe: Option<&QuickProbeConfig>,
    test_download: bool,
    test_upload: bool,
    cancel: &AtomicBool,
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
        success: false,
        error: None,
        resource_tests: Vec::new(),
        timestamp,
    };

    // Step 1: Latency probe — TCP (direct) or HEAD/GET (via temp xray).
    let mut resource_tests = Vec::new();
    let latency_outcome = match method {
        BenchMethod::Tcp => run_tcp(profile),
        BenchMethod::Quick | BenchMethod::Full => {
            run_service_resources(profile, method, probe_url, core_path, quick_probe, cancel).map(
                |(metrics, tests)| {
                    resource_tests = tests;
                    metrics
                },
            )
        }
        BenchMethod::Head | BenchMethod::Get => {
            run_via_temp_mihomo(profile, method, probe_url, core_path)
        }
    };

    // Step 2: Speed metrics are independent of the selected latency method.
    // Always execute every requested speed stage through a temporary Mihomo
    // instance; GET must not silently skip upload or bypass request flags.
    let need_speed =
        !matches!(method, BenchMethod::Quick | BenchMethod::Full) && (test_download || test_upload);

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
            let resource_error = service_resource_error(&resource_tests);
            let resources_passed = resource_error.is_empty();
            BenchResult {
                latency_ms: metrics.latency_ms,
                jitter_ms: metrics.jitter_ms,
                download_mbps,
                upload_mbps,
                download_error: speed_metrics.download.and_then(Result::err),
                upload_error: speed_metrics.upload.and_then(Result::err),
                loss_percent: metrics.loss_percent,
                success: resources_passed,
                error: (!resources_passed)
                    .then(|| format!("resource checks failed: {resource_error}")),
                resource_tests,
                ..base()
            }
        }
        Err(error) => {
            let resource_tests = if matches!(method, BenchMethod::Quick | BenchMethod::Full) {
                unavailable_service_resource_results(&error)
            } else {
                Vec::new()
            };
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
                resource_tests,
                ..base()
            }
        }
    }
}

fn unavailable_service_resource_results(error: &str) -> Vec<ResourceTestResult> {
    [
        ("ping_icmp", "ICMP ping", 1),
        ("ping_tcp", "TCP ping", 1),
        ("ping_proxy", "Proxy HTTPS ping", 1),
        ("youtube", "YouTube", 1),
        ("telegram", "Telegram", 1),
        ("ai", "AI Studio", 1),
    ]
    .into_iter()
    .map(|(id, name, attempts)| ResourceTestResult {
        contract_version: QUICK_RESOURCE_CONTRACT_VERSION,
        id: id.to_owned(),
        name: name.to_owned(),
        attempts,
        successes: 0,
        reachable: false,
        stable: false,
        avg_ttfb_ms: 0,
        max_ttfb_ms: 0,
        avg_download_kbps: 0.0,
        error: Some(error.to_owned()),
    })
    .collect()
}

/// Verify a failover candidate through its real proxy protocol, not merely by
/// opening the server's TCP port. Failover is accepted only when every HTTPS
/// sample succeeds; a partially working profile would recreate user-visible
/// flapping immediately after the switch.
pub fn verify_profile_for_failover(profile: &Profile, mihomo_path: &str) -> BenchResult {
    let cancel = AtomicBool::new(false);
    let result = benchmark_profile(
        profile,
        BenchMethod::Head,
        DEFAULT_PROBE_URL,
        DEFAULT_DOWNLOAD_URL,
        DEFAULT_UPLOAD_URL,
        mihomo_path,
        None,
        false,
        false,
        &cancel,
    );
    strict_failover_result(result)
}

fn strict_failover_result(mut result: BenchResult) -> BenchResult {
    if result.success && result.loss_percent > 0.0 {
        result.success = false;
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

fn run_service_resources(
    profile: &Profile,
    method: BenchMethod,
    probe_url: &str,
    mihomo_path: &str,
    quick_probe: Option<&QuickProbeConfig>,
    cancel: &AtomicBool,
) -> Result<(Metrics, Vec<ResourceTestResult>), String> {
    ensure_not_cancelled(cancel)?;
    let mut tests = vec![
        run_icmp_ping_probe(profile, cancel)?,
        run_tcp_ping_probe(profile, cancel)?,
    ];
    let runtime = spawn_bench_mihomo_with_path(profile, mihomo_path, Some(cancel));
    match runtime.as_ref() {
        Ok((port, _guard)) => tests.push(run_proxy_ping_probe(*port, probe_url, cancel)?),
        Err(error) => tests.push(failed_resource_result(
            "ping_proxy",
            "Proxy HTTPS ping",
            error,
        )),
    };
    if let Ok((port, _guard)) = runtime.as_ref() {
        let youtube = run_youtube_playback_probe(*port, cancel)?;
        let youtube_passed = youtube.stable;
        tests.push(youtube);
        if method == BenchMethod::Quick && !youtube_passed {
            tests.extend(skipped_service_results_from(
                "telegram",
                "skipped after YouTube failed",
            ));
        } else {
            let telegram = run_telegram_media_probe(*port, quick_probe, cancel)?;
            let telegram_passed = telegram.stable;
            tests.push(telegram);
            if method == BenchMethod::Quick && !telegram_passed {
                tests.extend(skipped_service_results_from(
                    "ai",
                    "skipped after Telegram failed",
                ));
            } else {
                tests.push(run_ai_studio_probe(*port, cancel)?);
            }
        }
    } else {
        let error = runtime.as_ref().err().expect("failed Mihomo runtime");
        if method == BenchMethod::Quick {
            tests.push(failed_resource_result("youtube", "YouTube", error));
            tests.extend(skipped_service_results_from(
                "telegram",
                "skipped after YouTube proxy setup failed",
            ));
        } else {
            tests.extend(unavailable_proxy_service_results(error));
        }
    }

    Ok((ping_metrics(&tests), tests))
}

fn ping_metrics(tests: &[ResourceTestResult]) -> Metrics {
    let samples = tests
        .iter()
        .filter(|test| test.id.starts_with("ping_"))
        .map(|test| test.avg_ttfb_ms)
        .filter(|sample| *sample > 0)
        .map(|sample| Duration::from_millis(u64::from(sample)))
        .collect::<Vec<_>>();
    let attempts = tests
        .iter()
        .filter(|test| test.id.starts_with("ping_"))
        .map(|test| test.attempts)
        .sum::<u32>();
    let failures = tests
        .iter()
        .filter(|test| test.id.starts_with("ping_"))
        .map(|test| test.attempts.saturating_sub(test.successes))
        .sum::<u32>();
    Metrics {
        latency_ms: average_ms(&samples),
        jitter_ms: jitter_ms(&samples),
        loss_percent: if attempts == 0 {
            100.0
        } else {
            failures as f32 * 100.0 / attempts as f32
        },
    }
}

fn run_icmp_ping_probe(
    profile: &Profile,
    cancel: &AtomicBool,
) -> Result<ResourceTestResult, String> {
    if profile.address.trim().is_empty() {
        return Ok(failed_resource_result(
            "ping_icmp",
            "ICMP ping",
            "profile has empty address",
        ));
    }
    let started = Instant::now();
    let mut command = Command::new("ping");
    command.args(["-c", "1", "-W", "2", profile.address.as_str()]);
    let output = run_cancellable_command(&mut command, cancel);
    Ok(match output {
        Ok(output) if output.status.success() => {
            successful_resource_result("ping_icmp", "ICMP ping", started.elapsed())
        }
        Ok(output) => failed_resource_result(
            "ping_icmp",
            "ICMP ping",
            &format!("ping failed: {}", bounded_process_error(&output.stderr)),
        ),
        Err(error) => {
            failed_resource_result("ping_icmp", "ICMP ping", &format!("ping spawn: {error}"))
        }
    })
}

fn run_tcp_ping_probe(
    profile: &Profile,
    cancel: &AtomicBool,
) -> Result<ResourceTestResult, String> {
    ensure_not_cancelled(cancel)?;
    let port = profile.port.unwrap_or(443);
    let (latencies, failures) = tcp_probe(&profile.address, port, 1);
    ensure_not_cancelled(cancel)?;
    Ok(match latencies.first() {
        Some(latency) => successful_resource_result("ping_tcp", "TCP ping", *latency),
        None => failed_resource_result(
            "ping_tcp",
            "TCP ping",
            &format!("tcp connect {}:{port} failed {failures}/1", profile.address),
        ),
    })
}

fn run_proxy_ping_probe(
    port: u16,
    probe_url: &str,
    cancel: &AtomicBool,
) -> Result<ResourceTestResult, String> {
    Ok(
        match curl_probe(port, probe_url, BenchMethod::Head, Some(cancel)) {
            Ok(latency) => successful_resource_result("ping_proxy", "Proxy HTTPS ping", latency),
            Err(error) => failed_resource_result("ping_proxy", "Proxy HTTPS ping", &error),
        },
    )
}

fn successful_resource_result(id: &str, name: &str, latency: Duration) -> ResourceTestResult {
    let latency_ms = latency.as_millis().clamp(1, u128::from(u32::MAX)) as u32;
    ResourceTestResult {
        contract_version: QUICK_RESOURCE_CONTRACT_VERSION,
        id: id.to_owned(),
        name: name.to_owned(),
        attempts: 1,
        successes: 1,
        reachable: true,
        stable: true,
        avg_ttfb_ms: latency_ms,
        max_ttfb_ms: latency_ms,
        avg_download_kbps: 0.0,
        error: None,
    }
}

fn failed_resource_result(id: &str, name: &str, error: &str) -> ResourceTestResult {
    ResourceTestResult {
        contract_version: QUICK_RESOURCE_CONTRACT_VERSION,
        id: id.to_owned(),
        name: name.to_owned(),
        attempts: 1,
        successes: 0,
        reachable: false,
        stable: false,
        avg_ttfb_ms: 0,
        max_ttfb_ms: 0,
        avg_download_kbps: 0.0,
        error: Some(error.to_owned()),
    }
}

fn skipped_resource_result(id: &str, name: &str, error: &str) -> ResourceTestResult {
    ResourceTestResult {
        attempts: 0,
        ..failed_resource_result(id, name, error)
    }
}

fn skipped_service_results(error: &str) -> Vec<ResourceTestResult> {
    [
        ("youtube", "YouTube"),
        ("telegram", "Telegram"),
        ("ai", "AI Studio"),
    ]
    .into_iter()
    .map(|(id, name)| skipped_resource_result(id, name, error))
    .collect()
}

fn skipped_service_results_from(id: &str, error: &str) -> Vec<ResourceTestResult> {
    let start = match id {
        "telegram" => 1,
        "ai" => 2,
        _ => 0,
    };
    skipped_service_results(error)
        .into_iter()
        .skip(start)
        .collect()
}

fn unavailable_proxy_service_results(error: &str) -> Vec<ResourceTestResult> {
    [
        ("youtube", "YouTube"),
        ("telegram", "Telegram"),
        ("ai", "AI Studio"),
    ]
    .into_iter()
    .map(|(id, name)| failed_resource_result(id, name, error))
    .collect()
}

fn service_resource_error(tests: &[ResourceTestResult]) -> String {
    if tests.is_empty() {
        return String::new();
    }
    let ping_passed = tests
        .iter()
        .filter(|test| test.id.starts_with("ping_"))
        .any(|test| test.reachable);
    let mut failures = Vec::new();
    if !ping_passed {
        let errors = tests
            .iter()
            .filter(|test| test.id.starts_with("ping_"))
            .filter_map(|test| test.error.as_deref())
            .collect::<Vec<_>>()
            .join("; ");
        failures.push(format!("Ping failed: {errors}"));
    }
    failures.extend(
        tests
            .iter()
            .filter(|test| !test.id.starts_with("ping_") && !test.stable)
            .map(|test| {
                format!(
                    "{} {}/{}{}",
                    test.name,
                    test.successes,
                    test.attempts,
                    test.error
                        .as_deref()
                        .map_or_else(String::new, |error| format!(": {error}"))
                )
            }),
    );
    failures.join(", ")
}

fn run_youtube_playback_probe(
    port: u16,
    cancel: &AtomicBool,
) -> Result<ResourceTestResult, String> {
    // Concurrent anonymous Innertube bootstraps from one router IP trigger
    // throttling and TLS resets. Keep the user-selected profile concurrency,
    // but serialize this narrow external-service boundary.
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = lock_cancellable(LOCK.get_or_init(|| Mutex::new(())), cancel)?;
    let mut successes = Vec::new();
    let mut errors = Vec::new();
    for attempt in 0..YOUTUBE_ATTEMPTS {
        match youtube_playback_attempt(port, cancel) {
            Ok(success) => {
                successes.push(success);
                break;
            }
            Err(error) => {
                let retry = attempt + 1 < YOUTUBE_ATTEMPTS && youtube_error_is_transient(&error);
                errors.push(error);
                if !retry {
                    break;
                }
            }
        }
    }
    Ok(aggregate_quick_resource_probe(
        "youtube",
        "YouTube",
        successes.len() as u32 + errors.len() as u32,
        &successes,
        &errors,
        true,
    ))
}

pub(crate) fn probe_youtube_via_socks(port: u16) -> ResourceTestResult {
    let cancel = AtomicBool::new(false);
    run_youtube_playback_probe(port, &cancel)
        .unwrap_or_else(|error| failed_resource_result("youtube", "YouTube", &error))
}

fn youtube_error_is_transient(error: &str) -> bool {
    let transient_curl = [5, 6, 7, 28, 35, 52, 55, 56].iter().any(|code| {
        error.contains(&format!("rc={code}:")) || error.contains(&format!("rc={code},"))
    });
    let transient_http = error
        .split("http=")
        .skip(1)
        .filter_map(|status| status.split(|ch: char| !ch.is_ascii_digit()).next())
        .filter_map(|status| status.parse::<u16>().ok())
        .any(|status| matches!(status, 408 | 425 | 429) || status >= 500);
    transient_curl
        || transient_http
        || error.contains("returned no visitor data")
        || error.contains("parse YouTube player response")
}

fn run_telegram_media_probe(
    port: u16,
    quick_probe: Option<&QuickProbeConfig>,
    cancel: &AtomicBool,
) -> Result<ResourceTestResult, String> {
    ensure_not_cancelled(cancel)?;
    let mut successes = Vec::new();
    let mut errors = Vec::new();
    let result = quick_probe
        .ok_or_else(|| "Telegram probe is not configured".to_owned())
        .and_then(|quick_probe| {
            quick_probe
                .telegram
                .as_ref()
                .ok_or_else(|| "Telegram probe is not configured".to_owned())
                .and_then(|config| {
                    probe_media(
                        Path::new(&quick_probe.telegram_session_path),
                        config,
                        port,
                        cancel,
                    )
                    .map(|result| QuickResourceAttempt {
                        ttfb_ms: result.elapsed_ms,
                        total_ms: result.elapsed_ms.max(1),
                        bytes: result.bytes,
                    })
                })
        });
    match result {
        Ok(attempt) => successes.push(attempt),
        Err(error) => errors.push(error),
    }
    ensure_not_cancelled(cancel)?;
    Ok(aggregate_quick_resource_probe(
        "telegram", "Telegram", 1, &successes, &errors, false,
    ))
}

fn run_ai_studio_probe(port: u16, cancel: &AtomicBool) -> Result<ResourceTestResult, String> {
    let (successes, errors) = match ipregion_ai_studio_attempt(port, cancel) {
        Ok(attempt) => (vec![attempt], Vec::new()),
        Err(error) => (Vec::new(), vec![error]),
    };
    ensure_not_cancelled(cancel)?;
    Ok(aggregate_quick_resource_probe(
        "ai",
        "AI Studio",
        1,
        &successes,
        &errors,
        false,
    ))
}

fn ipregion_ai_studio_attempt(
    port: u16,
    cancel: &AtomicBool,
) -> Result<QuickResourceAttempt, String> {
    // Based on vernette/ipregion's Google + Gemini Supported lookups.
    let (google_page, google_metrics) = curl_bounded_text_via_socks(
        port,
        IPREGION_GOOGLE_URL,
        IPREGION_GOOGLE_MAX_BYTES,
        "ipregion Google",
        cancel,
    )?;
    let country_code = google_region_code(&google_page)
        .ok_or_else(|| "ipregion Google response has no region".to_owned())?;
    let (country_json, country_metrics) = curl_bounded_text_via_socks(
        port,
        &format!("{IPREGION_COUNTRY_URL}{country_code}"),
        IPREGION_RESPONSE_MAX_BYTES,
        "ipregion country",
        cancel,
    )?;
    let country_name = serde_json::from_str::<serde_json::Value>(&country_json)
        .map_err(|error| format!("parse ipregion country response: {error}"))?
        .get("name")
        .and_then(serde_json::Value::as_str)
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(|| "ipregion country response has no name".to_owned())?
        .trim()
        .to_owned();
    let (regions, regions_metrics) = curl_bounded_text_via_socks(
        port,
        IPREGION_GEMINI_REGIONS_URL,
        IPREGION_RESPONSE_MAX_BYTES,
        "ipregion Gemini regions",
        cancel,
    )?;
    if !gemini_region_supported(&regions, &country_code, &country_name) {
        return Err(format!(
            "AI Studio is unavailable in Google region {country_code} ({country_name})"
        ));
    }
    Ok(QuickResourceAttempt {
        ttfb_ms: seconds_to_millis(google_metrics.ttfb_secs, 0),
        total_ms: [&google_metrics, &country_metrics, &regions_metrics]
            .iter()
            .map(|metrics| seconds_to_millis(metrics.total_secs, 1))
            .sum(),
        bytes: google_metrics.bytes + country_metrics.bytes + regions_metrics.bytes,
    })
}

fn curl_bounded_text_via_socks(
    port: u16,
    url: &str,
    max_bytes: u64,
    label: &str,
    cancel: &AtomicBool,
) -> Result<(String, CurlMetrics), String> {
    let response = NamedTempFile::new().map_err(|error| format!("{label} response: {error}"))?;
    let mut command = Command::new("curl");
    command
        .arg("--socks5-hostname")
        .arg(format!("127.0.0.1:{port}"))
        .arg("-L")
        .arg("--connect-timeout")
        .arg("5")
        .arg("--max-time")
        .arg("20")
        .arg("--max-filesize")
        .arg(max_bytes.to_string())
        .arg("--silent")
        .arg("--show-error")
        .arg("--user-agent")
        .arg(IPREGION_USER_AGENT)
        .arg("--output")
        .arg(response.path())
        .arg("--write-out")
        .arg("%{http_code} %{size_download} %{time_starttransfer} %{time_total}")
        .arg(url);
    let output = run_cancellable_command(&mut command, cancel).map_err(|error| {
        if error == "benchmark cancelled" {
            error
        } else {
            format!("{label} curl: {error}")
        }
    })?;
    let metrics = parse_curl_metrics(&output.stdout)?;
    if !output.status.success() || !(200..300).contains(&metrics.http_status) {
        return Err(format!(
            "{label} rc={}, http={}: {}",
            output
                .status
                .code()
                .map_or_else(|| "?".to_owned(), |code| code.to_string()),
            metrics.http_status,
            bounded_process_error(&output.stderr)
        ));
    }
    let text = std::fs::read_to_string(response.path())
        .map_err(|error| format!("read {label} response: {error}"))?;
    Ok((text, metrics))
}

fn google_region_code(page: &str) -> Option<String> {
    let marker = "name=\"region\" value=\"";
    let value = page.get(page.find(marker)? + marker.len()..)?;
    let code = value.get(..value.find('"')?)?;
    (code.len() == 2 && code.bytes().all(|byte| byte.is_ascii_alphabetic()))
        .then(|| code.to_ascii_uppercase())
}

fn gemini_region_supported(regions: &str, country_code: &str, country_name: &str) -> bool {
    let documented_name = match country_code {
        "BS" => "The Bahamas",
        "CV" => "Cabo Verde",
        "CI" => "Côte d'Ivoire",
        "CZ" => "Czech Republic",
        "GM" => "The Gambia",
        "KR" => "South Korea",
        "TR" => "Türkiye",
        "US" => "United States",
        _ => country_name,
    };
    regions.lines().any(|line| {
        line.strip_prefix("- ")
            .is_some_and(|name| name == documented_name)
    })
}

fn aggregate_quick_resource_probe(
    id: &str,
    name: &str,
    attempts: u32,
    successes: &[QuickResourceAttempt],
    errors: &[String],
    any_success_is_stable: bool,
) -> ResourceTestResult {
    let success_count = successes.len() as u32;
    let avg_ttfb_ms = successes
        .iter()
        .map(|attempt| u64::from(attempt.ttfb_ms))
        .sum::<u64>()
        .checked_div(successes.len() as u64)
        .unwrap_or(0) as u32;
    let max_ttfb_ms = successes
        .iter()
        .map(|attempt| attempt.ttfb_ms)
        .max()
        .unwrap_or(0);
    let avg_download_kbps = if successes.is_empty() {
        0.0
    } else {
        successes
            .iter()
            .map(|attempt| attempt.bytes as f32 * 8.0 / attempt.total_ms.max(1) as f32)
            .sum::<f32>()
            / successes.len() as f32
    };
    ResourceTestResult {
        contract_version: QUICK_RESOURCE_CONTRACT_VERSION,
        id: id.to_owned(),
        name: name.to_owned(),
        attempts,
        successes: success_count,
        reachable: success_count > 0,
        stable: success_count > 0 && (any_success_is_stable || success_count == attempts),
        avg_ttfb_ms,
        max_ttfb_ms,
        avg_download_kbps,
        error: (!errors.is_empty()).then(|| errors.join("; ")),
    }
}

fn youtube_playback_attempt(
    port: u16,
    cancel: &AtomicBool,
) -> Result<QuickResourceAttempt, String> {
    let cookie_file = NamedTempFile::new().map_err(|error| format!("YouTube cookies: {error}"))?;
    let watch_file =
        NamedTempFile::new().map_err(|error| format!("YouTube watch page: {error}"))?;
    let mut watch_command = Command::new("curl");
    watch_command
        .arg("--socks5-hostname")
        .arg(format!("127.0.0.1:{port}"))
        .arg("-L")
        .arg("--connect-timeout")
        .arg(YOUTUBE_CONNECT_TIMEOUT_SECS.to_string())
        .arg("--max-time")
        .arg("20")
        .arg("--max-filesize")
        .arg(YOUTUBE_PAGE_MAX_BYTES.to_string())
        .arg("--silent")
        .arg("--show-error")
        .arg("--user-agent")
        .arg(YOUTUBE_WEB_USER_AGENT)
        .arg("--cookie-jar")
        .arg(cookie_file.path())
        .arg("--output")
        .arg(watch_file.path())
        .arg("--write-out")
        .arg("%{http_code}")
        .arg(YOUTUBE_WATCH_URL);
    let watch = run_cancellable_command(&mut watch_command, cancel).map_err(|error| {
        if error == "benchmark cancelled" {
            error
        } else {
            format!("YouTube bootstrap curl: {error}")
        }
    })?;
    if !watch.status.success() {
        return Err(format!(
            "YouTube bootstrap rc={}: {}",
            watch
                .status
                .code()
                .map_or_else(|| "?".to_owned(), |code| code.to_string()),
            bounded_process_error(&watch.stderr)
        ));
    }
    let watch_status = parse_http_status(&watch.stdout, "YouTube bootstrap")?;
    if !(200..300).contains(&watch_status) {
        return Err(format!("YouTube bootstrap http={watch_status}"));
    }
    let watch_page = std::fs::read_to_string(watch_file.path())
        .map_err(|error| format!("read YouTube bootstrap: {error}"))?;
    let visitor_data = embedded_json_string(&watch_page, "visitorData")
        .ok_or_else(|| "YouTube bootstrap returned no visitor data".to_owned())?;
    let signature_timestamp =
        embedded_json_u64(&watch_page, "signatureTimestamp").unwrap_or(YOUTUBE_SIGNATURE_TIMESTAMP);
    let player_body = serde_json::json!({
        "context": {"client": {
            "clientName": "ANDROID_VR",
            "clientVersion": "1.65.10",
            "deviceMake": "Oculus",
            "deviceModel": "Quest 3",
            "androidSdkVersion": 32,
            "userAgent": YOUTUBE_VR_USER_AGENT,
            "osName": "Android",
            "osVersion": "12L",
            "hl": "en",
            "timeZone": "UTC",
            "utcOffsetMinutes": 0,
            "visitorData": visitor_data,
        }},
        "videoId": YOUTUBE_VIDEO_ID,
        "playbackContext": {"contentPlaybackContext": {
            "html5Preference": "HTML5_PREF_WANTS",
            "signatureTimestamp": signature_timestamp,
        }},
        "contentCheckOk": true,
        "racyCheckOk": true,
    })
    .to_string();
    let player_file = NamedTempFile::new().map_err(|error| format!("YouTube player: {error}"))?;
    let mut player_command = Command::new("curl");
    player_command
        .arg("--socks5-hostname")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--connect-timeout")
        .arg(YOUTUBE_CONNECT_TIMEOUT_SECS.to_string())
        .arg("--max-time")
        .arg("20")
        .arg("--max-filesize")
        .arg(YOUTUBE_PLAYER_MAX_BYTES.to_string())
        .arg("--silent")
        .arg("--show-error")
        .arg("--cookie")
        .arg(cookie_file.path())
        .arg("--header")
        .arg("Content-Type: application/json")
        .arg("--header")
        .arg("X-Youtube-Client-Name: 28")
        .arg("--header")
        .arg("X-Youtube-Client-Version: 1.65.10")
        .arg("--header")
        .arg(format!("X-Goog-Visitor-Id: {visitor_data}"))
        .arg("--header")
        .arg("Origin: https://www.youtube.com")
        .arg("--user-agent")
        .arg(YOUTUBE_VR_USER_AGENT)
        .arg("--request")
        .arg("POST")
        .arg("--data")
        .arg(player_body)
        .arg("--output")
        .arg(player_file.path())
        .arg("--write-out")
        .arg("%{http_code}")
        .arg(YOUTUBE_PLAYER_URL);
    let player = run_cancellable_command(&mut player_command, cancel).map_err(|error| {
        if error == "benchmark cancelled" {
            error
        } else {
            format!("YouTube player curl: {error}")
        }
    })?;
    if !player.status.success() {
        return Err(format!(
            "YouTube player rc={}: {}",
            player
                .status
                .code()
                .map_or_else(|| "?".to_owned(), |code| code.to_string()),
            bounded_process_error(&player.stderr)
        ));
    }
    let player_status = parse_http_status(&player.stdout, "YouTube player")?;
    if !(200..300).contains(&player_status) {
        return Err(format!("YouTube player http={player_status}"));
    }
    let player: serde_json::Value = serde_json::from_reader(
        std::fs::File::open(player_file.path())
            .map_err(|error| format!("open YouTube player response: {error}"))?,
    )
    .map_err(|error| format!("parse YouTube player response: {error}"))?;
    let status = player
        .pointer("/playabilityStatus/status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("UNKNOWN");
    if status != "OK" {
        let reason = player
            .pointer("/playabilityStatus/reason")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("no reason");
        return Err(format!("YouTube player {status}: {reason}"));
    }
    let media_urls = youtube_direct_media_urls(&player);
    if media_urls.is_empty() {
        return Err("YouTube player returned no direct video format".to_owned());
    }
    let mut errors = Vec::new();
    for media_url in media_urls {
        match curl_youtube_range(port, media_url, cookie_file.path(), cancel) {
            Ok(attempt) => return Ok(attempt),
            Err(error) => errors.push(error),
        }
    }
    Err(errors.join("; "))
}

fn parse_http_status(output: &[u8], stage: &str) -> Result<u16, String> {
    std::str::from_utf8(output)
        .ok()
        .map(str::trim)
        .and_then(|status| status.parse().ok())
        .ok_or_else(|| format!("{stage} returned invalid HTTP status"))
}

fn embedded_json_string(source: &str, key: &str) -> Option<String> {
    let marker = format!("\"{key}\":");
    let value = source.get(source.find(&marker)? + marker.len()..)?;
    serde_json::Deserializer::from_str(value)
        .into_iter::<String>()
        .next()?
        .ok()
}

fn embedded_json_u64(source: &str, key: &str) -> Option<u64> {
    let marker = format!("\"{key}\":");
    let value = source.get(source.find(&marker)? + marker.len()..)?;
    let digits = value
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    digits.parse().ok()
}

fn youtube_direct_media_urls(player: &serde_json::Value) -> Vec<&str> {
    let mut urls = player
        .pointer("/streamingData/adaptiveFormats")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(youtube_format_direct_video_url)
        .collect::<Vec<_>>();
    urls.sort_by_key(|format| std::cmp::Reverse(format.1.unwrap_or(0)));
    let mut candidates = Vec::new();
    for url in urls.into_iter().map(|format| format.2) {
        push_unique_youtube_url(&mut candidates, url);
        if candidates.len() == 2 {
            break;
        }
    }
    if let Some(formats) = player
        .pointer("/streamingData/formats")
        .and_then(serde_json::Value::as_array)
        && let Some(url) = formats
            .iter()
            .filter_map(youtube_format_direct_video_url)
            .max_by_key(|format| format.1.unwrap_or(0))
            .map(|format| format.2)
    {
        push_unique_youtube_url(&mut candidates, url);
    }
    candidates
}

fn push_unique_youtube_url<'a>(urls: &mut Vec<&'a str>, candidate: &'a str) {
    if !urls.contains(&candidate) {
        urls.push(candidate);
    }
}

fn youtube_format_direct_video_url(
    format: &serde_json::Value,
) -> Option<(Option<u64>, Option<u64>, &str)> {
    format
        .get("mimeType")
        .and_then(serde_json::Value::as_str)
        .filter(|mime| mime.starts_with("video/"))
        .and_then(|_| {
            Some((
                format.get("itag").and_then(serde_json::Value::as_u64),
                format.get("bitrate").and_then(serde_json::Value::as_u64),
                format.get("url")?.as_str()?,
            ))
        })
}

fn curl_youtube_range(
    port: u16,
    media_url: &str,
    cookie_file: &Path,
    cancel: &AtomicBool,
) -> Result<QuickResourceAttempt, String> {
    let output_file =
        NamedTempFile::new().map_err(|error| format!("temp YouTube media: {error}"))?;
    let mut command = Command::new("curl");
    command
        .arg("--socks5-hostname")
        .arg(format!("127.0.0.1:{port}"))
        .arg("-L")
        .arg("--connect-timeout")
        .arg(YOUTUBE_CONNECT_TIMEOUT_SECS.to_string())
        .arg("--max-time")
        .arg("30")
        .arg("--range")
        .arg(format!("0-{}", YOUTUBE_SEGMENT_BYTES - 1))
        .arg("--max-filesize")
        .arg(YOUTUBE_SEGMENT_BYTES.to_string())
        .arg("--silent")
        .arg("--show-error")
        .arg("--user-agent")
        .arg(YOUTUBE_VR_USER_AGENT)
        .arg("--cookie")
        .arg(cookie_file)
        .arg("--output")
        .arg(output_file.path())
        .arg("--write-out")
        .arg("%{http_code} %{size_download} %{time_starttransfer} %{time_total}")
        .arg(media_url);
    let output = run_cancellable_command(&mut command, cancel)?;
    let metrics = parse_curl_metrics(&output.stdout)?;
    if !output.status.success() || !(200..300).contains(&metrics.http_status) || metrics.bytes == 0
    {
        return Err(format!(
            "curl rc={}, http={}, bytes={}: {}",
            output
                .status
                .code()
                .map_or_else(|| "?".to_owned(), |code| code.to_string()),
            metrics.http_status,
            metrics.bytes,
            bounded_process_error(&output.stderr)
        ));
    }
    Ok(QuickResourceAttempt {
        ttfb_ms: seconds_to_millis(metrics.ttfb_secs, 0),
        total_ms: seconds_to_millis(metrics.total_secs, 1),
        bytes: metrics.bytes,
    })
}

#[allow(dead_code)]
fn legacy_ai_studio_attempt(port: u16) -> Result<QuickResourceAttempt, String> {
    let headers = NamedTempFile::new().map_err(|error| format!("AI Studio headers: {error}"))?;
    let page = NamedTempFile::new().map_err(|error| format!("AI Studio page: {error}"))?;
    let output = Command::new("curl")
        .arg("--socks5-hostname")
        .arg(format!("127.0.0.1:{port}"))
        .arg("-L")
        .arg("--connect-timeout")
        .arg("5")
        .arg("--max-time")
        .arg("20")
        .arg("--max-filesize")
        .arg(AI_STUDIO_PAGE_MAX_BYTES.to_string())
        .arg("--silent")
        .arg("--show-error")
        .arg("--dump-header")
        .arg(headers.path())
        .arg("--output")
        .arg(page.path())
        .arg("--write-out")
        .arg("%{http_code} %{size_download} %{time_starttransfer} %{time_total} %{url_effective}")
        .arg(AI_STUDIO_URL)
        .output()
        .map_err(|error| format!("AI Studio curl: {error}"))?;
    let metrics = parse_ai_curl_metrics(&output.stdout)?;
    let redirect_headers = std::fs::read_to_string(headers.path())
        .map_err(|error| format!("read AI Studio headers: {error}"))?;
    if ai_studio_region_unavailable(&metrics.final_url)
        || redirect_headers.lines().any(|line| {
            line.split_once(':').is_some_and(|(name, url)| {
                name.eq_ignore_ascii_case("location") && ai_studio_region_unavailable(url.trim())
            })
        })
    {
        return Err("AI Studio redirected to the unsupported-region page".to_owned());
    }
    if ai_studio_sign_in_required(&metrics.final_url) {
        return Err(
            "AI Studio requires Google sign-in; regional access cannot be verified anonymously"
                .to_owned(),
        );
    }
    if !output.status.success() || !(200..300).contains(&metrics.base.http_status) {
        return Err(format!(
            "AI Studio rc={}, http={}: {}",
            output
                .status
                .code()
                .map_or_else(|| "?".to_owned(), |code| code.to_string()),
            metrics.base.http_status,
            bounded_process_error(&output.stderr)
        ));
    }
    Ok(QuickResourceAttempt {
        ttfb_ms: seconds_to_millis(metrics.base.ttfb_secs, 0),
        total_ms: seconds_to_millis(metrics.base.total_secs, 1),
        bytes: metrics.base.bytes,
    })
}

#[allow(dead_code)]
fn ai_studio_region_unavailable(url: &str) -> bool {
    url.trim()
        .to_ascii_lowercase()
        .starts_with(AI_STUDIO_UNAVAILABLE_URL)
}

#[allow(dead_code)]
fn ai_studio_sign_in_required(url: &str) -> bool {
    url.trim()
        .to_ascii_lowercase()
        .starts_with(AI_STUDIO_SIGN_IN_URL)
}

struct CurlMetrics {
    http_status: u16,
    bytes: u64,
    ttfb_secs: f64,
    total_secs: f64,
}

struct AiCurlMetrics {
    base: CurlMetrics,
    final_url: String,
}

fn parse_ai_curl_metrics(output: &[u8]) -> Result<AiCurlMetrics, String> {
    let raw = String::from_utf8_lossy(output);
    let mut parts = raw.split_whitespace();
    let base = parse_curl_metrics(
        parts
            .by_ref()
            .take(4)
            .collect::<Vec<_>>()
            .join(" ")
            .as_bytes(),
    )?;
    let final_url = parts
        .next()
        .ok_or_else(|| format!("unexpected AI Studio curl metrics: {raw}"))?;
    if parts.next().is_some() {
        return Err(format!("unexpected AI Studio curl metrics: {raw}"));
    }
    Ok(AiCurlMetrics {
        base,
        final_url: final_url.to_owned(),
    })
}

fn parse_curl_metrics(output: &[u8]) -> Result<CurlMetrics, String> {
    let raw = String::from_utf8_lossy(output);
    let parts = raw.split_whitespace().collect::<Vec<_>>();
    if parts.len() != 4 {
        return Err(format!("unexpected curl metrics: {raw}"));
    }
    Ok(CurlMetrics {
        http_status: parts[0]
            .parse::<u16>()
            .map_err(|error| format!("curl HTTP status: {error}"))?,
        bytes: parts[1]
            .parse::<u64>()
            .map_err(|error| format!("curl byte count: {error}"))?,
        ttfb_secs: parts[2]
            .parse::<f64>()
            .map_err(|error| format!("curl TTFB: {error}"))?,
        total_secs: parts[3]
            .parse::<f64>()
            .map_err(|error| format!("curl total time: {error}"))?,
    })
}

fn seconds_to_millis(seconds: f64, minimum: u32) -> u32 {
    (seconds * 1000.0)
        .round()
        .clamp(f64::from(minimum), f64::from(u32::MAX)) as u32
}

fn bounded_process_error(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    text.chars().take(500).collect::<String>().trim().to_owned()
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

    wait_until_socks_ready(port, guard.as_mut(), process_log.path(), None)?;

    let mut latencies = Vec::new();
    let mut failures = 0usize;
    for _ in 0..PROBE_ATTEMPTS {
        match curl_probe(port, probe_url, method, None) {
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

        wait_until_socks_ready(port, guard.as_mut(), process_log.path(), None)?;
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
        .arg("-d")
        .arg(benchmark_mihomo_home(config_path))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
}

fn benchmark_mihomo_home(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_owned()
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
    cancel: Option<&AtomicBool>,
) -> Result<(), String> {
    let started = Instant::now();
    while started.elapsed() < XRAY_READY_TIMEOUT {
        if cancel.is_some_and(|cancel| cancel.load(Ordering::Relaxed)) {
            return Err("benchmark cancelled".to_owned());
        }
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

fn curl_probe(
    port: u16,
    url: &str,
    method: BenchMethod,
    cancel: Option<&AtomicBool>,
) -> Result<Duration, String> {
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
    let output = match cancel {
        Some(cancel) => run_cancellable_command(&mut cmd, cancel)?,
        None => cmd.output().map_err(|e| format!("curl spawn: {e}"))?,
    };
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

fn ensure_not_cancelled(cancel: &AtomicBool) -> Result<(), String> {
    if cancel.load(Ordering::Relaxed) {
        Err("benchmark cancelled".to_owned())
    } else {
        Ok(())
    }
}

fn lock_cancellable<'a, T>(
    mutex: &'a Mutex<T>,
    cancel: &AtomicBool,
) -> Result<std::sync::MutexGuard<'a, T>, String> {
    loop {
        ensure_not_cancelled(cancel)?;
        match mutex.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(std::sync::TryLockError::WouldBlock) => {
                thread::sleep(Duration::from_millis(40));
            }
            Err(std::sync::TryLockError::Poisoned(poison)) => return Ok(poison.into_inner()),
        }
    }
}

fn run_cancellable_command(
    command: &mut Command,
    cancel: &AtomicBool,
) -> Result<std::process::Output, String> {
    ensure_not_cancelled(cancel)?;
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;
    loop {
        if cancel.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            return Err("benchmark cancelled".to_owned());
        }
        match child.try_wait().map_err(|error| error.to_string())? {
            Some(_) => return child.wait_with_output().map_err(|error| error.to_string()),
            None => thread::sleep(Duration::from_millis(40)),
        }
    }
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
    spawn_bench_mihomo_with_path(profile, "mihomo", None).ok()
}

fn spawn_bench_mihomo_with_path(
    profile: &Profile,
    mihomo_path: &str,
    cancel: Option<&AtomicBool>,
) -> Result<(u16, ChildGuard), String> {
    let port = reserve_local_port()?;
    let config_yaml = build_mihomo_bench_config(profile, "127.0.0.1", port)?;
    let mut config_file = NamedTempFile::with_suffix(".yaml")
        .map_err(|error| format!("temp Mihomo config: {error}"))?;
    config_file
        .write_all(config_yaml.as_bytes())
        .map_err(|error| format!("write Mihomo config: {error}"))?;
    config_file
        .flush()
        .map_err(|error| format!("flush Mihomo config: {error}"))?;
    let process_log = NamedTempFile::new().map_err(|error| format!("temp Mihomo log: {error}"))?;
    let child = spawn_mihomo_with_combined_log(mihomo_path, config_file.path(), &process_log)
        .map_err(|error| format!("Mihomo spawn ({mihomo_path}): {error}"))?;
    let mut guard = ChildGuard { child: Some(child) };
    wait_until_socks_ready(port, guard.as_mut(), process_log.path(), cancel)?;
    Ok((port, guard))
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
        match curl_probe(port, DEFAULT_PROBE_URL, BenchMethod::Head, None) {
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
        if curl_probe(port, DEFAULT_PROBE_URL, BenchMethod::Head, None).is_ok() {
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
    fn benchmark_mihomo_home_uses_temp_config_directory() {
        assert_eq!(
            benchmark_mihomo_home(Path::new("/tmp/bench/config.yaml")),
            Path::new("/tmp/bench")
        );
        assert_eq!(
            benchmark_mihomo_home(Path::new("config.yaml")),
            Path::new(".")
        );
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
            success: true,
            error: None,
            resource_tests: Vec::new(),
            timestamp: 1,
        };

        let strict = strict_failover_result(result);
        assert!(!strict.success);
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
        assert_eq!(BenchMethod::parse_method("FULL"), Some(BenchMethod::Full));
        assert_eq!(BenchMethod::parse_method("quic"), None);
    }

    #[test]
    fn youtube_probe_has_bounded_retry_and_response_budgets() {
        assert_eq!(YOUTUBE_CONNECT_TIMEOUT_SECS, 10);
        assert_eq!(YOUTUBE_ATTEMPTS, 2);
        assert_eq!(YOUTUBE_PLAYER_MAX_BYTES, 2 * 1024 * 1024);
    }

    #[test]
    fn youtube_retries_only_transient_failures() {
        for error in [
            "YouTube bootstrap rc=28: timeout",
            "YouTube bootstrap rc=35: TLS reset",
            "curl rc=28, http=000, bytes=0",
            "YouTube bootstrap http=429",
            "YouTube player http=503",
            "curl rc=0, http=403, bytes=0; curl rc=0, http=503, bytes=0",
            "YouTube bootstrap returned no visitor data",
            "parse YouTube player response: EOF",
        ] {
            assert!(youtube_error_is_transient(error), "{error}");
        }
        for error in [
            "YouTube player LOGIN_REQUIRED: Sign in to confirm you’re not a bot",
            "YouTube player returned no direct video format",
            "curl rc=0, http=403, bytes=0",
        ] {
            assert!(!youtube_error_is_transient(error), "{error}");
        }
    }

    #[test]
    fn youtube_retry_passes_after_one_verified_playback() {
        let success = QuickResourceAttempt {
            ttfb_ms: 120,
            total_ms: 300,
            bytes: YOUTUBE_SEGMENT_BYTES,
        };
        let result = aggregate_quick_resource_probe(
            "youtube",
            "YouTube",
            2,
            &[success],
            &["YouTube bootstrap rc=28: timeout".to_owned()],
            true,
        );
        assert!(result.reachable);
        assert!(result.stable);
        assert_eq!(result.successes, 1);
        assert_eq!(result.attempts, 2);
    }

    #[test]
    fn parses_youtube_http_status() {
        assert_eq!(
            parse_http_status(b"200", "YouTube").expect("valid HTTP status"),
            200
        );
        assert!(parse_http_status(b"", "YouTube").is_err());
        assert!(parse_http_status(b"not-a-status", "YouTube").is_err());
    }

    #[test]
    fn service_result_requires_any_ping_and_all_service_checks() {
        let mut tests = vec![
            failed_resource_result("ping_icmp", "ICMP ping", "blocked"),
            successful_resource_result("ping_tcp", "TCP ping", Duration::from_millis(20)),
            failed_resource_result("ping_proxy", "Proxy HTTPS ping", "timeout"),
        ];
        for (id, name) in [
            ("youtube", "YouTube"),
            ("telegram", "Telegram"),
            ("ai", "AI Studio"),
        ] {
            tests.push(successful_resource_result(
                id,
                name,
                Duration::from_millis(30),
            ));
        }
        assert!(service_resource_error(&tests).is_empty());

        tests[4] = failed_resource_result("telegram", "Telegram", "timeout");
        assert!(service_resource_error(&tests).contains("Telegram"));
    }

    #[test]
    fn quick_skipped_checks_are_not_reported_as_attempted() {
        let tests = skipped_service_results_from("telegram", "YouTube failed");
        assert_eq!(tests.len(), 2);
        assert!(tests.iter().all(|test| test.attempts == 0));
        assert_eq!(tests[0].id, "telegram");
        assert_eq!(tests[1].id, "ai");
    }

    #[test]
    fn quick_benchmark_requires_proxy_protocol_runtime() {
        let profile = Profile {
            id: 9,
            name: "quick".to_owned(),
            protocol: Protocol::Vless,
            address: "127.0.0.1".to_owned(),
            port: Some(443),
            raw: "vless://11111111-1111-1111-1111-111111111111@127.0.0.1:443#quick".to_owned(),
            selected: false,
            block_quic: false,
            group: None,
        };

        let cancel = AtomicBool::new(false);
        let result = benchmark_profile(
            &profile,
            BenchMethod::Quick,
            "",
            "",
            "",
            "/definitely/missing/mihomo",
            None,
            true,
            true,
            &cancel,
        );

        assert!(!result.success);
        assert_eq!(result.method, "quick");
        assert_eq!(result.download_mbps, None);
        assert_eq!(result.upload_mbps, None);
        assert!(
            result
                .error
                .as_deref()
                .is_some_and(|error| error.contains("Mihomo spawn"))
        );
        assert_eq!(result.resource_tests.len(), 6);
        assert!(
            result
                .resource_tests
                .iter()
                .any(|test| test.id == "ping_proxy")
        );
        assert!(
            result
                .resource_tests
                .iter()
                .filter(|test| !test.id.starts_with("ping_"))
                .all(|test| !test.stable)
        );
    }

    #[test]
    fn quick_resource_aggregation_rejects_partial_telegram_delivery() {
        let attempts = [
            QuickResourceAttempt {
                ttfb_ms: 120,
                total_ms: 200,
                bytes: 20_000,
            },
            QuickResourceAttempt {
                ttfb_ms: 180,
                total_ms: 260,
                bytes: 20_000,
            },
        ];

        let result = aggregate_quick_resource_probe(
            "telegram",
            "Telegram",
            3,
            &attempts,
            &["timeout".to_owned()],
            false,
        );

        assert_eq!(result.contract_version, 6);
        assert!(result.reachable);
        assert!(!result.stable);
        assert_eq!(result.successes, 2);
        assert_eq!(result.attempts, 3);
        assert_eq!(result.avg_ttfb_ms, 150);
        assert_eq!(result.max_ttfb_ms, 180);
        assert!(result.avg_download_kbps > 0.0);
        assert_eq!(result.error.as_deref(), Some("timeout"));
    }

    #[test]
    fn parses_bounded_curl_metrics() {
        let metrics = parse_curl_metrics(b"206 524288 0.561453 0.826157").expect("metrics");
        assert_eq!(metrics.http_status, 206);
        assert_eq!(metrics.bytes, 524_288);
        assert_eq!(seconds_to_millis(metrics.ttfb_secs, 0), 561);
        assert_eq!(seconds_to_millis(metrics.total_secs, 1), 826);
    }

    #[test]
    fn parses_ai_studio_metrics_and_detects_region_redirect() {
        let metrics =
            parse_ai_curl_metrics(b"200 12345 0.250 0.500 https://aistudio.google.com/welcome")
                .expect("metrics");
        assert_eq!(metrics.base.http_status, 200);
        assert_eq!(metrics.final_url, "https://aistudio.google.com/welcome");
        assert!(ai_studio_region_unavailable(
            "https://ai.google.dev/gemini-api/docs/available-regions?hl=en"
        ));
        assert!(!ai_studio_region_unavailable(&metrics.final_url));
        assert!(ai_studio_sign_in_required(
            "https://accounts.google.com/v3/signin/identifier?continue=https%3A%2F%2Faistudio.google.com"
        ));
        assert!(!ai_studio_sign_in_required(&metrics.final_url));
    }

    #[test]
    fn parses_ipregion_google_region_and_gemini_support() {
        assert_eq!(
            google_region_code(r#"<input name="region" value="nl">"#).as_deref(),
            Some("NL")
        );
        assert_eq!(
            google_region_code(r#"<input name="region" value="RUS">"#),
            None
        );
        let regions = "# Available regions\n\n- Netherlands\n- Türkiye\n- United States\n";
        assert!(gemini_region_supported(regions, "NL", "Netherlands"));
        assert!(gemini_region_supported(regions, "TR", "Turkey"));
        assert!(gemini_region_supported(
            regions,
            "US",
            "United States of America"
        ));
        assert!(!gemini_region_supported(regions, "RU", "Russia"));
    }

    #[test]
    fn parses_youtube_bootstrap_and_direct_format() {
        let page = r#"before "visitorData":"visitor-123","signatureTimestamp":20653 after"#;
        assert_eq!(
            embedded_json_string(page, "visitorData").as_deref(),
            Some("visitor-123")
        );
        assert_eq!(embedded_json_u64(page, "signatureTimestamp"), Some(20_653));
        let player = serde_json::json!({
            "streamingData": {"adaptiveFormats": [
                {"itag": 251, "mimeType": "audio/webm", "url": "https://audio.example/"},
                {"itag": 160, "mimeType": "video/mp4", "url": "https://video.example/"}
            ]}
        });
        assert_eq!(
            youtube_direct_media_urls(&player),
            vec!["https://video.example/"]
        );

        let progressive = serde_json::json!({
            "streamingData": {
                "adaptiveFormats": [
                    {"itag": 251, "mimeType": "audio/webm", "url": "https://audio.example/"}
                ],
                "formats": [
                    {"itag": 18, "mimeType": "video/mp4", "url": "https://progressive.example/"}
                ]
            }
        });
        assert_eq!(
            youtube_direct_media_urls(&progressive),
            vec!["https://progressive.example/"]
        );

        let alternatives = serde_json::json!({
            "streamingData": {"adaptiveFormats": [
                {"itag": 160, "bitrate": 100000, "mimeType": "video/mp4", "url": "https://low.example/"},
                {"itag": 315, "bitrate": 12000000, "mimeType": "video/webm", "url": "https://high.example/"}
            ]}
        });
        assert_eq!(
            youtube_direct_media_urls(&alternatives),
            vec!["https://high.example/", "https://low.example/"]
        );

        let bounded_fallback = serde_json::json!({
            "streamingData": {
                "adaptiveFormats": [
                    {"itag": 315, "bitrate": 12000000, "mimeType": "video/webm", "url": "https://high.example/"},
                    {"itag": 401, "bitrate": 8000000, "mimeType": "video/webm", "url": "https://medium.example/"},
                    {"itag": 160, "bitrate": 100000, "mimeType": "video/mp4", "url": "https://low.example/"}
                ],
                "formats": [
                    {"itag": 18, "bitrate": 500000, "mimeType": "video/mp4", "url": "https://progressive.example/"}
                ]
            }
        });
        assert_eq!(
            youtube_direct_media_urls(&bounded_fallback),
            vec![
                "https://high.example/",
                "https://medium.example/",
                "https://progressive.example/"
            ]
        );
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
        let cancel = AtomicBool::new(false);
        let result = benchmark_profile(
            &profile,
            BenchMethod::Head,
            DEFAULT_PROBE_URL,
            DEFAULT_DOWNLOAD_URL,
            DEFAULT_UPLOAD_URL,
            "/definitely/missing/mihomo",
            None,
            false,
            false,
            &cancel,
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
        let cancel = AtomicBool::new(false);
        let result = benchmark_profile(
            &profile,
            BenchMethod::Tcp,
            DEFAULT_PROBE_URL,
            DEFAULT_DOWNLOAD_URL,
            DEFAULT_UPLOAD_URL,
            "xray",
            None,
            false,
            false,
            &cancel,
        );
        assert!(!result.success);
        assert!(result.error.is_some());
        assert_eq!(result.profile_id, 7);
    }

    #[cfg(unix)]
    #[test]
    fn cancellable_command_kills_and_reaps_the_owned_child() {
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let worker = thread::spawn(move || {
            let mut command = Command::new("sh");
            command.args(["-c", "sleep 5"]);
            run_cancellable_command(&mut command, &worker_cancel)
        });
        thread::sleep(Duration::from_millis(80));
        let started = Instant::now();
        cancel.store(true, Ordering::Relaxed);
        let error = worker
            .join()
            .expect("cancellable command worker")
            .expect_err("command must be cancelled");
        assert_eq!(error, "benchmark cancelled");
        assert!(started.elapsed() < Duration::from_secs(1));
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
        let cancel = AtomicBool::new(false);
        let result = benchmark_profile(
            &profile,
            BenchMethod::Tcp,
            DEFAULT_PROBE_URL,
            DEFAULT_DOWNLOAD_URL,
            DEFAULT_UPLOAD_URL,
            "/definitely/missing/mihomo",
            None,
            true,
            true,
            &cancel,
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
        let job = new_bench_job(BenchMethod::Tcp, 0, 1);
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
            None,
            false,
            false,
            Arc::clone(&job),
            cancel,
            on_result,
        )
        .expect("spawn bench worker");
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

    #[test]
    fn benchmark_concurrency_four_creates_four_profile_workers() {
        assert_eq!(benchmark_worker_count(4, 8), 4);
        assert_eq!(benchmark_worker_count(4, 2), 2);
        assert_eq!(benchmark_worker_count(9, 8), 6);
    }

    #[test]
    fn quick_bench_passes_configured_mihomo_path() {
        let profile = Profile {
            id: 10,
            name: "quick-path".to_owned(),
            protocol: Protocol::Vless,
            address: "127.0.0.1".to_owned(),
            port: Some(443),
            raw: "vless://11111111-1111-1111-1111-111111111111@127.0.0.1:443#quick-path".to_owned(),
            selected: false,
            block_quic: false,
            group: None,
        };
        let job = new_bench_job(BenchMethod::Quick, 1, 1);
        let collected = Arc::new(Mutex::new(Vec::new()));
        let collected_for_callback = Arc::clone(&collected);
        let handle = run_bench(
            vec![profile],
            BenchMethod::Quick,
            String::new(),
            String::new(),
            String::new(),
            "/definitely/missing/quick-mihomo".to_owned(),
            None,
            false,
            false,
            Arc::clone(&job),
            Arc::new(AtomicBool::new(false)),
            Box::new(move |result| {
                collected_for_callback
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .push(result);
            }),
        )
        .expect("spawn quick benchmark worker");

        handle.join().expect("quick benchmark worker");
        let results = collected
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        assert_eq!(results.len(), 1);
        assert!(
            results[0]
                .error
                .as_deref()
                .is_some_and(|error| error.contains("/definitely/missing/quick-mihomo"))
        );
    }
}
