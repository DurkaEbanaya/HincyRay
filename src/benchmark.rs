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
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tempfile::{NamedTempFile, TempDir};

use crate::mihomo_config::build_mihomo_bench_config;
use crate::profiles::Profile;
#[cfg(test)]
use crate::profiles::Protocol;
use crate::telegram_probe::{TelegramProbeConfig, probe_media};

#[path = "youtube_availability.rs"]
mod youtube_availability;
pub use youtube_availability::YOUTUBE_AVAILABILITY_CONTRACT_VERSION;

pub const DEFAULT_PROBE_URL: &str = "https://www.gstatic.com/generate_204";
pub const DEFAULT_DOWNLOAD_URL: &str = "https://proof.ovh.net/files/100Mb.dat";
pub const DEFAULT_UPLOAD_URL: &str = "https://speed.cloudflare.com/__up";
pub const MIN_DEEP_BENCH_STABILITY_MINUTES: u32 = 1;
pub const MAX_DEEP_BENCH_STABILITY_MINUTES: u32 = 15;

const PROBE_ATTEMPTS: usize = 3;
const PROBE_TIMEOUT_SECS: u64 = 6;
const PREFLIGHT_FAILURE_LIMIT: usize = 20;
const PREFLIGHT_ERROR_BYTES: usize = 2048;
const PREFLIGHT_CORE_LOG_BYTES: usize = 64 * 1024;
const DOWNLOAD_MAX_SECS: u64 = 3;
const SUSTAINED_DOWNLOAD_MAX_SECS: u64 = 15;
const XRAY_READY_TIMEOUT: Duration = Duration::from_secs(8);
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
pub const QUICK_RESOURCE_CONTRACT_VERSION: u8 = 7;
const YOUTUBE_VIDEO_ID: &str = "aqz-KE-bpKQ";
const YOUTUBE_PLAYER_URL: &str = "https://www.youtube.com/youtubei/v1/player?prettyPrint=false";
const YOUTUBE_PLAYER_USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5 Safari/605.1.15";
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
    pub service_checks: Option<ServiceCheckOptions>,
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
    #[serde(rename = "availability_quick")]
    AvailabilityQuick,
    #[serde(rename = "availability_full")]
    AvailabilityFull,
}

impl BenchMethod {
    pub fn parse_method(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "tcp" => Some(Self::Tcp),
            "head" => Some(Self::Head),
            "get" => Some(Self::Get),
            "quick" => Some(Self::Quick),
            "full" => Some(Self::Full),
            "availability_quick" => Some(Self::AvailabilityQuick),
            "availability_full" => Some(Self::AvailabilityFull),
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
            Self::AvailabilityQuick => "availability_quick",
            Self::AvailabilityFull => "availability_full",
        }
    }

    pub fn is_service(self) -> bool {
        matches!(
            self,
            Self::Quick | Self::Full | Self::AvailabilityQuick | Self::AvailabilityFull
        )
    }

    pub fn is_availability(self) -> bool {
        matches!(self, Self::AvailabilityQuick | Self::AvailabilityFull)
    }

    pub fn is_fail_fast(self) -> bool {
        matches!(self, Self::Quick | Self::AvailabilityQuick)
    }
}

/// One profile's benchmark outcome. Persisted into `HincyrayState::stats`
/// by the daemon thread callback; also surfaced live in the job state.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BenchResult {
    pub profile_id: usize,
    pub profile_name: String,
    #[serde(default, skip_serializing)]
    #[schemars(skip)]
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

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResourceTestResult {
    #[serde(default)]
    pub contract_version: u8,
    pub id: String,
    pub name: String,
    pub attempts: u32,
    pub successes: u32,
    pub reachable: bool,
    pub stable: bool,
    #[serde(default)]
    pub inconclusive: bool,
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

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdaptiveSearchOptions {
    #[schemars(range(min = 1, max = 20))]
    pub target_good: usize,
    #[schemars(regex(pattern = "^(all|youtube|telegram|ai)$"))]
    pub required_services: String,
    #[serde(default = "default_search_fail_fast")]
    pub fail_fast: bool,
}

fn default_search_fail_fast() -> bool {
    true
}

impl AdaptiveSearchOptions {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=20).contains(&self.target_good) {
            return Err("target_good must be between 1 and 20".to_owned());
        }
        if !matches!(
            self.required_services.as_str(),
            "all" | "youtube" | "telegram" | "ai"
        ) {
            return Err("required_services must be all, youtube, telegram, or ai".to_owned());
        }
        Ok(())
    }
}

/// Ordinary availability checks use an ordered YT/TG/AI prefix, without search preflight.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceCheckOptions {
    pub required_services: ServiceCheckPrefix,
    pub fail_fast: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub reject_no_ping: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub full_ping: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ServiceCheckPrefix {
    All,
    Youtube,
    Telegram,
    Ai,
}

impl ServiceCheckPrefix {
    fn last_service(self) -> &'static str {
        match self {
            Self::Youtube => "youtube",
            Self::Telegram => "telegram",
            Self::All | Self::Ai => "ai",
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, schemars::JsonSchema)]
pub struct SearchProgress {
    pub target_good: usize,
    pub required_services: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail_fast: Option<bool>,
    pub found_good: usize,
    pub preflight_completed: usize,
    pub preflight_rejected: usize,
    pub quick_completed: usize,
    pub finish_reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, schemars::JsonSchema)]
pub struct PreflightFailure {
    pub profile_id: usize,
    #[schemars(regex(pattern = "^(setup|https)$"))]
    pub phase: String,
    #[schemars(length(max = 2048))]
    pub error: String,
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
    pub search: Option<SearchProgress>,
    pub service_checks: Option<ServiceCheckOptions>,
    pub preflight_failures: Vec<PreflightFailure>,
    pub(crate) requested_concurrency: usize,
    pub(crate) memory_limited: bool,
    pub(crate) worker_count: usize,
    pub(crate) memory_reserve_kb: Option<u64>,
    pub memory_pressure: bool,
}

#[derive(Clone, Debug, Serialize, schemars::JsonSchema)]
pub struct ActiveBenchProfile {
    pub id: usize,
    pub name: String,
}

pub type SharedJob = Arc<Mutex<BenchJob>>;
pub type BenchCompleteCallback = Box<dyn Fn(Vec<BenchResult>) -> Vec<BenchResult> + Send + 'static>;

pub fn new_bench_job(method: BenchMethod, total: usize, concurrency: usize) -> SharedJob {
    Arc::new(Mutex::new(BenchJob {
        running: true,
        method: Some(method),
        total,
        last_updated: unix_now(),
        requested_concurrency: concurrency.clamp(1, 6),
        memory_limited: false,
        worker_count: benchmark_worker_count(concurrency, total),
        ..BenchJob::default()
    }))
}

/// Spawn the benchmark worker thread. Returns immediately; the caller
/// keeps the `SharedJob` for status reads and the `AtomicBool` to
/// request cancellation. `on_result` is invoked once per finished
/// profile (success or failure) so the daemon can persist stats without
/// the benchmark module depending on `hincyray`. With `job.search` set,
/// rejected preflights emit no result and completion post-actions never run.
#[allow(clippy::too_many_arguments)]
pub fn run_bench(
    profiles: Vec<Profile>,
    method: BenchMethod,
    probe_url: String,
    download_url: String,
    upload_url: String,
    core_path: String,
    mut quick_probe: Option<QuickProbeConfig>,
    test_download: bool,
    test_upload: bool,
    job: SharedJob,
    cancel: Arc<AtomicBool>,
    on_result: Box<dyn Fn(BenchResult) + Send + Sync + 'static>,
    on_complete: Option<BenchCompleteCallback>,
) -> Result<thread::JoinHandle<()>, String> {
    let policy = job.lock().unwrap_or_else(|poison| poison.into_inner());
    if policy.service_checks.is_some() && (!method.is_availability() || policy.search.is_some()) {
        return Err("service_checks requires availability without search".to_owned());
    }
    if let Some(options) = &policy.service_checks {
        quick_probe
            .get_or_insert_with(|| QuickProbeConfig {
                telegram_session_path: String::new(),
                telegram: None,
                service_checks: None,
            })
            .service_checks = Some(options.clone());
    }
    let search_fail_fast = policy
        .search
        .as_ref()
        .and_then(|search| search.fail_fast)
        .unwrap_or(true);
    if !method.is_availability() && !search_fail_fast {
        return Err("search.fail_fast=false requires availability_quick".to_owned());
    }
    if let Some(search) = &policy.search {
        if !method.is_fail_fast() {
            return Err("adaptive search requires quick or availability_quick".to_owned());
        }
        AdaptiveSearchOptions {
            target_good: search.target_good,
            required_services: search.required_services.clone(),
            fail_fast: search_fail_fast,
        }
        .validate()?;
    }
    drop(policy);
    run_bench_with_probe(
        profiles,
        job,
        cancel,
        on_result,
        on_complete,
        move |profile, required, cancel, on_preflight, on_preflight_failure| {
            if let Some(required) = required {
                benchmark_adaptive_profile(
                    profile,
                    method,
                    required,
                    search_fail_fast,
                    &probe_url,
                    &core_path,
                    quick_probe.as_ref(),
                    cancel,
                    on_preflight,
                    on_preflight_failure,
                )
            } else {
                Some(benchmark_profile(
                    profile,
                    method,
                    &probe_url,
                    &download_url,
                    &upload_url,
                    &core_path,
                    quick_probe.as_ref(),
                    test_download,
                    test_upload,
                    cancel,
                ))
            }
        },
        || thread::sleep(Duration::from_millis(50)),
    )
}

fn run_bench_with_probe(
    profiles: Vec<Profile>,
    job: SharedJob,
    cancel: Arc<AtomicBool>,
    on_result: Box<dyn Fn(BenchResult) + Send + Sync + 'static>,
    on_complete: Option<BenchCompleteCallback>,
    probe: impl Fn(
        &Profile,
        Option<&str>,
        &AtomicBool,
        &dyn Fn(bool),
        &dyn Fn(&str, &str),
    ) -> Option<BenchResult>
    + Send
    + Sync
    + 'static,
    idle_wait: impl Fn() + Send + Sync + 'static,
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
            let reserve = job
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .memory_reserve_kb;
            let monitor_done = AtomicBool::new(false);

            thread::scope(|scope| {
                struct MonitorExit<'a>(&'a AtomicBool);
                impl Drop for MonitorExit<'_> {
                    fn drop(&mut self) {
                        self.0.store(true, Ordering::Relaxed);
                    }
                }
                let monitor_exit = MonitorExit(&monitor_done);
                if let Some(reserve) = reserve {
                    let monitor_done = &monitor_done;
                    let cancel = &cancel;
                    let job = &job;
                    scope.spawn(move || {
                        while !monitor_done.load(Ordering::Relaxed)
                            && !cancel.load(Ordering::Relaxed)
                        {
                            let available = available_memory_kb();
                            if available.is_none_or(|available| available < reserve) {
                                cancel.store(true, Ordering::Relaxed);
                                let mut state =
                                    job.lock().unwrap_or_else(|poison| poison.into_inner());
                                state.memory_pressure = true;
                                state.cancel_requested = true;
                                break;
                            }
                            thread::sleep(Duration::from_millis(100));
                        }
                    });
                }
                // Join workers before signaling the scoped monitor to exit.
                thread::scope(|scope| {
                    for _ in 0..worker_count {
                        let queue = Arc::clone(&queue);
                        let job = Arc::clone(&job);
                        let cancel = Arc::clone(&cancel);
                        let on_result = Arc::clone(&on_result);
                        let probe = &probe;
                        let idle_wait = &idle_wait;
                        scope.spawn(move || {
                            loop {
                                if cancel.load(Ordering::Relaxed) {
                                    break;
                                }
                                let (profile, required) = {
                                    let mut state =
                                        job.lock().unwrap_or_else(|poison| poison.into_inner());
                                    if cancel.load(Ordering::Relaxed) {
                                        break;
                                    }
                                    if let Some(search) = &state.search {
                                        if search.found_good >= search.target_good {
                                            break;
                                        }
                                        if search.found_good + state.active_profiles.len()
                                            >= search.target_good
                                        {
                                            drop(state);
                                            idle_wait();
                                            continue;
                                        }
                                    }
                                    // Admission and reservation are atomic; always lock job before queue.
                                    let Some(profile) = queue
                                        .lock()
                                        .unwrap_or_else(|poison| poison.into_inner())
                                        .pop_front()
                                    else {
                                        break;
                                    };
                                    state.current_profile_id = Some(profile.id);
                                    state.current_profile_name = Some(profile.name.clone());
                                    if state.active_profiles.len() < 6 {
                                        state.active_profiles.push(ActiveBenchProfile {
                                            id: profile.id,
                                            name: profile.name.clone(),
                                        });
                                    }
                                    state.last_updated = unix_now();
                                    let required = state
                                        .search
                                        .as_ref()
                                        .map(|search| search.required_services.clone());
                                    (profile, required)
                                };

                                let on_preflight = |passed: bool| {
                                    let mut state =
                                        job.lock().unwrap_or_else(|poison| poison.into_inner());
                                    if let Some(search) = &mut state.search {
                                        search.preflight_completed += 1;
                                        search.preflight_rejected += usize::from(!passed);
                                        state.last_updated = unix_now();
                                    }
                                };
                                let on_preflight_failure = |phase: &str, error: &str| {
                                    let mut state =
                                        job.lock().unwrap_or_else(|poison| poison.into_inner());
                                    if state.search.is_some() {
                                        if state.preflight_failures.len() == PREFLIGHT_FAILURE_LIMIT
                                        {
                                            state.preflight_failures.remove(0);
                                        }
                                        state.preflight_failures.push(PreflightFailure {
                                            profile_id: profile.id,
                                            phase: phase.chars().take(32).collect(),
                                            error: bounded_preflight_error(error),
                                        });
                                        state.last_updated = unix_now();
                                    }
                                };
                                let result = probe(
                                    &profile,
                                    required.as_deref(),
                                    &cancel,
                                    &on_preflight,
                                    &on_preflight_failure,
                                );
                                // Private cores/captures and decoder buffers have been dropped.
                                // Return freed glibc pages now rather than waiting for watchdog.
                                crate::hincyray::trim_process_allocator();

                                if cancel.load(Ordering::Relaxed) {
                                    let mut state =
                                        job.lock().unwrap_or_else(|poison| poison.into_inner());
                                    state
                                        .active_profiles
                                        .retain(|active| active.id != profile.id);
                                    continue;
                                }

                                if let Some(result) = &result {
                                    on_result(result.clone());
                                }
                                let mut state =
                                    job.lock().unwrap_or_else(|poison| poison.into_inner());
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
                                let unique_good = result.as_ref().is_some_and(|result| {
                                    required.as_deref().is_some_and(|required| {
                                        adaptive_result_is_good(result, required)
                                            && !state.results.iter().any(|previous| {
                                                previous.profile_raw == result.profile_raw
                                                    && adaptive_result_is_good(previous, required)
                                            })
                                    })
                                });
                                if let Some(search) = &mut state.search
                                    && result.is_some()
                                {
                                    search.quick_completed += 1;
                                    search.found_good += usize::from(unique_good);
                                }
                                if let Some(result) = result {
                                    state.results.push(result);
                                }
                                state.completed += 1;
                                state.last_updated = unix_now();
                            }
                        });
                    }
                });
                drop(monitor_exit);
            });

            let completed_results = {
                let state = job.lock().unwrap_or_else(|poison| poison.into_inner());
                (state.search.is_none()
                    && !cancel.load(Ordering::Relaxed)
                    && state.completed == state.total)
                    .then(|| state.results.clone())
            };
            if let (Some(on_complete), Some(results)) = (on_complete, completed_results) {
                let results = on_complete(results);
                job.lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .results = results;
            }
            drop(queue);
            crate::hincyray::trim_process_allocator();

            {
                let mut state = job.lock().unwrap_or_else(|poison| poison.into_inner());
                state.running = false;
                state.current_profile_id = None;
                state.current_profile_name = None;
                state.active_profiles.clear();
                if let Some(search) = &mut state.search {
                    search.finish_reason = Some(
                        if cancel.load(Ordering::Relaxed) {
                            "cancelled"
                        } else if search.found_good >= search.target_good {
                            "target_reached"
                        } else {
                            "exhausted"
                        }
                        .to_owned(),
                    );
                }
                state.last_updated = unix_now();
            }
        })
        .map_err(|error| format!("spawn benchmark worker: {error}"))
}

fn available_memory_kb() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
        meminfo.lines().find_map(|line| {
            line.strip_prefix("MemAvailable:")?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
    }
    #[cfg(not(target_os = "linux"))]
    None
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
        BenchMethod::Quick
        | BenchMethod::Full
        | BenchMethod::AvailabilityQuick
        | BenchMethod::AvailabilityFull => {
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
    let need_speed = !method.is_service() && (test_download || test_upload);

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
            let (resources_passed, resource_error) = service_resource_outcome(
                &resource_tests,
                quick_probe.and_then(|probe| probe.service_checks.as_ref()),
            );
            BenchResult {
                latency_ms: metrics.latency_ms,
                jitter_ms: metrics.jitter_ms,
                download_mbps,
                upload_mbps,
                download_error: speed_metrics.download.and_then(Result::err),
                upload_error: speed_metrics.upload.and_then(Result::err),
                loss_percent: metrics.loss_percent,
                success: resources_passed,
                error: (!resource_error.is_empty())
                    .then(|| format!("resource checks failed: {resource_error}")),
                resource_tests,
                ..base()
            }
        }
        Err(error) => {
            let resource_tests = if method.is_service() {
                let mut tests = unavailable_service_resource_results(&error);
                if method.is_availability() {
                    tests[3] = youtube_availability::unavailable();
                }
                tests
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
        inconclusive: false,
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
    let options = quick_probe.and_then(|probe| probe.service_checks.as_ref());
    let full_ping = options.map_or(!method.is_availability(), |options| options.full_ping);
    let mut tests = run_direct_ping_diagnostics(
        full_ping,
        cancel,
        || run_icmp_ping_probe(profile, cancel),
        || run_tcp_ping_probe(profile, cancel),
    )?;
    let runtime = spawn_bench_mihomo_with_path(profile, mihomo_path, Some(cancel));
    match runtime.as_ref() {
        Ok((port, _guard)) => tests.push(run_proxy_ping_probe(*port, probe_url, cancel)?),
        Err(error) => tests.push(failed_resource_result(
            "ping_proxy",
            "Proxy HTTPS ping",
            error,
        )),
    };
    if reject_services_after_ping(options, &tests) {
        tests.extend(run_service_probes_after_ping(
            method,
            options,
            &tests,
            cancel,
            |_| unreachable!("services must not run after failed ping"),
        )?);
    } else if let Ok((port, _guard)) = runtime.as_ref() {
        tests.extend(run_service_probes_after_ping(
            method,
            options,
            &tests,
            cancel,
            |id| match id {
                "youtube" if method.is_availability() => youtube_availability::probe(*port, cancel),
                "youtube" => run_youtube_playback_probe(*port, cancel),
                "telegram" => run_telegram_media_probe(*port, quick_probe, cancel),
                _ => run_ai_studio_probe(*port, cancel),
            },
        )?);
    } else {
        let error = runtime.as_ref().err().expect("failed Mihomo runtime");
        if let Some(options) = quick_probe.and_then(|probe| probe.service_checks.as_ref()) {
            tests.extend(run_complete_service_probes(
                method,
                Some(options),
                cancel,
                |id| {
                    Ok(if id == "youtube" {
                        youtube_availability::unavailable()
                    } else {
                        failed_resource_result(
                            id,
                            if id == "telegram" {
                                "Telegram"
                            } else {
                                "AI Studio"
                            },
                            error,
                        )
                    })
                },
            )?);
        } else if method.is_fail_fast() {
            tests.push(if method.is_availability() {
                youtube_availability::unavailable()
            } else {
                failed_resource_result("youtube", "YouTube", error)
            });
            tests.extend(skipped_service_results_from(
                "telegram",
                "skipped after YouTube proxy setup failed",
            ));
        } else {
            let mut unavailable = unavailable_proxy_service_results(error);
            if method.is_availability() {
                unavailable[0] = youtube_availability::unavailable();
            }
            tests.extend(unavailable);
        }
    }

    Ok((ping_metrics(&tests), tests))
}

fn run_direct_ping_diagnostics(
    full_ping: bool,
    cancel: &AtomicBool,
    icmp: impl FnOnce() -> Result<ResourceTestResult, String>,
    tcp: impl FnOnce() -> Result<ResourceTestResult, String>,
) -> Result<Vec<ResourceTestResult>, String> {
    ensure_not_cancelled(cancel)?;
    if full_ping {
        let icmp = icmp()?;
        ensure_not_cancelled(cancel)?;
        Ok(vec![icmp, tcp()?])
    } else {
        Ok(vec![
            skipped_resource_result("ping_icmp", "ICMP ping", "minimal Ping: proxy HTTPS only"),
            skipped_resource_result("ping_tcp", "TCP ping", "minimal Ping: proxy HTTPS only"),
        ])
    }
}

fn reject_services_after_ping(
    options: Option<&ServiceCheckOptions>,
    tests: &[ResourceTestResult],
) -> bool {
    options.is_some_and(|options| options.reject_no_ping)
        && !tests.iter().any(|test| {
            matches!(test.id.as_str(), "ping_icmp" | "ping_tcp" | "ping_proxy")
                && test.attempts > 0
                && test.reachable
        })
}

fn run_service_probes_after_ping(
    method: BenchMethod,
    options: Option<&ServiceCheckOptions>,
    ping_tests: &[ResourceTestResult],
    cancel: &AtomicBool,
    service: impl FnMut(&str) -> Result<ResourceTestResult, String>,
) -> Result<Vec<ResourceTestResult>, String> {
    if !reject_services_after_ping(options, ping_tests) {
        return run_complete_service_probes(method, options, cancel, service);
    }
    ensure_not_cancelled(cancel)?;
    let required = options
        .expect("explicit ping policy")
        .required_services
        .last_service();
    let mut requested = true;
    Ok([
        ("youtube", "YouTube"),
        ("telegram", "Telegram"),
        ("ai", "AI Studio"),
    ]
    .into_iter()
    .map(|(id, name)| {
        let mut test = skipped_resource_result(
            id,
            name,
            if requested {
                "skipped after all ping checks failed (reject_no_ping)"
            } else {
                "not requested by service_checks"
            },
        );
        if id == "youtube" && method.is_availability() {
            test.id = "youtube_thumbnails".to_owned();
            test.contract_version = YOUTUBE_AVAILABILITY_CONTRACT_VERSION;
        }
        if id == required {
            requested = false;
        }
        test
    })
    .collect())
}

fn run_complete_service_probes(
    method: BenchMethod,
    options: Option<&ServiceCheckOptions>,
    cancel: &AtomicBool,
    mut service: impl FnMut(&str) -> Result<ResourceTestResult, String>,
) -> Result<Vec<ResourceTestResult>, String> {
    let mut tests = Vec::new();
    let required = options.map_or("ai", |options| options.required_services.last_service());
    let fail_fast = options.map_or(method.is_fail_fast(), |options| options.fail_fast);
    let mut requested = true;
    let mut skip_reason: Option<String> = None;
    for (id, name, next) in [
        ("youtube", "YouTube", "telegram"),
        ("telegram", "Telegram", "ai"),
        ("ai", "AI Studio", ""),
    ] {
        ensure_not_cancelled(cancel)?;
        let test = if !requested {
            skipped_resource_result(id, name, "not requested by service_checks")
        } else if let Some(reason) = &skip_reason {
            skipped_resource_result(id, name, reason)
        } else {
            match service(id) {
                Ok(test) => test,
                Err(error) if options.is_some() => {
                    ensure_not_cancelled(cancel)?;
                    if error == "benchmark cancelled" {
                        return Err(error);
                    }
                    let mut test = failed_resource_result(id, name, &error);
                    if id == "youtube" && method.is_availability() {
                        test.id = "youtube_thumbnails".to_owned();
                        test.contract_version = YOUTUBE_AVAILABILITY_CONTRACT_VERSION;
                    }
                    test
                }
                Err(error) => return Err(error),
            }
        };
        if requested && skip_reason.is_none() && fail_fast && !test.stable && !next.is_empty() {
            skip_reason = Some(format!("skipped after {name} failed"));
        }
        if id == required {
            requested = false;
        }
        tests.push(test);
    }
    ensure_not_cancelled(cancel)?;
    Ok(tests)
}

/// Search requires valid ping evidence and the stable selected service prefix;
/// unrequested services remain skipped without affecting search success.
pub fn adaptive_result_is_good(result: &BenchResult, required: &str) -> bool {
    if !matches!(result.method.as_str(), "search" | "search_availability") {
        return false;
    }
    let count = match required {
        "youtube" => 1,
        "telegram" => 2,
        "all" | "ai" => 3,
        _ => return false,
    };
    result.resource_tests.iter().any(|test| {
        test.contract_version == QUICK_RESOURCE_CONTRACT_VERSION
            && matches!(test.id.as_str(), "ping_icmp" | "ping_tcp" | "ping_proxy")
            && test.attempts > 0
            && test.successes > 0
            && test.successes <= test.attempts
            && test.reachable
    }) && ["youtube", "telegram", "ai"]
        .into_iter()
        .take(count)
        .all(|id| {
            let (id, contract_version) =
                if id == "youtube" && result.method == "search_availability" {
                    ("youtube_thumbnails", YOUTUBE_AVAILABILITY_CONTRACT_VERSION)
                } else {
                    (id, QUICK_RESOURCE_CONTRACT_VERSION)
                };
            result.resource_tests.iter().any(|test| {
                test.contract_version == contract_version
                    && test.id == id
                    && test.attempts > 0
                    && test.successes > 0
                    && test.successes <= test.attempts
                    && (id != "youtube_thumbnails" || test.reachable)
                    && test.stable
                    && !test.inconclusive
            })
        })
}

#[allow(clippy::too_many_arguments)]
fn benchmark_adaptive_profile(
    profile: &Profile,
    method: BenchMethod,
    required: &str,
    fail_fast: bool,
    probe_url: &str,
    mihomo_path: &str,
    quick_probe: Option<&QuickProbeConfig>,
    cancel: &AtomicBool,
    on_preflight: &dyn Fn(bool),
    on_preflight_failure: &dyn Fn(&str, &str),
) -> Option<BenchResult> {
    let tests = run_adaptive_resource_probes(
        required,
        fail_fast,
        cancel,
        on_preflight,
        || {
            let runtime = spawn_bench_mihomo_with_path(profile, mihomo_path, Some(cancel))
                .inspect_err(|error| {
                    if !cancel.load(Ordering::Relaxed) {
                        on_preflight_failure("setup", error);
                    }
                })?;
            let sample = run_adaptive_proxy_preflight(runtime.0, probe_url, cancel)?;
            if !sample.reachable {
                let error = preflight_error_with_core_log(
                    sample.error.as_deref().unwrap_or("no response"),
                    runtime.1._process_log.path(),
                );
                ensure_not_cancelled(cancel)?;
                on_preflight_failure("https", &error);
            }
            Ok((sample, runtime))
        },
        || {
            Ok(vec![
                skipped_resource_result(
                    "ping_icmp",
                    "ICMP ping",
                    "proxy preflight already proves reachability",
                ),
                skipped_resource_result(
                    "ping_tcp",
                    "TCP ping",
                    "proxy preflight already proves reachability",
                ),
            ])
        },
        |runtime, id| match id {
            "youtube" if method.is_availability() => youtube_availability::probe(runtime.0, cancel),
            "youtube" => run_youtube_playback_probe(runtime.0, cancel),
            "telegram" => run_telegram_media_probe(runtime.0, quick_probe, cancel),
            _ => run_ai_studio_probe(runtime.0, cancel),
        },
    )
    .ok()??;
    let metrics = ping_metrics(&tests);
    let attempted = tests
        .iter()
        .filter(|test| test.attempts > 0)
        .cloned()
        .collect::<Vec<_>>();
    let (_, error) = service_resource_outcome(&attempted, None);
    Some(BenchResult {
        profile_id: profile.id,
        profile_name: profile.name.clone(),
        profile_raw: profile.raw.clone(),
        method: if method.is_availability() {
            "search_availability"
        } else {
            "search"
        }
        .to_owned(),
        latency_ms: metrics.latency_ms,
        jitter_ms: metrics.jitter_ms,
        download_mbps: None,
        upload_mbps: None,
        download_error: None,
        upload_error: None,
        loss_percent: metrics.loss_percent,
        success: error.is_empty(),
        error: (!error.is_empty()).then(|| format!("resource checks failed: {error}")),
        resource_tests: tests,
        timestamp: unix_now(),
    })
}

fn run_adaptive_resource_probes<T>(
    required: &str,
    fail_fast: bool,
    cancel: &AtomicBool,
    on_preflight: impl FnOnce(bool),
    preflight: impl FnOnce() -> Result<(ResourceTestResult, T), String>,
    direct: impl FnOnce() -> Result<Vec<ResourceTestResult>, String>,
    mut service: impl FnMut(&T, &str) -> Result<ResourceTestResult, String>,
) -> Result<Option<Vec<ResourceTestResult>>, String> {
    ensure_not_cancelled(cancel)?;
    let preflight = preflight();
    ensure_not_cancelled(cancel)?;
    on_preflight(preflight.as_ref().is_ok_and(|(sample, _)| sample.reachable));
    let Ok((sample, runtime)) = preflight else {
        return Ok(None);
    };
    if !sample.reachable {
        return Ok(None);
    }
    // Keep the runtime alive and reuse the HTTPS sample instead of probing twice.
    let mut tests = direct()?;
    tests.push(sample);
    let mut skip_reason: Option<String> = None;
    let mut requested = true;
    for (id, name) in [
        ("youtube", "YouTube"),
        ("telegram", "Telegram"),
        ("ai", "AI Studio"),
    ] {
        ensure_not_cancelled(cancel)?;
        let test = if !requested {
            skipped_resource_result(id, name, "not requested by adaptive search")
        } else if let Some(reason) = &skip_reason {
            skipped_resource_result(id, name, reason)
        } else {
            match service(&runtime, id) {
                Ok(test) => test,
                Err(error) => {
                    ensure_not_cancelled(cancel)?;
                    if error == "benchmark cancelled" {
                        return Err(error);
                    }
                    failed_resource_result(id, name, &error)
                }
            }
        };
        if fail_fast && requested && skip_reason.is_none() && !test.stable {
            skip_reason = Some(format!("skipped after {name} failed"));
        }
        if id == required {
            requested = false;
        }
        tests.push(test);
    }
    ensure_not_cancelled(cancel)?;
    Ok(Some(tests))
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

fn bounded_preflight_error(error: &str) -> String {
    let mut end = error.len().min(PREFLIGHT_ERROR_BYTES);
    while !error.is_char_boundary(end) {
        end -= 1;
    }
    error[..end].to_owned()
}

fn preflight_error_with_core_log(error: &str, process_log: &Path) -> String {
    let log = read_tail(process_log, PREFLIGHT_CORE_LOG_BYTES).to_ascii_lowercase();
    let certificate_error = log.contains("x509:") || log.contains("certificate");
    // Only fixed categories cross the private-core boundary, never log text or endpoint identity.
    let categories = [
        (
            "deadline_exceeded",
            &["context deadline exceeded", "i/o timeout"][..],
        ),
        (
            "resolution_failed",
            &["dns resolve failed", "no such host", "server misbehaving"][..],
        ),
        ("connection_refused", &["connection refused"][..]),
        (
            "certificate_expired",
            &["is after", "certificate expired"][..],
        ),
        (
            "certificate_not_yet_valid",
            &["is before", "certificate not yet valid"][..],
        ),
        (
            "certificate_name_mismatch",
            &[
                "certificate is valid for",
                "cannot validate certificate for",
                "hostname mismatch",
            ][..],
        ),
        ("certificate_authority", &["unknown authority"][..]),
        (
            "ws_handshake",
            &["websocket: bad handshake", "bad websocket handshake"][..],
        ),
        ("configuration_invalid", &["parse config error"][..]),
    ]
    .into_iter()
    .filter(|(category, _)| !category.starts_with("certificate_") || certificate_error)
    .filter_map(|(category, patterns)| {
        patterns
            .iter()
            .any(|pattern| log.contains(pattern))
            .then_some(category)
    })
    .collect::<Vec<_>>();
    let mut error = bounded_preflight_error(error);
    if !categories.is_empty() {
        let label = if categories.contains(&"deadline_exceeded") {
            "upstream dial/stream deadline exceeded"
        } else {
            "upstream core failure"
        };
        let suffix = format!("; {label} [{}]", categories.join(", "));
        let mut end = error
            .len()
            .min(PREFLIGHT_ERROR_BYTES.saturating_sub(suffix.len()));
        while !error.is_char_boundary(end) {
            end -= 1;
        }
        error.truncate(end);
        error.push_str(&suffix);
    }
    error
}

fn run_adaptive_proxy_preflight(
    port: u16,
    probe_url: &str,
    cancel: &AtomicBool,
) -> Result<ResourceTestResult, String> {
    adaptive_preflight_with_probe(probe_url, cancel, |url| {
        let mut command = Command::new("curl");
        command
            .arg("-q")
            .args(["--noproxy", "", "--socks5-hostname"])
            .arg(format!("127.0.0.1:{port}"))
            .args(["--proto", "=https", "--head", "--max-time"])
            .arg(PROBE_TIMEOUT_SECS.to_string())
            .args([
                "--silent",
                "--show-error",
                "--output",
                "/dev/null",
                "--write-out",
                "%{http_code}",
            ])
            .arg(url);
        run_cancellable_command(&mut command, cancel)
    })
}

fn adaptive_preflight_with_probe(
    probe_url: &str,
    cancel: &AtomicBool,
    mut probe: impl FnMut(&str) -> Result<std::process::Output, String>,
) -> Result<ResourceTestResult, String> {
    let fallback = if probe_url == "https://www.youtube.com/" {
        DEFAULT_PROBE_URL
    } else {
        "https://www.youtube.com/"
    };
    let mut last_error = String::new();
    for (index, url) in [probe_url, fallback].into_iter().enumerate() {
        ensure_not_cancelled(cancel)?;
        let started = Instant::now();
        let result = probe(url).and_then(|output| {
            let status = String::from_utf8_lossy(&output.stdout);
            // HTTP rejection still proves HTTPS transport; native service tests decide quality.
            if output.status.success()
                && status
                    .trim()
                    .parse::<u16>()
                    .is_ok_and(|code| (200..600).contains(&code))
            {
                Ok(started.elapsed())
            } else {
                Err(format!(
                    "curl rc={}, http={}, {}",
                    output
                        .status
                        .code()
                        .map_or_else(|| "?".to_owned(), |code| code.to_string()),
                    status.trim(),
                    bounded_process_error(&output.stderr),
                ))
            }
        });
        ensure_not_cancelled(cancel)?;
        match result {
            Ok(latency) => {
                let mut sample =
                    successful_resource_result("ping_proxy", "Proxy HTTPS ping", latency);
                sample.attempts = index as u32 + 1;
                return Ok(sample);
            }
            Err(error) if error == "benchmark cancelled" => return Err(error),
            Err(error) => last_error = bounded_preflight_error(&error),
        }
    }
    let mut sample = failed_resource_result("ping_proxy", "Proxy HTTPS ping", &last_error);
    sample.attempts = 2;
    Ok(sample)
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
        inconclusive: false,
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
        inconclusive: false,
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

fn service_resource_outcome(
    tests: &[ResourceTestResult],
    policy: Option<&ServiceCheckOptions>,
) -> (bool, String) {
    if tests.is_empty() {
        return (policy.is_none(), String::new());
    }
    let count = policy.map_or(3, |options| match options.required_services {
        ServiceCheckPrefix::Youtube => 1,
        ServiceCheckPrefix::Telegram => 2,
        ServiceCheckPrefix::All | ServiceCheckPrefix::Ai => 3,
    });
    let requested = &["youtube_thumbnails", "telegram", "ai"][..count];
    let prefix_complete = policy.is_none()
        || requested.iter().all(|id| {
            tests.iter().any(|test| {
                test.id == *id
                    && test.contract_version
                        == if *id == "youtube_thumbnails" {
                            YOUTUBE_AVAILABILITY_CONTRACT_VERSION
                        } else {
                            QUICK_RESOURCE_CONTRACT_VERSION
                        }
                    && test.attempts > 0
                    && test.stable
                    && !test.inconclusive
            })
        });
    let ping_passed = tests
        .iter()
        .filter(|test| test.id.starts_with("ping_"))
        .any(|test| test.reachable);
    let mut failures = Vec::new();
    if !ping_passed
        && (policy.is_none()
            || tests
                .iter()
                .any(|test| test.id.starts_with("ping_") && test.attempts > 0))
    {
        let errors = tests
            .iter()
            .filter(|test| test.id.starts_with("ping_"))
            .filter(|test| policy.is_none() || test.attempts > 0)
            .filter_map(|test| test.error.as_deref())
            .collect::<Vec<_>>()
            .join("; ");
        failures.push(format!("Ping failed: {errors}"));
    }
    failures.extend(
        tests
            .iter()
            .filter(|test| !test.id.starts_with("ping_") && (!test.stable || test.inconclusive))
            .filter(|test| {
                policy.is_none() || (test.attempts > 0 && requested.contains(&test.id.as_str()))
            })
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
    (
        failures.is_empty() && prefix_complete && (policy.is_none() || ping_passed),
        failures.join(", "),
    )
}

fn run_youtube_playback_probe(
    port: u16,
    cancel: &AtomicBool,
) -> Result<ResourceTestResult, String> {
    // Concurrent anonymous Innertube requests from one router IP trigger
    // throttling and TLS resets. Keep the user-selected profile concurrency,
    // but serialize this narrow external-service boundary.
    let _guard = lock_cancellable(youtube_probe_lock(), cancel)?;
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
    Ok(youtube_probe_result(&successes, &errors))
}

fn youtube_probe_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn youtube_probe_result(
    successes: &[QuickResourceAttempt],
    errors: &[String],
) -> ResourceTestResult {
    let mut result = aggregate_quick_resource_probe(
        "youtube",
        "YouTube",
        successes.len() as u32 + errors.len() as u32,
        successes,
        errors,
        true,
    );
    if successes.is_empty()
        && errors
            .iter()
            .any(|error| youtube_error_is_inconclusive(error))
    {
        result.inconclusive = true;
        // A player response/challenge proves contact, not media playback.
        result.reachable = errors.iter().any(|error| {
            error.starts_with("YouTube player ")
                && !error.contains("rc=")
                && !error.contains("curl:")
                || error.contains("http=403")
                || error.contains("http=429")
                || error.contains("no direct video format")
                || error.contains("parse YouTube player response")
                || error.contains("not video media")
        });
    }
    result
}

fn youtube_error_is_inconclusive(error: &str) -> bool {
    (error.starts_with("YouTube player ") && !error.contains("rc=") && !error.contains("curl:"))
        || error.contains("no direct video format")
        || error.contains("parse YouTube player response")
        || error.contains("curl spawn:")
        || error.contains("command spawn:")
        || error.contains("command capture:")
        || error.contains("command output limit")
        || error.contains("not video media")
        || error.split("http=").skip(1).any(|status| {
            status
                .split(|ch: char| !ch.is_ascii_digit())
                .next()
                .and_then(|status| status.parse::<u16>().ok())
                .is_some_and(|status| (400..600).contains(&status))
        })
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
        inconclusive: false,
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
    // This native client does not require the web watch bootstrap or a JS signature.
    // Anonymous challenges remain inconclusive; only a real media transfer can pass.
    let player_body = youtube_player_body().to_string();
    let player_file = NamedTempFile::new().map_err(|error| format!("YouTube player: {error}"))?;
    let mut player_command = Command::new("curl");
    player_command
        .arg("-q")
        .args(["--noproxy", "", "--socks5-hostname"])
        .arg(format!("127.0.0.1:{port}"))
        .arg("--connect-timeout")
        .arg(YOUTUBE_CONNECT_TIMEOUT_SECS.to_string())
        .arg("--max-time")
        .arg("20")
        .arg("--max-filesize")
        .arg(YOUTUBE_PLAYER_MAX_BYTES.to_string())
        .arg("--silent")
        .arg("--show-error")
        .arg("--header")
        .arg("Content-Type: application/json")
        .arg("--header")
        .arg("X-Youtube-Client-Name: 101")
        .arg("--header")
        .arg("X-Youtube-Client-Version: 1.02")
        .arg("--header")
        .arg("Origin: https://www.youtube.com")
        .arg("--user-agent")
        .arg(YOUTUBE_PLAYER_USER_AGENT)
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
    youtube_player_status(&player)?;
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
        match curl_youtube_range(port, media_url, cancel) {
            Ok(attempt) => return Ok(attempt),
            Err(error) => errors.push(error),
        }
    }
    Err(errors.join("; "))
}

fn youtube_player_status(player: &std::process::Output) -> Result<u16, String> {
    let player_status = parse_http_status(&player.stdout, "YouTube player");
    if !player.status.success() {
        return Err(format!(
            "YouTube player rc={}, http={}: {}",
            player
                .status
                .code()
                .map_or_else(|| "?".to_owned(), |code| code.to_string()),
            player_status.unwrap_or(0),
            bounded_process_error(&player.stderr)
        ));
    }
    let player_status = player_status?;
    if !(200..300).contains(&player_status) {
        return Err(format!("YouTube player http={player_status}"));
    }
    Ok(player_status)
}

fn youtube_player_body() -> serde_json::Value {
    serde_json::json!({
        "context": {"client": {
            "clientName": "VISIONOS",
            "clientVersion": "1.02",
            "deviceMake": "Apple",
            "deviceModel": "RealityDevice17,1",
            "userAgent": YOUTUBE_PLAYER_USER_AGENT,
            "osName": "visionOS",
            "osVersion": "26.5.23O471",
            "hl": "en",
            "timeZone": "UTC",
            "utcOffsetMinutes": 0,
        }},
        "videoId": YOUTUBE_VIDEO_ID,
        "contentCheckOk": true,
        "racyCheckOk": true,
    })
}

fn parse_http_status(output: &[u8], stage: &str) -> Result<u16, String> {
    std::str::from_utf8(output)
        .ok()
        .map(str::trim)
        .and_then(|status| status.parse().ok())
        .ok_or_else(|| format!("{stage} returned invalid HTTP status"))
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
    cancel: &AtomicBool,
) -> Result<QuickResourceAttempt, String> {
    let output_file =
        NamedTempFile::new().map_err(|error| format!("temp YouTube media: {error}"))?;
    let mut command = Command::new("curl");
    command
        .arg("-q")
        .args(["--noproxy", "", "--socks5-hostname"])
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
        .arg(YOUTUBE_PLAYER_USER_AGENT)
        .arg("--output")
        .arg(output_file.path())
        .arg("--write-out")
        .arg("%{http_code} %{size_download} %{time_starttransfer} %{time_total}|%{content_type}")
        .arg(media_url);
    let output = run_cancellable_command(&mut command, cancel)?;
    youtube_media_attempt(&output)
}

fn youtube_media_attempt(output: &std::process::Output) -> Result<QuickResourceAttempt, String> {
    let text = std::str::from_utf8(&output.stdout).map_err(|_| "invalid YouTube media metrics")?;
    let (metrics, content_type) = text
        .split_once('|')
        .ok_or("missing YouTube media content type")?;
    let metrics = parse_curl_metrics(metrics.as_bytes())?;
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
    let content_type = content_type.trim().split(';').next().unwrap_or_default();
    if !content_type.starts_with("video/") || metrics.bytes < 16 * 1024 {
        return Err(format!(
            "YouTube response is not video media: http={}, bytes={}, content_type={}",
            metrics.http_status, metrics.bytes, content_type
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
    let (port, _guard) = spawn_bench_mihomo_with_path(profile, mihomo_path, None)?;

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
    let (port, _guard) = match spawn_bench_mihomo_with_path(profile, mihomo_path, None) {
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
    let mut command = Command::new(mihomo_path);
    command
        .arg("-f")
        .arg(config_path)
        .arg("-d")
        .arg(benchmark_mihomo_home(config_path))
        .env("GOMEMLIMIT", "16MiB")
        .env("GOGC", "20")
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    #[cfg(target_os = "linux")]
    {
        // SAFETY: getpid has no preconditions and does not dereference pointers.
        let parent_pid = unsafe { libc::getpid() };
        // SAFETY: the closure only invokes async-signal-safe libc calls between
        // fork and exec, and returns an io::Error on failure.
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != parent_pid {
                    libc::kill(libc::getpid(), libc::SIGKILL);
                    return Err(std::io::Error::other(
                        "benchmark parent exited while spawning Mihomo",
                    ));
                }
                Ok(())
            });
        }
    }
    #[cfg(target_os = "linux")]
    return crate::hincyray::spawn_core_on_persistent_thread(command);
    #[cfg(not(target_os = "linux"))]
    command.spawn()
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
            return Err(preflight_error_with_core_log(
                &format!("benchmark core exited early: {status}"),
                process_log_path,
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
    cmd.arg("-q")
        .args(["--noproxy", ""])
        .arg("--socks5-hostname")
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
    curl_download_with_timeout(port, url, DOWNLOAD_MAX_SECS, None)
}

fn curl_download_with_timeout(
    port: u16,
    url: &str,
    max_secs: u64,
    cancel: Option<&AtomicBool>,
) -> Result<f32, String> {
    let mut command = Command::new("curl");
    command
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
        .arg(url);
    let output = match cancel {
        Some(cancel) => run_cancellable_command(&mut command, cancel)?,
        None => command.output().map_err(|e| format!("curl spawn: {e}"))?,
    };

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
/// HTTP `100 Continue` is accepted as a valid response only when curl exits
/// successfully. A timeout is an error even when `size_upload` reached the
/// requested body size: `time_total` then equals the deadline and would report
/// a censored boundary as measured throughput.
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
    if !output.status.success() || !http_ok || bytes <= 0.0 {
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
    let Ok(mut file) = std::fs::File::open(path) else {
        return String::new();
    };
    let Ok(length) = file.metadata().map(|metadata| metadata.len()) else {
        return String::new();
    };
    if file
        .seek(SeekFrom::Start(length.saturating_sub(limit as u64)))
        .is_err()
    {
        return String::new();
    }
    let mut bytes = Vec::new();
    if file.take(limit as u64).read_to_end(&mut bytes).is_err() {
        return String::new();
    }
    String::from_utf8_lossy(&bytes).trim().to_owned()
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
    // Pipe capture can deadlock before exit when a child fills either pipe.
    // Private files let cancellation and bounded-output admission keep progressing.
    const LIMIT: u64 = 64 * 1024;
    let stdout = NamedTempFile::new().map_err(|error| format!("command capture: {error}"))?;
    let stderr = NamedTempFile::new().map_err(|error| format!("command capture: {error}"))?;
    struct Guard(Child);
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = Guard(
        command
            .stdout(
                stdout
                    .reopen()
                    .map_err(|error| format!("command capture: {error}"))?,
            )
            .stderr(
                stderr
                    .reopen()
                    .map_err(|error| format!("command capture: {error}"))?,
            )
            .spawn()
            .map_err(|error| format!("command spawn: {error}"))?,
    );
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("benchmark cancelled".to_owned());
        }
        for file in [&stdout, &stderr] {
            if file
                .as_file()
                .metadata()
                .map_err(|error| format!("command capture: {error}"))?
                .len()
                > LIMIT
            {
                return Err("command output limit exceeded".to_owned());
            }
        }
        match child.0.try_wait().map_err(|error| error.to_string())? {
            Some(status) => {
                let read = |file: &NamedTempFile| -> Result<Vec<u8>, String> {
                    let mut bytes = Vec::new();
                    file.reopen()
                        .map_err(|error| format!("command capture: {error}"))?
                        .take(LIMIT + 1)
                        .read_to_end(&mut bytes)
                        .map_err(|error| format!("command capture: {error}"))?;
                    if bytes.len() as u64 > LIMIT {
                        return Err("command output limit exceeded".to_owned());
                    }
                    Ok(bytes)
                };
                return Ok(std::process::Output {
                    status,
                    stdout: read(&stdout)?,
                    stderr: read(&stderr)?,
                });
            }
            None => thread::sleep(Duration::from_millis(40)),
        }
    }
}

/// Reap the core before removing its private config, log, and home.
struct ChildGuard {
    child: Option<Child>,
    _config_file: NamedTempFile,
    _process_log: NamedTempFile,
    _home: TempDir,
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
    if let Some(cancel) = cancel {
        ensure_not_cancelled(cancel)?;
    }
    let port = reserve_local_port()?;
    let config_yaml = build_mihomo_bench_config(profile, "127.0.0.1", port)?;
    let home = TempDir::new().map_err(|error| format!("temp Mihomo home: {error}"))?;
    let mut config_file = NamedTempFile::new_in(home.path())
        .map_err(|error| format!("temp Mihomo config: {error}"))?;
    config_file
        .write_all(config_yaml.as_bytes())
        .map_err(|error| format!("write Mihomo config: {error}"))?;
    config_file
        .flush()
        .map_err(|error| format!("flush Mihomo config: {error}"))?;
    let process_log =
        NamedTempFile::new_in(home.path()).map_err(|error| format!("temp Mihomo log: {error}"))?;
    let child = spawn_mihomo_with_combined_log(mihomo_path, config_file.path(), &process_log)
        .map_err(|error| format!("Mihomo spawn ({mihomo_path}): {error}"))?;
    let mut guard = ChildGuard {
        child: Some(child),
        _config_file: config_file,
        _process_log: process_log,
        _home: home,
    };
    wait_until_socks_ready(
        port,
        guard.child.as_mut().expect("temporary core child"),
        guard._process_log.path(),
        cancel,
    )?;
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
    let observation_secs = minutes
        .clamp(
            MIN_DEEP_BENCH_STABILITY_MINUTES,
            MAX_DEEP_BENCH_STABILITY_MINUTES,
        )
        .saturating_mul(60);
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

    if cancel.load(Ordering::Relaxed) {
        return None;
    }
    let total_attempts = latency_samples.len() as u32 + drop_count;
    let (sustained_download_mbps, sustained_download_source, sustained_download_error) =
        sustained_download_probe(port, cancel);
    if cancel.load(Ordering::Relaxed) {
        return None;
    }
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
    let unlock = run_unlock_test_cancellable(port, Some(cancel));
    if cancel.load(Ordering::Relaxed) {
        return None;
    }
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

fn sustained_download_probe(port: u16, cancel: &AtomicBool) -> (f32, String, String) {
    let mut errors = Vec::new();
    for url in SUSTAINED_DOWNLOAD_CANDIDATES {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        match curl_download_with_timeout(port, url, SUSTAINED_DOWNLOAD_MAX_SECS, Some(cancel)) {
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
fn probe_unlock(port: u16, url: &str, cancel: Option<&AtomicBool>) -> UnlockStatus {
    let mut best = UnlockStatus::default();
    for _ in 0..UNLOCK_RETRIES {
        if cancel.is_some_and(|cancel| cancel.load(Ordering::Relaxed)) {
            break;
        }
        let mut command = Command::new("curl");
        command
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
            .arg(url);
        let output = match cancel {
            Some(cancel) => run_cancellable_command(&mut command, cancel),
            None => command.output().map_err(|error| error.to_string()),
        };
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
    run_unlock_test_cancellable(port, None)
}

fn run_unlock_test_cancellable(port: u16, cancel: Option<&AtomicBool>) -> UnlockTestResult {
    UnlockTestResult {
        github: probe_unlock(port, "https://github.com", cancel),
        cloudflare: probe_unlock(port, "https://www.cloudflare.com", cancel),
        google: probe_unlock(port, "https://www.google.com", cancel),
        telegram: probe_unlock(port, "https://web.telegram.org", cancel),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn preflight_output(rc: i32, http: &str) -> std::process::Output {
        use std::os::unix::process::ExitStatusExt;
        std::process::Output {
            status: std::process::ExitStatus::from_raw(rc << 8),
            stdout: http.as_bytes().to_vec(),
            stderr: b"fixture transport error".to_vec(),
        }
    }

    #[test]
    fn resource_result_legacy_json_defaults_to_conclusive() {
        let mut value =
            serde_json::to_value(failed_resource_result("ping_proxy", "ping", "failed"))
                .expect("serialize resource");
        value
            .as_object_mut()
            .expect("resource object")
            .remove("inconclusive");
        let result: ResourceTestResult = serde_json::from_value(value).expect("legacy resource");
        assert!(!result.inconclusive);
    }

    #[cfg(unix)]
    #[test]
    fn adaptive_preflight_http_rejection_is_reachability_not_playback() {
        for status in ["200", "204", "301", "405", "429", "599"] {
            let sample =
                adaptive_preflight_with_probe(DEFAULT_PROBE_URL, &AtomicBool::new(false), |_| {
                    Ok(preflight_output(0, status))
                })
                .expect("HTTPS response");
            assert_eq!(sample.id, "ping_proxy");
            assert!(sample.reachable);
            assert_eq!(sample.attempts, 1);
            assert_eq!(sample.successes, 1);
            assert!(!sample.inconclusive);
        }
    }

    #[cfg(unix)]
    #[test]
    fn adaptive_preflight_retries_transport_once_on_another_domain() {
        let mut urls = Vec::new();
        let sample =
            adaptive_preflight_with_probe(DEFAULT_PROBE_URL, &AtomicBool::new(false), |url| {
                urls.push(url.to_owned());
                Ok(if urls.len() == 1 {
                    preflight_output(28, "000")
                } else {
                    preflight_output(0, "204")
                })
            })
            .expect("retry succeeds");
        assert_eq!(urls, [DEFAULT_PROBE_URL, "https://www.youtube.com/"]);
        assert!(sample.reachable);
        assert_eq!(sample.attempts, 2);
        assert_eq!(sample.successes, 1);
    }

    #[cfg(unix)]
    #[test]
    fn adaptive_preflight_rejects_invalid_http_and_certificate_failures() {
        for (rc, http) in [
            (0, "000"),
            (0, "199"),
            (0, "600"),
            (0, "invalid"),
            (60, "429"),
            (28, "200"),
        ] {
            let mut calls = 0;
            let sample = adaptive_preflight_with_probe(
                "https://www.youtube.com/",
                &AtomicBool::new(false),
                |url| {
                    if calls == 1 {
                        assert_eq!(url, DEFAULT_PROBE_URL);
                    }
                    calls += 1;
                    Ok(preflight_output(rc, http))
                },
            )
            .expect("failed sample is not cancellation");
            assert!(!sample.reachable);
            assert_eq!(sample.successes, 0);
            assert_eq!(sample.attempts, 2);
            assert_eq!(calls, 2);
        }
    }

    #[cfg(unix)]
    #[test]
    fn adaptive_preflight_cancellation_prevents_retry() {
        let cancel = AtomicBool::new(false);
        let mut calls = 0;
        let result = adaptive_preflight_with_probe(DEFAULT_PROBE_URL, &cancel, |_| {
            calls += 1;
            cancel.store(true, Ordering::Relaxed);
            Ok(preflight_output(28, "000"))
        });
        assert_eq!(result.expect_err("cancelled"), "benchmark cancelled");
        assert_eq!(calls, 1);
    }

    #[cfg(unix)]
    #[test]
    fn adaptive_preflight_keeps_only_latest_http_error() {
        let mut calls = 0;
        let sample =
            adaptive_preflight_with_probe(DEFAULT_PROBE_URL, &AtomicBool::new(false), |_| {
                calls += 1;
                Ok(preflight_output(if calls == 1 { 28 } else { 35 }, "000"))
            })
            .expect("failed preflight sample");
        let error = sample.error.expect("latest HTTP error");
        assert!(error.contains("rc=35"));
        assert!(!error.contains("rc=28"));
        assert_eq!(sample.attempts, 2);
    }

    #[test]
    fn adaptive_preflight_diagnostics_are_job_local_bounded_and_not_persisted() {
        let job = search_job(25, 1, 1);
        run_bench_with_probe(
            search_profiles(25),
            Arc::clone(&job),
            Arc::new(AtomicBool::new(false)),
            Box::new(|_| panic!("rejections must not persist health")),
            Some(Box::new(|_| panic!("search must not run post-actions"))),
            |_, _, _, on_preflight, on_failure| {
                on_failure("setup", &"\u{e9}".repeat(PREFLIGHT_ERROR_BYTES + 1));
                on_preflight(false);
                None
            },
            || {},
        )
        .expect("spawn search")
        .join()
        .expect("complete search");
        let state = job.lock().expect("job snapshot");
        assert_eq!(state.preflight_failures.len(), PREFLIGHT_FAILURE_LIMIT);
        assert_eq!(state.preflight_failures[0].profile_id, 5);
        assert!(state.preflight_failures.iter().all(
            |failure| failure.phase == "setup" && failure.error.len() <= PREFLIGHT_ERROR_BYTES
        ));
        assert!(state.results.is_empty());
        assert_eq!(
            state.search.as_ref().expect("search").preflight_rejected,
            25
        );
        assert!(BenchJob::default().preflight_failures.is_empty());
        assert_eq!(
            bounded_preflight_error(&format!("{}\u{e9}", "x".repeat(PREFLIGHT_ERROR_BYTES - 1)))
                .len(),
            PREFLIGHT_ERROR_BYTES - 1,
        );
    }

    #[test]
    fn adaptive_preflight_records_real_setup_error_without_result() {
        let failures = std::cell::RefCell::new(Vec::new());
        let result = benchmark_adaptive_profile(
            &search_profiles(1)[0],
            BenchMethod::Quick,
            "youtube",
            true,
            DEFAULT_PROBE_URL,
            "/definitely/missing/preflight-mihomo",
            None,
            &AtomicBool::new(false),
            &|passed| assert!(!passed),
            &|phase, error| {
                failures
                    .borrow_mut()
                    .push((phase.to_owned(), error.to_owned()))
            },
        );
        assert!(result.is_none());
        let failures = failures.borrow();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].0, "setup");
        assert!(failures[0].1.contains("Mihomo spawn"));
    }

    #[test]
    fn preflight_core_categories_are_fixed_bounded_and_secret_free() {
        let mut log = NamedTempFile::new().expect("private core log");
        writeln!(log, "connection refused outside the retained tail").expect("old log");
        log.write_all(&vec![b'x'; PREFLIGHT_CORE_LOG_BYTES])
            .expect("large log");
        writeln!(log, "error: context deadline exceeded https://provider.example/sub/<token> password=core-secret-canary").expect("failure log");
        let error = preflight_error_with_core_log("curl rc=35, http=000, TLS EOF", log.path());
        assert_eq!(
            error,
            "curl rc=35, http=000, TLS EOF; upstream dial/stream deadline exceeded [deadline_exceeded]"
        );
        assert!(!error.contains("core-secret-canary"));
        assert!(!error.contains("provider.example"));
        assert!(!error.contains("connection_refused"));
        let bounded =
            preflight_error_with_core_log(&"\u{e9}".repeat(PREFLIGHT_ERROR_BYTES), log.path());
        assert!(bounded.len() <= PREFLIGHT_ERROR_BYTES);
        assert!(bounded.ends_with("[deadline_exceeded]"));

        for (message, category) in [
            ("dns resolve failed: no such host", "resolution_failed"),
            ("dial tcp: connection refused", "connection_refused"),
            (
                "x509: current time is after certificate validity",
                "certificate_expired",
            ),
            (
                "x509: current time is before certificate validity",
                "certificate_not_yet_valid",
            ),
            (
                "x509: certificate is valid for another name",
                "certificate_name_mismatch",
            ),
            (
                "x509: certificate signed by unknown authority",
                "certificate_authority",
            ),
            ("websocket: bad handshake", "ws_handshake"),
        ] {
            log.as_file_mut().set_len(0).expect("reset log");
            log.as_file_mut()
                .seek(SeekFrom::Start(0))
                .expect("rewind log");
            writeln!(log, "{message}; token=core-secret-canary").expect("category fixture");
            assert_eq!(
                preflight_error_with_core_log("curl failed", log.path()),
                format!("curl failed; upstream core failure [{category}]")
            );
        }
        log.as_file_mut().set_len(0).expect("reset log");
        log.as_file_mut()
            .seek(SeekFrom::Start(0))
            .expect("rewind log");
        writeln!(log, "unrelated date is before another date").expect("non-certificate log");
        assert_eq!(
            preflight_error_with_core_log("curl failed", log.path()),
            "curl failed"
        );
    }

    #[test]
    fn adaptive_preflight_core_failure_has_no_persistence_or_post_actions() {
        let mut log = NamedTempFile::new().expect("private core log");
        writeln!(log, "context deadline exceeded token=core-secret-canary").expect("core failure");
        let job = search_job(1, 1, 1);
        run_bench_with_probe(
            search_profiles(1),
            Arc::clone(&job),
            Arc::new(AtomicBool::new(false)),
            Box::new(|_| panic!("no health persistence for a preflight rejection")),
            Some(Box::new(|_| {
                panic!("no search promotion or Dead Servers post-actions")
            })),
            move |_, _, cancel, on_preflight, on_failure| {
                run_adaptive_resource_probes(
                    "youtube",
                    true,
                    cancel,
                    on_preflight,
                    || {
                        let error =
                            preflight_error_with_core_log("curl rc=35, http=000", log.path());
                        on_failure("https", &error);
                        Ok((failed_resource_result("ping_proxy", "ping", &error), ()))
                    },
                    || panic!("no direct probes"),
                    |_, _| panic!("no native or preview probes"),
                )
                .expect("rejection is not cancellation")
                .map(|_| panic!("rejection emits no result"))
            },
            || {},
        )
        .expect("search worker")
        .join()
        .expect("search finishes");
        let state = job.lock().expect("job snapshot");
        assert!(state.results.is_empty());
        assert_eq!(state.preflight_failures.len(), 1);
        assert_eq!(state.preflight_failures[0].profile_id, 0);
        assert_eq!(state.preflight_failures[0].phase, "https");
        assert!(
            state.preflight_failures[0]
                .error
                .ends_with("[deadline_exceeded]")
        );
        assert!(
            !state.preflight_failures[0]
                .error
                .contains("core-secret-canary")
        );
        assert_eq!(state.search.as_ref().expect("search").preflight_rejected, 1);
    }

    #[cfg(unix)]
    #[test]
    fn early_core_exit_reports_categories_not_raw_private_log() {
        let mut log = NamedTempFile::new().expect("private core log");
        writeln!(
            log,
            "Parse config error: password=core-secret-canary https://provider.example/sub/<token>"
        )
        .expect("private failure log");
        let mut child = Command::new("sh")
            .args(["-c", "exit 7"])
            .spawn()
            .expect("exiting child");
        let error = wait_until_socks_ready(0, &mut child, log.path(), None).expect_err("core exit");
        assert!(error.contains("benchmark core exited early:"));
        assert!(error.ends_with("[configuration_invalid]"));
        assert!(!error.contains("core-secret-canary"));
        assert!(!error.contains("provider.example"));
    }

    #[cfg(unix)]
    #[test]
    fn temporary_core_resources_are_private_retained_and_removed_after_reap() {
        let make_guard = || {
            let home = TempDir::new().expect("private home");
            let config_file = NamedTempFile::new_in(home.path()).expect("private config");
            let process_log = NamedTempFile::new_in(home.path()).expect("private log");
            let child = Command::new("sleep")
                .arg("30")
                .spawn()
                .expect("stand-in child");
            ChildGuard {
                child: Some(child),
                _config_file: config_file,
                _process_log: process_log,
                _home: home,
            }
        };
        let mut first = make_guard();
        let second = make_guard();
        let home = first._home.path().to_owned();
        let config = first._config_file.path().to_owned();
        let log = first._process_log.path().to_owned();
        assert_ne!(home, second._home.path());
        assert_eq!(benchmark_mihomo_home(&config), home);
        assert!(config.exists() && log.exists());
        assert!(
            first
                .child
                .as_mut()
                .expect("child")
                .try_wait()
                .expect("running child")
                .is_none()
        );
        let cancel = AtomicBool::new(true);
        assert_eq!(
            wait_until_socks_ready(0, first.child.as_mut().expect("child"), &log, Some(&cancel),)
                .expect_err("cancel readiness"),
            "benchmark cancelled",
        );
        #[cfg(target_os = "linux")]
        let pid = first.child.as_ref().expect("child").id() as libc::pid_t;
        drop(first);
        #[cfg(target_os = "linux")]
        {
            assert_eq!(
                // SAFETY: waitpid accepts null; this exact child was already reaped by Drop.
                unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) },
                -1
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ECHILD)
            );
        }
        assert!(!home.exists() && !config.exists() && !log.exists());
        assert!(second._config_file.path().exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn benchmark_spawn_uses_economical_env_and_survives_caller_thread_exit() {
        use std::os::unix::fs::PermissionsExt;
        let home = TempDir::new().expect("home");
        let config = NamedTempFile::new_in(home.path()).expect("config");
        let log = NamedTempFile::new_in(home.path()).expect("log");
        let executable = home.path().join("fake-core");
        std::fs::write(&executable, "#!/bin/sh\n[ \"$GOMEMLIMIT\" = 16MiB ] && [ \"$GOGC\" = 20 ] || exit 9\nexec sleep 30\n").expect("fake core");
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
            .expect("permissions");
        let path = config.path().to_owned();
        let mut child = thread::spawn(move || {
            spawn_mihomo_with_combined_log(executable.to_str().expect("path"), &path, &log)
                .expect("spawn")
        })
        .join()
        .expect("short caller exits");
        thread::sleep(Duration::from_millis(100));
        assert!(child.try_wait().expect("alive").is_none());
        child.kill().expect("kill owned core");
        child.wait().expect("reap");
    }

    #[test]
    fn memory_pressure_cancels_and_joins_workers_without_false_completion() {
        let job = new_bench_job(BenchMethod::AvailabilityFull, 3, 3);
        job.lock().expect("job").memory_reserve_kb = Some(u64::MAX);
        let cancel = Arc::new(AtomicBool::new(false));
        let handle = run_bench_with_probe(
            search_profiles(3),
            Arc::clone(&job),
            Arc::clone(&cancel),
            Box::new(|_| panic!("no result from aborted probe")),
            Some(Box::new(|_| {
                panic!("no complete actions under memory pressure")
            })),
            |_, _, cancel, _, _| {
                while !cancel.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(10));
                }
                None
            },
            || thread::sleep(Duration::from_millis(10)),
        )
        .expect("workers");
        handle.join().expect("monitor and workers join");
        let state = job.lock().expect("final job");
        assert!(state.memory_pressure && state.cancel_requested);
        assert!(!state.running);
        assert!(state.active_profiles.is_empty() && state.results.is_empty());
    }

    #[test]
    fn process_log_tail_read_is_bounded() {
        let mut log = NamedTempFile::new().expect("log");
        log.write_all(&vec![b'x'; 10_000]).expect("log body");
        log.write_all(b"final diagnostic").expect("log suffix");
        assert_eq!(read_tail(log.path(), 16), "final diagnostic");
        assert_eq!(read_tail(log.path(), 0), "");
    }

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
        assert!(service_resource_outcome(&tests, None).0);

        tests[4] = failed_resource_result("telegram", "Telegram", "timeout");
        assert!(
            service_resource_outcome(&tests, None)
                .1
                .contains("Telegram")
        );
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

        assert_eq!(result.contract_version, QUICK_RESOURCE_CONTRACT_VERSION);
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
    fn youtube_native_request_does_not_require_web_bootstrap() {
        let body = youtube_player_body();
        assert_eq!(body["context"]["client"]["clientName"], "VISIONOS");
        assert_eq!(body["context"]["client"]["clientVersion"], "1.02");
        assert!(body["context"]["client"].get("visitorData").is_none());
        assert!(body.get("playbackContext").is_none());
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
    fn youtube_challenge_is_inconclusive_not_playback_or_transport_failure() {
        for error in [
            "YouTube player LOGIN_REQUIRED: Sign in to confirm you’re not a bot",
            "YouTube player http=429",
            "YouTube player returned no direct video format",
        ] {
            let result = youtube_probe_result(&[], &[error.to_owned()]);
            assert!(result.inconclusive && result.reachable);
            assert!(!result.stable);
            assert_eq!(result.successes, 0);
        }
        let transport = youtube_probe_result(
            &[],
            &["YouTube player rc=28: Connection timed out".to_owned()],
        );
        assert!(!transport.inconclusive && !transport.reachable && !transport.stable);
    }

    #[test]
    fn youtube_verified_media_overrides_earlier_transient_challenge() {
        let result = youtube_probe_result(
            &[QuickResourceAttempt {
                ttfb_ms: 50,
                total_ms: 100,
                bytes: YOUTUBE_SEGMENT_BYTES,
            }],
            &["YouTube player http=429".to_owned()],
        );
        assert!(result.stable && result.reachable && !result.inconclusive);
        assert_eq!(result.successes, 1);
    }

    #[cfg(unix)]
    #[test]
    fn youtube_requires_video_payload_not_just_http_200() {
        for metrics in [
            "200 524288 0.05 0.1|text/html",
            "200 524288 0.05 0.1|application/octet-stream",
            "200 128 0.05 0.1|video/mp4",
            "403 128 0.05 0.1|text/html",
        ] {
            assert!(youtube_media_attempt(&preflight_output(0, metrics)).is_err());
        }
        let media = youtube_media_attempt(&preflight_output(0, "206 524288 0.05 0.1|video/mp4"))
            .expect("real video range");
        assert_eq!(media.bytes, YOUTUBE_SEGMENT_BYTES);
    }

    #[cfg(unix)]
    #[test]
    fn youtube_http_refusal_survives_a_failed_body_transfer() {
        let error = youtube_player_status(&preflight_output(28, "429"))
            .expect_err("HTTP rejection despite curl timeout");
        assert!(error.contains("http=429"));
        let result = youtube_probe_result(&[], &[error]);
        assert!(result.inconclusive && result.reachable && !result.stable);
    }

    #[cfg(unix)]
    #[test]
    fn cancellable_command_local_spawn_and_output_limits_do_not_poison_youtube() {
        let cancel = AtomicBool::new(false);
        let dir = TempDir::new().expect("test dir");
        let error =
            run_cancellable_command(&mut Command::new(dir.path().join("missing-curl")), &cancel)
                .expect_err("missing command");
        assert!(error.starts_with("command spawn:") && youtube_error_is_inconclusive(&error));
        let mut command = Command::new("sh");
        command.args(["-c", "while :; do printf '%064d\\n' 0; done"]);
        let error = run_cancellable_command(&mut command, &cancel)
            .expect_err("oversized output killed and reaped");
        assert!(error.contains("command output limit") && youtube_error_is_inconclusive(&error));
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
                .is_some_and(|e| e.contains("Mihomo spawn"))
        );
        assert!(
            result
                .upload_error
                .as_deref()
                .is_some_and(|e| e.contains("Mihomo spawn"))
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
            None,
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

    fn search_profiles(count: usize) -> Vec<Profile> {
        (0..count)
            .map(|id| Profile {
                id,
                name: format!("candidate-{id}"),
                protocol: Protocol::Vless,
                address: "server.example".to_owned(),
                port: Some(443),
                raw: format!(
                    "vless://11111111-1111-1111-1111-111111111111@server.example:443#{id}"
                ),
                selected: false,
                block_quic: false,
                group: None,
            })
            .collect()
    }

    fn search_job(total: usize, target: usize, workers: usize) -> SharedJob {
        let job = new_bench_job(BenchMethod::Quick, total, workers);
        job.lock().expect("lock new search job").search = Some(SearchProgress {
            target_good: target,
            required_services: "youtube".to_owned(),
            ..SearchProgress::default()
        });
        job
    }

    fn search_result(profile: &Profile, required: &str) -> BenchResult {
        let cancel = AtomicBool::new(false);
        let resource_tests = run_adaptive_resource_probes(
            required,
            true,
            &cancel,
            |_| {},
            || {
                Ok((
                    successful_resource_result(
                        "ping_proxy",
                        "Proxy HTTPS ping",
                        Duration::from_millis(1),
                    ),
                    (),
                ))
            },
            || {
                Ok([("ping_icmp", "ICMP ping"), ("ping_tcp", "TCP ping")]
                    .into_iter()
                    .map(|(id, name)| {
                        skipped_resource_result(
                            id,
                            name,
                            "proxy preflight already proves reachability",
                        )
                    })
                    .collect())
            },
            |_, id| Ok(successful_resource_result(id, id, Duration::from_millis(1))),
        )
        .expect("run injected search probes")
        .expect("injected search preflight passes");
        let attempted = resource_tests
            .iter()
            .filter(|test| test.attempts > 0)
            .cloned()
            .collect::<Vec<_>>();
        let (_, error) = service_resource_outcome(&attempted, None);
        BenchResult {
            profile_id: profile.id,
            profile_name: profile.name.clone(),
            profile_raw: profile.raw.clone(),
            method: "search".to_owned(),
            latency_ms: 1,
            jitter_ms: 0,
            download_mbps: None,
            upload_mbps: None,
            download_error: None,
            upload_error: None,
            loss_percent: 0.0,
            success: error.is_empty(),
            error: (!error.is_empty()).then_some(error),
            resource_tests,
            timestamp: 0,
        }
    }

    #[test]
    fn adaptive_options_validate_and_reject_unknown_fields() {
        for target in [0, 21] {
            assert!(
                AdaptiveSearchOptions {
                    target_good: target,
                    required_services: "youtube".to_owned(),
                    fail_fast: true,
                }
                .validate()
                .is_err()
            );
        }
        for required in ["all", "youtube", "telegram", "ai"] {
            assert!(
                AdaptiveSearchOptions {
                    target_good: 20,
                    required_services: required.to_owned(),
                    fail_fast: true,
                }
                .validate()
                .is_ok()
            );
        }
        assert!(
            AdaptiveSearchOptions {
                target_good: 1,
                required_services: "unknown".to_owned(),
                fail_fast: true,
            }
            .validate()
            .is_err()
        );
        assert!(
            serde_json::from_str::<AdaptiveSearchOptions>(
                r#"{"target_good":1,"required_services":"youtube","extra":true}"#
            )
            .is_err()
        );
        let options = serde_json::from_str::<AdaptiveSearchOptions>(
            r#"{"target_good":1,"required_services":"all"}"#,
        )
        .expect("omitted adaptive fail-fast defaults to true");
        assert!(options.fail_fast);
        assert_eq!(
            serde_json::to_value(options).expect("serialize default search")["fail_fast"],
            true
        );
        for invalid in [
            serde_json::Value::Null,
            serde_json::json!("false"),
            serde_json::json!(1),
        ] {
            assert!(
                serde_json::from_value::<AdaptiveSearchOptions>(serde_json::json!({
                    "target_good": 1, "required_services": "all", "fail_fast": invalid,
                }))
                .is_err()
            );
        }
        assert!(
            new_bench_job(BenchMethod::Quick, 1, 1)
                .lock()
                .expect("lock default benchmark job")
                .search
                .is_none()
        );
    }

    #[test]
    fn adaptive_preflight_rejection_skips_every_other_probe_and_persistence() {
        for setup_failed in [false, true] {
            let outcome = run_adaptive_resource_probes(
                "ai",
                true,
                &AtomicBool::new(false),
                |passed| assert!(!passed),
                || {
                    if setup_failed {
                        Err("setup failed".to_owned())
                    } else {
                        Ok((
                            failed_resource_result("ping_proxy", "Proxy HTTPS ping", "unreachable"),
                            (),
                        ))
                    }
                },
                || panic!("direct probes must not run"),
                |_, _| panic!("services must not run"),
            )
            .expect("rejected preflight is not a cancellation");
            assert!(outcome.is_none());
        }
        let job = search_job(3, 1, 3);
        run_bench_with_probe(
            search_profiles(3),
            Arc::clone(&job),
            Arc::new(AtomicBool::new(false)),
            Box::new(|_| panic!("preflight rejects must not persist stats")),
            Some(Box::new(|_| {
                panic!("search must never invoke completion post-actions")
            })),
            |_, _, _, on_preflight, _| {
                on_preflight(false);
                None
            },
            || thread::sleep(Duration::from_millis(50)),
        )
        .expect("spawn rejecting search scheduler")
        .join()
        .expect("rejecting search scheduler exits cleanly");
        let state = job.lock().expect("lock rejected search state");
        let search = state.search.as_ref().expect("rejected search has progress");
        assert_eq!(state.completed, 3);
        assert!(state.results.is_empty());
        assert_eq!(search.preflight_completed, 3);
        assert_eq!(search.preflight_rejected, 3);
        assert_eq!(search.quick_completed, 0);
        assert_eq!(search.found_good, 0);
        assert_eq!(search.finish_reason.as_deref(), Some("exhausted"));
    }

    #[test]
    fn adaptive_probes_reuse_preflight_and_skip_unrequested_prefix_suffix() {
        for (required, count) in [("youtube", 1), ("telegram", 2), ("ai", 3)] {
            let calls = std::cell::RefCell::new(Vec::new());
            let tests = run_adaptive_resource_probes(
                required,
                true,
                &AtomicBool::new(false),
                |passed| assert!(passed),
                || {
                    calls.borrow_mut().push("preflight".to_owned());
                    Ok((
                        successful_resource_result(
                            "ping_proxy",
                            "Proxy HTTPS ping",
                            Duration::from_millis(7),
                        ),
                        123,
                    ))
                },
                || {
                    calls.borrow_mut().push("direct_skipped".to_owned());
                    Ok([("ping_icmp", "ICMP ping"), ("ping_tcp", "TCP ping")]
                        .into_iter()
                        .map(|(id, name)| {
                            skipped_resource_result(
                                id,
                                name,
                                "proxy preflight already proves reachability",
                            )
                        })
                        .collect())
                },
                |runtime, id| {
                    assert_eq!(*runtime, 123);
                    calls.borrow_mut().push(id.to_owned());
                    Ok(successful_resource_result(id, id, Duration::from_millis(1)))
                },
            )
            .expect("run injected prefix probes")
            .expect("prefix preflight passes");
            assert_eq!(&calls.borrow()[..2], &["preflight", "direct_skipped"]);
            assert_eq!(calls.borrow().len(), 2 + count);
            assert_eq!(
                tests.iter().filter(|test| test.id == "ping_proxy").count(),
                1
            );
            assert_eq!(tests[2].avg_ttfb_ms, 7);
            for test in tests.iter().take(2) {
                assert_eq!(test.attempts, 0);
                assert_eq!(test.successes, 0);
            }
            for test in tests.iter().skip(3 + count) {
                assert_eq!(test.attempts, 0);
                assert_eq!(test.successes, 0);
            }
            let mut result = search_result(&search_profiles(1)[0], required);
            assert!(adaptive_result_is_good(&result, required));
            assert_eq!(result.method, "search");
            assert!(result.success);
            assert!(result.error.is_none());
            assert_eq!(
                service_resource_outcome(&result.resource_tests, None).0,
                required == "ai"
            );
            result.resource_tests[2].reachable = false;
            assert!(!adaptive_result_is_good(&result, required));
            result.resource_tests.push(successful_resource_result(
                "ping_tcp",
                "TCP ping",
                Duration::from_millis(1),
            ));
            assert!(adaptive_result_is_good(&result, required));
            result.resource_tests[3].stable = false;
            assert!(!adaptive_result_is_good(&result, required));
            assert!(!adaptive_result_is_good(&result, "invalid"));
        }
        let tests = run_adaptive_resource_probes(
            "telegram",
            true,
            &AtomicBool::new(false),
            |passed| assert!(passed),
            || {
                Ok((
                    successful_resource_result(
                        "ping_proxy",
                        "Proxy HTTPS ping",
                        Duration::from_millis(1),
                    ),
                    (),
                ))
            },
            || Ok(Vec::new()),
            |_, id| {
                assert_eq!(id, "youtube");
                Ok(failed_resource_result(id, id, "failed"))
            },
        )
        .expect("run failed prefix probes")
        .expect("failed prefix still retains its successful preflight");
        assert_eq!(tests[2].attempts, 0);
        assert_eq!(
            tests[2].error.as_deref(),
            Some("skipped after YouTube failed")
        );
        assert_eq!(tests[3].attempts, 0);
    }

    #[test]
    fn adaptive_preflight_cancellation_does_not_start_quick() {
        let cancel = AtomicBool::new(false);
        let error = run_adaptive_resource_probes(
            "ai",
            true,
            &cancel,
            |_| panic!("cancelled preflight must not be counted"),
            || {
                cancel.store(true, Ordering::Relaxed);
                Ok((
                    successful_resource_result(
                        "ping_proxy",
                        "Proxy HTTPS ping",
                        Duration::from_millis(1),
                    ),
                    (),
                ))
            },
            || panic!("cancelled preflight must not start direct probes"),
            |_, _| panic!("cancelled preflight must not start services"),
        )
        .expect_err("preflight cancellation must propagate");
        assert_eq!(error, "benchmark cancelled");
    }

    #[test]
    fn adaptive_goodness_rejects_stale_contract_and_invalid_sample_counts() {
        let profile = &search_profiles(1)[0];
        for required in ["youtube", "telegram", "ai"] {
            let result = search_result(profile, required);
            for id in result
                .resource_tests
                .iter()
                .filter(|test| test.attempts > 0)
                .map(|test| test.id.as_str())
            {
                for invalid in 0..5 {
                    let mut invalid_result = result.clone();
                    let test = invalid_result
                        .resource_tests
                        .iter_mut()
                        .find(|test| test.id == id)
                        .expect("selected sample exists in cloned result");
                    match invalid {
                        0 => test.contract_version = QUICK_RESOURCE_CONTRACT_VERSION - 1,
                        1 => test.attempts = 0,
                        2 => test.successes = 0,
                        3 => test.successes = test.attempts + 1,
                        _ => test.id = "ping_invalid".to_owned(),
                    }
                    assert!(
                        !adaptive_result_is_good(&invalid_result, required),
                        "accepted invalid sample {id}, case {invalid}, prefix {required}"
                    );
                }
            }
        }
    }

    #[test]
    fn availability_methods_roundtrip_and_keep_legacy_method_names() {
        for (method, name, service, availability, fail_fast) in [
            (BenchMethod::Tcp, "tcp", false, false, false),
            (BenchMethod::Head, "head", false, false, false),
            (BenchMethod::Get, "get", false, false, false),
            (BenchMethod::Quick, "quick", true, false, true),
            (BenchMethod::Full, "full", true, false, false),
            (
                BenchMethod::AvailabilityQuick,
                "availability_quick",
                true,
                true,
                true,
            ),
            (
                BenchMethod::AvailabilityFull,
                "availability_full",
                true,
                true,
                false,
            ),
        ] {
            assert_eq!(method.as_str(), name);
            assert_eq!(
                BenchMethod::parse_method(&name.to_ascii_uppercase()),
                Some(method)
            );
            assert_eq!(
                serde_json::to_value(method).expect("serialize method"),
                name
            );
            assert_eq!(
                serde_json::from_value::<BenchMethod>(serde_json::json!(name))
                    .expect("deserialize method"),
                method
            );
            assert_eq!(method.is_service(), service);
            assert_eq!(method.is_availability(), availability);
            assert_eq!(method.is_fail_fast(), fail_fast);
        }
        assert_eq!(BenchMethod::parse_method("search_availability"), None);
    }

    #[test]
    fn adaptive_admission_accepts_only_legacy_and_availability_quick() {
        for method in [
            BenchMethod::Tcp,
            BenchMethod::Head,
            BenchMethod::Get,
            BenchMethod::Quick,
            BenchMethod::Full,
            BenchMethod::AvailabilityQuick,
            BenchMethod::AvailabilityFull,
        ] {
            let job = new_bench_job(method, 0, 1);
            job.lock().expect("job admission").search = Some(SearchProgress {
                target_good: 1,
                required_services: "youtube".to_owned(),
                ..SearchProgress::default()
            });
            let worker = run_bench(
                Vec::new(),
                method,
                DEFAULT_PROBE_URL.to_owned(),
                DEFAULT_DOWNLOAD_URL.to_owned(),
                DEFAULT_UPLOAD_URL.to_owned(),
                "unused-core".to_owned(),
                None,
                false,
                false,
                job,
                Arc::new(AtomicBool::new(false)),
                Box::new(|_| panic!("empty search has no results")),
                Some(Box::new(|_| panic!("search never runs post-actions"))),
            );
            if method.is_fail_fast() {
                worker
                    .expect("Quick search admission")
                    .join()
                    .expect("empty search finishes");
            } else {
                assert_eq!(
                    worker.err().as_deref(),
                    Some("adaptive search requires quick or availability_quick")
                );
            }
        }
    }

    #[test]
    fn availability_complete_scope_short_circuits_quick_but_continues_full() {
        for method in [
            BenchMethod::Quick,
            BenchMethod::Full,
            BenchMethod::AvailabilityQuick,
            BenchMethod::AvailabilityFull,
        ] {
            let mut calls = Vec::new();
            let tests = run_complete_service_probes(method, None, &AtomicBool::new(false), |id| {
                calls.push(id.to_owned());
                Ok(if id == "youtube" && method.is_availability() {
                    youtube_availability::unavailable()
                } else if id == "youtube" {
                    failed_resource_result(id, id, "failed")
                } else {
                    successful_resource_result(id, id, Duration::from_millis(1))
                })
            })
            .expect("complete service scope");
            assert_eq!(calls.len(), if method.is_fail_fast() { 1 } else { 3 });
            assert_eq!(tests.len(), 3);
            assert_eq!(
                tests[0].id,
                if method.is_availability() {
                    "youtube_thumbnails"
                } else {
                    "youtube"
                }
            );
            for test in tests.iter().skip(1) {
                assert_eq!(test.contract_version, QUICK_RESOURCE_CONTRACT_VERSION);
                assert_eq!(test.attempts, u32::from(!method.is_fail_fast()));
            }
        }
        let cancel = AtomicBool::new(false);
        let error =
            run_complete_service_probes(BenchMethod::AvailabilityFull, None, &cancel, |_| {
                cancel.store(true, Ordering::Relaxed);
                Ok(youtube_availability::unavailable())
            })
            .expect_err("cancel prevents Telegram stage");
        assert_eq!(error, "benchmark cancelled");
    }

    #[test]
    fn service_checks_prefix_and_fail_fast_are_independent_of_availability_method() {
        for method in [
            BenchMethod::AvailabilityQuick,
            BenchMethod::AvailabilityFull,
        ] {
            for (required_services, count) in [
                (ServiceCheckPrefix::Youtube, 1),
                (ServiceCheckPrefix::Telegram, 2),
                (ServiceCheckPrefix::Ai, 3),
                (ServiceCheckPrefix::All, 3),
            ] {
                for fail_fast in [false, true] {
                    for failure in [None, Some("youtube"), Some("telegram"), Some("ai")] {
                        let options = ServiceCheckOptions {
                            required_services,
                            fail_fast,
                            reject_no_ping: false,
                            full_ping: false,
                        };
                        let mut calls = Vec::new();
                        let tests = run_complete_service_probes(
                            method,
                            Some(&options),
                            &AtomicBool::new(false),
                            |id| {
                                calls.push(id.to_owned());
                                let mut test = if Some(id) == failure {
                                    failed_resource_result(id, id, "failed")
                                } else {
                                    successful_resource_result(id, id, Duration::from_millis(1))
                                };
                                if id == "youtube" {
                                    test.id = "youtube_thumbnails".to_owned();
                                    test.contract_version = YOUTUBE_AVAILABILITY_CONTRACT_VERSION;
                                }
                                Ok(test)
                            },
                        )
                        .expect("explicit ordinary service policy");
                        let expected = if fail_fast {
                            ["youtube", "telegram", "ai"]
                                .iter()
                                .position(|id| Some(*id) == failure)
                                .map_or(count, |index| count.min(index + 1))
                        } else {
                            count
                        };
                        assert_eq!(calls, ["youtube", "telegram", "ai"][..expected]);
                        assert_eq!(tests.len(), 3);
                        assert_eq!(tests[0].id, "youtube_thumbnails");
                        assert_eq!(
                            tests[0].contract_version,
                            YOUTUBE_AVAILABILITY_CONTRACT_VERSION
                        );
                        for test in tests.iter().skip(expected) {
                            assert_eq!(test.attempts, 0);
                            assert_eq!(test.successes, 0);
                        }
                        let mut resources = ["ping_icmp", "ping_tcp", "ping_proxy"]
                            .into_iter()
                            .map(|id| successful_resource_result(id, id, Duration::from_millis(1)))
                            .collect::<Vec<_>>();
                        resources.extend(tests);
                        let (success, selected_error) =
                            service_resource_outcome(&resources, Some(&options));
                        let selected_failed = ["youtube", "telegram", "ai"][..count]
                            .iter()
                            .any(|id| Some(*id) == failure);
                        assert_eq!(
                            success, !selected_failed,
                            "unrequested skipped services must not contaminate selected-prefix success"
                        );
                        assert!(!selected_error.contains("0/0"));
                    }
                }
            }
        }
    }

    #[test]
    fn service_checks_fail_fast_summary_excludes_skips_without_granting_incomplete_success() {
        let options = ServiceCheckOptions {
            required_services: ServiceCheckPrefix::All,
            fail_fast: true,
            reject_no_ping: false,
            full_ping: false,
        };
        let mut tests = vec![successful_resource_result(
            "ping_proxy",
            "Proxy HTTPS ping",
            Duration::from_millis(1),
        )];
        tests.extend(
            run_complete_service_probes(
                BenchMethod::AvailabilityFull,
                Some(&options),
                &AtomicBool::new(false),
                |id| {
                    assert_eq!(id, "youtube", "fail-fast must not attempt TG/AI");
                    let mut test =
                        failed_resource_result("youtube_thumbnails", "YouTube", "preview failed");
                    test.contract_version = YOUTUBE_AVAILABILITY_CONTRACT_VERSION;
                    Ok(test)
                },
            )
            .expect("failed preview is per-service evidence"),
        );
        let (success, error) = service_resource_outcome(&tests, Some(&options));
        assert!(!success);
        assert!(error.contains("YouTube"));
        assert!(!error.contains("Telegram"));
        assert!(!error.contains("AI Studio"));
        assert!(!error.contains("0/0"));
        let (_, legacy_error) = service_resource_outcome(&tests, None);
        assert!(legacy_error.contains("Telegram 0/0"));
        assert!(legacy_error.contains("AI Studio 0/0"));

        tests[1] =
            successful_resource_result("youtube_thumbnails", "YouTube", Duration::from_millis(1));
        tests[1].contract_version = YOUTUBE_AVAILABILITY_CONTRACT_VERSION;
        assert_eq!(
            service_resource_outcome(&tests, Some(&options)),
            (false, String::new()),
            "passing YT plus skipped TG/AI is not an all-services pass"
        );
        let youtube_only = ServiceCheckOptions {
            required_services: ServiceCheckPrefix::Youtube,
            fail_fast: true,
            reject_no_ping: false,
            full_ping: false,
        };
        assert_eq!(
            service_resource_outcome(&tests, Some(&youtube_only)),
            (true, String::new())
        );
        for invalid in 0..4 {
            let mut incomplete = tests.clone();
            match invalid {
                0 => {
                    incomplete.remove(1);
                }
                1 => incomplete[1].attempts = 0,
                2 => incomplete[1].contract_version = QUICK_RESOURCE_CONTRACT_VERSION,
                _ => incomplete[1].inconclusive = true,
            }
            assert!(!service_resource_outcome(&incomplete, Some(&youtube_only)).0);
        }
        tests.remove(0);
        assert!(
            !service_resource_outcome(&tests, Some(&youtube_only)).0,
            "existing ping evidence is still required"
        );
        assert!(!service_resource_outcome(&[], Some(&options)).0);
        assert!(
            service_resource_outcome(&[], None).0,
            "legacy empty aggregation is unchanged"
        );
    }

    #[test]
    fn ping_gate_skips_services_for_every_prefix_independently_of_fail_fast() {
        for required_services in [
            ServiceCheckPrefix::All,
            ServiceCheckPrefix::Youtube,
            ServiceCheckPrefix::Telegram,
            ServiceCheckPrefix::Ai,
        ] {
            for fail_fast in [false, true] {
                for reject_no_ping in [false, true] {
                    let options = ServiceCheckOptions {
                        required_services,
                        fail_fast,
                        reject_no_ping,
                        full_ping: false,
                    };
                    let pings = ["ping_icmp", "ping_tcp", "ping_proxy"]
                        .map(|id| failed_resource_result(id, id, "no response"));
                    let mut calls = Vec::new();
                    let tests = run_service_probes_after_ping(
                        BenchMethod::AvailabilityFull,
                        Some(&options),
                        &pings,
                        &AtomicBool::new(false),
                        |id| {
                            calls.push(id.to_owned());
                            let mut test =
                                successful_resource_result(id, id, Duration::from_millis(1));
                            if id == "youtube" {
                                test.id = "youtube_thumbnails".to_owned();
                                test.contract_version = YOUTUBE_AVAILABILITY_CONTRACT_VERSION;
                            }
                            Ok(test)
                        },
                    )
                    .expect("service checks");
                    if reject_no_ping {
                        assert!(
                            calls.is_empty(),
                            "no service/network call after failed ping"
                        );
                        assert!(tests.iter().all(|test| test.attempts == 0
                            && test.successes == 0
                            && !test.reachable));
                        assert!(
                            tests[0]
                                .error
                                .as_deref()
                                .is_some_and(|error| error.contains("reject_no_ping"))
                        );
                        assert_eq!(tests[0].id, "youtube_thumbnails");
                        assert_eq!(
                            tests[0].contract_version,
                            YOUTUBE_AVAILABILITY_CONTRACT_VERSION
                        );
                    } else {
                        assert!(!calls.is_empty(), "legacy continued checks retained");
                    }
                    let mut resources = pings.to_vec();
                    resources.extend(tests);
                    let (passed, error) = service_resource_outcome(&resources, Some(&options));
                    assert!(!passed);
                    assert!(error.contains("Ping failed"));
                    assert!(!error.contains("0/0"));
                    if reject_no_ping {
                        assert!(!error.contains("YouTube"));
                        assert!(!error.contains("Telegram"));
                    }
                }
            }
        }
    }

    #[test]
    fn ping_gate_accepts_any_successful_ping_and_preserves_cancellation() {
        let options = ServiceCheckOptions {
            required_services: ServiceCheckPrefix::All,
            fail_fast: false,
            reject_no_ping: true,
            full_ping: false,
        };
        for success in 0..3 {
            let mut pings = ["ping_icmp", "ping_tcp", "ping_proxy"]
                .map(|id| failed_resource_result(id, id, "no response"));
            let id = pings[success].id.clone();
            pings[success] = successful_resource_result(&id, &id, Duration::from_millis(1));
            let mut calls = 0;
            run_service_probes_after_ping(
                BenchMethod::AvailabilityFull,
                Some(&options),
                &pings,
                &AtomicBool::new(false),
                |id| {
                    calls += 1;
                    Ok(successful_resource_result(id, id, Duration::from_millis(1)))
                },
            )
            .expect("reachable server services");
            assert_eq!(calls, 3);
        }
        let error = run_service_probes_after_ping(
            BenchMethod::AvailabilityFull,
            Some(&options),
            &[],
            &AtomicBool::new(true),
            |_| panic!("cancelled services"),
        )
        .expect_err("cancelled gate");
        assert_eq!(error, "benchmark cancelled");
    }

    #[test]
    fn ping_gate_policy_is_optional_strict_and_roundtrips() {
        for reject_no_ping in [false, true] {
            let policy: ServiceCheckOptions = serde_json::from_value(serde_json::json!({
                "required_services":"youtube","fail_fast":false,"reject_no_ping":reject_no_ping
            }))
            .expect("boolean policy");
            assert_eq!(policy.reject_no_ping, reject_no_ping);
        }
        let legacy: ServiceCheckOptions =
            serde_json::from_str(r#"{"required_services":"youtube","fail_fast":false}"#)
                .expect("legacy policy");
        assert!(!legacy.reject_no_ping);
        for invalid in [
            serde_json::json!(null),
            serde_json::json!("true"),
            serde_json::json!(1),
        ] {
            assert!(
                serde_json::from_value::<ServiceCheckOptions>(serde_json::json!({
                    "required_services":"youtube","fail_fast":false,"reject_no_ping":invalid
                }))
                .is_err()
            );
        }
    }

    #[test]
    fn minimal_ping_avoids_direct_probes_and_full_ping_restores_them() {
        let cancel = AtomicBool::new(false);
        let skipped = run_direct_ping_diagnostics(
            false,
            &cancel,
            || panic!("minimal Ping must not spawn ICMP"),
            || panic!("minimal Ping must not resolve/connect TCP"),
        )
        .expect("minimal ping");
        assert_eq!(skipped.len(), 2);
        assert!(
            skipped
                .iter()
                .all(|test| test.attempts == 0 && !test.reachable)
        );
        let proxy = successful_resource_result("ping_proxy", "HTTPS", Duration::from_millis(42));
        assert_eq!(
            ping_metrics(&[skipped[0].clone(), skipped[1].clone(), proxy]).latency_ms,
            42
        );
        let full = run_direct_ping_diagnostics(
            true,
            &cancel,
            || {
                Ok(successful_resource_result(
                    "ping_icmp",
                    "ICMP",
                    Duration::from_millis(1),
                ))
            },
            || Ok(failed_resource_result("ping_tcp", "TCP", "no response")),
        )
        .expect("full ping");
        assert!(full.iter().all(|test| test.attempts == 1));
        assert!(full[0].reachable);
        assert!(!full[1].reachable);
        let cancelled = run_direct_ping_diagnostics(
            true,
            &cancel,
            || {
                cancel.store(true, Ordering::Relaxed);
                Ok(full[0].clone())
            },
            || panic!("cancelled TCP must not start"),
        );
        assert_eq!(cancelled.expect_err("cancelled"), "benchmark cancelled");
        assert!(
            run_direct_ping_diagnostics(
                false,
                &cancel,
                || panic!("cancelled ICMP"),
                || panic!("cancelled TCP"),
            )
            .is_err()
        );
    }

    #[test]
    fn full_ping_policy_is_optional_strict_and_roundtrips() {
        for full_ping in [false, true] {
            let policy: ServiceCheckOptions = serde_json::from_value(serde_json::json!({
                "required_services":"all", "fail_fast":false, "full_ping":full_ping
            }))
            .expect("boolean ping mode");
            assert_eq!(policy.full_ping, full_ping);
            let roundtrip: ServiceCheckOptions =
                serde_json::from_value(serde_json::to_value(&policy).expect("serialize"))
                    .expect("roundtrip");
            assert_eq!(roundtrip, policy);
        }
        let legacy: ServiceCheckOptions =
            serde_json::from_str(r#"{"required_services":"all","fail_fast":false}"#)
                .expect("omitted means minimal");
        assert!(!legacy.full_ping);
        for invalid in [
            serde_json::json!(null),
            serde_json::json!("true"),
            serde_json::json!(1),
        ] {
            assert!(
                serde_json::from_value::<ServiceCheckOptions>(serde_json::json!({
                    "required_services":"all", "fail_fast":false, "full_ping":invalid
                }))
                .is_err()
            );
        }
    }

    #[test]
    fn ping_gate_worker_reports_failed_candidate_without_attempting_services() {
        let mut profile = search_profiles(1).remove(0);
        profile.address.clear();
        let policy = QuickProbeConfig {
            telegram_session_path: String::new(),
            telegram: None,
            service_checks: Some(ServiceCheckOptions {
                required_services: ServiceCheckPrefix::All,
                fail_fast: false,
                reject_no_ping: true,
                full_ping: false,
            }),
        };
        let result = benchmark_profile(
            &profile,
            BenchMethod::AvailabilityFull,
            DEFAULT_PROBE_URL,
            DEFAULT_DOWNLOAD_URL,
            DEFAULT_UPLOAD_URL,
            "/definitely/missing/ping-gate-mihomo",
            Some(&policy),
            false,
            false,
            &AtomicBool::new(false),
        );
        assert!(!result.success);
        assert_eq!(result.resource_tests.len(), 6);
        assert!(
            result.resource_tests[..2]
                .iter()
                .all(|test| test.attempts == 0)
        );
        assert!(
            result
                .error
                .as_deref()
                .is_some_and(|error| error.contains("Ping failed"))
        );
        for test in result.resource_tests.iter().skip(3) {
            assert_eq!(test.attempts, 0);
            assert!(
                test.error
                    .as_deref()
                    .is_some_and(|error| error.contains("reject_no_ping"))
            );
        }
    }

    #[test]
    fn availability_without_policy_defaults_to_minimal_ping() {
        let mut profile = search_profiles(1).remove(0);
        profile.address.clear();
        let (_, tests) = run_service_resources(
            &profile,
            BenchMethod::AvailabilityFull,
            DEFAULT_PROBE_URL,
            "/definitely/missing/minimal-ping-mihomo",
            None,
            &AtomicBool::new(false),
        )
        .expect("unavailable core diagnostic");
        assert_eq!(tests.len(), 6);
        assert!(tests[..2].iter().all(|test| test.attempts == 0));
        assert_eq!(tests[2].id, "ping_proxy");
        assert_eq!(tests[2].attempts, 1);
    }

    #[test]
    fn service_checks_worker_captures_job_policy_without_adaptive_preflight() {
        let method = BenchMethod::AvailabilityFull;
        let mut profile = search_profiles(1).remove(0);
        profile.address.clear();
        let job = new_bench_job(method, 1, 1);
        job.lock().expect("job policy").service_checks = Some(ServiceCheckOptions {
            required_services: ServiceCheckPrefix::Youtube,
            fail_fast: false,
            reject_no_ping: false,
            full_ping: false,
        });
        run_bench(
            vec![profile],
            method,
            DEFAULT_PROBE_URL.to_owned(),
            DEFAULT_DOWNLOAD_URL.to_owned(),
            DEFAULT_UPLOAD_URL.to_owned(),
            "/definitely/missing/service-checks-mihomo".to_owned(),
            None,
            false,
            false,
            Arc::clone(&job),
            Arc::new(AtomicBool::new(false)),
            Box::new(|_| {}),
            None,
        )
        .expect("ordinary worker starts")
        .join()
        .expect("ordinary worker finishes");
        let state = job.lock().expect("completed ordinary job");
        assert!(state.search.is_none());
        assert!(state.preflight_failures.is_empty());
        assert_eq!(state.completed, 1);
        assert_eq!(
            state.results.len(),
            1,
            "setup failure is an ordinary result, not preflight rejection"
        );
        let result = &state.results[0];
        assert_eq!(result.method, "availability_full");
        assert!(!result.success);
        assert_eq!(result.resource_tests[3].id, "youtube_thumbnails");
        assert_eq!(
            result.resource_tests[3].contract_version,
            YOUTUBE_AVAILABILITY_CONTRACT_VERSION
        );
        assert_eq!(result.resource_tests[4].attempts, 0);
        assert_eq!(result.resource_tests[5].attempts, 0);
    }

    #[test]
    fn service_checks_errors_continue_unless_fail_fast_and_cancellation_always_interrupts() {
        for fail_fast in [false, true] {
            let options = ServiceCheckOptions {
                required_services: ServiceCheckPrefix::All,
                fail_fast,
                reject_no_ping: false,
                full_ping: false,
            };
            let mut calls = Vec::new();
            let tests = run_complete_service_probes(
                BenchMethod::AvailabilityFull,
                Some(&options),
                &AtomicBool::new(false),
                |id| {
                    calls.push(id.to_owned());
                    Err("service unavailable".to_owned())
                },
            )
            .expect("ordinary errors remain per-service evidence");
            assert_eq!(calls.len(), if fail_fast { 1 } else { 3 });
            assert_eq!(tests[0].id, "youtube_thumbnails");
            assert_eq!(
                tests[0].contract_version,
                YOUTUBE_AVAILABILITY_CONTRACT_VERSION
            );
            assert_eq!(tests[0].error.as_deref(), Some("service unavailable"));
            for cancelled in [false, true] {
                let cancel = AtomicBool::new(false);
                let error = run_complete_service_probes(
                    BenchMethod::AvailabilityFull,
                    Some(&options),
                    &cancel,
                    |_| {
                        cancel.store(cancelled, Ordering::Relaxed);
                        Err(if cancelled {
                            "interrupted"
                        } else {
                            "benchmark cancelled"
                        }
                        .to_owned())
                    },
                )
                .expect_err("cancellation is not a per-service failure");
                assert_eq!(error, "benchmark cancelled");
            }
        }
    }

    #[test]
    fn adaptive_availability_fail_fast_false_continues_selected_prefix_after_failure() {
        for (required, count) in [("youtube", 1), ("telegram", 2), ("ai", 3), ("all", 3)] {
            for fail_fast in [false, true] {
                let mut calls = Vec::new();
                let tests = run_adaptive_resource_probes(
                    required,
                    fail_fast,
                    &AtomicBool::new(false),
                    |passed| assert!(passed),
                    || {
                        Ok((
                            successful_resource_result(
                                "ping_proxy",
                                "Proxy HTTPS ping",
                                Duration::from_millis(1),
                            ),
                            (),
                        ))
                    },
                    || Ok(Vec::new()),
                    |_, id| {
                        calls.push(id.to_owned());
                        Ok(if id == "youtube" {
                            youtube_availability::unavailable()
                        } else {
                            successful_resource_result(id, id, Duration::from_millis(1))
                        })
                    },
                )
                .expect("adaptive policy")
                .expect("passing preflight retains failed service evidence");
                let attempted = if fail_fast { 1 } else { count };
                assert_eq!(calls.len(), attempted);
                assert_eq!(tests[1].id, "youtube_thumbnails");
                for test in tests.iter().skip(1 + attempted) {
                    assert_eq!(test.attempts, 0);
                }
            }
            let mut result = search_result(&search_profiles(1)[0], required);
            result.method = "search_availability".to_owned();
            result.resource_tests[3].id = "youtube_thumbnails".to_owned();
            result.resource_tests[3].contract_version = YOUTUBE_AVAILABILITY_CONTRACT_VERSION;
            assert!(adaptive_result_is_good(&result, required));
            assert_eq!(
                adaptive_result_is_good(&result, "all"),
                adaptive_result_is_good(&result, "ai")
            );
        }
    }

    #[test]
    fn adaptive_goodness_accepts_only_search_producers_even_with_valid_evidence() {
        for required in ["youtube", "telegram", "ai", "all"] {
            for producer in ["search", "search_availability"] {
                let mut result = search_result(&search_profiles(1)[0], required);
                result.method = producer.to_owned();
                if producer == "search_availability" {
                    result.resource_tests[3].id = "youtube_thumbnails".to_owned();
                    result.resource_tests[3].contract_version =
                        YOUTUBE_AVAILABILITY_CONTRACT_VERSION;
                }
                assert!(adaptive_result_is_good(&result, required));
                for unsupported in [
                    "",
                    "tcp",
                    "head",
                    "get",
                    "quick",
                    "full",
                    "availability_quick",
                    "availability_full",
                    "Search",
                    "search_unknown",
                    "search_availability_extra",
                ] {
                    result.method = unsupported.to_owned();
                    assert!(
                        !adaptive_result_is_good(&result, required),
                        "{unsupported} must fail closed for {producer} evidence"
                    );
                }
            }
        }
    }

    #[test]
    fn availability_search_goodness_never_confuses_thumbnail_and_native_evidence() {
        for required in ["youtube", "telegram", "ai"] {
            let mut result = search_result(&search_profiles(1)[0], required);
            assert!(adaptive_result_is_good(&result, required));
            result.method = "search_availability".to_owned();
            assert!(!adaptive_result_is_good(&result, required));
            let test = &mut result.resource_tests[3];
            test.id = "youtube_thumbnails".to_owned();
            test.contract_version = YOUTUBE_AVAILABILITY_CONTRACT_VERSION;
            assert!(adaptive_result_is_good(&result, required));
            for wrong_method in [
                "search",
                "quick",
                "full",
                "availability_quick",
                "search_availability_extra",
            ] {
                result.method = wrong_method.to_owned();
                assert!(!adaptive_result_is_good(&result, required));
            }
            result.method = "search_availability".to_owned();
            for invalid in 0..7 {
                let mut invalid_result = result.clone();
                let thumbnail = &mut invalid_result.resource_tests[3];
                match invalid {
                    0 => thumbnail.contract_version = QUICK_RESOURCE_CONTRACT_VERSION,
                    1 => thumbnail.inconclusive = true,
                    2 => thumbnail.stable = false,
                    3 => thumbnail.attempts = 0,
                    4 => thumbnail.successes = 0,
                    5 => thumbnail.successes = thumbnail.attempts + 1,
                    _ => thumbnail.reachable = false,
                }
                assert!(!adaptive_result_is_good(&invalid_result, required));
            }
            if required != "youtube" {
                result.resource_tests[4].contract_version = YOUTUBE_AVAILABILITY_CONTRACT_VERSION;
                assert!(!adaptive_result_is_good(&result, required));
            }
        }
    }

    #[test]
    fn adaptive_service_errors_retain_failed_results_but_cancel_propagates() {
        for failed_id in ["youtube", "telegram", "ai"] {
            let tests = run_adaptive_resource_probes(
                "ai",
                true,
                &AtomicBool::new(false),
                |passed| assert!(passed),
                || {
                    Ok((
                        successful_resource_result(
                            "ping_proxy",
                            "Proxy HTTPS ping",
                            Duration::from_millis(1),
                        ),
                        (),
                    ))
                },
                || Ok(Vec::new()),
                |_, id| {
                    if id == failed_id {
                        Err("service unavailable".to_owned())
                    } else {
                        Ok(successful_resource_result(id, id, Duration::from_millis(1)))
                    }
                },
            )
            .expect("ordinary service errors are represented in resource results")
            .expect("successful preflight retains the Quick outcome");
            let failed = tests
                .iter()
                .find(|test| test.id == failed_id)
                .expect("failed service is present");
            assert_eq!(failed.attempts, 1);
            assert_eq!(failed.successes, 0);
            assert!(!failed.stable);
            assert_eq!(failed.error.as_deref(), Some("service unavailable"));
            assert!(!service_resource_outcome(&tests, None).0);
        }
        for cancellation_flag in [false, true] {
            let cancel = AtomicBool::new(false);
            let error = run_adaptive_resource_probes(
                "ai",
                true,
                &cancel,
                |passed| assert!(passed),
                || {
                    Ok((
                        successful_resource_result(
                            "ping_proxy",
                            "Proxy HTTPS ping",
                            Duration::from_millis(1),
                        ),
                        (),
                    ))
                },
                || Ok(Vec::new()),
                |_, _| {
                    cancel.store(cancellation_flag, Ordering::Relaxed);
                    Err(if cancellation_flag {
                        "interrupted"
                    } else {
                        "benchmark cancelled"
                    }
                    .to_owned())
                },
            )
            .expect_err("service cancellation must not become a resource failure");
            assert_eq!(error, "benchmark cancelled");
        }

        let job = search_job(1, 1, 1);
        let persisted = Arc::new(Mutex::new(Vec::new()));
        let collected = Arc::clone(&persisted);
        run_bench_with_probe(
            search_profiles(1),
            Arc::clone(&job),
            Arc::new(AtomicBool::new(false)),
            Box::new(move |result| {
                collected
                    .lock()
                    .expect("lock failed-service collection")
                    .push(result)
            }),
            Some(Box::new(|_| {
                panic!("failed search must not invoke post-actions")
            })),
            |profile, required, cancel, on_preflight, _| {
                let required = required.expect("search admission supplies service prefix");
                let tests = run_adaptive_resource_probes(
                    required,
                    true,
                    cancel,
                    on_preflight,
                    || {
                        Ok((
                            successful_resource_result(
                                "ping_proxy",
                                "Proxy HTTPS ping",
                                Duration::from_millis(1),
                            ),
                            (),
                        ))
                    },
                    || Ok(Vec::new()),
                    |_, _| Err("service unavailable".to_owned()),
                )
                .expect("ordinary service error keeps probe outcome")
                .expect("ordinary service error keeps successful preflight");
                let attempted = tests
                    .iter()
                    .filter(|test| test.attempts > 0)
                    .cloned()
                    .collect::<Vec<_>>();
                let (_, error) = service_resource_outcome(&attempted, None);
                let mut result = search_result(profile, required);
                result.success = error.is_empty();
                result.error = (!error.is_empty()).then_some(error);
                result.resource_tests = tests;
                Some(result)
            },
            || thread::sleep(Duration::from_millis(50)),
        )
        .expect("spawn search with ordinary service error")
        .join()
        .expect("failed-service search scheduler exits cleanly");
        let state = job.lock().expect("lock failed-service search state");
        let search = state
            .search
            .as_ref()
            .expect("failed-service search has progress");
        assert_eq!(state.completed, 1);
        assert_eq!(state.results.len(), 1);
        assert!(!state.results[0].success);
        assert_eq!(
            persisted
                .lock()
                .expect("lock collected service failure")
                .len(),
            1
        );
        assert_eq!(search.preflight_completed, 1);
        assert_eq!(search.preflight_rejected, 0);
        assert_eq!(search.quick_completed, 1);
        assert_eq!(search.found_good, 0);
        assert_eq!(search.finish_reason.as_deref(), Some("exhausted"));
    }

    #[test]
    fn adaptive_scheduler_limits_in_flight_and_stops_without_cancel() {
        for target in [1, 2] {
            let job = search_job(12, target, 6);
            let observed_job = Arc::clone(&job);
            let cancel = Arc::new(AtomicBool::new(false));
            let persisted = Arc::new(Mutex::new(Vec::new()));
            let observed_persisted = Arc::clone(&persisted);
            run_bench_with_probe(
                search_profiles(12),
                Arc::clone(&job),
                Arc::clone(&cancel),
                Box::new(move |result| {
                    observed_persisted
                        .lock()
                        .expect("lock persisted search results")
                        .push(result)
                }),
                Some(Box::new(|_| panic!("target stop is intentionally partial"))),
                move |profile, required, _, on_preflight, _| {
                    let state = observed_job.lock().expect("lock admitted search candidate");
                    assert!(
                        state.active_profiles.len()
                            + state
                                .search
                                .as_ref()
                                .expect("admitted search has progress")
                                .found_good
                            <= target
                    );
                    drop(state);
                    on_preflight(true);
                    assert!(
                        observed_job
                            .lock()
                            .expect("lock preflight search progress")
                            .search
                            .as_ref()
                            .expect("preflight search has progress")
                            .preflight_completed
                            > 0
                    );
                    thread::sleep(Duration::from_millis(10));
                    Some(search_result(
                        profile,
                        required.expect("search admission supplies a service prefix"),
                    ))
                },
                || thread::sleep(Duration::from_millis(50)),
            )
            .expect("spawn target-limited search scheduler")
            .join()
            .expect("target-limited search scheduler exits cleanly");
            let state = job.lock().expect("lock completed target search");
            assert_eq!(state.completed, target);
            assert_eq!(state.total, 12);
            assert_eq!(state.results.len(), target);
            assert_eq!(
                persisted
                    .lock()
                    .expect("lock collected target results")
                    .len(),
                target
            );
            assert!(!cancel.load(Ordering::Relaxed));
            let search = state.search.as_ref().expect("target search has progress");
            assert_eq!(search.found_good, target);
            assert_eq!(search.quick_completed, target);
            assert_eq!(search.finish_reason.as_deref(), Some("target_reached"));
        }
    }

    #[test]
    fn adaptive_scheduler_reuses_waiting_workers_after_failed_reservation() {
        fn wait_until(cancel: &AtomicBool, ready: impl Fn() -> bool) {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !cancel.load(Ordering::Relaxed) && !ready() {
                if Instant::now() >= deadline {
                    cancel.store(true, Ordering::Relaxed);
                    break;
                }
                thread::sleep(Duration::from_millis(1));
            }
        }

        let job = search_job(4, 2, 4);
        let cancel = Arc::new(AtomicBool::new(false));
        let phase = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (events_tx, events_rx) = std::sync::mpsc::channel();
        let probe_events = events_tx.clone();
        let probe_phase = Arc::clone(&phase);
        let probe_job = Arc::clone(&job);
        let wait_phase = Arc::clone(&phase);
        let wait_job = Arc::clone(&job);
        let wait_cancel = Arc::clone(&cancel);
        let handle = run_bench_with_probe(
            search_profiles(4),
            Arc::clone(&job),
            Arc::clone(&cancel),
            Box::new(|_| {}),
            Some(Box::new(|_| {
                panic!("search never invokes completion post-actions")
            })),
            move |profile, required, cancel, on_preflight, _| {
                assert!(
                    probe_job
                        .lock()
                        .expect("lock reserved test candidate")
                        .active_profiles
                        .len()
                        <= 2
                );
                probe_events
                    .send((thread::current().id(), Some(profile.id)))
                    .expect("report reserved test candidate");
                wait_until(cancel, || {
                    probe_phase.load(Ordering::Relaxed) >= if profile.id == 0 { 1 } else { 2 }
                });
                if profile.id == 0 {
                    on_preflight(false);
                    None
                } else {
                    on_preflight(true);
                    Some(search_result(
                        profile,
                        required.expect("reserved search has a service prefix"),
                    ))
                }
            },
            move || {
                if wait_phase.load(Ordering::Relaxed) == 0 {
                    events_tx
                        .send((thread::current().id(), None))
                        .expect("report initially saturated worker");
                    wait_until(&wait_cancel, || wait_phase.load(Ordering::Relaxed) >= 1);
                } else {
                    wait_until(&wait_cancel, || {
                        if wait_phase.load(Ordering::Relaxed) >= 2 {
                            return true;
                        }
                        let state = wait_job.lock().expect("inspect released test reservation");
                        state.completed == 1 && state.active_profiles.len() == 2
                    });
                    if wait_phase.load(Ordering::Relaxed) < 2
                        && !wait_cancel.load(Ordering::Relaxed)
                    {
                        events_tx
                            .send((thread::current().id(), None))
                            .expect("report worker retry after failed reservation");
                        wait_until(&wait_cancel, || wait_phase.load(Ordering::Relaxed) >= 2);
                    }
                }
            },
        )
        .expect("spawn deterministic saturated-worker regression");

        // Hold both reservations until every excess worker has entered the wait
        // path. After failure, hold the replacement and observe the entire pool.
        let mut initially_waiting = Vec::new();
        let mut surviving_probe = None;
        for _ in 0..4 {
            let (worker, profile) = events_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("all four workers reach reserved or waiting state");
            match profile {
                None => initially_waiting.push(worker),
                Some(1) => surviving_probe = Some(worker),
                Some(0) => {}
                _ => panic!("no replacement is admitted before a reservation fails"),
            }
        }
        assert_eq!(initially_waiting.len(), 2);
        phase.store(1, Ordering::Relaxed);
        let mut resumed = std::collections::HashSet::new();
        let mut replacement_seen = false;
        while resumed.len() < 3 {
            let (worker, profile) = events_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("idle workers return to scheduling after the failed reservation");
            assert!(profile.is_none() || profile == Some(2));
            replacement_seen |= profile == Some(2);
            resumed.insert(worker);
        }
        assert!(replacement_seen);
        assert!(
            initially_waiting
                .iter()
                .all(|worker| resumed.contains(worker))
        );
        assert!(
            !resumed.contains(&surviving_probe.expect("one original reservation remains active"))
        );
        {
            let state = job.lock().expect("inspect restored parallel reservations");
            assert_eq!(state.completed, 1);
            assert_eq!(state.active_profiles.len(), 2);
        }
        phase.store(2, Ordering::Relaxed);
        handle
            .join()
            .expect("retained worker pool reaches its target");
        let state = job.lock().expect("inspect retained-worker search outcome");
        assert_eq!(state.completed, 3);
        assert_eq!(state.results.len(), 2);
        assert_eq!(
            state
                .search
                .as_ref()
                .expect("retained-worker search has progress")
                .found_good,
            2
        );
        assert!(!cancel.load(Ordering::Relaxed));
    }

    #[test]
    fn adaptive_scheduler_counts_raw_uniquely_and_preserves_results_on_cancel() {
        for cancelled in [false, true] {
            let job = search_job(3, 2, 1);
            let mut profiles = search_profiles(3);
            profiles[1].raw = profiles[0].raw.clone();
            run_bench_with_probe(
                profiles,
                Arc::clone(&job),
                Arc::new(AtomicBool::new(false)),
                Box::new(|_| {}),
                Some(Box::new(|_| panic!("no search post-actions"))),
                move |profile, required, cancel, on_preflight, _| {
                    if cancelled && profile.id == 1 {
                        cancel.store(true, Ordering::Relaxed);
                        return None;
                    }
                    on_preflight(true);
                    Some(search_result(
                        profile,
                        required.expect("search admission supplies a service prefix"),
                    ))
                },
                || thread::sleep(Duration::from_millis(50)),
            )
            .expect("spawn deduplicating search scheduler")
            .join()
            .expect("deduplicating search scheduler exits cleanly");
            let state = job.lock().expect("lock deduplicated search state");
            let search = state
                .search
                .as_ref()
                .expect("deduplicated search has progress");
            assert_eq!(state.completed, if cancelled { 1 } else { 3 });
            assert_eq!(state.results.len(), state.completed);
            assert_eq!(search.found_good, if cancelled { 1 } else { 2 });
            assert_eq!(
                search.finish_reason.as_deref(),
                Some(if cancelled {
                    "cancelled"
                } else {
                    "target_reached"
                })
            );
            assert!(!state.running);
            assert!(state.active_profiles.is_empty());
        }
    }

    #[test]
    fn run_bench_skips_completion_callback_after_cancellation() {
        let job = new_bench_job(BenchMethod::Quick, 0, 1);
        let cancel = Arc::new(AtomicBool::new(true));
        let completed = Arc::new(AtomicBool::new(false));
        let completed_for_callback = Arc::clone(&completed);
        let handle = run_bench(
            Vec::new(),
            BenchMethod::Quick,
            String::new(),
            String::new(),
            String::new(),
            "mihomo".to_owned(),
            None,
            false,
            false,
            job,
            cancel,
            Box::new(|_| {}),
            Some(Box::new(move |_| {
                completed_for_callback.store(true, Ordering::Relaxed);
                Vec::new()
            })),
        )
        .expect("spawn cancelled benchmark");
        handle.join().expect("cancelled benchmark exits");
        assert!(!completed.load(Ordering::Relaxed));
    }

    #[test]
    fn benchmark_concurrency_four_creates_four_profile_workers() {
        assert_eq!(benchmark_worker_count(4, 8), 4);
        assert_eq!(benchmark_worker_count(4, 2), 2);
        assert_eq!(benchmark_worker_count(9, 8), 6);
        for (requested, total, expected_requested, expected_workers) in
            [(0, 8, 1, 1), (4, 2, 4, 2), (9, 8, 6, 6)]
        {
            let job = new_bench_job(BenchMethod::Quick, total, requested);
            let state = job
                .lock()
                .expect("inspect requested and effective worker counts");
            assert_eq!(state.requested_concurrency, expected_requested);
            assert_eq!(state.worker_count, expected_workers);
            assert!(!state.memory_limited);
        }
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
        let completed = Arc::new(Mutex::new(Vec::<Vec<BenchResult>>::new()));
        let completed_for_callback = Arc::clone(&completed);
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
            Some(Box::new(move |mut results| {
                results[0].profile_id = 99;
                completed_for_callback
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .push(results.clone());
                results
            })),
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
        drop(results);
        let completed = completed
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].len(), 1);
        assert_eq!(completed[0][0].profile_id, 99);
        assert_eq!(
            job.lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .results[0]
                .profile_id,
            99
        );
    }
}
