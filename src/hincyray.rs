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
    sync::{Arc, Mutex, MutexGuard},
    thread,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::profiles::{Profile, load_subscription_detailed, parse_input};
use crate::xray_config::build_xray_config;

const DEFAULT_LISTEN: &str = "0.0.0.0:8088";
const MAX_BODY_BYTES: usize = 1024 * 1024;

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

/// Placeholder for future policy-routing rules (e.g. per-SSID / per-device
/// traffic steering). Stored now so future migrations do not need to
/// restructure the state file.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RoutingRule {
    pub name: String,
    pub kind: String,
    pub pattern: String,
    pub target: String,
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

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
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
        ("POST", "/api/active-profile") => handle_set_active(body, daemon),
        ("GET", "/api/xray/config") => handle_get_xray_config(daemon),
        ("POST", "/api/core/start") => handle_core_start(daemon),
        ("POST", "/api/core/stop") => handle_core_stop(daemon),
        ("POST", "/api/core/restart") => handle_core_restart(daemon),
        _ => (
            404,
            "application/json",
            json!({"error": "not found", "path": path}).to_string(),
        ),
    }
}

fn handle_import(body: &str, daemon: &Daemon) -> (u16, &'static str, String) {
    let parsed = parse_input(body);
    let mut incoming = parsed.profiles;
    let mut errors: Vec<String> = Vec::new();

    for source in &parsed.subscriptions {
        match load_subscription_detailed(source) {
            Ok(report) => incoming.extend(report.profiles),
            Err(error) => errors.push(error),
        }
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
        }
    }
    let count_after = inner.state.profiles.len();
    let added = count_after.saturating_sub(count_before);

    if let Err(error) = persist_state(&daemon.state_path, &inner.state) {
        errors.push(format!("persist: {error}"));
    }

    let response = json!({
        "profile_count": count_after,
        "added": added,
        "subscriptions": parsed.subscriptions.len(),
        "candidate_count": parsed.candidates,
        "unsupported_placeholders": parsed.unsupported_placeholders,
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

    let listen_host = inner.state.listen_host.clone();
    let socks_port = inner.state.socks_port;
    let config = match build_xray_config(&profile, &listen_host, socks_port) {
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

    inner.state.active_profile_id = Some(id);
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
    let Some(id) = inner.state.active_profile_id else {
        return (
            400,
            "application/json",
            json!({"error": "no active profile"}).to_string(),
        );
    };
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
            json!({"error": "active profile missing"}).to_string(),
        );
    };
    let listen_host = inner.state.listen_host.clone();
    let socks_port = inner.state.socks_port;
    match build_xray_config(&profile, &listen_host, socks_port) {
        Ok(config) => (200, "application/json", config.to_string()),
        Err(error) => (
            400,
            "application/json",
            json!({"error": error, "profile_id": id}).to_string(),
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
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;max-width:1100px;margin:1.4em auto;padding:0 .8em;color:#1f2328;background:#f6f8fa}
h1{margin:0 0 .15em;font-size:1.6em}
h2{margin:1.3em 0 .4em;font-size:1.05em;border-bottom:1px solid #d0d7de;padding-bottom:.25em}
.subtle{color:#57606a;font-size:.88em}
code{background:#eaeef2;padding:.12em .35em;border-radius:4px;font-size:.88em}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:.6em;margin:.7em 0}
.card{background:#fff;border:1px solid #d0d7de;border-radius:6px;padding:.55em .75em}
.card .label{color:#57606a;font-size:.75em;text-transform:uppercase;letter-spacing:.04em}
.card .value{font-size:.95em;margin-top:.18em;word-break:break-all}
.badge{display:inline-block;padding:.12em .5em;border-radius:12px;font-size:.78em;font-weight:600}
.badge.ok{background:#dafbe1;color:#1a7f37}
.badge.stop{background:#ffebe9;color:#cf222e}
button{font:inherit;padding:.34em .8em;border:1px solid #1f2328;background:#f6f8fa;border-radius:5px;cursor:pointer}
button:hover{background:#eaeef2}
button.primary{background:#1f6feb;color:#fff;border-color:#1f6feb}
button.primary:hover{background:#218bff}
.row{display:flex;gap:.5em;flex-wrap:wrap;align-items:center}
textarea{width:100%;min-height:108px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85em;padding:.5em;border:1px solid #d0d7de;border-radius:6px;box-sizing:border-box}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #d0d7de;border-radius:6px;overflow:hidden}
th,td{padding:.4em .6em;text-align:left;border-bottom:1px solid #eaeef2;font-size:.9em;vertical-align:middle}
th{background:#eaeef2;font-weight:600}
tr:last-child td{border-bottom:none}
tr.active{background:#fff8c5}
.msg{margin:.6em 0;padding:.55em .75em;border-radius:6px;font-size:.9em;display:none}
.msg.err{background:#ffebe9;border:1px solid #ff8182;color:#82071e;display:block}
.msg.ok{background:#dafbe1;border:1px solid #4ac26b;color:#1a7f37;display:block}
pre{background:#1f2328;color:#e6edf3;padding:.7em;border-radius:6px;overflow:auto;max-height:420px;font-size:.82em}
</style>
</head>
<body>
<h1>HincyRay daemon</h1>
<p class="subtle">Lightweight Keenetic VPN/proxy panel &middot; MVP. Talks to the local JSON API over fetch.</p>

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

<h2>Import</h2>
<p class="subtle">Paste a subscription URL, direct share links (<code>vless://</code>, <code>hysteria2://</code>), or an Xray JSON config; one per line or mixed.</p>
<textarea id="import-text" placeholder="https://example.com/sub&#10;vless://...&#10;{ &quot;outbounds&quot;: [...] }"></textarea>
<div class="row" style="margin-top:.4em">
  <button class="primary" id="btn-import">Import</button>
  <span class="subtle" id="import-status"></span>
</div>

<h2>Profiles</h2>
<table>
  <thead><tr><th>Active</th><th>ID</th><th>Name</th><th>Protocol</th><th>Transport</th><th>Address:port</th><th></th></tr></thead>
  <tbody id="profiles-body"><tr><td colspan="7" class="subtle">No profiles yet.</td></tr></tbody>
</table>

<h2>Generated Xray config</h2>
<div class="row">
  <button id="btn-load-config">Load / show</button>
  <span class="subtle">Fetches <code>GET /api/xray/config</code> for the active profile.</span>
</div>
<pre id="xray-config">&mdash;</pre>

<hr class="subtle">
<p class="subtle">HincyRay daemon &middot; API: <code>/api/health</code>, <code>/api/status</code>, <code>/api/profiles</code>, <code>/api/xray/config</code>, <code>/api/core/*</code>.</p>

<script>
(function(){
"use strict";
var msgEl = document.getElementById("msg");
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

function renderProfiles(profiles){
  var tbody = document.getElementById("profiles-body");
  if(!profiles || !profiles.length){
    tbody.innerHTML = '<tr><td colspan="7" class="subtle">No profiles yet. Import above.</td></tr>';
    return;
  }
  var rows = profiles.map(function(p){
    var addr = esc(p.address) + ":" + (p.port == null ? "?" : p.port);
    var activeMark = p.active ? '<span class="badge ok">active</span>' : '';
    return '<tr class="' + (p.active ? "active" : "") + '">'
      + '<td>' + activeMark + '</td>'
      + '<td>' + p.id + '</td>'
      + '<td>' + esc(p.name) + '</td>'
      + '<td>' + esc(p.protocol) + '</td>'
      + '<td>' + esc(p.transport) + '</td>'
      + '<td>' + addr + '</td>'
      + '<td><button class="select-btn" data-id="' + p.id + '">Select</button></td>'
      + '</tr>';
  });
  tbody.innerHTML = rows.join("");
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
}

function refreshAll(){
  return Promise.all([ api("GET","/api/status"), api("GET","/api/profiles") ])
    .then(function(results){
      renderStatus(results[0]);
      renderProfiles(results[1].profiles || []);
    })
    .catch(function(err){ setMsg("Refresh failed: " + err.message); });
}

function coreAction(path, label){
  api("POST", path).then(function(data){
    showOk(label + " &rarr; " + (data && data.core_status ? data.core_status : "ok"));
    return refreshAll();
  }).catch(function(err){ setMsg(label + " failed: " + err.message); });
}

document.getElementById("btn-refresh").addEventListener("click", function(){ clearMsg(); refreshAll(); });
document.getElementById("btn-start").addEventListener("click", function(){ coreAction("/api/core/start", "Start core"); });
document.getElementById("btn-stop").addEventListener("click", function(){ coreAction("/api/core/stop", "Stop core"); });
document.getElementById("btn-restart").addEventListener("click", function(){ coreAction("/api/core/restart", "Restart core"); });

document.getElementById("btn-import").addEventListener("click", function(){
  var text = document.getElementById("import-text").value.trim();
  if(!text){ setMsg("Paste something first."); return; }
  var status = document.getElementById("import-status");
  status.textContent = "Importing…";
  api("POST", "/api/profiles/import", text).then(function(data){
    status.textContent = "";
    var parts = ["added " + data.added, "total " + data.profile_count];
    if(data.errors && data.errors.length){
      setMsg("Import finished with errors: " + data.errors.join("; "), "err");
    } else {
      showOk("Imported: " + parts.join(", "));
    }
    document.getElementById("import-text").value = "";
    return refreshAll();
  }).catch(function(err){
    status.textContent = "";
    setMsg("Import failed: " + err.message);
  });
});

document.getElementById("btn-load-config").addEventListener("click", function(){
  api("GET", "/api/xray/config").then(function(data){
    document.getElementById("xray-config").textContent = JSON.stringify(data, null, 2);
  }).catch(function(err){ setMsg("Load config failed: " + err.message); });
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
}
