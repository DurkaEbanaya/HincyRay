use std::{
    fs::File,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::Sender,
    },
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use url::Url;

use crate::mihomo_config::build_mihomo_bench_config;
use crate::profiles::{Profile, Protocol};
use crate::scoring::quality_score;
use crate::xray_config::{build_xray_config, percent_decode, query_value};

#[derive(Clone, Debug)]
pub enum TestUpdate {
    Started { total: usize },
    Running { profile_id: usize },
    Result(TestResult),
    Finished,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestResult {
    pub profile_id: usize,
    pub latency_ms: u32,
    pub jitter_ms: u32,
    pub download_mbps: f32,
    pub loss_percent: f32,
    pub score: u32,
    pub status: TestStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TestStatus {
    Pending,
    Running,
    Passed,
    Failed(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestSettings {
    pub probe_urls: Vec<String>,
    pub download_urls: Vec<String>,
    pub download_seconds: u64,
}

impl Default for TestSettings {
    fn default() -> Self {
        Self {
            probe_urls: vec![
                "https://www.cloudflare.com/cdn-cgi/trace".to_owned(),
                "https://detectportal.firefox.com/success.txt".to_owned(),
                "https://www.gstatic.com/generate_204".to_owned(),
            ],
            download_urls: vec![
                "https://proof.ovh.net/files/100Mb.dat".to_owned(),
                "https://download.thinkbroadband.com/100MB.zip".to_owned(),
                "https://ash-speed.hetzner.com/100MB.bin".to_owned(),
            ],
            download_seconds: 5,
        }
    }
}

pub fn spawn_benchmark(
    profiles: Vec<Profile>,
    settings: TestSettings,
    cancel: Arc<AtomicBool>,
    sender: Sender<TestUpdate>,
) {
    thread::spawn(move || {
        let total = profiles.len();
        let _ = sender.send(TestUpdate::Started { total });

        for profile in profiles {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            let _ = sender.send(TestUpdate::Running {
                profile_id: profile.id,
            });
            let result = benchmark_profile(&profile, &settings);
            let _ = sender.send(TestUpdate::Result(result));
        }

        let _ = sender.send(TestUpdate::Finished);
    });
}

fn benchmark_profile(profile: &Profile, settings: &TestSettings) -> TestResult {
    match run_proxy_test(profile, settings) {
        Ok(metrics) => TestResult {
            profile_id: profile.id,
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
            status: TestStatus::Passed,
        },
        Err(error) => TestResult {
            profile_id: profile.id,
            latency_ms: 0,
            jitter_ms: 0,
            download_mbps: 0.0,
            loss_percent: 100.0,
            score: 0,
            status: TestStatus::Failed(error),
        },
    }
}

fn run_proxy_test(profile: &Profile, settings: &TestSettings) -> Result<Metrics, String> {
    run_mihomo_test(profile, settings)
}

struct Metrics {
    latency_ms: u32,
    jitter_ms: u32,
    download_mbps: f32,
    loss_percent: f32,
}

#[allow(dead_code)]
fn run_xray_test(profile: &Profile, settings: &TestSettings) -> Result<Metrics, String> {
    ensure_xray_available()?;

    let port = reserve_local_port()?;
    let config = build_xray_config(profile, "127.0.0.1", port)?;
    let mut config_file = NamedTempFile::new().map_err(|error| error.to_string())?;
    serde_json::to_writer_pretty(&mut config_file, &config).map_err(|error| error.to_string())?;
    config_file.flush().map_err(|error| error.to_string())?;
    let stderr_file = NamedTempFile::new().map_err(|error| error.to_string())?;
    let stderr_writer = stderr_file.reopen().map_err(|error| error.to_string())?;

    let mut child = Command::new("xray")
        .arg("run")
        .arg("-format")
        .arg("json")
        .arg("-c")
        .arg(config_file.path())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr_writer))
        .spawn()
        .map_err(|error| format!("xray не запустился: {error}"))?;

    let result = run_proxy_metrics(port, &mut child, settings);
    stop_child(&mut child);

    result.map_err(|error| append_core_stderr("xray", error, stderr_file.path()))
}

#[allow(dead_code)]
fn run_sing_box_test(profile: &Profile, settings: &TestSettings) -> Result<Metrics, String> {
    ensure_sing_box_available()?;

    let port = reserve_local_port()?;
    let config = build_sing_box_config(profile, port)?;
    let mut config_file = NamedTempFile::new().map_err(|error| error.to_string())?;
    serde_json::to_writer_pretty(&mut config_file, &config).map_err(|error| error.to_string())?;
    config_file.flush().map_err(|error| error.to_string())?;
    let stderr_file = NamedTempFile::new().map_err(|error| error.to_string())?;
    let stderr_writer = stderr_file.reopen().map_err(|error| error.to_string())?;

    let mut child = Command::new("sing-box")
        .arg("run")
        .arg("-c")
        .arg(config_file.path())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr_writer))
        .spawn()
        .map_err(|error| format!("sing-box не запустился: {error}"))?;

    let result = run_proxy_metrics(port, &mut child, settings);
    stop_child(&mut child);

    result.map_err(|error| append_core_stderr("sing-box", error, stderr_file.path()))
}

#[allow(dead_code)]
fn ensure_sing_box_available() -> Result<(), String> {
    Command::new("sing-box")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| "sing-box не найден в PATH".to_owned())?
        .success()
        .then_some(())
        .ok_or_else(|| "sing-box установлен, но команда version завершилась ошибкой".to_owned())
}

#[allow(dead_code)]
fn ensure_xray_available() -> Result<(), String> {
    Command::new("xray")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| "xray не найден в PATH, он нужен для VLESS XHTTP".to_owned())?
        .success()
        .then_some(())
        .ok_or_else(|| "xray установлен, но команда version завершилась ошибкой".to_owned())
}

fn ensure_mihomo_available() -> Result<(), String> {
    Command::new("mihomo")
        .arg("v")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| {
            "mihomo не найден в PATH. Установите: brew install mihomo (macOS) или скачайте с GitHub"
                .to_owned()
        })?
        .success()
        .then_some(())
        .ok_or_else(|| "mihomo установлен, но команда -v завершилась ошибкой".to_owned())
}

fn run_mihomo_test(profile: &Profile, settings: &TestSettings) -> Result<Metrics, String> {
    ensure_mihomo_available()?;

    let port = reserve_local_port()?;
    let config_yaml = build_mihomo_bench_config(profile, "127.0.0.1", port)?;
    let mut config_file = NamedTempFile::with_suffix(".yaml").map_err(|error| error.to_string())?;
    config_file
        .write_all(config_yaml.as_bytes())
        .map_err(|error| error.to_string())?;
    config_file.flush().map_err(|error| error.to_string())?;
    let stderr_file = NamedTempFile::new().map_err(|error| error.to_string())?;
    let stderr_writer = stderr_file.reopen().map_err(|error| error.to_string())?;

    let mut child = Command::new("mihomo")
        .arg("-f")
        .arg(config_file.path())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr_writer))
        .spawn()
        .map_err(|error| format!("mihomo не запустился: {error}"))?;

    let result = run_proxy_metrics(port, &mut child, settings);
    stop_child(&mut child);

    result.map_err(|error| append_core_stderr("mihomo", error, stderr_file.path()))
}

fn reserve_local_port() -> Result<u16, String> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|error| error.to_string())?;
    let port = listener
        .local_addr()
        .map_err(|error| error.to_string())?
        .port();
    drop(listener);
    Ok(port)
}

fn run_proxy_metrics(
    port: u16,
    child: &mut Child,
    settings: &TestSettings,
) -> Result<Metrics, String> {
    wait_until_proxy_ready(port, child, settings)?;

    let mut latencies = Vec::new();
    let mut failures = 0;
    for _ in 0..3 {
        match probe_latency(port, &settings.probe_urls) {
            Ok(latency) => latencies.push(latency),
            Err(_) => failures += 1,
        }
        thread::sleep(Duration::from_millis(120));
    }

    if latencies.is_empty() {
        return Err("все probe-запросы через proxy завершились ошибкой".to_owned());
    }

    let download_mbps = measure_download(port, settings)?;
    let latency_ms = average_duration_ms(&latencies);
    let jitter_ms = jitter_duration_ms(&latencies);
    let loss_percent = failures as f32 / 3.0 * 100.0;

    Ok(Metrics {
        latency_ms,
        jitter_ms,
        download_mbps,
        loss_percent,
    })
}

fn wait_until_proxy_ready(
    port: u16,
    child: &mut Child,
    settings: &TestSettings,
) -> Result<(), String> {
    let started = Instant::now();
    let mut last_error = String::new();

    while started.elapsed() < Duration::from_secs(8) {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            return Err(format!("sing-box завершился раньше времени: {status}"));
        }

        if TcpStream::connect(("127.0.0.1", port)).is_err() {
            thread::sleep(Duration::from_millis(100));
            continue;
        }

        match probe_latency(port, &settings.probe_urls) {
            Ok(_) => return Ok(()),
            Err(error) => last_error = error,
        }
        thread::sleep(Duration::from_millis(250));
    }

    Err(format!("проверка соединения не прошла: {last_error}"))
}

fn probe_latency(port: u16, urls: &[String]) -> Result<Duration, String> {
    let mut errors = Vec::new();

    for url in urls.iter().filter(|url| !url.trim().is_empty()) {
        let started = Instant::now();
        match curl_probe(port, url) {
            Ok(_) => return Ok(started.elapsed()),
            Err(error) => errors.push(format!("{url}: {error}")),
        }
    }

    if errors.is_empty() {
        Err("probe endpoints list is empty".to_owned())
    } else {
        Err(errors.join(" | "))
    }
}

fn curl_probe(port: u16, url: &str) -> Result<(), String> {
    let output = Command::new("curl")
        .arg("--socks5-hostname")
        .arg(format!("127.0.0.1:{port}"))
        .arg("-L")
        .arg("--max-time")
        .arg("6")
        .arg("--silent")
        .arg("--show-error")
        .arg("--output")
        .arg("/dev/null")
        .arg("--write-out")
        .arg("%{http_code}")
        .arg(url)
        .output()
        .map_err(|error| format!("curl не запустился: {error}"))?;

    let http_code = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if output.status.success() && http_code.starts_with('2') {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "curl rc {:?}, http {http_code}, {stderr}",
            output.status.code()
        ))
    }
}

fn measure_download(port: u16, settings: &TestSettings) -> Result<f32, String> {
    let mut errors = Vec::new();

    for url in settings
        .download_urls
        .iter()
        .filter(|url| !url.trim().is_empty())
    {
        match curl_download(port, url, settings.download_seconds) {
            Ok(speed_mbps) if speed_mbps > 0.0 => return Ok(speed_mbps),
            Ok(_) => errors.push(format!("{url}: zero speed")),
            Err(error) => errors.push(format!("{url}: {error}")),
        }
    }

    if errors.is_empty() {
        Err("download endpoints list is empty".to_owned())
    } else {
        Err(format!("download endpoints failed: {}", errors.join(" | ")))
    }
}

fn curl_download(port: u16, url: &str, download_seconds: u64) -> Result<f32, String> {
    let output = Command::new("curl")
        .arg("--socks5-hostname")
        .arg(format!("127.0.0.1:{port}"))
        .arg("-L")
        .arg("--max-time")
        .arg(download_seconds.clamp(1, 60).to_string())
        .arg("--range")
        .arg("0-104857599")
        .arg("--silent")
        .arg("--show-error")
        .arg("--output")
        .arg("/dev/null")
        .arg("--write-out")
        .arg("%{http_code} %{size_download} %{time_total}")
        .arg(url)
        .output()
        .map_err(|error| format!("curl не запустился: {error}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parts = stdout.split_whitespace().collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(format!("unexpected curl output: {stdout}"));
    }

    let http_code = parts[0];
    let bytes = parts[1].parse::<f32>().map_err(|error| error.to_string())?;
    let seconds = parts[2].parse::<f32>().map_err(|error| error.to_string())?;

    let http_ok = http_code.starts_with('2') || http_code == "000";
    let timed_out_after_data = output.status.code() == Some(28) && bytes > 0.0 && http_ok;

    if (!output.status.success() && !timed_out_after_data) || !http_ok || bytes <= 0.0 {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "curl rc {:?}, http {http_code}, bytes {bytes}, {stderr}",
            output.status.code()
        ));
    }

    Ok(bytes * 8.0 / seconds.max(0.1) / 1_000_000.0)
}

fn average_duration_ms(values: &[Duration]) -> u32 {
    let total = values.iter().map(Duration::as_millis).sum::<u128>();
    (total / values.len() as u128) as u32
}

fn jitter_duration_ms(values: &[Duration]) -> u32 {
    if values.len() < 2 {
        return 0;
    }

    let average = average_duration_ms(values) as i64;
    let total_deviation = values
        .iter()
        .map(|value| (value.as_millis() as i64 - average).unsigned_abs())
        .sum::<u64>();
    (total_deviation / values.len() as u64) as u32
}

fn stop_child(child: &mut Child) {
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill();
    }
    let _ = child.wait();
}

fn append_core_stderr(core: &str, error: String, stderr_path: &std::path::Path) -> String {
    let mut stderr = String::new();
    if File::open(stderr_path)
        .and_then(|mut file| file.read_to_string(&mut stderr))
        .is_ok()
    {
        let stderr = stderr.trim();
        if !stderr.is_empty() {
            return format!("{error}; {core}: {}", tail_chars(stderr, 500));
        }
    }

    error
}

fn tail_chars(value: &str, limit: usize) -> String {
    let chars = value.chars().collect::<Vec<_>>();
    let start = chars.len().saturating_sub(limit);
    chars[start..].iter().collect()
}

fn build_sing_box_config(profile: &Profile, port: u16) -> Result<Value, String> {
    let outbound = match profile.protocol {
        Protocol::Vless => build_vless_outbound(profile)?,
        Protocol::VMess => build_vmess_outbound(profile)?,
        Protocol::Trojan => build_trojan_outbound(profile)?,
        Protocol::Shadowsocks => build_shadowsocks_outbound(profile)?,
        Protocol::Hysteria2 => build_hysteria2_outbound(profile)?,
        Protocol::WireGuard => {
            return Err(
                "WireGuard бенчмарк не поддерживается в desktop; используйте роутер".to_owned(),
            );
        }
        Protocol::Tuic => {
            return Err("TUIC бенчмарк не поддерживается в desktop; используйте роутер".to_owned());
        }
        Protocol::Unknown(_) => return Err("неподдерживаемый протокол".to_owned()),
    };

    Ok(json!({
        "log": { "level": "error", "disabled": false },
        "inbounds": [{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": port
        }],
        "outbounds": [outbound],
        "route": { "final": "proxy" }
    }))
}

fn build_vless_outbound(profile: &Profile) -> Result<Value, String> {
    let url = Url::parse(&profile.raw).map_err(|error| error.to_string())?;
    let uuid = url.username();
    if uuid.is_empty() {
        return Err("VLESS ссылка без UUID".to_owned());
    }

    let server = profile.address.clone();
    let server_port = profile.port.unwrap_or(443);
    let flow = query_value(&url, "flow");
    let security = query_value(&url, "security");

    let mut outbound = json!({
        "type": "vless",
        "tag": "proxy",
        "server": server,
        "server_port": server_port,
        "uuid": uuid,
        "packet_encoding": "xudp"
    });

    if let Some(flow) = flow.filter(|value| !value.is_empty()) {
        outbound["flow"] = json!(flow);
    }

    let network = query_value(&url, "type").unwrap_or_else(|| "tcp".to_owned());
    if network != "tcp" {
        outbound["transport"] = build_transport(&url, &network);
    }

    if security.as_deref().is_some_and(|value| value != "none") {
        outbound["tls"] = build_tls(&url, security.as_deref() == Some("reality"), true);
    }

    Ok(outbound)
}

fn build_hysteria2_outbound(profile: &Profile) -> Result<Value, String> {
    let url = Url::parse(&profile.raw).map_err(|error| error.to_string())?;
    let password = if !url.username().is_empty() {
        percent_decode(url.username())
    } else {
        query_value(&url, "password").unwrap_or_default()
    };

    if password.is_empty() {
        return Err("Hysteria2 ссылка без пароля".to_owned());
    }

    let mut outbound = json!({
        "type": "hysteria2",
        "tag": "proxy",
        "server": profile.address,
        "server_port": profile.port.unwrap_or(443),
        "password": password,
        "tls": build_tls(&url, false, false)
    });

    if let Some(obfs_password) =
        query_value(&url, "obfs-password").or_else(|| query_value(&url, "obfsPassword"))
    {
        outbound["obfs"] = json!({
            "type": query_value(&url, "obfs").unwrap_or_else(|| "salamander".to_owned()),
            "password": obfs_password
        });
    }

    Ok(outbound)
}

fn build_vmess_outbound(profile: &Profile) -> Result<Value, String> {
    let json = crate::profiles::decode_vmess_json(&profile.raw)
        .ok_or_else(|| "VMess: не удалось декодировать base64 JSON".to_owned())?;

    let address = json
        .get("add")
        .and_then(Value::as_str)
        .ok_or_else(|| "VMess: нет адреса".to_owned())?;
    let port = json
        .get("port")
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .unwrap_or(443) as u16;
    let uuid = json
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| "VMess: нет UUID".to_owned())?;
    let alter_id = json
        .get("aid")
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .unwrap_or(0) as u32;
    let security = json.get("scy").and_then(Value::as_str).unwrap_or("auto");

    let mut outbound = json!({
        "type": "vmess",
        "tag": "proxy",
        "server": address,
        "server_port": port,
        "uuid": uuid,
        "alter_id": alter_id,
        "security": security
    });

    let network = json.get("net").and_then(Value::as_str).unwrap_or("tcp");
    if network != "tcp" {
        let mut transport = json!({ "type": network });
        if network == "ws" {
            if let Some(path) = json.get("path").and_then(Value::as_str) {
                transport["path"] = json!(path);
            }
            if let Some(host) = json.get("host").and_then(Value::as_str) {
                transport["headers"] = json!({ "Host": host });
            }
        } else if network == "grpc"
            && let Some(service_name) = json
                .get("path")
                .and_then(Value::as_str)
                .or_else(|| json.get("serviceName").and_then(Value::as_str))
        {
            transport["service_name"] = json!(service_name);
        }
        outbound["transport"] = transport;
    }

    let tls = json.get("tls").and_then(Value::as_str);
    if tls == Some("tls") {
        let url = Url::parse(&profile.raw).ok();
        let mut tls_val = json!({ "enabled": true });
        if let Some(sni) = json.get("sni").and_then(Value::as_str) {
            tls_val["server_name"] = json!(sni);
        } else if let Some(host) = json.get("host").and_then(Value::as_str) {
            tls_val["server_name"] = json!(host);
        }
        if let Some(fp) = json.get("fp").and_then(Value::as_str) {
            tls_val["utls"] = json!({ "enabled": true, "fingerprint": fp });
        }
        if let Some(url) = url
            && let Some(insecure) = query_value(&url, "allowInsecure").as_deref()
            && matches!(insecure, "1" | "true")
        {
            tls_val["insecure"] = json!(true);
        }
        if let Some(alpn) = json.get("alpn").and_then(Value::as_str) {
            tls_val["alpn"] = json!(alpn.split(',').collect::<Vec<_>>());
        }
        outbound["tls"] = tls_val;
    }

    Ok(outbound)
}

fn build_trojan_outbound(profile: &Profile) -> Result<Value, String> {
    let url = Url::parse(&profile.raw).map_err(|error| error.to_string())?;
    let password = percent_decode(url.username());
    if password.is_empty() {
        return Err("Trojan ссылка без пароля".to_owned());
    }

    let mut outbound = json!({
        "type": "trojan",
        "tag": "proxy",
        "server": profile.address,
        "server_port": profile.port.unwrap_or(443),
        "password": password
    });

    let security = query_value(&url, "security");
    if security.as_deref().is_some_and(|v| v != "none") {
        outbound["tls"] = build_tls(&url, security.as_deref() == Some("reality"), true);
    }

    let network = query_value(&url, "type").unwrap_or_else(|| "tcp".to_owned());
    if network != "tcp" {
        outbound["transport"] = build_transport(&url, &network);
    }

    Ok(outbound)
}

fn build_shadowsocks_outbound(profile: &Profile) -> Result<Value, String> {
    let (method, password) = crate::xray_config::extract_ss_credentials(&profile.raw)?;

    Ok(json!({
        "type": "shadowsocks",
        "tag": "proxy",
        "server": profile.address,
        "server_port": profile.port.unwrap_or(8388),
        "method": method,
        "password": password
    }))
}

fn build_tls(url: &Url, reality: bool, utls_enabled: bool) -> Value {
    let server_name = query_value(url, "sni").or_else(|| query_value(url, "peer"));
    let insecure = query_value(url, "allowInsecure")
        .or_else(|| query_value(url, "insecure"))
        .is_some_and(|value| matches!(value.as_str(), "1" | "true"));

    let mut tls = json!({
        "enabled": true,
        "insecure": insecure
    });

    if utls_enabled {
        let fingerprint = query_value(url, "fp").unwrap_or_else(|| "chrome".to_owned());
        tls["utls"] = json!({
            "enabled": true,
            "fingerprint": fingerprint
        });
    }

    if let Some(alpn) = query_value(url, "alpn") {
        tls["alpn"] = json!(alpn.split(',').collect::<Vec<_>>());
    }

    if let Some(server_name) = server_name {
        tls["server_name"] = json!(server_name);
    }

    if reality {
        let mut reality_config = json!({ "enabled": true });
        if let Some(public_key) = query_value(url, "pbk") {
            reality_config["public_key"] = json!(public_key);
        }
        if let Some(short_id) = query_value(url, "sid") {
            reality_config["short_id"] = json!(short_id);
        }
        tls["reality"] = reality_config;
    }

    tls
}

fn build_transport(url: &Url, network: &str) -> Value {
    let mut transport = json!({ "type": network });

    if let Some(path) = query_value(url, "path") {
        transport["path"] = json!(path);
    }

    if let Some(host) = query_value(url, "host") {
        transport["headers"] = json!({ "Host": host });
    }

    if let Some(service_name) = query_value(url, "serviceName") {
        transport["service_name"] = json!(service_name);
    }

    transport
}

#[allow(dead_code)]
fn is_xhttp_vless(profile: &Profile) -> bool {
    matches!(profile.protocol, Protocol::Vless)
        && Url::parse(&profile.raw)
            .ok()
            .and_then(|url| query_value(&url, "type"))
            .is_some_and(|value| value == "xhttp")
}

#[cfg(test)]
mod tests {
    use std::{io::Write, process::Command};

    use tempfile::NamedTempFile;

    use super::build_sing_box_config;
    use crate::profiles::parse_profiles;
    use crate::xray_config::build_xray_config;

    #[test]
    fn generated_vless_tls_config_is_valid_for_sing_box() {
        let profile = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&sni=example.com&type=tcp#Test",
        )
        .remove(0);

        assert_sing_box_accepts(
            build_sing_box_config(&profile, 20801).expect("VLESS config should build"),
        );
    }

    #[test]
    fn generated_vless_reality_config_is_valid_for_sing_box() {
        let profile = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&sni=www.example.com&type=tcp&fp=chrome&pbk=0123456789abcdef0123456789abcdef0123456789a&sid=abcd&flow=xtls-rprx-vision#Test",
        )
        .remove(0);

        assert_sing_box_accepts(
            build_sing_box_config(&profile, 20803).expect("VLESS Reality config should build"),
        );
    }

    #[test]
    fn generated_hysteria2_config_is_valid_for_sing_box() {
        let profile =
            parse_profiles("hysteria2://secret@example.com:443?sni=example.com#Test").remove(0);

        assert_sing_box_accepts(
            build_sing_box_config(&profile, 20802).expect("Hysteria2 config should build"),
        );
    }

    #[test]
    fn generated_vless_xhttp_reality_config_is_valid_for_xray() {
        let profile = parse_profiles(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=xhttp&security=reality&sni=www.example.com&fp=chrome&pbk=0123456789abcdef0123456789abcdef0123456789a&sid=abcd#Test",
        )
        .remove(0);

        assert_xray_accepts(
            build_xray_config(&profile, "127.0.0.1", 20804).expect("XHTTP config should build"),
        );
    }

    fn assert_sing_box_accepts(config: serde_json::Value) {
        if Command::new("sing-box").arg("version").output().is_err() {
            return;
        }

        let mut file = NamedTempFile::new().expect("temp config file should be created");
        serde_json::to_writer_pretty(&mut file, &config).expect("config should serialize");
        file.flush().expect("config should flush");

        let output = Command::new("sing-box")
            .arg("check")
            .arg("-c")
            .arg(file.path())
            .output()
            .expect("sing-box check should run");

        assert!(
            output.status.success(),
            "sing-box rejected config: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn assert_xray_accepts(config: serde_json::Value) {
        if Command::new("xray").arg("version").output().is_err() {
            return;
        }

        let mut file = NamedTempFile::new().expect("temp config file should be created");
        serde_json::to_writer_pretty(&mut file, &config).expect("config should serialize");
        file.flush().expect("config should flush");

        let output = Command::new("xray")
            .arg("run")
            .arg("-test")
            .arg("-format")
            .arg("json")
            .arg("-c")
            .arg(file.path())
            .output()
            .expect("xray test should run");

        assert!(
            output.status.success(),
            "xray rejected config: stdout: {}; stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
