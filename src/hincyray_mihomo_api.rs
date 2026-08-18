//! Mihomo external-controller REST API client.
//!
//! This module owns the EC transport boundary. Daemon handlers pass only an
//! already-resolved controller descriptor plus the desired EC path; they do not
//! build HTTP clients or know wildcard bind-address rewrite rules.

use std::{io::Read, process::Command, time::Duration};

use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::Value;

use crate::mihomo_config::MihomoFeatures;

const MAX_CONNECTIONS_JSON_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_DIAGNOSTIC_CONNECTIONS_JSON_BYTES: usize = 4 * 1024 * 1024;

/// Return the fixed internal controller endpoint and its optional persisted secret.
pub fn mihomo_controller(features: &MihomoFeatures) -> Option<(String, Option<String>)> {
    Some((
        "127.0.0.1:9090".to_owned(),
        features.external_controller.secret.clone(),
    ))
}

#[cfg(test)]
pub(crate) fn controller_dial_address(bind_address: &str) -> String {
    if let Some(port) = bind_address.strip_prefix("0.0.0.0:") {
        return format!("127.0.0.1:{port}");
    }
    if let Some(port) = bind_address.strip_prefix("[::]:") {
        return format!("127.0.0.1:{port}");
    }
    if let Some(port) = bind_address.strip_prefix(":::") {
        return format!("127.0.0.1:{port}");
    }
    if bind_address.starts_with(':') {
        return format!("127.0.0.1{bind_address}");
    }
    bind_address.to_owned()
}

/// Make a GET request to the Mihomo external-controller REST API.
pub fn mihomo_api_get(addr: &str, secret: Option<&str>, path: &str) -> Result<String, String> {
    let (status, body) = mihomo_api_get_response(addr, secret, path)?;
    if !(200..300).contains(&status) {
        return Err(format!("Mihomo API {path}: HTTP {status}"));
    }
    Ok(body)
}

pub fn mihomo_api_get_response(
    addr: &str,
    secret: Option<&str>,
    path: &str,
) -> Result<(u16, String), String> {
    let url = format!("http://{addr}{path}");
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(3))
        .no_proxy()
        .build()
        .map_err(|e| e.to_string())?;
    let mut req = client.get(&url);
    if let Some(s) = secret
        && !s.is_empty()
    {
        req = req.header("Authorization", format!("Bearer {s}"));
    }
    let resp = req.send().map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let body = resp.text().map_err(|e| e.to_string())?;
    Ok((status, body))
}

pub fn mihomo_api_delete(addr: &str, secret: Option<&str>, path: &str) -> Result<u16, String> {
    let url = format!("http://{addr}{path}");
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(3))
        .no_proxy()
        .build()
        .map_err(|e| e.to_string())?;
    let mut req = client.delete(&url);
    if let Some(s) = secret
        && !s.is_empty()
    {
        req = req.header("Authorization", format!("Bearer {s}"));
    }
    let resp = req.send().map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    if !resp.status().is_success() {
        return Err(format!("Mihomo API {path}: HTTP {}", resp.status()));
    }
    Ok(status)
}

pub fn mihomo_api_post(
    addr: &str,
    secret: Option<&str>,
    path: &str,
    body: &str,
) -> Result<String, String> {
    let (status, response) = mihomo_api_post_response(addr, secret, path, body)?;
    if !(200..300).contains(&status) {
        return Err(format!("Mihomo API {path}: HTTP {status}"));
    }
    Ok(response)
}

pub fn mihomo_api_post_response(
    addr: &str,
    secret: Option<&str>,
    path: &str,
    body: &str,
) -> Result<(u16, String), String> {
    let url = format!("http://{addr}{path}");
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(3))
        .no_proxy()
        .build()
        .map_err(|e| e.to_string())?;
    let mut req = client.post(&url);
    if let Some(s) = secret
        && !s.is_empty()
    {
        req = req.header("Authorization", format!("Bearer {s}"));
    }
    if !body.trim().is_empty() {
        req = req
            .header("Content-Type", "application/json")
            .body(body.to_owned());
    }
    let resp = req.send().map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let response = resp.text().map_err(|e| e.to_string())?;
    Ok((status, response))
}

pub fn mihomo_api_put(
    addr: &str,
    secret: Option<&str>,
    path: &str,
    body: Option<&str>,
) -> Result<(), String> {
    let url = format!("http://{addr}{path}");
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .no_proxy()
        .build()
        .map_err(|e| e.to_string())?;
    let mut req = client.put(&url);
    if let Some(s) = secret
        && !s.is_empty()
    {
        req = req.header("Authorization", format!("Bearer {s}"));
    }
    if let Some(body) = body {
        req = req
            .header("Content-Type", "application/json")
            .body(body.to_owned());
    }
    let resp = req.send().map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("Mihomo API {path}: HTTP {}", resp.status()));
    }
    Ok(())
}

/// Like `mihomo_api_get` but for streaming endpoints (`/traffic`, `/memory`).
/// Uses `curl --max-time` because reqwest's blocking API would wait for the
/// endless stream rather than returning the first JSON snapshot.
pub fn mihomo_api_stream_get(
    addr: &str,
    secret: Option<&str>,
    path: &str,
) -> Result<String, String> {
    let url = format!("http://{addr}{path}");
    let mut cmd = Command::new("curl");
    cmd.args(["-s", "--max-time", "2", &url]);
    if let Some(s) = secret
        && !s.is_empty()
    {
        cmd.args(["-H", &format!("Authorization: Bearer {s}")]);
    }
    let output = cmd.output().map_err(|e| e.to_string())?;
    let body = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() && body.trim().is_empty() {
        return Err(format!(
            "Mihomo API {path}: curl exit {:?}",
            output.status.code()
        ));
    }
    first_stream_json(&body).ok_or_else(|| format!("empty or invalid Mihomo stream {path}"))
}

pub fn first_stream_json(body: &str) -> Option<String> {
    let first = body.lines().find(|line| !line.trim().is_empty())?;
    serde_json::from_str::<Value>(first).ok()?;
    Some(first.to_owned())
}

pub fn mihomo_api_get_json(addr: &str, secret: Option<&str>, path: &str) -> Result<Value, String> {
    let body = mihomo_api_get(addr, secret, path)?;
    serde_json::from_str(&body).map_err(|e| format!("Mihomo API {path}: parse error: {e}"))
}

/// Read Mihomo's potentially large connections snapshot with a hard size cap.
pub fn mihomo_api_get_connections_json(addr: &str, secret: Option<&str>) -> Result<Value, String> {
    mihomo_api_get_connections_json_bounded(addr, secret, MAX_CONNECTIONS_JSON_BYTES)
}

pub fn mihomo_api_get_connections_json_bounded(
    addr: &str,
    secret: Option<&str>,
    max_bytes: usize,
) -> Result<Value, String> {
    let path = "/connections";
    let url = format!("http://{addr}{path}");
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(3))
        .no_proxy()
        .build()
        .map_err(|error| format!("Mihomo API {path}: client error: {error}"))?;
    let mut request = client.get(&url);
    if let Some(secret) = secret
        && !secret.is_empty()
    {
        request = request.header("Authorization", format!("Bearer {secret}"));
    }
    let mut response = request
        .send()
        .map_err(|error| format!("Mihomo API {path}: request error: {error}"))?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(format!("Mihomo API {path}: HTTP {status}"));
    }
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(format!(
            "Mihomo API {path}: response exceeds {max_bytes} bytes"
        ));
    }

    let capacity = response
        .content_length()
        .unwrap_or(64 * 1024)
        .min(max_bytes as u64) as usize;
    let mut bytes = Vec::with_capacity(capacity);
    response
        .by_ref()
        .take((max_bytes + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("Mihomo API {path}: body read error: {error}"))?;
    if bytes.len() > max_bytes {
        return Err(format!(
            "Mihomo API {path}: response exceeds {max_bytes} bytes"
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("Mihomo API {path}: parse error: {error}"))
}

pub fn mihomo_api_stream_get_json(
    addr: &str,
    secret: Option<&str>,
    path: &str,
) -> Result<Value, String> {
    let body = mihomo_api_stream_get(addr, secret, path)?;
    serde_json::from_str(&body).map_err(|e| format!("Mihomo API {path}: parse error: {e}"))
}

/// Test the delay (latency) of a specific proxy through the Mihomo API.
pub fn mihomo_api_delay(
    addr: &str,
    secret: Option<&str>,
    proxy_name: &str,
    test_url: &str,
    timeout_ms: u32,
) -> Result<u32, String> {
    let path = format!(
        "/proxies/{}/delay?url={}&timeout={}",
        utf8_percent_encode(proxy_name, NON_ALPHANUMERIC),
        utf8_percent_encode(test_url, NON_ALPHANUMERIC),
        timeout_ms
    );
    let json = mihomo_api_get_json(addr, secret, &path)?;
    json.get("delay")
        .and_then(Value::as_u64)
        .map(|d| d as u32)
        .ok_or_else(|| {
            json.get("message")
                .and_then(Value::as_str)
                .unwrap_or("no delay in response")
                .to_owned()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mihomo_config::MihomoFeatures;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    fn connections_fixture(
        response_head: String,
        body: Vec<u8>,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("fixture listener");
        let address = listener.local_addr().expect("fixture address").to_string();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("fixture request");
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).expect("read fixture request");
            stream
                .write_all(response_head.as_bytes())
                .expect("write fixture headers");
            let _ = stream.write_all(&body);
        });
        (address, worker)
    }

    #[test]
    fn first_stream_json_returns_first_valid_line() {
        let body = "{\"inuse\":123}\n{\"inuse\":456}\n";
        assert_eq!(first_stream_json(body).as_deref(), Some("{\"inuse\":123}"));
        assert!(first_stream_json("").is_none());
        assert!(first_stream_json("not-json\n{\"later\":true}").is_none());
    }

    #[test]
    fn mihomo_controller_is_fixed_to_loopback_and_preserves_secret() {
        let mut features = MihomoFeatures::default();
        features.external_controller.secret = Some("s".to_owned());
        let ec = mihomo_controller(&features).expect("controller");
        assert_eq!(ec.0, "127.0.0.1:9090");
        assert_eq!(ec.1.as_deref(), Some("s"));
    }

    #[test]
    fn connections_json_rejects_oversized_content_length() {
        let (address, worker) = connections_fixture(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                MAX_CONNECTIONS_JSON_BYTES + 1
            ),
            Vec::new(),
        );
        let error = mihomo_api_get_connections_json(&address, None).expect_err("oversized header");
        worker.join().expect("fixture worker");
        assert!(error.contains("response exceeds"), "{error}");
        assert!(error.len() < 200, "unbounded error: {error}");
    }

    #[test]
    fn connections_json_rejects_oversized_chunked_body() {
        let payload = vec![b' '; MAX_CONNECTIONS_JSON_BYTES + 1];
        let chunk_size = format!("{:x}\r\n", payload.len());
        let mut body = Vec::with_capacity(chunk_size.len() + payload.len() + 7);
        body.extend_from_slice(chunk_size.as_bytes());
        body.extend_from_slice(&payload);
        body.extend_from_slice(b"\r\n0\r\n\r\n");
        let (address, worker) = connections_fixture(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_owned(),
            body,
        );
        let error = mihomo_api_get_connections_json(&address, None).expect_err("oversized body");
        worker.join().expect("fixture worker");
        assert!(error.contains("response exceeds"), "{error}");
        assert!(error.len() < 200, "unbounded error: {error}");
    }
}
