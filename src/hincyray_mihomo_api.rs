//! Mihomo external-controller REST API client.
//!
//! This module owns the EC transport boundary. Daemon handlers pass only an
//! already-resolved controller descriptor plus the desired EC path; they do not
//! build HTTP clients or know wildcard bind-address rewrite rules.

use std::{process::Command, time::Duration};

use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::Value;

use crate::mihomo_config::MihomoFeatures;

/// Extract the external-controller address and secret from `MihomoFeatures`,
/// returning `None` if the controller is disabled.
pub fn mihomo_controller(features: &MihomoFeatures) -> Option<(String, Option<String>)> {
    if features.external_controller.enabled {
        Some((
            controller_dial_address(&features.external_controller.address),
            features.external_controller.secret.clone(),
        ))
    } else {
        None
    }
}

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
    use crate::mihomo_config::{ExternalControllerConfig, MihomoFeatures};

    #[test]
    fn first_stream_json_returns_first_valid_line() {
        let body = "{\"inuse\":123}\n{\"inuse\":456}\n";
        assert_eq!(first_stream_json(body).as_deref(), Some("{\"inuse\":123}"));
        assert!(first_stream_json("").is_none());
        assert!(first_stream_json("not-json\n{\"later\":true}").is_none());
    }

    #[test]
    fn mihomo_controller_maps_wildcard_bind_to_loopback() {
        let mut features = MihomoFeatures::default();
        assert!(mihomo_controller(&features).is_none());
        features.external_controller = ExternalControllerConfig {
            enabled: true,
            address: "0.0.0.0:9090".to_owned(),
            secret: Some("s".to_owned()),
            allow_origins: Vec::new(),
            allow_private_network: false,
        };
        let ec = mihomo_controller(&features).expect("ec");
        assert_eq!(ec.0, "127.0.0.1:9090");
        assert_eq!(ec.1.as_deref(), Some("s"));
    }
}
