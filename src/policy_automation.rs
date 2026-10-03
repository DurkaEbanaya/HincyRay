//! Opt-in Keenetic device policy assignment driven by scheduled Direct samples.
//! MACs, rather than DHCP addresses, identify the selected registered devices.
use std::{
    collections::HashSet,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const MAX_DEVICES: usize = 16;
const HOSTS_URL: &str = "http://127.0.0.1:79/rci/show/ip/hotspot/host";
const POLICIES_URL: &str = "http://127.0.0.1:79/rci/show/ip/policy";
const RCI_LIMIT: u64 = 512 * 1024;
const POLICY_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    enabled: bool,
    devices: Vec<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyAutomationRequest {
    pub enabled: bool,
    pub devices: Vec<String>,
}

#[derive(Serialize, JsonSchema)]
pub struct PolicyAutomationStatus {
    pub enabled: bool,
    pub devices: Vec<Value>,
    pub last_check_unix: Option<u64>,
    pub last_action_unix: Option<u64>,
    pub last_action: Option<String>,
    pub error: Option<String>,
}

#[derive(Default)]
struct Runtime {
    settings: Settings,
    last_check_unix: Option<u64>,
    last_action_unix: Option<u64>,
    last_action: Option<String>,
    error: Option<String>,
}

pub struct PolicyAutomation {
    path: PathBuf,
    runtime: Mutex<Runtime>,
}

#[derive(Clone)]
struct Host {
    mac: String,
    ip: String,
    name: String,
    policy: String,
    registered: bool,
    active: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DesiredPolicy {
    Xkeen,
    Default,
}

fn desired_policy(statuses: &[bool; 4]) -> Option<DesiredPolicy> {
    if !statuses[1] && !statuses[2] {
        None
    } else if statuses[0] {
        Some(DesiredPolicy::Default)
    } else {
        Some(DesiredPolicy::Xkeen)
    }
}

fn policy_command(mac: &str, policy: DesiredPolicy) -> String {
    match policy {
        DesiredPolicy::Xkeen => format!("ip hotspot host {mac} policy Policy0"),
        DesiredPolicy::Default => format!("ip hotspot host {mac} no policy"),
    }
}

fn canonical_mac(mac: &str) -> Option<String> {
    let bytes: Vec<_> = mac.split(':').collect();
    (bytes.len() == 6
        && bytes
            .iter()
            .all(|part| part.len() == 2 && part.bytes().all(|b| b.is_ascii_hexdigit()))
        && bytes.iter().any(|part| *part != "00"))
    .then(|| mac.to_ascii_lowercase())
}

fn parse_hosts(value: &Value) -> Vec<Host> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let mac = canonical_mac(entry["mac"].as_str()?)?;
            Some(Host {
                mac,
                ip: entry["ip"]
                    .as_str()
                    .unwrap_or("")
                    .chars()
                    .take(48)
                    .collect(),
                name: entry["name"]
                    .as_str()
                    .unwrap_or("")
                    .chars()
                    .take(100)
                    .collect(),
                policy: entry["policy"]
                    .as_str()
                    .unwrap_or("")
                    .chars()
                    .take(40)
                    .collect(),
                registered: entry["registered"] == true,
                active: entry["active"] == true,
            })
        })
        .take(256)
        .collect()
}

fn has_xkeen_policy(value: &Value) -> bool {
    value
        .get("Policy0")
        .and_then(|policy| policy["description"].as_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("xkeen"))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn rci_get(url: &str) -> Result<Value, String> {
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(4))
        .build()
        .map_err(|_| "RCI client unavailable")?;
    let response = client
        .get(url)
        .send()
        .map_err(|_| "Keenetic RCI unavailable")?;
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|size| size > RCI_LIMIT)
    {
        return Err("Keenetic RCI rejected request".to_owned());
    }
    let mut bytes = Vec::new();
    response
        .take(RCI_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Keenetic RCI read failed")?;
    if bytes.len() as u64 > RCI_LIMIT {
        return Err("Keenetic RCI response too large".to_owned());
    }
    serde_json::from_slice(&bytes).map_err(|_| "Keenetic RCI response invalid".to_owned())
}

fn read_hosts() -> Result<Vec<Host>, String> {
    let value = rci_get(HOSTS_URL)?;
    if !value.is_array() {
        return Err("Keenetic host list invalid".to_owned());
    }
    Ok(parse_hosts(&value))
}

fn assign_policy(mac: &str, desired: DesiredPolicy) -> Result<(), String> {
    let mut child = Command::new("ndmc")
        .arg("-c")
        .arg(policy_command(mac, desired))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "Keenetic policy command unavailable")?;
    let deadline = Instant::now() + POLICY_COMMAND_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Keenetic may report CLI errors while returning exit code zero.
                let output = child
                    .wait_with_output()
                    .map_err(|_| "Keenetic policy response invalid")?;
                if status.success()
                    && !String::from_utf8_lossy(&output.stdout).contains("error[")
                    && !String::from_utf8_lossy(&output.stderr).contains("error[")
                {
                    return Ok(());
                }
                return Err("Keenetic policy assignment failed".to_owned());
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Keenetic policy command timed out".to_owned());
            }
        }
    }
}

fn reconcile_devices(
    settings: &Settings,
    desired: DesiredPolicy,
    hosts: &[Host],
    mut assign: impl FnMut(&str, DesiredPolicy) -> Result<(), String>,
    mut current_hosts: impl FnMut() -> Result<Vec<Host>, String>,
) -> (Option<String>, Option<String>) {
    let mut last_action = None;
    let mut last_error = None;
    for mac in &settings.devices {
        if crate::hincyray::shutting_down() {
            break;
        }
        let matches: Vec<_> = hosts
            .iter()
            .filter(|host| host.mac == *mac && host.registered)
            .collect();
        if matches.len() != 1 {
            last_error = Some("selected device unavailable or ambiguous".to_owned());
            continue;
        }
        let host = matches[0];
        let expected = if desired == DesiredPolicy::Xkeen {
            "Policy0"
        } else {
            ""
        };
        if host.policy == expected {
            continue;
        }
        if let Err(error) = assign(mac, desired) {
            last_error = Some(error);
            continue;
        }
        if !current_hosts().is_ok_and(|current| {
            let matches: Vec<_> = current
                .iter()
                .filter(|candidate| candidate.mac == *mac && candidate.registered)
                .collect();
            matches.len() == 1 && matches[0].policy == expected
        }) {
            last_error = Some("Keenetic policy verification failed".to_owned());
            continue;
        }
        last_action = Some(format!(
            "{} → {}",
            host.ip,
            if desired == DesiredPolicy::Xkeen {
                "XKeen"
            } else {
                "Default Policy"
            }
        ));
    }
    (last_action, last_error)
}

fn write_private(path: &Path, settings: &Settings) -> Result<(), String> {
    let bytes = serde_json::to_vec(settings).map_err(|_| "cannot encode automation settings")?;
    let parent = path.parent().ok_or("invalid automation path")?;
    let mut temp =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| "cannot save automation settings")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o600))
            .map_err(|_| "cannot protect automation settings")?;
    }
    temp.write_all(&bytes)
        .and_then(|_| temp.as_file().sync_all())
        .map_err(|_| "cannot save automation settings")?;
    temp.persist(path)
        .map_err(|_| "cannot save automation settings")?;
    Ok(())
}

impl PolicyAutomation {
    pub fn new(state_path: &Path) -> std::sync::Arc<Self> {
        let path = state_path.with_file_name("direct-policy-automation.json");
        let settings = fs::read(&path)
            .ok()
            .filter(|bytes| bytes.len() <= 4096)
            .and_then(|bytes| serde_json::from_slice::<Settings>(&bytes).ok())
            .filter(|settings| {
                settings.devices.len() <= MAX_DEVICES
                    && settings
                        .devices
                        .iter()
                        .all(|mac| canonical_mac(mac).as_deref() == Some(mac))
                    && settings.devices.iter().collect::<HashSet<_>>().len()
                        == settings.devices.len()
            })
            .unwrap_or_default();
        std::sync::Arc::new(Self {
            path,
            runtime: Mutex::new(Runtime {
                settings,
                ..Runtime::default()
            }),
        })
    }

    pub fn status(&self) -> Result<Value, String> {
        let hosts = read_hosts()?;
        let runtime = self
            .runtime
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut devices: Vec<Value> = hosts
            .into_iter()
            .filter(|host| host.registered)
            .map(|host| {
                json!({
                    "mac":host.mac,"ip":host.ip,"name":host.name,"policy":host.policy,"active":host.active,
                    "selected":runtime.settings.devices.contains(&host.mac),
                })
            })
            .collect();
        // Retain selected devices in the UI even when they are temporarily offline.
        for mac in &runtime.settings.devices {
            if !devices.iter().any(|device| device["mac"] == *mac) {
                devices.push(json!({"mac":mac,"ip":"","name":"","policy":null,"selected":true,"active":false}));
            }
        }
        devices.truncate(256);
        Ok(json!({"enabled":runtime.settings.enabled,"devices":devices,
            "last_check_unix":runtime.last_check_unix,"last_action_unix":runtime.last_action_unix,
            "last_action":runtime.last_action,"error":runtime.error}))
    }

    pub fn configure(&self, body: &str) -> Result<Value, String> {
        let request: PolicyAutomationRequest =
            serde_json::from_str(body).map_err(|_| "invalid automation settings")?;
        if request.devices.len() > MAX_DEVICES {
            return Err("too many selected devices".to_owned());
        }
        let devices: Vec<String> = request
            .devices
            .iter()
            .map(|mac| canonical_mac(mac).ok_or_else(|| "invalid device MAC".to_owned()))
            .collect::<Result<_, _>>()?;
        if devices.iter().collect::<HashSet<_>>().len() != devices.len() {
            return Err("duplicate device MAC".to_owned());
        }
        if request.enabled && !devices.is_empty() {
            if !has_xkeen_policy(&rci_get(POLICIES_URL)?) {
                return Err("XKeen Policy0 missing".to_owned());
            }
            let hosts = read_hosts()?;
            if devices
                .iter()
                .any(|mac| !hosts.iter().any(|host| host.registered && &host.mac == mac))
            {
                return Err("selected device is not registered in Keenetic".to_owned());
            }
        }
        let settings = Settings {
            enabled: request.enabled,
            devices,
        };
        let mut runtime = self
            .runtime
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        write_private(&self.path, &settings)?;
        runtime.settings = settings;
        runtime.error = None;
        Ok(json!({"enabled":runtime.settings.enabled,"selected":runtime.settings.devices.len()}))
    }

    pub fn on_sample(&self, statuses: &[bool; 4]) {
        let mut runtime = self
            .runtime
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if !runtime.settings.enabled || runtime.settings.devices.is_empty() {
            return;
        }
        runtime.last_check_unix = Some(now());
        let Some(desired) = desired_policy(statuses) else {
            runtime.error = None;
            return;
        };
        if !matches!(rci_get(POLICIES_URL), Ok(value) if has_xkeen_policy(&value)) {
            runtime.error = Some("XKeen Policy0 unavailable".to_owned());
            return;
        }
        let hosts = match read_hosts() {
            Ok(hosts) => hosts,
            Err(error) => {
                runtime.error = Some(error);
                return;
            }
        };
        // The operator explicitly selected these MACs; reconcile a manual
        // policy edit on the next scheduled sample, never on a manual probe.
        let (action, error) = reconcile_devices(
            &runtime.settings,
            desired,
            &hosts,
            assign_policy,
            read_hosts,
        );
        runtime.error = error;
        if let Some(action) = action {
            runtime.last_action_unix = Some(now());
            runtime.last_action = Some(action);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decisions_require_reachability_and_only_google_selects_default() {
        assert_eq!(desired_policy(&[true, false, false, true]), None);
        assert_eq!(desired_policy(&[false, false, false, false]), None);
        assert_eq!(
            desired_policy(&[false, true, false, true]),
            Some(DesiredPolicy::Xkeen)
        );
        assert_eq!(
            desired_policy(&[false, false, true, true]),
            Some(DesiredPolicy::Xkeen)
        );
        assert_eq!(
            desired_policy(&[true, true, false, false]),
            Some(DesiredPolicy::Default)
        );
        assert_eq!(
            policy_command("02:00:00:00:00:33", DesiredPolicy::Xkeen),
            "ip hotspot host 02:00:00:00:00:33 policy Policy0"
        );
        assert_eq!(
            policy_command("02:00:00:00:00:33", DesiredPolicy::Default),
            "ip hotspot host 02:00:00:00:00:33 no policy"
        );
    }
    #[test]
    fn disabled_by_default_and_mac_is_canonical() {
        let dir = tempfile::tempdir().expect("tempdir");
        let automation = PolicyAutomation::new(&dir.path().join("state.json"));
        assert!(!automation.runtime.lock().expect("runtime").settings.enabled);
        assert_eq!(
            canonical_mac("AA:bb:01:02:03:04").as_deref(),
            Some("aa:bb:01:02:03:04")
        );
        assert!(canonical_mac("00:00:00:00:00:00").is_none());
        let hosts = parse_hosts(
            &json!([{"mac":"AA:bb:01:02:03:04","ip":"192.0.2.4","policy":"Policy0","registered":true,"active":true}]),
        );
        assert_eq!(hosts[0].mac, "aa:bb:01:02:03:04");
        assert!(hosts[0].active);
        let offline =
            parse_hosts(&json!([{"mac":"aa:bb:01:02:03:04","registered":true,"active":false}]));
        assert!(!offline[0].active);
        assert!(has_xkeen_policy(
            &json!({"Policy0":{"description":"XKeen"}})
        ));
        assert!(!has_xkeen_policy(
            &json!({"Policy0":{"description":"Other"}})
        ));
    }

    #[test]
    fn selected_mac_reconciles_manual_policy_edits_and_verifies_assignment() {
        let selected = "02:00:00:00:00:33".to_owned();
        let other = "02:00:00:00:00:44".to_owned();
        let settings = Settings {
            enabled: true,
            devices: vec![selected.clone()],
        };
        let make_host = |mac: &str, policy: &str| Host {
            mac: mac.to_owned(),
            ip: "192.168.2.33".to_owned(),
            name: "PC".to_owned(),
            policy: policy.to_owned(),
            registered: true,
            active: true,
        };
        let hosts = vec![
            make_host(&selected, "OtherPolicy"),
            make_host(&other, "Policy0"),
        ];
        let mut changed = Vec::new();
        let (action, error) = reconcile_devices(
            &settings,
            DesiredPolicy::Default,
            &hosts,
            |mac, policy| {
                changed.push((mac.to_owned(), policy));
                Ok(())
            },
            || Ok(vec![make_host(&selected, "")]),
        );
        assert_eq!(changed, vec![(selected.clone(), DesiredPolicy::Default)]);
        assert_eq!(action.as_deref(), Some("192.168.2.33 → Default Policy"));
        assert!(error.is_none());

        let (_, error) = reconcile_devices(
            &settings,
            DesiredPolicy::Xkeen,
            &[make_host(&selected, "")],
            |_, _| Ok(()),
            || Ok(vec![make_host(&selected, "")]),
        );
        assert_eq!(
            error.as_deref(),
            Some("Keenetic policy verification failed")
        );
        let (action, error) = reconcile_devices(
            &settings,
            DesiredPolicy::Xkeen,
            &[make_host(&selected, "")],
            |_, _| Ok(()),
            || Ok(vec![make_host(&selected, "Policy0")]),
        );
        assert_eq!(action.as_deref(), Some("192.168.2.33 → XKeen"));
        assert!(error.is_none());

        let mut called = false;
        let (action, error) = reconcile_devices(
            &settings,
            DesiredPolicy::Xkeen,
            &[make_host(&selected, "Policy0")],
            |_, _| {
                called = true;
                Ok(())
            },
            || Ok(Vec::new()),
        );
        assert!(!called);
        assert!(action.is_none() && error.is_none());
    }
}
