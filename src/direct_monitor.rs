//! Low-cost Direct reachability monitor and private Telegram notification binding.
//! Bot credentials never enter the regular state, backups, or public diagnostics.
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::policy_automation::PolicyAutomation;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const INTERVAL: Duration = Duration::from_secs(300);
const MAX_BOT_REPLY_BYTES: u64 = 16 * 1024;
const POLL_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectMonitorSettingsRequest {
    token: Option<String>,
    enabled: bool,
}

#[derive(Serialize, JsonSchema)]
pub struct DirectMonitorSettingsResponse {
    bot_configured: bool,
    bot_paired: bool,
}

#[derive(Serialize, JsonSchema)]
pub struct DirectMonitorStatusResponse {
    ok: bool,
    results: Vec<Value>,
    checked_at: Option<u64>,
    running: bool,
    bot_configured: bool,
    bot_paired: bool,
    interval_seconds: u32,
}

pub const TARGETS: [(&str, &str, &str); 4] = [
    ("google", "Google", "https://www.google.com/generate_204"),
    ("vk", "Vk.ru", "https://vk.ru/"),
    ("ya", "ya.ru", "https://ya.ru/"),
    ("youtube", "YouTube", "https://www.youtube.com/generate_204"),
];

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BotConfig {
    token: String,
    #[serde(default)]
    chat_id: Option<i64>,
    #[serde(default)]
    offset: i64,
    configured_at: u64,
}

#[derive(Default)]
struct Snapshot {
    results: Vec<Value>,
    checked_at: Option<u64>,
    last_sent: Option<[bool; 4]>,
    running: bool,
    next_check: Option<Instant>,
}

pub struct DirectMonitor {
    config_path: PathBuf,
    socks_port: u16,
    snapshot: Mutex<Snapshot>,
    bot: Mutex<Option<BotConfig>>,
    policy: Arc<PolicyAutomation>,
}

impl DirectMonitor {
    pub fn new(state_path: &Path, socks_port: u16) -> Arc<Self> {
        let config_path = state_path.with_file_name("direct-notifications.json");
        let bot = fs::read(&config_path)
            .ok()
            .filter(|bytes| bytes.len() <= 4096)
            .and_then(|bytes| serde_json::from_slice::<BotConfig>(&bytes).ok())
            .filter(|config| valid_token(&config.token));
        Arc::new(Self {
            config_path,
            socks_port,
            snapshot: Mutex::new(Snapshot::default()),
            bot: Mutex::new(bot),
            policy: PolicyAutomation::new(state_path),
        })
    }

    pub fn policy(&self) -> &PolicyAutomation {
        &self.policy
    }

    pub fn status(&self) -> Value {
        let bot = self.bot.lock().unwrap_or_else(|error| error.into_inner());
        let snapshot = self
            .snapshot
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        json!({
            "ok": snapshot.results.iter().all(|item| item["ok"] == true) && snapshot.results.len() == TARGETS.len(),
            "results": snapshot.results,
            "checked_at": snapshot.checked_at,
            "running": snapshot.running,
            "bot_configured": bot.is_some(),
            "bot_paired": bot.as_ref().is_some_and(|config| config.chat_id.is_some()),
            "interval_seconds": 300,
        })
    }

    pub fn configure(&self, input: &str) -> Result<Value, String> {
        let request: DirectMonitorSettingsRequest =
            serde_json::from_str(input).map_err(|_| "invalid bot settings")?;
        let mut bot = self.bot.lock().unwrap_or_else(|error| error.into_inner());
        if !request.enabled {
            if self.config_path.exists() {
                fs::remove_file(&self.config_path).map_err(|_| "cannot disable notifications")?;
            }
            *bot = None;
        } else {
            let token = request.token.filter(|token| !token.is_empty());
            if token.as_ref().is_some_and(|token| !valid_token(token)) {
                return Err("invalid bot token".to_owned());
            }
            let config = if let Some(token) = token {
                BotConfig {
                    token,
                    chat_id: None,
                    offset: 0,
                    configured_at: now(),
                }
            } else {
                bot.clone().ok_or("bot token required")?
            };
            self.save(&config)?;
            *bot = Some(config);
        }
        Ok(
            json!({"bot_configured": bot.is_some(), "bot_paired": bot.as_ref().is_some_and(|config| config.chat_id.is_some())}),
        )
    }

    fn save(&self, config: &BotConfig) -> Result<(), String> {
        let bytes = serde_json::to_vec(config).map_err(|_| "cannot encode bot settings")?;
        let mut temp =
            tempfile::NamedTempFile::new_in(self.config_path.parent().ok_or("invalid state path")?)
                .map_err(|_| "cannot save bot settings")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o600))
                .map_err(|_| "cannot protect bot settings")?;
        }
        use std::io::Write;
        temp.write_all(&bytes)
            .map_err(|_| "cannot save bot settings")?;
        temp.as_file()
            .sync_all()
            .map_err(|_| "cannot save bot settings")?;
        temp.persist(&self.config_path)
            .map_err(|_| "cannot save bot settings")?;
        Ok(())
    }

    pub fn refresh(&self) -> Value {
        self.run_probes(false)
    }

    fn run_probes(&self, scheduled: bool) -> Value {
        {
            let mut snapshot = self
                .snapshot
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if snapshot.running {
                drop(snapshot);
                return self.status();
            }
            snapshot.running = true;
        }
        let results = thread::scope(|scope| {
            let workers: Vec<_> = TARGETS
                .iter()
                .map(|&(id, name, url)| {
                    scope.spawn(move || crate::hincyray::direct_availability_probe(id, name, url))
                })
                .collect();
            workers.into_iter().enumerate().map(|(index, worker)| worker.join().unwrap_or_else(|_| {
                json!({"id": TARGETS[index].0, "name": TARGETS[index].1, "ok": false, "error": "probe failed"})
            })).collect::<Vec<_>>()
        });
        let statuses = std::array::from_fn(|index| results[index]["ok"] == true);
        if scheduled {
            self.policy.on_sample(&statuses);
        }
        let chat = self
            .bot
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        let should_send = {
            let mut snapshot = self
                .snapshot
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            snapshot.results = results;
            snapshot.checked_at = Some(now());
            if scheduled {
                snapshot.next_check = Some(Instant::now() + INTERVAL);
            }
            // First sample establishes a baseline; never notify on startup alone.
            let changed = statuses_changed(snapshot.last_sent, statuses);
            if !changed {
                snapshot.last_sent = Some(statuses);
            }
            chat.as_ref().and_then(|bot| bot.chat_id).is_some() && changed
        };
        if should_send
            && let Some(bot) = chat
            && send_message(&bot, &format_message(&statuses), self.socks_port)
            && self
                .bot
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .as_ref()
                .is_some_and(|current| current.token == bot.token && current.chat_id == bot.chat_id)
        {
            self.snapshot
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .last_sent = Some(statuses);
        }
        let mut snapshot = self
            .snapshot
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        snapshot.running = false;
        drop(snapshot);
        self.status()
    }

    fn poll_pairing(&self) {
        let config = self
            .bot
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        let Some(config) = config.filter(|config| config.chat_id.is_none()) else {
            return;
        };
        let Some(response) = bot_request(
            &config,
            "getUpdates",
            &json!({"offset": config.offset, "limit": 20, "timeout": 0, "allowed_updates": ["message"]}),
            self.socks_port,
        ) else {
            return;
        };
        let Some(updates) = response["result"].as_array() else {
            return;
        };
        let next = pairing_from_updates(&config, updates);
        let mut bot = self.bot.lock().unwrap_or_else(|error| error.into_inner());
        if (next.offset != config.offset || next.chat_id != config.chat_id)
            && bot.as_ref().is_some_and(|current| {
                current.token == config.token
                    && current.configured_at == config.configured_at
                    && current.chat_id.is_none()
            })
            && self.save(&next).is_ok()
        {
            *bot = Some(next);
        }
    }

    pub fn start(self: &Arc<Self>) -> Result<JoinHandle<()>, String> {
        let monitor = Arc::clone(self);
        thread::Builder::new()
            .name("hincyray-direct-monitor".to_owned())
            .stack_size(256 * 1024)
            .spawn(move || {
                let mut last_pair_attempt = Instant::now() - POLL_INTERVAL;
                loop {
                    if crate::hincyray::shutting_down() {
                        break;
                    }
                    let due = monitor
                        .snapshot
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .next_check
                        .is_none_or(|next| Instant::now() >= next);
                    if due {
                        monitor.run_probes(true);
                    }
                    if last_pair_attempt.elapsed() >= POLL_INTERVAL {
                        monitor.poll_pairing();
                        last_pair_attempt = Instant::now();
                    }
                    thread::sleep(Duration::from_secs(1));
                }
            })
            .map_err(|_| "cannot start direct monitor".to_owned())
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn valid_token(token: &str) -> bool {
    let Some((id, secret)) = token.split_once(':') else {
        return false;
    };
    (6..=16).contains(&id.len())
        && id.bytes().all(|b| b.is_ascii_digit())
        && (20..=128).contains(&secret.len())
        && secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn private_start_chat(message: &Value, configured_at: u64) -> Option<i64> {
    (message["chat"]["type"] == "private"
        && message["text"]
            .as_str()
            .is_some_and(|text| text == "/start")
        && message["date"]
            .as_u64()
            .is_some_and(|date| date >= configured_at))
    .then(|| message["chat"]["id"].as_i64())
    .flatten()
}

fn pairing_from_updates(config: &BotConfig, updates: &[Value]) -> BotConfig {
    let mut next = config.clone();
    for update in updates {
        if let Some(id) = update["update_id"].as_i64() {
            next.offset = next.offset.max(id.saturating_add(1));
        }
        if let Some(id) = private_start_chat(&update["message"], next.configured_at) {
            next.chat_id = Some(id);
            break;
        }
    }
    next
}

fn statuses_changed(previous: Option<[bool; 4]>, current: [bool; 4]) -> bool {
    previous.is_some_and(|previous| previous != current)
}

fn bot_request(
    config: &BotConfig,
    method: &str,
    payload: &Value,
    socks_port: u16,
) -> Option<Value> {
    let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{socks_port}")).ok()?;
    let client = reqwest::blocking::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(6))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .ok()?;
    let response = client
        .post(format!(
            "https://api.telegram.org/bot{}/{method}",
            config.token
        ))
        .header("Content-Type", "application/json")
        .body(payload.to_string())
        .send()
        .ok()?;
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|len| len > MAX_BOT_REPLY_BYTES)
    {
        return None;
    }
    use std::io::Read;
    let mut response = response;
    let mut bytes = Vec::new();
    (&mut response)
        .take(MAX_BOT_REPLY_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_BOT_REPLY_BYTES {
        return None;
    }
    let parsed: Value = serde_json::from_slice(&bytes).ok()?;
    (parsed["ok"] == true).then_some(parsed)
}

fn send_message(config: &BotConfig, text: &str, socks_port: u16) -> bool {
    config.chat_id.is_some_and(|chat_id| {
        bot_request(
            config,
            "sendMessage",
            &json!({"chat_id":chat_id,"text":text}),
            socks_port,
        )
        .is_some()
    })
}

fn format_message(statuses: &[bool; 4]) -> String {
    let mut message = String::from("Доступность Direct изменилась:\n");
    for (index, (_, name, _)) in TARGETS.iter().enumerate() {
        message.push_str(if statuses[index] { "✅ " } else { "❌ " });
        message.push_str(name);
        message.push('\n');
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_only_recent_private_start_and_keeps_token_private() {
        let dir = tempfile::tempdir().expect("tempdir");
        let monitor = DirectMonitor::new(&dir.path().join("state.json"), 10808);
        assert_eq!(
            TARGETS.map(|target| target.0),
            ["google", "vk", "ya", "youtube"]
        );
        assert!(!valid_token("broken"));
        assert!(valid_token("123456:abcdefghijklmnopqrstuvwxyz"));
        let reply = monitor
            .configure(r#"{"enabled":true,"token":"123456:abcdefghijklmnopqrstuvwxyz"}"#)
            .expect("configure");
        assert_eq!(reply["bot_paired"], false);
        assert!(
            !monitor
                .status()
                .to_string()
                .contains("abcdefghijklmnopqrstuvwxyz")
        );
        assert!(monitor.config_path.exists());
        let message = format_message(&[true, false, true, false]);
        assert!(message.contains("❌ YouTube"));
        assert!(!message.contains("Telegram"));
        assert!(!message.contains("bing"));
        assert_eq!(message.lines().count(), TARGETS.len() + 1);
        assert_eq!(
            private_start_chat(
                &json!({"chat":{"type":"private","id":42},"text":"/start","date":20}),
                19
            ),
            Some(42)
        );
        assert_eq!(
            private_start_chat(
                &json!({"chat":{"type":"group","id":42},"text":"/start","date":20}),
                19
            ),
            None
        );
        assert_eq!(
            private_start_chat(
                &json!({"chat":{"type":"private","id":42},"text":"/start","date":18}),
                19
            ),
            None
        );
        let initial = BotConfig {
            token: "123456:abcdefghijklmnopqrstuvwxyz".to_owned(),
            chat_id: None,
            offset: 0,
            configured_at: 19,
        };
        let paired = pairing_from_updates(
            &initial,
            &[
                json!({"update_id": 12, "message": {"chat":{"type":"private","id":7},"text":"/start","date":18}}),
                json!({"update_id": 13, "message": {"chat":{"type":"group","id":8},"text":"/start","date":20}}),
                json!({"update_id": 14, "message": {"chat":{"type":"private","id":42},"text":"/start","date":20}}),
            ],
        );
        assert_eq!(paired.chat_id, Some(42));
        assert_eq!(paired.offset, 15);
        let baseline = [true, false, true, false];
        assert!(!statuses_changed(None, baseline));
        assert!(!statuses_changed(Some(baseline), baseline));
        let changed = [true, false, true, true];
        assert!(statuses_changed(Some(baseline), changed));
        assert!(!statuses_changed(Some(changed), changed));
    }
}
