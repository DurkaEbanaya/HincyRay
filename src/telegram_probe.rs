//! Authorized, bounded Telegram media probe and login helpers.

use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use grammers_client::sender::{ConnectionParams, SenderPool, SenderPoolFatHandle};
use grammers_client::session::storages::SqliteSession;
use grammers_client::{Client, SignInError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::runtime::Builder;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const MEDIA_CHUNK_BYTES: i32 = 256 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct TelegramProbeConfig {
    pub api_id: i32,
    pub api_hash: String,
    pub phone: String,
    pub peer: String,
    pub message_id: i32,
    #[serde(default)]
    pub authorized: bool,
}

pub enum LoginState {
    Code(grammers_client::client::LoginToken),
    Password(Box<grammers_client::client::PasswordToken>),
}

pub enum ConfirmResult {
    Authorized,
    PasswordRequired { hint: Option<String> },
}

pub struct MediaProbeResult {
    pub elapsed_ms: u32,
    pub bytes: u64,
}

fn session_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

pub fn load_config(path: &Path) -> Result<TelegramProbeConfig, String> {
    let text =
        fs::read_to_string(path).map_err(|error| format!("read Telegram config: {error}"))?;
    serde_json::from_str(&text).map_err(|error| format!("parse Telegram config: {error}"))
}

pub fn save_config(path: &Path, config: &TelegramProbeConfig) -> Result<(), String> {
    if config.api_id <= 0
        || config.api_hash.trim().is_empty()
        || config.phone.trim().is_empty()
        || normalize_peer(&config.peer).is_none()
        || config.message_id <= 0
    {
        return Err(
            "api_id, api_hash, phone, public peer, and positive message_id are required".to_owned(),
        );
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| format!("create Telegram config dir: {error}"))?;
    let temporary = path.with_extension("json.tmp");
    write_private(
        &temporary,
        &serde_json::to_vec(config).map_err(|error| error.to_string())?,
    )?;
    fs::rename(&temporary, path).map_err(|error| format!("install Telegram config: {error}"))
}

pub fn request_login_code(
    session_path: &Path,
    config: &TelegramProbeConfig,
    socks_port: u16,
) -> Result<LoginState, String> {
    let _guard = session_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    run_async(async {
        let (client, handle, runner) = connect(session_path, config.api_id, socks_port).await?;
        let result = timeout(
            OPERATION_TIMEOUT,
            client.request_login_code(config.phone.trim(), config.api_hash.trim()),
        )
        .await
        .map_err(|_| "Telegram login-code request timed out".to_owned())?
        .map(LoginState::Code)
        .map_err(|error| format!("Telegram login-code request failed: {error}"));
        disconnect(handle, runner, session_path).await;
        result
    })
}

pub fn confirm_login(
    session_path: &Path,
    api_id: i32,
    socks_port: u16,
    state: LoginState,
    code: Option<&str>,
    password: Option<&str>,
) -> Result<(ConfirmResult, Option<LoginState>), String> {
    let _guard = session_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    run_async(async {
        let (client, handle, runner) = connect(session_path, api_id, socks_port).await?;
        let result = match state {
            LoginState::Code(token) => {
                let code = code
                    .filter(|value| !value.trim().is_empty())
                    .ok_or_else(|| "login code is required".to_owned())?;
                match timeout(OPERATION_TIMEOUT, client.sign_in(&token, code.trim())).await {
                    Err(_) => Err("Telegram sign-in timed out".to_owned()),
                    Ok(Ok(_)) => Ok((ConfirmResult::Authorized, None)),
                    Ok(Err(SignInError::PasswordRequired(token))) => {
                        let hint = token.hint().map(str::to_owned);
                        if let Some(password) = password.filter(|value| !value.is_empty()) {
                            check_password(&client, token, password).await
                        } else {
                            Ok((
                                ConfirmResult::PasswordRequired { hint },
                                Some(LoginState::Password(Box::new(token))),
                            ))
                        }
                    }
                    Ok(Err(error)) => Err(format!("Telegram sign-in failed: {error}")),
                }
            }
            LoginState::Password(token) => {
                let password = password
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| "2FA password is required".to_owned())?;
                check_password(&client, *token, password).await
            }
        };
        disconnect(handle, runner, session_path).await;
        result
    })
}

pub fn revoke_and_delete(
    session_path: &Path,
    config: Option<&TelegramProbeConfig>,
    socks_port: u16,
) -> bool {
    let _guard = session_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let revoked = config.is_some_and(|config| {
        run_async(async {
            let (client, handle, runner) = connect(session_path, config.api_id, socks_port).await?;
            let result = timeout(OPERATION_TIMEOUT, client.sign_out())
                .await
                .ok()
                .and_then(Result::ok)
                .is_some();
            disconnect(handle, runner, session_path).await;
            Ok(result)
        })
        .unwrap_or(false)
    });
    let _ = fs::remove_file(session_path);
    for suffix in ["-shm", "-wal"] {
        let _ = fs::remove_file(format!("{}{suffix}", session_path.display()));
    }
    revoked
}

pub fn probe_media(
    session_path: &Path,
    config: &TelegramProbeConfig,
    socks_port: u16,
    cancel: &AtomicBool,
) -> Result<MediaProbeResult, String> {
    let _guard = loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("benchmark cancelled".to_owned());
        }
        match session_lock().try_lock() {
            Ok(guard) => break guard,
            Err(std::sync::TryLockError::WouldBlock) => {
                std::thread::sleep(Duration::from_millis(40));
            }
            Err(std::sync::TryLockError::Poisoned(poison)) => break poison.into_inner(),
        }
    };
    run_async(async {
        let started = Instant::now();
        let (client, handle, runner) = connect(session_path, config.api_id, socks_port).await?;
        let operation = async {
            if !client
                .is_authorized()
                .await
                .map_err(|error| error.to_string())?
            {
                return Err("Telegram session is not authorized".to_owned());
            }
            let username = normalize_peer(&config.peer)
                .ok_or_else(|| "Telegram peer must be a public username or t.me link".to_owned())?;
            let peer = client
                .resolve_username(&username)
                .await
                .map_err(|error| format!("resolve Telegram peer: {error}"))?
                .ok_or_else(|| "Telegram peer not found".to_owned())?;
            let peer_ref = peer
                .to_ref()
                .await
                .map_err(|error| format!("resolve Telegram peer ref: {error}"))?
                .ok_or_else(|| "Telegram peer has no usable access hash".to_owned())?;
            let message = client
                .get_messages_by_id(peer_ref, &[config.message_id])
                .await
                .map_err(|error| format!("get Telegram message: {error}"))?
                .into_iter()
                .next()
                .flatten()
                .ok_or_else(|| "Telegram test message not found".to_owned())?;
            let media = message
                .media()
                .ok_or_else(|| "Telegram test message has no media".to_owned())?;
            let bytes = client
                .iter_download(&media)
                .chunk_size(MEDIA_CHUNK_BYTES)
                .next()
                .await
                .map_err(|error| format!("download Telegram media: {error}"))?
                .ok_or_else(|| "Telegram media returned no bytes".to_owned())?;
            Ok(MediaProbeResult {
                elapsed_ms: started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32,
                bytes: bytes.len() as u64,
            })
        };
        tokio::pin!(operation);
        let operation_started = Instant::now();
        let result = loop {
            if cancel.load(Ordering::Relaxed) {
                break Err("benchmark cancelled".to_owned());
            }
            if operation_started.elapsed() >= OPERATION_TIMEOUT {
                break Err("Telegram media probe timed out".to_owned());
            }
            tokio::select! {
                result = &mut operation => break result,
                () = sleep(Duration::from_millis(40)) => {}
            }
        };
        disconnect(handle, runner, session_path).await;
        result
    })
}

async fn check_password(
    client: &Client,
    token: grammers_client::client::PasswordToken,
    password: &str,
) -> Result<(ConfirmResult, Option<LoginState>), String> {
    match timeout(OPERATION_TIMEOUT, client.check_password(token, password)).await {
        Err(_) => Err("Telegram 2FA check timed out".to_owned()),
        Ok(Ok(_)) => Ok((ConfirmResult::Authorized, None)),
        Ok(Err(SignInError::InvalidPassword(token))) => {
            let hint = token.hint().map(str::to_owned);
            Ok((
                ConfirmResult::PasswordRequired { hint },
                Some(LoginState::Password(Box::new(token))),
            ))
        }
        Ok(Err(error)) => Err(format!("Telegram 2FA check failed: {error}")),
    }
}

async fn connect(
    session_path: &Path,
    api_id: i32,
    socks_port: u16,
) -> Result<(Client, SenderPoolFatHandle, JoinHandle<()>), String> {
    ensure_private_session_file(session_path)?;
    let session = Arc::new(
        SqliteSession::open(session_path)
            .await
            .map_err(|error| format!("open Telegram session: {error}"))?,
    );
    secure_session_files(session_path)?;
    let params = ConnectionParams {
        app_version: format!("HincyRay {}", env!("CARGO_PKG_VERSION")),
        proxy_url: Some(format!("socks5://127.0.0.1:{socks_port}")),
        ..Default::default()
    };
    let SenderPool { runner, handle, .. } = SenderPool::with_configuration(session, api_id, params);
    let client = Client::new(handle.clone());
    let task = tokio::spawn(runner.run());
    Ok((client, handle, task))
}

async fn disconnect(handle: SenderPoolFatHandle, runner: JoinHandle<()>, session_path: &Path) {
    handle.quit();
    let _ = runner.await;
    let _ = secure_session_files(session_path);
}

fn run_async<T>(future: impl Future<Output = Result<T, String>>) -> Result<T, String> {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("create Telegram runtime: {error}"))?
        .block_on(future)
}

fn normalize_peer(peer: &str) -> Option<String> {
    let trimmed = peer.trim().trim_start_matches('@');
    let username = trimmed
        .strip_prefix("https://t.me/")
        .or_else(|| trimmed.strip_prefix("http://t.me/"))
        .unwrap_or(trimmed)
        .split('/')
        .next()
        .unwrap_or_default();
    (!username.is_empty()
        && username
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_'))
    .then(|| username.to_owned())
}

fn ensure_private_session_file(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create Telegram session dir: {error}"))?;
    }
    if !path.exists() {
        write_private(path, &[])?;
    }
    set_private_permissions(path)
}

fn secure_session_files(path: &Path) -> Result<(), String> {
    set_private_permissions(path)?;
    for suffix in ["-shm", "-wal"] {
        let sidecar = format!("{}{suffix}", path.display());
        let sidecar = Path::new(&sidecar);
        if sidecar.exists() {
            set_private_permissions(sidecar)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("open private file: {error}"))?;
    file.write_all(bytes)
        .map_err(|error| format!("write private file: {error}"))
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, bytes).map_err(|error| format!("write private file: {error}"))
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("secure private file: {error}"))
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_public_peer_inputs() {
        assert_eq!(
            normalize_peer("@example_channel"),
            Some("example_channel".to_owned())
        );
        assert_eq!(
            normalize_peer("https://t.me/example_channel/42"),
            Some("example_channel".to_owned())
        );
        assert_eq!(normalize_peer("bad peer"), None);
    }

    #[cfg(unix)]
    #[test]
    fn config_is_written_with_private_permissions() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("telegram.json");
        save_config(
            &path,
            &TelegramProbeConfig {
                api_id: 1,
                api_hash: "secret".to_owned(),
                phone: "+10000000000".to_owned(),
                peer: "example_channel".to_owned(),
                message_id: 1,
                authorized: false,
            },
        )
        .expect("save config");
        assert_eq!(
            fs::metadata(path).expect("metadata").permissions().mode() & 0o777,
            0o600
        );
    }
}
