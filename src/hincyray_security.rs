//! Authentication primitives for the router daemon.
//!
//! This module owns password hashing, cryptographic session-token generation,
//! session expiry, and login throttling. HTTP and persisted-state code pass
//! intent into this boundary; they never implement security policy themselves.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Condvar, Mutex, OnceLock};

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};

pub const SESSION_IDLE_TIMEOUT_SECS: u64 = 30 * 60;
pub const SESSION_ABSOLUTE_TIMEOUT_SECS: u64 = 12 * 60 * 60;
pub const MAX_WEB_SESSIONS: usize = 32;
const LOGIN_WINDOW_SECS: u64 = 5 * 60;
const LOGIN_MAX_FAILURES: usize = 5;
const LOGIN_BLOCK_SECS: u64 = 15 * 60;
const MAX_LOGIN_SOURCES: usize = 256;
pub const MAX_CONCURRENT_PASSWORD_OPS: usize = 2;

#[derive(Clone, Debug)]
pub struct WebSession {
    pub created_at_unix: u64,
    pub last_seen_unix: u64,
    pub expires_at_unix: u64,
}

impl WebSession {
    pub fn new(now: u64) -> Self {
        Self {
            created_at_unix: now,
            last_seen_unix: now,
            expires_at_unix: now.saturating_add(SESSION_ABSOLUTE_TIMEOUT_SECS),
        }
    }

    pub fn validate_and_touch(&mut self, now: u64) -> bool {
        if self.is_expired(now) {
            return false;
        }
        self.last_seen_unix = now;
        true
    }

    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at_unix
            || now
                >= self
                    .last_seen_unix
                    .saturating_add(SESSION_IDLE_TIMEOUT_SECS)
    }
}

#[derive(Clone, Debug, Default)]
struct LoginSourceState {
    failures: VecDeque<u64>,
    blocked_until_unix: u64,
}

#[derive(Clone, Debug, Default)]
pub struct LoginLimiter {
    sources: HashMap<IpAddr, LoginSourceState>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoginReservation {
    retry_after_on_failure: Option<u64>,
}

impl LoginReservation {
    pub fn retry_after_on_failure(self) -> Option<u64> {
        self.retry_after_on_failure
    }
}

impl LoginLimiter {
    /// Atomically admit and account for an attempt before password verification.
    /// The caller must hold the limiter's owning lock for this call.
    pub fn reserve_attempt(&mut self, source: IpAddr, now: u64) -> Result<LoginReservation, u64> {
        self.compact(now);
        let state = self.sources.entry(source).or_default();
        if state.blocked_until_unix > now {
            return Err(state.blocked_until_unix - now);
        }
        state
            .failures
            .retain(|timestamp| now.saturating_sub(*timestamp) <= LOGIN_WINDOW_SECS);
        state.failures.push_back(now);
        let retry_after_on_failure = if state.failures.len() >= LOGIN_MAX_FAILURES {
            state.blocked_until_unix = now.saturating_add(LOGIN_BLOCK_SECS);
            state.failures.clear();
            Some(LOGIN_BLOCK_SECS)
        } else {
            None
        };
        Ok(LoginReservation {
            retry_after_on_failure,
        })
    }

    pub fn record_success(&mut self, source: IpAddr) {
        self.sources.remove(&source);
    }

    fn compact(&mut self, now: u64) {
        self.sources.retain(|_, state| {
            state.blocked_until_unix > now
                || state
                    .failures
                    .iter()
                    .any(|timestamp| now.saturating_sub(*timestamp) <= LOGIN_WINDOW_SECS)
        });
        if self.sources.len() > MAX_LOGIN_SOURCES {
            self.sources.clear();
        }
    }
}

#[derive(Debug)]
pub struct PasswordWorkLimiter {
    permits: usize,
    available: Mutex<usize>,
    changed: Condvar,
}

impl PasswordWorkLimiter {
    pub fn new(permits: usize) -> Self {
        assert!(permits > 0);
        Self {
            permits,
            available: Mutex::new(permits),
            changed: Condvar::new(),
        }
    }

    fn acquire(&self) -> PasswordWorkPermit<'_> {
        let mut available = self
            .available
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        available = self
            .changed
            .wait_while(available, |available| *available == 0)
            .unwrap_or_else(|poison| poison.into_inner());
        *available -= 1;
        PasswordWorkPermit { limiter: self }
    }

    pub fn try_acquire(&self) -> Option<PasswordWorkPermit<'_>> {
        let mut available = self
            .available
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if *available == 0 {
            return None;
        }
        *available -= 1;
        Some(PasswordWorkPermit { limiter: self })
    }

    #[cfg(test)]
    fn in_use(&self) -> usize {
        let available = self
            .available
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        self.permits - *available
    }
}

pub struct PasswordWorkPermit<'a> {
    limiter: &'a PasswordWorkLimiter,
}

impl Drop for PasswordWorkPermit<'_> {
    fn drop(&mut self) {
        let mut available = self
            .limiter
            .available
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        *available += 1;
        debug_assert!(*available <= self.limiter.permits);
        self.limiter.changed.notify_one();
    }
}

fn password_work_limiter() -> &'static PasswordWorkLimiter {
    static LIMITER: OnceLock<PasswordWorkLimiter> = OnceLock::new();
    LIMITER.get_or_init(|| PasswordWorkLimiter::new(MAX_CONCURRENT_PASSWORD_OPS))
}

pub fn hash_password(password: &str) -> Result<String, String> {
    if password.is_empty() {
        return Err("password must not be empty".to_owned());
    }
    let permit = password_work_limiter().acquire();
    hash_password_with_permit(password, permit)
}

pub fn hash_password_with_permit(
    password: &str,
    _permit: PasswordWorkPermit<'_>,
) -> Result<String, String> {
    if password.is_empty() {
        return Err("password must not be empty".to_owned());
    }
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| format!("hash password: {error}"))
}

pub fn verify_password(password: &str, encoded: &str) -> Result<bool, String> {
    let permit = password_work_limiter().acquire();
    verify_password_with_permit(password, encoded, permit)
}

pub fn try_acquire_password_work() -> Option<PasswordWorkPermit<'static>> {
    password_work_limiter().try_acquire()
}

pub fn verify_password_with_permit(
    password: &str,
    encoded: &str,
    _permit: PasswordWorkPermit<'_>,
) -> Result<bool, String> {
    let parsed =
        PasswordHash::new(encoded).map_err(|error| format!("parse password hash: {error}"))?;
    match Argon2::default().verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(error) => Err(format!("verify password: {error}")),
    }
}

pub fn generate_session_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| format!("session entropy: {error}"))?;
    let mut token = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut token, "{byte:02x}").map_err(|error| error.to_string())?;
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Barrier, mpsc};
    use std::thread;

    #[test]
    fn password_hash_round_trip_and_wrong_password() {
        let hash = hash_password("correct horse").expect("hash");
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password("correct horse", &hash).expect("verify"));
        assert!(!verify_password("wrong", &hash).expect("verify wrong"));
        assert!(!hash.contains("correct horse"));
    }

    #[test]
    fn session_token_is_256_bit_hex_and_unique() {
        let first = generate_session_token().expect("token");
        let second = generate_session_token().expect("token");
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first, second);
    }

    #[test]
    fn session_enforces_idle_and_absolute_expiry() {
        let mut session = WebSession::new(100);
        assert!(session.validate_and_touch(101));
        assert!(!session.validate_and_touch(101 + SESSION_IDLE_TIMEOUT_SECS));
        let mut session = WebSession::new(100);
        session.last_seen_unix = 100 + SESSION_ABSOLUTE_TIMEOUT_SECS - 1;
        assert!(!session.validate_and_touch(100 + SESSION_ABSOLUTE_TIMEOUT_SECS));
    }

    #[test]
    fn login_limiter_blocks_after_five_failures_and_resets_on_success() {
        let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut limiter = LoginLimiter::default();
        for attempt in 0..4 {
            assert_eq!(
                limiter
                    .reserve_attempt(source, 100 + attempt)
                    .expect("reserve")
                    .retry_after_on_failure(),
                None
            );
        }
        assert_eq!(
            limiter
                .reserve_attempt(source, 104)
                .expect("fifth reservation")
                .retry_after_on_failure(),
            Some(LOGIN_BLOCK_SECS)
        );
        assert_eq!(
            limiter.reserve_attempt(source, 105),
            Err(LOGIN_BLOCK_SECS - 1)
        );
        limiter.record_success(source);
        assert!(limiter.reserve_attempt(source, 105).is_ok());
    }

    #[test]
    fn concurrent_login_reservations_admit_only_the_attempt_budget() {
        const WORKERS: usize = LOGIN_MAX_FAILURES + 3;
        let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let limiter = Arc::new(Mutex::new(LoginLimiter::default()));
        let start = Arc::new(Barrier::new(WORKERS));
        let mut handles = Vec::new();
        for _ in 0..WORKERS {
            let limiter = Arc::clone(&limiter);
            let start = Arc::clone(&start);
            handles.push(thread::spawn(move || {
                start.wait();
                limiter
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .reserve_attempt(source, 100)
                    .is_ok()
            }));
        }
        let admitted = handles
            .into_iter()
            .map(|handle| handle.join().expect("worker"))
            .filter(|admitted| *admitted)
            .count();
        assert_eq!(admitted, LOGIN_MAX_FAILURES);
    }

    #[test]
    fn password_work_limiter_never_exceeds_its_permit_count() {
        const WORKERS: usize = 8;
        let limiter = Arc::new(PasswordWorkLimiter::new(2));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let (entered_tx, entered_rx) = mpsc::channel();
        let mut handles = Vec::new();
        for _ in 0..WORKERS {
            let limiter = Arc::clone(&limiter);
            let release = Arc::clone(&release);
            let entered_tx = entered_tx.clone();
            handles.push(thread::spawn(move || {
                let _permit = limiter.acquire();
                entered_tx.send(()).expect("report entry");
                let (lock, changed) = &*release;
                let released = lock.lock().unwrap_or_else(|poison| poison.into_inner());
                drop(
                    changed
                        .wait_while(released, |released| !*released)
                        .unwrap_or_else(|poison| poison.into_inner()),
                );
            }));
        }
        drop(entered_tx);

        entered_rx.recv().expect("first permit");
        entered_rx.recv().expect("second permit");
        assert_eq!(limiter.in_use(), 2);

        let (lock, changed) = &*release;
        *lock.lock().unwrap_or_else(|poison| poison.into_inner()) = true;
        changed.notify_all();
        for handle in handles {
            handle.join().expect("worker");
        }
        assert_eq!(entered_rx.iter().count(), WORKERS - 2);
        assert_eq!(limiter.in_use(), 0);
    }

    #[test]
    fn nonblocking_password_admission_rejects_instead_of_queueing() {
        let limiter = PasswordWorkLimiter::new(2);
        let first = limiter.try_acquire().expect("first permit");
        let second = limiter.try_acquire().expect("second permit");
        assert!(limiter.try_acquire().is_none());
        drop(first);
        assert!(limiter.try_acquire().is_some());
        drop(second);
    }
}
