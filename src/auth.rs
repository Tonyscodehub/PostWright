//! Password hashing (Argon2id), credential checks, brute-force throttling and
//! per-IP connection limits.

use crate::store::{self, Store, User};
use anyhow::Result;
use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use base64::Engine;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub fn hash_password(pw: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("hashing failed: {e}"))
}

fn verify_hash(pw: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(h) => Argon2::default().verify_password(pw.as_bytes(), &h).is_ok(),
        Err(_) => false,
    }
}

/// A fixed hash used when the user does not exist, so response timing does not reveal
/// which accounts are valid.
static DUMMY_HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Argon2 deliberately costs ~19 MB and real CPU per check. Bounding concurrent checks keeps
/// memory flat and stops a login flood from starving the server.
fn hash_slots() -> &'static tokio::sync::Semaphore {
    static S: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    S.get_or_init(|| tokio::sync::Semaphore::new(std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2).clamp(2, 8)))
}

/// Check credentials. Runs Argon2 on the blocking pool.
pub async fn authenticate(store: &Store, email: &str, password: &str) -> Result<Option<User>> {
    if password.len() > 1024 || email.len() > 320 {
        return Ok(None);
    }
    let _slot = hash_slots().acquire().await?;
    let email = email.trim().to_ascii_lowercase();
    let pw = password.to_string();
    store
        .call(move |c| {
            let user = store::find_user(c, &email)?;
            let dummy = DUMMY_HASH.get_or_init(|| hash_password("postwright-dummy").unwrap_or_default());
            let (hash, user) = match user {
                Some(u) if u.enabled => (u.password.clone(), Some(u)),
                _ => (dummy.clone(), None),
            };
            let ok = verify_hash(&pw, &hash);
            Ok(if ok { user } else { None })
        })
        .await
}

/// Decode a SASL PLAIN response: authzid \0 authcid \0 passwd.
pub fn decode_plain(b64: &str) -> Option<(String, String)> {
    let raw = base64::engine::general_purpose::STANDARD.decode(b64.trim()).ok()?;
    let mut parts = raw.split(|&b| b == 0);
    let authz = parts.next()?;
    let user = parts.next()?;
    let pass = parts.next()?;
    let user = String::from_utf8(user.to_vec()).ok()?;
    let authz = String::from_utf8(authz.to_vec()).ok()?;
    // We don't support acting as another user.
    if !authz.is_empty() && !authz.eq_ignore_ascii_case(&user) {
        return None;
    }
    Some((user, String::from_utf8(pass.to_vec()).ok()?))
}

pub fn b64d(s: &str) -> Option<String> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .ok()
        .and_then(|v| String::from_utf8(v).ok())
}


// ------------------------------------------------------------- throttling

#[derive(Clone)]
pub struct Guard {
    inner: Arc<Mutex<GuardState>>,
    max_failures: u32,
    window: Duration,
    max_per_ip: usize,
}

#[derive(Default)]
struct GuardState {
    failures: HashMap<IpAddr, (u32, Instant)>,
    conns: HashMap<IpAddr, usize>,
}

/// Held for the lifetime of a connection; releases the per-IP slot on drop.
pub struct ConnSlot {
    guard: Guard,
    ip: IpAddr,
}

impl Drop for ConnSlot {
    fn drop(&mut self) {
        let mut s = self.guard.inner.lock().unwrap();
        if let Some(n) = s.conns.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                s.conns.remove(&self.ip);
            }
        }
    }
}

impl Guard {
    pub fn new(max_failures: u32, block_secs: u64, max_per_ip: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(GuardState::default())),
            max_failures,
            window: Duration::from_secs(block_secs),
            max_per_ip,
        }
    }

    pub fn connect(&self, ip: IpAddr) -> Option<ConnSlot> {
        let mut s = self.inner.lock().unwrap();
        let n = s.conns.entry(ip).or_insert(0);
        if *n >= self.max_per_ip {
            return None;
        }
        *n += 1;
        Some(ConnSlot { guard: self.clone(), ip })
    }

    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        let mut s = self.inner.lock().unwrap();
        match s.failures.get(&ip) {
            Some((n, t)) if t.elapsed() < self.window => *n >= self.max_failures,
            Some(_) => {
                s.failures.remove(&ip);
                false
            }
            None => false,
        }
    }

    pub fn record_failure(&self, ip: IpAddr) {
        let mut s = self.inner.lock().unwrap();
        let e = s.failures.entry(ip).or_insert((0, Instant::now()));
        if e.1.elapsed() >= self.window {
            *e = (0, Instant::now());
        }
        e.0 += 1;
        e.1 = Instant::now();
        if e.0 == self.max_failures {
            tracing::warn!(%ip, "blocking IP after repeated authentication failures");
        }
        // Keep the table bounded.
        if s.failures.len() > 100_000 {
            let w = self.window;
            s.failures.retain(|_, (_, t)| t.elapsed() < w);
        }
    }

    pub fn record_success(&self, ip: IpAddr) {
        self.inner.lock().unwrap().failures.remove(&ip);
    }
}
