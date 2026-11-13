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
    if hash.starts_with("$argon2") {
        return match PasswordHash::new(hash) {
            Ok(h) => Argon2::default().verify_password(pw.as_bytes(), &h).is_ok(),
            Err(_) => false,
        };
    }
    verify_legacy(pw, hash)
}

pub fn is_legacy(hash: &str) -> bool {
    !hash.starts_with("$argon2")
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Salted digest: base64(digest(pw + salt) + salt), as used by Dovecot/iRedMail {SSHA*}.
fn ssha<D: sha2::Digest>(pw: &str, b64: &str) -> bool {
    let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) else { return false };
    let n = <D as sha2::Digest>::output_size();
    if raw.len() <= n {
        return false;
    }
    let (digest, salt) = raw.split_at(n);
    let mut h = D::new();
    h.update(pw.as_bytes());
    h.update(salt);
    ct_eq(&h.finalize(), digest)
}

fn plain_digest<D: sha2::Digest>(pw: &str, enc: &str) -> bool {
    let d = D::digest(pw.as_bytes());
    let e = enc.trim();
    ct_eq(base64::engine::general_purpose::STANDARD.encode(&d).as_bytes(), e.as_bytes())
        || ct_eq(hex::encode(&d).as_bytes(), e.to_ascii_lowercase().as_bytes())
}

/// Password schemes found in iRedMail/Dovecot/Postfixadmin databases. Verified once, then
/// replaced with Argon2id by the caller.
pub fn verify_legacy(pw: &str, hash: &str) -> bool {
    let hash = hash.trim();
    let (scheme, rest) = match hash.strip_prefix('{').and_then(|h| h.split_once('}')) {
        Some((s, r)) => (s.to_ascii_uppercase(), r),
        None => (String::new(), hash),
    };
    match scheme.as_str() {
        "SSHA512" => ssha::<sha2::Sha512>(pw, rest),
        "SSHA256" => ssha::<sha2::Sha256>(pw, rest),
        "SSHA" => ssha::<sha1::Sha1>(pw, rest),
        "SHA512" => plain_digest::<sha2::Sha512>(pw, rest),
        "SHA256" => plain_digest::<sha2::Sha256>(pw, rest),
        "SHA" | "SHA1" => plain_digest::<sha1::Sha1>(pw, rest),
        "PLAIN-MD5" | "MD5" | "LDAP-MD5" => plain_digest::<md5::Md5>(pw, rest),
        "SMD5" => ssha::<md5::Md5>(pw, rest),
        "PLAIN" | "CLEARTEXT" | "CLEAR" => ct_eq(pw.as_bytes(), rest.as_bytes()),
        // {CRYPT}, {BLF-CRYPT}, {SHA512-CRYPT}, {MD5-CRYPT} or a bare crypt(3) string.
        "" | "CRYPT" | "BLF-CRYPT" | "SHA512-CRYPT" | "SHA256-CRYPT" | "MD5-CRYPT" => {
            rest.starts_with('$') && pwhash::unix::verify(pw, rest)
        }
        _ => false,
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

/// Sign-in for mail apps and calendars (IMAP, SMTP, CalDAV): an app password always
/// works; the account password works only while two-factor authentication is off.
pub async fn authenticate(store: &Store, email: &str, password: &str) -> Result<Option<User>> {
    let (e, p) = (email.trim().to_ascii_lowercase(), password.to_string());
    let via_app = store
        .call(move |c| {
            let Some(u) = store::find_user(c, &e)? else { return Ok(Err(false)) };
            if !u.enabled {
                return Ok(Err(false));
            }
            if crate::identity::check_app_password(c, u.id, &p)? {
                return Ok(Ok(u));
            }
            Ok(Err(crate::identity::enabled(c, u.id)?))
        })
        .await?;
    match via_app {
        Ok(u) => Ok(Some(u)),
        Err(true) => {
            // 2FA is on: the account password isn't accepted here. Still spend the
            // same time so this can't be used to probe which accounts have 2FA.
            let _ = verify_password(store, "", password).await;
            Ok(None)
        }
        Err(false) => verify_password(store, email, password).await,
    }
}

pub enum WebLogin {
    Ok(User),
    /// Password right; a code from the authenticator app (or a recovery code) is needed.
    NeedCode,
    Fail,
}

/// Sign-in for the web pages and admin app: account password, plus a code when 2FA is on.
pub async fn web_login(store: &Store, email: &str, password: &str, code: Option<&str>) -> Result<WebLogin> {
    let Some(u) = verify_password(store, email, password).await? else { return Ok(WebLogin::Fail) };
    let code = code.map(|c| c.trim().to_string()).filter(|c| !c.is_empty());
    let id = u.id;
    let res = store
        .call(move |c| {
            if !crate::identity::enabled(c, id)? {
                return Ok(Some(true));
            }
            match code {
                None => Ok(None),
                Some(code) => Ok(Some(crate::identity::verify_code(c, id, &code)?)),
            }
        })
        .await?;
    Ok(match res {
        Some(true) => WebLogin::Ok(u),
        None => WebLogin::NeedCode,
        Some(false) => WebLogin::Fail,
    })
}

/// Check the account password itself. Runs Argon2 on the blocking pool.
pub async fn verify_password(store: &Store, email: &str, password: &str) -> Result<Option<User>> {
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
            if ok {
                if let Some(u) = &user {
                    if is_legacy(&u.password) {
                        // Transparent upgrade of imported hashes to Argon2id.
                        let new = hash_password(&pw)?;
                        store::set_password(c, &u.email, &new)?;
                        tracing::info!("upgraded password hash for {} to Argon2id", u.email);
                    }
                }
            }
            Ok(if ok { user } else { None })
        })
        .await
}

/// Decode a SASL PLAIN response: authzid \0 authcid \0 passwd.
/// `{"status":"invalid_token"}` base64-encoded, the RFC 7628 failure challenge.
pub const BEARER_ERROR_B64: &str = "eyJzdGF0dXMiOiJpbnZhbGlkX3Rva2VuIn0=";

/// Decode an OAUTHBEARER (RFC 7628) or XOAUTH2 initial response into (user, token).
pub fn decode_bearer(b64: &str) -> Option<(Option<String>, String)> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD.decode(b64.trim()).ok()?;
    let s = String::from_utf8(raw).ok()?;
    let mut user = None;
    let mut token = None;
    for part in s.split('\x01') {
        if let Some(gs2) = part.strip_prefix("n,").or_else(|| part.strip_prefix("y,")) {
            // GS2 header: n,a=user@example.com,
            for f in gs2.split(',') {
                if let Some(a) = f.strip_prefix("a=") {
                    user = Some(a.replace("=2C", ",").replace("=3D", "="));
                }
            }
        } else if let Some(u) = part.strip_prefix("user=") {
            user = Some(u.to_string());
        } else if let Some(a) = part.strip_prefix("auth=") {
            let t = a.strip_prefix("Bearer ").or_else(|| a.strip_prefix("bearer "))?;
            token = Some(t.trim().to_string());
        }
    }
    Some((user.filter(|u| !u.is_empty()), token?))
}

/// Sign in to IMAP/SMTP/CalDAV with a device token. If the client also names a user it
/// must match the token's owner.
pub async fn token_login(store: &Store, who: Option<&str>, token: &str) -> Result<Option<User>> {
    let t = token.to_string();
    let u = store.call(move |c| crate::identity::session_user(c, &t, &["device"])).await?;
    Ok(u.filter(|u| who.map(|w| w.eq_ignore_ascii_case(&u.email)).unwrap_or(true)))
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_hashes() {
        // Generated with: doveadm pw -s SSHA512 -p secret123 (format reproduced here).
        use sha2::Digest;
        let salt = b"abcdefgh";
        let mut h = sha2::Sha512::new();
        h.update(b"secret123");
        h.update(salt);
        let mut raw = h.finalize().to_vec();
        raw.extend_from_slice(salt);
        let ssha512 = format!("{{SSHA512}}{}", base64::engine::general_purpose::STANDARD.encode(raw));
        assert!(verify_legacy("secret123", &ssha512));
        assert!(!verify_legacy("wrong", &ssha512));
        let bcrypt = pwhash::bcrypt::hash("secret123").unwrap();
        assert!(verify_legacy("secret123", &format!("{{CRYPT}}{bcrypt}")));
        assert!(verify_legacy("secret123", &format!("{{BLF-CRYPT}}{bcrypt}")));
        let sha512c = pwhash::sha512_crypt::hash("secret123").unwrap();
        assert!(verify_legacy("secret123", &format!("{{CRYPT}}{sha512c}")));
        assert!(verify_legacy("secret123", &sha512c));
        let md5hex = hex::encode(<md5::Md5 as sha2::Digest>::digest(b"secret123"));
        assert!(verify_legacy("secret123", &format!("{{PLAIN-MD5}}{md5hex}")));
        assert!(!verify_legacy("x", "{UNKNOWN}abc"));
        assert!(!verify_legacy("x", ""));
    }
}
