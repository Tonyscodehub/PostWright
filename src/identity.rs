//! Two-factor authentication (TOTP, RFC 6238), recovery codes, app passwords, sign-in
//! sessions, and mailbox delegation.

use crate::store::{self, now, User};
use anyhow::{anyhow, bail, Result};
use base64::Engine;
use hmac::{Hmac, Mac};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS mfa(
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret TEXT,
    pending TEXT,
    enabled INTEGER NOT NULL DEFAULT 0,
    last_step INTEGER NOT NULL DEFAULT 0,
    enabled_at INTEGER
);
CREATE TABLE IF NOT EXISTS recovery_codes(
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    hash TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS app_passwords(
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    hash TEXT NOT NULL,
    created INTEGER NOT NULL,
    last_used INTEGER
);
CREATE INDEX IF NOT EXISTS app_passwords_user ON app_passwords(user_id);
CREATE TABLE IF NOT EXISTS sessions(
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    kind TEXT NOT NULL,
    name TEXT
);
CREATE TABLE IF NOT EXISTS delegations(
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    grantee_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mailbox TEXT NOT NULL DEFAULT 'none',
    send TEXT NOT NULL DEFAULT 'none',
    created INTEGER NOT NULL,
    PRIMARY KEY(owner_id, grantee_id)
);
"#;

pub fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

// ---------------------------------------------------------------------- TOTP

const STEP: u64 = 30;

pub fn totp(secret: &[u8], step: u64) -> u32 {
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(secret).expect("any key length");
    mac.update(&step.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = (h[19] & 0x0f) as usize;
    let bin = ((h[off] as u32 & 0x7f) << 24) | ((h[off + 1] as u32) << 16) | ((h[off + 2] as u32) << 8) | h[off + 3] as u32;
    bin % 1_000_000
}

fn decode_secret(b32: &str) -> Option<Vec<u8>> {
    data_encoding::BASE32_NOPAD.decode(b32.trim().to_ascii_uppercase().trim_end_matches('=').as_bytes()).ok()
}

/// Returns the matching time step (current ±1 for clock drift).
fn check_totp(secret_b32: &str, code: &str, at: i64) -> Option<u64> {
    let code: String = code.chars().filter(|c| c.is_ascii_digit()).collect();
    if code.len() != 6 {
        return None;
    }
    let want: u32 = code.parse().ok()?;
    let secret = decode_secret(secret_b32)?;
    let now = at.max(0) as u64 / STEP;
    [now, now.saturating_sub(1), now + 1].into_iter().find(|&s| totp(&secret, s) == want)
}

#[derive(Serialize)]
pub struct Enrolment {
    pub secret: String,
    pub uri: String,
    pub qr_svg: String,
}

/// Start (or restart) setting up an authenticator app. Nothing changes until confirmed.
pub fn begin_enrolment(c: &Connection, user: &User, issuer: &str) -> Result<Enrolment> {
    let raw: [u8; 20] = rand::random();
    let secret = data_encoding::BASE32_NOPAD.encode(&raw);
    c.execute(
        "INSERT INTO mfa(user_id, pending) VALUES(?1, ?2) ON CONFLICT(user_id) DO UPDATE SET pending = ?2",
        params![user.id, secret],
    )?;
    let enc = |s: &str| crate::http::enc_path(s).replace('@', "%40");
    let uri = format!(
        "otpauth://totp/{}:{}?secret={secret}&issuer={}&algorithm=SHA1&digits=6&period=30",
        enc(issuer),
        enc(&user.email),
        enc(issuer)
    );
    let qr = qrcode::QrCode::new(uri.as_bytes())?;
    let qr_svg = qr
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(220, 220)
        .dark_color(qrcode::render::svg::Color("#000000"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build();
    Ok(Enrolment { secret, uri, qr_svg })
}

/// Confirm with a code from the app. Returns fresh recovery codes (shown once).
pub fn confirm_enrolment(c: &mut Connection, user_id: i64, code: &str) -> Result<Vec<String>> {
    let pending: Option<String> = c.query_row("SELECT pending FROM mfa WHERE user_id = ?1", [user_id], |r| r.get(0)).optional()?.flatten();
    let pending = pending.ok_or_else(|| anyhow!("start setup first"))?;
    let step = check_totp(&pending, code, now()).ok_or_else(|| anyhow!("that code isn't right – check the time on your phone and try the next code"))?;
    let codes = make_codes();
    let tx = c.transaction()?;
    tx.execute(
        "UPDATE mfa SET secret = pending, pending = NULL, enabled = 1, last_step = ?2, enabled_at = ?3 WHERE user_id = ?1",
        params![user_id, step as i64, now()],
    )?;
    store_codes(&tx, user_id, &codes)?;
    tx.commit()?;
    Ok(codes)
}

fn make_codes() -> Vec<String> {
    (0..10)
        .map(|_| {
            let n: u64 = rand::random::<u64>() % 10_000_000_000;
            let s = format!("{n:010}");
            format!("{}-{}", &s[..5], &s[5..])
        })
        .collect()
}

fn store_codes(c: &Connection, user_id: i64, codes: &[String]) -> Result<()> {
    c.execute("DELETE FROM recovery_codes WHERE user_id = ?1", [user_id])?;
    for code in codes {
        c.execute("INSERT INTO recovery_codes(user_id, hash) VALUES(?1, ?2)", params![user_id, sha256_hex(&code.replace('-', ""))])?;
    }
    Ok(())
}

/// Replace the recovery codes (the old set stops working).
pub fn new_recovery_codes(c: &mut Connection, user_id: i64) -> Result<Vec<String>> {
    if !enabled(c, user_id)? {
        bail!("two-factor authentication is off");
    }
    let codes = make_codes();
    let tx = c.transaction()?;
    store_codes(&tx, user_id, &codes)?;
    tx.commit()?;
    Ok(codes)
}

pub fn disable(c: &Connection, user_id: i64) -> Result<()> {
    c.execute("DELETE FROM mfa WHERE user_id = ?1", [user_id])?;
    c.execute("DELETE FROM recovery_codes WHERE user_id = ?1", [user_id])?;
    Ok(())
}

pub fn enabled(c: &Connection, user_id: i64) -> Result<bool> {
    Ok(c.query_row("SELECT enabled FROM mfa WHERE user_id = ?1", [user_id], |r| r.get::<_, i64>(0)).optional()?.unwrap_or(0) != 0)
}

#[derive(Serialize)]
pub struct MfaStatus {
    pub enabled: bool,
    pub enabled_at: Option<i64>,
    pub recovery_codes_left: i64,
}

pub fn status(c: &Connection, user_id: i64) -> Result<MfaStatus> {
    let row: Option<(i64, Option<i64>)> =
        c.query_row("SELECT enabled, enabled_at FROM mfa WHERE user_id = ?1", [user_id], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
    let left: i64 = c.query_row("SELECT COUNT(*) FROM recovery_codes WHERE user_id = ?1 AND used = 0", [user_id], |r| r.get(0))?;
    Ok(MfaStatus { enabled: row.map(|r| r.0 != 0).unwrap_or(false), enabled_at: row.and_then(|r| r.1), recovery_codes_left: left })
}

/// Check a TOTP or recovery code. Each TOTP step and each recovery code works once.
pub fn verify_code(c: &Connection, user_id: i64, code: &str) -> Result<bool> {
    let row: Option<(Option<String>, i64)> =
        c.query_row("SELECT secret, last_step FROM mfa WHERE user_id = ?1 AND enabled = 1", [user_id], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
    let Some((Some(secret), last)) = row else { return Ok(false) };
    if let Some(step) = check_totp(&secret, code, now()) {
        if step as i64 <= last {
            return Ok(false); // replayed code
        }
        c.execute("UPDATE mfa SET last_step = ?2 WHERE user_id = ?1", params![user_id, step as i64])?;
        return Ok(true);
    }
    let digits: String = code.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() == 10 {
        let n = c.execute(
            "UPDATE recovery_codes SET used = 1 WHERE user_id = ?1 AND hash = ?2 AND used = 0",
            params![user_id, sha256_hex(&digits)],
        )?;
        if n > 0 {
            tracing::warn!("recovery code used for user id {user_id}");
            return Ok(true);
        }
    }
    Ok(false)
}

// ------------------------------------------------------------- app passwords

fn normalise_app_password(p: &str) -> String {
    p.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_ascii_lowercase()
}

fn app_hash(user_id: i64, p: &str) -> String {
    sha256_hex(&format!("{user_id}:{}", normalise_app_password(p)))
}

/// Create an app password: 16 random letters, shown once, e.g. "abcd-efgh-ijkl-mnop".
pub fn create_app_password(c: &Connection, user_id: i64, name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() || name.len() > 60 {
        bail!("give the app password a name, e.g. \"Mailwright on laptop\"");
    }
    const ALPHA: &[u8] = b"abcdefghjkmnpqrstuvwxyz"; // no i, l, o: easy to read and type
    let raw: String = (0..16).map(|_| ALPHA[rand::random::<usize>() % ALPHA.len()] as char).collect();
    let shown = format!("{}-{}-{}-{}", &raw[..4], &raw[4..8], &raw[8..12], &raw[12..]);
    c.execute(
        "INSERT INTO app_passwords(user_id, name, hash, created) VALUES(?1, ?2, ?3, ?4)",
        params![user_id, name, app_hash(user_id, &raw), now()],
    )?;
    Ok(shown)
}

#[derive(Serialize)]
pub struct AppPassword {
    pub id: i64,
    pub name: String,
    pub created: i64,
    pub last_used: Option<i64>,
}

pub fn list_app_passwords(c: &Connection, user_id: i64) -> Result<Vec<AppPassword>> {
    let mut st = c.prepare("SELECT id, name, created, last_used FROM app_passwords WHERE user_id = ?1 ORDER BY created")?;
    let v = st
        .query_map([user_id], |r| Ok(AppPassword { id: r.get(0)?, name: r.get(1)?, created: r.get(2)?, last_used: r.get(3)? }))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(v)
}

pub fn delete_app_password(c: &Connection, user_id: i64, id: i64) -> Result<bool> {
    Ok(c.execute("DELETE FROM app_passwords WHERE user_id = ?1 AND id = ?2", params![user_id, id])? > 0)
}

/// Check an app password (cheap: they're long random strings, so a fast hash is safe).
pub fn check_app_password(c: &Connection, user_id: i64, p: &str) -> Result<bool> {
    let norm = normalise_app_password(p);
    if norm.len() != 16 {
        return Ok(false);
    }
    let id: Option<i64> = c
        .query_row("SELECT id FROM app_passwords WHERE user_id = ?1 AND hash = ?2", params![user_id, app_hash(user_id, &norm)], |r| r.get(0))
        .optional()?;
    if let Some(id) = id {
        c.execute("UPDATE app_passwords SET last_used = ?2 WHERE id = ?1", params![id, now()])?;
        return Ok(true);
    }
    Ok(false)
}

// ------------------------------------------------------------------ sessions

/// Session kinds: "web" (browser cookie), "app" (admin desktop app), "device" (a mail
/// app such as Mailwright signing in to IMAP/SMTP with OAUTHBEARER).
fn limits(kind: &str) -> (i64, Option<i64>) {
    match kind {
        "device" => (90 * 86400, None), // stays signed in while used at least every 90 days
        _ => (12 * 3600, Some(7 * 86400)),
    }
}

/// Create a sign-in session; returns the bearer token (only its hash is stored).
pub fn create_session(c: &Connection, user_id: i64, kind: &str, name: Option<&str>) -> Result<String> {
    let raw: [u8; 32] = rand::random();
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    let name = name.map(|n| n.chars().filter(|c| !c.is_control()).take(80).collect::<String>());
    c.execute(
        "INSERT INTO sessions(token_hash, user_id, created, last_seen, kind, name) VALUES(?1, ?2, ?3, ?3, ?4, ?5)",
        params![sha256_hex(&token), user_id, now(), kind, name],
    )?;
    // Housekeeping.
    c.execute(
        "DELETE FROM sessions WHERE (kind != 'device' AND (last_seen < ?1 OR created < ?2)) OR (kind = 'device' AND last_seen < ?3)",
        params![now() - 12 * 3600, now() - 7 * 86400, now() - 90 * 86400],
    )?;
    Ok(token)
}

/// Resolve a token to its user, if the session is live and of an accepted kind.
pub fn session_user(c: &Connection, token: &str, kinds: &[&str]) -> Result<Option<User>> {
    let h = sha256_hex(token);
    let row: Option<(i64, i64, i64, String)> = c
        .query_row("SELECT user_id, created, last_seen, kind FROM sessions WHERE token_hash = ?1", [&h], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .optional()?;
    let Some((uid, created, seen, kind)) = row else { return Ok(None) };
    if !kinds.contains(&kind.as_str()) {
        return Ok(None);
    }
    let t = now();
    let (idle, max) = limits(&kind);
    if t - seen > idle || max.map(|m| t - created > m).unwrap_or(false) {
        c.execute("DELETE FROM sessions WHERE token_hash = ?1", [&h])?;
        return Ok(None);
    }
    if t - seen > 60 {
        c.execute("UPDATE sessions SET last_seen = ?2 WHERE token_hash = ?1", params![h, t])?;
    }
    Ok(store::user_by_id(c, uid)?.filter(|u| u.enabled))
}

pub fn end_session(c: &Connection, token: &str) -> Result<()> {
    c.execute("DELETE FROM sessions WHERE token_hash = ?1", [sha256_hex(token)])?;
    Ok(())
}

/// Sign a user out everywhere (password reset, MFA reset, account disabled).
pub fn end_all_sessions(c: &Connection, user_id: i64) -> Result<()> {
    c.execute("DELETE FROM sessions WHERE user_id = ?1", [user_id])?;
    Ok(())
}

#[derive(Serialize)]
pub struct SignedIn {
    pub id: String,
    pub kind: String,
    pub name: Option<String>,
    pub created: i64,
    pub last_seen: i64,
    pub current: bool,
}

/// Signed-in apps and browsers for the settings page.
pub fn list_sessions(c: &Connection, user_id: i64, current_token: Option<&str>) -> Result<Vec<SignedIn>> {
    let cur = current_token.map(sha256_hex);
    let mut st = c.prepare("SELECT token_hash, kind, name, created, last_seen FROM sessions WHERE user_id = ?1 ORDER BY last_seen DESC")?;
    let v = st
        .query_map([user_id], |r| {
            let h: String = r.get(0)?;
            Ok(SignedIn {
                current: cur.as_deref() == Some(h.as_str()),
                id: h[..16].to_string(),
                kind: r.get(1)?,
                name: r.get(2)?,
                created: r.get(3)?,
                last_seen: r.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(v)
}

pub fn end_session_by_id(c: &Connection, user_id: i64, id: &str) -> Result<bool> {
    if id.len() != 16 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(false);
    }
    Ok(c.execute("DELETE FROM sessions WHERE user_id = ?1 AND substr(token_hash, 1, 16) = ?2", params![user_id, id])? > 0)
}

// --------------------------------------------------------------- delegation

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MailboxRight {
    None,
    Read,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SendRight {
    None,
    OnBehalf,
    As,
}

impl MailboxRight {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "none" | "" => Self::None,
            "read" => Self::Read,
            "full" => Self::Full,
            _ => bail!("mailbox access must be none, read or full"),
        })
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Read => "read",
            Self::Full => "full",
        }
    }
}

impl SendRight {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "none" | "" => Self::None,
            "on_behalf" | "on-behalf" => Self::OnBehalf,
            "as" | "send_as" => Self::As,
            _ => bail!("send rights must be none, on_behalf or as"),
        })
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::OnBehalf => "on_behalf",
            Self::As => "as",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Delegation {
    pub owner: String,
    pub grantee: String,
    pub mailbox: MailboxRight,
    pub send: SendRight,
    pub created: i64,
    #[serde(skip)]
    pub owner_id: i64,
}

pub fn grant(c: &Connection, owner: &str, grantee: &str, mailbox: MailboxRight, send: SendRight) -> Result<()> {
    let o = store::find_user(c, owner)?.ok_or_else(|| anyhow!("no such mailbox {owner}"))?;
    let g = store::find_user(c, grantee)?.ok_or_else(|| anyhow!("no such user {grantee}"))?;
    if o.id == g.id {
        bail!("a user already has full access to their own mailbox");
    }
    if mailbox == MailboxRight::None && send == SendRight::None {
        c.execute("DELETE FROM delegations WHERE owner_id = ?1 AND grantee_id = ?2", params![o.id, g.id])?;
        return Ok(());
    }
    c.execute(
        "INSERT INTO delegations(owner_id, grantee_id, mailbox, send, created) VALUES(?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(owner_id, grantee_id) DO UPDATE SET mailbox = ?3, send = ?4",
        params![o.id, g.id, mailbox.as_str(), send.as_str(), now()],
    )?;
    Ok(())
}

fn row_delegation(r: &rusqlite::Row) -> rusqlite::Result<Delegation> {
    let m: String = r.get(2)?;
    let s: String = r.get(3)?;
    Ok(Delegation {
        owner: r.get(0)?,
        grantee: r.get(1)?,
        mailbox: MailboxRight::parse(&m).unwrap_or(MailboxRight::None),
        send: SendRight::parse(&s).unwrap_or(SendRight::None),
        created: r.get(4)?,
        owner_id: r.get(5)?,
    })
}

const DEL_SQL: &str = "SELECT o.email, g.email, d.mailbox, d.send, d.created, d.owner_id FROM delegations d
     JOIN users o ON o.id = d.owner_id JOIN users g ON g.id = d.grantee_id";

pub fn list_all(c: &Connection) -> Result<Vec<Delegation>> {
    let mut st = c.prepare(&format!("{DEL_SQL} ORDER BY o.email, g.email"))?;
    let v = st.query_map([], row_delegation)?.collect::<Result<Vec<_>, _>>()?;
    Ok(v)
}

/// Mailboxes and send rights this user has been given.
pub fn granted_to(c: &Connection, grantee_id: i64) -> Result<Vec<Delegation>> {
    let mut st = c.prepare(&format!("{DEL_SQL} WHERE d.grantee_id = ?1 ORDER BY o.email"))?;
    let v = st.query_map([grantee_id], row_delegation)?.collect::<Result<Vec<_>, _>>()?;
    Ok(v)
}

/// Addresses this user may put in From:, with the delegation mode required.
pub fn delegated_senders(c: &Connection, grantee_id: i64) -> Result<Vec<(String, SendRight)>> {
    let mut out = Vec::new();
    for d in granted_to(c, grantee_id)? {
        if d.send == SendRight::None {
            continue;
        }
        if let Some(owner) = store::user_by_id(c, d.owner_id)? {
            for a in store::sender_addresses(c, &owner)? {
                out.push((a, d.send));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_vectors() {
        // RFC 6238 appendix B, SHA-1 secret "12345678901234567890" (8-digit codes mod 1e6).
        let secret = b"12345678901234567890";
        assert_eq!(totp(secret, 59 / 30), 287082);
        assert_eq!(totp(secret, 1111111109 / 30), 81804);
        assert_eq!(totp(secret, 1234567890 / 30), 5924);
        let b32 = data_encoding::BASE32_NOPAD.encode(secret);
        assert_eq!(check_totp(&b32, "287 082", 59), Some(1));
        assert_eq!(check_totp(&b32, "287082", 59 + 30), Some(1)); // one step of drift
        assert_eq!(check_totp(&b32, "287082", 59 + 90), None);
        assert_eq!(normalise_app_password("abcd-EFGH ijkl-mnop"), "abcdefghijklmnop");
    }
}
