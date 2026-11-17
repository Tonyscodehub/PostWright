//! Two-step codes checked by an external RADIUS server, such as multiOTP (which runs
//! on Windows), LinOTP, privacyIDEA or FreeRADIUS. One token then covers mail and
//! anything else that server protects (a VPN on OPNsense, Windows sign-in...).
//!
//! RFC 2865 Access-Request with PAP, always carrying a Message-Authenticator
//! (RFC 3579; required by current servers since the "BlastRADIUS" fixes), and the
//! reply's Response Authenticator and Message-Authenticator checked.

use anyhow::{anyhow, bail, Result};
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS radius_users(user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE);";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct RadiusConfig {
    /// "host:port", usually port 1812.
    pub server: String,
    /// Tried when the first doesn't answer.
    pub backup_server: String,
    pub secret: String,
    /// "all" users, or only those "selected" in the admin console.
    pub users: String,
    /// What to send as the user name: "email" (tony@example.com) or "local" (tony).
    pub username: String,
    /// What to send as the password: the "code" alone, or "password+code" for servers
    /// set up with a PIN or password prefix.
    pub send: String,
    pub nas_identifier: String,
    pub timeout_secs: u64,
    /// Let mail apps keep using the account password (instead of app passwords) for
    /// users this applies to. Less secure; useful while people move over.
    pub mail_apps_keep_password: bool,
}

impl Default for RadiusConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            backup_server: String::new(),
            secret: String::new(),
            users: "selected".into(),
            username: "email".into(),
            send: "code".into(),
            nas_identifier: "postwright".into(),
            timeout_secs: 5,
            mail_apps_keep_password: false,
        }
    }
}

static CURRENT: RwLock<Option<Arc<RadiusConfig>>> = RwLock::new(None);

/// The settings in force (None when RADIUS isn't used).
pub fn current() -> Option<Arc<RadiusConfig>> {
    CURRENT.read().unwrap().clone()
}

pub fn set(c: Option<RadiusConfig>) {
    *CURRENT.write().unwrap() = c.filter(|c| !c.server.trim().is_empty()).map(Arc::new);
}

pub fn validate(c: &RadiusConfig) -> Result<()> {
    let addr_ok = |a: &str| a.rsplit_once(':').map(|(h, p)| !h.is_empty() && p.parse::<u16>().is_ok()).unwrap_or(false);
    if !addr_ok(c.server.trim()) {
        bail!("the server should look like 192.168.1.72:1812");
    }
    if !c.backup_server.trim().is_empty() && !addr_ok(c.backup_server.trim()) {
        bail!("the backup server should look like 192.168.1.73:1812");
    }
    if c.secret.len() < 8 {
        bail!("use a shared secret of at least 8 characters (the same one set on the RADIUS server)");
    }
    if !["all", "selected"].contains(&c.users.as_str()) || !["email", "local"].contains(&c.username.as_str()) || !["code", "password+code"].contains(&c.send.as_str()) {
        bail!("unknown option");
    }
    if c.timeout_secs == 0 || c.timeout_secs > 30 {
        bail!("use a timeout between 1 and 30 seconds");
    }
    Ok(())
}

/// Does RADIUS decide this user's second step?
pub fn applies(c: &Connection, user_id: i64) -> Result<bool> {
    let Some(cfg) = current() else { return Ok(false) };
    if cfg.users == "all" {
        return Ok(true);
    }
    Ok(c.query_row("SELECT 1 FROM radius_users WHERE user_id = ?1", [user_id], |_| Ok(())).optional()?.is_some())
}

/// Mail apps need an app password for this user (RADIUS applies and the account
/// password isn't allowed for mail apps).
pub fn blocks_mail_password(c: &Connection, user_id: i64) -> Result<bool> {
    Ok(applies(c, user_id)? && !current().map(|c| c.mail_apps_keep_password).unwrap_or(false))
}

pub fn select(c: &Connection, user_id: i64, on: bool) -> Result<()> {
    if on {
        c.execute("INSERT OR IGNORE INTO radius_users(user_id) VALUES(?1)", [user_id])?;
    } else {
        c.execute("DELETE FROM radius_users WHERE user_id = ?1", [user_id])?;
    }
    Ok(())
}

pub fn selected(c: &Connection) -> Result<Vec<i64>> {
    let mut st = c.prepare("SELECT user_id FROM radius_users")?;
    let v = st.query_map(params![], |r| r.get(0))?.collect::<Result<Vec<i64>, _>>()?;
    Ok(v)
}

#[derive(Debug, PartialEq)]
pub enum Answer {
    Accept,
    Reject(Option<String>),
    /// The server wants another round (SMS, push...). Not supported for sign-in yet.
    Challenge(Option<String>),
}

/// Ask the server about a code. Errors mean no usable answer (unreachable, bad
/// secret, forged reply).
pub async fn check(cfg: &RadiusConfig, email: &str, password: &str, code: &str) -> Result<(Answer, Duration)> {
    let user = if cfg.username == "local" { email.split('@').next().unwrap_or(email).to_string() } else { email.to_string() };
    let pass = if cfg.send == "password+code" { format!("{password}{code}") } else { code.to_string() };
    let mut last = anyhow!("no RADIUS server set");
    for server in [cfg.server.trim(), cfg.backup_server.trim()].into_iter().filter(|s| !s.is_empty()) {
        let started = Instant::now();
        match ask(server, &cfg.secret, &cfg.nas_identifier, &user, &pass, Duration::from_secs(cfg.timeout_secs)).await {
            Ok(a) => return Ok((a, started.elapsed())),
            Err(e) => {
                tracing::warn!("RADIUS {server}: {e:#}");
                last = e.context(format!("RADIUS server {server}"));
            }
        }
    }
    Err(last)
}

type HmacMd5 = Hmac<Md5>;

fn md5(parts: &[&[u8]]) -> [u8; 16] {
    let mut h = Md5::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// RFC 2865 5.2: the password, padded to 16-byte blocks, chained with MD5.
pub fn hide_password(pass: &[u8], secret: &[u8], authenticator: &[u8; 16]) -> Vec<u8> {
    let mut p = pass.to_vec();
    let n = p.len().div_ceil(16).max(1) * 16;
    p.resize(n.min(128), 0);
    let mut out = Vec::with_capacity(p.len());
    let mut prev: Vec<u8> = authenticator.to_vec();
    for chunk in p.chunks(16) {
        let b = md5(&[secret, &prev]);
        let c: Vec<u8> = chunk.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect();
        prev = c.clone();
        out.extend(c);
    }
    out
}

fn attr(out: &mut Vec<u8>, t: u8, v: &[u8]) {
    out.push(t);
    out.push((v.len() + 2) as u8);
    out.extend_from_slice(v);
}

/// Build an Access-Request. Returns (packet, request authenticator).
pub fn request(id: u8, secret: &str, nas: &str, user: &str, pass: &str) -> Result<(Vec<u8>, [u8; 16])> {
    if user.len() > 253 || pass.len() > 128 || nas.len() > 253 {
        bail!("user name or code too long");
    }
    let ra: [u8; 16] = rand::random();
    let mut attrs = Vec::new();
    // Message-Authenticator first, as the BlastRADIUS guidance recommends.
    attr(&mut attrs, 80, &[0u8; 16]);
    attr(&mut attrs, 1, user.as_bytes());
    attr(&mut attrs, 2, &hide_password(pass.as_bytes(), secret.as_bytes(), &ra));
    attr(&mut attrs, 32, nas.as_bytes());
    attr(&mut attrs, 6, &1u32.to_be_bytes()); // Service-Type = Login-User
    let len = 20 + attrs.len();
    let mut pkt = vec![1u8, id];
    pkt.extend_from_slice(&(len as u16).to_be_bytes());
    pkt.extend_from_slice(&ra);
    pkt.extend_from_slice(&attrs);
    let mut mac = HmacMd5::new_from_slice(secret.as_bytes()).map_err(|e| anyhow!("{e}"))?;
    mac.update(&pkt);
    let tag = mac.finalize().into_bytes();
    // The Message-Authenticator value sits right after its 2-byte header at offset 20.
    pkt[22..38].copy_from_slice(&tag);
    Ok((pkt, ra))
}

/// Check and read a reply to the request with this id and authenticator.
pub fn parse_reply(pkt: &[u8], id: u8, ra: &[u8; 16], secret: &str) -> Result<Answer> {
    if pkt.len() < 20 || pkt[1] != id {
        bail!("reply doesn't match the request");
    }
    let len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if len < 20 || len > pkt.len() {
        bail!("malformed reply");
    }
    let pkt = &pkt[..len];
    let expect = md5(&[&pkt[..4], ra, &pkt[20..], secret.as_bytes()]);
    if expect[..] != pkt[4..20] {
        bail!("the reply didn't verify: check that the shared secret matches the RADIUS server's");
    }
    let mut message: Option<String> = None;
    let mut i = 20;
    let mut ma_at = None;
    while i + 2 <= pkt.len() {
        let (t, l) = (pkt[i], pkt[i + 1] as usize);
        if l < 2 || i + l > pkt.len() {
            bail!("malformed reply attributes");
        }
        let v = &pkt[i + 2..i + l];
        match t {
            18 => message = Some(String::from_utf8_lossy(v).into_owned()),
            80 if l == 18 => ma_at = Some(i + 2),
            _ => {}
        }
        i += l;
    }
    if let Some(at) = ma_at {
        // Computed over the reply with the request authenticator and a zeroed MA.
        let mut copy = pkt.to_vec();
        copy[4..20].copy_from_slice(ra);
        copy[at..at + 16].fill(0);
        let mut mac = HmacMd5::new_from_slice(secret.as_bytes()).map_err(|e| anyhow!("{e}"))?;
        mac.update(&copy);
        mac.verify_slice(&pkt[at..at + 16]).map_err(|_| anyhow!("the reply's Message-Authenticator didn't verify"))?;
    }
    Ok(match pkt[0] {
        2 => Answer::Accept,
        3 => Answer::Reject(message),
        11 => Answer::Challenge(message),
        c => bail!("unexpected RADIUS reply code {c}"),
    })
}

async fn ask(server: &str, secret: &str, nas: &str, user: &str, pass: &str, timeout: Duration) -> Result<Answer> {
    let addr: SocketAddr = tokio::net::lookup_host(server).await?.next().ok_or_else(|| anyhow!("can't resolve {server}"))?;
    let sock = tokio::net::UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await?;
    sock.connect(addr).await?;
    let id: u8 = rand::random();
    let (pkt, ra) = request(id, secret, nas, user, pass)?;
    let mut buf = vec![0u8; 4096];
    // Up to three tries within the timeout (UDP can drop a packet).
    let per_try = timeout / 3;
    for _ in 0..3 {
        sock.send(&pkt).await?;
        let deadline = tokio::time::Instant::now() + per_try;
        loop {
            match tokio::time::timeout_at(deadline, sock.recv(&mut buf)).await {
                Err(_) => break,
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    bail!("nothing is answering RADIUS at {server}: is the RADIUS service running, and is UDP port {} allowed through its firewall?", addr.port())
                }
                Ok(Err(e)) => return Err(anyhow!("{e}")),
                Ok(Ok(n)) => {
                    // Ignore stray packets; a reply that fails verification is an error.
                    if n >= 2 && buf[1] == id {
                        return parse_reply(&buf[..n], id, &ra, secret);
                    }
                }
            }
        }
    }
    bail!("no answer within {} seconds: check the address, that UDP port {} is allowed through the firewall, that this server is listed as a client on the RADIUS server, and that the shared secret matches", timeout.as_secs(), addr.port())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc2865_password_hiding() {
        // Hiding is reversible with the same secret and authenticator.
        let ra = [7u8; 16];
        let hidden = hide_password(b"123456", b"s3cretsecret", &ra);
        assert_eq!(hidden.len(), 16);
        let b = md5(&[b"s3cretsecret", &ra]);
        let back: Vec<u8> = hidden.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect();
        assert_eq!(&back[..6], b"123456");
        assert!(back[6..].iter().all(|x| *x == 0));
        assert_eq!(hide_password(&[b'a'; 20], b"x", &ra).len(), 32);
    }

    #[test]
    fn request_has_valid_message_authenticator() {
        let (pkt, _) = request(9, "testing123", "postwright", "tony@example.com", "123456").unwrap();
        assert_eq!(pkt[0], 1);
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]) as usize, pkt.len());
        let mut zeroed = pkt.clone();
        zeroed[22..38].fill(0);
        let mut mac = HmacMd5::new_from_slice(b"testing123").unwrap();
        mac.update(&zeroed);
        mac.verify_slice(&pkt[22..38]).unwrap();
    }

    #[test]
    fn forged_reply_refused() {
        let ra = [1u8; 16];
        // An Access-Accept "signed" with the wrong secret.
        let mut pkt = vec![2u8, 5, 0, 20];
        let auth = md5(&[&pkt[..4], &ra, b"wrong"]);
        pkt.extend_from_slice(&auth);
        assert!(parse_reply(&pkt, 5, &ra, "right-secret").is_err());
        let mut ok = vec![2u8, 5, 0, 20];
        ok.extend_from_slice(&md5(&[&ok[..4], &ra, b"right-secret"]));
        assert_eq!(parse_reply(&ok, 5, &ra, "right-secret").unwrap(), Answer::Accept);
    }
}
