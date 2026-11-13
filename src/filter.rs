//! Spam and malware filtering.
//!
//! Built in (pure Rust, no external services): DNS blocklists, forward-confirmed reverse
//! DNS, early-talker (pre-greeting) detection, HELO sanity, and scoring of SPF/DKIM/DMARC
//! results.
//!
//! Plugins (optional, enabled by adding their section to the config):
//!   * ClamAV   – clamd INSTREAM over TCP or a Unix socket. Viruses are refused in-session.
//!   * Rspamd   – the /checkv2 HTTP protocol; its score and action are honoured, and
//!                messages users move into or out of Junk are learnt.
//!   * SpamAssassin – the spamd protocol (SYMBOLS / TELL).
//!
//! Every verdict is reached before the SMTP transaction ends, so spam and viruses are
//! rejected rather than bounced later (no backscatter).

use crate::server::Shared;
use anyhow::{anyhow, bail, Context, Result};
use mail_auth::common::cache::NoCache;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// ------------------------------------------------------------------ config

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FilterConfig {
    pub enabled: bool,
    /// DNS blocklists and the score each listing adds. Note: Spamhaus refuses queries
    /// that arrive via big public resolvers; use your own resolver (e.g. Unbound on
    /// OPNsense) or a Spamhaus DQS key zone.
    pub dnsbl: Vec<Dnsbl>,
    /// Pause before the SMTP banner on port 25 (milliseconds); clients that talk before
    /// it are almost always spambots. 0 disables.
    pub greet_pause_ms: u64,
    /// Score at which mail is delivered to the Junk folder.
    pub junk_score: f64,
    /// Score at which mail is refused.
    pub reject_score: f64,
    /// Add X-Spam-* headers to delivered mail.
    pub add_headers: bool,
    /// Also scan mail sent by your own users (viruses always; spam score is recorded).
    pub scan_outbound: bool,
    pub clamav: Option<ClamavConfig>,
    pub rspamd: Option<RspamdConfig>,
    pub spamassassin: Option<SpamdConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dnsbl {
    pub zone: String,
    pub score: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OnFail {
    /// Ask the sender to retry later (451). Safest for antivirus.
    #[default]
    Tempfail,
    /// Carry on without this scanner's verdict.
    Accept,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClamavConfig {
    /// "127.0.0.1:3310" or "unix:/run/clamav/clamd.ctl"
    pub address: String,
    #[serde(default)]
    pub on_fail: OnFail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RspamdConfig {
    /// Normal worker, e.g. "http://127.0.0.1:11333"
    pub url: String,
    /// Controller for learning, e.g. "http://127.0.0.1:11334"
    #[serde(default)]
    pub controller_url: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default = "accept")]
    pub on_fail: OnFail,
    /// Learn spam/ham when users move mail into/out of Junk.
    #[serde(default = "yes")]
    pub learn: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpamdConfig {
    /// "127.0.0.1:783" or "unix:/run/spamd.sock"
    pub address: String,
    #[serde(default = "accept")]
    pub on_fail: OnFail,
    /// Requires spamd to run with --allow-tell.
    #[serde(default)]
    pub learn: bool,
}

fn accept() -> OnFail {
    OnFail::Accept
}
fn yes() -> bool {
    true
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dnsbl: vec![
                Dnsbl { zone: "zen.spamhaus.org".into(), score: 8.0 },
                Dnsbl { zone: "bl.spamcop.net".into(), score: 4.0 },
            ],
            greet_pause_ms: 1500,
            junk_score: 5.0,
            reject_score: 12.0,
            add_headers: true,
            scan_outbound: true,
            clamav: None,
            rspamd: None,
            spamassassin: None,
        }
    }
}

// ------------------------------------------------------------------ verdict

#[derive(Debug, Default, Clone)]
pub struct Verdict {
    pub score: f64,
    pub reasons: Vec<String>,
    pub virus: Option<String>,
    /// Plugin demanded an outright rejection.
    pub force_reject: bool,
    /// A fail-closed scanner was unavailable.
    pub tempfail: Option<String>,
    /// The spam engine asked for greylisting / soft reject (inbound only).
    pub greylist: bool,
}

pub enum Action {
    Deliver,
    Junk,
    Reject(String),
    Tempfail(String),
}

impl Verdict {
    pub fn add(&mut self, score: f64, why: impl Into<String>) {
        self.score += score;
        self.reasons.push(format!("{}({score:+.1})", why.into()));
    }

    pub fn action(&self, cfg: &FilterConfig) -> Action {
        if let Some(v) = &self.virus {
            return Action::Reject(format!("554 5.7.1 Message contains malware ({v})"));
        }
        if let Some(t) = &self.tempfail {
            return Action::Tempfail(format!("451 4.7.1 {t}, try again later"));
        }
        if self.greylist {
            return Action::Tempfail("451 4.7.1 Greylisted, try again later".into());
        }
        if self.force_reject || self.score >= cfg.reject_score {
            return Action::Reject(format!("550 5.7.1 Message rejected as spam (score {:.1})", self.score));
        }
        if self.score >= cfg.junk_score {
            return Action::Junk;
        }
        Action::Deliver
    }

    pub fn headers(&self, cfg: &FilterConfig, host: &str) -> String {
        let spam = self.score >= cfg.junk_score;
        let mut reasons = self.reasons.join(" ");
        if reasons.is_empty() {
            reasons = "none".into();
        }
        // Fold long lines to stay within RFC 5322 limits.
        let mut folded = String::new();
        let mut len = 0;
        for word in reasons.split(' ') {
            if len + word.len() > 70 {
                folded.push_str("\r\n\t");
                len = 0;
            } else if !folded.is_empty() {
                folded.push(' ');
            }
            folded.push_str(word);
            len += word.len() + 1;
        }
        format!(
            "X-Spam-Flag: {}\r\nX-Spam-Score: {:.1}\r\nX-Spam-Status: {}, score={:.1} required={:.1} by {host}\r\nX-Spam-Report: {folded}\r\n",
            if spam { "YES" } else { "NO" },
            self.score,
            if spam { "Yes" } else { "No" },
            self.score,
            cfg.junk_score
        )
    }
}

// ----------------------------------------------------------------- built-ins

/// Query each DNSBL for the connecting IP.
pub async fn dnsbl(srv: &Shared, ip: IpAddr, v: &mut Verdict) {
    if is_private(ip) {
        return;
    }
    let rev = reverse_ip(ip);
    let lookups = srv.cfg.filter.dnsbl.iter().map(|bl| {
        let name = format!("{rev}.{}.", bl.zone);
        let srv = srv.clone();
        async move {
            let r = srv.dns.ipv4_lookup(name.as_str(), None::<&NoCache<String, Arc<Vec<std::net::Ipv4Addr>>>>).await;
            (bl.clone(), r)
        }
    });
    for (bl, r) in futures_join(lookups.collect()).await {
        if let Ok(addrs) = r {
            let codes: Vec<String> = addrs.iter().map(|a| a.to_string()).collect();
            // 127.255.255.x means the list refused the query (e.g. public resolver).
            if addrs.iter().any(|a| a.octets()[0] == 127 && a.octets()[1] != 255) {
                v.add(bl.score, format!("DNSBL_{}", bl.zone.to_ascii_uppercase().replace('.', "_")));
            } else if addrs.iter().any(|a| a.octets()[1] == 255) {
                tracing::warn!("{} refused the lookup ({}); use your own resolver or a DQS key", bl.zone, codes.join(","));
            }
        }
    }
}

async fn futures_join<F: std::future::Future>(fs: Vec<F>) -> Vec<F::Output> {
    let mut out = Vec::with_capacity(fs.len());
    // Small number of lists: run them concurrently via join handles on the same task.
    let mut pinned: Vec<std::pin::Pin<Box<F>>> = fs.into_iter().map(Box::pin).collect();
    let mut results: Vec<Option<F::Output>> = (0..pinned.len()).map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut pending = false;
        for (i, f) in pinned.iter_mut().enumerate() {
            if results[i].is_none() {
                match f.as_mut().poll(cx) {
                    std::task::Poll::Ready(r) => results[i] = Some(r),
                    std::task::Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(())
        }
    })
    .await;
    for r in results {
        out.push(r.unwrap());
    }
    out
}

pub fn reverse_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let hex: String = v6.octets().iter().map(|b| format!("{b:02x}")).collect();
            hex.chars().rev().map(|c| c.to_string()).collect::<Vec<_>>().join(".")
        }
    }
}

pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

pub fn helo_score(helo: &str, v: &mut Verdict) {
    let h = helo.trim_start_matches('[').trim_end_matches(']');
    if h.parse::<IpAddr>().is_ok() {
        v.add(1.0, "HELO_IP_LITERAL");
    } else if !h.contains('.') {
        v.add(1.5, "HELO_NOT_FQDN");
    }
}

// ------------------------------------------------------------------- ClamAV

trait Rw: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Rw for T {}

async fn connect(addr: &str) -> Result<Box<dyn Rw>> {
    if let Some(path) = addr.strip_prefix("unix:") {
        #[cfg(unix)]
        {
            return Ok(Box::new(tokio::net::UnixStream::connect(path).await.with_context(|| format!("connecting to {path}"))?));
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            bail!("Unix sockets are not available on this platform; use host:port");
        }
    }
    let s = tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow!("timed out connecting to {addr}"))?
        .with_context(|| format!("connecting to {addr}"))?;
    Ok(Box::new(s))
}

/// Scan with clamd. Ok(Some(name)) = infected, Ok(None) = clean.
pub async fn clamav_scan(cfg: &ClamavConfig, data: &[u8]) -> Result<Option<String>> {
    tokio::time::timeout(Duration::from_secs(120), async {
        let mut s = connect(&cfg.address).await?;
        s.write_all(b"zINSTREAM\0").await?;
        for chunk in data.chunks(64 * 1024) {
            s.write_all(&(chunk.len() as u32).to_be_bytes()).await?;
            s.write_all(chunk).await?;
        }
        s.write_all(&0u32.to_be_bytes()).await?;
        s.flush().await?;
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).await?;
        let text = String::from_utf8_lossy(&resp).trim_end_matches('\0').trim().to_string();
        if text.ends_with("OK") {
            Ok(None)
        } else if let Some(found) = text.strip_suffix(" FOUND") {
            Ok(Some(found.trim_start_matches("stream:").trim().to_string()))
        } else {
            bail!("clamd: {text}")
        }
    })
    .await
    .map_err(|_| anyhow!("clamd timed out"))?
}

// ------------------------------------------------------------------- Rspamd

struct Url {
    host: String,
    port: u16,
    path: String,
}

fn parse_url(u: &str) -> Result<Url> {
    let rest = u.strip_prefix("http://").ok_or_else(|| anyhow!("only http:// URLs are supported for local scanners: {u}"))?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].trim_end_matches('/').to_string()),
        None => (rest, String::new()),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse()?),
        None => (hostport.to_string(), 80),
    };
    Ok(Url { host, port, path })
}

/// Minimal HTTP/1.1 POST for talking to a local scanner.
async fn http_post(base: &str, path: &str, headers: &[(&str, String)], body: &[u8]) -> Result<(u16, Vec<u8>)> {
    let u = parse_url(base)?;
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut s = connect(&format!("{}:{}", u.host, u.port)).await?;
        let mut req = format!("POST {}{path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n", u.path, u.host, body.len());
        for (k, v) in headers {
            let v: String = v.chars().filter(|c| !c.is_control()).collect();
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("\r\n");
        s.write_all(req.as_bytes()).await?;
        s.write_all(body).await?;
        s.flush().await?;
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).await?;
        let split = resp.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| anyhow!("bad HTTP response"))?;
        let head = String::from_utf8_lossy(&resp[..split]).to_string();
        let status: u16 = head.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let mut body = resp[split + 4..].to_vec();
        if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            body = dechunk(&body);
        }
        Ok((status, body))
    })
    .await
    .map_err(|_| anyhow!("timed out"))?
}

fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let Some(nl) = b.windows(2).position(|w| w == b"\r\n") else { break };
        let size = usize::from_str_radix(String::from_utf8_lossy(&b[..nl]).split(';').next().unwrap_or("0").trim(), 16).unwrap_or(0);
        if size == 0 || nl + 2 + size > b.len() {
            break;
        }
        out.extend_from_slice(&b[nl + 2..nl + 2 + size]);
        b = &b[(nl + 4 + size).min(b.len())..];
    }
    out
}

pub struct Envelope<'a> {
    pub ip: IpAddr,
    pub helo: &'a str,
    pub mail_from: &'a str,
    pub rcpts: &'a [String],
    pub user: Option<&'a str>,
}

#[derive(Deserialize)]
struct RspamdReply {
    #[serde(default)]
    action: String,
    #[serde(default)]
    score: f64,
}

pub async fn rspamd_check(cfg: &RspamdConfig, env: &Envelope<'_>, data: &[u8], v: &mut Verdict) -> Result<()> {
    let mut h: Vec<(&str, String)> = vec![("IP", env.ip.to_string()), ("Helo", env.helo.to_string()), ("From", env.mail_from.to_string())];
    for r in env.rcpts {
        h.push(("Rcpt", r.clone()));
    }
    if let Some(u) = env.user {
        h.push(("User", u.to_string()));
    }
    if let Some(p) = &cfg.password {
        h.push(("Password", p.clone()));
    }
    let (status, body) = http_post(&cfg.url, "/checkv2", &h, data).await?;
    if status != 200 {
        bail!("rspamd HTTP {status}: {}", String::from_utf8_lossy(&body));
    }
    let r: RspamdReply = serde_json::from_slice(&body).context("rspamd reply")?;
    v.add(r.score, format!("RSPAMD[{}]", r.action.replace(' ', "_")));
    match r.action.as_str() {
        "reject" => v.force_reject = true,
        "soft reject" | "greylist" => v.greylist = true,
        _ => {}
    }
    Ok(())
}

// ------------------------------------------------------------- SpamAssassin

pub async fn spamd_check(cfg: &SpamdConfig, user: Option<&str>, data: &[u8], v: &mut Verdict) -> Result<()> {
    let resp = tokio::time::timeout(Duration::from_secs(60), async {
        let mut s = connect(&cfg.address).await?;
        let mut req = format!("SYMBOLS SPAMC/1.5\r\nContent-length: {}\r\n", data.len());
        if let Some(u) = user {
            req.push_str(&format!("User: {u}\r\n"));
        }
        req.push_str("\r\n");
        s.write_all(req.as_bytes()).await?;
        s.write_all(data).await?;
        s.flush().await?;
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).await?;
        Ok::<_, anyhow::Error>(String::from_utf8_lossy(&resp).to_string())
    })
    .await
    .map_err(|_| anyhow!("spamd timed out"))??;
    if !resp.starts_with("SPAMD/") || !resp.lines().next().unwrap_or("").contains("EX_OK") {
        bail!("spamd: {}", resp.lines().next().unwrap_or(""));
    }
    // "Spam: True ; 15.3 / 5.0"
    let line = resp.lines().find(|l| l.to_ascii_lowercase().starts_with("spam:")).ok_or_else(|| anyhow!("spamd: no Spam header"))?;
    let score: f64 = line.split(';').nth(1).and_then(|x| x.split('/').next()).and_then(|x| x.trim().parse().ok()).unwrap_or(0.0);
    v.add(score, "SPAMASSASSIN");
    Ok(())
}

// ----------------------------------------------------------------- learning

/// Teach the spam engines from a user moving mail into (spam) or out of (ham) Junk.
pub fn learn(srv: &Shared, blobs: Vec<String>, spam: bool, user: String) {
    let f = &srv.cfg.filter;
    let rs = f.rspamd.clone().filter(|r| r.learn);
    let sa = f.spamassassin.clone().filter(|s| s.learn);
    if !f.enabled || (rs.is_none() && sa.is_none()) || blobs.is_empty() {
        return;
    }
    let srv = srv.clone();
    tokio::spawn(async move {
        for b in blobs {
            let Ok(data) = srv.store.get_blob(&b).await else { continue };
            if let Some(r) = &rs {
                let base = r.controller_url.clone().unwrap_or_else(|| r.url.replace(":11333", ":11334"));
                let mut h = vec![];
                if let Some(p) = &r.password {
                    h.push(("Password", p.clone()));
                }
                let path = if spam { "/learnspam" } else { "/learnham" };
                match http_post(&base, path, &h, &data).await {
                    Ok((200, _)) | Ok((208, _)) => {}
                    Ok((s, body)) => tracing::debug!("rspamd learn HTTP {s}: {}", String::from_utf8_lossy(&body)),
                    Err(e) => tracing::warn!("rspamd learn failed: {e:#}"),
                }
            }
            if let Some(s) = &sa {
                let res: Result<()> = async {
                    let mut c = connect(&s.address).await?;
                    let req = format!(
                        "TELL SPAMC/1.5\r\nMessage-class: {}\r\nSet: local\r\nUser: {user}\r\nContent-length: {}\r\n\r\n",
                        if spam { "spam" } else { "ham" },
                        data.len()
                    );
                    c.write_all(req.as_bytes()).await?;
                    c.write_all(&data).await?;
                    let mut r = Vec::new();
                    c.read_to_end(&mut r).await?;
                    Ok(())
                }
                .await;
                if let Err(e) = res {
                    tracing::warn!("spamd learn failed: {e:#}");
                }
            }
        }
        tracing::info!("learnt {} for {user}", if spam { "spam" } else { "ham" });
    });
}

// ---------------------------------------------------------------- pipeline

/// Run the content scanners (ClamAV, Rspamd, SpamAssassin) and merge into `v`.
pub async fn scan_content(srv: &Shared, env: &Envelope<'_>, data: &[u8], v: &mut Verdict) {
    let f = &srv.cfg.filter;
    if let Some(c) = &f.clamav {
        match clamav_scan(c, data).await {
            Ok(Some(virus)) => {
                tracing::warn!("ClamAV: {virus} in message from {} <{}>", env.ip, env.mail_from);
                v.virus = Some(virus);
                return; // no need to spam-score malware
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!("ClamAV unavailable: {e:#}");
                if c.on_fail == OnFail::Tempfail {
                    v.tempfail = Some("Virus scanner unavailable".into());
                }
            }
        }
    }
    if let Some(r) = &f.rspamd {
        if let Err(e) = rspamd_check(r, env, data, v).await {
            tracing::error!("Rspamd unavailable: {e:#}");
            if r.on_fail == OnFail::Tempfail {
                v.tempfail = Some("Spam filter unavailable".into());
            }
        }
    }
    if let Some(s) = &f.spamassassin {
        if let Err(e) = spamd_check(s, env.rcpts.first().map(|s| s.as_str()), data, v).await {
            tracing::error!("SpamAssassin unavailable: {e:#}");
            if s.on_fail == OnFail::Tempfail {
                v.tempfail = Some("Spam filter unavailable".into());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse() {
        assert_eq!(reverse_ip("192.0.2.1".parse().unwrap()), "1.2.0.192");
        assert!(reverse_ip("2001:db8::1".parse().unwrap()).starts_with("1.0.0.0"));
        assert!(reverse_ip("2001:db8::1".parse().unwrap()).ends_with("8.b.d.0.1.0.0.2"));
        assert!(is_private("192.168.1.62".parse().unwrap()));
        assert!(!is_private("81.2.69.160".parse().unwrap()));
    }

    #[test]
    fn verdicts() {
        let cfg = FilterConfig::default();
        let mut v = Verdict::default();
        v.add(3.0, "SPF_FAIL");
        assert!(matches!(v.action(&cfg), Action::Deliver));
        v.add(3.0, "X");
        assert!(matches!(v.action(&cfg), Action::Junk));
        v.add(8.0, "DNSBL");
        assert!(matches!(v.action(&cfg), Action::Reject(_)));
        v.virus = Some("Eicar".into());
        let Action::Reject(r) = v.action(&cfg) else { panic!() };
        assert!(r.contains("malware"));
        assert!(v.headers(&cfg, "mx").contains("X-Spam-Flag: YES"));
        assert_eq!(dechunk(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"), b"hello world");
    }
}
