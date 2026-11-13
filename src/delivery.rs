//! Recipient resolution, local delivery, DKIM signing and the outbound queue.

use crate::server::Shared;
use crate::store::{self, now, QueueItem};
use anyhow::{anyhow, bail, Result};
use lettre::address::Envelope;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::transport::smtp::extension::ClientId;
use lettre::{Address, AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use mail_auth::common::cache::NoCache;
use mail_auth::common::crypto::{RsaKey, Sha256};
use mail_auth::common::headers::HeaderWriter;
use mail_auth::dkim::DkimSigner;
use mail_auth::MX;
use rusqlite::Connection;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

pub fn split_addr(addr: &str) -> Option<(&str, &str)> {
    let (l, d) = addr.rsplit_once('@')?;
    if l.is_empty() || d.is_empty() || !d.contains('.') && d != "localhost" {
        return None;
    }
    Some((l, d))
}

pub fn domain_of(addr: &str) -> String {
    addr.rsplit_once('@').map(|x| x.1.to_ascii_lowercase()).unwrap_or_default()
}

pub fn is_local_domain(c: &Connection, domain: &str) -> Result<bool> {
    Ok(store::find_domain(c, domain)?.is_some())
}

#[derive(Default, Debug)]
pub struct Resolved {
    pub users: Vec<i64>,
    pub external: Vec<String>,
}

/// Expand an address through users, aliases, sub-addressing (user+tag@) and catch-alls.
pub fn resolve(c: &Connection, addr: &str, depth: u8, out: &mut Resolved) -> Result<()> {
    let addr = addr.trim().to_ascii_lowercase();
    if depth > 6 {
        return Ok(());
    }
    let Some((local, domain)) = split_addr(&addr) else { return Ok(()) };
    let Some(dom) = store::find_domain(c, domain)? else {
        if !out.external.contains(&addr) {
            out.external.push(addr.clone());
        }
        return Ok(());
    };
    let before = out.users.len() + out.external.len();
    if let Some(u) = store::find_user(c, &addr)? {
        if u.enabled && !out.users.contains(&u.id) {
            out.users.push(u.id);
        }
    }
    for t in store::alias_targets(c, &addr)? {
        resolve(c, &t, depth + 1, out)?;
    }
    if out.users.len() + out.external.len() == before {
        if let Some((base, _tag)) = local.split_once('+') {
            resolve(c, &format!("{base}@{domain}"), depth + 1, out)?;
        }
    }
    if out.users.len() + out.external.len() == before {
        if let Some(ca) = dom.catch_all {
            if ca != addr {
                resolve(c, &ca, depth + 1, out)?;
            }
        }
    }
    Ok(())
}

/// Result of checking a recipient on the inbound path.
pub enum RcptCheck {
    Ok,
    NotLocal,
    Unknown,
    OverQuota,
}

pub fn check_local_rcpt(c: &Connection, addr: &str, size_hint: i64) -> Result<RcptCheck> {
    let d = domain_of(addr);
    if !is_local_domain(c, &d)? {
        return Ok(RcptCheck::NotLocal);
    }
    let mut r = Resolved::default();
    resolve(c, addr, 0, &mut r)?;
    if r.users.is_empty() && r.external.is_empty() {
        return Ok(RcptCheck::Unknown);
    }
    for uid in &r.users {
        if let Some(u) = store::user_by_id(c, *uid)? {
            if u.quota_bytes > 0 && store::user_usage(c, u.id)? + size_hint > u.quota_bytes {
                return Ok(RcptCheck::OverQuota);
            }
        }
    }
    Ok(RcptCheck::Ok)
}

/// Deliver a finished message to every recipient: local users go straight into INBOX,
/// everything else is queued per destination domain. Returns recipients that failed.
pub async fn deliver(srv: &Shared, mail_from: &str, rcpts: &[String], data: Vec<u8>) -> Result<Vec<String>> {
    let size = data.len() as i64;
    let headers = data[..find_header_end(&data)].to_vec();
    let blob = srv.store.put_blob(Arc::new(data)).await?;
    let from = mail_from.to_string();
    let rcpts = rcpts.to_vec();
    let (touched, failed, queued, replies) = srv
        .store
        .call(move |c| {
            let mut touched = Vec::new();
            let mut replies: Vec<(i64, String)> = Vec::new();
            let mut failed = Vec::new();
            let mut remote: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for r in &rcpts {
                let mut res = Resolved::default();
                resolve(c, r, 0, &mut res)?;
                if res.users.is_empty() && res.external.is_empty() {
                    failed.push(r.clone());
                    continue;
                }
                for uid in res.users {
                    if touched.contains(&uid) {
                        continue;
                    }
                    let Some(u) = store::user_by_id(c, uid)? else { continue };
                    if u.quota_bytes > 0 && store::user_usage(c, uid)? + size > u.quota_bytes {
                        failed.push(r.clone());
                        continue;
                    }
                    let inbox = store::find_mailbox(c, uid, "INBOX")?.ok_or_else(|| anyhow!("INBOX missing"))?;
                    store::append_message(c, inbox.id, &blob, size, now(), &[])?;
                    touched.push(uid);
                    replies.push((uid, r.clone()));
                }
                for ext in res.external {
                    let list = remote.entry(domain_of(&ext)).or_default();
                    if !list.contains(&ext) {
                        list.push(ext);
                    }
                }
            }
            let queued = !remote.is_empty();
            for (domain, list) in remote {
                store::enqueue(c, &from, &domain, &list, &blob)?;
            }
            Ok((touched, failed, queued, replies))
        })
        .await?;
    for u in touched {
        srv.notify_user(u);
    }
    if !mail_from.is_empty() {
        for (uid, rcpt) in replies {
            let fut = crate::prefs::vacation_reply(srv.clone(), uid, rcpt, mail_from.to_string(), headers.clone());
            tokio::spawn(async move {
                if let Err(e) = fut.await {
                    tracing::warn!("out-of-office reply failed: {e:#}");
                }
            });
        }
    }
    if queued {
        srv.queue_wake.notify_one();
    }
    Ok(failed)
}

// --------------------------------------------------------------------- DKIM

pub const SIGNED_HEADERS: &[&str] = &[
    "From", "Reply-To", "Subject", "Date", "To", "Cc", "Message-ID", "In-Reply-To", "References",
    "MIME-Version", "Content-Type", "Content-Transfer-Encoding", "List-Unsubscribe",
];

/// Prepend a DKIM-Signature if the domain has a key. Returns the message unchanged otherwise.
pub fn dkim_sign(domain: &store::Domain, data: Vec<u8>) -> Result<Vec<u8>> {
    let (Some(sel), Some(key)) = (&domain.dkim_selector, &domain.dkim_key) else { return Ok(data) };
    let key = RsaKey::<Sha256>::from_pkcs1_pem(key).map_err(|e| anyhow!("DKIM key for {}: {e}", domain.name))?;
    // Only sign headers that are actually present (signing absent headers is legal but
    // prevents later addition; we keep the list conservative).
    let present = header_names(&data);
    let headers: Vec<&str> = SIGNED_HEADERS
        .iter()
        .copied()
        .filter(|h| present.iter().any(|p| p.eq_ignore_ascii_case(h)))
        .collect();
    let sig = DkimSigner::from_key(key)
        .domain(domain.name.clone())
        .selector(sel.clone())
        .headers(headers)
        .sign(&data)
        .map_err(|e| anyhow!("DKIM signing failed: {e}"))?;
    let mut out = sig.to_header().into_bytes();
    out.extend_from_slice(&data);
    Ok(out)
}

fn header_names(data: &[u8]) -> Vec<String> {
    let mut v = Vec::new();
    for line in data.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        if line[0] == b' ' || line[0] == b'\t' {
            continue;
        }
        if let Some(p) = line.iter().position(|&b| b == b':') {
            v.push(String::from_utf8_lossy(&line[..p]).trim().to_string());
        }
    }
    v
}

pub fn generate_dkim_key() -> Result<(String, String)> {
    use rsa::pkcs1::EncodeRsaPrivateKey;
    let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048)?;
    let pem = key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)?.to_string();
    let public = dkim_public_from_pem(&pem)?;
    Ok((pem, public))
}

pub fn dkim_public_from_pem(pem: &str) -> Result<String> {
    use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPublicKey};
    let k = rsa::RsaPrivateKey::from_pkcs1_pem(pem)?;
    let pubk = rsa::RsaPublicKey::from(&k).to_pkcs1_der()?;
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(pubk.as_bytes()))
}

// -------------------------------------------------------------------- queue

const BACKOFF: &[i64] = &[60, 300, 900, 1800, 3600, 7200, 14400];

pub async fn run_queue(srv: Shared) {
    let sem = Arc::new(Semaphore::new(srv.cfg.queue.concurrency.max(1)));
    let mut gc_tick = tokio::time::interval(Duration::from_secs(3600));
    loop {
        let interval = Duration::from_secs(srv.cfg.queue.scan_interval_secs.max(1));
        tokio::select! {
            _ = srv.queue_wake.notified() => {}
            _ = tokio::time::sleep(interval) => {}
            _ = gc_tick.tick() => {
                if let Ok(n) = srv.store.gc_blobs().await { if n > 0 { tracing::info!("removed {n} unreferenced message blobs"); } }
                continue;
            }
        }
        let limit = srv.cfg.queue.concurrency * 4;
        let items = match srv.store.call(move |c| store::claim_due(c, limit, 900)).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("queue scan: {e:#}");
                continue;
            }
        };
        for item in items {
            let permit = sem.clone().acquire_owned().await.unwrap();
            let srv = srv.clone();
            tokio::spawn(async move {
                let _p = permit;
                process_item(&srv, item).await;
            });
        }
    }
}

async fn process_item(srv: &Shared, item: QueueItem) {
    let id = item.id;
    let data = match srv.store.get_blob(&item.blob).await {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("queue {id}: blob missing: {e}");
            let _ = srv.store.call(move |c| store::queue_done(c, id)).await;
            return;
        }
    };
    let result = send_remote(srv, &item, &data).await;
    match result {
        Ok(()) => {
            tracing::info!("queue {id}: delivered to {} ({})", item.domain, item.rcpts.join(", "));
            let _ = srv.store.call(move |c| store::queue_done(c, id)).await;
        }
        Err(SendError::Permanent(msg)) => {
            tracing::warn!("queue {id}: permanent failure for {}: {msg}", item.domain);
            bounce(srv, &item, &data, &msg).await;
            let _ = srv.store.call(move |c| store::queue_done(c, id)).await;
        }
        Err(SendError::Temporary(msg)) => {
            let age_limit = srv.cfg.queue.max_age_hours as i64 * 3600;
            if now() - item.created > age_limit {
                tracing::warn!("queue {id}: giving up on {}: {msg}", item.domain);
                bounce(srv, &item, &data, &format!("Delivery timed out. Last error: {msg}")).await;
                let _ = srv.store.call(move |c| store::queue_done(c, id)).await;
            } else {
                let delay = BACKOFF[(item.attempts as usize).min(BACKOFF.len() - 1)];
                tracing::info!("queue {id}: deferred {} for {delay}s: {msg}", item.domain);
                let rcpts = item.rcpts.clone();
                let _ = srv.store.call(move |c| store::queue_retry(c, id, &rcpts, now() + delay, &msg)).await;
            }
        }
    }
}

enum SendError {
    Temporary(String),
    Permanent(String),
}

async fn send_remote(srv: &Shared, item: &QueueItem, data: &[u8]) -> Result<(), SendError> {
    let from: Option<Address> = if item.mail_from.is_empty() {
        None
    } else {
        Some(item.mail_from.parse().map_err(|e| SendError::Permanent(format!("bad sender: {e}")))?)
    };
    let to: Vec<Address> = item.rcpts.iter().filter_map(|r| r.parse().ok()).collect();
    if to.is_empty() {
        return Err(SendError::Permanent("no valid recipients".into()));
    }
    let envelope = Envelope::new(from, to).map_err(|e| SendError::Permanent(e.to_string()))?;
    let q = &srv.cfg.queue;

    // Smarthost mode.
    if let Some(relay) = &q.relay_host {
        let (host, port) = match relay.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().unwrap_or(587)),
            None => (relay.clone(), 587),
        };
        let params = TlsParameters::new(host.clone()).map_err(|e| SendError::Temporary(e.to_string()))?;
        let mut b = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&host)
            .port(port)
            .hello_name(ClientId::Domain(srv.cfg.hostname.clone()))
            .timeout(Some(Duration::from_secs(120)))
            .tls(if port == 465 { Tls::Wrapper(params) } else { Tls::Required(params) });
        if let (Some(u), Some(p)) = (&q.relay_username, &q.relay_password) {
            b = b.credentials(Credentials::new(u.clone(), p.clone()));
        }
        return b.build().send_raw(&envelope, data).await.map(|_| ()).map_err(classify);
    }

    let hosts = mx_hosts(srv, &item.domain).await.map_err(|e| SendError::Temporary(format!("DNS: {e}")))?;
    if hosts.is_empty() {
        return Err(SendError::Permanent(format!("domain {} does not exist or does not accept mail", item.domain)));
    }
    let mut last = SendError::Temporary("no MX hosts tried".into());
    for host in hosts {
        let verify = q.require_valid_remote_tls;
        let params = match TlsParameters::builder(host.clone())
            .dangerous_accept_invalid_certs(!verify)
            .dangerous_accept_invalid_hostnames(!verify)
            .build()
        {
            Ok(p) => p,
            Err(e) => {
                last = SendError::Temporary(e.to_string());
                continue;
            }
        };
        let t = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&host)
            .port(25)
            .hello_name(ClientId::Domain(srv.cfg.hostname.clone()))
            .timeout(Some(Duration::from_secs(120)))
            .tls(if verify { Tls::Required(params) } else { Tls::Opportunistic(params) })
            .build();
        match t.send_raw(&envelope, data).await {
            Ok(_) => return Ok(()),
            Err(e) => {
                let err = classify(e);
                if let SendError::Permanent(_) = err {
                    // A definitive 5xx from an MX is authoritative; don't try lower priority hosts.
                    return Err(err);
                }
                tracing::debug!("MX {host} failed, trying next");
                last = err;
            }
        }
    }
    Err(last)
}

fn classify(e: lettre::transport::smtp::Error) -> SendError {
    if e.is_permanent() {
        SendError::Permanent(e.to_string())
    } else {
        SendError::Temporary(e.to_string())
    }
}

/// MX hosts in preference order, falling back to the domain itself (RFC 5321 5.1).
async fn mx_hosts(srv: &Shared, domain: &str) -> Result<Vec<String>> {
    match srv.dns.mx_lookup(domain, None::<&NoCache<String, Arc<Vec<MX>>>>).await {
        Ok(mxs) => {
            let mut v = Vec::new();
            for mx in mxs.iter() {
                for h in &mx.exchanges {
                    let h = h.trim_end_matches('.').to_string();
                    if h.is_empty() {
                        return Ok(vec![]); // RFC 7505 null MX
                    }
                    if !v.contains(&h) {
                        v.push(h);
                    }
                }
            }
            if v.is_empty() {
                v.push(domain.to_string());
            }
            Ok(v)
        }
        Err(mail_auth::Error::DnsRecordNotFound(_)) => {
            // No MX: fall back to the address record, unless the domain has none at all.
            let v4 = srv.dns.ipv4_lookup(domain, None::<&NoCache<String, Arc<Vec<std::net::Ipv4Addr>>>>).await;
            let v6 = srv.dns.ipv6_lookup(domain, None::<&NoCache<String, Arc<Vec<std::net::Ipv6Addr>>>>).await;
            let nx4 = matches!(v4, Err(mail_auth::Error::DnsRecordNotFound(_)));
            let nx6 = matches!(v6, Err(mail_auth::Error::DnsRecordNotFound(_)));
            if nx4 && nx6 {
                Ok(vec![])
            } else {
                Ok(vec![domain.to_string()])
            }
        }
        Err(e) => bail!("{e}"),
    }
}

/// Send a non-delivery report to the original sender. Bounces are never bounced.
async fn bounce(srv: &Shared, item: &QueueItem, original: &[u8], reason: &str) {
    if item.mail_from.is_empty() {
        return;
    }
    let host = &srv.cfg.hostname;
    let boundary = format!("=_pw{}", rand::random::<u64>());
    let headers_end = find_header_end(original);
    let orig_headers = String::from_utf8_lossy(&original[..headers_end]);
    let date = chrono::Utc::now().to_rfc2822();
    let msgid = format!("<{}.{}@{}>", now(), rand::random::<u32>(), host);
    let rcpt_lines: String = item
        .rcpts
        .iter()
        .map(|r| format!("Final-Recipient: rfc822; {r}\r\nAction: failed\r\nStatus: 5.0.0\r\n\r\n"))
        .collect();
    let msg = format!(
        "From: Mail Delivery System <MAILER-DAEMON@{host}>\r\n\
To: <{to}>\r\n\
Subject: Undelivered Mail Returned to Sender\r\n\
Date: {date}\r\n\
Message-ID: {msgid}\r\n\
Auto-Submitted: auto-replied\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/report; report-type=delivery-status; boundary=\"{boundary}\"\r\n\
\r\n\
--{boundary}\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
This is the mail system at {host}.\r\n\
\r\n\
Your message could not be delivered to: {list}\r\n\
\r\n\
Reason: {reason}\r\n\
\r\n\
--{boundary}\r\n\
Content-Type: message/delivery-status\r\n\
\r\n\
Reporting-MTA: dns; {host}\r\n\
\r\n\
{rcpt_lines}\
--{boundary}\r\n\
Content-Type: text/rfc822-headers\r\n\
\r\n\
{orig_headers}\r\n\
--{boundary}--\r\n",
        to = item.mail_from,
        list = item.rcpts.join(", "),
    );
    if let Err(e) = deliver(srv, "", std::slice::from_ref(&item.mail_from), msg.into_bytes()).await {
        tracing::error!("failed to generate bounce: {e:#}");
    }
}

pub fn find_header_end(data: &[u8]) -> usize {
    if let Some(p) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        return p + 2;
    }
    if let Some(p) = data.windows(2).position(|w| w == b"\n\n") {
        return p + 1;
    }
    data.len()
}
