//! Mail held while a scanner set to "hold" is unavailable.
//!
//! Instead of turning senders away, the message is accepted and kept here. Every
//! minute (and whenever an administrator asks) held mail is scanned again; once the
//! scanners answer it is delivered, filed as junk, or dropped as the verdict says.
//! Administrators see a banner in the webmail and admin console while anything waits.

use crate::filter::{Action, Envelope, Verdict};
use crate::server::Shared;
use crate::store;
use anyhow::{anyhow, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS held(
    id INTEGER PRIMARY KEY,
    received INTEGER NOT NULL,
    direction TEXT NOT NULL,          -- 'in' (from the internet) or 'out' (sent by a user)
    mail_from TEXT NOT NULL,
    rcpts TEXT NOT NULL,              -- JSON list
    blob TEXT NOT NULL,
    size INTEGER NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    helo TEXT NOT NULL DEFAULT '',
    user TEXT,
    score REAL NOT NULL DEFAULT 0,    -- built-in checks already done (inbound)
    reasons TEXT NOT NULL DEFAULT '',
    waiting_for TEXT NOT NULL,
    subject TEXT NOT NULL DEFAULT '',
    attempts INTEGER NOT NULL DEFAULT 0,
    last_try INTEGER
);
"#;

pub static WAKE: Notify = Notify::const_new();

pub struct NewHeld<'a> {
    pub direction: &'a str,
    pub mail_from: &'a str,
    pub rcpts: &'a [String],
    pub ip: String,
    pub helo: &'a str,
    pub user: Option<&'a str>,
    pub verdict: &'a Verdict,
}

/// Keep a message until it can be scanned.
pub async fn hold(srv: &Shared, h: NewHeld<'_>, data: Vec<u8>) -> Result<()> {
    let size = data.len() as i64;
    let subject = mail_parser::MessageParser::default().parse_headers(&data).and_then(|m| m.subject().map(String::from)).unwrap_or_default();
    let blob = srv.store.put_blob(Arc::new(data)).await?;
    let waiting = h.verdict.hold.clone().unwrap_or_else(|| "a scanner".into());
    tracing::warn!("held {} message from <{}> to {} recipient(s): {waiting} isn't responding", if h.direction == "in" { "incoming" } else { "outgoing" }, h.mail_from, h.rcpts.len());
    let (dir, from, rcpts, ip, helo, user, score, reasons) = (
        h.direction.to_string(),
        h.mail_from.to_string(),
        serde_json::to_string(h.rcpts)?,
        h.ip,
        h.helo.to_string(),
        h.user.map(String::from),
        h.verdict.score,
        h.verdict.reasons.join(" "),
    );
    srv.store
        .call(move |c| {
            c.execute(
                "INSERT INTO held(received, direction, mail_from, rcpts, blob, size, ip, helo, user, score, reasons, waiting_for, subject)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![store::now(), dir, from, rcpts, blob, size, ip, helo, user, score, reasons, waiting, subject],
            )?;
            store::blob_ref(c, &blob, 1)?;
            Ok(())
        })
        .await?;
    forget_alerts();
    Ok(())
}

#[derive(Clone, Debug)]
struct Item {
    id: i64,
    direction: String,
    mail_from: String,
    rcpts: Vec<String>,
    blob: String,
    ip: String,
    helo: String,
    user: Option<String>,
    score: f64,
    reasons: String,
}

fn items(c: &Connection, id: Option<i64>) -> Result<Vec<Item>> {
    let mut st = c.prepare("SELECT id, direction, mail_from, rcpts, blob, ip, helo, user, score, reasons FROM held WHERE ?1 IS NULL OR id = ?1 ORDER BY id")?;
    let v = st
        .query_map([id], |r| {
            Ok(Item {
                id: r.get(0)?,
                direction: r.get(1)?,
                mail_from: r.get(2)?,
                rcpts: serde_json::from_str(&r.get::<_, String>(3)?).unwrap_or_default(),
                blob: r.get(4)?,
                ip: r.get(5)?,
                helo: r.get(6)?,
                user: r.get(7)?,
                score: r.get(8)?,
                reasons: r.get(9)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(v)
}


/// For the admin console.
pub fn list(c: &Connection) -> Result<Vec<Value>> {
    let mut st = c.prepare("SELECT id, received, direction, mail_from, rcpts, size, waiting_for, subject, attempts, last_try FROM held ORDER BY id LIMIT 500")?;
    let v = st
        .query_map([], |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?, "received": r.get::<_, i64>(1)?, "direction": r.get::<_, String>(2)?,
                "from": r.get::<_, String>(3)?, "to": serde_json::from_str::<Value>(&r.get::<_, String>(4)?).unwrap_or(Value::Null),
                "size": r.get::<_, i64>(5)?, "waiting_for": r.get::<_, String>(6)?, "subject": r.get::<_, String>(7)?,
                "attempts": r.get::<_, i64>(8)?, "last_try": r.get::<_, Option<i64>>(9)?,
            }))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(v)
}

async fn remove(srv: &Shared, it: &Item) -> Result<()> {
    let (id, blob) = (it.id, it.blob.clone());
    srv.store
        .call(move |c| {
            if c.execute("DELETE FROM held WHERE id = ?1", [id])? > 0 {
                store::blob_ref(c, &blob, -1)?;
            }
            Ok(())
        })
        .await?;
    forget_alerts();
    Ok(())
}

/// Deliver as the message would have been delivered had it not been held.
async fn deliver(srv: &Shared, it: &Item, data: Vec<u8>, junk: bool) -> Result<()> {
    if it.direction == "in" {
        crate::delivery::deliver_to(srv, &it.mail_from, &it.rcpts, data, junk).await?;
    } else {
        crate::delivery::deliver(srv, &it.mail_from, &it.rcpts, data).await?;
    }
    Ok(())
}

/// Scan one held message again. Returns true when it has left the queue.
async fn process(srv: &Shared, it: &Item) -> Result<bool> {
    let data = srv.store.get_blob(&it.blob).await?;
    let f = srv.filter();
    let mut v = Verdict { score: it.score, reasons: it.reasons.split_whitespace().map(String::from).collect(), ..Default::default() };
    let ip: std::net::IpAddr = it.ip.parse().unwrap_or(std::net::IpAddr::from([127, 0, 0, 1]));
    let env = Envelope { ip, helo: &it.helo, mail_from: &it.mail_from, rcpts: &it.rcpts, user: it.user.as_deref() };
    if f.enabled {
        crate::filter::scan_content(srv, &env, &data, &mut v).await;
    }
    if let Some(w) = v.hold.clone().or(v.tempfail.clone()) {
        let id = it.id;
        srv.store
            .call(move |c| {
                c.execute("UPDATE held SET attempts = attempts + 1, last_try = ?2, waiting_for = ?3 WHERE id = ?1", params![id, store::now(), w])?;
                Ok(())
            })
            .await?;
        return Ok(false);
    }
    if it.direction == "in" {
        match v.action(&f) {
            Action::Reject(r) | Action::Tempfail(r) => {
                // Already accepted, so nothing is bounced to a (probably forged) sender.
                tracing::warn!("held message from <{}> dropped after scanning: {r} [{}]", it.mail_from, v.reasons.join(" "));
            }
            a => {
                let mut full = if f.add_headers { v.headers(&f, &srv.cfg.hostname).into_bytes() } else { Vec::new() };
                full.extend_from_slice(&data);
                deliver(srv, it, full, matches!(a, Action::Junk)).await?;
                tracing::info!("held message from <{}> scanned and delivered", it.mail_from);
            }
        }
    } else if v.virus.is_some() || v.force_reject {
        let why = v.virus.clone().map(|x| format!("it contains malware ({x})")).unwrap_or_else(|| "the spam filter rejected it".into());
        tracing::warn!("held outgoing message from <{}> not sent: {why}", it.mail_from);
        if let Some(u) = &it.user {
            notify_sender(srv, u, it, &why).await;
        }
    } else {
        deliver(srv, it, data, false).await?;
        tracing::info!("held outgoing message from <{}> scanned and sent", it.mail_from);
    }
    remove(srv, it).await?;
    Ok(true)
}

async fn notify_sender(srv: &Shared, user: &str, it: &Item, why: &str) {
    let dom = crate::delivery::domain_of(user);
    let text = format!(
        "From: Mail Delivery System <postmaster@{dom}>\r\nTo: <{user}>\r\nSubject: Not sent: your message to {}\r\nDate: {}\r\nAuto-Submitted: auto-replied\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nYour message to {} was held while the mail scanner was unavailable, and was not sent because {why}.\r\n",
        it.rcpts.join(", "),
        chrono::Utc::now().to_rfc2822(),
        it.rcpts.join(", ")
    );
    let _ = crate::delivery::deliver_to(srv, "", &[user.to_string()], text.into_bytes(), false).await;
}

/// Background task: retry held mail every minute, or when woken.
pub async fn run(srv: Shared) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(60)) => {}
            _ = WAKE.notified() => {}
        }
        if let Err(e) = retry_all(&srv).await {
            tracing::error!("held mail: {e:#}");
        }
    }
}

pub async fn retry_all(srv: &Shared) -> Result<usize> {
    let list = srv.store.call(|c| items(c, None)).await?;
    let mut done = 0;
    for it in list {
        match process(srv, &it).await {
            Ok(true) => done += 1,
            Ok(false) => break, // the scanner is still down: no point trying the rest now
            Err(e) => tracing::error!("held message {}: {e:#}", it.id),
        }
    }
    Ok(done)
}

/// Admin: deliver without waiting for the scanners, or delete.
pub async fn release(srv: &Shared, id: i64) -> Result<()> {
    let it = srv.store.call(move |c| items(c, Some(id))).await?.pop().ok_or_else(|| anyhow!("that message is no longer held"))?;
    let data = srv.store.get_blob(&it.blob).await?;
    deliver(srv, &it, data, false).await?;
    remove(srv, &it).await?;
    tracing::warn!("held message from <{}> released without scanning by an administrator", it.mail_from);
    Ok(())
}

pub async fn delete(srv: &Shared, id: i64) -> Result<()> {
    let it = srv.store.call(move |c| items(c, Some(id))).await?.pop().ok_or_else(|| anyhow!("that message is no longer held"))?;
    remove(srv, &it).await
}

// ------------------------------------------------------------------- alerts

static ALERTS: Mutex<Option<(Instant, Vec<Value>)>> = Mutex::new(None);

fn forget_alerts() {
    *ALERTS.lock().unwrap() = None;
}

/// Notices for administrators (the coloured banner), refreshed at most every 30 s.
pub async fn alerts(srv: &Shared) -> Vec<Value> {
    if let Some((t, v)) = ALERTS.lock().unwrap().clone() {
        if t.elapsed() < Duration::from_secs(30) {
            return v;
        }
    }
    let mut out = Vec::new();
    let held: Option<(i64, String)> = srv
        .store
        .call(|c| Ok(c.query_row("SELECT COUNT(*), MAX(waiting_for) FROM held", [], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?.unwrap_or_default()))).optional()?))
        .await
        .ok()
        .flatten();
    let health = crate::filter::health(srv).await;
    let down: Vec<String> = health.iter().filter(|h| h["ok"] == false).filter_map(|h| h["name"].as_str().map(String::from)).collect();
    match held {
        Some((n, w)) if n > 0 => out.push(json!({
            "level": "warn",
            "text": format!("{n} message{} {} held because {} {} responding. {} delivered automatically once scanning works again.",
                if n == 1 { "" } else { "s" }, if n == 1 { "is" } else { "are" },
                if down.is_empty() { w.clone() } else { down.join(" and ") }, if down.len() > 1 { "aren't" } else { "isn't" },
                if n == 1 { "It will be" } else { "They'll be" }),
            "link": "/admin#filters",
        })),
        _ if !down.is_empty() => out.push(json!({
            "level": "err",
            "text": format!("{} {} responding, so mail isn't being scanned for {}.", down.join(" and "), if down.len() > 1 { "aren't" } else { "isn't" },
                if down.iter().any(|d| d == "ClamAV") { "viruses" } else { "spam" }),
            "link": "/admin#filters",
        })),
        _ => {}
    }
    *ALERTS.lock().unwrap() = Some((Instant::now(), out.clone()));
    out
}
