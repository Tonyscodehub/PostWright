//! Per-user preferences: out-of-office auto-replies (RFC 3834) and roaming signatures.

use crate::delivery;
use crate::imap::mime;
use crate::server::Shared;
use crate::store::{self, now};
use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Vacation {
    pub enabled: bool,
    pub subject: String,
    pub body: String,
    /// Unix timestamps; either may be omitted.
    pub start: Option<i64>,
    pub end: Option<i64>,
    /// Only reply to senders in domains hosted on this server.
    pub internal_only: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Signature {
    pub text: String,
    pub html: String,
    /// Have the server add the signature to outgoing mail that doesn't already contain it.
    pub append: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub vacation: Vacation,
    pub signature: Signature,
}

pub fn load(c: &Connection, user_id: i64) -> Result<Settings> {
    Ok(c.query_row(
        "SELECT vacation_enabled, vacation_subject, vacation_body, vacation_start, vacation_end, vacation_internal_only,
                signature_text, signature_html, signature_append FROM user_settings WHERE user_id = ?1",
        [user_id],
        |r| {
            Ok(Settings {
                vacation: Vacation {
                    enabled: r.get::<_, i64>(0)? != 0,
                    subject: r.get(1)?,
                    body: r.get(2)?,
                    start: r.get(3)?,
                    end: r.get(4)?,
                    internal_only: r.get::<_, i64>(5)? != 0,
                },
                signature: Signature { text: r.get(6)?, html: r.get(7)?, append: r.get::<_, i64>(8)? != 0 },
            })
        },
    )
    .optional()?
    .unwrap_or_default())
}

pub fn save(c: &Connection, user_id: i64, s: &Settings) -> Result<()> {
    let v = &s.vacation;
    let g = &s.signature;
    c.execute(
        "INSERT INTO user_settings(user_id, vacation_enabled, vacation_subject, vacation_body, vacation_start, vacation_end,
             vacation_internal_only, signature_text, signature_html, signature_append)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(user_id) DO UPDATE SET vacation_enabled = ?2, vacation_subject = ?3, vacation_body = ?4,
             vacation_start = ?5, vacation_end = ?6, vacation_internal_only = ?7, signature_text = ?8,
             signature_html = ?9, signature_append = ?10",
        params![user_id, v.enabled as i64, v.subject, v.body, v.start, v.end, v.internal_only as i64, g.text, g.html, g.append as i64],
    )?;
    // A fresh out-of-office period should reply to everyone again.
    if !v.enabled {
        c.execute("DELETE FROM vacation_log WHERE user_id = ?1", [user_id])?;
    }
    Ok(())
}

impl Vacation {
    pub fn active(&self, t: i64) -> bool {
        self.enabled && self.start.map(|s| t >= s).unwrap_or(true) && self.end.map(|e| t < e).unwrap_or(true)
    }
}

const REPLY_INTERVAL: i64 = 4 * 24 * 3600; // RFC 3834 suggests days, not hours

/// RFC 3834 / common-practice checks: never auto-reply to bulk, list, automated or bounce mail.
pub fn should_reply(sender: &str, headers: &[(String, Vec<u8>)]) -> bool {
    let s = sender.to_ascii_lowercase();
    let local = s.split('@').next().unwrap_or("");
    if s.is_empty()
        || local.starts_with("owner-")
        || local.ends_with("-request")
        || ["mailer-daemon", "postmaster", "noreply", "no-reply", "do-not-reply", "donotreply", "bounce", "bounces", "listserv", "majordomo"]
            .iter()
            .any(|x| local == *x || local.starts_with(&format!("{x}+")))
    {
        return false;
    }
    for (name, val) in headers {
        let n = name.to_ascii_lowercase();
        let v = String::from_utf8_lossy(val).to_ascii_lowercase();
        match n.as_str() {
            "auto-submitted" if v.trim() != "no" => return false,
            "precedence" if ["bulk", "list", "junk"].iter().any(|p| v.contains(p)) => return false,
            "list-id" | "list-unsubscribe" | "list-post" | "list-help" | "feedback-id" => return false,
            "x-auto-response-suppress" if v.contains("oof") || v.contains("all") => return false,
            "x-autoreply" | "x-autorespond" => return false,
            _ => {}
        }
    }
    true
}

fn encode_header_word(s: &str) -> String {
    if s.is_ascii() {
        s.to_string()
    } else {
        use base64::Engine;
        format!("=?UTF-8?B?{}?=", base64::engine::general_purpose::STANDARD.encode(s))
    }
}

fn crlf(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\n', "\r\n")
}

/// Called after a message is delivered to a local user. Sends at most one reply per sender
/// per interval. Boxed so it can recurse into `delivery::deliver`.
pub fn vacation_reply(
    srv: Shared,
    user_id: i64,
    rcpt: String,
    sender: String,
    headers: Vec<u8>,
) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
    Box::pin(async move {
        let fields = mime::header_fields(&headers);
        if !should_reply(&sender, &fields) {
            return Ok(());
        }
        let snd = sender.to_ascii_lowercase();
        let rc = rcpt.to_ascii_lowercase();
        let plan = srv
            .store
            .call(move |c| {
                let Some(user) = store::user_by_id(c, user_id)? else { return Ok(None) };
                let s = load(c, user_id)?;
                let t = now();
                if !s.vacation.active(t) || snd == user.email {
                    return Ok(None);
                }
                if s.vacation.internal_only && !delivery::is_local_domain(c, &delivery::domain_of(&snd))? {
                    return Ok(None);
                }
                let last: Option<i64> = c
                    .query_row("SELECT sent FROM vacation_log WHERE user_id = ?1 AND sender = ?2", params![user_id, snd], |r| r.get(0))
                    .optional()?;
                if let Some(l) = last {
                    if t - l < REPLY_INTERVAL && l >= s.vacation.start.unwrap_or(0) {
                        return Ok(None);
                    }
                }
                c.execute(
                    "INSERT INTO vacation_log(user_id, sender, sent) VALUES(?1, ?2, ?3)
                     ON CONFLICT(user_id, sender) DO UPDATE SET sent = ?3",
                    params![user_id, snd, t],
                )?;
                // Reply from the address the mail was sent to, if it's one this user owns.
                let owned = store::sender_addresses(c, &user)?;
                let from = if owned.contains(&rc) { rc } else { user.email.clone() };
                let dom = store::find_domain(c, &delivery::domain_of(&from))?;
                Ok(Some((from, s.vacation, dom)))
            })
            .await?;
        let Some((from, vac, dom)) = plan else { return Ok(()) };
        let get = |n: &str| {
            fields.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| String::from_utf8_lossy(v).into_owned())
        };
        let orig_subject = get("Subject").unwrap_or_default();
        let subject = if vac.subject.trim().is_empty() {
            format!("Automatic reply: {orig_subject}")
        } else {
            vac.subject.clone()
        };
        let body = if vac.body.trim().is_empty() { "I am currently away and will reply when I return.".to_string() } else { vac.body.clone() };
        let mut refs = String::new();
        if let Some(id) = get("Message-ID") {
            let prev = get("References").map(|r| format!("{r} ")).unwrap_or_default();
            refs = format!("In-Reply-To: {id}\r\nReferences: {prev}{id}\r\n");
        }
        let msg = format!(
            "From: <{from}>\r\nTo: <{sender}>\r\nSubject: {}\r\nDate: {}\r\nMessage-ID: <{}.{:x}@{}>\r\n{refs}\
Auto-Submitted: auto-replied\r\nX-Auto-Response-Suppress: All\r\nPrecedence: auto_reply\r\n\
MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{}\r\n",
            encode_header_word(&subject),
            chrono::Utc::now().to_rfc2822(),
            now(),
            rand::random::<u64>(),
            delivery::domain_of(&from),
            crlf(&body)
        );
        let mut data = msg.into_bytes();
        if let Some(d) = dom {
            data = delivery::dkim_sign(&d, data)?;
        }
        tracing::info!("out-of-office reply from {from} to {sender}");
        // Null envelope sender (RFC 3834 section 3.3) so replies to the reply can't loop.
        delivery::deliver(&srv, "", &[sender], data).await?;
        Ok(())
    })
}

// --------------------------------------------------------------- signatures

fn qp_encode(s: &str) -> String {
    let mut out = String::new();
    for line in s.split("\r\n") {
        let mut cur = String::new();
        for &b in line.as_bytes() {
            let piece = if (b == b' ' || b == b'\t' || (33..=126).contains(&b)) && b != b'=' {
                (b as char).to_string()
            } else {
                format!("={b:02X}")
            };
            if cur.len() + piece.len() > 75 {
                out.push_str(&cur);
                out.push_str("=\r\n");
                cur.clear();
            }
            cur.push_str(&piece);
        }
        if cur.ends_with(' ') || cur.ends_with('\t') {
            let last = cur.pop().unwrap();
            cur.push_str(&format!("={:02X}", last as u8));
        }
        out.push_str(&cur);
        out.push_str("\r\n");
    }
    out.trim_end_matches("\r\n").to_string()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Append the user's signature to the first text/plain and text/html parts of a message,
/// unless it's already there. Base64-encoded bodies are left untouched.
pub fn apply_signature(data: Vec<u8>, sig: &Signature) -> Vec<u8> {
    if !sig.append || sig.text.trim().is_empty() && sig.html.trim().is_empty() {
        return data;
    }
    let text = crlf(sig.text.trim_end());
    let html = if sig.html.trim().is_empty() {
        format!("<br><div class=\"signature\">-- <br>{}</div>", html_escape(&text).replace("\r\n", "<br>"))
    } else {
        format!("<br><div class=\"signature\">{}</div>", sig.html.trim())
    };
    let marker = text.lines().find(|l| !l.trim().is_empty()).unwrap_or("").trim().to_string();
    if !marker.is_empty() && String::from_utf8_lossy(&data).contains(&marker) {
        return data; // the client already inserted it
    }
    // Collect (offset, bytes) insertions, then apply from the end backwards.
    let mut inserts: Vec<(usize, Vec<u8>)> = Vec::new();
    {
        let root = mime::parse(&data);
        let base = data.as_ptr() as usize;
        let mut done_plain = false;
        let mut done_html = false;
        let mut stack = vec![&root];
        while let Some(p) = stack.pop() {
            if p.is_multipart() {
                for c in p.children.iter().rev() {
                    stack.push(c);
                }
                continue;
            }
            if p.ctype != "text" {
                continue;
            }
            let disp = p.header("Content-Disposition").map(|d| String::from_utf8_lossy(d).to_ascii_lowercase()).unwrap_or_default();
            if disp.starts_with("attachment") {
                continue;
            }
            let enc = p.header("Content-Transfer-Encoding").map(|e| String::from_utf8_lossy(e).trim().to_ascii_lowercase()).unwrap_or_default();
            let qp = enc == "quoted-printable";
            if !(enc.is_empty() || enc == "7bit" || enc == "8bit" || qp) {
                continue;
            }
            let charset = p.params.iter().find(|(k, _)| k == "charset").map(|(_, v)| v.to_ascii_lowercase()).unwrap_or_default();
            let start = p.body.as_ptr() as usize - base;
            let end = start + p.body.len();
            let enc_text = |s: &str| if qp { qp_encode(s) } else { s.to_string() };
            if p.subtype == "plain" && !done_plain && !text.is_empty() {
                if !text.is_ascii() && !charset.contains("utf-8") && !charset.contains("utf8") {
                    continue;
                }
                let sep = if p.body.ends_with(b"\n") { "" } else { "\r\n" };
                inserts.push((end, format!("{sep}{}\r\n", enc_text(&format!("\r\n-- \r\n{text}"))).into_bytes()));
                done_plain = true;
            } else if p.subtype == "html" && !done_html {
                if !html.is_ascii() && !charset.contains("utf-8") && !charset.contains("utf8") {
                    continue;
                }
                let lower = String::from_utf8_lossy(p.body).to_ascii_lowercase();
                let at = lower.rfind("</body>").map(|i| start + i).unwrap_or(end);
                let enc = if qp { format!("=\r\n{}=\r\n", qp_encode(&html)) } else { html.clone() };
                inserts.push((at, enc.into_bytes()));
                done_html = true;
            }
        }
    }
    let mut data = data;
    inserts.sort_by(|a, b| b.0.cmp(&a.0));
    for (at, bytes) in inserts {
        data.splice(at..at, bytes);
    }
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_rules() {
        let h = |n: &str, v: &str| vec![(n.to_string(), v.as_bytes().to_vec())];
        assert!(should_reply("bob@example.com", &[]));
        assert!(!should_reply("", &[]));
        assert!(!should_reply("noreply@example.com", &[]));
        assert!(!should_reply("bob@example.com", &h("Auto-Submitted", "auto-replied")));
        assert!(should_reply("bob@example.com", &h("Auto-Submitted", "no")));
        assert!(!should_reply("bob@example.com", &h("List-Id", "<x.example.com>")));
        assert!(!should_reply("bob@example.com", &h("Precedence", "bulk")));
    }

    #[test]
    fn signature_plain_and_alternative() {
        let sig = Signature { text: "Tony\nPoffles".into(), html: String::new(), append: true };
        let m = b"Subject: x\r\nContent-Type: text/plain\r\n\r\nHello\r\n".to_vec();
        let out = String::from_utf8(apply_signature(m, &sig)).unwrap();
        assert!(out.ends_with("Hello\r\n\r\n-- \r\nTony\r\nPoffles\r\n"), "{out:?}");
        let m = b"Content-Type: multipart/alternative; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nHi\r\n--b\r\nContent-Type: text/html\r\n\r\n<html><body>Hi</body></html>\r\n--b--\r\n".to_vec();
        let out = String::from_utf8(apply_signature(m, &sig)).unwrap();
        assert!(out.contains("Hi\r\n\r\n-- \r\nTony\r\nPoffles\r\n\r\n--b\r\n"), "{out}");
        assert!(out.contains("Hi<br><div class=\"signature\">-- <br>Tony<br>Poffles</div></body>"), "{out}");
        // Not appended twice.
        let again = String::from_utf8(apply_signature(out.clone().into_bytes(), &sig)).unwrap();
        assert_eq!(again, out);
    }
}
