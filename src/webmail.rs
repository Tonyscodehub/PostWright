//! Webmail: the API behind the /mail page (mail, calendar and contacts in a browser).
//!
//! Everything here acts as the signed-in user, on the same store IMAP, CalDAV and
//! CardDAV use, so changes show up in Outlook, phones and Thunderbird straight away.

use crate::http::{builder, json, Req, Resp};
use crate::server::Shared;
use crate::store::{self, User};
use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, TimeZone, Utc};
use http_body_util::Full;
use hyper::StatusCode;
use mail_parser::{MessageParser, MimeHeaders};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json as j, Value};
use std::sync::Arc;

pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS msg_summary(
    blob TEXT PRIMARY KEY,
    data TEXT NOT NULL
);
"#;

const PAGE: usize = 50;

fn query(r: &Req) -> std::collections::HashMap<String, String> {
    r.query
        .split('&')
        .filter_map(|kv| kv.split_once('=').or(Some((kv, ""))))
        .filter(|(k, _)| !k.is_empty())
        .map(|(k, v)| (crate::http::pct_decode(&k.replace('+', " ")), crate::http::pct_decode(&v.replace('+', " "))))
        .collect()
}

fn ok(v: Value) -> Result<Resp> {
    Ok(json(StatusCode::OK, &v))
}

pub async fn api(srv: &Shared, user: &User, r: &Req, segs: &[&str]) -> Result<Resp> {
    match (r.method.as_str(), segs) {
        ("GET", ["mail", "folders"]) => folders(srv, user).await,
        ("POST", ["mail", "folders"]) => folder_change(srv, user, r).await,
        ("GET", ["mail", "messages"]) => messages(srv, user, r).await,
        ("GET", ["mail", "message"]) => message(srv, user, r).await,
        ("GET", ["mail", "part"]) => part(srv, user, r).await,
        ("GET", ["mail", "raw"]) => raw(srv, user, r).await,
        ("POST", ["mail", "flags"]) => flags(srv, user, r).await,
        ("POST", ["mail", "move"]) => move_msgs(srv, user, r).await,
        ("POST", ["mail", "delete"]) => delete(srv, user, r).await,
        ("POST", ["mail", "send"]) => send(srv, user, r, false).await,
        ("POST", ["mail", "draft"]) => send(srv, user, r, true).await,
        ("POST", ["mail", "invite"]) => invite(srv, user, r).await,
        ("GET", ["mail", "identities"]) => identities(srv, user).await,
        ("GET", ["mail", "contacts"]) => suggest(srv, user, r).await,
        ("GET", ["cal", "events"]) => events(srv, user, r).await,
        ("POST", ["cal", "event"]) => save_event(srv, user, r).await,
        ("DELETE", ["cal", "event"]) => delete_event(srv, user, r).await,
        ("GET", ["contacts"]) => contacts(srv, user).await,
        ("POST", ["contacts"]) => save_contact(srv, user, r).await,
        ("DELETE", ["contacts"]) => delete_contact(srv, user, r).await,
        _ => Ok(crate::http::json_err(StatusCode::NOT_FOUND, "unknown endpoint")),
    }
}

// ------------------------------------------------------------------- folders

fn special_of(mb: &store::Mailbox) -> Option<&'static str> {
    let s = mb.special.as_deref().unwrap_or("");
    let n = mb.name.to_ascii_lowercase();
    Some(match (s, n.as_str()) {
        (_, "inbox") => "inbox",
        ("\\Sent", _) | (_, "sent" | "sent items" | "sent messages") => "sent",
        ("\\Drafts", _) | (_, "drafts") => "drafts",
        ("\\Trash", _) | (_, "trash" | "deleted items" | "deleted messages") => "trash",
        ("\\Junk", _) | (_, "junk" | "spam" | "junk e-mail") => "junk",
        ("\\Archive", _) | (_, "archive") => "archive",
        _ => return None,
    })
}

fn find_special(c: &Connection, user_id: i64, which: &str) -> Result<Option<store::Mailbox>> {
    Ok(store::list_mailboxes(c, user_id)?.into_iter().find(|m| special_of(m) == Some(which)))
}

fn mailbox(c: &Connection, user_id: i64, name: &str) -> Result<store::Mailbox> {
    store::find_mailbox(c, user_id, name)?.ok_or_else(|| anyhow!("that folder doesn't exist"))
}

async fn folders(srv: &Shared, user: &User) -> Result<Resp> {
    let uid = user.id;
    let v = srv
        .store
        .call(move |c| {
            let mut counts = std::collections::HashMap::new();
            let mut st = c.prepare(
                "SELECT m.mailbox_id, COUNT(*), SUM(CASE WHEN instr(m.flags, '\\Seen') = 0 THEN 1 ELSE 0 END)
                 FROM messages m JOIN mailboxes b ON b.id = m.mailbox_id WHERE b.user_id = ?1 GROUP BY m.mailbox_id",
            )?;
            for row in st.query_map([uid], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)))? {
                let (id, n, unseen) = row?;
                counts.insert(id, (n, unseen));
            }
            let mut out = Vec::new();
            for mb in store::list_mailboxes(c, uid)? {
                let (n, unseen) = counts.get(&mb.id).copied().unwrap_or((0, 0));
                out.push(j!({ "name": mb.name, "special": special_of(&mb), "total": n, "unread": unseen }));
            }
            Ok(out)
        })
        .await?;
    ok(j!(v))
}

#[derive(Deserialize)]
struct FolderChange {
    action: String,
    name: String,
    #[serde(default)]
    to: String,
}

async fn folder_change(srv: &Shared, user: &User, r: &Req) -> Result<Resp> {
    let f: FolderChange = serde_json::from_slice(&r.body)?;
    let uid = user.id;
    let name = f.name.trim().to_string();
    if name.is_empty() || name.len() > 200 || name.contains(['\\', '*', '%', '"']) {
        bail!("choose a folder name without \\ * % or quotes");
    }
    srv.store
        .call(move |c| {
            match f.action.as_str() {
                "create" => store::create_mailbox(c, uid, &name)?,
                "rename" => {
                    let mb = mailbox(c, uid, &name)?;
                    if special_of(&mb).is_some() {
                        bail!("standard folders can't be renamed");
                    }
                    store::rename_mailbox(c, uid, &name, f.to.trim())?
                }
                "delete" => {
                    let mb = mailbox(c, uid, &name)?;
                    if special_of(&mb).is_some() {
                        bail!("standard folders can't be deleted");
                    }
                    store::delete_mailbox(c, uid, &name)?
                }
                _ => bail!("unknown folder action"),
            }
            Ok(())
        })
        .await?;
    srv.notify_user(uid);
    ok(j!({ "ok": true }))
}

// ------------------------------------------------------------------ messages

/// What the message list shows, cached by blob (messages never change).
fn summarise(data: &[u8], internal_date: i64) -> Value {
    let Some(m) = MessageParser::default().parse(data) else {
        return j!({ "subject": "", "from": "", "from_addr": "", "to": "", "date": internal_date, "preview": "", "attach": false });
    };
    let first = m.from().and_then(|a| a.first());
    let to: Vec<String> = m.to().map(|a| a.iter().map(|x| x.name().or(x.address()).unwrap_or("").to_string()).collect()).unwrap_or_default();
    let preview: String = m.body_preview(200).map(|p| p.split_whitespace().collect::<Vec<_>>().join(" ")).unwrap_or_default();
    j!({
        "subject": m.subject().unwrap_or(""),
        "from": first.and_then(|a| a.name()).filter(|n| !n.is_empty()).or(first.and_then(|a| a.address())).unwrap_or(""),
        "from_addr": first.and_then(|a| a.address()).unwrap_or(""),
        "to": to.join(", "),
        "date": m.date().map(|d| d.to_timestamp()).filter(|t| *t > 0).unwrap_or(internal_date),
        "preview": preview.chars().take(160).collect::<String>(),
        "attach": m.attachments().any(|p| p.attachment_name().is_some() || !p.is_text()),
    })
}

async fn summaries(srv: &Shared, metas: &[store::MsgMeta]) -> Result<Vec<Value>> {
    let blobs: Vec<String> = metas.iter().map(|m| m.blob.clone()).collect();
    let cached: std::collections::HashMap<String, String> = srv
        .store
        .call(move |c| {
            let mut out = std::collections::HashMap::new();
            let mut st = c.prepare_cached("SELECT data FROM msg_summary WHERE blob = ?1")?;
            for b in &blobs {
                if let Some(d) = st.query_row([b], |r| r.get::<_, String>(0)).optional()? {
                    out.insert(b.clone(), d);
                }
            }
            Ok(out)
        })
        .await?;
    let mut out = Vec::with_capacity(metas.len());
    let mut fresh: Vec<(String, String)> = Vec::new();
    for m in metas {
        let mut v = match cached.get(&m.blob).and_then(|d| serde_json::from_str::<Value>(d).ok()) {
            Some(v) => v,
            None => {
                let data = srv.store.get_blob(&m.blob).await.unwrap_or_default();
                let v = summarise(&data, m.internal_date);
                fresh.push((m.blob.clone(), v.to_string()));
                v
            }
        };
        v["uid"] = j!(m.uid);
        v["size"] = j!(m.size);
        v["seen"] = j!(m.flags.iter().any(|f| f == "\\Seen"));
        v["flagged"] = j!(m.flags.iter().any(|f| f == "\\Flagged"));
        v["answered"] = j!(m.flags.iter().any(|f| f == "\\Answered"));
        out.push(v);
    }
    if !fresh.is_empty() {
        srv.store
            .call(move |c| {
                let mut st = c.prepare_cached("INSERT OR REPLACE INTO msg_summary(blob, data) VALUES(?1, ?2)")?;
                for (b, d) in &fresh {
                    st.execute(params![b, d])?;
                }
                Ok(())
            })
            .await?;
    }
    Ok(out)
}

async fn messages(srv: &Shared, user: &User, r: &Req) -> Result<Resp> {
    let q = query(r);
    let folder = q.get("folder").cloned().unwrap_or_else(|| "INBOX".into());
    let page: usize = q.get("page").and_then(|p| p.parse().ok()).unwrap_or(0);
    let search = q.get("q").map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty());
    let unread_only = q.get("unread").map(|v| v == "1").unwrap_or(false);
    let uid = user.id;
    let mut metas = srv
        .store
        .call(move |c| {
            let mb = mailbox(c, uid, &folder)?;
            store::list_messages(c, mb.id)
        })
        .await?;
    metas.sort_by(|a, b| b.internal_date.cmp(&a.internal_date).then(b.uid.cmp(&a.uid)));
    if unread_only {
        metas.retain(|m| !m.flags.iter().any(|f| f == "\\Seen"));
    }
    let total;
    let items = if let Some(s) = search {
        let all = summaries(srv, &metas).await?;
        let words: Vec<&str> = s.split_whitespace().collect();
        let hits: Vec<Value> = all
            .into_iter()
            .filter(|v| {
                let hay = format!("{} {} {} {} {}", v["subject"], v["from"], v["from_addr"], v["to"], v["preview"]).to_lowercase();
                words.iter().all(|w| hay.contains(w))
            })
            .collect();
        total = hits.len();
        hits.into_iter().skip(page * PAGE).take(PAGE).collect()
    } else {
        total = metas.len();
        let slice: Vec<store::MsgMeta> = metas.into_iter().skip(page * PAGE).take(PAGE).collect();
        summaries(srv, &slice).await?
    };
    ok(j!({ "total": total, "page": page, "page_size": PAGE, "messages": items }))
}

async fn load(srv: &Shared, user_id: i64, folder: &str, uid: u32) -> Result<(store::Mailbox, store::MsgMeta, Vec<u8>)> {
    let folder = folder.to_string();
    let (mb, meta) = srv
        .store
        .call(move |c| {
            let mb = mailbox(c, user_id, &folder)?;
            let meta = store::list_messages(c, mb.id)?.into_iter().find(|m| m.uid == uid).ok_or_else(|| anyhow!("that message is no longer there"))?;
            Ok((mb, meta))
        })
        .await?;
    let data = srv.store.get_blob(&meta.blob).await?;
    Ok((mb, meta, data))
}

fn addrs(a: Option<&mail_parser::Address>) -> Vec<Value> {
    a.map(|a| a.iter().map(|x| j!({ "name": x.name().unwrap_or(""), "email": x.address().unwrap_or("") })).collect()).unwrap_or_default()
}

fn text_list(h: &mail_parser::HeaderValue) -> Vec<String> {
    match h {
        mail_parser::HeaderValue::Text(t) => vec![t.to_string()],
        mail_parser::HeaderValue::TextList(l) => l.iter().map(|x| x.to_string()).collect(),
        _ => vec![],
    }
}

fn b64(d: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(d)
}

async fn message(srv: &Shared, user: &User, r: &Req) -> Result<Resp> {
    let q = query(r);
    let folder = q.get("folder").cloned().unwrap_or_default();
    let uid: u32 = q.get("uid").and_then(|u| u.parse().ok()).ok_or_else(|| anyhow!("which message?"))?;
    let (mb, meta, data) = load(srv, user.id, &folder, uid).await?;
    // Opening a message marks it read.
    if !meta.flags.iter().any(|f| f == "\\Seen") {
        let mut fl = meta.flags.clone();
        fl.push("\\Seen".into());
        let id = meta.id;
        srv.store.call(move |c| store::set_flags(c, id, &fl)).await?;
        srv.notify_user(user.id);
    }
    let m = MessageParser::default().parse(&data).ok_or_else(|| anyhow!("this message couldn't be read"))?;
    let mut html = if m.html_body_count() > 0 && m.html_bodies().any(|p| p.is_text_html()) { m.body_html(0).map(|s| s.to_string()) } else { None };
    let text = m.body_text(0).map(|s| s.to_string()).unwrap_or_default();
    let mut atts = Vec::new();
    let mut invite = None;
    for (i, p) in m.parts.iter().enumerate() {
        let ct = p.content_type();
        let (t, st) = ct.map(|c| (c.ctype().to_ascii_lowercase(), c.subtype().unwrap_or("").to_ascii_lowercase())).unwrap_or_default();
        if t == "text" && st == "calendar" || p.attachment_name().map(|n| n.to_ascii_lowercase().ends_with(".ics")).unwrap_or(false) {
            if invite.is_none() {
                if let Some(ics) = std::str::from_utf8(p.contents()).ok() {
                    invite = invite_summary(ics, &user.email);
                }
            }
        }
        // Inline images referenced by cid: go into the HTML as data: URLs, because the
        // sandboxed message frame can't fetch anything that needs the session cookie.
        if let (Some(cid), Some(h)) = (p.content_id(), html.as_mut()) {
            let cid = cid.trim_matches(['<', '>']);
            if t == "image" && p.contents().len() < 3_000_000 && h.contains(&format!("cid:{cid}")) {
                *h = h.replace(&format!("cid:{cid}"), &format!("data:{t}/{st};base64,{}", b64(p.contents())));
                continue;
            }
        }
        let is_body = m.text_body.contains(&(i as u32)) || m.html_body.contains(&(i as u32));
        if p.is_multipart() || (is_body && p.attachment_name().is_none()) || i == 0 && !p.is_binary() && p.attachment_name().is_none() {
            continue;
        }
        if p.is_text() && p.attachment_name().is_none() && !(t == "text" && st == "calendar") {
            continue;
        }
        let name = p.attachment_name().map(String::from).unwrap_or_else(|| if t == "text" && st == "calendar" { "invite.ics".into() } else { format!("part-{i}") });
        atts.push(j!({ "part": i, "name": name, "type": format!("{t}/{st}"), "size": p.contents().len() }));
    }
    // A guest's answer to one of my meetings updates my copy of it.
    if let Some(inv) = &invite {
        if inv["method"] == "REPLY" {
            if let Some(ics) = calendar_part(&m) {
                if let Err(e) = apply_reply(srv, user, &ics).await {
                    tracing::debug!("webmail: reply not applied: {e:#}");
                }
            }
        }
    }
    ok(j!({
        "uid": uid,
        "folder": mb.name,
        "subject": m.subject().unwrap_or(""),
        "from": addrs(m.from()),
        "to": addrs(m.to()),
        "cc": addrs(m.cc()),
        "reply_to": addrs(m.reply_to()),
        "date": m.date().map(|d| d.to_timestamp()).unwrap_or(meta.internal_date),
        "message_id": m.message_id(),
        "references": text_list(m.references()),
        "html": html,
        "text": text,
        "attachments": atts,
        "flagged": meta.flags.iter().any(|f| f == "\\Flagged"),
        "draft": special_of(&mb) == Some("drafts"),
        "invite": invite,
        "list_unsubscribe": text_list(m.list_unsubscribe()).first().cloned(),
    }))
}

fn safe_filename(n: &str) -> String {
    let s: String = n.chars().map(|c| if c.is_control() || "\"\\/:*?<>|".contains(c) { '_' } else { c }).take(150).collect();
    if s.trim().is_empty() { "attachment".into() } else { s }
}

fn download(data: Vec<u8>, name: &str, ctype: &str, inline: bool) -> Resp {
    // Only images and PDFs are shown inline; everything else downloads, and nothing is
    // ever sniffed or run on this origin.
    let show = inline && (ctype.starts_with("image/") && !ctype.contains("svg") || ctype == "application/pdf");
    let ascii: String = name.chars().map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '_' }).collect();
    builder(StatusCode::OK)
        .header("Content-Type", if show { ctype } else { "application/octet-stream" })
        .header(
            "Content-Disposition",
            format!("{}; filename=\"{}\"; filename*=UTF-8''{}", if show { "inline" } else { "attachment" }, ascii, crate::http::enc_path(name)),
        )
        .header("X-Content-Type-Options", "nosniff")
        .header("Content-Security-Policy", "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; sandbox")
        .header("Cache-Control", "private, max-age=300")
        .body(Full::new(Bytes::from(data)))
        .unwrap()
}

async fn part(srv: &Shared, user: &User, r: &Req) -> Result<Resp> {
    let q = query(r);
    let folder = q.get("folder").cloned().unwrap_or_default();
    let uid: u32 = q.get("uid").and_then(|u| u.parse().ok()).ok_or_else(|| anyhow!("which message?"))?;
    let idx: usize = q.get("part").and_then(|u| u.parse().ok()).ok_or_else(|| anyhow!("which attachment?"))?;
    let (_, _, data) = load(srv, user.id, &folder, uid).await?;
    let m = MessageParser::default().parse(&data).ok_or_else(|| anyhow!("this message couldn't be read"))?;
    let p = m.parts.get(idx).ok_or_else(|| anyhow!("no such attachment"))?;
    let ct = p.content_type().map(|c| format!("{}/{}", c.ctype(), c.subtype().unwrap_or("octet-stream")).to_ascii_lowercase()).unwrap_or_else(|| "application/octet-stream".into());
    let name = safe_filename(p.attachment_name().unwrap_or("attachment"));
    Ok(download(p.contents().to_vec(), &name, &ct, q.get("view").is_some()))
}

async fn raw(srv: &Shared, user: &User, r: &Req) -> Result<Resp> {
    let q = query(r);
    let folder = q.get("folder").cloned().unwrap_or_default();
    let uid: u32 = q.get("uid").and_then(|u| u.parse().ok()).ok_or_else(|| anyhow!("which message?"))?;
    let (_, _, data) = load(srv, user.id, &folder, uid).await?;
    let subj = MessageParser::default().parse(&data).and_then(|m| m.subject().map(String::from)).unwrap_or_else(|| "message".into());
    Ok(download(data, &format!("{}.eml", safe_filename(&subj)), "message/rfc822", false))
}

#[derive(Deserialize)]
struct Sel {
    folder: String,
    uids: Vec<u32>,
    #[serde(default)]
    add: Vec<String>,
    #[serde(default)]
    remove: Vec<String>,
    #[serde(default)]
    to: String,
}

async fn flags(srv: &Shared, user: &User, r: &Req) -> Result<Resp> {
    let s: Sel = serde_json::from_slice(&r.body)?;
    let allowed = ["\\Seen", "\\Flagged", "\\Answered", "$Forwarded", "$Junk", "$NotJunk"];
    if s.add.iter().chain(&s.remove).any(|f| !allowed.contains(&f.as_str())) {
        bail!("unsupported flag");
    }
    let uid = user.id;
    srv.store
        .call(move |c| {
            let mb = mailbox(c, uid, &s.folder)?;
            for m in store::list_messages(c, mb.id)?.into_iter().filter(|m| s.uids.contains(&m.uid)) {
                let mut f: Vec<String> = m.flags.into_iter().filter(|x| !s.remove.contains(x)).collect();
                for a in &s.add {
                    if !f.contains(a) {
                        f.push(a.clone());
                    }
                }
                store::set_flags(c, m.id, &f)?;
            }
            Ok(())
        })
        .await?;
    srv.notify_user(uid);
    ok(j!({ "ok": true }))
}

async fn move_msgs(srv: &Shared, user: &User, r: &Req) -> Result<Resp> {
    let s: Sel = serde_json::from_slice(&r.body)?;
    let uid = user.id;
    let (blobs, from_junk, to_junk, to_trash) = srv
        .store
        .call(move |c| {
            let src = mailbox(c, uid, &s.folder)?;
            let dst = mailbox(c, uid, &s.to)?;
            if src.id == dst.id {
                return Ok((vec![], false, false, false));
            }
            let blobs: Vec<String> = store::list_messages(c, src.id)?.into_iter().filter(|m| s.uids.contains(&m.uid)).map(|m| m.blob).collect();
            store::move_messages(c, src.id, dst.id, &s.uids)?;
            Ok((blobs, special_of(&src) == Some("junk"), special_of(&dst) == Some("junk"), special_of(&dst) == Some("trash")))
        })
        .await?;
    // Same teaching as IMAP: into Junk is spam, rescued from Junk is ham.
    if to_junk && !from_junk && !blobs.is_empty() {
        crate::filter::learn(srv, blobs, true, user.email.clone());
    } else if from_junk && !to_junk && !to_trash && !blobs.is_empty() {
        crate::filter::learn(srv, blobs, false, user.email.clone());
    }
    srv.notify_user(uid);
    ok(j!({ "ok": true }))
}

/// Delete: to Trash, or for good when already in Trash (or Junk).
async fn delete(srv: &Shared, user: &User, r: &Req) -> Result<Resp> {
    let s: Sel = serde_json::from_slice(&r.body)?;
    let uid = user.id;
    srv.store
        .call(move |c| {
            let src = mailbox(c, uid, &s.folder)?;
            let trash = find_special(c, uid, "trash")?;
            match trash {
                Some(t) if t.id != src.id && special_of(&src) != Some("junk") => {
                    store::move_messages(c, src.id, t.id, &s.uids)?;
                }
                _ => store::expunge_uids(c, src.id, &s.uids)?,
            }
            Ok(())
        })
        .await?;
    srv.notify_user(uid);
    ok(j!({ "ok": true }))
}

// ------------------------------------------------------------------- sending

async fn identities(srv: &Shared, user: &User) -> Result<Resp> {
    let u = user.clone();
    let (own, delegated, name, sig) = srv
        .store
        .call(move |c| {
            let own = store::sender_addresses(c, &u)?;
            let del = crate::identity::delegated_senders(c, u.id)?;
            let name = store::display_name(c, u.id)?;
            let sig = crate::prefs::load(c, u.id)?.signature;
            Ok((own, del, name, sig))
        })
        .await?;
    let mut list: Vec<Value> = own.iter().map(|a| j!({ "email": a, "name": name.clone().unwrap_or_default(), "kind": "own" })).collect();
    for (a, right) in delegated {
        list.push(j!({ "email": a, "name": "", "kind": right.as_str() }));
    }
    ok(j!({ "identities": list, "default": user.email, "signature": { "text": sig.text, "html": sig.html, "append": sig.append } }))
}

#[derive(Deserialize, Default)]
struct Upload {
    name: String,
    #[serde(rename = "type", default)]
    ctype: String,
    /// base64
    data: String,
}

#[derive(Deserialize, Default)]
struct Compose {
    from: String,
    #[serde(default)]
    to: Vec<String>,
    #[serde(default)]
    cc: Vec<String>,
    #[serde(default)]
    bcc: Vec<String>,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    text: String,
    #[serde(default)]
    html: Option<String>,
    #[serde(default)]
    in_reply_to: Option<String>,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    attachments: Vec<Upload>,
    /// Attachments to carry over from an existing message (forwarding, drafts).
    #[serde(default)]
    keep: Option<KeepParts>,
    /// The draft this replaces (removed once sent or saved again).
    #[serde(default)]
    draft_uid: Option<u32>,
    /// The message being answered or forwarded, flagged once this is sent.
    #[serde(default)]
    answering: Option<Answering>,
    /// A calendar part (method and data), for invitations and replies.
    #[serde(skip)]
    ics: Option<(String, String)>,
}

#[derive(Deserialize, Default)]
struct KeepParts {
    folder: String,
    uid: u32,
    parts: Vec<usize>,
}

#[derive(Deserialize, Default)]
struct Answering {
    folder: String,
    uid: u32,
    forwarded: bool,
}

fn mailbox_of(s: &str) -> Result<lettre::message::Mailbox> {
    let s = s.trim();
    s.parse::<lettre::message::Mailbox>().map_err(|_| anyhow!("\"{s}\" isn't a valid email address"))
}

fn build(c: &Compose, sender: Option<&str>, kept: Vec<(String, String, Vec<u8>)>) -> Result<Vec<u8>> {
    use lettre::message::{header::ContentType, Attachment, MultiPart, SinglePart};
    let from = mailbox_of(&c.from)?;
    let domain = from.email.domain().to_string();
    let mut b = lettre::Message::builder().from(from).subject(c.subject.clone());
    for a in &c.to {
        b = b.to(mailbox_of(a)?);
    }
    for a in &c.cc {
        b = b.cc(mailbox_of(a)?);
    }
    for a in &c.bcc {
        b = b.bcc(mailbox_of(a)?);
    }
    if let Some(s) = sender {
        b = b.sender(mailbox_of(s)?);
    }
    if let Some(r) = c.in_reply_to.as_ref().filter(|r| !r.trim().is_empty()) {
        b = b.in_reply_to(r.clone());
    }
    if !c.references.is_empty() {
        b = b.references(c.references.join(" "));
    }
    b = b.message_id(Some(format!("<{}.{:x}@{}>", store::now(), rand::random::<u64>(), domain)));
    b = b.user_agent("Postwright Webmail".into());
    let text_part = SinglePart::plain(c.text.clone());
    let mut body = match &c.html {
        Some(h) if !h.trim().is_empty() => MultiPart::alternative().singlepart(text_part).singlepart(SinglePart::html(h.clone())),
        _ => MultiPart::alternative().singlepart(text_part),
    };
    if let Some((method, data)) = &c.ics {
        let ct = ContentType::parse(&format!("text/calendar; method={method}; charset=UTF-8")).map_err(|e| anyhow!("{e}"))?;
        body = body.singlepart(SinglePart::builder().header(ct).body(data.clone()));
    }
    let mut files: Vec<(String, String, Vec<u8>)> = kept;
    for a in &c.attachments {
        use base64::Engine;
        let d = base64::engine::general_purpose::STANDARD.decode(a.data.as_bytes()).context("reading an attachment")?;
        files.push((a.name.clone(), a.ctype.clone(), d));
    }
    let msg = if files.is_empty() && c.ics.is_none() && c.html.as_ref().map(|h| h.trim().is_empty()).unwrap_or(true) {
        b.singlepart(SinglePart::plain(c.text.clone()))?
    } else if files.is_empty() {
        b.multipart(body)?
    } else {
        let mut mixed = MultiPart::mixed().multipart(body);
        for (name, ct, data) in files {
            let ct = ContentType::parse(&ct).unwrap_or_else(|_| ContentType::parse("application/octet-stream").unwrap());
            mixed = mixed.singlepart(Attachment::new(safe_filename(&name)).body(data, ct));
        }
        b.multipart(mixed)?
    };
    Ok(msg.formatted())
}

async fn kept_parts(srv: &Shared, user_id: i64, k: &Option<KeepParts>) -> Result<Vec<(String, String, Vec<u8>)>> {
    let Some(k) = k else { return Ok(vec![]) };
    if k.parts.is_empty() {
        return Ok(vec![]);
    }
    let (_, _, data) = load(srv, user_id, &k.folder, k.uid).await?;
    let m = MessageParser::default().parse(&data).ok_or_else(|| anyhow!("the original message couldn't be read"))?;
    let mut out = Vec::new();
    for i in &k.parts {
        if let Some(p) = m.parts.get(*i) {
            let ct = p.content_type().map(|c| format!("{}/{}", c.ctype(), c.subtype().unwrap_or("octet-stream"))).unwrap_or_else(|| "application/octet-stream".into());
            out.push((p.attachment_name().unwrap_or("attachment").to_string(), ct, p.contents().to_vec()));
        }
    }
    Ok(out)
}

async fn send(srv: &Shared, user: &User, r: &Req, draft: bool) -> Result<Resp> {
    let c: Compose = serde_json::from_slice(&r.body)?;
    let v = submit(srv, user, c, draft).await?;
    ok(v)
}

async fn submit(srv: &Shared, user: &User, mut c: Compose, draft: bool) -> Result<Value> {
    let u = user.clone();
    let from_addr = mailbox_of(&c.from)?.email.to_string().to_ascii_lowercase();
    let fa = from_addr.clone();
    let (own, right) = srv
        .store
        .call(move |cn| {
            let own = store::sender_addresses(cn, &u)?;
            let right = crate::identity::delegated_senders(cn, u.id)?.into_iter().find(|(a, _)| *a == fa).map(|(_, r)| r);
            Ok((own, right))
        })
        .await?;
    let is_own = own.iter().any(|a| a.eq_ignore_ascii_case(&from_addr));
    if !is_own && right.is_none() && !draft {
        bail!("you can't send from {from_addr}");
    }
    let sender = (!is_own && right == Some(crate::identity::SendRight::OnBehalf)).then(|| user.email.clone());
    let rcpts: Vec<String> = c.to.iter().chain(&c.cc).chain(&c.bcc).map(|a| mailbox_of(a).map(|m| m.email.to_string())).collect::<Result<_>>()?;
    if !draft && rcpts.is_empty() {
        bail!("add at least one recipient");
    }
    if c.subject.len() > 1000 {
        bail!("the subject is too long");
    }
    c.subject = c.subject.replace(['\r', '\n'], " ");
    let kept = kept_parts(srv, user.id, &c.keep).await?;
    let mut data = build(&c, sender.as_deref(), kept)?;
    let uid = user.id;
    let old_draft = c.draft_uid;

    if draft {
        let size = data.len() as i64;
        let blob = srv.store.put_blob(Arc::new(data)).await?;
        let new_uid = srv
            .store
            .call(move |cn| {
                let d = find_special(cn, uid, "drafts")?.ok_or_else(|| anyhow!("there's no Drafts folder"))?;
                let n = store::append_message(cn, d.id, &blob, size, store::now(), &["\\Draft".into(), "\\Seen".into()])?;
                if let Some(o) = old_draft {
                    store::expunge_uids(cn, d.id, &[o])?;
                }
                Ok(n)
            })
            .await?;
        srv.notify_user(uid);
        return Ok(j!({ "ok": true, "draft_uid": new_uid }));
    }

    // Same checks and treatment as mail sent from an email app.
    let fcfg = srv.cfg.filter.clone();
    if fcfg.enabled && fcfg.scan_outbound {
        let mut v = crate::filter::Verdict::default();
        let env = crate::filter::Envelope { ip: std::net::IpAddr::from([127, 0, 0, 1]), helo: "webmail", mail_from: &from_addr, rcpts: &rcpts, user: Some(&user.email) };
        crate::filter::scan_content(srv, &env, &data, &mut v).await;
        if let Some(virus) = &v.virus {
            bail!("not sent: an attachment contains malware ({virus})");
        }
        if v.force_reject {
            bail!("not sent: the spam filter rejected this message");
        }
        if let Some(t) = v.tempfail {
            bail!("not sent: {t}. Try again in a minute");
        }
    }
    let settings = srv.store.call(move |cn| crate::prefs::load(cn, uid)).await?;
    data = crate::prefs::apply_signature(data, &settings.signature);
    let mut full = format!(
        "Received: from webmail (authenticated as {}) by {} with HTTPS; {}\r\n",
        user.email,
        srv.cfg.hostname,
        chrono::Utc::now().to_rfc2822()
    )
    .into_bytes();
    full.extend_from_slice(&data);
    let dom_name = crate::delivery::domain_of(&from_addr);
    let dom = srv.store.call(move |cn| store::find_domain(cn, &dom_name)).await?;
    if let Some(d) = dom {
        full = crate::delivery::dkim_sign(&d, full)?;
    }
    let failed = crate::delivery::deliver(srv, &from_addr, &rcpts, full).await?;
    if failed.len() == rcpts.len() {
        bail!("couldn't send to any of the recipients");
    }
    tracing::info!("webmail: {} sent a message to {} recipient(s)", user.email, rcpts.len());

    // A copy in Sent (without the Received/DKIM lines, like an email app saves it).
    let size = data.len() as i64;
    let blob = srv.store.put_blob(Arc::new(data)).await?;
    let answering = c.answering.take();
    srv.store
        .call(move |cn| {
            if let Some(s) = find_special(cn, uid, "sent")? {
                store::append_message(cn, s.id, &blob, size, store::now(), &["\\Seen".into()])?;
            }
            if let (Some(o), Some(d)) = (old_draft, find_special(cn, uid, "drafts")?) {
                store::expunge_uids(cn, d.id, &[o])?;
            }
            if let Some(a) = answering {
                if let Ok(mb) = mailbox(cn, uid, &a.folder) {
                    if let Some(m) = store::list_messages(cn, mb.id)?.into_iter().find(|m| m.uid == a.uid) {
                        let mut f = m.flags.clone();
                        let flag = if a.forwarded { "$Forwarded" } else { "\\Answered" };
                        if !f.iter().any(|x| x == flag) {
                            f.push(flag.into());
                            store::set_flags(cn, m.id, &f)?;
                        }
                    }
                }
            }
            Ok(())
        })
        .await?;
    srv.notify_user(uid);
    Ok(j!({ "ok": true, "failed": failed }))
}

// ------------------------------------------------------------ contacts lookup

async fn suggest(srv: &Shared, user: &User, r: &Req) -> Result<Resp> {
    let q = query(r).get("q").cloned().unwrap_or_default().to_lowercase();
    if q.len() < 2 {
        return ok(j!([]));
    }
    let (u, scope) = (user.clone(), srv.cfg.contacts.directory.clone());
    let v = srv
        .store
        .call(move |c| {
            let mut out: Vec<(String, String)> = Vec::new();
            for b in crate::carddav::list_books(c, &u, &scope)? {
                for card in crate::carddav::list_cards(c, &u, &b, &scope)? {
                    let m = crate::carddav::vcard_meta(&card.data)?;
                    let name = m.full_name.unwrap_or_default();
                    for e in m.emails {
                        if (name.to_lowercase().contains(&q) || e.contains(&q)) && !out.iter().any(|(_, x)| *x == e) {
                            out.push((name.clone(), e));
                        }
                    }
                }
            }
            out.sort_by_key(|(n, e)| (!e.starts_with(&q) && !n.to_lowercase().starts_with(&q), n.to_lowercase()));
            out.truncate(12);
            Ok(out.into_iter().map(|(n, e)| j!({ "name": n, "email": e })).collect::<Vec<_>>())
        })
        .await?;
    ok(j!(v))
}

// ------------------------------------------------------------------ contacts

fn unesc(s: &str) -> String {
    s.replace("\\n", "\n").replace("\\N", "\n").replace("\\,", ",").replace("\\;", ";").replace("\\\\", "\\")
}

fn card_json(book: &crate::carddav::Book, card: &crate::carddav::Card) -> Value {
    let (mut name, mut emails, mut phones, mut org, mut title, mut note, mut adr) = (String::new(), vec![], vec![], String::new(), String::new(), String::new(), String::new());
    for l in crate::carddav::lines(&card.data) {
        let Some((key, val)) = l.split_once(':') else { continue };
        let k = key.split(';').next().unwrap_or("");
        let k = k.rsplit('.').next().unwrap_or(k).to_ascii_uppercase();
        let typ = key.to_ascii_lowercase();
        let kind = ["work", "home", "cell", "mobile"].into_iter().find(|t| typ.contains(t)).unwrap_or("");
        match k.as_str() {
            "FN" => name = unesc(val),
            "EMAIL" => emails.push(j!({ "value": val.trim(), "type": kind })),
            "TEL" => phones.push(j!({ "value": val.trim().trim_start_matches("tel:"), "type": kind })),
            "ORG" => org = unesc(&val.replace(';', " ")).trim().to_string(),
            "TITLE" => title = unesc(val),
            "NOTE" => note = unesc(val),
            "ADR" => adr = unesc(&val.split(';').filter(|x| !x.is_empty()).collect::<Vec<_>>().join(", ")),
            _ => {}
        }
    }
    j!({ "book": book.slug, "book_name": book.name, "id": card.name, "write": book.write && !book.directory,
         "name": name, "emails": emails, "phones": phones, "org": org, "title": title, "note": note, "address": adr })
}

async fn contacts(srv: &Shared, user: &User) -> Result<Resp> {
    let (u, scope) = (user.clone(), srv.cfg.contacts.directory.clone());
    let v = srv
        .store
        .call(move |c| {
            let mut books = Vec::new();
            let mut cards = Vec::new();
            for b in crate::carddav::list_books(c, &u, &scope)? {
                books.push(j!({ "slug": b.slug, "name": b.name, "write": b.write && !b.directory, "directory": b.directory }));
                for card in crate::carddav::list_cards(c, &u, &b, &scope)? {
                    cards.push(card_json(&b, &card));
                }
            }
            Ok(j!({ "books": books, "contacts": cards }))
        })
        .await?;
    ok(v)
}

#[derive(Deserialize)]
struct ContactIn {
    book: String,
    #[serde(default)]
    id: Option<String>,
    name: String,
    #[serde(default)]
    emails: Vec<String>,
    #[serde(default)]
    phones: Vec<String>,
    #[serde(default)]
    org: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    note: String,
}

async fn save_contact(srv: &Shared, user: &User, r: &Req) -> Result<Resp> {
    let ci: ContactIn = serde_json::from_slice(&r.body)?;
    if ci.name.trim().is_empty() {
        bail!("enter a name");
    }
    let (u, scope) = (user.clone(), srv.cfg.contacts.directory.clone());
    let id = srv
        .store
        .call(move |c| {
            let book = crate::carddav::resolve(c, &u, &ci.book, &scope)?.filter(|b| b.write && !b.directory).ok_or_else(|| anyhow!("you can't change that address book"))?;
            let e = crate::carddav::vesc;
            // Editing keeps the parts of the card this form doesn't show (photos, birthdays...).
            let (name, uid, mut keep) = match &ci.id {
                Some(id) => {
                    let old = crate::carddav::get_card(c, &u, &book, id, &scope)?.ok_or_else(|| anyhow!("that contact is no longer there"))?;
                    let uid = crate::carddav::vcard_meta(&old.data)?.uid.unwrap_or_else(|| format!("{:x}", rand::random::<u128>()));
                    let keep: Vec<String> = crate::carddav::lines(&old.data)
                        .into_iter()
                        .filter(|l| {
                            let k = l.split([':', ';']).next().unwrap_or("");
                            let k = k.rsplit('.').next().unwrap_or(k).to_ascii_uppercase();
                            !["BEGIN", "END", "VERSION", "UID", "FN", "N", "EMAIL", "TEL", "ORG", "TITLE", "NOTE", "REV", "PRODID", ""].contains(&k.as_str())
                        })
                        .collect();
                    (id.clone(), uid, keep)
                }
                None => {
                    let uid = format!("{:x}", rand::random::<u128>());
                    (format!("{uid}.vcf"), uid, vec![])
                }
            };
            let full = ci.name.trim();
            let (first, last) = match full.rsplit_once(' ') {
                Some((f, l)) => (f.trim(), l.trim()),
                None => (full, ""),
            };
            let mut v = vec!["BEGIN:VCARD".to_string(), "VERSION:3.0".into(), "PRODID:-//Postwright//Webmail//EN".into(), format!("UID:{uid}"), format!("FN:{}", e(full)), format!("N:{};{};;;", e(last), e(first))];
            for m in ci.emails.iter().map(|x| x.trim()).filter(|x| !x.is_empty()) {
                v.push(format!("EMAIL;TYPE=INTERNET:{}", e(m)));
            }
            for p in ci.phones.iter().map(|x| x.trim()).filter(|x| !x.is_empty()) {
                v.push(format!("TEL:{}", e(p)));
            }
            if !ci.org.trim().is_empty() {
                v.push(format!("ORG:{}", e(ci.org.trim())));
            }
            if !ci.title.trim().is_empty() {
                v.push(format!("TITLE:{}", e(ci.title.trim())));
            }
            if !ci.note.trim().is_empty() {
                v.push(format!("NOTE:{}", e(ci.note.trim())));
            }
            v.append(&mut keep);
            v.push(format!("REV:{}", chrono::Utc::now().format("%Y%m%dT%H%M%SZ")));
            v.push("END:VCARD".into());
            let data = v.into_iter().map(|l| crate::migrate::ical::fold(&l)).collect::<Vec<_>>().join("\r\n") + "\r\n";
            crate::carddav::put_card(c, book.id, &name, &data)?;
            Ok(name)
        })
        .await?;
    ok(j!({ "ok": true, "id": id }))
}

async fn delete_contact(srv: &Shared, user: &User, r: &Req) -> Result<Resp> {
    let q = query(r);
    let (book, id) = (q.get("book").cloned().unwrap_or_default(), q.get("id").cloned().unwrap_or_default());
    let (u, scope) = (user.clone(), srv.cfg.contacts.directory.clone());
    srv.store
        .call(move |c| {
            let b = crate::carddav::resolve(c, &u, &book, &scope)?.filter(|b| b.write && !b.directory).ok_or_else(|| anyhow!("you can't change that address book"))?;
            c.execute("DELETE FROM contacts WHERE addressbook_id = ?1 AND name = ?2", params![b.id, id])?;
            c.execute("UPDATE addressbooks SET ctag = ctag + 1 WHERE id = ?1", [b.id])?;
            Ok(())
        })
        .await?;
    ok(j!({ "ok": true }))
}

// ================================================================== calendar

/// One iCalendar property: name, parameters (upper-cased keys), value.
#[derive(Clone, Debug)]
pub struct Prop {
    pub name: String,
    pub params: Vec<(String, String)>,
    pub value: String,
}

impl Prop {
    fn param(&self, k: &str) -> Option<&str> {
        self.params.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }
}

/// The VEVENTs of an object (other components are left alone).
fn vevents(data: &str) -> Vec<Vec<Prop>> {
    let mut out = Vec::new();
    let mut cur: Option<Vec<Prop>> = None;
    let mut depth = 0;
    for l in unfold(data) {
        let up = l.to_ascii_uppercase();
        if up == "BEGIN:VEVENT" {
            cur = Some(Vec::new());
            depth = 0;
            continue;
        }
        if up == "END:VEVENT" {
            if let Some(c) = cur.take() {
                out.push(c);
            }
            continue;
        }
        if let Some(c) = cur.as_mut() {
            if up.starts_with("BEGIN:") {
                depth += 1;
                continue;
            }
            if up.starts_with("END:") {
                depth -= 1;
                continue;
            }
            if depth == 0 {
                if let Some(p) = parse_prop(&l) {
                    c.push(p);
                }
            }
        }
    }
    out
}

fn unfold(data: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in data.split('\n') {
        let l = raw.strip_suffix('\r').unwrap_or(raw);
        if (l.starts_with(' ') || l.starts_with('\t')) && !out.is_empty() {
            out.last_mut().unwrap().push_str(&l[1..]);
        } else if !l.is_empty() {
            out.push(l.to_string());
        }
    }
    out
}

fn parse_prop(l: &str) -> Option<Prop> {
    // The value starts at the first colon outside a quoted parameter.
    let mut in_q = false;
    let mut split = None;
    for (i, ch) in l.char_indices() {
        match ch {
            '"' => in_q = !in_q,
            ':' if !in_q => {
                split = Some(i);
                break;
            }
            _ => {}
        }
    }
    let i = split?;
    let (head, value) = (&l[..i], &l[i + 1..]);
    let mut parts = head.split(';');
    let name = parts.next()?.to_ascii_uppercase();
    let params = parts.filter_map(|p| p.split_once('=')).map(|(k, v)| (k.to_ascii_uppercase(), v.trim_matches('"').to_string())).collect();
    Some(Prop { name, params, value: value.to_string() })
}

fn get<'a>(ev: &'a [Prop], name: &str) -> Option<&'a Prop> {
    ev.iter().find(|p| p.name == name)
}

fn ical_unesc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('n' | 'N') => out.push('\n'),
                Some(x) => out.push(x),
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// A point in time: an all-day date, or an instant.
#[derive(Clone, Copy, Debug, PartialEq)]
enum When {
    Date(NaiveDate),
    At(DateTime<Utc>),
}

fn zone(tzid: &str) -> Option<chrono_tz::Tz> {
    tzid.parse::<chrono_tz::Tz>().ok().or_else(|| crate::migrate::ical::zone(tzid))
}

fn parse_when(p: &Prop, floating: chrono_tz::Tz) -> Option<When> {
    let v = p.value.trim();
    if p.param("VALUE").map(|x| x.eq_ignore_ascii_case("DATE")).unwrap_or(false) || v.len() == 8 {
        return NaiveDate::parse_from_str(&v[..8.min(v.len())], "%Y%m%d").ok().map(When::Date);
    }
    let (body, utc) = match v.strip_suffix('Z') {
        Some(b) => (b, true),
        None => (v, false),
    };
    let nd = NaiveDateTime::parse_from_str(body, "%Y%m%dT%H%M%S").ok()?;
    if utc {
        return Some(When::At(Utc.from_utc_datetime(&nd)));
    }
    let tz = p.param("TZID").and_then(zone).unwrap_or(floating);
    tz.from_local_datetime(&nd).earliest().map(|d| When::At(d.with_timezone(&Utc)))
}

fn parse_duration(s: &str) -> Option<chrono::Duration> {
    let s = s.trim();
    let (neg, s) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s.trim_start_matches('+')),
    };
    let s = s.strip_prefix('P')?;
    let mut secs: i64 = 0;
    let mut num = String::new();
    for ch in s.chars() {
        match ch {
            '0'..='9' => num.push(ch),
            'T' => {}
            'W' | 'D' | 'H' | 'M' | 'S' => {
                let n: i64 = num.parse().ok()?;
                num.clear();
                secs += n * match ch {
                    'W' => 604800,
                    'D' => 86400,
                    'H' => 3600,
                    'M' => 60,
                    _ => 1,
                };
            }
            _ => return None,
        }
    }
    Some(chrono::Duration::seconds(if neg { -secs } else { secs }))
}

fn when_json(w: When) -> Value {
    match w {
        When::Date(d) => j!(d.format("%Y-%m-%d").to_string()),
        When::At(t) => j!(t.timestamp()),
    }
}

fn when_ts(w: When) -> i64 {
    match w {
        When::Date(d) => d.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp(),
        When::At(t) => t.timestamp(),
    }
}

fn add(w: When, d: chrono::Duration) -> When {
    match w {
        When::Date(x) => When::Date(x + chrono::Duration::days((d.num_seconds() / 86400).max(1))),
        When::At(t) => When::At(t + d),
    }
}

fn ics_stamp(w: When) -> String {
    match w {
        When::Date(d) => d.format("%Y%m%d").to_string(),
        When::At(t) => t.format("%Y%m%dT%H%M%SZ").to_string(),
    }
}

fn mailto(v: &str) -> String {
    let v = v.trim();
    v.strip_prefix("mailto:").or_else(|| v.strip_prefix("MAILTO:")).unwrap_or(v).to_ascii_lowercase()
}

fn people(ev: &[Prop]) -> (Option<Value>, Vec<Value>) {
    let org = get(ev, "ORGANIZER").map(|p| j!({ "email": mailto(&p.value), "name": p.param("CN").unwrap_or("") }));
    let att = ev
        .iter()
        .filter(|p| p.name == "ATTENDEE")
        .map(|p| j!({ "email": mailto(&p.value), "name": p.param("CN").unwrap_or(""), "status": p.param("PARTSTAT").unwrap_or("NEEDS-ACTION").to_ascii_lowercase() }))
        .collect();
    (org, att)
}

/// Occurrences of the events in `data` that overlap [from, to).
fn occurrences(data: &str, from: DateTime<Utc>, to: DateTime<Utc>, floating: chrono_tz::Tz) -> Vec<Value> {
    let evs = vevents(data);
    let mut out = Vec::new();
    // Changed single occurrences (RECURRENCE-ID) replace the generated ones.
    let overrides: Vec<i64> = evs.iter().filter_map(|e| get(e, "RECURRENCE-ID").and_then(|p| parse_when(p, floating)).map(when_ts)).collect();
    for ev in &evs {
        let Some(start) = get(ev, "DTSTART").and_then(|p| parse_when(p, floating)) else { continue };
        let end = get(ev, "DTEND")
            .and_then(|p| parse_when(p, floating))
            .or_else(|| get(ev, "DURATION").and_then(|p| parse_duration(&p.value)).map(|d| add(start, d)))
            .unwrap_or(match start {
                When::Date(d) => When::Date(d + chrono::Duration::days(1)),
                When::At(t) => When::At(t),
            });
        let length = chrono::Duration::seconds((when_ts(end) - when_ts(start)).max(0));
        let rid = get(ev, "RECURRENCE-ID").and_then(|p| parse_when(p, floating)).map(when_ts);
        let rrule = get(ev, "RRULE").map(|p| p.value.clone()).filter(|_| rid.is_none());
        let mut starts: Vec<When> = Vec::new();
        if let Some(rule) = &rrule {
            // Expand with the same zone rules as the event, then drop EXDATEs.
            let dtstart_line = match start {
                When::Date(d) => format!("DTSTART:{}T000000Z", d.format("%Y%m%d")),
                When::At(_) => {
                    let p = get(ev, "DTSTART").unwrap();
                    match p.param("TZID").and_then(zone) {
                        Some(tz) if !p.value.ends_with('Z') => format!("DTSTART;TZID={}:{}", tz.name(), p.value.trim()),
                        _ => format!("DTSTART:{}", ics_stamp(start)),
                    }
                }
            };
            let mut exdates: Vec<i64> = Vec::new();
            for p in ev.iter().filter(|p| p.name == "EXDATE") {
                for v in p.value.split(',') {
                    let q = Prop { name: "EXDATE".into(), params: p.params.clone(), value: v.to_string() };
                    if let Some(w) = parse_when(&q, floating) {
                        exdates.push(when_ts(w));
                    }
                }
            }
            let text = format!("{dtstart_line}\nRRULE:{rule}");
            if let Ok(set) = text.parse::<rrule::RRuleSet>() {
                let lo = from - length - chrono::Duration::days(1);
                let set = set.after(lo.with_timezone(&rrule::Tz::UTC)).before(to.with_timezone(&rrule::Tz::UTC));
                for d in set.all(1000).dates {
                    let w = match start {
                        When::Date(_) => When::Date(d.with_timezone(&Utc).date_naive()),
                        When::At(_) => When::At(d.with_timezone(&Utc)),
                    };
                    let ts = when_ts(w);
                    if !exdates.contains(&ts) && !overrides.contains(&ts) {
                        starts.push(w);
                    }
                }
            }
        } else {
            starts.push(start);
        }
        let (org, att) = people(ev);
        for s in starts {
            let e = add(s, length);
            let (ss, ee) = (when_ts(s), when_ts(e).max(when_ts(s) + 1));
            if ss >= to.timestamp() || ee <= from.timestamp() {
                continue;
            }
            out.push(j!({
                "uid": get(ev, "UID").map(|p| p.value.clone()),
                "title": get(ev, "SUMMARY").map(|p| ical_unesc(&p.value)).unwrap_or_default(),
                "location": get(ev, "LOCATION").map(|p| ical_unesc(&p.value)).unwrap_or_default(),
                "description": get(ev, "DESCRIPTION").map(|p| ical_unesc(&p.value)).unwrap_or_default(),
                "allday": matches!(s, When::Date(_)),
                "start": when_json(s),
                "end": when_json(e),
                "recurring": rrule.is_some() || rid.is_some(),
                "occurrence": when_ts(s),
                "rrule": rrule,
                "organizer": org,
                "attendees": att,
                "status": get(ev, "STATUS").map(|p| p.value.to_ascii_lowercase()),
            }));
        }
    }
    out
}

async fn events(srv: &Shared, user: &User, r: &Req) -> Result<Resp> {
    let q = query(r);
    let from: i64 = q.get("from").and_then(|v| v.parse().ok()).ok_or_else(|| anyhow!("from?"))?;
    let to: i64 = q.get("to").and_then(|v| v.parse().ok()).ok_or_else(|| anyhow!("to?"))?;
    if to <= from || to - from > 400 * 86400 {
        bail!("ask for up to a year at a time");
    }
    let floating = q.get("tz").and_then(|t| zone(t)).unwrap_or(chrono_tz::UTC);
    let uid = user.id;
    let (cals, objs) = srv
        .store
        .call(move |c| {
            let cals = crate::caldav::list_calendars(c, uid)?;
            let mut objs = Vec::new();
            for cal in &cals {
                let mut st = c.prepare_cached(
                    "SELECT name, data FROM calendar_objects WHERE calendar_id = ?1 AND (component IS NULL OR component = 'VEVENT')
                     AND (recurring = 1 OR dtstart IS NULL OR (dtstart < ?3 + 86400 AND (dtend IS NULL OR dtend > ?2 - 86400)))",
                )?;
                for row in st.query_map(params![cal.id, from, to], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
                    let (n, d) = row?;
                    objs.push((cal.slug.clone(), n, d));
                }
            }
            Ok((cals, objs))
        })
        .await?;
    let (f, t) = (Utc.timestamp_opt(from, 0).single().unwrap(), Utc.timestamp_opt(to, 0).single().unwrap());
    let mut list = Vec::new();
    for (slug, name, data) in objs {
        for mut e in occurrences(&data, f, t, floating) {
            e["calendar"] = j!(slug);
            e["id"] = j!(name);
            list.push(e);
        }
    }
    let cal_list: Vec<Value> = cals
        .iter()
        .map(|c| j!({ "slug": c.slug, "name": c.name, "color": c.color.as_deref().map(|x| x.get(..7).unwrap_or(x)), "write": c.write, "owner": c.owner, "is_owner": c.is_owner }))
        .collect();
    ok(j!({ "calendars": cal_list, "events": list }))
}

#[derive(Deserialize)]
struct EventIn {
    calendar: String,
    #[serde(default)]
    id: Option<String>,
    title: String,
    #[serde(default)]
    location: String,
    #[serde(default)]
    description: String,
    allday: bool,
    /// "YYYY-MM-DD" when all day, otherwise "YYYY-MM-DDTHH:MM" in `tz`.
    start: String,
    end: String,
    tz: String,
    /// none | daily | weekly | monthly | yearly | keep
    #[serde(default)]
    repeat: String,
    #[serde(default)]
    attendees: Vec<String>,
}

fn esc(s: &str) -> String {
    crate::migrate::ical::esc(s)
}

fn local_when(v: &str, allday: bool, tz: chrono_tz::Tz) -> Result<When> {
    if allday {
        return Ok(When::Date(NaiveDate::parse_from_str(v.get(..10).unwrap_or(v), "%Y-%m-%d").context("date")?));
    }
    let nd = NaiveDateTime::parse_from_str(v, "%Y-%m-%dT%H:%M").or_else(|_| NaiveDateTime::parse_from_str(v, "%Y-%m-%dT%H:%M:%S")).context("time")?;
    Ok(When::At(tz.from_local_datetime(&nd).earliest().ok_or_else(|| anyhow!("that time doesn't exist (clocks change)"))?.with_timezone(&Utc)))
}

fn when_prop(name: &str, w: When, tz: chrono_tz::Tz, keep_zone: bool) -> String {
    match w {
        When::Date(d) => format!("{name};VALUE=DATE:{}", d.format("%Y%m%d")),
        // Repeating events keep their zone so they stay at the same local time across
        // daylight-saving changes; single ones are stored in UTC, which every app reads.
        When::At(t) if keep_zone && tz != chrono_tz::UTC => format!("{name};TZID={}:{}", tz.name(), t.with_timezone(&tz).format("%Y%m%dT%H%M%S")),
        When::At(t) => format!("{name}:{}", t.format("%Y%m%dT%H%M%SZ")),
    }
}

fn rrule_for(repeat: &str, start: When) -> Option<String> {
    Some(match repeat {
        "daily" => "FREQ=DAILY".into(),
        "weekdays" => "FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR".into(),
        "weekly" => "FREQ=WEEKLY".into(),
        "monthly" => "FREQ=MONTHLY".into(),
        "yearly" => {
            let _ = start.clone();
            "FREQ=YEARLY".into()
        }
        _ => return None,
    })
}

fn fold_join(lines: &[String]) -> String {
    lines.iter().map(|l| crate::migrate::ical::fold(l)).collect::<Vec<_>>().join("\r\n") + "\r\n"
}

/// Store an object under a given resource name (as a CalDAV client would PUT it).
fn put_named(c: &Connection, cal_id: i64, name: &str, data: &str) -> Result<()> {
    let meta = crate::caldav::ics_meta(data)?;
    let etag = format!("\"{}\"", &crate::identity::sha256_hex(data)[..32]);
    c.execute(
        "INSERT INTO calendar_objects(calendar_id, name, etag, data, component, dtstart, dtend, recurring, modified)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(calendar_id, name) DO UPDATE SET etag = ?3, data = ?4, component = ?5, dtstart = ?6, dtend = ?7, recurring = ?8, modified = ?9",
        params![cal_id, name, etag, data, meta.component, meta.dtstart, meta.dtend, meta.recurring as i64, store::now()],
    )?;
    crate::caldav::bump(c, cal_id)
}

async fn save_event(srv: &Shared, user: &User, r: &Req) -> Result<Resp> {
    let e: EventIn = serde_json::from_slice(&r.body)?;
    if e.title.trim().is_empty() {
        bail!("give the event a title");
    }
    let tz = zone(&e.tz).unwrap_or(chrono_tz::UTC);
    let start = local_when(&e.start, e.allday, tz)?;
    let mut end = local_when(&e.end, e.allday, tz)?;
    if e.allday {
        // The form shows the last day; iCalendar's end date is the day after.
        if let When::Date(d) = end {
            end = When::Date(d + chrono::Duration::days(1));
        }
    }
    if when_ts(end) < when_ts(start) {
        bail!("the event ends before it starts");
    }
    let invitees: Vec<String> = e.attendees.iter().map(|a| mailbox_of(a).map(|m| m.email.to_string().to_ascii_lowercase())).collect::<Result<_>>()?;
    let u = user.clone();
    let now = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let (data, new_invitees, removed, title) = srv
        .store
        .call(move |c| {
            let cal = crate::caldav::resolve(c, u.id, &e.calendar)?.filter(|c| c.write).ok_or_else(|| anyhow!("you can't change that calendar"))?;
            let existing = match &e.id {
                Some(id) => Some(crate::caldav::get_object(c, cal.id, id)?.ok_or_else(|| anyhow!("that event is no longer there"))?),
                None => None,
            };
            let old_events = existing.as_ref().map(|o| vevents(&o.data)).unwrap_or_default();
            let master = old_events.iter().find(|ev| get(ev, "RECURRENCE-ID").is_none());
            let old_rrule = master.and_then(|m| get(m, "RRULE")).map(|p| p.value.clone());
            let rrule = if e.repeat == "keep" { old_rrule.clone() } else { rrule_for(&e.repeat, start) };
            let uid = master.and_then(|m| get(m, "UID")).map(|p| p.value.clone()).unwrap_or_else(|| format!("{:x}@{}", rand::random::<u128>(), crate::delivery::domain_of(&u.email)));
            let seq = master.and_then(|m| get(m, "SEQUENCE")).and_then(|p| p.value.trim().parse::<i64>().ok()).map(|s| s + 1).unwrap_or(0);
            let old_att: Vec<String> = master.map(|m| m.iter().filter(|p| p.name == "ATTENDEE").map(|p| mailto(&p.value)).collect()).unwrap_or_default();
            let me = u.email.to_ascii_lowercase();
            let organised_by_other = master.and_then(|m| get(m, "ORGANIZER")).map(|p| mailto(&p.value)).filter(|o| *o != me);
            if organised_by_other.is_some() && !invitees.is_empty() && invitees != old_att {
                bail!("only the organiser can change who's invited");
            }

            let mut ev = vec!["BEGIN:VEVENT".to_string(), format!("UID:{uid}"), format!("DTSTAMP:{now}"), format!("LAST-MODIFIED:{now}"), format!("SEQUENCE:{seq}")];
            ev.push(when_prop("DTSTART", start, tz, rrule.is_some()));
            ev.push(when_prop("DTEND", end, tz, rrule.is_some()));
            ev.push(format!("SUMMARY:{}", esc(e.title.trim())));
            if !e.location.trim().is_empty() {
                ev.push(format!("LOCATION:{}", esc(e.location.trim())));
            }
            if !e.description.trim().is_empty() {
                ev.push(format!("DESCRIPTION:{}", esc(e.description.trim())));
            }
            if let Some(rr) = &rrule {
                ev.push(format!("RRULE:{rr}"));
                // Deleted occurrences stay deleted while the pattern is unchanged.
                if old_rrule.as_deref() == Some(rr.as_str()) {
                    if let Some(m) = master {
                        for p in m.iter().filter(|p| p.name == "EXDATE") {
                            let ps: String = p.params.iter().map(|(k, v)| format!(";{k}={v}")).collect();
                            ev.push(format!("EXDATE{ps}:{}", p.value));
                        }
                    }
                }
            }
            // Keep anything this form doesn't edit (alarms are separate components and
            // are not carried over; categories, colour, conference links are).
            if let Some(m) = master {
                for p in m {
                    if ["CATEGORIES", "COLOR", "CLASS", "TRANSP", "URL", "X-MICROSOFT-SKYPETEAMSMEETINGURL", "CONFERENCE", "PRIORITY"].contains(&p.name.as_str()) {
                        let ps: String = p.params.iter().map(|(k, v)| format!(";{k}={v}")).collect();
                        ev.push(format!("{}{ps}:{}", p.name, p.value));
                    }
                }
            }
            let (new_inv, removed) = if let Some(org) = &organised_by_other {
                // Someone else's meeting: keep their organiser and guest list as they are.
                if let Some(m) = master {
                    for p in m.iter().filter(|p| p.name == "ORGANIZER" || p.name == "ATTENDEE") {
                        let ps: String = p.params.iter().map(|(k, v)| format!(";{k}=\"{v}\"")).collect();
                        ev.push(format!("{}{ps}:{}", p.name, p.value));
                    }
                }
                let _ = org;
                (vec![], vec![])
            } else if !invitees.is_empty() {
                let name = store::display_name(c, u.id)?.unwrap_or_default();
                let cn = if name.is_empty() { String::new() } else { format!(";CN=\"{}\"", name.replace('"', "")) };
                ev.push(format!("ORGANIZER{cn}:mailto:{me}"));
                ev.push(format!("ATTENDEE{cn};ROLE=CHAIR;PARTSTAT=ACCEPTED:mailto:{me}"));
                for a in &invitees {
                    // Keep each guest's answer if they've already replied.
                    let status = master
                        .and_then(|m| m.iter().find(|p| p.name == "ATTENDEE" && mailto(&p.value) == *a))
                        .and_then(|p| p.param("PARTSTAT").map(String::from))
                        .unwrap_or_else(|| "NEEDS-ACTION".into());
                    if a != &me {
                        ev.push(format!("ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT={status};RSVP=TRUE:mailto:{a}"));
                    }
                }
                let removed: Vec<String> = old_att.iter().filter(|a| !invitees.contains(a) && **a != me).cloned().collect();
                (invitees.iter().filter(|a| **a != me).cloned().collect(), removed)
            } else {
                (vec![], old_att.into_iter().filter(|a| *a != me).collect())
            };
            ev.push("END:VEVENT".into());

            let mut lines = vec!["BEGIN:VCALENDAR".to_string(), "VERSION:2.0".into(), "PRODID:-//Postwright//Webmail//EN".into(), "CALSCALE:GREGORIAN".into()];
            lines.extend(ev);
            // Changed single occurrences survive edits that keep the pattern.
            if rrule.is_some() && old_rrule == rrule {
                if let Some(o) = &existing {
                    for x in old_events.iter().filter(|x| get(x, "RECURRENCE-ID").is_some()) {
                        lines.push("BEGIN:VEVENT".into());
                        for p in x {
                            let ps: String = p.params.iter().map(|(k, v)| format!(";{k}={v}")).collect();
                            lines.push(format!("{}{ps}:{}", p.name, p.value));
                        }
                        lines.push("END:VEVENT".into());
                    }
                    let _ = o;
                }
            }
            lines.push("END:VCALENDAR".into());
            let data = fold_join(&lines);
            let name = e.id.clone().unwrap_or_else(|| format!("{}.ics", uid.chars().filter(|c| c.is_ascii_alphanumeric() || "-_.".contains(*c)).take(100).collect::<String>()));
            put_named(c, cal.id, &name, &data)?;
            Ok((data, new_inv, removed, e.title.trim().to_string()))
        })
        .await?;
    srv.notify_user(user.id);
    // Invitations (or updates) to guests, and a cancellation to anyone taken off.
    if !new_invitees.is_empty() {
        let body = invite_text(&data, &title);
        let mut c = Compose { from: user.email.clone(), to: new_invitees, subject: format!("Invitation: {title}"), text: body, ..Default::default() };
        c.ics = Some(("REQUEST".into(), data.replace("VERSION:2.0\r\n", "VERSION:2.0\r\nMETHOD:REQUEST\r\n")));
        submit(srv, user, c, false).await?;
    }
    if !removed.is_empty() {
        let cancel = data.replace("VERSION:2.0\r\n", "VERSION:2.0\r\nMETHOD:CANCEL\r\n").replace("SEQUENCE:", "STATUS:CANCELLED\r\nSEQUENCE:");
        let mut c = Compose { from: user.email.clone(), to: removed, subject: format!("Cancelled: {title}"), text: format!("{title} has been cancelled.\n"), ..Default::default() };
        c.ics = Some(("CANCEL".into(), cancel));
        submit(srv, user, c, false).await?;
    }
    ok(j!({ "ok": true }))
}

fn invite_text(ics: &str, title: &str) -> String {
    let evs = vevents(ics);
    let Some(ev) = evs.first() else { return title.to_string() };
    let start = get(ev, "DTSTART").and_then(|p| parse_when(p, chrono_tz::UTC));
    let when = match start {
        Some(When::Date(d)) => d.format("%A %e %B %Y (all day)").to_string(),
        Some(When::At(t)) => t.format("%A %e %B %Y, %H:%M UTC").to_string(),
        None => String::new(),
    };
    let loc = get(ev, "LOCATION").map(|p| format!("\nWhere: {}", ical_unesc(&p.value))).unwrap_or_default();
    let desc = get(ev, "DESCRIPTION").map(|p| format!("\n\n{}", ical_unesc(&p.value))).unwrap_or_default();
    format!("{title}\nWhen: {when}{loc}{desc}\n")
}

async fn delete_event(srv: &Shared, user: &User, r: &Req) -> Result<Resp> {
    let q = query(r);
    let (cal, id) = (q.get("calendar").cloned().unwrap_or_default(), q.get("id").cloned().unwrap_or_default());
    let occurrence: Option<i64> = q.get("occurrence").and_then(|v| v.parse().ok());
    let u = user.clone();
    let me = user.email.to_ascii_lowercase();
    let cancel = srv
        .store
        .call(move |c| {
            let cal = crate::caldav::resolve(c, u.id, &cal)?.filter(|c| c.write).ok_or_else(|| anyhow!("you can't change that calendar"))?;
            let obj = crate::caldav::get_object(c, cal.id, &id)?.ok_or_else(|| anyhow!("that event is no longer there"))?;
            let evs = vevents(&obj.data);
            let master = evs.iter().find(|e| get(e, "RECURRENCE-ID").is_none());
            let organiser = master.and_then(|m| get(m, "ORGANIZER")).map(|p| mailto(&p.value));
            let guests: Vec<String> = master.map(|m| m.iter().filter(|p| p.name == "ATTENDEE").map(|p| mailto(&p.value)).filter(|a| *a != me).collect()).unwrap_or_default();
            if let (Some(ts), Some(m)) = (occurrence, master.filter(|m| get(m, "RRULE").is_some())) {
                // Just this one: add an EXDATE in the series' own form.
                let p = get(m, "DTSTART").unwrap();
                let w = Utc.timestamp_opt(ts, 0).single().unwrap();
                let ex = if p.param("VALUE").map(|v| v.eq_ignore_ascii_case("DATE")).unwrap_or(false) || p.value.len() == 8 {
                    format!("EXDATE;VALUE=DATE:{}", w.format("%Y%m%d"))
                } else if let (Some(tz), false) = (p.param("TZID").and_then(zone), p.value.ends_with('Z')) {
                    format!("EXDATE;TZID={}:{}", tz.name(), w.with_timezone(&tz).format("%Y%m%dT%H%M%S"))
                } else {
                    format!("EXDATE:{}", w.format("%Y%m%dT%H%M%SZ"))
                };
                let mut out = Vec::new();
                let mut in_master = false;
                let mut done = false;
                for l in unfold(&obj.data) {
                    let up = l.to_ascii_uppercase();
                    if up == "BEGIN:VEVENT" {
                        in_master = true;
                    }
                    if in_master && up.starts_with("RECURRENCE-ID") {
                        in_master = false;
                    }
                    if in_master && !done && up == "END:VEVENT" {
                        out.push(ex.clone());
                        done = true;
                    }
                    out.push(l);
                }
                put_named(c, cal.id, &id, &fold_join(&out))?;
                return Ok(None);
            }
            c.execute("DELETE FROM calendar_objects WHERE calendar_id = ?1 AND name = ?2", params![cal.id, id])?;
            crate::caldav::bump(c, cal.id)?;
            // Tell the guests if this was my meeting.
            if organiser.as_deref() == Some(me.as_str()) && !guests.is_empty() {
                let title = master.and_then(|m| get(m, "SUMMARY")).map(|p| ical_unesc(&p.value)).unwrap_or_default();
                let data = obj.data.replace("VERSION:2.0\r\n", "VERSION:2.0\r\nMETHOD:CANCEL\r\n").replace("SEQUENCE:", "STATUS:CANCELLED\r\nSEQUENCE:");
                return Ok(Some((guests, title, data)));
            }
            Ok(None)
        })
        .await?;
    srv.notify_user(user.id);
    if let Some((guests, title, data)) = cancel {
        let mut c = Compose { from: user.email.clone(), to: guests, subject: format!("Cancelled: {title}"), text: format!("{title} has been cancelled.\n"), ..Default::default() };
        c.ics = Some(("CANCEL".into(), data));
        submit(srv, user, c, false).await?;
    }
    ok(j!({ "ok": true }))
}

// --------------------------------------------------------------- invitations

fn invite_summary(ics: &str, me: &str) -> Option<Value> {
    let method = unfold(ics).into_iter().find(|l| l.to_ascii_uppercase().starts_with("METHOD:")).map(|l| l[7..].trim().to_ascii_uppercase()).unwrap_or_default();
    let evs = vevents(ics);
    let ev = evs.first()?;
    let start = get(ev, "DTSTART").and_then(|p| parse_when(p, chrono_tz::UTC))?;
    let end = get(ev, "DTEND").and_then(|p| parse_when(p, chrono_tz::UTC)).unwrap_or(start);
    let (org, att) = people(ev);
    let mine = att.iter().find(|a| a["email"] == me.to_ascii_lowercase()).map(|a| a["status"].clone());
    Some(j!({
        "method": method,
        "uid": get(ev, "UID").map(|p| p.value.clone()),
        "title": get(ev, "SUMMARY").map(|p| ical_unesc(&p.value)).unwrap_or_default(),
        "location": get(ev, "LOCATION").map(|p| ical_unesc(&p.value)).unwrap_or_default(),
        "start": when_json(start),
        "end": when_json(end),
        "allday": matches!(start, When::Date(_)),
        "recurring": get(ev, "RRULE").is_some(),
        "organizer": org,
        "attendees": att,
        "my_status": mine,
    }))
}

fn calendar_part(m: &mail_parser::Message) -> Option<String> {
    m.parts
        .iter()
        .find(|p| {
            p.content_type().map(|c| c.ctype().eq_ignore_ascii_case("text") && c.subtype().map(|s| s.eq_ignore_ascii_case("calendar")).unwrap_or(false)).unwrap_or(false)
                || p.attachment_name().map(|n| n.to_ascii_lowercase().ends_with(".ics")).unwrap_or(false)
        })
        .and_then(|p| std::str::from_utf8(p.contents()).ok().map(String::from))
}

/// Record each answering guest's PARTSTAT on the organiser's own copy of the event.
async fn apply_reply(srv: &Shared, user: &User, ics: &str) -> Result<()> {
    let evs = vevents(ics);
    let ev = evs.first().ok_or_else(|| anyhow!("empty reply"))?;
    let uid_val = get(ev, "UID").map(|p| p.value.clone()).ok_or_else(|| anyhow!("no UID"))?;
    let answers: Vec<(String, String)> = ev.iter().filter(|p| p.name == "ATTENDEE").map(|p| (mailto(&p.value), p.param("PARTSTAT").unwrap_or("NEEDS-ACTION").to_ascii_uppercase())).collect();
    let me = user.email.to_ascii_lowercase();
    let uid = user.id;
    let changed = srv
        .store
        .call(move |c| {
            for cal in crate::caldav::list_calendars(c, uid)?.into_iter().filter(|c| c.is_owner) {
                for o in crate::caldav::list_objects(c, cal.id)? {
                    let evs = vevents(&o.data);
                    let Some(master) = evs.iter().find(|e| get(e, "UID").map(|p| p.value == uid_val).unwrap_or(false) && get(e, "RECURRENCE-ID").is_none()) else { continue };
                    if get(master, "ORGANIZER").map(|p| mailto(&p.value)) != Some(me.clone()) {
                        return Ok(false);
                    }
                    let mut out = Vec::new();
                    let mut changed = false;
                    for l in unfold(&o.data) {
                        if l.to_ascii_uppercase().starts_with("ATTENDEE") {
                            if let Some(p) = parse_prop(&l) {
                                if let Some((_, st)) = answers.iter().find(|(a, _)| *a == mailto(&p.value)) {
                                    if p.param("PARTSTAT").map(|x| x.to_ascii_uppercase()) != Some(st.clone()) {
                                        let ps: String = p.params.iter().filter(|(k, _)| k != "PARTSTAT").map(|(k, v)| format!(";{k}={v}")).collect();
                                        out.push(format!("ATTENDEE{ps};PARTSTAT={st}:{}", p.value));
                                        changed = true;
                                        continue;
                                    }
                                }
                            }
                        }
                        out.push(l);
                    }
                    if changed {
                        put_named(c, cal.id, &o.name, &fold_join(&out))?;
                    }
                    return Ok(changed);
                }
            }
            Ok(false)
        })
        .await?;
    if changed {
        srv.notify_user(uid);
    }
    Ok(())
}

#[derive(Deserialize)]
struct InviteAnswer {
    folder: String,
    uid: u32,
    /// accepted | tentative | declined | remove (for cancellations)
    response: String,
}

async fn invite(srv: &Shared, user: &User, r: &Req) -> Result<Resp> {
    let a: InviteAnswer = serde_json::from_slice(&r.body)?;
    let (_, _, data) = load(srv, user.id, &a.folder, a.uid).await?;
    let m = MessageParser::default().parse(&data).ok_or_else(|| anyhow!("this message couldn't be read"))?;
    let ics = m
        .parts
        .iter()
        .find(|p| p.content_type().map(|c| c.ctype().eq_ignore_ascii_case("text") && c.subtype().map(|s| s.eq_ignore_ascii_case("calendar")).unwrap_or(false)).unwrap_or(false)
            || p.attachment_name().map(|n| n.to_ascii_lowercase().ends_with(".ics")).unwrap_or(false))
        .and_then(|p| std::str::from_utf8(p.contents()).ok().map(String::from))
        .ok_or_else(|| anyhow!("there's no invitation in this message"))?;
    let me = user.email.to_ascii_lowercase();
    let evs = vevents(&ics);
    let ev = evs.first().ok_or_else(|| anyhow!("the invitation is empty"))?.clone();
    let uid_val = get(&ev, "UID").map(|p| p.value.clone()).ok_or_else(|| anyhow!("the invitation has no UID"))?;
    let organiser = get(&ev, "ORGANIZER").map(|p| mailto(&p.value));
    let title = get(&ev, "SUMMARY").map(|p| ical_unesc(&p.value)).unwrap_or_default();
    let partstat = match a.response.as_str() {
        "accepted" => "ACCEPTED",
        "tentative" => "TENTATIVE",
        "declined" => "DECLINED",
        "remove" => "",
        _ => bail!("answer accepted, tentative or declined"),
    };

    // The calendar copy: without METHOD, with my answer.
    let mut lines: Vec<String> = Vec::new();
    for l in unfold(&ics) {
        let up = l.to_ascii_uppercase();
        if up.starts_with("METHOD:") {
            continue;
        }
        if up.starts_with("ATTENDEE") && !partstat.is_empty() {
            if let Some(p) = parse_prop(&l) {
                if mailto(&p.value) == me {
                    let ps: String = p.params.iter().filter(|(k, _)| k != "PARTSTAT" && k != "RSVP").map(|(k, v)| format!(";{k}=\"{v}\"")).collect();
                    lines.push(format!("ATTENDEE{ps};PARTSTAT={partstat}:mailto:{me}"));
                    continue;
                }
            }
        }
        lines.push(l);
    }
    let stored = fold_join(&lines);
    let uid = user.id;
    let uid2 = uid_val.clone();
    let remove = partstat.is_empty() || partstat == "DECLINED";
    srv.store
        .call(move |c| {
            // Find the event wherever it already is, else use the default calendar.
            let cals = crate::caldav::list_calendars(c, uid)?;
            let mut found: Option<(i64, String)> = None;
            for cal in cals.iter().filter(|c| c.is_owner) {
                for o in crate::caldav::list_objects(c, cal.id)? {
                    if vevents(&o.data).iter().any(|e| get(e, "UID").map(|p| p.value == uid2).unwrap_or(false)) {
                        found = Some((cal.id, o.name));
                        break;
                    }
                }
                if found.is_some() {
                    break;
                }
            }
            if remove {
                if let Some((cal, name)) = found {
                    c.execute("DELETE FROM calendar_objects WHERE calendar_id = ?1 AND name = ?2", params![cal, name])?;
                    crate::caldav::bump(c, cal)?;
                }
            } else {
                match found {
                    Some((cal, name)) => put_named(c, cal, &name, &stored)?,
                    None => {
                        let cal = crate::caldav::calendar_named(c, uid, "Calendar")?;
                        crate::caldav::import_object(c, cal, &stored)?;
                    }
                }
            }
            Ok(())
        })
        .await?;
    srv.notify_user(uid);

    // Tell the organiser (not for cancellations).
    if let (Some(org), false) = (organiser, partstat.is_empty()) {
        if org != me {
            let now = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
            let mut rep = vec!["BEGIN:VCALENDAR".to_string(), "VERSION:2.0".into(), "PRODID:-//Postwright//Webmail//EN".into(), "METHOD:REPLY".into(), "BEGIN:VEVENT".into()];
            for p in &ev {
                if ["UID", "DTSTART", "DTEND", "SUMMARY", "ORGANIZER", "SEQUENCE", "RECURRENCE-ID"].contains(&p.name.as_str()) {
                    let ps: String = p.params.iter().map(|(k, v)| format!(";{k}=\"{v}\"")).collect();
                    rep.push(format!("{}{ps}:{}", p.name, p.value));
                }
            }
            rep.push(format!("ATTENDEE;PARTSTAT={partstat}:mailto:{me}"));
            rep.push(format!("DTSTAMP:{now}"));
            rep.push("END:VEVENT".into());
            rep.push("END:VCALENDAR".into());
            let word = match partstat {
                "ACCEPTED" => "Accepted",
                "TENTATIVE" => "Tentative",
                _ => "Declined",
            };
            let mut c = Compose { from: user.email.clone(), to: vec![org], subject: format!("{word}: {title}"), text: format!("{} has {} {title}.\n", user.email, word.to_lowercase()), ..Default::default() };
            c.ics = Some(("REPLY".into(), fold_join(&rep)));
            submit(srv, user, c, false).await?;
        }
    }
    // Answered invitations are marked as such.
    let folder = a.folder.clone();
    let muid = a.uid;
    srv.store
        .call(move |c| {
            let mb = mailbox(c, uid, &folder)?;
            if let Some(m) = store::list_messages(c, mb.id)?.into_iter().find(|m| m.uid == muid) {
                let mut f = m.flags.clone();
                if !f.iter().any(|x| x == "\\Answered") {
                    f.push("\\Answered".into());
                    store::set_flags(c, m.id, &f)?;
                }
            }
            Ok(())
        })
        .await?;
    ok(j!({ "ok": true }))
}

#[allow(dead_code)]
fn _unused(d: NaiveDate) -> u32 {
    d.day()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_weekly_with_exdate_and_override() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:a\r\nSUMMARY:Standup\r\nDTSTART;TZID=Europe/London:20261005T090000\r\nDTEND;TZID=Europe/London:20261005T091500\r\nRRULE:FREQ=WEEKLY\r\nEXDATE;TZID=Europe/London:20261012T090000\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:a\r\nRECURRENCE-ID;TZID=Europe/London:20261019T090000\r\nDTSTART;TZID=Europe/London:20261019T100000\r\nDTEND;TZID=Europe/London:20261019T101500\r\nSUMMARY:Standup (late)\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let from = Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap();
        let to = Utc.with_ymd_and_hms(2026, 11, 3, 0, 0, 0).unwrap();
        let occ = occurrences(ics, from, to, chrono_tz::UTC);
        let starts: Vec<i64> = occ.iter().map(|e| e["start"].as_i64().unwrap()).collect();
        // 5 Oct (BST, 08:00Z), 12 Oct skipped, 19 Oct moved to 10:00 BST, 26 Oct and 2 Nov at 09:00 GMT.
        assert!(starts.contains(&Utc.with_ymd_and_hms(2026, 10, 5, 8, 0, 0).unwrap().timestamp()));
        assert!(!starts.contains(&Utc.with_ymd_and_hms(2026, 10, 12, 8, 0, 0).unwrap().timestamp()));
        assert!(!starts.contains(&Utc.with_ymd_and_hms(2026, 10, 19, 8, 0, 0).unwrap().timestamp()));
        assert!(starts.contains(&Utc.with_ymd_and_hms(2026, 10, 19, 9, 0, 0).unwrap().timestamp()));
        assert!(starts.contains(&Utc.with_ymd_and_hms(2026, 10, 26, 9, 0, 0).unwrap().timestamp()));
        assert!(starts.contains(&Utc.with_ymd_and_hms(2026, 11, 2, 9, 0, 0).unwrap().timestamp()));
        assert_eq!(occ.len(), 4);
    }

    #[test]
    fn all_day_and_duration() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:b\r\nSUMMARY:Holiday\r\nDTSTART;VALUE=DATE:20261224\r\nDTEND;VALUE=DATE:20261227\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:c\r\nSUMMARY:Call\r\nDTSTART:20261224T100000Z\r\nDURATION:PT1H30M\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let from = Utc.with_ymd_and_hms(2026, 12, 1, 0, 0, 0).unwrap();
        let to = Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap();
        let occ = occurrences(ics, from, to, chrono_tz::UTC);
        let hol = occ.iter().find(|e| e["title"] == "Holiday").unwrap();
        assert_eq!(hol["start"], "2026-12-24");
        assert_eq!(hol["end"], "2026-12-27");
        let call = occ.iter().find(|e| e["title"] == "Call").unwrap();
        assert_eq!(call["end"].as_i64().unwrap() - call["start"].as_i64().unwrap(), 5400);
    }

    #[test]
    fn quoted_params() {
        let p = parse_prop("ATTENDEE;CN=\"Smith: John\";PARTSTAT=ACCEPTED:mailto:j@x.org").unwrap();
        assert_eq!(p.param("CN"), Some("Smith: John"));
        assert_eq!(p.value, "mailto:j@x.org");
    }
}
