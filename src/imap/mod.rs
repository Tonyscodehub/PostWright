//! IMAP4rev1 server with IDLE, MOVE, UIDPLUS, SPECIAL-USE, LITERAL+, SASL-IR, NAMESPACE,
//! UNSELECT, ENABLE and ID. Login is refused until the connection is encrypted.

pub mod mime;
pub mod parse;
pub mod search;

use crate::auth;
use crate::net::{Conn, Stream};
use crate::server::Shared;
use crate::store::{self, Mailbox, MsgMeta, User};
use anyhow::{anyhow, bail, Result};
use chrono::{DateTime, TimeZone, Utc};
use parse::{compact, q, FetchAtt, SeqSet, Tok};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;

const SYSTEM_FLAGS: &[&str] = &["\\Answered", "\\Flagged", "\\Deleted", "\\Seen", "\\Draft"];

struct Selected {
    mb: Mailbox,
    ro: bool,
    msgs: Vec<MsgMeta>,
    /// Whose mailbox this is (differs from the signed-in user for delegated mailboxes).
    owner: i64,
}

/// Where other people's mailboxes appear for users who've been given access.
pub const SHARED_PREFIX: &str = "Other Users/";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Access {
    Own,
    Read,
    Full,
}

/// A mailbox name resolved for the signed-in user: one of their own, or one in a mailbox
/// that has been delegated to them ("Other Users/<owner>/<folder>").
struct Target {
    mb: Mailbox,
    owner: User,
    access: Access,
    /// The name as this user sees it.
    display: String,
}

fn is_shared_name(name: &str) -> bool {
    name.get(..SHARED_PREFIX.len()).map(|p| p.eq_ignore_ascii_case(SHARED_PREFIX)).unwrap_or(false) || name.eq_ignore_ascii_case("Other Users")
}

fn resolve(c: &rusqlite::Connection, user: &User, name: &str) -> Result<Option<Target>> {
    if name.eq_ignore_ascii_case("Other Users") {
        return Ok(None);
    }
    if !is_shared_name(name) {
        return Ok(store::find_mailbox(c, user.id, name)?.map(|mb| Target {
            display: mb.name.clone(),
            mb,
            owner: user.clone(),
            access: Access::Own,
        }));
    }
    let rest = &name[SHARED_PREFIX.len()..];
    let Some((email, folder)) = rest.split_once('/') else { return Ok(None) };
    if folder.is_empty() {
        return Ok(None);
    }
    let Some(d) = crate::identity::granted_to(c, user.id)?.into_iter().find(|d| d.owner.eq_ignore_ascii_case(email)) else {
        return Ok(None);
    };
    let access = match d.mailbox {
        crate::identity::MailboxRight::Full => Access::Full,
        crate::identity::MailboxRight::Read => Access::Read,
        crate::identity::MailboxRight::None => return Ok(None),
    };
    let Some(owner) = store::user_by_id(c, d.owner_id)? else { return Ok(None) };
    let Some(mb) = store::find_mailbox(c, owner.id, folder)? else { return Ok(None) };
    let display = format!("{SHARED_PREFIX}{}/{}", owner.email, mb.name);
    Ok(Some(Target { mb, owner, access, display }))
}

struct Session {
    srv: Shared,
    conn: Conn,
    peer: SocketAddr,
    user: Option<User>,
    sel: Option<Selected>,
    changes: broadcast::Receiver<i64>,
}

enum Flow {
    Continue,
    Logout,
    /// The handler already sent its tagged response.
    Replied,
}

/// Command failure that maps to a tagged NO/BAD.
struct Reply(String);

fn no(msg: impl Into<String>) -> anyhow::Error {
    anyhow!(Reply(format!("NO {}", msg.into())))
}
fn bad(msg: impl Into<String>) -> anyhow::Error {
    anyhow!(Reply(format!("BAD {}", msg.into())))
}
impl std::fmt::Display for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::fmt::Debug for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Reply {}

pub async fn handle(srv: Shared, stream: Stream, peer: SocketAddr) -> Result<()> {
    let timeout = Duration::from_secs(srv.cfg.limits.imap_timeout_secs);
    let changes = srv.changes.subscribe();
    let mut s = Session { conn: Conn::new(stream, timeout), srv, peer, user: None, sel: None, changes };
    if s.srv.guard.is_blocked(peer.ip()) {
        s.conn.send("* BYE Too many failed logins, try later").await?;
        return Ok(());
    }
    let greet = format!("* OK [CAPABILITY {}] Postwright IMAP ready", s.capabilities());
    s.conn.send(&greet).await?;
    s.run().await
}

fn literal_suffix(line: &[u8]) -> Option<(usize, bool)> {
    if !line.ends_with(b"}") {
        return None;
    }
    let open = line.iter().rposition(|&b| b == b'{')?;
    let inner = std::str::from_utf8(&line[open + 1..line.len() - 1]).ok()?;
    let (num, plus) = match inner.strip_suffix('+') {
        Some(n) => (n, true),
        None => (inner, false),
    };
    Some((num.parse().ok()?, plus))
}

pub fn fmt_internal_date(ts: i64) -> String {
    Utc.timestamp_opt(ts, 0).single().unwrap_or_default().format("%d-%b-%Y %H:%M:%S +0000").to_string()
}

fn canonical_flag(f: &str) -> Option<String> {
    if let Some(sys) = SYSTEM_FLAGS.iter().find(|s| s.eq_ignore_ascii_case(f)) {
        return Some(sys.to_string());
    }
    if f.starts_with('\\') || f.is_empty() || f.chars().any(|c| c.is_control() || " (){%*\"\\]".contains(c)) {
        return None; // \Recent and unknown system flags can't be set by clients
    }
    Some(f.to_string())
}

fn flags_list(flags: &[String]) -> String {
    format!("({})", flags.join(" "))
}

fn pattern_match(pat: &[char], name: &[char]) -> bool {
    match pat.first() {
        None => name.is_empty(),
        Some('*') => (0..=name.len()).any(|i| pattern_match(&pat[1..], &name[i..])),
        Some('%') => (0..=name.len())
            .take_while(|&i| i == 0 || name[i - 1] != '/')
            .any(|i| pattern_match(&pat[1..], &name[i..])),
        Some(c) => !name.is_empty() && name[0] == *c && pattern_match(&pat[1..], &name[1..]),
    }
}

impl Session {
    fn capabilities(&self) -> String {
        let mut c = String::from(
            "IMAP4rev1 LITERAL+ SASL-IR ID IDLE NAMESPACE UNSELECT MOVE UIDPLUS SPECIAL-USE ENABLE CHILDREN LIST-EXTENDED",
        );
        if !self.conn.stream.is_tls() {
            c.push_str(" STARTTLS LOGINDISABLED");
        } else if self.user.is_none() {
            c.push_str(" AUTH=PLAIN AUTH=OAUTHBEARER AUTH=XOAUTH2");
        }
        c
    }

    fn user(&self) -> Result<&User> {
        self.user.as_ref().ok_or_else(|| bad("Not authenticated"))
    }

    fn sel(&mut self) -> Result<&mut Selected> {
        self.sel.as_mut().ok_or_else(|| bad("No mailbox selected"))
    }

    async fn read_command(&mut self) -> Result<Option<Vec<u8>>> {
        let mut buf = Vec::new();
        loop {
            let line = self.conn.read_line().await?;
            buf.extend_from_slice(&line);
            if let Some((n, plus)) = literal_suffix(&line) {
                let limit = if self.user.is_some() { self.srv.cfg.limits.max_message_size + 65536 } else { 8192 };
                if n > limit {
                    if plus {
                        self.conn.send("* BYE Literal too large").await?;
                        bail!("oversized non-synchronising literal");
                    }
                    let tag = String::from_utf8_lossy(buf.split(|&b| b == b' ').next().unwrap_or(b"*")).to_string();
                    self.conn.send(&format!("{tag} NO [TOOBIG] Literal too large")).await?;
                    return Ok(None);
                }
                if !plus {
                    self.conn.send("+ Ready for literal data").await?;
                }
                buf.extend_from_slice(b"\r\n");
                let data = self.conn.read_exact_bytes(n).await?;
                buf.extend_from_slice(&data);
                continue;
            }
            return Ok(Some(buf));
        }
    }

    async fn run(&mut self) -> Result<()> {
        loop {
            let Some(raw) = self.read_command().await? else { continue };
            let toks = match parse::tokenize(&raw) {
                Ok(t) => t,
                Err(e) => {
                    let tag = String::from_utf8_lossy(raw.split(|&b| b == b' ').next().unwrap_or(b"*")).to_string();
                    self.conn.send(&format!("{tag} BAD {e}")).await?;
                    continue;
                }
            };
            let (Some(Tok::Atom(tag)), Some(cmd)) = (toks.first(), toks.get(1).and_then(|t| t.atom_upper())) else {
                self.conn.send("* BAD Missing tag or command").await?;
                continue;
            };
            let tag = tag.clone();
            let args = toks[2..].to_vec();
            let (cmd, args, uid) = if cmd == "UID" {
                let sub = args.first().and_then(|t| t.atom_upper()).unwrap_or_default();
                (sub, args[1.min(args.len())..].to_vec(), true)
            } else {
                (cmd, args, false)
            };
            match self.dispatch(&tag, &cmd, &args, uid).await {
                Ok((text, Flow::Continue)) => {
                    if self.sel.is_some() && !matches!(cmd.as_str(), "SELECT" | "EXAMINE" | "CLOSE" | "UNSELECT" | "LOGOUT") {
                        let allow_expunge = !matches!(cmd.as_str(), "FETCH" | "STORE" | "SEARCH");
                        let lines = self.refresh(allow_expunge).await?;
                        for l in lines {
                            self.conn.send(&l).await?;
                        }
                    }
                    self.conn.send(&format!("{tag} {text}")).await?;
                }
                Ok((_, Flow::Replied)) => {}
                Ok((text, Flow::Logout)) => {
                    self.conn.send(&format!("{tag} {text}")).await?;
                    return Ok(());
                }
                Err(e) => match e.downcast_ref::<Reply>() {
                    Some(r) => self.conn.send(&format!("{tag} {r}")).await?,
                    None => {
                        tracing::error!("IMAP {cmd} error: {e:#}");
                        self.conn.send(&format!("{tag} NO [SERVERBUG] Internal error")).await?;
                    }
                },
            }
        }
    }

    async fn dispatch(&mut self, tag: &str, cmd: &str, args: &[Tok], uid: bool) -> Result<(String, Flow)> {
        let ok = |s: &str| Ok((format!("OK {s}"), Flow::Continue));
        match cmd {
            "CAPABILITY" => {
                let c = format!("* CAPABILITY {}", self.capabilities());
                self.conn.send(&c).await?;
                ok("CAPABILITY completed")
            }
            "NOOP" | "CHECK" => ok(&format!("{cmd} completed")),
            "LOGOUT" => {
                self.conn.send("* BYE Postwright logging out").await?;
                Ok(("OK LOGOUT completed".into(), Flow::Logout))
            }
            "ID" => {
                self.conn.send(concat!("* ID (\"name\" \"Postwright\" \"version\" \"", env!("CARGO_PKG_VERSION"), "\")")).await?;
                ok("ID completed")
            }
            "STARTTLS" => {
                if self.conn.stream.is_tls() {
                    return Err(bad("TLS already active"));
                }
                if self.conn.has_buffered() {
                    return Err(bad("Pipelining not allowed with STARTTLS"));
                }
                self.conn.send(&format!("{tag} OK Begin TLS negotiation now")).await?;
                let acc = self.srv.tls();
                self.conn.upgrade(&acc).await?;
                // The tagged reply has already been sent before the handshake.
                Ok((String::new(), Flow::Replied))
            }
            "LOGIN" => {
                let u = args.first().and_then(|t| t.as_str()).ok_or_else(|| bad("Missing username"))?;
                let p = args.get(1).and_then(|t| t.as_str()).ok_or_else(|| bad("Missing password"))?;
                self.login(&u, &p).await
            }
            "AUTHENTICATE" => {
                let mech = args.first().and_then(|t| t.atom_upper()).ok_or_else(|| bad("Missing mechanism"))?;
                if !matches!(mech.as_str(), "PLAIN" | "OAUTHBEARER" | "XOAUTH2") {
                    return Err(no("Unsupported authentication mechanism"));
                }
                if !self.conn.stream.is_tls() {
                    return Err(no("[PRIVACYREQUIRED] Use STARTTLS first"));
                }
                if self.user.is_some() {
                    return Err(bad("Already authenticated"));
                }
                let resp = match args.get(1).and_then(|t| t.as_str()) {
                    Some(r) if r != "=" => r,
                    _ => {
                        self.conn.send("+ ").await?;
                        String::from_utf8_lossy(&self.conn.read_line().await?).to_string()
                    }
                };
                if resp.trim() == "*" {
                    return Err(bad("Authentication cancelled"));
                }
                if mech != "PLAIN" {
                    return self.login_token(&resp).await;
                }
                match auth::decode_plain(&resp) {
                    Some((u, p)) => self.login(&u, &p).await,
                    None => Err(bad("Malformed SASL response")),
                }
            }
            "ENABLE" => {
                self.user()?;
                self.conn.send("* ENABLED").await?;
                ok("ENABLE completed")
            }
            "NAMESPACE" => {
                self.user()?;
                self.conn.send("* NAMESPACE ((\"\" \"/\")) ((\"Other Users/\" \"/\")) NIL").await?;
                ok("NAMESPACE completed")
            }
            "SELECT" | "EXAMINE" => self.select(args, cmd == "EXAMINE").await,
            "CREATE" => {
                let uid_ = self.user()?.id;
                let name = mailbox_arg(args)?;
                if is_shared_name(&name) {
                    return Err(no("[NOPERM] Only the mailbox owner can create folders there"));
                }
                let n2 = name.clone();
                let exists = self.srv.store.call(move |c| store::find_mailbox(c, uid_, &n2)).await?.is_some();
                if exists {
                    return Err(no("[ALREADYEXISTS] Mailbox already exists"));
                }
                self.srv.store.call(move |c| store::create_mailbox(c, uid_, &name)).await.map_err(|e| no(e.to_string()))?;
                ok("CREATE completed")
            }
            "DELETE" => {
                let uid_ = self.user()?.id;
                let name = mailbox_arg(args)?;
                if is_shared_name(&name) {
                    return Err(no("[NOPERM] Only the mailbox owner can delete folders there"));
                }
                if self.sel.as_ref().map(|s| s.mb.name == store::normalise_mailbox(&name)).unwrap_or(false) {
                    self.sel = None;
                }
                self.srv.store.call(move |c| store::delete_mailbox(c, uid_, &name)).await.map_err(|e| no(e.to_string()))?;
                ok("DELETE completed")
            }
            "RENAME" => {
                let uid_ = self.user()?.id;
                let from = mailbox_arg(args)?;
                let to = args.get(1).and_then(|t| t.as_str()).ok_or_else(|| bad("Missing new name"))?;
                if is_shared_name(&from) || is_shared_name(&to) {
                    return Err(no("[NOPERM] Only the mailbox owner can rename folders there"));
                }
                self.srv.store.call(move |c| store::rename_mailbox(c, uid_, &from, &to)).await.map_err(|e| no(e.to_string()))?;
                ok("RENAME completed")
            }
            "SUBSCRIBE" | "UNSUBSCRIBE" => {
                let uid_ = self.user()?.id;
                let name = mailbox_arg(args)?;
                let sub = cmd == "SUBSCRIBE";
                if is_shared_name(&name) {
                    // Shared folders are always listed; nothing to store.
                    return ok(&format!("{cmd} completed"));
                }
                self.srv.store.call(move |c| store::set_subscribed(c, uid_, &name, sub)).await?;
                ok(&format!("{cmd} completed"))
            }
            "LIST" | "LSUB" => self.list(args, cmd == "LSUB").await,
            "STATUS" => self.status(args).await,
            "APPEND" => self.append(args).await,
            "IDLE" => self.idle(tag).await,
            "CLOSE" | "UNSELECT" => {
                let s = self.sel()?;
                if cmd == "CLOSE" && !s.ro {
                    let mbid = s.mb.id;
                    let del: Vec<u32> = s.msgs.iter().filter(|m| m.flags.iter().any(|f| f == "\\Deleted")).map(|m| m.uid).collect();
                    if !del.is_empty() {
                        let owner = s.owner;
                        self.srv.store.call(move |c| store::expunge_uids(c, mbid, &del)).await?;
                        self.srv.notify_user(owner);
                    }
                }
                self.sel = None;
                ok(&format!("{cmd} completed"))
            }
            "EXPUNGE" => self.expunge(args, uid).await,
            "SEARCH" => self.search(args, uid).await,
            "FETCH" => self.fetch(args, uid).await,
            "STORE" => self.store_flags(args, uid).await,
            "COPY" | "MOVE" => self.copy(args, uid, cmd == "MOVE").await,
            _ => Err(bad("Unknown command")),
        }
    }

    async fn login(&mut self, user: &str, pass: &str) -> Result<(String, Flow)> {
        if self.user.is_some() {
            return Err(bad("Already authenticated"));
        }
        if !self.conn.stream.is_tls() {
            return Err(no("[PRIVACYREQUIRED] Login is disabled until STARTTLS has been used"));
        }
        let ip = self.peer.ip();
        if self.srv.guard.is_blocked(ip) {
            return Err(no("[UNAVAILABLE] Too many failed logins, try later"));
        }
        match auth::authenticate(&self.srv.store, user, pass).await? {
            Some(u) => {
                self.srv.guard.record_success(ip);
                tracing::info!("IMAP login {} from {}", u.email, ip);
                self.user = Some(u);
                Ok((format!("OK [CAPABILITY {}] Logged in", self.capabilities()), Flow::Continue))
            }
            None => {
                self.srv.guard.record_failure(ip);
                tracing::warn!("IMAP login failed for {user} from {ip}");
                tokio::time::sleep(Duration::from_secs(2)).await;
                Err(no("[AUTHENTICATIONFAILED] Invalid credentials"))
            }
        }
    }

    /// OAUTHBEARER / XOAUTH2 sign-in with a device token from /api/v1/login (Mailwright).
    async fn login_token(&mut self, resp: &str) -> Result<(String, Flow)> {
        if self.user.is_some() {
            return Err(bad("Already authenticated"));
        }
        let ip = self.peer.ip();
        if self.srv.guard.is_blocked(ip) {
            return Err(no("[UNAVAILABLE] Too many failed logins, try later"));
        }
        let user = match auth::decode_bearer(resp) {
            Some((who, token)) => auth::token_login(&self.srv.store, who.as_deref(), &token).await?,
            None => None,
        };
        match user {
            Some(u) => {
                self.srv.guard.record_success(ip);
                tracing::info!("IMAP token login {} from {}", u.email, ip);
                self.user = Some(u);
                Ok((format!("OK [CAPABILITY {}] Logged in", self.capabilities()), Flow::Continue))
            }
            None => {
                self.srv.guard.record_failure(ip);
                tracing::warn!("IMAP token login failed from {ip}");
                // RFC 7628: send the error as a challenge, the client answers with ^A.
                self.conn.send(&format!("+ {}", auth::BEARER_ERROR_B64)).await?;
                let _ = self.conn.read_line().await;
                tokio::time::sleep(Duration::from_secs(2)).await;
                Err(no("[AUTHENTICATIONFAILED] Invalid or expired token"))
            }
        }
    }

    async fn select(&mut self, args: &[Tok], ro: bool) -> Result<(String, Flow)> {
        let user = self.user()?.clone();
        self.sel = None;
        let name = mailbox_arg(args)?;
        let (t, msgs) = self
            .srv
            .store
            .call(move |c| {
                let Some(t) = resolve(c, &user, &name)? else { return Ok(None) };
                let msgs = store::list_messages(c, t.mb.id)?;
                Ok(Some((t, msgs)))
            })
            .await?
            .ok_or_else(|| no("[NONEXISTENT] Mailbox does not exist"))?;
        if t.access != Access::Own {
            tracing::info!(
                "{} opened {}'s folder {} ({}) from {}",
                self.user()?.email,
                t.owner.email,
                t.mb.name,
                if t.access == Access::Read { "read only" } else { "full access" },
                self.peer.ip()
            );
        }
        let ro = ro || t.access == Access::Read;
        let owner = t.owner.id;
        let mb = t.mb;
        let mut out = vec![
            format!("* FLAGS ({})", SYSTEM_FLAGS.join(" ")),
            format!("* OK [PERMANENTFLAGS ({} \\*)] Flags permitted", SYSTEM_FLAGS.join(" ")),
            format!("* {} EXISTS", msgs.len()),
            "* 0 RECENT".into(),
        ];
        if let Some(i) = msgs.iter().position(|m| !m.flags.iter().any(|f| f == "\\Seen")) {
            out.push(format!("* OK [UNSEEN {}] First unseen", i + 1));
        }
        out.push(format!("* OK [UIDVALIDITY {}] UIDs valid", mb.uidvalidity));
        out.push(format!("* OK [UIDNEXT {}] Predicted next UID", mb.uidnext));
        for l in out {
            self.conn.send(&l).await?;
        }
        self.sel = Some(Selected { mb, ro, msgs, owner });
        Ok((
            format!("OK [{}] {} completed", if ro { "READ-ONLY" } else { "READ-WRITE" }, if ro { "EXAMINE" } else { "SELECT" }),
            Flow::Continue,
        ))
    }

    /// Bring the selected-mailbox snapshot up to date and return untagged updates.
    async fn refresh(&mut self, allow_expunge: bool) -> Result<Vec<String>> {
        let Some(sel) = self.sel.as_mut() else { return Ok(vec![]) };
        let mbid = sel.mb.id;
        let fresh = self.srv.store.call(move |c| store::list_messages(c, mbid)).await?;
        let mut out = Vec::new();
        let by_uid: HashMap<u32, &MsgMeta> = fresh.iter().map(|m| (m.uid, m)).collect();
        let before = sel.msgs.len();
        if allow_expunge {
            for i in (0..sel.msgs.len()).rev() {
                if !by_uid.contains_key(&sel.msgs[i].uid) {
                    out.push(format!("* {} EXPUNGE", i + 1));
                    sel.msgs.remove(i);
                }
            }
        }
        for (i, m) in sel.msgs.iter_mut().enumerate() {
            if let Some(f) = by_uid.get(&m.uid) {
                if f.flags != m.flags {
                    m.flags = f.flags.clone();
                    out.push(format!("* {} FETCH (UID {} FLAGS {})", i + 1, m.uid, flags_list(&m.flags)));
                }
            }
        }
        let max_uid = sel.msgs.last().map(|m| m.uid).unwrap_or(0);
        let new: Vec<MsgMeta> = fresh.iter().filter(|m| m.uid > max_uid).cloned().collect();
        let added = !new.is_empty();
        sel.msgs.extend(new);
        if added || sel.msgs.len() != before {
            out.push(format!("* {} EXISTS", sel.msgs.len()));
        }
        Ok(out)
    }

    async fn list(&mut self, args: &[Tok], lsub: bool) -> Result<(String, Flow)> {
        let uid_ = self.user()?.id;
        let mut strs = Vec::new();
        let mut subscribed_only = lsub;
        let mut patterns: Vec<String> = Vec::new();
        let mut it = args.iter().peekable();
        if let Some(Tok::List(opts)) = it.peek() {
            subscribed_only |= opts.iter().any(|o| o.atom_upper().as_deref() == Some("SUBSCRIBED"));
            it.next();
        }
        for t in it {
            match t {
                Tok::Atom(a) if a.eq_ignore_ascii_case("RETURN") => break,
                Tok::List(l) if strs.len() == 1 => patterns.extend(l.iter().filter_map(|x| x.as_str())),
                _ => strs.push(t.as_str().unwrap_or_default()),
            }
        }
        let reference = strs.first().cloned().unwrap_or_default();
        if patterns.is_empty() {
            patterns.push(strs.get(1).cloned().ok_or_else(|| bad("Missing pattern"))?);
        }
        let word = if lsub { "LSUB" } else { "LIST" };
        if patterns.len() == 1 && patterns[0].is_empty() {
            self.conn.send(&format!("* {word} (\\Noselect) \"/\" \"\"")).await?;
            return Ok((format!("OK {word} completed"), Flow::Continue));
        }
        let boxes = self.srv.store.call(move |c| store::list_mailboxes(c, uid_)).await?;
        let names: Vec<String> = boxes.iter().map(|b| b.name.clone()).collect();
        for b in &boxes {
            if subscribed_only && !b.subscribed {
                continue;
            }
            let hit = patterns.iter().any(|p| {
                let full = format!("{reference}{p}");
                let pat: Vec<char> = if full.eq_ignore_ascii_case("INBOX") { "INBOX".chars().collect() } else { full.chars().collect() };
                pattern_match(&pat, &b.name.chars().collect::<Vec<_>>())
            });
            if !hit {
                continue;
            }
            let mut attrs = vec![];
            let prefix = format!("{}/", b.name);
            attrs.push(if names.iter().any(|n| n.starts_with(&prefix)) { "\\HasChildren" } else { "\\HasNoChildren" }.to_string());
            if let Some(s) = &b.special {
                attrs.push(s.clone());
            }
            if subscribed_only && !lsub {
                attrs.push("\\Subscribed".into());
            }
            self.conn.send(&format!("* {word} ({}) \"/\" {}", attrs.join(" "), q(&b.name))).await?;
        }
        // Mailboxes other people have shared with this user.
        let shared = self
            .srv
            .store
            .call(move |c| {
                let mut out: Vec<(String, Vec<Mailbox>)> = Vec::new();
                for d in crate::identity::granted_to(c, uid_)? {
                    if d.mailbox == crate::identity::MailboxRight::None {
                        continue;
                    }
                    out.push((d.owner.clone(), store::list_mailboxes(c, d.owner_id)?));
                }
                Ok(out)
            })
            .await?;
        if !shared.is_empty() {
            let mut entries: Vec<(String, Vec<String>)> = vec![("Other Users".into(), vec!["\\Noselect".into(), "\\HasChildren".into()])];
            for (owner, boxes) in &shared {
                entries.push((format!("{SHARED_PREFIX}{owner}"), vec!["\\Noselect".into(), "\\HasChildren".into()]));
                let names: Vec<&str> = boxes.iter().map(|b| b.name.as_str()).collect();
                for b in boxes {
                    if subscribed_only && !b.subscribed {
                        continue;
                    }
                    let prefix = format!("{}/", b.name);
                    let mut attrs = vec![if names.iter().any(|n| n.starts_with(&prefix)) { "\\HasChildren" } else { "\\HasNoChildren" }.to_string()];
                    if subscribed_only && !lsub {
                        attrs.push("\\Subscribed".into());
                    }
                    entries.push((format!("{SHARED_PREFIX}{owner}/{}", b.name), attrs));
                }
            }
            for (name, attrs) in entries {
                let hit = patterns.iter().any(|p| pattern_match(&format!("{reference}{p}").chars().collect::<Vec<_>>(), &name.chars().collect::<Vec<_>>()));
                if hit {
                    self.conn.send(&format!("* {word} ({}) \"/\" {}", attrs.join(" "), q(&name))).await?;
                }
            }
        }
        Ok((format!("OK {word} completed"), Flow::Continue))
    }

    async fn status(&mut self, args: &[Tok]) -> Result<(String, Flow)> {
        let user = self.user()?.clone();
        let name = mailbox_arg(args)?;
        let Some(Tok::List(items)) = args.get(1) else { return Err(bad("Missing status items")) };
        let n2 = name.clone();
        let (mb, msgs) = self
            .srv
            .store
            .call(move |c| {
                let Some(t) = resolve(c, &user, &n2)? else { return Ok(None) };
                let m = store::list_messages(c, t.mb.id)?;
                let mut mb = t.mb;
                mb.name = t.display;
                Ok(Some((mb, m)))
            })
            .await?
            .ok_or_else(|| no("[NONEXISTENT] Mailbox does not exist"))?;
        let mut parts = Vec::new();
        for it in items {
            let k = it.atom_upper().unwrap_or_default();
            let v = match k.as_str() {
                "MESSAGES" => msgs.len().to_string(),
                "RECENT" => "0".into(),
                "UIDNEXT" => mb.uidnext.to_string(),
                "UIDVALIDITY" => mb.uidvalidity.to_string(),
                "UNSEEN" => msgs.iter().filter(|m| !m.flags.iter().any(|f| f == "\\Seen")).count().to_string(),
                "SIZE" => msgs.iter().map(|m| m.size).sum::<i64>().to_string(),
                _ => return Err(bad(format!("Unknown status item {k}"))),
            };
            parts.push(format!("{k} {v}"));
        }
        self.conn.send(&format!("* STATUS {} ({})", q(&mb.name), parts.join(" "))).await?;
        Ok(("OK STATUS completed".into(), Flow::Continue))
    }

    async fn append(&mut self, args: &[Tok]) -> Result<(String, Flow)> {
        let user = self.user()?.clone();
        let name = mailbox_arg(args)?;
        let Some(Tok::Str(data)) = args.last() else { return Err(bad("Missing message literal")) };
        if args.len() < 2 {
            return Err(bad("Missing message"));
        }
        let mut flags = Vec::new();
        let mut date = store::now();
        for t in &args[1..args.len() - 1] {
            match t {
                Tok::List(l) => {
                    for f in l {
                        if let Some(f) = f.as_str().and_then(|f| canonical_flag(&f)) {
                            if !flags.contains(&f) {
                                flags.push(f);
                            }
                        }
                    }
                }
                other => {
                    let s = other.as_str().unwrap_or_default();
                    if let Ok(d) = DateTime::parse_from_str(s.trim(), "%d-%b-%Y %H:%M:%S %z") {
                        date = d.timestamp();
                    }
                }
            }
        }
        if data.len() > self.srv.cfg.limits.max_message_size {
            return Err(no("[TOOBIG] Message too large"));
        }
        let size = data.len() as i64;
        let blob = self.srv.store.put_blob(Arc::new(data.clone())).await?;
        let res = self
            .srv
            .store
            .call(move |c| {
                let Some(t) = resolve(c, &user, &name)? else { return Ok(Err("[TRYCREATE] Mailbox does not exist")) };
                if t.access == Access::Read {
                    return Ok(Err("[NOPERM] You have read-only access to this mailbox"));
                }
                let owner = t.owner;
                if owner.quota_bytes > 0 && store::user_usage(c, owner.id)? + size > owner.quota_bytes {
                    return Ok(Err("[OVERQUOTA] Quota exceeded"));
                }
                let uid = store::append_message(c, t.mb.id, &blob, size, date, &flags)?;
                Ok(Ok((t.mb.uidvalidity, uid, owner.id)))
            })
            .await?;
        match res {
            Ok((v, uid, owner)) => {
                self.srv.notify_user(owner);
                Ok((format!("OK [APPENDUID {v} {uid}] APPEND completed"), Flow::Continue))
            }
            Err(e) => Err(no(e)),
        }
    }

    async fn idle(&mut self, tag: &str) -> Result<(String, Flow)> {
        let uid_ = self.user()?.id;
        self.conn.send("+ idling").await?;
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.tick().await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(self.srv.cfg.limits.imap_timeout_secs);
        loop {
            let mut changed = false;
            tokio::select! {
                line = self.conn.read_line() => {
                    let line = line?;
                    if line.eq_ignore_ascii_case(b"DONE") {
                        return Ok(("OK IDLE terminated".into(), Flow::Continue));
                    }
                    let _ = tag;
                    return Err(bad("Expected DONE"));
                }
                r = self.changes.recv() => {
                    match r {
                        Ok(u) if u == uid_ || Some(u) == self.sel.as_ref().map(|s| s.owner) => changed = true,
                        Err(broadcast::error::RecvError::Lagged(_)) => changed = true,
                        _ => {}
                    }
                }
                _ = tick.tick() => changed = true,
                _ = tokio::time::sleep_until(deadline) => {
                    self.conn.send("* BYE Idle timeout").await?;
                    bail!("idle timeout");
                }
            }
            if changed {
                for l in self.refresh(true).await? {
                    self.conn.send(&l).await?;
                }
            }
        }
    }

    /// Indices (0-based) of messages matching a sequence set.
    fn matching(&self, set: &SeqSet, uid: bool) -> Vec<usize> {
        let Some(sel) = &self.sel else { return vec![] };
        let max_seq = sel.msgs.len() as u32;
        let max_uid = sel.msgs.last().map(|m| m.uid).unwrap_or(0);
        sel.msgs
            .iter()
            .enumerate()
            .filter(|(i, m)| if uid { set.contains(m.uid, max_uid) } else { set.contains(*i as u32 + 1, max_seq) })
            .map(|(i, _)| i)
            .collect()
    }

    async fn expunge(&mut self, args: &[Tok], uid: bool) -> Result<(String, Flow)> {
        self.user()?;
        let user_id = self.sel()?.owner;
        let only: Option<SeqSet> = if uid {
            Some(SeqSet::parse(&args.first().and_then(|t| t.as_str()).ok_or_else(|| bad("Missing UID set"))?)?)
        } else {
            None
        };
        let in_set: Option<Vec<usize>> = only.as_ref().map(|s| self.matching(s, true));
        let sel = self.sel()?;
        if sel.ro {
            return Err(no("[READ-ONLY] Mailbox is read-only"));
        }
        let idx: Vec<usize> = (0..sel.msgs.len())
            .filter(|i| sel.msgs[*i].flags.iter().any(|f| f == "\\Deleted"))
            .filter(|i| in_set.as_ref().map(|s| s.contains(i)).unwrap_or(true))
            .collect();
        let uids: Vec<u32> = idx.iter().map(|&i| sel.msgs[i].uid).collect();
        let mbid = sel.mb.id;
        self.srv.store.call(move |c| store::expunge_uids(c, mbid, &uids)).await?;
        let sel = self.sel()?;
        let mut lines = Vec::new();
        for &i in idx.iter().rev() {
            lines.push(format!("* {} EXPUNGE", i + 1));
            sel.msgs.remove(i);
        }
        for l in lines {
            self.conn.send(&l).await?;
        }
        self.srv.notify_user(user_id);
        Ok(("OK EXPUNGE completed".into(), Flow::Continue))
    }

    async fn search(&mut self, args: &[Tok], uid: bool) -> Result<(String, Flow)> {
        // Ignore RETURN (...) options from ESEARCH-aware clients.
        let args: Vec<Tok> = if args.first().and_then(|t| t.atom_upper()).as_deref() == Some("RETURN") {
            args[2.min(args.len())..].to_vec()
        } else {
            args.to_vec()
        };
        let crit = search::parse(&args).map_err(|e| bad(e.to_string()))?;
        let need = crit.needs_content();
        let sel = self.sel.as_ref().ok_or_else(|| bad("No mailbox selected"))?;
        let max_seq = sel.msgs.len() as u32;
        let max_uid = sel.msgs.last().map(|m| m.uid).unwrap_or(0);
        let mut hits = Vec::new();
        for (i, m) in sel.msgs.iter().enumerate() {
            let raw = if need { self.srv.store.get_blob(&m.blob).await.ok() } else { None };
            let ctx = search::Ctx { meta: m, seq: i as u32 + 1, max_seq, max_uid, raw: raw.as_deref() };
            if search::eval(&crit, &ctx) {
                hits.push(if uid { m.uid } else { i as u32 + 1 });
            }
        }
        let line = if hits.is_empty() {
            "* SEARCH".to_string()
        } else {
            format!("* SEARCH {}", hits.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(" "))
        };
        self.conn.send(&line).await?;
        Ok(("OK SEARCH completed".into(), Flow::Continue))
    }

    async fn fetch(&mut self, args: &[Tok], uid: bool) -> Result<(String, Flow)> {
        let set = SeqSet::parse(&args.first().and_then(|t| t.as_str()).ok_or_else(|| bad("Missing sequence set"))?)
            .map_err(|e| bad(e.to_string()))?;
        let mut atts = parse::parse_fetch_atts(args.get(1).ok_or_else(|| bad("Missing fetch items"))?).map_err(|e| bad(e.to_string()))?;
        if uid && !atts.contains(&FetchAtt::Uid) {
            atts.insert(0, FetchAtt::Uid);
        }
        let needs_blob = atts.iter().any(|a| {
            !matches!(a, FetchAtt::Flags | FetchAtt::Uid | FetchAtt::InternalDate | FetchAtt::Rfc822Size)
        });
        let sets_seen = atts
            .iter()
            .any(|a| matches!(a, FetchAtt::Rfc822 | FetchAtt::Rfc822Text | FetchAtt::Section { peek: false, .. }));
        let idx = self.matching(&set, uid);
        let ro = self.sel.as_ref().map(|s| s.ro).unwrap_or(true);
        let mut any_seen = false;
        for i in idx {
            let m = self.sel.as_ref().unwrap().msgs[i].clone();
            let raw = if needs_blob {
                match self.srv.store.get_blob(&m.blob).await {
                    Ok(r) => Some(r),
                    Err(_) => continue, // expunged concurrently
                }
            } else {
                None
            };
            let mut flags = m.flags.clone();
            let mut flags_changed = false;
            if sets_seen && !ro && !flags.iter().any(|f| f == "\\Seen") {
                flags.push("\\Seen".into());
                let (id, f2) = (m.id, flags.clone());
                self.srv.store.call(move |c| store::set_flags(c, id, &f2)).await?;
                self.sel.as_mut().unwrap().msgs[i].flags = flags.clone();
                flags_changed = true;
                any_seen = true;
            }
            let part = raw.as_deref().map(mime::parse);
            let mut out = format!("* {} FETCH (", i + 1).into_bytes();
            let mut first = true;
            let mut sep = |out: &mut Vec<u8>| {
                if !first {
                    out.push(b' ');
                }
                first = false;
            };
            for a in &atts {
                sep(&mut out);
                match a {
                    FetchAtt::Flags => out.extend_from_slice(format!("FLAGS {}", flags_list(&flags)).as_bytes()),
                    FetchAtt::Uid => out.extend_from_slice(format!("UID {}", m.uid).as_bytes()),
                    FetchAtt::InternalDate => {
                        out.extend_from_slice(format!("INTERNALDATE \"{}\"", fmt_internal_date(m.internal_date)).as_bytes())
                    }
                    FetchAtt::Rfc822Size => out.extend_from_slice(format!("RFC822.SIZE {}", m.size).as_bytes()),
                    FetchAtt::Envelope => {
                        out.extend_from_slice(b"ENVELOPE ");
                        part.as_ref().unwrap().envelope(&mut out);
                    }
                    FetchAtt::BodyStructure => {
                        out.extend_from_slice(b"BODYSTRUCTURE ");
                        part.as_ref().unwrap().bodystructure(&mut out, true);
                    }
                    FetchAtt::Body => {
                        out.extend_from_slice(b"BODY ");
                        part.as_ref().unwrap().bodystructure(&mut out, false);
                    }
                    FetchAtt::Rfc822 => {
                        out.extend_from_slice(b"RFC822 ");
                        parse::lit(&mut out, raw.as_deref().unwrap());
                    }
                    FetchAtt::Rfc822Header => {
                        out.extend_from_slice(b"RFC822.HEADER ");
                        parse::lit(&mut out, part.as_ref().unwrap().header);
                    }
                    FetchAtt::Rfc822Text => {
                        out.extend_from_slice(b"RFC822.TEXT ");
                        parse::lit(&mut out, part.as_ref().unwrap().body);
                    }
                    FetchAtt::Section { section, partial, .. } => {
                        let data = part.as_ref().unwrap().section(section);
                        match partial {
                            Some((start, len)) => {
                                let s = (*start as usize).min(data.len());
                                let e = (s + *len as usize).min(data.len());
                                out.extend_from_slice(format!("BODY[{}]<{}> ", section.label(), start).as_bytes());
                                parse::lit(&mut out, &data[s..e]);
                            }
                            None => {
                                out.extend_from_slice(format!("BODY[{}] ", section.label()).as_bytes());
                                parse::lit(&mut out, &data);
                            }
                        }
                    }
                }
            }
            if flags_changed && !atts.contains(&FetchAtt::Flags) {
                sep(&mut out);
                out.extend_from_slice(format!("FLAGS {}", flags_list(&flags)).as_bytes());
            }
            out.extend_from_slice(b")\r\n");
            self.conn.write(&out).await?;
        }
        if any_seen {
            let id = self.sel()?.owner;
            self.srv.notify_user(id);
        }
        Ok(("OK FETCH completed".into(), Flow::Continue))
    }

    async fn store_flags(&mut self, args: &[Tok], uid: bool) -> Result<(String, Flow)> {
        let set = SeqSet::parse(&args.first().and_then(|t| t.as_str()).ok_or_else(|| bad("Missing sequence set"))?)
            .map_err(|e| bad(e.to_string()))?;
        let item = args.get(1).and_then(|t| t.atom_upper()).ok_or_else(|| bad("Missing store item"))?;
        let silent = item.ends_with(".SILENT");
        let op = item.trim_end_matches(".SILENT");
        let mut given = Vec::new();
        for t in &args[2.min(args.len())..] {
            match t {
                Tok::List(l) => given.extend(l.iter().filter_map(|x| x.as_str())),
                other => given.extend(other.as_str()),
            }
        }
        let given: Vec<String> = given.iter().filter_map(|f| canonical_flag(f)).collect();
        if self.sel()?.ro {
            return Err(no("[READ-ONLY] Mailbox is read-only"));
        }
        let idx = self.matching(&set, uid);
        let mut updates = Vec::new();
        let sel = self.sel()?;
        for &i in &idx {
            let m = &mut sel.msgs[i];
            let mut f = m.flags.clone();
            match op {
                "FLAGS" => f = given.clone(),
                "+FLAGS" => {
                    for g in &given {
                        if !f.contains(g) {
                            f.push(g.clone());
                        }
                    }
                }
                "-FLAGS" => f.retain(|x| !given.contains(x)),
                _ => return Err(bad("Bad store item")),
            }
            if f != m.flags {
                m.flags = f.clone();
                updates.push((m.id, f));
            }
        }
        let n = updates.len();
        self.srv
            .store
            .call(move |c| {
                let tx = c.transaction()?;
                for (id, f) in &updates {
                    store::set_flags(&tx, *id, f)?;
                }
                tx.commit()?;
                Ok(())
            })
            .await?;
        if !silent {
            let sel = self.sel.as_ref().unwrap();
            let mut lines = Vec::new();
            for &i in &idx {
                let m = &sel.msgs[i];
                lines.push(if uid {
                    format!("* {} FETCH (UID {} FLAGS {})", i + 1, m.uid, flags_list(&m.flags))
                } else {
                    format!("* {} FETCH (FLAGS {})", i + 1, flags_list(&m.flags))
                });
            }
            for l in lines {
                self.conn.send(&l).await?;
            }
        }
        if n > 0 {
            let id = self.sel()?.owner;
            self.srv.notify_user(id);
        }
        Ok(("OK STORE completed".into(), Flow::Continue))
    }

    async fn copy(&mut self, args: &[Tok], uid: bool, mv: bool) -> Result<(String, Flow)> {
        let user = self.user()?.clone();
        let set = SeqSet::parse(&args.first().and_then(|t| t.as_str()).ok_or_else(|| bad("Missing sequence set"))?)
            .map_err(|e| bad(e.to_string()))?;
        let dest = args.get(1).and_then(|t| t.as_str()).ok_or_else(|| bad("Missing destination"))?;
        let idx = self.matching(&set, uid);
        let sel = self.sel()?;
        if mv && sel.ro {
            return Err(no("[READ-ONLY] Mailbox is read-only"));
        }
        let src = sel.mb.id;
        let src_owner = sel.owner;
        let src_junk = is_junk(&sel.mb);
        let blobs: Vec<String> = idx.iter().map(|&i| sel.msgs[i].blob.clone()).collect();
        let uids: Vec<u32> = idx.iter().map(|&i| sel.msgs[i].uid).collect();
        let res = self
            .srv
            .store
            .call(move |c| {
                let Some(t) = resolve(c, &user, &dest)? else { return Ok(None) };
                if t.access == Access::Read {
                    return Ok(Some(Err(())));
                }
                let dst = t.mb;
                let pairs = if mv { store::move_messages(c, src, dst.id, &uids)? } else { store::copy_messages(c, src, dst.id, &uids)? };
                Ok(Some(Ok((dst.uidvalidity, pairs, is_junk(&dst), dst.special.as_deref() == Some("\\Trash") || dst.name == "Trash", t.owner.id))))
            })
            .await?;
        let Some(res) = res else { return Err(no("[TRYCREATE] Destination mailbox does not exist")) };
        let Ok((validity, pairs, dst_junk, dst_trash, dst_owner)) = res else {
            return Err(no("[NOPERM] You have read-only access to the destination mailbox"));
        };
        // Moving mail into Junk teaches the spam filter; rescuing it from Junk teaches ham.
        let email = self.user()?.email.clone();
        if dst_junk && !src_junk {
            crate::filter::learn(&self.srv, blobs, true, email);
        } else if src_junk && !dst_junk && !dst_trash && !pairs.is_empty() {
            crate::filter::learn(&self.srv, blobs, false, email);
        }
        let code = if pairs.is_empty() {
            String::new()
        } else {
            let s: Vec<u32> = pairs.iter().map(|p| p.0).collect();
            let d: Vec<u32> = pairs.iter().map(|p| p.1).collect();
            format!("[COPYUID {validity} {} {}] ", compact(&s), compact(&d))
        };
        self.srv.notify_user(src_owner);
        if dst_owner != src_owner {
            self.srv.notify_user(dst_owner);
        }
        if mv {
            if !code.is_empty() {
                self.conn.send(&format!("* OK {}Moved", code)).await?;
            }
            let sel = self.sel()?;
            let mut lines = Vec::new();
            for &i in idx.iter().rev() {
                lines.push(format!("* {} EXPUNGE", i + 1));
                sel.msgs.remove(i);
            }
            for l in lines {
                self.conn.send(&l).await?;
            }
            return Ok(("OK MOVE completed".into(), Flow::Continue));
        }
        Ok((format!("OK {code}COPY completed"), Flow::Continue))
    }
}

fn is_junk(mb: &Mailbox) -> bool {
    mb.special.as_deref() == Some("\\Junk") || mb.name.eq_ignore_ascii_case("Junk") || mb.name.eq_ignore_ascii_case("Spam")
}

fn mailbox_arg(args: &[Tok]) -> Result<String> {
    args.first().and_then(|t| t.as_str()).ok_or_else(|| bad("Missing mailbox name"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn patterns() {
        let m = |p: &str, n: &str| pattern_match(&p.chars().collect::<Vec<_>>(), &n.chars().collect::<Vec<_>>());
        assert!(m("*", "Work/Projects"));
        assert!(m("%", "Work"));
        assert!(!m("%", "Work/Projects"));
        assert!(m("Work/%", "Work/Projects"));
        assert_eq!(literal_suffix(b"A1 APPEND INBOX {310}"), Some((310, false)));
        assert_eq!(literal_suffix(b"A1 LOGIN {5+}"), Some((5, true)));
    }
}
