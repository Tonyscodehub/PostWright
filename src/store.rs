//! Storage: SQLite (WAL) for metadata, content-addressed files for message bodies.
//!
//! All blocking database work runs on Tokio's blocking pool via [`Store::call`], so
//! the async network front-ends are never stalled by disk I/O.

use anyhow::{anyhow, bail, Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS domains(
    name TEXT PRIMARY KEY,
    dkim_selector TEXT,
    dkim_key TEXT,
    catch_all TEXT
);
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    quota_bytes INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS aliases(
    source TEXT NOT NULL,
    target TEXT NOT NULL,
    PRIMARY KEY(source, target)
);
CREATE TABLE IF NOT EXISTS mailboxes(
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    uidvalidity INTEGER NOT NULL,
    uidnext INTEGER NOT NULL DEFAULT 1,
    subscribed INTEGER NOT NULL DEFAULT 1,
    special TEXT,
    UNIQUE(user_id, name)
);
CREATE TABLE IF NOT EXISTS messages(
    id INTEGER PRIMARY KEY,
    mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    uid INTEGER NOT NULL,
    blob TEXT NOT NULL,
    size INTEGER NOT NULL,
    internal_date INTEGER NOT NULL,
    flags TEXT NOT NULL DEFAULT '',
    UNIQUE(mailbox_id, uid)
);
CREATE INDEX IF NOT EXISTS messages_mailbox ON messages(mailbox_id, uid);
CREATE TABLE IF NOT EXISTS blobs(
    hash TEXT PRIMARY KEY,
    refcount INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS queue(
    id INTEGER PRIMARY KEY,
    mail_from TEXT NOT NULL,
    domain TEXT NOT NULL,
    rcpts TEXT NOT NULL,
    blob TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt INTEGER NOT NULL,
    created INTEGER NOT NULL,
    last_error TEXT
);
CREATE INDEX IF NOT EXISTS queue_due ON queue(next_attempt);
CREATE TABLE IF NOT EXISTS user_settings(
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    vacation_enabled INTEGER NOT NULL DEFAULT 0,
    vacation_subject TEXT NOT NULL DEFAULT '',
    vacation_body TEXT NOT NULL DEFAULT '',
    vacation_start INTEGER,
    vacation_end INTEGER,
    vacation_internal_only INTEGER NOT NULL DEFAULT 0,
    signature_text TEXT NOT NULL DEFAULT '',
    signature_html TEXT NOT NULL DEFAULT '',
    signature_append INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS vacation_log(
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sender TEXT NOT NULL,
    sent INTEGER NOT NULL,
    PRIMARY KEY(user_id, sender)
);
CREATE TABLE IF NOT EXISTS calendars(
    id INTEGER PRIMARY KEY,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    color TEXT,
    description TEXT,
    ctag INTEGER NOT NULL DEFAULT 1,
    UNIQUE(owner_id, slug)
);
CREATE TABLE IF NOT EXISTS calendar_objects(
    id INTEGER PRIMARY KEY,
    calendar_id INTEGER NOT NULL REFERENCES calendars(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    etag TEXT NOT NULL,
    data TEXT NOT NULL,
    component TEXT,
    dtstart INTEGER,
    dtend INTEGER,
    recurring INTEGER NOT NULL DEFAULT 0,
    modified INTEGER NOT NULL,
    UNIQUE(calendar_id, name)
);
CREATE TABLE IF NOT EXISTS calendar_shares(
    calendar_id INTEGER NOT NULL REFERENCES calendars(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    write INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(calendar_id, user_id)
);
"#;

/// Default folders created for each new user, with their RFC 6154 special-use attribute.
pub const DEFAULT_FOLDERS: &[(&str, Option<&str>)] = &[
    ("INBOX", None),
    ("Sent", Some("\\Sent")),
    ("Drafts", Some("\\Drafts")),
    ("Trash", Some("\\Trash")),
    ("Junk", Some("\\Junk")),
    ("Archive", Some("\\Archive")),
];

#[derive(Clone)]
pub struct Store {
    inner: Arc<Inner>,
}

struct Inner {
    conns: Vec<Mutex<Connection>>,
    next: AtomicUsize,
    blob_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: i64,
    pub email: String,
    pub password: String,
    pub quota_bytes: i64,
    pub enabled: bool,
    pub is_admin: bool,
}

#[derive(Debug, Clone)]
pub struct Domain {
    pub name: String,
    pub dkim_selector: Option<String>,
    pub dkim_key: Option<String>,
    pub catch_all: Option<String>,
    /// If set, this domain is an alias: local@name is delivered as local@alias_of.
    pub alias_of: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Mailbox {
    pub id: i64,
    pub name: String,
    pub uidvalidity: u32,
    pub uidnext: u32,
    pub subscribed: bool,
    pub special: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MsgMeta {
    pub id: i64,
    pub uid: u32,
    pub blob: String,
    pub size: i64,
    pub internal_date: i64,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct QueueItem {
    pub id: i64,
    pub mail_from: String,
    pub domain: String,
    pub rcpts: Vec<String>,
    pub blob: String,
    pub attempts: i64,
    pub created: i64,
    pub last_error: Option<String>,
    pub next_attempt: i64,
}

/// Additive schema changes for databases created by earlier versions.
fn migrate(c: &Connection) -> Result<()> {
    let has = |table: &str, col: &str| -> Result<bool> {
        let mut st = c.prepare(&format!("PRAGMA table_info({table})"))?;
        let cols = st.query_map([], |r| r.get::<_, String>(1))?.collect::<Result<Vec<_>, _>>()?;
        Ok(cols.iter().any(|c| c == col))
    };
    c.execute_batch(crate::certs::SCHEMA)?;
    c.execute_batch(crate::identity::SCHEMA)?;
    if !has("users", "is_admin")? {
        c.execute_batch("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")?;
    }
    if !has("domains", "alias_of")? {
        c.execute_batch("ALTER TABLE domains ADD COLUMN alias_of TEXT")?;
    }
    Ok(())
}

pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn open_conn(path: &Path) -> Result<Connection> {
    let c = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
    c.busy_timeout(std::time::Duration::from_secs(30))?;
    c.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;",
    )?;
    Ok(c)
}

impl Store {
    pub fn open(db_path: &Path, blob_dir: &Path, pool_size: usize) -> Result<Self> {
        if let Some(p) = db_path.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::create_dir_all(blob_dir)?;
        let first = open_conn(db_path)?;
        first.execute_batch(SCHEMA)?;
        migrate(&first)?;
        let mut conns = vec![Mutex::new(first)];
        for _ in 1..pool_size.max(1) {
            conns.push(Mutex::new(open_conn(db_path)?));
        }
        Ok(Self {
            inner: Arc::new(Inner { conns, next: AtomicUsize::new(0), blob_dir: blob_dir.to_path_buf() }),
        })
    }

    /// Run a closure against a pooled connection on the blocking thread pool.
    pub async fn call<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Connection) -> Result<R> + Send + 'static,
        R: Send + 'static,
    {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let n = inner.conns.len();
            let start = inner.next.fetch_add(1, Ordering::Relaxed) % n;
            // Prefer an idle connection; fall back to waiting on our slot.
            for i in 0..n {
                if let Ok(mut c) = inner.conns[(start + i) % n].try_lock() {
                    return f(&mut c);
                }
            }
            let mut c = inner.conns[start].lock().map_err(|_| anyhow!("db pool poisoned"))?;
            f(&mut c)
        })
        .await?
    }

    /// Synchronous access, for the admin CLI.
    pub fn sync<R>(&self, f: impl FnOnce(&mut Connection) -> Result<R>) -> Result<R> {
        let mut c = self.inner.conns[0].lock().map_err(|_| anyhow!("db pool poisoned"))?;
        f(&mut c)
    }

    // ---------------------------------------------------------------- blobs

    fn blob_path(&self, hash: &str) -> PathBuf {
        self.inner.blob_dir.join(&hash[..2]).join(hash)
    }

    /// Store message bytes and return their content hash. Idempotent.
    pub async fn put_blob(&self, data: Arc<Vec<u8>>) -> Result<String> {
        let hash = hex::encode(Sha256::digest(&data[..]));
        let path = self.blob_path(&hash);
        if !tokio::fs::try_exists(&path).await.unwrap_or(false) {
            tokio::fs::create_dir_all(path.parent().unwrap()).await?;
            let tmp = path.with_extension(format!("tmp{}", rand::random::<u32>()));
            tokio::fs::write(&tmp, &data[..]).await?;
            tokio::fs::rename(&tmp, &path).await?;
        }
        Ok(hash)
    }

    /// Blocking variant of `put_blob` for the CLI importer.
    pub fn put_blob_sync(&self, data: &[u8]) -> Result<String> {
        let hash = hex::encode(Sha256::digest(data));
        let path = self.blob_path(&hash);
        if !path.exists() {
            std::fs::create_dir_all(path.parent().unwrap())?;
            let tmp = path.with_extension(format!("tmp{}", rand::random::<u32>()));
            std::fs::write(&tmp, data)?;
            std::fs::rename(&tmp, &path)?;
        }
        Ok(hash)
    }

    pub async fn get_blob(&self, hash: &str) -> Result<Vec<u8>> {
        if hash.len() < 3 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("invalid blob id");
        }
        Ok(tokio::fs::read(self.blob_path(hash)).await?)
    }

    /// Drop blobs whose refcount reached zero.
    pub async fn gc_blobs(&self) -> Result<usize> {
        let dead: Vec<String> = self
            .call(|c| {
                let mut st = c.prepare("SELECT hash FROM blobs WHERE refcount <= 0")?;
                let v = st.query_map([], |r| r.get(0))?.collect::<Result<Vec<String>, _>>()?;
                c.execute("DELETE FROM blobs WHERE refcount <= 0", [])?;
                Ok(v)
            })
            .await?;
        for h in &dead {
            let _ = tokio::fs::remove_file(self.blob_path(h)).await;
        }
        Ok(dead.len())
    }
}

// ------------------------------------------------------------------ queries
// Plain synchronous functions taking a connection; call them inside Store::call.

pub fn blob_ref(c: &Connection, hash: &str, delta: i64) -> Result<()> {
    c.execute(
        "INSERT INTO blobs(hash, refcount) VALUES(?1, ?2)
         ON CONFLICT(hash) DO UPDATE SET refcount = refcount + ?2",
        params![hash, delta],
    )?;
    Ok(())
}

fn row_user(r: &rusqlite::Row) -> rusqlite::Result<User> {
    Ok(User {
        id: r.get(0)?,
        email: r.get(1)?,
        password: r.get(2)?,
        quota_bytes: r.get(3)?,
        enabled: r.get::<_, i64>(4)? != 0,
        is_admin: r.get::<_, i64>(5)? != 0,
    })
}

pub fn find_user(c: &Connection, email: &str) -> Result<Option<User>> {
    Ok(c.query_row(
        "SELECT id, email, password, quota_bytes, enabled, is_admin FROM users WHERE email = ?1",
        [email.to_ascii_lowercase()],
        row_user,
    )
    .optional()?)
}

pub fn user_by_id(c: &Connection, id: i64) -> Result<Option<User>> {
    Ok(c.query_row(
        "SELECT id, email, password, quota_bytes, enabled, is_admin FROM users WHERE id = ?1",
        [id],
        row_user,
    )
    .optional()?)
}

pub fn list_users(c: &Connection) -> Result<Vec<User>> {
    let mut st = c.prepare("SELECT id, email, password, quota_bytes, enabled, is_admin FROM users ORDER BY email")?;
    let v = st.query_map([], row_user)?.collect::<Result<Vec<_>, _>>()?;
    Ok(v)
}

pub fn create_user(c: &mut Connection, email: &str, pw_hash: &str, quota: i64) -> Result<i64> {
    let email = email.to_ascii_lowercase();
    let domain = email.rsplit_once('@').map(|x| x.1).ok_or_else(|| anyhow!("invalid address"))?;
    if find_domain(c, domain)?.is_none() {
        bail!("domain {domain} is not hosted here; add it first");
    }
    let tx = c.transaction()?;
    tx.execute(
        "INSERT INTO users(email, password, quota_bytes) VALUES(?1, ?2, ?3)",
        params![email, pw_hash, quota],
    )?;
    let id = tx.last_insert_rowid();
    for (name, special) in DEFAULT_FOLDERS {
        tx.execute(
            "INSERT INTO mailboxes(user_id, name, uidvalidity, special) VALUES(?1, ?2, ?3, ?4)",
            params![id, name, new_uidvalidity(), special],
        )?;
    }
    tx.execute(
        "INSERT INTO calendars(owner_id, slug, name, color) VALUES(?1, 'calendar', 'Calendar', '#2E7D32FF')",
        [id],
    )?;
    tx.commit()?;
    Ok(id)
}

pub fn set_password(c: &Connection, email: &str, pw_hash: &str) -> Result<bool> {
    Ok(c.execute("UPDATE users SET password = ?2 WHERE email = ?1", params![email.to_ascii_lowercase(), pw_hash])? > 0)
}

pub fn set_admin(c: &Connection, email: &str, admin: bool) -> Result<bool> {
    Ok(c.execute("UPDATE users SET is_admin = ?2 WHERE email = ?1", params![email.to_ascii_lowercase(), admin as i64])? > 0)
}

pub fn set_quota(c: &Connection, email: &str, bytes: i64) -> Result<bool> {
    Ok(c.execute("UPDATE users SET quota_bytes = ?2 WHERE email = ?1", params![email.to_ascii_lowercase(), bytes])? > 0)
}

pub fn delete_queue_item(c: &mut Connection, id: i64) -> Result<()> {
    queue_done(c, id)
}

pub fn set_enabled(c: &Connection, email: &str, enabled: bool) -> Result<bool> {
    Ok(c.execute("UPDATE users SET enabled = ?2 WHERE email = ?1", params![email.to_ascii_lowercase(), enabled as i64])? > 0)
}

pub fn delete_user(c: &mut Connection, email: &str) -> Result<bool> {
    let tx = c.transaction()?;
    let id: Option<i64> = tx
        .query_row("SELECT id FROM users WHERE email = ?1", [email.to_ascii_lowercase()], |r| r.get(0))
        .optional()?;
    let Some(id) = id else { return Ok(false) };
    tx.execute(
        "UPDATE blobs SET refcount = refcount - (SELECT COUNT(*) FROM messages m JOIN mailboxes b ON m.mailbox_id = b.id
           WHERE b.user_id = ?1 AND m.blob = blobs.hash)
         WHERE hash IN (SELECT m.blob FROM messages m JOIN mailboxes b ON m.mailbox_id = b.id WHERE b.user_id = ?1)",
        [id],
    )?;
    tx.execute("DELETE FROM users WHERE id = ?1", [id])?;
    tx.commit()?;
    Ok(true)
}

pub fn user_usage(c: &Connection, user_id: i64) -> Result<i64> {
    Ok(c.query_row(
        "SELECT COALESCE(SUM(m.size), 0) FROM messages m JOIN mailboxes b ON m.mailbox_id = b.id WHERE b.user_id = ?1",
        [user_id],
        |r| r.get(0),
    )?)
}

fn row_domain(r: &rusqlite::Row) -> rusqlite::Result<Domain> {
    Ok(Domain { name: r.get(0)?, dkim_selector: r.get(1)?, dkim_key: r.get(2)?, catch_all: r.get(3)?, alias_of: r.get(4)? })
}

pub fn find_domain(c: &Connection, name: &str) -> Result<Option<Domain>> {
    Ok(c.query_row(
        "SELECT name, dkim_selector, dkim_key, catch_all, alias_of FROM domains WHERE name = ?1",
        [name.to_ascii_lowercase()],
        row_domain,
    )
    .optional()?)
}

pub fn list_domains(c: &Connection) -> Result<Vec<Domain>> {
    let mut st = c.prepare("SELECT name, dkim_selector, dkim_key, catch_all, alias_of FROM domains ORDER BY name")?;
    let v = st.query_map([], row_domain)?.collect::<Result<Vec<_>, _>>()?;
    Ok(v)
}

pub fn add_domain(c: &Connection, name: &str, selector: &str, key_pem: &str) -> Result<()> {
    c.execute(
        "INSERT INTO domains(name, dkim_selector, dkim_key) VALUES(?1, ?2, ?3)",
        params![name.to_ascii_lowercase(), selector, key_pem],
    )?;
    Ok(())
}

pub fn add_alias_domain(c: &Connection, alias: &str, target: &str, dkim: Option<(&str, &str)>) -> Result<()> {
    let target = target.to_ascii_lowercase();
    if find_domain(c, &target)?.is_none() {
        bail!("target domain {target} is not hosted here");
    }
    c.execute(
        "INSERT INTO domains(name, alias_of, dkim_selector, dkim_key) VALUES(?1, ?2, ?3, ?4)",
        params![alias.to_ascii_lowercase(), target, dkim.map(|d| d.0), dkim.map(|d| d.1)],
    )?;
    Ok(())
}

pub fn set_dkim(c: &Connection, domain: &str, selector: &str, key_pem: &str) -> Result<bool> {
    Ok(c.execute(
        "UPDATE domains SET dkim_selector = ?2, dkim_key = ?3 WHERE name = ?1",
        params![domain.to_ascii_lowercase(), selector, key_pem],
    )? > 0)
}

pub fn set_catch_all(c: &Connection, domain: &str, target: Option<&str>) -> Result<bool> {
    Ok(c.execute(
        "UPDATE domains SET catch_all = ?2 WHERE name = ?1",
        params![domain.to_ascii_lowercase(), target.map(|t| t.to_ascii_lowercase())],
    )? > 0)
}

pub fn delete_domain(c: &Connection, name: &str) -> Result<bool> {
    let name = name.to_ascii_lowercase();
    let users: i64 = c.query_row("SELECT COUNT(*) FROM users WHERE email LIKE '%@' || ?1", [&name], |r| r.get(0))?;
    if users > 0 {
        bail!("domain still has {users} user(s); delete them first");
    }
    c.execute("DELETE FROM aliases WHERE source LIKE '%@' || ?1", [&name])?;
    Ok(c.execute("DELETE FROM domains WHERE name = ?1", [&name])? > 0)
}

pub fn add_alias(c: &Connection, source: &str, target: &str) -> Result<()> {
    let source = source.to_ascii_lowercase();
    let domain = source.rsplit_once('@').map(|x| x.1).ok_or_else(|| anyhow!("invalid alias address"))?;
    if find_domain(c, domain)?.is_none() {
        bail!("domain {domain} is not hosted here");
    }
    c.execute("INSERT OR IGNORE INTO aliases(source, target) VALUES(?1, ?2)", params![source, target.to_ascii_lowercase()])?;
    Ok(())
}

pub fn remove_alias(c: &Connection, source: &str, target: Option<&str>) -> Result<usize> {
    let source = source.to_ascii_lowercase();
    Ok(match target {
        Some(t) => c.execute("DELETE FROM aliases WHERE source = ?1 AND target = ?2", params![source, t.to_ascii_lowercase()])?,
        None => c.execute("DELETE FROM aliases WHERE source = ?1", [source])?,
    })
}

pub fn alias_targets(c: &Connection, source: &str) -> Result<Vec<String>> {
    let mut st = c.prepare("SELECT target FROM aliases WHERE source = ?1")?;
    let v = st.query_map([source.to_ascii_lowercase()], |r| r.get(0))?.collect::<Result<Vec<String>, _>>()?;
    Ok(v)
}

pub fn list_aliases(c: &Connection) -> Result<Vec<(String, String)>> {
    let mut st = c.prepare("SELECT source, target FROM aliases ORDER BY source")?;
    let v = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<Vec<_>, _>>()?;
    Ok(v)
}

/// Addresses (aliases) that deliver to this user and may therefore be used as a sender.
pub fn sender_addresses(c: &Connection, user: &User) -> Result<Vec<String>> {
    let mut st = c.prepare("SELECT source FROM aliases WHERE target = ?1")?;
    let mut v = st.query_map([&user.email], |r| r.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?;
    v.push(user.email.clone());
    // local@alias-domain is the same mailbox as local@domain.
    let mut extra = Vec::new();
    for a in &v {
        if let Some((local, dom)) = a.rsplit_once('@') {
            let mut st = c.prepare("SELECT name FROM domains WHERE alias_of = ?1")?;
            for d in st.query_map([dom], |r| r.get::<_, String>(0))? {
                extra.push(format!("{local}@{}", d?));
            }
        }
    }
    v.extend(extra);
    Ok(v)
}

// ---------------------------------------------------------------- mailboxes

pub fn new_uidvalidity() -> i64 {
    // Seconds since epoch fits in u32 until 2106 and is strictly increasing across recreations.
    (now() as u32).max(1) as i64
}

fn row_mailbox(r: &rusqlite::Row) -> rusqlite::Result<Mailbox> {
    Ok(Mailbox {
        id: r.get(0)?,
        name: r.get(1)?,
        uidvalidity: r.get::<_, i64>(2)? as u32,
        uidnext: r.get::<_, i64>(3)? as u32,
        subscribed: r.get::<_, i64>(4)? != 0,
        special: r.get(5)?,
    })
}

pub fn list_mailboxes(c: &Connection, user_id: i64) -> Result<Vec<Mailbox>> {
    let mut st = c.prepare(
        "SELECT id, name, uidvalidity, uidnext, subscribed, special FROM mailboxes WHERE user_id = ?1 ORDER BY name",
    )?;
    let v = st.query_map([user_id], row_mailbox)?.collect::<Result<Vec<_>, _>>()?;
    Ok(v)
}

pub fn find_mailbox(c: &Connection, user_id: i64, name: &str) -> Result<Option<Mailbox>> {
    let name = normalise_mailbox(name);
    Ok(c.query_row(
        "SELECT id, name, uidvalidity, uidnext, subscribed, special FROM mailboxes WHERE user_id = ?1 AND name = ?2",
        params![user_id, name],
        row_mailbox,
    )
    .optional()?)
}

pub fn normalise_mailbox(name: &str) -> String {
    if name.eq_ignore_ascii_case("INBOX") {
        "INBOX".into()
    } else {
        name.trim_end_matches('/').to_string()
    }
}

pub fn create_mailbox(c: &Connection, user_id: i64, name: &str) -> Result<()> {
    let name = normalise_mailbox(name);
    if name.is_empty() || name.split('/').any(|s| s.is_empty()) {
        bail!("invalid mailbox name");
    }
    // Create missing parents too (RFC 3501 6.3.3).
    let parts: Vec<&str> = name.split('/').collect();
    for i in 1..=parts.len() {
        let n = parts[..i].join("/");
        c.execute(
            "INSERT OR IGNORE INTO mailboxes(user_id, name, uidvalidity) VALUES(?1, ?2, ?3)",
            params![user_id, n, new_uidvalidity()],
        )?;
    }
    Ok(())
}

pub fn delete_mailbox(c: &mut Connection, user_id: i64, name: &str) -> Result<()> {
    let mb = find_mailbox(c, user_id, name)?.ok_or_else(|| anyhow!("no such mailbox"))?;
    if mb.name == "INBOX" {
        bail!("cannot delete INBOX");
    }
    let tx = c.transaction()?;
    tx.execute(
        "UPDATE blobs SET refcount = refcount - (SELECT COUNT(*) FROM messages WHERE mailbox_id = ?1 AND blob = blobs.hash)
         WHERE hash IN (SELECT blob FROM messages WHERE mailbox_id = ?1)",
        [mb.id],
    )?;
    tx.execute("DELETE FROM mailboxes WHERE id = ?1", [mb.id])?;
    tx.commit()?;
    Ok(())
}

pub fn rename_mailbox(c: &mut Connection, user_id: i64, from: &str, to: &str) -> Result<()> {
    let from = normalise_mailbox(from);
    let to = normalise_mailbox(to);
    if find_mailbox(c, user_id, &to)?.is_some() {
        bail!("target mailbox exists");
    }
    if from == "INBOX" {
        // RFC 3501: renaming INBOX moves its messages to the new mailbox, leaving INBOX empty.
        create_mailbox(c, user_id, &to)?;
        let src = find_mailbox(c, user_id, "INBOX")?.unwrap();
        let dst = find_mailbox(c, user_id, &to)?.unwrap();
        let uids: Vec<u32> = list_messages(c, src.id)?.iter().map(|m| m.uid).collect();
        move_messages(c, src.id, dst.id, &uids)?;
        return Ok(());
    }
    let tx = c.transaction()?;
    let n = tx.execute("UPDATE mailboxes SET name = ?3 WHERE user_id = ?1 AND name = ?2", params![user_id, from, to])?;
    if n == 0 {
        bail!("no such mailbox");
    }
    // Children move with their parent.
    tx.execute(
        "UPDATE mailboxes SET name = ?3 || substr(name, length(?2) + 1) WHERE user_id = ?1 AND name LIKE ?2 || '/%'",
        params![user_id, from, to],
    )?;
    tx.commit()?;
    Ok(())
}

pub fn set_subscribed(c: &Connection, user_id: i64, name: &str, sub: bool) -> Result<bool> {
    Ok(c.execute(
        "UPDATE mailboxes SET subscribed = ?3 WHERE user_id = ?1 AND name = ?2",
        params![user_id, normalise_mailbox(name), sub as i64],
    )? > 0)
}

// ----------------------------------------------------------------- messages

pub fn flags_to_string(flags: &[String]) -> String {
    flags.join(" ")
}

fn row_msg(r: &rusqlite::Row) -> rusqlite::Result<MsgMeta> {
    let flags: String = r.get(5)?;
    Ok(MsgMeta {
        id: r.get(0)?,
        uid: r.get::<_, i64>(1)? as u32,
        blob: r.get(2)?,
        size: r.get(3)?,
        internal_date: r.get(4)?,
        flags: flags.split_whitespace().map(String::from).collect(),
    })
}

pub fn list_messages(c: &Connection, mailbox_id: i64) -> Result<Vec<MsgMeta>> {
    let mut st = c.prepare_cached(
        "SELECT id, uid, blob, size, internal_date, flags FROM messages WHERE mailbox_id = ?1 ORDER BY uid",
    )?;
    let v = st.query_map([mailbox_id], row_msg)?.collect::<Result<Vec<_>, _>>()?;
    Ok(v)
}

/// Append a message (blob must already be written). Returns the new UID.
pub fn append_message(
    c: &mut Connection,
    mailbox_id: i64,
    blob: &str,
    size: i64,
    internal_date: i64,
    flags: &[String],
) -> Result<u32> {
    let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let uid: i64 = tx.query_row("SELECT uidnext FROM mailboxes WHERE id = ?1", [mailbox_id], |r| r.get(0))?;
    tx.execute("UPDATE mailboxes SET uidnext = uidnext + 1 WHERE id = ?1", [mailbox_id])?;
    tx.execute(
        "INSERT INTO messages(mailbox_id, uid, blob, size, internal_date, flags) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        params![mailbox_id, uid, blob, size, internal_date, flags_to_string(flags)],
    )?;
    blob_ref(&tx, blob, 1)?;
    tx.commit()?;
    Ok(uid as u32)
}

/// Insert a message keeping a specific UID (used when importing from Dovecot so mail
/// clients don't need to re-download). Caller must ensure the UID is free.
pub fn insert_with_uid(
    c: &Connection,
    mailbox_id: i64,
    uid: u32,
    blob: &str,
    size: i64,
    internal_date: i64,
    flags: &[String],
) -> Result<()> {
    c.execute(
        "INSERT INTO messages(mailbox_id, uid, blob, size, internal_date, flags) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        params![mailbox_id, uid, blob, size, internal_date, flags_to_string(flags)],
    )?;
    c.execute("UPDATE mailboxes SET uidnext = MAX(uidnext, ?2 + 1) WHERE id = ?1", params![mailbox_id, uid])?;
    blob_ref(c, blob, 1)?;
    Ok(())
}

pub fn set_uid_state(c: &Connection, mailbox_id: i64, uidvalidity: u32, uidnext: u32) -> Result<()> {
    c.execute(
        "UPDATE mailboxes SET uidvalidity = ?2, uidnext = MAX(uidnext, ?3) WHERE id = ?1",
        params![mailbox_id, uidvalidity, uidnext],
    )?;
    Ok(())
}

pub fn set_flags(c: &Connection, msg_id: i64, flags: &[String]) -> Result<()> {
    c.execute("UPDATE messages SET flags = ?2 WHERE id = ?1", params![msg_id, flags_to_string(flags)])?;
    Ok(())
}

/// Copy messages by UID; returns (src_uid, dst_uid) pairs for COPYUID.
pub fn copy_messages(c: &mut Connection, src: i64, dst: i64, uids: &[u32]) -> Result<Vec<(u32, u32)>> {
    let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let mut out = Vec::new();
    for &uid in uids {
        let row: Option<(String, i64, i64, String)> = tx
            .query_row(
                "SELECT blob, size, internal_date, flags FROM messages WHERE mailbox_id = ?1 AND uid = ?2",
                params![src, uid],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let Some((blob, size, date, flags)) = row else { continue };
        let new_uid: i64 = tx.query_row("SELECT uidnext FROM mailboxes WHERE id = ?1", [dst], |r| r.get(0))?;
        tx.execute("UPDATE mailboxes SET uidnext = uidnext + 1 WHERE id = ?1", [dst])?;
        tx.execute(
            "INSERT INTO messages(mailbox_id, uid, blob, size, internal_date, flags) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![dst, new_uid, blob, size, date, flags],
        )?;
        blob_ref(&tx, &blob, 1)?;
        out.push((uid, new_uid as u32));
    }
    tx.commit()?;
    Ok(out)
}

pub fn move_messages(c: &mut Connection, src: i64, dst: i64, uids: &[u32]) -> Result<Vec<(u32, u32)>> {
    let pairs = copy_messages(c, src, dst, uids)?;
    let moved: Vec<u32> = pairs.iter().map(|p| p.0).collect();
    expunge_uids(c, src, &moved)?;
    Ok(pairs)
}

pub fn expunge_uids(c: &mut Connection, mailbox_id: i64, uids: &[u32]) -> Result<()> {
    let tx = c.transaction()?;
    for &uid in uids {
        let blob: Option<String> = tx
            .query_row("SELECT blob FROM messages WHERE mailbox_id = ?1 AND uid = ?2", params![mailbox_id, uid], |r| r.get(0))
            .optional()?;
        if let Some(b) = blob {
            tx.execute("DELETE FROM messages WHERE mailbox_id = ?1 AND uid = ?2", params![mailbox_id, uid])?;
            blob_ref(&tx, &b, -1)?;
        }
    }
    tx.commit()?;
    Ok(())
}

// -------------------------------------------------------------------- queue

pub fn enqueue(c: &mut Connection, mail_from: &str, domain: &str, rcpts: &[String], blob: &str) -> Result<i64> {
    let tx = c.transaction()?;
    tx.execute(
        "INSERT INTO queue(mail_from, domain, rcpts, blob, next_attempt, created) VALUES(?1, ?2, ?3, ?4, ?5, ?5)",
        params![mail_from, domain, rcpts.join("\n"), blob, now()],
    )?;
    let id = tx.last_insert_rowid();
    blob_ref(&tx, blob, 1)?;
    tx.commit()?;
    Ok(id)
}

fn row_queue(r: &rusqlite::Row) -> rusqlite::Result<QueueItem> {
    let rcpts: String = r.get(3)?;
    Ok(QueueItem {
        id: r.get(0)?,
        mail_from: r.get(1)?,
        domain: r.get(2)?,
        rcpts: rcpts.lines().map(String::from).collect(),
        blob: r.get(4)?,
        attempts: r.get(5)?,
        created: r.get(6)?,
        last_error: r.get(7)?,
        next_attempt: r.get(8)?,
    })
}

const QUEUE_COLS: &str = "id, mail_from, domain, rcpts, blob, attempts, created, last_error, next_attempt";

/// Claim due items by pushing their next attempt into the future (lease), so a crash
/// mid-delivery simply retries later.
pub fn claim_due(c: &mut Connection, limit: usize, lease_secs: i64) -> Result<Vec<QueueItem>> {
    let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let t = now();
    let items = {
        let mut st = tx.prepare(&format!(
            "SELECT {QUEUE_COLS} FROM queue WHERE next_attempt <= ?1 ORDER BY next_attempt LIMIT ?2"
        ))?;
        let v = st.query_map(params![t, limit as i64], row_queue)?.collect::<Result<Vec<_>, _>>()?;
        v
    };
    for it in &items {
        tx.execute("UPDATE queue SET next_attempt = ?2 WHERE id = ?1", params![it.id, t + lease_secs])?;
    }
    tx.commit()?;
    Ok(items)
}

pub fn list_queue(c: &Connection) -> Result<Vec<QueueItem>> {
    let mut st = c.prepare(&format!("SELECT {QUEUE_COLS} FROM queue ORDER BY created"))?;
    let v = st.query_map([], row_queue)?.collect::<Result<Vec<_>, _>>()?;
    Ok(v)
}

pub fn queue_done(c: &mut Connection, id: i64) -> Result<()> {
    let tx = c.transaction()?;
    let blob: Option<String> = tx.query_row("SELECT blob FROM queue WHERE id = ?1", [id], |r| r.get(0)).optional()?;
    tx.execute("DELETE FROM queue WHERE id = ?1", [id])?;
    if let Some(b) = blob {
        blob_ref(&tx, &b, -1)?;
    }
    tx.commit()?;
    Ok(())
}

pub fn queue_retry(c: &Connection, id: i64, rcpts: &[String], next: i64, err: &str) -> Result<()> {
    c.execute(
        "UPDATE queue SET attempts = attempts + 1, next_attempt = ?2, last_error = ?3, rcpts = ?4 WHERE id = ?1",
        params![id, next, err, rcpts.join("\n")],
    )?;
    Ok(())
}

pub fn queue_flush(c: &Connection) -> Result<usize> {
    Ok(c.execute("UPDATE queue SET next_attempt = ?1", [now()])?)
}
