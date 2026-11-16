//! Migrations from other mail systems: Exchange Online (Microsoft Graph), Google
//! Workspace (Gmail, Calendar and People APIs), Exchange on-premises and any IMAP server,
//! and exported files (Google Takeout mbox, .ics, .vcf).
//!
//! Every copied item is recorded by a key derived from its source identity, so a
//! migration can be run again at any time and only copies what's new. That allows a bulk
//! copy days before switching MX records, then a quick catch-up afterwards.

pub mod files;
pub mod google;
pub mod graph;
pub mod ical;
pub mod imap;
pub mod net;

use crate::server::Shared;
use crate::store::{self, User};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as AsyncMutex;

pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS migrated(
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    PRIMARY KEY(user_id, key)
) WITHOUT ROWID;
"#;

// ------------------------------------------------------------------- jobs

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Source {
    /// Any IMAP server: Exchange on-premises, Dovecot, Zimbra, Gmail, Yahoo, ...
    Imap {
        host: String,
        #[serde(default = "default_imap_port")]
        port: u16,
        /// "tls" (port 993), "starttls" (port 143) or "none" (testing only).
        #[serde(default = "default_security")]
        security: String,
        /// Sign in to every mailbox with one administrator account instead of each
        /// user's own password.
        #[serde(default)]
        admin: Option<ImapAdmin>,
        /// Accept self-signed certificates on the old server.
        #[serde(default)]
        insecure: bool,
    },
    /// Microsoft 365 / Exchange Online through Microsoft Graph, with an app registration.
    ExchangeOnline {
        tenant: String,
        client_id: String,
        client_secret: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        graph_url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        login_url: Option<String>,
    },
    /// Google Workspace through a service account with domain-wide delegation.
    Google {
        /// The service account's JSON key file contents.
        service_account: String,
        /// A Workspace administrator, used to list users.
        admin_email: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        api_url: Option<String>,
    },
}

fn default_imap_port() -> u16 {
    993
}
fn default_security() -> String {
    "tls".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImapAdmin {
    pub user: String,
    pub password: String,
    /// "plain" – SASL PLAIN with the mailbox as authorisation identity (Exchange,
    /// Zimbra, Cyrus); "dovecot" – master user login "mailbox*admin".
    #[serde(default = "default_admin_style")]
    pub style: String,
}

fn default_admin_style() -> String {
    "plain".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxMap {
    /// Sign-in name or address on the old system.
    pub source: String,
    /// The user's own password on the old system (IMAP without an admin account).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Address on this server.
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Options {
    pub mail: bool,
    pub calendars: bool,
    pub contacts: bool,
    /// Create users (and domains) that don't exist here yet, with new passwords.
    pub create_users: bool,
    /// Only copy mail received on or after this date (YYYY-MM-DD).
    pub since: Option<String>,
    /// Old-system folder names to leave behind.
    pub skip_folders: Vec<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self { mail: true, calendars: true, contacts: true, create_users: true, since: None, skip_folders: vec![] }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub source: Source,
    pub mailboxes: Vec<MailboxMap>,
    #[serde(default)]
    pub options: Options,
}

impl Job {
    pub fn describe(&self) -> String {
        match &self.source {
            Source::Imap { host, .. } => format!("IMAP server {host}"),
            Source::ExchangeOnline { tenant, .. } => format!("Exchange Online ({tenant})"),
            Source::Google { admin_email, .. } => format!("Google Workspace ({})", admin_email.rsplit('@').next().unwrap_or("")),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Discovered {
    pub source: String,
    pub name: Option<String>,
    pub target: String,
    pub kind: String,
    pub exists_here: bool,
}

/// List the mailboxes on the old system, where it can be asked.
pub async fn discover(srv: &Shared, source: &Source) -> Result<Vec<Discovered>> {
    let mut list = match source {
        Source::ExchangeOnline { .. } => graph::discover(source).await?,
        Source::Google { .. } => google::discover(source).await?,
        Source::Imap { .. } => bail!("IMAP servers can't list their mailboxes: enter them, or paste a list"),
    };
    let targets: Vec<String> = list.iter().map(|d| d.target.clone()).collect();
    let exists = srv
        .store
        .call(move |c| targets.iter().map(|t| Ok(store::find_user(c, t)?.is_some())).collect::<Result<Vec<bool>>>())
        .await?;
    for (d, e) in list.iter_mut().zip(exists) {
        d.exists_here = e;
    }
    Ok(list)
}

/// Check that the old system accepts the given details (one mailbox for IMAP).
pub async fn test(source: &Source, mb: Option<&MailboxMap>) -> Result<String> {
    match source {
        Source::Imap { .. } => {
            let mb = mb.ok_or_else(|| anyhow!("enter at least one mailbox to test"))?;
            imap::test(source, mb).await
        }
        Source::ExchangeOnline { .. } => Ok(format!("Connected: {} mailboxes found", graph::discover(source).await?.len())),
        Source::Google { .. } => Ok(format!("Connected: {} users found", google::discover(source).await?.len())),
    }
}

// --------------------------------------------------------------- progress

#[derive(Debug, Clone, Serialize, Default)]
pub struct MbProgress {
    pub source: String,
    pub target: String,
    pub state: String,
    pub step: String,
    pub messages: u64,
    pub skipped: u64,
    pub bytes: u64,
    pub events: u64,
    pub contacts: u64,
    pub errors: u64,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Progress {
    pub running: bool,
    pub source: String,
    pub started: Option<i64>,
    pub finished: Option<i64>,
    pub cancelled: bool,
    pub error: Option<String>,
    pub mailboxes: Vec<MbProgress>,
    pub log: VecDeque<String>,
    /// Accounts created by this run, with their new passwords (kept in memory only).
    pub created: Vec<(String, String)>,
}

static PROGRESS: Mutex<Option<Progress>> = Mutex::new(None);
static CANCEL: AtomicBool = AtomicBool::new(false);

pub fn progress() -> Progress {
    PROGRESS.lock().unwrap().clone().unwrap_or_default()
}

pub(crate) fn with<T>(f: impl FnOnce(&mut Progress) -> T) -> T {
    let mut g = PROGRESS.lock().unwrap();
    f(g.get_or_insert_with(Progress::default))
}

pub fn log(msg: impl Into<String>) {
    let msg = msg.into();
    tracing::info!("migration: {msg}");
    with(|p| {
        p.log.push_back(format!("{} {msg}", chrono::Local::now().format("%H:%M:%S")));
        while p.log.len() > 1000 {
            p.log.pop_front();
        }
    });
}

pub fn cancelled() -> bool {
    CANCEL.load(Ordering::Relaxed)
}

pub fn cancel() {
    CANCEL.store(true, Ordering::Relaxed);
}

/// Forget the passwords of accounts created by the last run.
pub fn clear_created() {
    with(|p| p.created.clear());
}

/// Per-mailbox progress handle.
#[derive(Clone)]
pub struct Tick(usize);

impl Tick {
    pub fn step(&self, s: impl Into<String>) {
        let s = s.into();
        with(|p| p.mailboxes[self.0].step = s);
    }
    pub fn message(&self, bytes: usize) {
        with(|p| {
            p.mailboxes[self.0].messages += 1;
            p.mailboxes[self.0].bytes += bytes as u64;
        });
    }
    pub fn skipped(&self) {
        with(|p| p.mailboxes[self.0].skipped += 1);
    }
    pub fn event(&self) {
        with(|p| p.mailboxes[self.0].events += 1);
    }
    pub fn contact(&self) {
        with(|p| p.mailboxes[self.0].contacts += 1);
    }
    pub fn error(&self, what: &str, e: &anyhow::Error) {
        let line = format!("{what}: {e:#}");
        let src = with(|p| {
            let m = &mut p.mailboxes[self.0];
            m.errors += 1;
            m.last_error = Some(line.clone());
            m.source.clone()
        });
        log(format!("{src}: {line}"));
    }
    fn state(&self, s: &str) {
        with(|p| p.mailboxes[self.0].state = s.to_string());
    }
}

// ----------------------------------------------------------------- target

/// Writes into one Postwright account.
pub struct Target {
    pub srv: Shared,
    pub user: User,
    pub opts: Options,
    folders: AsyncMutex<HashMap<String, i64>>,
    since: Option<i64>,
}

impl Target {
    pub fn new(srv: Shared, user: User, opts: Options) -> Self {
        let since = opts
            .since
            .as_deref()
            .and_then(|s| chrono::NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d").ok())
            .and_then(|d| d.and_hms_opt(0, 0, 0))
            .map(|d| d.and_utc().timestamp());
        Self { srv, user, opts, folders: AsyncMutex::new(HashMap::new()), since }
    }

    pub fn since(&self) -> Option<i64> {
        self.since
    }

    pub fn skip_folder(&self, source_name: &str) -> bool {
        self.opts.skip_folders.iter().any(|f| f.eq_ignore_ascii_case(source_name.trim()))
    }

    fn key(&self, k: &str) -> String {
        hex::encode(&Sha256::digest(k.as_bytes())[..16])
    }

    /// Already copied on an earlier run?
    pub async fn seen(&self, key: &str) -> Result<bool> {
        let (uid, k) = (self.user.id, self.key(key));
        self.srv
            .store
            .call(move |c| Ok(c.query_row("SELECT 1 FROM migrated WHERE user_id = ?1 AND key = ?2", rusqlite::params![uid, k], |_| Ok(())).is_ok()))
            .await
    }

    async fn folder_id(&self, name: &str) -> Result<i64> {
        let name = &imap::encode_mutf7(name);
        let mut cache = self.folders.lock().await;
        if let Some(id) = cache.get(name) {
            return Ok(*id);
        }
        let (uid, n) = (self.user.id, name.to_string());
        let id = self
            .srv
            .store
            .call(move |c| {
                if store::find_mailbox(c, uid, &n)?.is_none() {
                    store::create_mailbox(c, uid, &n)?;
                }
                store::find_mailbox(c, uid, &n)?.map(|m| m.id).ok_or_else(|| anyhow!("couldn't create folder {n}"))
            })
            .await?;
        cache.insert(name.to_string(), id);
        Ok(id)
    }

    /// Store one message in a folder (created if needed) and remember its key.
    pub async fn add_message(&self, key: &str, folder: &str, raw: Vec<u8>, date: i64, flags: Vec<String>) -> Result<()> {
        let fid = self.folder_id(folder).await?;
        let raw = Arc::new(crate::iredmail::to_crlf(&raw));
        let size = raw.len() as i64;
        let blob = self.srv.store.put_blob(raw).await?;
        let (uid, k) = (self.user.id, self.key(key));
        self.srv
            .store
            .call(move |c| {
                store::append_message(c, fid, &blob, size, date, &flags)?;
                c.execute("INSERT OR IGNORE INTO migrated(user_id, key) VALUES(?1, ?2)", rusqlite::params![uid, k])?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Store a calendar object (one event or one repeating series with its exceptions)
    /// in the named calendar. The first calendar a migration writes to is the user's
    /// default one, so "Calendar" on the old system lands in "Calendar" here.
    pub async fn add_event(&self, calendar: &str, ics: String) -> Result<bool> {
        let (uid, cal) = (self.user.id, calendar.to_string());
        self.srv
            .store
            .call(move |c| {
                let id = crate::caldav::calendar_named(c, uid, &cal)?;
                crate::caldav::import_object(c, id, &ics)
            })
            .await
    }

    pub async fn add_contact(&self, book: &str, vcf: String) -> Result<bool> {
        let (u, b) = (self.user.clone(), book.to_string());
        self.srv
            .store
            .call(move |c| {
                let id = crate::carddav::book_named(c, &u, &b)?;
                crate::carddav::import_card(c, id, &vcf)
            })
            .await
    }

    pub fn notify(&self) {
        self.srv.notify_user(self.user.id);
    }
}

// ---------------------------------------------------------- folder mapping

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Special {
    Inbox,
    Sent,
    Drafts,
    Trash,
    Junk,
    Archive,
    /// Views of mail held elsewhere (Gmail's All Mail, Important, Starred): skipped.
    Virtual,
    /// Not mail (Exchange's Calendar, Contacts, Tasks, Sync Issues, Outbox): skipped.
    NotMail,
}

/// Guess a folder's role from its name when the server doesn't say.
pub fn special_by_name(path: &[String]) -> Option<Special> {
    let full = path.join("/").to_ascii_lowercase();
    let last = path.last().map(|s| s.to_ascii_lowercase()).unwrap_or_default();
    let top = path.first().map(|s| s.to_ascii_lowercase()).unwrap_or_default();
    if path.len() == 1 && top == "inbox" {
        return Some(Special::Inbox);
    }
    if matches!(full.as_str(), "[gmail]/all mail" | "[gmail]/important" | "[gmail]/starred" | "[google mail]/all mail" | "[google mail]/important" | "[google mail]/starred") {
        return Some(Special::Virtual);
    }
    if ["calendar", "contacts", "tasks", "notes", "journal", "outbox", "sync issues", "conflicts", "local failures", "server failures", "recoverable items", "suggested contacts", "conversation action settings", "quick step settings", "yammer root", "files", "recipient cache", "personmetadata", "companycontacts", "gal contacts", "organizational contacts"]
        .contains(&top.as_str())
    {
        return Some(Special::NotMail);
    }
    if path.len() > 2 || (path.len() == 2 && !top.starts_with('[')) {
        return None;
    }
    Some(match last.as_str() {
        "sent" | "sent items" | "sent mail" | "sent messages" | "sent-mail" | "gesendete elemente" | "gesendet" | "envoyés" | "éléments envoyés" | "verzonden items" => Special::Sent,
        "drafts" | "draft" | "entwürfe" | "brouillons" | "concepten" => Special::Drafts,
        "trash" | "bin" | "deleted items" | "deleted messages" | "deleted" | "gelöschte elemente" | "papierkorb" | "éléments supprimés" | "corbeille" | "verwijderde items" => Special::Trash,
        "junk" | "junk email" | "junk e-mail" | "spam" | "junk mail" | "bulk mail" | "junk-e-mail" | "courrier indésirable" | "ongewenste e-mail" => Special::Junk,
        "archive" | "archives" | "archiv" => Special::Archive,
        _ => return None,
    })
}

/// The Postwright folder for a folder path on the old system, or None to skip it.
pub fn map_folder(path: &[String], special: Option<Special>) -> Option<String> {
    let special = special.or_else(|| special_by_name(path));
    let clean: Vec<String> = path.iter().map(|s| s.replace('/', "-").trim().to_string()).filter(|s| !s.is_empty()).collect();
    match special {
        Some(Special::Virtual | Special::NotMail) => None,
        Some(Special::Inbox) => Some("INBOX".into()),
        Some(Special::Sent) => Some("Sent".into()),
        Some(Special::Drafts) => Some("Drafts".into()),
        Some(Special::Trash) => Some("Trash".into()),
        Some(Special::Junk) => Some("Junk".into()),
        Some(Special::Archive) => Some("Archive".into()),
        None if clean.is_empty() => None,
        None => {
            let mut v = clean;
            if v[0].eq_ignore_ascii_case("inbox") {
                v[0] = "INBOX".into();
            }
            // "[Gmail]/Foo" style containers aren't real folders.
            if v.len() > 1 && v[0].starts_with('[') && v[0].ends_with(']') {
                v.remove(0);
            }
            Some(v.join("/"))
        }
    }
}

/// Keep IMAP flags a Postwright folder understands.
pub fn clean_flags(flags: impl IntoIterator<Item = String>) -> Vec<String> {
    flags
        .into_iter()
        .filter(|f| {
            let l = f.to_ascii_lowercase();
            l != "\\recent" && l != "\\*" && !f.is_empty() && !f.contains(['(', ')', '"', ' ', '{'])
        })
        .collect()
}

// ------------------------------------------------------------------ runner

fn new_password() -> String {
    const CH: &[u8] = b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut r = rand::thread_rng();
    (0..16).map(|_| CH[rand::Rng::gen_range(&mut r, 0..CH.len())] as char).collect()
}

/// Make sure the target account (and its domain) exist. Returns the user and, when one
/// was created, its new password.
pub(crate) async fn prepare_target(srv: &Shared, m: &MailboxMap, create: bool) -> Result<(User, Option<String>)> {
    let email = m.target.trim().to_ascii_lowercase();
    if !email.contains('@') {
        bail!("{email} isn't an email address");
    }
    let e = email.clone();
    if let Some(u) = srv.store.call(move |c| store::find_user(c, &e)).await? {
        return Ok((u, None));
    }
    if !create {
        bail!("{email} doesn't exist here (turn on \"create users\" or add it first)");
    }
    let domain = email.rsplit_once('@').map(|x| x.1.to_string()).unwrap_or_default();
    // Several mailboxes in the same new domain are prepared at once: create it only once.
    static DOMAIN_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _g = DOMAIN_LOCK.lock().await;
    let d2 = domain.clone();
    if srv.store.call(move |c| store::find_domain(c, &d2)).await?.is_none() {
        let (pem, _) = tokio::task::spawn_blocking(crate::delivery::generate_dkim_key).await??;
        let d3 = domain.clone();
        srv.store.call(move |c| store::add_domain(c, &d3, "pw1", &pem)).await?;
        log(format!("added domain {domain} (publish its DNS records before switching MX)"));
    }
    let pw = new_password();
    let hash = crate::auth::hash_password(&pw)?;
    let (e, name) = (email.clone(), m.name.clone());
    let u = srv
        .store
        .call(move |c| {
            store::create_user(c, &e, &hash, 0)?;
            let u = store::find_user(c, &e)?.ok_or_else(|| anyhow!("user vanished"))?;
            if let Some(n) = &name {
                store::set_display_name(c, u.id, Some(n))?;
            }
            Ok(u)
        })
        .await?;
    log(format!("created account {email}"));
    Ok((u, Some(pw)))
}

/// Mark a migration as started (fails if one is already running).
pub(crate) fn begin(desc: &str, mailboxes: &[MailboxMap]) -> Result<()> {
    let mut g = PROGRESS.lock().unwrap();
    if g.as_ref().map(|p| p.running).unwrap_or(false) {
        bail!("a migration is already running");
    }
    if mailboxes.is_empty() {
        bail!("choose at least one mailbox");
    }
    let keep_created = g.as_ref().map(|p| p.created.clone()).unwrap_or_default();
    *g = Some(Progress {
        running: true,
        source: desc.to_string(),
        started: Some(store::now()),
        mailboxes: mailboxes
            .iter()
            .map(|m| MbProgress { source: m.source.clone(), target: m.target.to_ascii_lowercase(), state: "waiting".into(), ..Default::default() })
            .collect(),
        created: keep_created,
        ..Default::default()
    });
    CANCEL.store(false, Ordering::Relaxed);
    drop(g);
    log(format!("migration from {desc} started: {} mailbox(es)", mailboxes.len()));
    Ok(())
}

/// Final state for one mailbox.
pub(crate) fn finish_one(i: usize) {
    with(|p| {
        let m = &mut p.mailboxes[i];
        if m.state == "failed" {
        } else if CANCEL.load(Ordering::Relaxed) {
            m.state = "cancelled".into();
        } else {
            m.state = if m.errors > 0 { "done with errors".into() } else { "done".into() };
        }
        m.step.clear();
    });
}

pub(crate) fn end() {
    let summary = with(|p| {
        p.running = false;
        p.finished = Some(store::now());
        p.cancelled = cancelled();
        let (m, e, c) = p.mailboxes.iter().fold((0, 0, 0), |a, x| (a.0 + x.messages, a.1 + x.events, a.2 + x.contacts));
        format!("{m} messages, {e} calendar items and {c} contacts copied")
    });
    log(format!("migration {}: {summary}", if cancelled() { "stopped" } else { "finished" }));
}

/// Start a migration in the background.
pub fn start(srv: Shared, job: Job) -> Result<()> {
    begin(&job.describe(), &job.mailboxes)?;
    // Remember the job so it can be run again (catch-up) later.
    if let Ok(text) = serde_json::to_string(&job) {
        let store = srv.store.clone();
        tokio::spawn(async move {
            let _ = store.call(move |c| store::set_meta(c, "migration.last_job", &text)).await;
        });
    }
    tokio::spawn(async move {
        let job = Arc::new(job);
        let sem = Arc::new(tokio::sync::Semaphore::new(3));
        let mut tasks = Vec::new();
        for (i, m) in job.mailboxes.iter().cloned().enumerate() {
            let (srv, job, sem) = (srv.clone(), job.clone(), sem.clone());
            tasks.push(tokio::spawn(async move {
                let _permit = sem.acquire().await;
                let tick = Tick(i);
                if !cancelled() {
                    tick.state("running");
                    if let Err(e) = run_one(&srv, &job, &m, &tick).await {
                        tick.error("failed", &e);
                        tick.state("failed");
                    }
                }
                finish_one(i);
            }));
        }
        for t in tasks {
            let _ = t.await;
        }
        end();
    });
    Ok(())
}

async fn run_one(srv: &Shared, job: &Job, m: &MailboxMap, tick: &Tick) -> Result<()> {
    tick.step("preparing account");
    let (user, pw) = prepare_target(srv, m, job.options.create_users).await?;
    if let Some(pw) = pw {
        with(|p| p.created.push((user.email.clone(), pw)));
    }
    let t = Target::new(srv.clone(), user, job.options.clone());
    let r = match &job.source {
        Source::Imap { .. } => imap::migrate(&job.source, m, &t, tick).await,
        Source::ExchangeOnline { .. } => graph::migrate(&job.source, m, &t, tick).await,
        Source::Google { .. } => google::migrate(&job.source, m, &t, tick).await,
    };
    t.notify();
    r
}

/// Run a job to completion (command line).
pub async fn run_blocking(srv: Shared, job: Job) -> Result<Progress> {
    start(srv, job)?;
    Ok(wait_blocking().await)
}

/// Print the log until the running migration finishes.
pub async fn wait_blocking() -> Progress {
    let mut last = 0;
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let p = progress();
        for l in p.log.iter().skip(last) {
            println!("{l}");
        }
        last = p.log.len();
        if !p.running {
            return p;
        }
    }
}

pub async fn last_job(srv: &Shared) -> Result<Option<Job>> {
    let t = srv.store.call(|c| store::get_meta(c, "migration.last_job")).await?;
    Ok(t.and_then(|t| serde_json::from_str(&t).ok()))
}

/// Strip secrets before sending a job to the browser.
pub fn redact(job: &Job) -> Value {
    let mut v = serde_json::to_value(job).unwrap_or(Value::Null);
    for k in ["client_secret", "service_account"] {
        if v["source"].get(k).is_some() {
            v["source"][k] = json!("(saved)");
        }
    }
    if let Some(a) = v["source"].get_mut("admin") {
        if a.get("password").is_some() {
            a["password"] = json!("(saved)");
        }
    }
    if let Some(list) = v["mailboxes"].as_array_mut() {
        for m in list {
            if m.get("password").is_some() {
                m["password"] = json!("(saved)");
            }
        }
    }
    v
}

/// Put saved secrets back where the browser sent "(saved)".
pub fn unredact(mut job: Job, saved: Option<&Job>) -> Job {
    let Some(old) = saved else { return job };
    let keep = |s: &mut String, o: &str| {
        if s == "(saved)" {
            *s = o.to_string();
        }
    };
    match (&mut job.source, &old.source) {
        (Source::ExchangeOnline { client_secret, .. }, Source::ExchangeOnline { client_secret: o, .. }) => keep(client_secret, o),
        (Source::Google { service_account, .. }, Source::Google { service_account: o, .. }) => keep(service_account, o),
        (Source::Imap { admin: Some(a), .. }, Source::Imap { admin: Some(o), .. }) => keep(&mut a.password, &o.password),
        _ => {}
    }
    for m in &mut job.mailboxes {
        if m.password.as_deref() == Some("(saved)") {
            m.password = old.mailboxes.iter().find(|o| o.source.eq_ignore_ascii_case(&m.source)).and_then(|o| o.password.clone());
        }
    }
    job
}

pub async fn forget_saved(srv: &Shared) -> Result<()> {
    srv.store.call(|c| Ok(c.execute("DELETE FROM meta WHERE key = 'migration.last_job'", [])?)).await?;
    Ok(())
}

/// Parse a pasted list of mailboxes: one per line, "source[,target[,password]]",
/// separated by commas, semicolons or tabs.
pub fn parse_list(text: &str, default_domain: Option<&str>) -> Vec<MailboxMap> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|l| !l.to_ascii_lowercase().starts_with("source"))
        .map(|l| {
            let parts: Vec<&str> = l.split([',', ';', '\t']).map(str::trim).collect();
            let source = parts[0].to_string();
            let mut target = parts.get(1).filter(|s| !s.is_empty()).map(|s| s.to_string()).unwrap_or_else(|| source.clone());
            if !target.contains('@') {
                if let Some(d) = default_domain {
                    target = format!("{target}@{d}");
                }
            }
            MailboxMap {
                source,
                target: target.to_ascii_lowercase(),
                password: parts.get(2).filter(|s| !s.is_empty()).map(|s| s.to_string()),
                name: None,
            }
        })
        .collect()
}

// ------------------------------------------------------- HTTP (console/wizard)

pub async fn api(srv: &Shared, method: &str, path: &[&str], body: &[u8]) -> Result<Value> {
    match (method, path) {
        ("GET", ["status"]) => {
            let p = progress();
            let last = last_job(srv).await?.map(|j| redact(&j));
            Ok(json!({ "progress": p, "last_job": last }))
        }
        ("POST", ["discover"]) => {
            let src: Source = serde_json::from_slice::<Value>(body)
                .context("invalid request")
                .and_then(|v| Ok(serde_json::from_value(v["source"].clone())?))?;
            let saved = last_job(srv).await?;
            let src = unredact(Job { source: src, mailboxes: vec![], options: Options::default() }, saved.as_ref()).source;
            Ok(json!(discover(srv, &src).await?))
        }
        ("POST", ["test"]) => {
            let job: Job = serde_json::from_slice(body).context("invalid request")?;
            let saved = last_job(srv).await?;
            let job = unredact(job, saved.as_ref());
            Ok(json!({ "message": test(&job.source, job.mailboxes.first()).await? }))
        }
        ("POST", ["parse-list"]) => {
            #[derive(Deserialize)]
            struct P {
                text: String,
                domain: Option<String>,
            }
            let p: P = serde_json::from_slice(body)?;
            Ok(json!(parse_list(&p.text, p.domain.as_deref())))
        }
        ("POST", ["start"]) => {
            let job: Job = serde_json::from_slice(body).context("invalid request")?;
            let saved = last_job(srv).await?;
            let job = unredact(job, saved.as_ref());
            start(srv.clone(), job)?;
            Ok(json!({ "started": true }))
        }
        ("POST", ["rerun"]) => {
            let job = last_job(srv).await?.ok_or_else(|| anyhow!("no earlier migration to run again"))?;
            start(srv.clone(), job)?;
            Ok(json!({ "started": true }))
        }
        ("POST", ["cancel"]) => {
            cancel();
            Ok(json!({ "ok": true }))
        }
        ("POST", ["forget"]) => {
            forget_saved(srv).await?;
            clear_created();
            Ok(json!({ "ok": true }))
        }
        ("POST", ["files"]) => {
            #[derive(Deserialize)]
            struct F {
                path: String,
                target: String,
                #[serde(default)]
                folder: Option<String>,
            }
            let f: F = serde_json::from_slice(body)?;
            files::start(srv.clone(), f.path, f.target, f.folder)?;
            Ok(json!({ "started": true }))
        }
        ("GET", ["created.csv"]) => {
            let p = progress();
            let mut csv = String::from("email,password\n");
            for (e, pw) in p.created {
                csv.push_str(&format!("{e},{pw}\n"));
            }
            Ok(Value::String(csv))
        }
        _ => bail!("unknown migration endpoint"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn p(s: &str) -> Vec<String> {
        s.split('/').map(String::from).collect()
    }
    #[test]
    fn folders() {
        assert_eq!(map_folder(&p("INBOX"), None).as_deref(), Some("INBOX"));
        assert_eq!(map_folder(&p("Inbox/Projects/2026"), None).as_deref(), Some("INBOX/Projects/2026"));
        assert_eq!(map_folder(&p("Sent Items"), None).as_deref(), Some("Sent"));
        assert_eq!(map_folder(&p("[Gmail]/Sent Mail"), None).as_deref(), Some("Sent"));
        assert_eq!(map_folder(&p("[Gmail]/All Mail"), None), None);
        assert_eq!(map_folder(&p("Junk Email"), None).as_deref(), Some("Junk"));
        assert_eq!(map_folder(&p("Calendar"), None), None);
        assert_eq!(map_folder(&p("Calendar/Birthdays"), None), None);
        assert_eq!(map_folder(&p("Customers/Sent"), None).as_deref(), Some("Customers/Sent"));
        assert_eq!(map_folder(&p("Weird"), Some(Special::Sent)).as_deref(), Some("Sent"));
        assert_eq!(map_folder(&p("[Gmail]/Receipts"), None).as_deref(), Some("Receipts"));
    }
    #[test]
    fn list() {
        let v = parse_list("source,target,password\namy@old.test\nbob , bob@new.test, pw;x\n# comment\ncarol\t\tsecret", Some("new.test"));
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].target, "amy@old.test");
        assert_eq!(v[1].target, "bob@new.test");
        assert_eq!(v[2].target, "carol@new.test");
        assert_eq!(v[2].password.as_deref(), Some("secret"));
    }
}
