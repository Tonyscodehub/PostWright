//! Migration from iRedMail. Run on the iRedMail server as root:
//!
//!     postwright -c /path/to/postwright.toml import iredmail [--dry-run]
//!
//! It auto-detects the account backend (MariaDB/MySQL, PostgreSQL or OpenLDAP) from the
//! Postfix configuration and imports:
//!   * domains and alias domains, with their existing DKIM keys and selectors
//!   * users with their existing password hashes (upgraded to Argon2id on first login)
//!   * per-user aliases, forwardings and alias accounts
//!   * all Maildir mail with folders, flags, keywords, received dates and Dovecot UIDs
//!   * SOGo calendars and calendar sharing
//!
//! It is safe to run repeatedly: existing accounts are updated and mail already imported
//! is skipped, so you can do a bulk copy first and a quick final sync at cutover.
//!
//! Database access goes through the system's own `mysql`, `psql` and `ldapsearch` tools,
//! using the credentials iRedMail already configured, so nothing needs to be opened up.

use crate::caldav;

/// Output of the most recent import, for the admin console.
pub static OUTPUT: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

macro_rules! say {
    ($($t:tt)*) => {{
        let line = format!($($t)*);
        println!("{line}");
        if let Ok(mut o) = OUTPUT.lock() {
            o.extend(line.lines().map(String::from));
        }
    }};
}
use crate::store::{self, Store};
use anyhow::{anyhow, bail, Context, Result};
use rusqlite::params;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct Opts {
    pub backend: Option<String>,
    pub postfix_dir: PathBuf,
    pub dry_run: bool,
    pub mail: bool,
    pub calendars: bool,
    pub only_user: Option<String>,
    /// Override the SQL command (advanced), e.g. "mysql -h db -u vmailadmin -pXXX".
    pub sql_cmd: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Backend {
    Mysql,
    Pgsql,
    Ldap,
}

#[derive(Debug, Default, Clone)]
struct Account {
    email: String,
    password: String,
    quota_bytes: i64,
    maildir: Option<PathBuf>,
    enabled: bool,
}

#[derive(Debug, Default)]
struct Snapshot {
    domains: Vec<String>,
    alias_domains: Vec<(String, String)>,
    users: Vec<Account>,
    /// (source, target) pairs; a user forwarding with "keep a copy" has a self pair.
    forwards: Vec<(String, String)>,
    warnings: Vec<String>,
}

#[derive(Default, Debug)]
struct Report {
    domains: usize,
    alias_domains: usize,
    dkim: usize,
    users_new: usize,
    users_updated: usize,
    aliases: usize,
    folders: usize,
    messages: usize,
    skipped: usize,
    calendars: usize,
    events: usize,
    shares: usize,
}

pub fn run(store: &Store, o: &Opts) -> Result<()> {
    let backend = match o.backend.as_deref() {
        Some("mysql") | Some("mariadb") => Backend::Mysql,
        Some("pgsql") | Some("postgres") | Some("postgresql") => Backend::Pgsql,
        Some("ldap") => Backend::Ldap,
        Some(x) => bail!("unknown backend {x} (use mysql, pgsql or ldap)"),
        None => detect_backend(&o.postfix_dir)?,
    };
    say!("iRedMail backend: {backend:?}");
    let mut snap = match backend {
        Backend::Mysql | Backend::Pgsql => read_sql(backend, o)?,
        Backend::Ldap => read_ldap(o)?,
    };
    if let Some(u) = &o.only_user {
        let u = u.to_ascii_lowercase();
        snap.users.retain(|a| a.email == u);
        if snap.users.is_empty() {
            bail!("user {u} not found in iRedMail");
        }
    }
    let dkim = read_dkim(&snap.domains, &snap.alias_domains);
    say!(
        "Found {} domain(s), {} alias domain(s), {} mailbox(es), {} alias/forwarding rule(s), {} DKIM key(s)",
        snap.domains.len(),
        snap.alias_domains.len(),
        snap.users.len(),
        snap.forwards.len(),
        dkim.len()
    );
    for w in &snap.warnings {
        say!("  note: {w}");
    }
    if o.dry_run {
        for u in &snap.users {
            say!(
                "  {:40} {}  maildir: {}",
                u.email,
                if u.enabled { "active " } else { "disabled" },
                u.maildir.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "(none)".into())
            );
        }
        say!("Dry run: nothing written.");
        return Ok(());
    }

    let mut rep = Report::default();
    apply_accounts(store, &snap, &dkim, &mut rep)?;
    if o.mail {
        for u in &snap.users {
            if let Some(dir) = &u.maildir {
                match import_maildir(store, &u.email, dir, &mut rep) {
                    Ok(()) => {}
                    Err(e) => say!("  warning: mail for {}: {e:#}", u.email),
                }
            }
        }
    }
    if o.calendars {
        match import_sogo(store, &snap, &mut rep) {
            Ok(true) => {}
            Ok(false) => say!("  SOGo not found; skipping calendars"),
            Err(e) => say!("  warning: calendars: {e:#}"),
        }
    }
    say!("\nImport complete:");
    say!("  domains        {} (+{} alias domains, {} DKIM keys kept)", rep.domains, rep.alias_domains, rep.dkim);
    say!("  users          {} new, {} updated", rep.users_new, rep.users_updated);
    say!("  aliases        {}", rep.aliases);
    say!("  mail           {} message(s) in {} folder(s) ({} already present)", rep.messages, rep.folders, rep.skipped);
    say!("  calendars      {} with {} event(s), {} share(s)", rep.calendars, rep.events, rep.shares);
    say!("\nUsers keep their current passwords. DKIM DNS records need no changes.");
    Ok(())
}

// ------------------------------------------------------------------ detect

fn detect_backend(postfix_dir: &Path) -> Result<Backend> {
    let main = postfix_dir.join("main.cf");
    let text = std::fs::read_to_string(&main)
        .with_context(|| format!("reading {} (run this on the iRedMail server, or pass --backend)", main.display()))?;
    let line = text
        .lines()
        .find(|l| l.trim_start().starts_with("virtual_mailbox_domains"))
        .unwrap_or("")
        .to_ascii_lowercase();
    if line.contains("mysql:") {
        Ok(Backend::Mysql)
    } else if line.contains("pgsql:") {
        Ok(Backend::Pgsql)
    } else if line.contains("ldap:") {
        Ok(Backend::Ldap)
    } else {
        bail!("could not detect the iRedMail backend from {}; pass --backend mysql|pgsql|ldap", main.display())
    }
}

// --------------------------------------------------------------------- SQL

/// Decode one field of MySQL batch / PostgreSQL COPY text output.
fn unescape_field(f: &str) -> Option<String> {
    if f == "NULL" || f == "\\N" {
        return None;
    }
    let mut out = String::with_capacity(f.len());
    let mut it = f.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('0') => out.push('\0'),
                Some('\\') => out.push('\\'),
                Some(o) => {
                    out.push('\\');
                    out.push(o);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    Some(out)
}

pub struct Sql {
    backend_pg: bool,
    db: String,
    custom: Option<String>,
    /// For SOGo: explicit connection details.
    conn: Option<(String, u16, String, String)>,
}

impl Sql {
    fn query(&self, q: &str) -> Result<Vec<Vec<Option<String>>>> {
        let mut cmd = if let Some(c) = &self.custom {
            let mut parts = c.split_whitespace();
            let mut cmd = Command::new(parts.next().unwrap_or("mysql"));
            cmd.args(parts);
            if self.backend_pg {
                cmd.args(["-d", &self.db, "-c", &format!("COPY ({q}) TO STDOUT")]);
            } else {
                cmd.args(["-N", "-B", &self.db, "-e", q]);
            }
            cmd
        } else if self.backend_pg {
            let mut cmd;
            if let Some((host, port, user, pass)) = &self.conn {
                cmd = Command::new("psql");
                cmd.env("PGPASSWORD", pass).args(["-h", host, "-p", &port.to_string(), "-U", user]);
            } else {
                // iRedMail's PostgreSQL trusts the local postgres superuser.
                cmd = Command::new("runuser");
                cmd.args(["-u", "postgres", "--", "psql"]);
            }
            cmd.args(["-X", "-q", "-d", &self.db, "-c", &format!("COPY ({q}) TO STDOUT")]);
            cmd
        } else {
            let mut cmd = Command::new("mysql");
            if let Some((host, port, user, pass)) = &self.conn {
                cmd.env("MYSQL_PWD", pass).args(["-h", host, "-P", &port.to_string(), "-u", user]);
            } else if Path::new("/root/.my.cnf").exists() {
                // iRedMail writes the root credentials here.
                cmd.arg("--defaults-file=/root/.my.cnf");
            }
            cmd.args(["-N", "-B", &self.db, "-e", q]);
            cmd
        };
        let out = cmd.output().with_context(|| format!("running {:?}", cmd.get_program()))?;
        if !out.status.success() {
            bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
        }
        let text = String::from_utf8_lossy(&out.stdout);
        Ok(text.lines().filter(|l| !l.is_empty()).map(|l| l.split('\t').map(unescape_field).collect()).collect())
    }
}

fn col(r: &[Option<String>], i: usize) -> String {
    r.get(i).cloned().flatten().unwrap_or_default()
}

fn find_maildir(home: &Path) -> Option<PathBuf> {
    let md = home.join("Maildir");
    if md.join("cur").is_dir() || md.join("new").is_dir() {
        return Some(md);
    }
    if home.join("cur").is_dir() || home.join("new").is_dir() {
        return Some(home.to_path_buf());
    }
    None
}

fn read_sql(backend: Backend, o: &Opts) -> Result<Snapshot> {
    let sql = Sql { backend_pg: backend == Backend::Pgsql, db: "vmail".into(), custom: o.sql_cmd.clone(), conn: None };
    let mut s = Snapshot::default();
    for r in sql.query("SELECT domain FROM domain WHERE active = 1")? {
        s.domains.push(col(&r, 0).to_ascii_lowercase());
    }
    if let Ok(rows) = sql.query("SELECT alias_domain, target_domain FROM alias_domain WHERE active = 1") {
        for r in rows {
            s.alias_domains.push((col(&r, 0).to_ascii_lowercase(), col(&r, 1).to_ascii_lowercase()));
        }
    }
    for r in sql.query(
        "SELECT username, password, quota, storagebasedirectory, storagenode, maildir, active FROM mailbox",
    )? {
        let home = PathBuf::from(col(&r, 3)).join(col(&r, 4)).join(col(&r, 5));
        s.users.push(Account {
            email: col(&r, 0).to_ascii_lowercase(),
            password: col(&r, 1),
            quota_bytes: col(&r, 2).parse::<i64>().unwrap_or(0) * 1024 * 1024,
            maildir: find_maildir(&home),
            enabled: col(&r, 6) == "1",
        });
    }
    // iRedMail >= 0.9.8 keeps aliases, forwardings and list members in `forwardings`.
    match sql.query("SELECT address, forwarding, is_list FROM forwardings WHERE active = 1") {
        Ok(rows) => {
            for r in rows {
                let (a, f) = (col(&r, 0).to_ascii_lowercase(), col(&r, 1).to_ascii_lowercase());
                if !a.is_empty() && !f.is_empty() {
                    s.forwards.push((a, f));
                }
            }
        }
        Err(_) => {
            // Older schema: alias(address, goto) with comma-separated targets.
            for r in sql.query("SELECT address, goto FROM alias WHERE active = 1")? {
                let a = col(&r, 0).to_ascii_lowercase();
                for f in col(&r, 1).split(',').map(|x| x.trim().to_ascii_lowercase()).filter(|x| !x.is_empty()) {
                    s.forwards.push((a.clone(), f));
                }
            }
        }
    }
    if let Ok(rows) = sql.query("SELECT address FROM maillists WHERE active = 1") {
        if !rows.is_empty() {
            s.warnings.push(format!(
                "{} mlmmj mailing list(s) found; members are imported as aliases, but list archives and moderation are not",
                rows.len()
            ));
        }
    }
    s.forwards = normalise_forwards(&s.users, std::mem::take(&mut s.forwards));
    Ok(s)
}

/// In iRedMail a mailbox with no forwarding rows simply receives mail; once forwarding
/// is configured, a self-row means "keep a copy". Old schemas also store a self-row
/// for every mailbox, which we drop when it's the only one.
fn normalise_forwards(users: &[Account], fw: Vec<(String, String)>) -> Vec<(String, String)> {
    let mailboxes: HashSet<&str> = users.iter().map(|u| u.email.as_str()).collect();
    let mut by_src: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (a, f) in fw {
        let v = by_src.entry(a).or_default();
        if !v.contains(&f) {
            v.push(f);
        }
    }
    let mut out = Vec::new();
    for (a, targets) in by_src {
        if mailboxes.contains(a.as_str()) && targets.len() == 1 && targets[0] == a {
            continue; // plain mailbox
        }
        for t in targets {
            out.push((a.clone(), t));
        }
    }
    out
}

// -------------------------------------------------------------------- LDAP

fn parse_kv_file(path: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    if let Ok(t) = std::fs::read_to_string(path) {
        for l in t.lines() {
            let l = l.trim();
            if l.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = l.split_once('=') {
                m.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }
    }
    m
}

/// Parse LDIF output (`ldapsearch -LLL`) into entries of attribute -> values.
pub fn parse_ldif(text: &str) -> Vec<HashMap<String, Vec<String>>> {
    use base64::Engine;
    let mut entries = Vec::new();
    let mut cur: HashMap<String, Vec<String>> = HashMap::new();
    let mut lines: Vec<String> = Vec::new();
    for raw in text.lines() {
        if let Some(cont) = raw.strip_prefix(' ') {
            if let Some(last) = lines.last_mut() {
                last.push_str(cont);
            }
        } else {
            lines.push(raw.to_string());
        }
    }
    for l in lines {
        if l.trim().is_empty() {
            if !cur.is_empty() {
                entries.push(std::mem::take(&mut cur));
            }
            continue;
        }
        if l.starts_with('#') {
            continue;
        }
        let (k, v) = if let Some((k, v)) = l.split_once(":: ") {
            let d = base64::engine::general_purpose::STANDARD.decode(v.trim()).unwrap_or_default();
            (k.to_string(), String::from_utf8_lossy(&d).into_owned())
        } else if let Some((k, v)) = l.split_once(": ") {
            (k.to_string(), v.to_string())
        } else {
            continue;
        };
        cur.entry(k.to_ascii_lowercase()).or_default().push(v);
    }
    if !cur.is_empty() {
        entries.push(cur);
    }
    entries
}

fn read_ldap(_o: &Opts) -> Result<Snapshot> {
    // Dovecot's LDAP config has a bind DN that can read userPassword.
    let dv = parse_kv_file("/etc/dovecot/dovecot-ldap.conf");
    let pf = parse_kv_file("/etc/postfix/ldap/virtual_mailbox_maps.cf");
    let uri = dv
        .get("uris")
        .cloned()
        .or_else(|| dv.get("hosts").map(|h| format!("ldap://{}", h.split_whitespace().next().unwrap_or("127.0.0.1"))))
        .or_else(|| pf.get("server_host").map(|h| if h.contains("://") { h.clone() } else { format!("ldap://{h}") }))
        .unwrap_or_else(|| "ldap://127.0.0.1".into());
    let dn = dv.get("dn").or(pf.get("bind_dn")).cloned().ok_or_else(|| anyhow!("no LDAP bind DN found in Dovecot/Postfix config"))?;
    let pw = dv.get("dnpass").or(pf.get("bind_pw")).cloned().unwrap_or_default();
    let base = dv
        .get("base")
        .cloned()
        .or_else(|| pf.get("search_base").cloned())
        .ok_or_else(|| anyhow!("no LDAP search base found"))?;
    // Dovecot/Postfix bases contain per-domain placeholders; climb to o=domains,...
    let base = match base.find("o=domains") {
        Some(i) => base[i..].to_string(),
        None => base.rsplit_once("%d,").map(|x| x.1.to_string()).unwrap_or(base),
    };
    let search = |filter: &str, attrs: &[&str]| -> Result<Vec<HashMap<String, Vec<String>>>> {
        let pwfile = std::env::temp_dir().join(format!("pw-ldap-{}", std::process::id()));
        std::fs::write(&pwfile, &pw)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&pwfile, std::fs::Permissions::from_mode(0o600))?;
        }
        let out = Command::new("ldapsearch")
            .args(["-LLL", "-x", "-o", "ldif-wrap=no", "-H", &uri, "-D", &dn, "-y"])
            .arg(&pwfile)
            .args(["-b", &base, filter])
            .args(attrs)
            .output();
        let _ = std::fs::remove_file(&pwfile);
        let out = out.context("running ldapsearch")?;
        if !out.status.success() {
            bail!("ldapsearch: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(parse_ldif(&String::from_utf8_lossy(&out.stdout)))
    };
    let first = |e: &HashMap<String, Vec<String>>, k: &str| e.get(k).and_then(|v| v.first()).cloned().unwrap_or_default();
    let mut s = Snapshot::default();
    for e in search("(objectClass=mailDomain)", &["domainName", "domainAliasName", "accountStatus"])? {
        if first(&e, "accountstatus") != "active" {
            continue;
        }
        let d = first(&e, "domainname").to_ascii_lowercase();
        for a in e.get("domainaliasname").cloned().unwrap_or_default() {
            s.alias_domains.push((a.to_ascii_lowercase(), d.clone()));
        }
        s.domains.push(d);
    }
    let mut fw = Vec::new();
    for e in search(
        "(objectClass=mailUser)",
        &["mail", "userPassword", "mailQuota", "homeDirectory", "storageBaseDirectory", "mailMessageStore", "accountStatus", "shadowAddress", "mailForwardingAddress"],
    )? {
        let mail = first(&e, "mail").to_ascii_lowercase();
        let home = match e.get("homedirectory").and_then(|v| v.first()) {
            Some(h) => PathBuf::from(h),
            None => PathBuf::from(first(&e, "storagebasedirectory")).join(first(&e, "mailmessagestore")),
        };
        for a in e.get("shadowaddress").cloned().unwrap_or_default() {
            fw.push((a.to_ascii_lowercase(), mail.clone()));
        }
        for f in e.get("mailforwardingaddress").cloned().unwrap_or_default() {
            fw.push((mail.clone(), f.to_ascii_lowercase()));
        }
        s.users.push(Account {
            email: mail,
            password: first(&e, "userpassword"),
            quota_bytes: first(&e, "mailquota").parse().unwrap_or(0),
            maildir: find_maildir(&home),
            enabled: first(&e, "accountstatus") == "active",
        });
    }
    for e in search("(objectClass=mailAlias)", &["mail", "mailForwardingAddress", "shadowAddress", "accountStatus"])? {
        if first(&e, "accountstatus") != "active" {
            continue;
        }
        let mail = first(&e, "mail").to_ascii_lowercase();
        let targets = e.get("mailforwardingaddress").cloned().unwrap_or_default();
        for t in &targets {
            fw.push((mail.clone(), t.to_ascii_lowercase()));
            for sa in e.get("shadowaddress").cloned().unwrap_or_default() {
                fw.push((sa.to_ascii_lowercase(), t.to_ascii_lowercase()));
            }
        }
    }
    // Users with mailForwardingAddress but no copy kept are forward-only in iRedMail,
    // which matches our semantics once the self-row is absent.
    s.forwards = fw;
    let lists = search("(objectClass=mailList)", &["mail"]).map(|v| v.len()).unwrap_or(0);
    if lists > 0 {
        s.warnings.push(format!("{lists} LDAP mailing list(s) found; recreate them as aliases (postwright alias add)"));
    }
    Ok(s)
}

// -------------------------------------------------------------------- DKIM

/// DKIM keys from amavisd's dkim_key('domain', 'selector', '/path/key.pem') lines,
/// falling back to iRedMail's default /var/lib/dkim/<domain>.pem with selector "dkim".
fn read_dkim(domains: &[String], aliases: &[(String, String)]) -> HashMap<String, (String, String)> {
    let mut out = HashMap::new();
    for conf in ["/etc/amavisd/amavisd.conf", "/etc/amavis/conf.d/50-user", "/etc/amavisd.conf", "/usr/local/etc/amavisd.conf"] {
        let Ok(text) = std::fs::read_to_string(conf) else { continue };
        for line in text.lines() {
            let l = line.trim();
            if l.starts_with('#') || !l.starts_with("dkim_key") {
                continue;
            }
            let args: Vec<String> = l
                .split(['\'', '"'])
                .enumerate()
                .filter(|(i, _)| i % 2 == 1)
                .map(|(_, s)| s.to_string())
                .collect();
            if args.len() >= 3 {
                if let Some(pem) = load_rsa_pem(Path::new(&args[2])) {
                    out.insert(args[0].to_ascii_lowercase(), (args[1].clone(), pem));
                }
            }
        }
    }
    for d in domains.iter().chain(aliases.iter().map(|a| &a.0)) {
        if !out.contains_key(d) {
            if let Some(pem) = load_rsa_pem(&Path::new("/var/lib/dkim").join(format!("{d}.pem"))) {
                out.insert(d.clone(), ("dkim".into(), pem));
            }
        }
    }
    out
}

/// Load an RSA key in PKCS#1 or PKCS#8 PEM and return it as PKCS#1 PEM.
pub fn load_rsa_pem(path: &Path) -> Option<String> {
    use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
    use rsa::pkcs8::DecodePrivateKey;
    let text = std::fs::read_to_string(path).ok()?;
    let key = rsa::RsaPrivateKey::from_pkcs1_pem(&text).ok().or_else(|| rsa::RsaPrivateKey::from_pkcs8_pem(&text).ok())?;
    Some(key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).ok()?.to_string())
}

// ------------------------------------------------------------ apply accounts

fn apply_accounts(store: &Store, s: &Snapshot, dkim: &HashMap<String, (String, String)>, rep: &mut Report) -> Result<()> {
    store.sync(|c| {
        for d in &s.domains {
            let existing = store::find_domain(c, d)?;
            match (existing, dkim.get(d)) {
                (None, Some((sel, pem))) => {
                    store::add_domain(c, d, sel, pem)?;
                    rep.dkim += 1;
                }
                (None, None) => {
                    let (pem, _) = crate::delivery::generate_dkim_key()?;
                    store::add_domain(c, d, "pw1", &pem)?;
                    say!("  {d}: no existing DKIM key found; generated one (selector pw1) – publish it with `postwright domain dns {d}`");
                }
                (Some(_), Some((sel, pem))) => {
                    store::set_dkim(c, d, sel, pem)?;
                    rep.dkim += 1;
                }
                (Some(_), None) => {}
            }
            rep.domains += 1;
        }
        for (a, t) in &s.alias_domains {
            if store::find_domain(c, a)?.is_none() {
                let k = dkim.get(a).map(|(s, p)| (s.as_str(), p.as_str()));
                store::add_alias_domain(c, a, t, k)?;
                if k.is_some() {
                    rep.dkim += 1;
                }
            }
            rep.alias_domains += 1;
        }
        Ok(())
    })?;
    for u in &s.users {
        let (new, quota) = (u.clone(), u.quota_bytes);
        store.sync(|c| {
            match store::find_user(c, &new.email)? {
                None => {
                    store::create_user(c, &new.email, &new.password, quota)?;
                    store::set_enabled(c, &new.email, new.enabled)?;
                    rep.users_new += 1;
                }
                Some(existing) => {
                    // Keep a password the user has already changed or upgraded on Postwright.
                    if crate::auth::is_legacy(&existing.password) {
                        store::set_password(c, &new.email, &new.password)?;
                    }
                    c.execute("UPDATE users SET quota_bytes = ?2 WHERE id = ?1", params![existing.id, quota])?;
                    store::set_enabled(c, &new.email, new.enabled)?;
                    rep.users_updated += 1;
                }
            }
            Ok(())
        })?;
    }
    store.sync(|c| {
        for (a, t) in &s.forwards {
            if crate::delivery::split_addr(a).is_none() || crate::delivery::split_addr(t).is_none() {
                continue;
            }
            match store::add_alias(c, a, t) {
                Ok(()) => rep.aliases += 1,
                Err(e) => say!("  skipped alias {a} -> {t}: {e}"),
            }
        }
        Ok(())
    })?;
    Ok(())
}

// ----------------------------------------------------------------- Maildir

struct DovecotUids {
    uidvalidity: u32,
    nextuid: u32,
    by_base: HashMap<String, u32>,
}

/// Parse dovecot-uidlist (versions 1 and 3).
fn read_uidlist(dir: &Path) -> Option<DovecotUids> {
    let text = std::fs::read_to_string(dir.join("dovecot-uidlist")).ok()?;
    let mut lines = text.lines();
    let header = lines.next()?;
    let mut parts = header.split_whitespace();
    let version = parts.next()?;
    let (mut uidv, mut next) = (0u32, 0u32);
    if version == "1" {
        uidv = parts.next()?.parse().ok()?;
        next = parts.next()?.parse().ok()?;
    } else {
        for p in parts {
            if let Some(v) = p.strip_prefix('V') {
                uidv = v.parse().ok()?;
            } else if let Some(n) = p.strip_prefix('N') {
                next = n.parse().ok()?;
            }
        }
    }
    let mut by_base = HashMap::new();
    for l in lines {
        let l = l.trim();
        let (uid, rest) = l.split_once(' ')?;
        let Ok(uid) = uid.parse::<u32>() else { continue };
        // v3: "<uid> [ext...] :<filename>"; v1: "<uid> <filename>"
        let fname = match rest.find(':') {
            Some(i) if version != "1" => &rest[i + 1..],
            _ => rest.trim(),
        };
        by_base.insert(base_name(fname).to_string(), uid);
    }
    if uidv == 0 {
        return None;
    }
    Some(DovecotUids { uidvalidity: uidv, nextuid: next, by_base })
}

/// The part of a Maildir filename that stays stable when flags change.
fn base_name(f: &str) -> &str {
    let f = f.split(":2,").next().unwrap_or(f);
    f.split(',').next().unwrap_or(f)
}

fn keywords(dir: &Path) -> HashMap<char, String> {
    let mut m = HashMap::new();
    if let Ok(t) = std::fs::read_to_string(dir.join("dovecot-keywords")) {
        for l in t.lines() {
            if let Some((i, name)) = l.split_once(' ') {
                if let Ok(i) = i.parse::<u8>() {
                    if i < 26 {
                        m.insert((b'a' + i) as char, name.trim().to_string());
                    }
                }
            }
        }
    }
    m
}

pub fn maildir_flags(fname: &str, kw: &HashMap<char, String>) -> Vec<String> {
    let mut v = Vec::new();
    if let Some((_, info)) = fname.rsplit_once(":2,") {
        for ch in info.chars() {
            let f = match ch {
                'S' => Some("\\Seen".to_string()),
                'R' => Some("\\Answered".to_string()),
                'F' => Some("\\Flagged".to_string()),
                'T' => Some("\\Deleted".to_string()),
                'D' => Some("\\Draft".to_string()),
                'P' => Some("$Forwarded".to_string()),
                c if c.is_ascii_lowercase() => kw.get(&c).cloned(),
                _ => None,
            };
            if let Some(f) = f {
                if !v.contains(&f) {
                    v.push(f);
                }
            }
        }
    }
    v
}

/// Maildir++ folder directory name (".Archive.2024") to IMAP name ("Archive/2024").
fn folder_name(dir: &str) -> String {
    dir.trim_start_matches('.').replace('.', "/")
}

pub fn to_crlf(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 40);
    let mut prev = 0u8;
    for &b in data {
        if b == b'\n' && prev != b'\r' {
            out.push(b'\r');
        }
        out.push(b);
        prev = b;
    }
    out
}

fn import_maildir(store: &Store, email: &str, root: &Path, rep: &mut Report) -> Result<()> {
    let user = store.sync(|c| store::find_user(c, email))?.ok_or_else(|| anyhow!("user missing"))?;
    let mut folders: Vec<(String, PathBuf)> = vec![("INBOX".into(), root.to_path_buf())];
    for e in std::fs::read_dir(root)? {
        let e = e?;
        let n = e.file_name().to_string_lossy().into_owned();
        if n.starts_with('.') && n != "." && n != ".." && e.path().is_dir() && (e.path().join("cur").is_dir() || e.path().join("new").is_dir()) {
            folders.push((folder_name(&n), e.path()));
        }
    }
    let mut count = 0usize;
    for (name, dir) in folders {
        let mb = store.sync(|c| {
            if store::find_mailbox(c, user.id, &name)?.is_none() {
                store::create_mailbox(c, user.id, &name)?;
            }
            Ok(store::find_mailbox(c, user.id, &name)?.unwrap())
        })?;
        let uids = read_uidlist(&dir);
        let kw = keywords(&dir);
        let (existing_blobs, existing_uids): (HashSet<String>, HashSet<u32>) = store.sync(|c| {
            let m = store::list_messages(c, mb.id)?;
            Ok((m.iter().map(|x| x.blob.clone()).collect(), m.iter().map(|x| x.uid).collect()))
        })?;
        // Adopt Dovecot's UIDVALIDITY while the folder is still empty, so clients keep
        // their caches when they reconnect to the new server.
        if let Some(u) = &uids {
            if existing_uids.is_empty() {
                store.sync(|c| store::set_uid_state(c, mb.id, u.uidvalidity, u.nextuid))?;
            }
        }
        let mut files: Vec<(PathBuf, String)> = Vec::new();
        for sub in ["cur", "new"] {
            let Ok(rd) = std::fs::read_dir(dir.join(sub)) else { continue };
            for e in rd.flatten() {
                if e.path().is_file() {
                    files.push((e.path(), e.file_name().to_string_lossy().into_owned()));
                }
            }
        }
        // Keep arrival order.
        files.sort_by_key(|(p, _)| std::fs::metadata(p).and_then(|m| m.modified()).ok());
        let mut batch: Vec<(Option<u32>, String, i64, i64, Vec<String>)> = Vec::new();
        let mut seen_blobs = existing_blobs;
        for (path, fname) in files {
            let raw = match std::fs::read(&path) {
                Ok(r) => r,
                Err(_) => continue, // moved by Dovecot while we were reading
            };
            let data = to_crlf(&raw);
            let blob = store.put_blob_sync(&data)?;
            if !seen_blobs.insert(blob.clone()) {
                rep.skipped += 1;
                continue;
            }
            let date = std::fs::metadata(&path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or_else(store::now);
            let uid = uids.as_ref().and_then(|u| u.by_base.get(base_name(&fname)).copied()).filter(|u| !existing_uids.contains(u));
            batch.push((uid, blob, data.len() as i64, date, maildir_flags(&fname, &kw)));
        }
        let n = batch.len();
        store.sync(|c| {
            let tx = c.transaction()?;
            let mut used: HashSet<u32> = existing_uids.clone();
            for (uid, blob, size, date, flags) in &batch {
                match uid {
                    Some(u) if used.insert(*u) => store::insert_with_uid(&tx, mb.id, *u, blob, *size, *date, flags)?,
                    _ => {
                        let next: i64 = tx.query_row("SELECT uidnext FROM mailboxes WHERE id = ?1", [mb.id], |r| r.get(0))?;
                        let mut u = next as u32;
                        while used.contains(&u) {
                            u += 1;
                        }
                        used.insert(u);
                        store::insert_with_uid(&tx, mb.id, u, blob, *size, *date, flags)?;
                    }
                }
            }
            tx.commit()?;
            Ok(())
        })?;
        rep.folders += 1;
        rep.messages += n;
        count += n;
    }
    say!("  {email}: {count} message(s) imported");
    Ok(())
}

// -------------------------------------------------------------------- SOGo

/// Parse a SOGo storage URL: mysql://user:pass@host:port/db/table
fn parse_sogo_url(url: &str) -> Option<(bool, String, u16, String, String, String, String)> {
    let (scheme, rest) = url.split_once("://")?;
    let pg = scheme.starts_with("postgres");
    let (auth, rest) = rest.rsplit_once('@')?;
    let (user, pass) = auth.split_once(':').unwrap_or((auth, ""));
    let mut segs = rest.split('/');
    let hostport = segs.next()?;
    let db = segs.next()?.to_string();
    let table = segs.next().unwrap_or("").to_string();
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (hostport.to_string(), if pg { 5432 } else { 3306 }),
    };
    let dec = |s: &str| crate::http::pct_decode(s);
    Some((pg, host, port, dec(user), dec(pass), db, table))
}

fn sogo_conf() -> Option<HashMap<String, String>> {
    let text = std::fs::read_to_string("/etc/sogo/sogo.conf").ok()?;
    let mut m = HashMap::new();
    for l in text.lines() {
        let l = l.trim();
        if let Some((k, v)) = l.split_once('=') {
            let v = v.trim().trim_end_matches(';').trim().trim_matches('"').to_string();
            m.insert(k.trim().to_string(), v);
        }
    }
    Some(m)
}

fn import_sogo(store: &Store, snap: &Snapshot, rep: &mut Report) -> Result<bool> {
    let Some(conf) = sogo_conf() else { return Ok(false) };
    let info_url = conf.get("OCSFolderInfoURL").ok_or_else(|| anyhow!("OCSFolderInfoURL missing from sogo.conf"))?;
    let (pg, host, port, user, pass, db, info_table) = parse_sogo_url(info_url).ok_or_else(|| anyhow!("cannot parse {info_url}"))?;
    let sql = Sql { backend_pg: pg, db, custom: None, conn: Some((host, port, user, pass)) };
    let store_table = conf.get("OCSStoreURL").and_then(|u| parse_sogo_url(u)).map(|x| x.6);
    let acl_table = conf.get("OCSAclURL").and_then(|u| parse_sogo_url(u)).map(|x| x.6);
    let known: HashSet<&str> = snap.users.iter().map(|u| u.email.as_str()).collect();
    let folders = sql.query(&format!(
        "SELECT c_folder_id, c_path2, c_path4, c_foldername, c_location, c_acl_location FROM {info_table} WHERE c_folder_type = 'Appointment'"
    ))?;
    let mut pending_shares: Vec<(i64, String, String)> = Vec::new(); // (cal id, sogo acl location/folder, owner)
    for f in folders {
        let (fid, owner, path4, display) = (col(&f, 0), col(&f, 1).to_ascii_lowercase(), col(&f, 2), col(&f, 3));
        if !known.contains(owner.as_str()) {
            continue;
        }
        let Some(u) = store.sync(|c| store::find_user(c, &owner))? else { continue };
        let content_q = match &store_table {
            Some(t) => format!("SELECT c_name, c_content FROM {t} WHERE c_folder_id = {fid} AND (c_deleted IS NULL OR c_deleted <> 1)"),
            None => {
                let loc = col(&f, 4);
                let table = loc.rsplit('/').next().unwrap_or("").to_string();
                if table.is_empty() || !table.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    continue;
                }
                format!("SELECT c_name, c_content FROM {table} WHERE c_deleted IS NULL OR c_deleted <> 1")
            }
        };
        let objects = sql.query(&content_q)?;
        let cal_id = store.sync(|c| {
            caldav::ensure_default(c, u.id)?;
            let slug = if path4 == "personal" {
                "calendar".to_string()
            } else {
                let mut s: String = path4.chars().map(|ch| if ch.is_ascii_alphanumeric() || "-_".contains(ch) { ch } else { '-' }).collect();
                if !caldav::valid_slug(&s) {
                    s = caldav::slug_for(c, u.id, &display)?;
                }
                s
            };
            if caldav::resolve(c, u.id, &slug)?.is_none() {
                caldav::create_calendar(c, u.id, &slug, &display, None)?;
            } else if path4 == "personal" && !display.is_empty() {
                c.execute("UPDATE calendars SET name = ?3 WHERE owner_id = ?1 AND slug = ?2", params![u.id, slug, display])?;
            }
            Ok(caldav::resolve(c, u.id, &slug)?.unwrap().id)
        })?;
        let mut n = 0;
        store.sync(|c| {
            let tx = c.transaction()?;
            for o in &objects {
                let (name, data) = (col(o, 0), col(o, 1));
                let Ok(meta) = caldav::ics_meta(&data) else { continue };
                let etag = format!("\"{}\"", &hex::encode(<sha2::Sha256 as sha2::Digest>::digest(data.as_bytes()))[..32]);
                tx.execute(
                    "INSERT INTO calendar_objects(calendar_id, name, etag, data, component, dtstart, dtend, recurring, modified)
                     VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                     ON CONFLICT(calendar_id, name) DO UPDATE SET etag = ?3, data = ?4, component = ?5, dtstart = ?6,
                        dtend = ?7, recurring = ?8, modified = ?9",
                    params![cal_id, name, etag, data, meta.component, meta.dtstart, meta.dtend, meta.recurring as i64, store::now()],
                )?;
                n += 1;
            }
            tx.execute("UPDATE calendars SET ctag = ctag + 1 WHERE id = ?1", [cal_id])?;
            tx.commit()?;
            Ok(())
        })?;
        rep.calendars += 1;
        rep.events += n;
        let acl_src = match &acl_table {
            Some(t) => format!("SELECT c_uid, c_role FROM {t} WHERE c_folder_id = {fid} AND c_object = '/Users/{owner}/Calendar/{path4}'"),
            None => {
                let table = col(&f, 5).rsplit('/').next().unwrap_or("").to_string();
                if table.is_empty() || !table.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    continue;
                }
                format!("SELECT c_uid, c_role FROM {table} WHERE c_object = '/Users/{owner}/Calendar/{path4}'")
            }
        };
        pending_shares.push((cal_id, acl_src, owner));
    }
    for (cal_id, q, _owner) in pending_shares {
        let Ok(rows) = sql.query(&q) else { continue };
        let mut grants: HashMap<String, bool> = HashMap::new();
        for r in rows {
            let (who, role) = (col(&r, 0).to_ascii_lowercase(), col(&r, 1));
            if who.starts_with('<') || who == "anonymous" || !who.contains('@') {
                continue;
            }
            let write = matches!(role.as_str(), "ObjectEditor" | "ObjectCreator" | "ObjectEraser" | "PublicModifier" | "ConfidentialModifier" | "PrivateModifier");
            let read = write || role.ends_with("Viewer") || role == "PublicDAndTViewer";
            if read {
                let e = grants.entry(who).or_insert(false);
                *e |= write;
            }
        }
        for (who, write) in grants {
            let ok = store.sync(|c| {
                if store::find_user(c, &who)?.is_none() {
                    return Ok(false);
                }
                caldav::share(c, cal_id, &who, write)?;
                Ok(true)
            })?;
            if ok {
                rep.shares += 1;
            }
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_and_names() {
        assert_eq!(unescape_field("a\\nb\\tc\\\\d").unwrap(), "a\nb\tc\\d");
        assert_eq!(unescape_field("NULL"), None);
        assert_eq!(unescape_field("\\N"), None);
        assert_eq!(folder_name(".Archive.2024"), "Archive/2024");
        assert_eq!(base_name("1700000000.M1P2.host,S=1234,W=1260:2,FS"), "1700000000.M1P2.host");
        let mut kw = HashMap::new();
        kw.insert('a', "$Junk".to_string());
        assert_eq!(maildir_flags("x:2,FSa", &kw), vec!["\\Flagged", "\\Seen", "$Junk"]);
        assert_eq!(to_crlf(b"a\nb\r\nc\n"), b"a\r\nb\r\nc\r\n");
        let p = parse_sogo_url("mysql://sogo:p%40ss@127.0.0.1:3306/sogo/sogo_folder_info").unwrap();
        assert_eq!((p.3.as_str(), p.4.as_str(), p.5.as_str(), p.6.as_str()), ("sogo", "p@ss", "sogo", "sogo_folder_info"));
    }

    #[test]
    fn ldif() {
        let t = "dn: mail=tony@x.com,ou=Users\nmail: tony@x.com\nuserPassword:: e1NTSEE1MTJ9YWJj\nshadowAddress: t@x.com\nshadowAddress: tj@x.com\n\ndn: mail=amy@x.com\nmail: amy@x\n .com\n";
        let e = parse_ldif(t);
        assert_eq!(e.len(), 2);
        assert_eq!(e[0]["userpassword"][0], "{SSHA512}abc");
        assert_eq!(e[0]["shadowaddress"].len(), 2);
        assert_eq!(e[1]["mail"][0], "amy@x.com");
    }

    #[test]
    fn forwards_normalised() {
        let users = vec![Account { email: "a@x.com".into(), ..Default::default() }];
        let f = normalise_forwards(
            &users,
            vec![("a@x.com".into(), "a@x.com".into()), ("b@x.com".into(), "a@x.com".into())],
        );
        assert_eq!(f, vec![("b@x.com".to_string(), "a@x.com".to_string())]);
        let f = normalise_forwards(&users, vec![("a@x.com".into(), "a@x.com".into()), ("a@x.com".into(), "z@y.com".into())]);
        assert_eq!(f.len(), 2); // keep-a-copy forwarding
    }
}
