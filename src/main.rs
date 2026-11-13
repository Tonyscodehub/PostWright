//! Postwright – a secure, multi-domain mail server (SMTP, submission, IMAP) in Rust.

mod auth;
mod caldav;
mod config;
mod delivery;
mod filter;
mod http;
mod imap;
mod iredmail;
mod logbuf;
mod admin;
mod net;
mod prefs;
mod server;
mod smtp;
mod store;
mod xml;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use config::Config;
use std::path::{Path, PathBuf};
use store::Store;

#[derive(Parser)]
#[command(name = "postwright", version, about = "Secure multi-domain SMTP + IMAP mail server")]
struct Cli {
    /// Path to the configuration file.
    #[arg(short, long, default_value = "postwright.toml", global = true)]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a starter config (and a self-signed certificate if none exists).
    Init {
        /// Public host name of this server, e.g. mail.example.com
        #[arg(long)]
        hostname: String,
        #[arg(long, default_value = "./data")]
        data_dir: PathBuf,
    },
    /// Run the mail server.
    Serve,
    /// Manage hosted domains.
    Domain {
        #[command(subcommand)]
        cmd: DomainCmd,
    },
    /// Manage mailbox users.
    User {
        #[command(subcommand)]
        cmd: UserCmd,
    },
    /// Manage aliases (forwarding addresses).
    Alias {
        #[command(subcommand)]
        cmd: AliasCmd,
    },
    /// Manage calendars and calendar sharing.
    Calendar {
        #[command(subcommand)]
        cmd: CalendarCmd,
    },
    /// Migrate from another mail server.
    Import {
        #[command(subcommand)]
        cmd: ImportCmd,
    },
    /// Inspect the outbound queue.
    Queue {
        #[command(subcommand)]
        cmd: QueueCmd,
    },
}

#[derive(Subcommand)]
enum ImportCmd {
    /// Import everything from an iRedMail server. Run on that server as root.
    Iredmail {
        /// Account backend: mysql, pgsql or ldap (auto-detected from Postfix if omitted).
        #[arg(long)]
        backend: Option<String>,
        #[arg(long, default_value = "/etc/postfix")]
        postfix_dir: PathBuf,
        /// Show what would be imported without writing anything.
        #[arg(long)]
        dry_run: bool,
        /// Accounts only; don't copy mail.
        #[arg(long)]
        no_mail: bool,
        /// Skip SOGo calendars.
        #[arg(long)]
        no_calendars: bool,
        /// Import a single user (e.g. for a trial run).
        #[arg(long)]
        user: Option<String>,
        /// Custom SQL client command for non-standard setups.
        #[arg(long)]
        sql_cmd: Option<String>,
    },
}

#[derive(Subcommand)]
enum DomainCmd {
    /// Host a new domain. Generates a DKIM key unless --dkim-key is given.
    Add {
        name: String,
        #[arg(long, default_value = "pw1")]
        selector: String,
        /// Use an existing DKIM private key (PEM, PKCS#1 or PKCS#8) so DNS doesn't change.
        #[arg(long)]
        dkim_key: Option<PathBuf>,
    },
    /// Make ALIAS an alias domain of TARGET (local@ALIAS is delivered to local@TARGET).
    Alias { alias: String, target: String },
    List,
    Remove { name: String },
    /// Print the DNS records the domain needs.
    Dns { name: String },
    /// Route mail for unknown addresses to a target address (omit target to clear).
    CatchAll { domain: String, target: Option<String> },
}

#[derive(Subcommand)]
enum UserCmd {
    /// Create a mailbox user. Prompts for the password if --password is omitted.
    Add {
        email: String,
        #[arg(long)]
        password: Option<String>,
        /// Mailbox quota in MB (0 = unlimited).
        #[arg(long, default_value_t = 0)]
        quota_mb: i64,
    },
    Passwd {
        email: String,
        #[arg(long)]
        password: Option<String>,
    },
    List,
    Remove { email: String },
    Disable { email: String },
    Enable { email: String },
    /// Grant or revoke access to the admin console and admin API.
    Admin {
        email: String,
        /// Revoke instead of grant.
        #[arg(long)]
        off: bool,
    },
    /// Set or clear a user's out-of-office auto-reply.
    Vacation {
        email: String,
        /// Turn auto-replies off.
        #[arg(long)]
        off: bool,
        #[arg(long)]
        subject: Option<String>,
        #[arg(long)]
        message: Option<String>,
        /// Start date (YYYY-MM-DD, UTC midnight).
        #[arg(long)]
        from: Option<String>,
        /// End date (YYYY-MM-DD, exclusive).
        #[arg(long)]
        until: Option<String>,
        #[arg(long)]
        internal_only: bool,
    },
    /// Set a user's signature.
    Signature {
        email: String,
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        html: Option<String>,
        /// Have the server append it to outgoing mail.
        #[arg(long)]
        append: Option<bool>,
    },
}

#[derive(Subcommand)]
enum CalendarCmd {
    /// List a user's calendars (own and shared with them).
    List { email: String },
    /// Create a calendar for a user.
    Create { email: String, name: String },
    /// Share one of OWNER's calendars with another user.
    Share {
        owner: String,
        calendar: String,
        with: String,
        /// Allow editing (default is view only).
        #[arg(long)]
        write: bool,
    },
    Unshare { owner: String, calendar: String, with: String },
}

#[derive(Subcommand)]
enum AliasCmd {
    Add { source: String, target: String },
    Remove { source: String, target: Option<String> },
    List,
}

#[derive(Subcommand)]
enum QueueCmd {
    List,
    /// Retry everything immediately (takes effect on the next queue scan).
    Flush,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Cmd::Init { hostname, data_dir } = &cli.cmd {
        return init(&cli.config, hostname, data_dir);
    }
    let cfg = Config::load(&cli.config)?;
    match cli.cmd {
        Cmd::Serve => serve(cfg),
        Cmd::Domain { cmd } => domain_cmd(&cfg, cmd),
        Cmd::User { cmd } => user_cmd(&cfg, cmd),
        Cmd::Alias { cmd } => alias_cmd(&cfg, cmd),
        Cmd::Queue { cmd } => queue_cmd(&cfg, cmd),
        Cmd::Calendar { cmd } => calendar_cmd(&cfg, cmd),
        Cmd::Import { cmd: ImportCmd::Iredmail { backend, postfix_dir, dry_run, no_mail, no_calendars, user, sql_cmd } } => {
            let st = open_store(&cfg)?;
            iredmail::run(
                &st,
                &iredmail::Opts { backend, postfix_dir, dry_run, mail: !no_mail, calendars: !no_calendars, only_user: user, sql_cmd },
            )
        }
        Cmd::Init { .. } => unreachable!(),
    }
}

fn open_store(cfg: &Config) -> Result<Store> {
    Store::open(&cfg.db_path(), &cfg.blob_dir(), 1)
}

fn init(path: &Path, hostname: &str, data_dir: &Path) -> Result<()> {
    if path.exists() {
        bail!("{} already exists", path.display());
    }
    let mut cfg = Config::default();
    cfg.hostname = hostname.to_ascii_lowercase();
    cfg.data_dir = data_dir.to_path_buf();
    cfg.tls.cert = data_dir.join("tls").join("cert.pem");
    cfg.tls.key = data_dir.join("tls").join("key.pem");
    std::fs::create_dir_all(data_dir.join("tls"))?;
    if !cfg.tls.cert.exists() {
        let ck = rcgen::generate_simple_self_signed(vec![cfg.hostname.clone()])?;
        std::fs::write(&cfg.tls.cert, ck.cert.pem())?;
        write_private(&cfg.tls.key, ck.key_pair.serialize_pem().as_bytes())?;
        println!("Generated a self-signed certificate for {hostname}.");
        println!("Replace it with a real one (e.g. Let's Encrypt) before going live: see README.");
    }
    let text = format!(
        "# Postwright configuration. All keys are optional; defaults shown.\n{}",
        toml::to_string_pretty(&cfg)?
    );
    std::fs::write(path, text)?;
    open_store(&cfg)?;
    println!("Wrote {}. Next: postwright domain add <domain>", path.display());
    Ok(())
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    std::fs::write(path, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn read_password(given: Option<String>) -> Result<String> {
    let pw = match given {
        Some(p) => p,
        None => {
            let a = rpassword::prompt_password("Password: ")?;
            let b = rpassword::prompt_password("Repeat:   ")?;
            if a != b {
                bail!("passwords do not match");
            }
            a
        }
    };
    if pw.chars().count() < 10 {
        bail!("password must be at least 10 characters");
    }
    Ok(pw)
}

fn domain_cmd(cfg: &Config, cmd: DomainCmd) -> Result<()> {
    let st = open_store(cfg)?;
    match cmd {
        DomainCmd::Alias { alias, target } => {
            st.sync(|c| store::add_alias_domain(c, &alias, &target, None))?;
            println!("{alias} is now an alias of {target}");
        }
        DomainCmd::Add { name, selector, dkim_key } => {
            let name = name.to_ascii_lowercase();
            if !name.contains('.') {
                bail!("'{name}' does not look like a domain");
            }
            let pem = match dkim_key {
                Some(p) => iredmail::load_rsa_pem(&p).ok_or_else(|| anyhow!("{} is not an RSA private key", p.display()))?,
                None => {
                    println!("Generating 2048-bit RSA DKIM key...");
                    delivery::generate_dkim_key()?.0
                }
            };
            st.sync(|c| store::add_domain(c, &name, &selector, &pem))?;
            println!("Added {name}.\n");
            print_dns(cfg, &st, &name)?;
        }
        DomainCmd::List => {
            for d in st.sync(|c| store::list_domains(c))? {
                let ca = d.catch_all.map(|c| format!("  catch-all -> {c}")).unwrap_or_default();
                match d.alias_of {
                    Some(t) => println!("{}  (alias of {t})", d.name),
                    None => println!("{}  (DKIM selector {}){ca}", d.name, d.dkim_selector.unwrap_or_default()),
                }
            }
        }
        DomainCmd::Remove { name } => {
            if st.sync(|c| store::delete_domain(c, &name))? {
                println!("Removed {name}");
            } else {
                bail!("no such domain");
            }
        }
        DomainCmd::Dns { name } => print_dns(cfg, &st, &name)?,
        DomainCmd::CatchAll { domain, target } => {
            if !st.sync(|c| store::set_catch_all(c, &domain, target.as_deref()))? {
                bail!("no such domain");
            }
            match target {
                Some(t) => println!("Unknown addresses at {domain} now go to {t}"),
                None => println!("Catch-all cleared for {domain}"),
            }
        }
    }
    Ok(())
}

fn print_dns(cfg: &Config, st: &Store, name: &str) -> Result<()> {
    let d = st.sync(|c| store::find_domain(c, name))?.ok_or_else(|| anyhow!("no such domain"))?;
    let host = &cfg.hostname;
    let selector = d.dkim_selector.clone().unwrap_or_default();
    let pubkey = d.dkim_key.as_deref().map(delivery::dkim_public_from_pem).transpose()?.unwrap_or_default();
    let dkim = format!("v=DKIM1; k=rsa; p={pubkey}");
    // TXT strings are limited to 255 bytes each; split for zone files that need it.
    let chunks: Vec<String> = dkim.as_bytes().chunks(250).map(|c| format!("\"{}\"", String::from_utf8_lossy(c))).collect();
    println!("DNS records for {name}:\n");
    println!("{name}.                     MX   10 {host}.");
    println!("{name}.                     TXT  \"v=spf1 mx -all\"");
    println!("{selector}._domainkey.{name}.  TXT  {}", chunks.join(" "));
    println!("_dmarc.{name}.              TXT  \"v=DMARC1; p=quarantine; adkim=s; aspf=s; rua=mailto:postmaster@{name}\"");
    println!("_submissions._tcp.{name}.   SRV  0 1 465 {host}.");
    println!("_submission._tcp.{name}.    SRV  0 1 587 {host}.");
    println!("_imaps._tcp.{name}.         SRV  0 1 993 {host}.");
    println!("\nAlso required once per server (not per domain):");
    println!("  {host}.  A/AAAA  <your public IP>");
    println!("  PTR (reverse DNS) for that IP -> {host}   (set at your ISP / hosting provider)");
    println!("\nThe single-string DKIM value (for web DNS panels):\n{dkim}");
    Ok(())
}

fn user_cmd(cfg: &Config, cmd: UserCmd) -> Result<()> {
    let st = open_store(cfg)?;
    match cmd {
        UserCmd::Add { email, password, quota_mb } => {
            if !smtp::valid_address(&email) {
                bail!("invalid address");
            }
            let pw = read_password(password)?;
            let hash = auth::hash_password(&pw)?;
            st.sync(|c| store::create_user(c, &email, &hash, quota_mb * 1024 * 1024))?;
            println!("Created {email} with folders INBOX, Sent, Drafts, Trash, Junk, Archive");
        }
        UserCmd::Passwd { email, password } => {
            let pw = read_password(password)?;
            let hash = auth::hash_password(&pw)?;
            if !st.sync(|c| store::set_password(c, &email, &hash))? {
                bail!("no such user");
            }
            println!("Password updated");
        }
        UserCmd::List => {
            for u in st.sync(|c| store::list_users(c))? {
                let usage = st.sync(|c| store::user_usage(c, u.id))?;
                let quota = if u.quota_bytes > 0 { format!("{} MB", u.quota_bytes / 1048576) } else { "unlimited".into() };
                println!(
                    "{:40} {:>8.1} MB used / {quota}{}{}",
                    u.email,
                    usage as f64 / 1048576.0,
                    if u.enabled { "" } else { "  [disabled]" },
                    if u.is_admin { "  [admin]" } else { "" }
                );
            }
        }
        UserCmd::Remove { email } => {
            if !st.sync(|c| store::delete_user(c, &email))? {
                bail!("no such user");
            }
            println!("Removed {email} and all its mail");
        }
        UserCmd::Disable { email } => {
            if !st.sync(|c| store::set_enabled(c, &email, false))? {
                bail!("no such user");
            }
            println!("Disabled {email}");
        }
        UserCmd::Enable { email } => {
            if !st.sync(|c| store::set_enabled(c, &email, true))? {
                bail!("no such user");
            }
            println!("Enabled {email}");
        }
        UserCmd::Admin { email, off } => {
            if !st.sync(|c| store::set_admin(c, &email, !off))? {
                bail!("no such user");
            }
            println!("{email} is {} an administrator", if off { "no longer" } else { "now" });
        }
        UserCmd::Vacation { email, off, subject, message, from, until, internal_only } => {
            let u = st.sync(|c| store::find_user(c, &email))?.ok_or_else(|| anyhow!("no such user"))?;
            let date = |d: &Option<String>| -> Result<Option<i64>> {
                d.as_deref()
                    .map(|s| {
                        chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
                            .map(|d| d.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp())
                            .map_err(|_| anyhow!("dates must be YYYY-MM-DD"))
                    })
                    .transpose()
            };
            let mut s = st.sync(|c| prefs::load(c, u.id))?;
            if off {
                s.vacation.enabled = false;
            } else {
                s.vacation = prefs::Vacation {
                    enabled: true,
                    subject: subject.unwrap_or(s.vacation.subject),
                    body: message.unwrap_or(s.vacation.body),
                    start: date(&from)?,
                    end: date(&until)?,
                    internal_only,
                };
            }
            st.sync(|c| prefs::save(c, u.id, &s))?;
            println!("Out of office for {email}: {}", if s.vacation.enabled { "on" } else { "off" });
        }
        UserCmd::Signature { email, text, html, append } => {
            let u = st.sync(|c| store::find_user(c, &email))?.ok_or_else(|| anyhow!("no such user"))?;
            let mut s = st.sync(|c| prefs::load(c, u.id))?;
            if let Some(t) = text {
                s.signature.text = t.replace("\\n", "\n");
            }
            if let Some(h) = html {
                s.signature.html = h;
            }
            if let Some(a) = append {
                s.signature.append = a;
            }
            st.sync(|c| prefs::save(c, u.id, &s))?;
            println!("Signature saved for {email}");
        }
    }
    Ok(())
}

fn alias_cmd(cfg: &Config, cmd: AliasCmd) -> Result<()> {
    let st = open_store(cfg)?;
    match cmd {
        AliasCmd::Add { source, target } => {
            if !smtp::valid_address(&source) || !smtp::valid_address(&target) {
                bail!("invalid address");
            }
            st.sync(|c| store::add_alias(c, &source, &target))?;
            println!("{source} -> {target}");
        }
        AliasCmd::Remove { source, target } => {
            let n = st.sync(|c| store::remove_alias(c, &source, target.as_deref()))?;
            println!("Removed {n} alias entr{}", if n == 1 { "y" } else { "ies" });
        }
        AliasCmd::List => {
            for (s, t) in st.sync(|c| store::list_aliases(c))? {
                println!("{s} -> {t}");
            }
        }
    }
    Ok(())
}

fn calendar_cmd(cfg: &Config, cmd: CalendarCmd) -> Result<()> {
    let st = open_store(cfg)?;
    let user = |e: &str| -> Result<store::User> { st.sync(|c| store::find_user(c, e))?.ok_or_else(|| anyhow!("no such user {e}")) };
    match cmd {
        CalendarCmd::List { email } => {
            let u = user(&email)?;
            for cal in st.sync(|c| caldav::list_calendars(c, u.id))? {
                let shares = if cal.is_owner { st.sync(|c| caldav::shares_of(c, cal.id))? } else { vec![] };
                let s: Vec<String> = shares.iter().map(|(u, w)| format!("{u}{}", if *w { " (edit)" } else { " (view)" })).collect();
                if cal.is_owner {
                    println!("{:24} {}{}", cal.slug, cal.name, if s.is_empty() { String::new() } else { format!("  shared with: {}", s.join(", ")) });
                } else {
                    println!("{:24} {}  (owned by {}, {})", cal.slug, cal.name, cal.owner, if cal.write { "can edit" } else { "view only" });
                }
            }
        }
        CalendarCmd::Create { email, name } => {
            let u = user(&email)?;
            let slug = st.sync(|c| {
                let slug = caldav::slug_for(c, u.id, &name)?;
                caldav::create_calendar(c, u.id, &slug, &name, None)?;
                Ok(slug)
            })?;
            println!("Created calendar '{name}' ({slug}) for {email}");
        }
        CalendarCmd::Share { owner, calendar, with, write } => {
            let u = user(&owner)?;
            let cal = st.sync(|c| caldav::resolve(c, u.id, &calendar))?.filter(|c| c.is_owner).ok_or_else(|| anyhow!("{owner} has no calendar '{calendar}'"))?;
            st.sync(|c| caldav::share(c, cal.id, &with, write))?;
            println!("Shared '{}' with {with} ({})", cal.name, if write { "can edit" } else { "view only" });
        }
        CalendarCmd::Unshare { owner, calendar, with } => {
            let u = user(&owner)?;
            let cal = st.sync(|c| caldav::resolve(c, u.id, &calendar))?.filter(|c| c.is_owner).ok_or_else(|| anyhow!("{owner} has no calendar '{calendar}'"))?;
            st.sync(|c| caldav::unshare(c, cal.id, &with))?;
            println!("Stopped sharing '{}' with {with}", cal.name);
        }
    }
    Ok(())
}

fn queue_cmd(cfg: &Config, cmd: QueueCmd) -> Result<()> {
    let st = open_store(cfg)?;
    match cmd {
        QueueCmd::List => {
            let items = st.sync(|c| store::list_queue(c))?;
            if items.is_empty() {
                println!("Queue is empty");
            }
            for i in items {
                let next = chrono::DateTime::from_timestamp(i.next_attempt, 0).map(|d| d.to_rfc3339()).unwrap_or_default();
                println!(
                    "#{} from <{}> to {} | attempts {} | next {} | {}",
                    i.id,
                    i.mail_from,
                    i.rcpts.join(", "),
                    i.attempts,
                    next,
                    i.last_error.unwrap_or_default()
                );
            }
        }
        QueueCmd::Flush => {
            let n = st.sync(|c| store::queue_flush(c))?;
            println!("{n} message(s) scheduled for immediate retry");
        }
    }
    Ok(())
}

fn serve(cfg: Config) -> Result<()> {
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(|| logbuf::Tee)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,lettre=warn,hickory=warn".into()),
        )
        .init();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    admin::mark_start();
    rt.block_on(async move {
        let srv = server::Server::new(cfg).context("starting server")?;
        let l = srv.cfg.listeners.clone();
        server::listen(srv.clone(), "smtp", &l.smtp, false, |s, st, p| smtp::handle(s, st, p, smtp::Mode::Inbound)).await?;
        server::listen(srv.clone(), "submission", &l.submission, false, |s, st, p| {
            smtp::handle(s, st, p, smtp::Mode::Submission)
        })
        .await?;
        server::listen(srv.clone(), "submissions", &l.submissions, true, |s, st, p| {
            smtp::handle(s, st, p, smtp::Mode::Submission)
        })
        .await?;
        server::listen(srv.clone(), "imap", &l.imap, false, imap::handle).await?;
        server::listen(srv.clone(), "imaps", &l.imaps, true, imap::handle).await?;
        server::listen(srv.clone(), "https", &l.https, true, http::handle).await?;
        tokio::spawn(delivery::run_queue(srv.clone()));

        // Pick up renewed certificates: on SIGHUP (Unix) and every 12 hours everywhere.
        {
            let srv = srv.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(12 * 3600));
                tick.tick().await;
                loop {
                    tick.tick().await;
                    if let Err(e) = srv.reload_tls() {
                        tracing::error!("TLS reload failed: {e:#}");
                    }
                }
            });
        }
        #[cfg(unix)]
        {
            let srv = srv.clone();
            tokio::spawn(async move {
                let Ok(mut hup) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) else { return };
                while hup.recv().await.is_some() {
                    if let Err(e) = srv.reload_tls() {
                        tracing::error!("TLS reload failed: {e:#}");
                    }
                }
            });
        }
        tracing::info!("Postwright {} running as {}", env!("CARGO_PKG_VERSION"), srv.cfg.hostname);
        tokio::signal::ctrl_c().await?;
        tracing::info!("shutting down");
        Ok(())
    })
}
