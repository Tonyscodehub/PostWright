//! Postwright – a secure, multi-domain mail server (SMTP, submission, IMAP) in Rust.

mod auth;
mod caldav;
mod carddav;
mod certs;
mod config;
mod configloc;
mod delivery;
mod filter;
mod hold;
mod http;
mod identity;
mod imap;
mod iredmail;
mod logbuf;
mod migrate;
mod admin;
mod net;
mod prefs;
mod radius;
mod server;
mod service;
mod setup;
mod upgrade;
mod webmail;
mod smtp;
mod store;
mod xml;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use config::Config;
use configloc::Loc;
use std::path::{Path, PathBuf};
use store::Store;

#[derive(Parser)]
#[command(
    name = "postwright",
    version,
    about = "Secure multi-domain mail server (SMTP, IMAP, CalDAV, CardDAV)",
    after_help = "Run with no command to start the server. The first time, it opens a setup page in your browser."
)]
struct Cli {
    /// Use this settings file. Without it, settings are in the registry on Windows
    /// (HKLM\SOFTWARE\Postwright) and in /etc/postwright/postwright.toml on Linux.
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

fn config_loc(given: Option<PathBuf>, is_service: bool) -> Loc {
    if let Some(p) = given {
        return Loc::File(p);
    }
    #[cfg(unix)]
    {
        let _ = is_service;
        // An installation made by an earlier version keeps its settings where they are.
        let here = PathBuf::from("postwright.toml");
        let std = Loc::standard();
        if !std.exists() && here.exists() {
            return Loc::File(here);
        }
        std
    }
    #[cfg(windows)]
    {
        let loc = Loc::Registry;
        if !loc.exists() && !is_service {
            let mine = std::env::current_exe().ok().and_then(|e| e.parent().map(|d| d.join("postwright.toml"))).unwrap_or_else(|| PathBuf::from("postwright.toml"));
            if let Some(prev) = upgrade::find_previous(&mine) {
                if let Err(e) = upgrade::import_legacy(&prev) {
                    eprintln!(
                        "\nFound the settings of an earlier version at {} but couldn't move them into the registry: {e:#}\nUsing that file as it is for now.\n",
                        prev.display()
                    );
                    return Loc::File(prev);
                }
            }
        }
        loc
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a starter config (and a self-signed certificate if none exists).
    Init {
        /// Public host name of this server, e.g. mail.example.com
        #[arg(long)]
        hostname: String,
        /// Where mail is kept (default: C:\ProgramData\Postwright\data on Windows,
        /// /var/lib/postwright on Linux, or "data" next to a -c settings file).
        #[arg(long)]
        data_dir: Option<PathBuf>,
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
    /// TLS certificate status, manual install, and keys allowed to push certificates.
    Cert {
        #[command(subcommand)]
        cmd: CertCmd,
    },
    /// Migrate from another mail server.
    Import {
        #[command(subcommand)]
        cmd: ImportCmd,
    },
    /// Copy mail, calendars and contacts from Exchange Online, Google Workspace, any IMAP
    /// server, or exported files. (Easier from the admin console's Migration page.)
    Migrate {
        #[command(subcommand)]
        cmd: MigrateCmd,
    },
    /// Run Postwright as a service that starts automatically at boot (Windows service,
    /// or systemd on Linux).
    Service {
        #[command(subcommand)]
        cmd: ServiceCmd,
    },
    /// See, back up or restore the settings (kept in the registry on Windows).
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },
    /// Let one user open another's mailbox and/or send from their address.
    Delegate {
        #[command(subcommand)]
        cmd: DelegateCmd,
    },
    /// Inspect the outbound queue.
    Queue {
        #[command(subcommand)]
        cmd: QueueCmd,
    },
}

#[derive(Subcommand)]
enum CertCmd {
    /// Show the current certificate and how to push renewals from OPNsense.
    Status,
    /// Allow an SSH public key (e.g. OPNsense's "Show identity") to push certificates.
    KeyAdd {
        /// The whole public key line, in quotes.
        key: String,
    },
    KeyList,
    /// Remove an allowed key by its SHA256 fingerprint.
    KeyRemove { fingerprint: String },
    /// Install a certificate and key from files (validated first). A running server picks it up within seconds.
    Install {
        #[arg(long)]
        fullchain: PathBuf,
        #[arg(long)]
        key: PathBuf,
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
    /// Turn off two-factor authentication for a user who has lost their phone and
    /// recovery codes. Also signs them out everywhere and removes their app passwords.
    MfaReset { email: String },
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
enum ConfigCmd {
    /// Say where the settings are kept.
    Where,
    /// Print the settings.
    Show,
    /// Save the settings to a file.
    Export { file: PathBuf },
    /// Replace the settings with those in a file (checked first).
    Import { file: PathBuf },
}

#[derive(Subcommand)]
enum ServiceCmd {
    /// Install (or update) the service and set it to start at boot.
    Install {
        /// Also start it now.
        #[arg(long)]
        start: bool,
    },
    /// Stop and remove the service.
    Uninstall,
    Start,
    Stop,
    Status,
    /// Used by the Windows service manager to run the service.
    #[command(hide = true)]
    Run,
}

#[derive(Subcommand)]
enum MigrateCmd {
    /// Run a migration described in a JSON file (see README). Safe to run again: only
    /// new items are copied.
    Run { job: PathBuf },
    /// List the mailboxes on the old system (Exchange Online or Google Workspace).
    Discover { job: PathBuf },
    /// Import .mbox (incl. Google Takeout), .ics and .vcf files, or a folder of them.
    Files {
        path: PathBuf,
        #[arg(long)]
        user: String,
        /// Folder for mbox files without Gmail labels (default: the file's name).
        #[arg(long)]
        folder: Option<String>,
    },
}

#[derive(Subcommand)]
enum DelegateCmd {
    /// Give GRANTEE access to OWNER's mailbox and/or permission to send from it.
    Grant {
        owner: String,
        grantee: String,
        /// Mailbox access: none, read or full.
        #[arg(long, default_value = "full")]
        mailbox: String,
        /// Sending: none, on-behalf (recipients see "X on behalf of OWNER") or as.
        #[arg(long, default_value = "none")]
        send: String,
    },
    /// Remove all of GRANTEE's access to OWNER's mailbox.
    Revoke { owner: String, grantee: String },
    List,
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
    let interactive = std::env::args().len() == 1;
    let r = real_main();
    if let Err(e) = &r {
        // Double-clicked on Windows: keep the window open long enough to read the error.
        if interactive && cfg!(windows) {
            eprintln!("\nError: {e:#}\n\nPress Enter to close.");
            let _ = std::io::stdin().read_line(&mut String::new());
        }
    }
    r
}

fn interactive_start() -> bool {
    std::env::args().len() == 1
}

fn config_cmd(loc: &Loc, cmd: ConfigCmd) -> Result<()> {
    match cmd {
        ConfigCmd::Where => {
            println!("Settings: {}", loc.describe());
            if let Ok(cfg) = Config::load_loc(loc) {
                println!("Data:     {}", cfg.data_dir.display());
            }
        }
        ConfigCmd::Show => print!("{}", loc.read()?),
        ConfigCmd::Export { file } => {
            std::fs::write(&file, format!("# Postwright settings exported from {}\n{}", loc.describe(), loc.read()?))?;
            println!("Saved to {}", file.display());
        }
        ConfigCmd::Import { file } => {
            let text = std::fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?;
            Config::from_toml(&text, &loc.base_dir()).context("those settings aren't valid, so nothing was changed")?;
            loc.write(&text)?;
            println!("Settings in {} replaced. Restart Postwright (or the service) to use them.", loc.describe());
        }
    }
    Ok(())
}

fn service_cmd(path: &Loc, cmd: &ServiceCmd) -> Result<()> {
    match cmd {
        ServiceCmd::Install { start } => {
            if !path.exists() {
                bail!("there are no settings yet ({}): run postwright on its own first to go through setup", path.describe());
            }
            println!("{}", service::install(path)?);
            if *start {
                service::start()?;
                println!("Started.");
            }
        }
        ServiceCmd::Uninstall => println!("{}", service::uninstall()?),
        ServiceCmd::Start => {
            service::start()?;
            println!("Started.");
        }
        ServiceCmd::Stop => {
            service::stop()?;
            println!("Stopped.");
        }
        ServiceCmd::Status => println!("{}", service::state().describe()),
        ServiceCmd::Run => {
            #[cfg(windows)]
            return service::dispatch(match path {
                Loc::File(p) => Loc::File(std::path::absolute(p)?),
                Loc::Registry => Loc::Registry,
            });
            #[cfg(not(windows))]
            bail!("\"service run\" is only used on Windows; on Linux systemd runs \"postwright serve\"");
        }
    }
    Ok(())
}

fn real_main() -> Result<()> {
    let cli = Cli::parse();
    let is_service = matches!(cli.cmd, Some(Cmd::Service { cmd: ServiceCmd::Run }));
    let path = config_loc(cli.config, is_service);
    let cmd = cli.cmd.unwrap_or(Cmd::Serve);
    if let Cmd::Init { hostname, data_dir } = &cmd {
        return init(&path, hostname, data_dir.as_deref());
    }
    if let Cmd::Serve = cmd {
        // Double-clicked while the service is already running: don't fight it for the ports.
        if interactive_start() && service::state() == service::State::Running && upgrade::offer_service_upgrade(&path)? {
            return Ok(());
        }
        if interactive_start() && service::state() == service::State::Running {
            let url = "https://localhost/admin";
            println!("\nPostwright is already running as a service (it starts automatically at boot).\nOpen {url} to manage it, or use Services (services.msc) to stop it.\n");
            #[cfg(windows)]
            {
                let _ = std::process::Command::new("cmd").args(["/C", "start", "", url]).spawn();
                println!("Press Enter to close.");
                let _ = std::io::stdin().read_line(&mut String::new());
            }
            return Ok(());
        }
        return serve(&path);
    }
    if let Cmd::Service { cmd } = &cmd {
        return service_cmd(&path, cmd);
    }
    if let Cmd::Config { cmd } = cmd {
        return config_cmd(&path, cmd);
    }
    let cfg = Config::load_loc(&path).map_err(|e| {
        if !path.exists() {
            anyhow!("there are no settings yet ({}): run \"postwright\" on its own to start the setup wizard", path.describe())
        } else {
            e
        }
    })?;
    match cmd {
        Cmd::Serve | Cmd::Service { .. } | Cmd::Config { .. } => unreachable!(),
        Cmd::Domain { cmd } => domain_cmd(&cfg, cmd),
        Cmd::User { cmd } => user_cmd(&cfg, cmd),
        Cmd::Alias { cmd } => alias_cmd(&cfg, cmd),
        Cmd::Queue { cmd } => queue_cmd(&cfg, cmd),
        Cmd::Calendar { cmd } => calendar_cmd(&cfg, cmd),
        Cmd::Delegate { cmd } => delegate_cmd(&cfg, cmd),
        Cmd::Migrate { cmd } => migrate_cmd(cfg, cmd),
        Cmd::Cert { cmd } => cert_cmd(&cfg, cmd),
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

fn init(path: &Loc, hostname: &str, data_dir: Option<&Path>) -> Result<()> {
    if path.exists() {
        bail!("settings already exist in {}", path.describe());
    }
    let data_dir = &data_dir.map(Path::to_path_buf).unwrap_or_else(|| path.new_data_dir());
    // Relative to the settings, like everything else.
    let abs = if data_dir.is_relative() { path.base_dir().join(data_dir) } else { data_dir.clone() };
    let mut cfg = Config::default();
    cfg.hostname = hostname.to_ascii_lowercase();
    cfg.data_dir = data_dir.to_path_buf();
    cfg.tls.cert = data_dir.join("tls").join("cert.pem");
    cfg.tls.key = data_dir.join("tls").join("key.pem");
    std::fs::create_dir_all(abs.join("tls"))?;
    if !abs.join("tls").join("cert.pem").exists() {
        let ck = rcgen::generate_simple_self_signed(vec![cfg.hostname.clone()])?;
        std::fs::write(abs.join("tls").join("cert.pem"), ck.cert.pem())?;
        write_private(&abs.join("tls").join("key.pem"), ck.key_pair.serialize_pem().as_bytes())?;
        println!("Generated a self-signed certificate for {hostname}.");
        println!("Replace it with a real one (e.g. Let's Encrypt) before going live: see README.");
    }
    let text = format!(
        "# Postwright configuration. All keys are optional; defaults shown.\n{}",
        toml::to_string_pretty(&cfg)?
    );
    path.write(&text)?;
    open_store(&Config::load_loc(path)?)?;
    println!("Wrote the settings to {}. Next: postwright domain add <domain>", path.describe());
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
            if let Some(u) = st.sync(|c| store::find_user(c, &email))? {
                st.sync(|c| identity::end_all_sessions(c, u.id))?;
            }
            println!("Password updated (and signed out of the web pages and apps)");
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
        UserCmd::MfaReset { email } => {
            let u = st.sync(|c| store::find_user(c, &email))?.ok_or_else(|| anyhow!("no such user"))?;
            st.sync(|c| {
                identity::disable(c, u.id)?;
                identity::end_all_sessions(c, u.id)?;
                c.execute("DELETE FROM app_passwords WHERE user_id = ?1", [u.id])?;
                Ok(())
            })?;
            println!("Two-factor authentication is off for {email}; they've been signed out and their app passwords removed.");
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

fn cert_cmd(cfg: &Config, cmd: CertCmd) -> Result<()> {
    let st = open_store(cfg)?;
    match cmd {
        CertCmd::Status => {
            match certs::current(cfg) {
                Ok(i) => {
                    println!("Certificate:  {}", i.names.join(", "));
                    println!("Issuer:       {}", i.issuer);
                    println!(
                        "Expires:      {} ({} days){}",
                        chrono::DateTime::from_timestamp(i.not_after, 0).unwrap_or_default().format("%d %b %Y"),
                        i.days_left,
                        if i.covers_hostname { "" } else { "  – does NOT cover the host name!" }
                    );
                }
                Err(e) => println!("Certificate:  unreadable ({e:#})"),
            }
            let r = certs::receiver_info(cfg)?;
            println!();
            if r.listen.is_empty() {
                println!("SFTP receiver: disabled ([certs] sftp_listen is empty)");
            } else {
                println!("SFTP receiver: {} as user '{}'", r.listen.join(", "), r.user);
                println!("Host key:      {}", r.host_key_fingerprint);
                println!("               {}", r.host_key);
            }
            let keys = st.sync(|c| certs::list_keys(c))?;
            println!("Allowed keys:  {}", if keys.is_empty() { "none yet – add OPNsense's with `postwright cert key-add`".into() } else { keys.len().to_string() });
            for k in keys {
                println!("               {} {} {}", k.fingerprint, k.algorithm, k.comment);
            }
        }
        CertCmd::KeyAdd { key } => {
            let fp = st.sync(|c| certs::add_key(c, &key))?;
            println!("Allowed {fp} to push certificates");
        }
        CertCmd::KeyList => {
            for k in st.sync(|c| certs::list_keys(c))? {
                println!("{} {} {}", k.fingerprint, k.algorithm, k.comment);
            }
        }
        CertCmd::KeyRemove { fingerprint } => {
            if !st.sync(|c| certs::remove_key(c, &fingerprint))? {
                bail!("no such key");
            }
            println!("Removed");
        }
        CertCmd::Install { fullchain, key } => {
            let chain = std::fs::read(&fullchain)?;
            let k = std::fs::read(&key)?;
            let info = certs::validate(&chain, &k, &cfg.hostname, cfg.certs.require_hostname_match)?;
            std::fs::write(&cfg.tls.key, &k)?;
            std::fs::write(&cfg.tls.cert, &chain)?;
            println!("Installed certificate for {} (expires in {} days)", info.names.join(", "), info.days_left);
        }
    }
    Ok(())
}

fn migrate_cmd(cfg: Config, cmd: MigrateCmd) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async move {
        let srv = server::Server::new(cfg)?;
        let read_job = |p: &Path| -> Result<migrate::Job> {
            let t = std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
            serde_json::from_str(&t).with_context(|| format!("parsing {}", p.display()))
        };
        let p = match cmd {
            MigrateCmd::Discover { job } => {
                let j = read_job(&job)?;
                for d in migrate::discover(&srv, &j.source).await? {
                    println!("{:40} {:30} {}{}", d.source, d.name.unwrap_or_default(), d.kind, if d.exists_here { " (exists here)" } else { "" });
                }
                return Ok(());
            }
            MigrateCmd::Run { job } => migrate::run_blocking(srv, read_job(&job)?).await?,
            MigrateCmd::Files { path, user, folder } => {
                migrate::files::start(srv, path.display().to_string(), user, folder)?;
                migrate::wait_blocking().await
            }
        };
        for m in &p.mailboxes {
            println!(
                "{:32} -> {:32} {:16} {} messages, {} events, {} contacts{}",
                m.source, m.target, m.state, m.messages, m.events, m.contacts,
                if m.errors > 0 { format!(", {} errors (last: {})", m.errors, m.last_error.clone().unwrap_or_default()) } else { String::new() }
            );
        }
        if !p.created.is_empty() {
            println!("\nNew accounts and their passwords:");
            for (e, pw) in &p.created {
                println!("  {e}  {pw}");
            }
        }
        Ok(())
    })
}

fn delegate_cmd(cfg: &Config, cmd: DelegateCmd) -> Result<()> {
    let st = open_store(cfg)?;
    match cmd {
        DelegateCmd::Grant { owner, grantee, mailbox, send } => {
            let m = identity::MailboxRight::parse(&mailbox)?;
            let s = identity::SendRight::parse(&send)?;
            st.sync(|c| identity::grant(c, &owner.to_ascii_lowercase(), &grantee.to_ascii_lowercase(), m, s))?;
            println!("{grantee}: mailbox {} access to {owner}, send {}", m.as_str(), s.as_str());
        }
        DelegateCmd::Revoke { owner, grantee } => {
            st.sync(|c| identity::grant(c, &owner.to_ascii_lowercase(), &grantee.to_ascii_lowercase(), identity::MailboxRight::None, identity::SendRight::None))?;
            println!("Removed {grantee}'s access to {owner}");
        }
        DelegateCmd::List => {
            for d in st.sync(|c| identity::list_all(c))? {
                println!("{:32} -> {:32} mailbox={:5} send={}", d.grantee, d.owner, d.mailbox.as_str(), d.send.as_str());
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

pub fn serve(path: &Loc) -> Result<()> {
    let _ = configloc::ACTIVE.set(path.clone());
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(|| logbuf::Tee)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,lettre=warn,hickory=warn".into()),
        )
        .init();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    admin::mark_start();
    if setup::needed(path)? {
        if !rt.block_on(setup::run(path))? {
            return Ok(());
        }
    }
    let cfg = Config::load_loc(path)?;
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
        tokio::spawn(hold::run(srv.clone()));

        // Pick up renewed certificates as soon as the files change (any platform), and
        // accept pushes from OPNsense's ACME client on the built-in SFTP receiver.
        tokio::spawn(certs::watch(srv.clone()));
        if let Err(e) = certs::run_receiver(srv.clone()).await {
            tracing::error!("certificate receiver: {e:#}");
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
        tokio::select! {
            r = tokio::signal::ctrl_c() => r?,
            _ = service::STOP.notified() => {}
        }
        tracing::info!("shutting down");
        Ok(())
    })
}
