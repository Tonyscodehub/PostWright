//! First-run setup wizard.
//!
//! When Postwright starts with no configuration, or with no administrator yet, it
//! doesn't start the mail services. Instead it serves a guided setup page over HTTPS
//! (self-signed certificate for now) and prints a one-time setup code to the console.
//! The page only answers on the networks in security.admin_networks and only to
//! someone who has the code. When the wizard finishes, Postwright starts normally.

use crate::config::Config;
use crate::http::{builder, json, json_err, text, Req, Resp};
use crate::server::{self, Shared};
use crate::store::{self, User};
use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use http_body_util::Full;
use hyper::StatusCode;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tokio::sync::Notify;

const SETUP_HTML: &str = include_str!("web/setup.html");
const SETUP_JS: &str = include_str!("web/setup.js");

/// Does this installation still need the wizard?
pub fn needed(config: &Path) -> Result<bool> {
    if !config.exists() {
        return Ok(true);
    }
    let cfg = Config::load(config)?;
    if !cfg.db_path().exists() {
        return Ok(true);
    }
    let st = store::Store::open(&cfg.db_path(), &cfg.blob_dir(), 1)?;
    st.sync(|c| {
        let admins: i64 = c.query_row("SELECT COUNT(*) FROM users WHERE is_admin = 1", [], |r| r.get(0))?;
        let done = store::get_meta(c, "setup.done")?.is_some();
        Ok(admins == 0 && !done)
    })
}

pub fn machine_name() -> String {
    let n = std::env::var("COMPUTERNAME")
        .ok()
        .or_else(|| std::fs::read_to_string("/proc/sys/kernel/hostname").ok())
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if n.contains('.') {
        n
    } else {
        "mail.example.com".into()
    }
}

/// Write a starting configuration with a self-signed certificate.
pub fn write_initial_config(path: &Path, hostname: &str) -> Result<()> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&dir)?;
    let mut cfg = Config::default();
    cfg.hostname = hostname.to_string();
    cfg.data_dir = PathBuf::from("data");
    cfg.tls.cert = PathBuf::from("data/tls/cert.pem");
    cfg.tls.key = PathBuf::from("data/tls/key.pem");
    let text = format!("# Postwright configuration, written by the setup wizard. Defaults are used for anything not listed.\n{}", toml::to_string_pretty(&cfg)?);
    std::fs::write(path, text)?;
    let loaded = Config::load(path)?;
    self_signed(&loaded, false)?;
    Ok(())
}

/// Make a self-signed certificate for the host name (replacing an earlier self-signed
/// one, never a real one).
fn self_signed(cfg: &Config, replace: bool) -> Result<bool> {
    if cfg.tls.cert.exists() && !replace {
        return Ok(false);
    }
    if cfg.tls.cert.exists() {
        if let Ok(info) = crate::certs::current(cfg) {
            if !info.self_signed {
                return Ok(false);
            }
        }
    }
    if let Some(d) = cfg.tls.cert.parent() {
        std::fs::create_dir_all(d)?;
    }
    let ck = rcgen::generate_simple_self_signed(vec![cfg.hostname.clone()])?;
    std::fs::write(&cfg.tls.cert, ck.cert.pem())?;
    std::fs::write(&cfg.tls.key, ck.key_pair.serialize_pem())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg.tls.key, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(true)
}

/// Change top-level or nested keys in the config file, keeping the rest.
fn edit_config(path: &Path, f: impl FnOnce(&mut toml::Table)) -> Result<()> {
    let old = std::fs::read_to_string(path)?;
    let mut t: toml::Table = old.parse().context("parsing config")?;
    f(&mut t);
    let new = format!("# Postwright configuration. Defaults are used for anything not listed.\n{}", toml::to_string_pretty(&t)?);
    std::fs::write(path, &new)?;
    if let Err(e) = Config::load(path) {
        std::fs::write(path, old)?;
        return Err(e.context("the new setting wasn't valid, so nothing was changed"));
    }
    Ok(())
}

fn table<'a>(t: &'a mut toml::Table, key: &str) -> &'a mut toml::Table {
    if !t.get(key).map(|v| v.is_table()).unwrap_or(false) {
        t.insert(key.into(), toml::Value::Table(Default::default()));
    }
    t.get_mut(key).unwrap().as_table_mut().unwrap()
}

struct State {
    path: PathBuf,
    srv: RwLock<Shared>,
    code: String,
    done: Notify,
    receiver: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    /// The certificate the setup page started with. It's kept for the whole wizard
    /// even if the certificate files change, because the browser has only accepted
    /// this one: a new self-signed certificate would make every request fail.
    tls: tokio_rustls::TlsAcceptor,
    finished: std::sync::atomic::AtomicBool,
}

fn new_code() -> String {
    const CH: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut r = rand::thread_rng();
    let s: String = (0..12).map(|_| CH[rand::Rng::gen_range(&mut r, 0..CH.len())] as char).collect();
    format!("{}-{}-{}", &s[..4], &s[4..8], &s[8..])
}

fn local_ips() -> Vec<String> {
    // The address used to reach the internet is the one people browse to.
    let mut v = Vec::new();
    if let Ok(s) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if s.connect("1.1.1.1:53").is_ok() {
            if let Ok(a) = s.local_addr() {
                v.push(a.ip().to_string());
            }
        }
    }
    v
}

fn open_browser(url: &str) {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("cmd").args(["/C", "start", "", url]).spawn();
    }
    #[cfg(not(windows))]
    {
        if std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some() {
            let _ = std::process::Command::new("xdg-open").arg(url).spawn();
        }
    }
}

/// Run the wizard until it's finished. Returns when Postwright should start normally.
pub async fn run(path: &Path) -> Result<()> {
    if !path.exists() {
        write_initial_config(path, &machine_name())?;
        tracing::info!("wrote a starting configuration to {}", path.display());
    }
    let cfg = Config::load(path)?;
    self_signed(&cfg, false)?;
    let srv = server::Server::new(cfg).context("starting the setup wizard")?;
    let st = Arc::new(State {
        path: path.to_path_buf(),
        tls: srv.tls(),
        srv: RwLock::new(srv.clone()),
        code: new_code(),
        done: Notify::new(),
        receiver: Default::default(),
        finished: Default::default(),
    });

    // Bind the HTTPS listeners, falling back to 8443 (e.g. Linux without root).
    let mut bound: Vec<(tokio::net::TcpListener, u16)> = Vec::new();
    for a in &srv.cfg.listeners.https {
        match tokio::net::TcpListener::bind(a).await {
            Ok(l) => {
                let port = l.local_addr()?.port();
                bound.push((l, port));
            }
            Err(e) => tracing::warn!("setup: cannot bind {a}: {e}"),
        }
    }
    if bound.is_empty() {
        let l = tokio::net::TcpListener::bind("0.0.0.0:8443").await.context("couldn't open port 443 or 8443 for the setup page")?;
        bound.push((l, 8443));
    }
    let port = bound[0].1;
    let suffix = if port == 443 { String::new() } else { format!(":{port}") };
    let mut tasks = Vec::new();
    for (l, _) in bound {
        let st = st.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                let Ok((tcp, peer)) = l.accept().await else { continue };
                let st = st.clone();
                tokio::spawn(async move {
                    let acceptor = st.tls.clone();
                    let Ok(stream) = crate::net::accept_tls(&acceptor, tcp).await else { return };
                    let io = hyper_util::rt::TokioIo::new(stream);
                    let svc = hyper::service::service_fn(move |req| {
                        let st = st.clone();
                        async move { Ok::<_, std::convert::Infallible>(handle(st, peer, req).await) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new().timer(hyper_util::rt::TokioTimer::new()).serve_connection(io, svc).await;
                });
            }
        }));
    }
    restart_receiver(&st);

    let ips = local_ips();
    let first = format!("https://localhost{suffix}/setup#{}", st.code);
    let banner = format!(
        "\n  ================================================================\n   Postwright setup\n\n   Open this page in a browser to set up your mail server:\n\n     {first}\n{}\n   Setup code (if the page asks): {}\n\n   Your browser will warn about the certificate: that's expected\n   until a real certificate is installed. Continue to the page.\n  ================================================================\n",
        ips.iter().map(|ip| format!("     https://{ip}{suffix}/setup#{}\n", st.code)).collect::<String>(),
        st.code
    );
    // Also into the log and a file next to the settings, because a Windows service
    // has no console to print to.
    crate::logbuf::write_line(&format!("SETUP: open {first} (setup code {})", st.code));
    let code_file = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")).join("setup-code.txt");
    let _ = std::fs::write(&code_file, format!("Postwright setup\r\n\r\nOpen: {first}\r\n{}\r\nSetup code: {}\r\n", ips.iter().map(|ip| format!("  or: https://{ip}{suffix}/setup#{}\r\n", st.code)).collect::<String>(), st.code));
    println!("{banner}");
    tracing::info!("setup wizard waiting on port {port}");
    open_browser(&first);

    st.done.notified().await;
    for t in tasks {
        t.abort();
    }
    for h in st.receiver.lock().unwrap().drain(..) {
        h.abort();
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let _ = std::fs::remove_file(&code_file);
    println!("\n  Setup finished: starting Postwright.\n");
    Ok(())
}

fn restart_receiver(st: &Arc<State>) {
    let srv = st.srv.read().unwrap().clone();
    for h in st.receiver.lock().unwrap().drain(..) {
        h.abort();
    }
    let st = st.clone();
    tokio::spawn(async move {
        // Give the old listener a moment to close.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        match crate::certs::start_receiver(srv).await {
            Ok(h) => st.receiver.lock().unwrap().extend(h),
            Err(e) => tracing::warn!("certificate receiver: {e:#}"),
        }
    });
}

fn static_file(ct: &str, body: &'static str) -> Resp {
    builder(StatusCode::OK).header("Content-Type", ct).header("Cache-Control", "no-store").body(Full::new(Bytes::from_static(body.as_bytes()))).unwrap()
}

fn same_code(a: &str, b: &str) -> bool {
    let (a, b) = (a.trim().to_ascii_uppercase().replace('-', ""), b.replace('-', ""));
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |x, (p, q)| x | (p ^ q)) == 0
}

async fn handle(st: Arc<State>, peer: SocketAddr, req: hyper::Request<hyper::body::Incoming>) -> Resp {
    if st.finished.load(std::sync::atomic::Ordering::Relaxed) {
        // Setup is over: close kept-alive connections so the browser reaches the real server.
        return builder(StatusCode::SERVICE_UNAVAILABLE).header("Connection", "close").header("Retry-After", "1").body(Full::default()).unwrap();
    }
    let srv = st.srv.read().unwrap().clone();
    if !crate::admin::in_networks(peer.ip(), &srv.cfg.security.admin_networks) {
        return text(StatusCode::FORBIDDEN, "Setup is only available from the local network.");
    }
    let r = match crate::http::read_req(req).await {
        Ok(r) => r,
        Err(e) => return e,
    };
    match r.path.as_str() {
        "/setup" | "/setup/" => {
            return builder(StatusCode::OK)
                .header("Content-Type", "text/html; charset=utf-8")
                .header("Cache-Control", "no-store")
                .header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
                .header("Referrer-Policy", "no-referrer")
                .body(Full::new(Bytes::from_static(SETUP_HTML.as_bytes())))
                .unwrap()
        }
        "/setup.js" => return static_file("application/javascript; charset=utf-8", SETUP_JS),
        "/migrate.js" => return static_file("application/javascript; charset=utf-8", crate::http::MIGRATE_JS),
        _ => {}
    }
    let Some(rest) = r.path.strip_prefix("/setup/api/") else {
        return builder(StatusCode::FOUND).header("Location", "/setup").body(Full::default()).unwrap();
    };
    if srv.guard.is_blocked(peer.ip()) {
        return json_err(StatusCode::TOO_MANY_REQUESTS, "Too many wrong codes. Wait a few minutes.");
    }
    if !r.header("x-setup-code").map(|c| same_code(&c, &st.code)).unwrap_or(false) {
        srv.guard.record_failure(peer.ip());
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        return json_err(StatusCode::UNAUTHORIZED, "That setup code isn't right. It's shown in the window where Postwright is running.");
    }
    if !matches!(r.method.as_str(), "GET" | "DELETE") && !r.header("content-type").unwrap_or_default().starts_with("application/json") {
        return json_err(StatusCode::UNSUPPORTED_MEDIA_TYPE, "Content-Type must be application/json");
    }
    match api(&st, &srv, &r, rest).await {
        Ok(v) => json(StatusCode::OK, &v),
        Err(e) => {
            tracing::warn!("setup: {rest}: {e:#}");
            json_err(StatusCode::BAD_REQUEST, &format!("{e:#}"))
        }
    }
}

fn wizard_user() -> User {
    User { id: 0, email: "setup wizard".into(), password: String::new(), quota_bytes: 0, enabled: true, is_admin: true }
}

fn body(r: &Req) -> Result<Value> {
    if r.body.is_empty() {
        return Ok(Value::Null);
    }
    Ok(serde_json::from_slice(&r.body)?)
}

async fn api(st: &Arc<State>, srv: &Shared, r: &Req, rest: &str) -> Result<Value> {
    let segs: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    match (r.method.as_str(), segs.as_slice()) {
        ("GET", ["state"]) => state(st, srv).await,
        ("POST", ["hostname"]) => {
            let b = body(r)?;
            let host = b["hostname"].as_str().unwrap_or("").trim().trim_end_matches('.').to_ascii_lowercase();
            if !host.contains('.') || host.len() > 253 || !host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
                bail!("enter the server's full name, e.g. mail.yourcompany.com");
            }
            if host == srv.cfg.hostname {
                return Ok(json!({ "ok": true, "certificate_regenerated": false }));
            }
            let h2 = host.clone();
            edit_config(&st.path, |t| {
                t.insert("hostname".into(), toml::Value::String(h2));
            })?;
            let cfg = Config::load(&st.path)?;
            let regenerated = self_signed(&cfg, true)?;
            let new = server::Server::new(cfg)?;
            *st.srv.write().unwrap() = new;
            restart_receiver(st);
            Ok(json!({ "ok": true, "certificate_regenerated": regenerated }))
        }
        ("POST", ["check-host"]) => {
            let b = body(r)?;
            let host = b["hostname"].as_str().unwrap_or(&srv.cfg.hostname).to_string();
            let (ips, ptr_ok, ptrs) = crate::admin::server_dns(srv, &host).await;
            let outbound25 = tokio::time::timeout(std::time::Duration::from_secs(6), tokio::net::TcpStream::connect("gmail-smtp-in.l.google.com:25")).await.map(|r| r.is_ok()).unwrap_or(false);
            Ok(json!({ "addresses": ips, "ptr": ptrs, "ptr_matches": ptr_ok, "outbound_25": outbound25 }))
        }
        ("GET", ["scanners"]) => {
            let found = crate::filter::detect_local().await;
            let cfg = &srv.cfg.filter;
            Ok(json!({ "detected": found, "configured": { "clamav": cfg.clamav.is_some(), "rspamd": cfg.rspamd.is_some(), "spamassassin": cfg.spamassassin.is_some() } }))
        }
        ("POST", ["scanners"]) => {
            let b = body(r)?;
            let found = crate::filter::detect_local().await;
            let addr = |n: &str| found.iter().find(|f| f["name"] == n).and_then(|f| f["address"].as_str()).unwrap_or("").to_string();
            let (c, rs, sa) = (b["clamav"].as_bool().unwrap_or(false), b["rspamd"].as_bool().unwrap_or(false), b["spamassassin"].as_bool().unwrap_or(false));
            let (ca, ra, sa_addr) = (addr("clamav"), addr("rspamd"), addr("spamassassin"));
            edit_config(&st.path, |t| {
                let f = table(t, "filter");
                for (on, key, val) in [(c, "clamav", ("address", ca)), (rs, "rspamd", ("url", ra)), (sa, "spamassassin", ("address", sa_addr))] {
                    if on {
                        let mut x = toml::Table::new();
                        x.insert(val.0.into(), toml::Value::String(val.1));
                        f.insert(key.into(), toml::Value::Table(x));
                    } else {
                        f.remove(key);
                    }
                }
            })?;
            reload(st)?;
            Ok(json!({ "ok": true }))
        }
        ("POST", ["service"]) => {
            let how = crate::service::install(&st.path)?;
            Ok(json!({ "ok": true, "how": how }))
        }
        ("POST", ["finish"]) => {
            let b = body(r)?;
            let admins: i64 = srv.store.call(|c| Ok(c.query_row("SELECT COUNT(*) FROM users WHERE is_admin = 1", [], |r| r.get(0))?)).await?;
            if admins == 0 {
                bail!("create an administrator account first");
            }
            srv.store.call(|c| store::set_meta(c, "setup.done", &store::now().to_string())).await?;
            let use_service = b["start_service"].as_bool().unwrap_or(false);
            let st2 = st.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(800)).await;
                st2.finished.store(true, std::sync::atomic::Ordering::Relaxed);
                if use_service {
                    crate::service::hand_over();
                }
                st2.done.notify_one();
            });
            Ok(json!({ "ok": true }))
        }
        (m, ["migrate", rest @ ..]) => crate::migrate::api(srv, m, rest, &r.body).await,
        // Everything else is the admin console's API, used as-is.
        (_, ["admin", ..]) => {
            let rest = rest.trim_start_matches("admin/");
            let me = wizard_user();
            let v = crate::admin::route(srv, &me, r, rest).await?;
            if r.method != "GET" && rest.starts_with("certs") {
                reload(st)?;
            }
            Ok(v)
        }
        _ => Err(anyhow!("unknown setup endpoint")),
    }
}

/// Re-read the configuration (and certificate) after a change.
fn reload(st: &Arc<State>) -> Result<()> {
    let cfg = Config::load(&st.path)?;
    *st.srv.write().unwrap() = server::Server::new(cfg)?;
    Ok(())
}

async fn state(st: &Arc<State>, srv: &Shared) -> Result<Value> {
    let (domains, admins, users) = srv
        .store
        .call(|c| {
            let mut s = c.prepare("SELECT name, alias_of FROM domains ORDER BY name")?;
            let d: Vec<Value> = s.query_map([], |r| Ok(json!({"name": r.get::<_, String>(0)?, "alias_of": r.get::<_, Option<String>>(1)?})))?.collect::<Result<_, _>>()?;
            let mut s = c.prepare("SELECT email FROM users WHERE is_admin = 1 ORDER BY email")?;
            let a: Vec<String> = s.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
            let n: i64 = c.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?;
            Ok((d, a, n))
        })
        .await?;
    let iredmail = cfg!(unix) && Path::new("/etc/postfix/main.cf").exists() && (Path::new("/var/vmail").exists() || Path::new("/opt/iredmail").exists() || Path::new("/etc/amavisd").exists() || Path::new("/etc/amavisd.conf").exists());
    let exe = std::env::current_exe().ok().map(|p| p.display().to_string());
    Ok(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "hostname": srv.cfg.hostname,
        "config_path": st.path.canonicalize().unwrap_or(st.path.clone()).display().to_string(),
        "data_dir": srv.cfg.data_dir.display().to_string(),
        "platform": std::env::consts::OS,
        "is_root": is_root(),
        "exe": exe,
        "local_ips": local_ips(),
        "certificate": crate::certs::current(&srv.cfg).ok(),
        "receiver": crate::certs::receiver_info(&srv.cfg).ok(),
        "domains": domains,
        "admins": admins,
        "users": users,
        "iredmail_detected": iredmail,
        "admin_networks": srv.cfg.security.admin_networks,
        "listeners": srv.cfg.listeners.https,
        "service": crate::service::state().describe(),
        "service_supported": is_root() && (cfg!(windows) || Path::new("/run/systemd/system").exists()),
    }))
}

fn is_root() -> bool {
    #[cfg(unix)]
    {
        std::fs::metadata("/proc/self").map(|m| std::os::unix::fs::MetadataExt::uid(&m) == 0).unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        // "net session" only succeeds for administrators.
        std::process::Command::new("net").arg("session").stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().map(|s| s.success()).unwrap_or(false)
    }
}

