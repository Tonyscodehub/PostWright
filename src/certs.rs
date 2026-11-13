//! TLS certificate delivery and hot reload.
//!
//! * A watcher reloads the certificate whenever the files on disk change, on every
//!   platform, so any delivery method (OPNsense, certbot, a copy over SMB) needs no restart.
//! * A built-in, upload-only SFTP receiver lets OPNsense's ACME client push renewed
//!   certificates straight to Postwright with its standard "Upload certificate via SFTP"
//!   automation – on Windows too, with no OpenSSH server to install.
//!
//! The receiver accepts public-key logins only, from `security.admin_networks` only, for
//! keys you've approved. It understands nothing but uploads: there is no shell, no
//! command execution, and nothing can be downloaded. Uploaded files are held in memory,
//! and only a valid certificate and matching key that cover this server's host name are
//! ever installed.

use crate::server::Shared;
use crate::store;
use anyhow::{anyhow, bail, Context, Result};
use russh::keys::{HashAlg, PrivateKey, PublicKey};
use russh::server::{Auth, Msg, Session};
use russh::{Channel, ChannelId};
use russh_sftp::protocol::{Attrs, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CertConfig {
    /// Where the SFTP receiver listens. Empty disables it.
    pub sftp_listen: Vec<String>,
    /// User name OPNsense logs in with.
    pub sftp_user: String,
    /// Refuse certificates that don't cover `hostname` (protects against a wrong
    /// certificate being attached to the automation).
    pub require_hostname_match: bool,
}

impl Default for CertConfig {
    fn default() -> Self {
        Self { sftp_listen: vec!["0.0.0.0:2222".into()], sftp_user: "acme".into(), require_hostname_match: true }
    }
}

const ALLOWED: &[&str] = &["fullchain.pem", "cert.pem", "key.pem", "ca.pem", "chain.pem", "privkey.pem"];
const MAX_FILE: usize = 256 * 1024;

pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS cert_upload_keys(
    fingerprint TEXT PRIMARY KEY,
    key TEXT NOT NULL,
    comment TEXT,
    added INTEGER NOT NULL
);";

// ------------------------------------------------------------- inspection

#[derive(Debug, Clone, Serialize)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub names: Vec<String>,
    pub not_before: i64,
    pub not_after: i64,
    pub days_left: i64,
    pub sha256: String,
    pub covers_hostname: bool,
    pub self_signed: bool,
}

fn parse_pem_chain(pem: &[u8]) -> Result<Vec<Vec<u8>>> {
    let certs: Vec<_> = rustls_pemfile::certs(&mut &pem[..]).collect::<Result<_, _>>()?;
    if certs.is_empty() {
        bail!("no certificate found");
    }
    Ok(certs.into_iter().map(|c| c.as_ref().to_vec()).collect())
}

fn name_matches(pattern: &str, host: &str) -> bool {
    let (p, h) = (pattern.to_ascii_lowercase(), host.to_ascii_lowercase());
    match p.strip_prefix("*.") {
        Some(rest) => h.split_once('.').map(|(_, d)| d == rest).unwrap_or(false),
        None => p == h,
    }
}

pub fn inspect(der: &[u8], hostname: &str) -> Result<CertInfo> {
    let (_, c) = x509_parser::parse_x509_certificate(der).map_err(|e| anyhow!("bad certificate: {e}"))?;
    let mut names: Vec<String> = Vec::new();
    if let Ok(Some(san)) = c.subject_alternative_name() {
        for n in &san.value.general_names {
            if let x509_parser::extensions::GeneralName::DNSName(d) = n {
                names.push(d.to_string());
            }
        }
    }
    if names.is_empty() {
        for cn in c.subject().iter_common_name() {
            if let Ok(s) = cn.as_str() {
                names.push(s.to_string());
            }
        }
    }
    let not_after = c.validity().not_after.timestamp();
    Ok(CertInfo {
        subject: c.subject().to_string(),
        issuer: c.issuer().to_string(),
        covers_hostname: names.iter().any(|n| name_matches(n, hostname)),
        names,
        not_before: c.validity().not_before.timestamp(),
        not_after,
        days_left: (not_after - store::now()) / 86400,
        sha256: hex::encode(Sha256::digest(der)).to_uppercase(),
        self_signed: c.subject() == c.issuer(),
    })
}

pub fn current(cfg: &crate::config::Config) -> Result<CertInfo> {
    let pem = std::fs::read(&cfg.tls.cert).with_context(|| format!("reading {}", cfg.tls.cert.display()))?;
    let chain = parse_pem_chain(&pem)?;
    inspect(&chain[0], &cfg.hostname)
}

/// Check a certificate chain and key belong together and are usable.
pub fn validate(chain_pem: &[u8], key_pem: &[u8], hostname: &str, require_host: bool) -> Result<CertInfo> {
    let chain = parse_pem_chain(chain_pem)?;
    let key = rustls_pemfile::private_key(&mut &key_pem[..])?.ok_or_else(|| anyhow!("no private key found"))?;
    let signing = rustls::crypto::ring::sign::any_supported_type(&key).map_err(|e| anyhow!("unsupported private key: {e}"))?;
    let info = inspect(&chain[0], hostname)?;
    // The key's public half must match the certificate's.
    let (_, c) = x509_parser::parse_x509_certificate(&chain[0]).map_err(|e| anyhow!("bad certificate: {e}"))?;
    match signing.public_key() {
        Some(spki) if spki.as_ref() == c.public_key().raw => {}
        Some(_) => bail!("the private key does not match the certificate"),
        None => {}
    }
    if info.not_after <= store::now() {
        bail!("certificate expired on {}", chrono::DateTime::from_timestamp(info.not_after, 0).unwrap_or_default().to_rfc2822());
    }
    if require_host && !info.covers_hostname {
        bail!("certificate is for {} and does not cover {hostname}", info.names.join(", "));
    }
    Ok(info)
}

fn write_atomic(path: &Path, data: &[u8], private: bool) -> Result<()> {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let tmp = path.with_extension(format!("tmp{}", rand::random::<u32>()));
    std::fs::write(&tmp, data)?;
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = private;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Validate and install a certificate, then switch the running server to it.
pub fn install(srv: &Shared, chain_pem: &[u8], key_pem: &[u8], source: &str) -> Result<CertInfo> {
    let cfg = &srv.cfg;
    let info = validate(chain_pem, key_pem, &cfg.hostname, cfg.certs.require_hostname_match)?;
    let unchanged = std::fs::read(&cfg.tls.cert).map(|c| c == chain_pem).unwrap_or(false)
        && std::fs::read(&cfg.tls.key).map(|k| k == key_pem).unwrap_or(false);
    if unchanged {
        return Ok(info);
    }
    // Key first, then certificate: the watcher only acts once both agree.
    write_atomic(&cfg.tls.key, key_pem, true)?;
    write_atomic(&cfg.tls.cert, chain_pem, false)?;
    srv.reload_tls()?;
    *LAST_INSTALL.lock().unwrap() = Some((store::now(), source.to_string()));
    tracing::info!(
        "installed certificate for {} from {source} (expires in {} days)",
        info.names.join(", "),
        info.days_left
    );
    Ok(info)
}

pub static LAST_INSTALL: Mutex<Option<(i64, String)>> = Mutex::new(None);

// ---------------------------------------------------------------- watcher

fn mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

/// Reload the certificate whenever either file changes on disk. If the files are
/// mid-update (new certificate, old key) the current certificate stays in use and the
/// reload is retried on the next tick.
pub async fn watch(srv: Shared) {
    let (cert, key) = (srv.cfg.tls.cert.clone(), srv.cfg.tls.key.clone());
    let mut seen = (mtime(&cert), mtime(&key));
    let mut warned = false;
    let mut expiry_tick = 0u32;
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        let now = (mtime(&cert), mtime(&key));
        if now != seen {
            tokio::time::sleep(Duration::from_secs(2)).await; // let writers finish
            match srv.reload_tls() {
                Ok(()) => {
                    seen = (mtime(&cert), mtime(&key));
                    warned = false;
                    if let Ok(i) = current(&srv.cfg) {
                        tracing::info!("certificate files changed; now serving {} (expires in {} days)", i.names.join(", "), i.days_left);
                    }
                }
                Err(e) => {
                    if !warned {
                        tracing::warn!("certificate files changed but can't be loaded yet ({e:#}); keeping the current certificate");
                        warned = true;
                    }
                }
            }
        }
        expiry_tick += 1;
        if expiry_tick % 8640 == 1 {
            // About once a day.
            if let Ok(i) = current(&srv.cfg) {
                if i.days_left < 14 {
                    tracing::warn!("TLS certificate expires in {} days – check your renewal automation", i.days_left);
                }
            }
        }
    }
}

// ----------------------------------------------------------- upload keys

/// Parse an OpenSSH public key line, tolerating option prefixes such as the
/// `from="…",restrict` that OPNsense's "Show identity" adds.
pub fn parse_key_line(line: &str) -> Result<(PublicKey, String)> {
    let line = line.trim();
    let start = ["ssh-ed25519", "ssh-rsa", "ecdsa-sha2-", "sk-ssh-ed25519", "sk-ecdsa-"]
        .iter()
        .filter_map(|p| line.find(p))
        .min()
        .ok_or_else(|| anyhow!("that doesn't look like an SSH public key"))?;
    let key_part = &line[start..];
    let k = PublicKey::from_openssh(key_part).map_err(|e| anyhow!("invalid SSH public key: {e}"))?;
    Ok((k.clone(), k.comment().to_string()))
}

pub fn fingerprint(k: &PublicKey) -> String {
    k.fingerprint(HashAlg::Sha256).to_string()
}

pub fn add_key(c: &Connection, line: &str) -> Result<String> {
    let (k, comment) = parse_key_line(line)?;
    let fp = fingerprint(&k);
    let openssh = k.to_openssh().map_err(|e| anyhow!("{e}"))?;
    c.execute(
        "INSERT OR REPLACE INTO cert_upload_keys(fingerprint, key, comment, added) VALUES(?1, ?2, ?3, ?4)",
        params![fp, openssh, comment, store::now()],
    )?;
    Ok(fp)
}

pub fn remove_key(c: &Connection, fp: &str) -> Result<bool> {
    Ok(c.execute("DELETE FROM cert_upload_keys WHERE fingerprint = ?1", [fp])? > 0)
}

#[derive(Debug, Clone, Serialize)]
pub struct UploadKey {
    pub fingerprint: String,
    pub algorithm: String,
    pub comment: String,
    pub added: i64,
}

pub fn list_keys(c: &Connection) -> Result<Vec<UploadKey>> {
    let mut st = c.prepare("SELECT fingerprint, key, comment, added FROM cert_upload_keys ORDER BY added")?;
    let v = st
        .query_map([], |r| {
            let key: String = r.get(1)?;
            Ok(UploadKey {
                fingerprint: r.get(0)?,
                algorithm: key.split_whitespace().next().unwrap_or("").to_string(),
                comment: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                added: r.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(v)
}

fn key_allowed(c: &Connection, k: &PublicKey) -> Result<bool> {
    let n: i64 = c.query_row("SELECT COUNT(*) FROM cert_upload_keys WHERE fingerprint = ?1", [fingerprint(k)], |r| r.get(0))?;
    Ok(n > 0)
}

// --------------------------------------------------------------- host key

pub fn host_key_path(data_dir: &Path) -> PathBuf {
    data_dir.join("ssh_host_ed25519_key")
}

pub fn host_key(data_dir: &Path) -> Result<PrivateKey> {
    let p = host_key_path(data_dir);
    if let Ok(text) = std::fs::read_to_string(&p) {
        return PrivateKey::from_openssh(&text).map_err(|e| anyhow!("{}: {e}", p.display()));
    }
    let seed: [u8; 32] = rand::random();
    let kp = russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&seed);
    let key = PrivateKey::from(kp);
    let text = key.to_openssh(russh::keys::ssh_key::LineEnding::LF).map_err(|e| anyhow!("{e}"))?;
    write_atomic(&p, text.as_bytes(), true)?;
    Ok(key)
}

#[derive(Debug, Clone, Serialize)]
pub struct ReceiverInfo {
    pub listen: Vec<String>,
    pub user: String,
    pub host_key: String,
    pub host_key_fingerprint: String,
}

pub fn receiver_info(cfg: &crate::config::Config) -> Result<ReceiverInfo> {
    let k = host_key(&cfg.data_dir)?;
    let pubk = k.public_key();
    Ok(ReceiverInfo {
        listen: cfg.certs.sftp_listen.clone(),
        user: cfg.certs.sftp_user.clone(),
        host_key: pubk.to_openssh().map_err(|e| anyhow!("{e}"))?,
        host_key_fingerprint: fingerprint(pubk),
    })
}

// ------------------------------------------------------------ SSH server

pub async fn run_receiver(srv: Shared) -> Result<()> {
    let addrs = srv.cfg.certs.sftp_listen.clone();
    if addrs.is_empty() {
        return Ok(());
    }
    let key = host_key(&srv.cfg.data_dir)?;
    let config = Arc::new(russh::server::Config {
        keys: vec![key],
        auth_rejection_time: Duration::from_secs(2),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        inactivity_timeout: Some(Duration::from_secs(120)),
        max_auth_attempts: 3,
        server_id: russh::SshId::Standard("SSH-2.0-Postwright".into()),
        ..Default::default()
    });
    for addr in addrs {
        let listener = match tokio::net::TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!("certificate receiver: cannot bind {addr}: {e}");
                continue;
            }
        };
        tracing::info!("certificate receiver (SFTP) listening on {addr}");
        let (srv, config) = (srv.clone(), config.clone());
        tokio::spawn(async move {
            loop {
                let Ok((tcp, peer)) = listener.accept().await else { continue };
                if !crate::admin::in_networks(peer.ip(), &srv.cfg.security.admin_networks) {
                    tracing::warn!("certificate receiver: refused {} (not in admin_networks)", peer.ip());
                    continue;
                }
                if srv.guard.is_blocked(peer.ip()) {
                    continue;
                }
                let Some(slot) = srv.guard.connect(peer.ip()) else { continue };
                let handler = SshHandler { srv: srv.clone(), peer, channels: HashMap::new(), user: None };
                let config = config.clone();
                tokio::spawn(async move {
                    let _slot = slot;
                    match russh::server::run_stream(config, tcp, handler).await {
                        Ok(session) => {
                            if let Err(e) = session.await {
                                tracing::debug!("certificate receiver session ended: {e:#}");
                            }
                        }
                        Err(e) => tracing::debug!("certificate receiver handshake failed from {peer}: {e:#}"),
                    }
                });
            }
        });
    }
    Ok(())
}

struct SshHandler {
    srv: Shared,
    peer: SocketAddr,
    channels: HashMap<ChannelId, Channel<Msg>>,
    user: Option<String>,
}

impl russh::server::Handler for SshHandler {
    type Error = anyhow::Error;

    async fn auth_publickey_offered(&mut self, user: &str, offer: russh::server::PublicKeyOffer<'_>) -> Result<Auth, Self::Error> {
        let ok = user == self.srv.cfg.certs.sftp_user && {
            let k = offer.public_key.clone();
            self.srv.store.call(move |c| key_allowed(c, &k)).await.unwrap_or(false)
        };
        Ok(if ok { Auth::Accept } else { Auth::Reject { proceed_with_methods: None, partial_success: false } })
    }

    async fn auth_publickey(&mut self, user: &str, key: russh::server::VerifiedPublicKey<'_>) -> Result<Auth, Self::Error> {
        let k = key.public_key.clone();
        let fp = fingerprint(&k);
        let ok = user == self.srv.cfg.certs.sftp_user && self.srv.store.call(move |c| key_allowed(c, &k)).await.unwrap_or(false);
        if ok {
            self.srv.guard.record_success(self.peer.ip());
            self.user = Some(fp.clone());
            tracing::info!("certificate receiver: {} logged in with key {fp}", self.peer.ip());
            Ok(Auth::Accept)
        } else {
            self.srv.guard.record_failure(self.peer.ip());
            tracing::warn!("certificate receiver: rejected key {fp} for user '{user}' from {}", self.peer.ip());
            Ok(Auth::Reject { proceed_with_methods: None, partial_success: false })
        }
    }

    async fn auth_password(&mut self, _user: &str, _password: &str) -> Result<Auth, Self::Error> {
        self.srv.guard.record_failure(self.peer.ip());
        Ok(Auth::Reject { proceed_with_methods: None, partial_success: false })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn channel_eof(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        session.close(channel)?;
        Ok(())
    }

    async fn subsystem_request(&mut self, id: ChannelId, name: &str, session: &mut Session) -> Result<(), Self::Error> {
        match (name, self.channels.remove(&id)) {
            ("sftp", Some(ch)) => {
                session.channel_success(id)?;
                let sftp = Sftp { srv: self.srv.clone(), peer: self.peer, files: BTreeMap::new(), handles: HashMap::new(), next: 0, dir_done: HashMap::new() };
                tokio::spawn(russh_sftp::server::run(ch.into_stream(), sftp));
            }
            _ => session.channel_failure(id)?,
        }
        Ok(())
    }

    async fn exec_request(&mut self, id: ChannelId, _data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        session.channel_failure(id)?; // no command execution, ever
        Ok(())
    }

    async fn shell_request(&mut self, id: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        session.channel_failure(id)?;
        Ok(())
    }
}

// ------------------------------------------------------------ SFTP layer

/// A virtual, write-only filesystem. Every directory "exists"; recognised certificate
/// files are kept in memory for this session and installed once a valid set arrives.
struct Sftp {
    srv: Shared,
    peer: SocketAddr,
    /// Uploaded files by base name.
    files: BTreeMap<String, Vec<u8>>,
    /// Open handles: handle -> (base name, buffer, is_dir)
    handles: HashMap<String, (String, Vec<u8>, bool)>,
    next: u64,
    dir_done: HashMap<String, bool>,
}

fn base(path: &str) -> String {
    path.trim_end_matches('/').rsplit(['/', '\\']).next().unwrap_or("").to_ascii_lowercase()
}

fn dir_attrs() -> FileAttributes {
    let mut a = FileAttributes::empty();
    a.permissions = Some(0o040755);
    a.mtime = Some(store::now() as u32);
    a
}

fn file_attrs(size: usize) -> FileAttributes {
    let mut a = FileAttributes::empty();
    a.permissions = Some(0o100600);
    a.size = Some(size as u64);
    a.mtime = Some(store::now() as u32);
    a
}

fn ok(id: u32) -> Status {
    Status { id, status_code: StatusCode::Ok, error_message: "Ok".into(), language_tag: "en-US".into() }
}

fn normalise(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for p in path.split('/') {
        match p {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            x => parts.push(x),
        }
    }
    format!("/{}", parts.join("/"))
}

impl Sftp {
    fn try_install(&mut self) {
        let f = &self.files;
        let chain = match (f.get("fullchain.pem"), f.get("cert.pem"), f.get("ca.pem").or(f.get("chain.pem"))) {
            (Some(fc), _, _) => fc.clone(),
            (None, Some(c), Some(ca)) => {
                let mut v = c.clone();
                if !v.ends_with(b"\n") {
                    v.push(b'\n');
                }
                v.extend_from_slice(ca);
                v
            }
            (None, Some(c), None) => c.clone(),
            _ => return,
        };
        let Some(key) = f.get("key.pem").or(f.get("privkey.pem")).cloned() else {
            // OPNsense sends the key last, so this usually waits for it. A renewal that
            // reuses the existing key installs straight away against the current key.
            if let Ok(k) = std::fs::read(&self.srv.cfg.tls.key) {
                let _ = install(&self.srv, &chain, &k, &format!("SFTP upload from {}", self.peer.ip()));
            }
            return;
        };
        match install(&self.srv, &chain, &key, &format!("SFTP upload from {}", self.peer.ip())) {
            Ok(_) => {}
            Err(e) => tracing::warn!("certificate receiver: upload from {} not installed: {e:#}", self.peer.ip()),
        }
    }
}

impl russh_sftp::server::Handler for Sftp {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(&mut self, _version: u32, _ext: HashMap<String, String>) -> Result<Version, Self::Error> {
        Ok(Version::new())
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let p = normalise(&path);
        Ok(Name { id, files: vec![File::new(p, dir_attrs())] })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let b = base(&path);
        Ok(Attrs { id, attrs: match self.files.get(&b) { Some(f) => file_attrs(f.len()), None => dir_attrs() } })
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        self.stat(id, path).await
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        match self.handles.get(&handle) {
            Some((_, buf, false)) => Ok(Attrs { id, attrs: file_attrs(buf.len()) }),
            Some((_, _, true)) => Ok(Attrs { id, attrs: dir_attrs() }),
            None => Err(StatusCode::Failure),
        }
    }

    async fn mkdir(&mut self, id: u32, _path: String, _attrs: FileAttributes) -> Result<Status, Self::Error> {
        Ok(ok(id))
    }

    async fn rmdir(&mut self, id: u32, _path: String) -> Result<Status, Self::Error> {
        Ok(ok(id))
    }

    async fn setstat(&mut self, id: u32, _path: String, _attrs: FileAttributes) -> Result<Status, Self::Error> {
        Ok(ok(id)) // chmod/chgrp/modtime: accepted and ignored
    }

    async fn fsetstat(&mut self, id: u32, _handle: String, _attrs: FileAttributes) -> Result<Status, Self::Error> {
        Ok(ok(id))
    }

    async fn remove(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        self.files.remove(&base(&path));
        Ok(ok(id))
    }

    async fn rename(&mut self, id: u32, old: String, new: String) -> Result<Status, Self::Error> {
        if let Some(d) = self.files.remove(&base(&old)) {
            self.files.insert(base(&new), d);
        }
        Ok(ok(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        self.next += 1;
        let h = format!("d{}", self.next);
        self.handles.insert(h.clone(), (path, Vec::new(), true));
        self.dir_done.insert(h.clone(), false);
        Ok(Handle { id, handle: h })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        if self.dir_done.get(&handle).copied().unwrap_or(true) {
            return Err(StatusCode::Eof);
        }
        self.dir_done.insert(handle, true);
        let mut files = vec![File::new(".", dir_attrs()), File::new("..", dir_attrs())];
        files.extend(self.files.iter().map(|(n, d)| File::new(n.clone(), file_attrs(d.len()))));
        Ok(Name { id, files })
    }

    async fn open(&mut self, id: u32, filename: String, pflags: OpenFlags, _attrs: FileAttributes) -> Result<Handle, Self::Error> {
        if !pflags.intersects(OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::APPEND) {
            return Err(StatusCode::PermissionDenied); // nothing can be read back
        }
        if self.handles.len() > 32 {
            return Err(StatusCode::Failure);
        }
        self.next += 1;
        let h = format!("f{}", self.next);
        self.handles.insert(h.clone(), (base(&filename), Vec::new(), false));
        Ok(Handle { id, handle: h })
    }

    async fn read(&mut self, _id: u32, _handle: String, _offset: u64, _len: u32) -> Result<russh_sftp::protocol::Data, Self::Error> {
        Err(StatusCode::PermissionDenied)
    }

    async fn write(&mut self, id: u32, handle: String, offset: u64, data: Vec<u8>) -> Result<Status, Self::Error> {
        let Some((_, buf, false)) = self.handles.get_mut(&handle) else { return Err(StatusCode::Failure) };
        let end = offset as usize + data.len();
        if end > MAX_FILE {
            return Err(StatusCode::Failure);
        }
        if buf.len() < end {
            buf.resize(end, 0);
        }
        buf[offset as usize..end].copy_from_slice(&data);
        Ok(ok(id))
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.dir_done.remove(&handle);
        if let Some((name, buf, is_dir)) = self.handles.remove(&handle) {
            if !is_dir {
                let known = ALLOWED.contains(&name.as_str());
                self.files.insert(name.clone(), buf);
                if known {
                    // Validation does crypto and disk I/O; don't stall the async workers.
                    tokio::task::block_in_place(|| self.try_install());
                }
            }
        }
        Ok(ok(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert!(name_matches("*.johncock.co.uk", "mail.johncock.co.uk"));
        assert!(!name_matches("*.johncock.co.uk", "johncock.co.uk"));
        assert!(name_matches("MAIL.example.com", "mail.example.com"));
        assert_eq!(base("/home/acme/mail.example.com/fullchain.pem"), "fullchain.pem");
        assert_eq!(normalise("/a/./b/../c/"), "/a/c");
        assert_eq!(normalise("."), "/");
        let line = r#"from="192.168.1.1",restrict ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl root@OPNsense"#;
        let (k, comment) = parse_key_line(line).unwrap();
        assert_eq!(comment, "root@OPNsense");
        assert!(fingerprint(&k).starts_with("SHA256:"));
        assert!(parse_key_line("hello").is_err());
    }
}
