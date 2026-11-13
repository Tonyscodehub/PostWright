//! Server configuration (TOML).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Public FQDN of this server (used in banners, EHLO, Received headers and as the MX target).
    pub hostname: String,
    /// Directory holding the database, message blobs and DKIM keys.
    pub data_dir: PathBuf,
    pub tls: TlsConfig,
    pub listeners: Listeners,
    pub limits: Limits,
    pub inbound: InboundPolicy,
    pub submission: SubmissionPolicy,
    pub queue: QueueConfig,
    pub security: SecurityConfig,
    pub filter: crate::filter::FilterConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsConfig {
    /// PEM certificate chain (e.g. Let's Encrypt fullchain.pem).
    pub cert: PathBuf,
    /// PEM private key (PKCS#8, PKCS#1 or SEC1).
    pub key: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Listeners {
    /// Inbound MX (STARTTLS offered; accepts mail only for hosted domains, never relays).
    pub smtp: Vec<String>,
    /// Message submission with STARTTLS (RFC 6409). Authentication mandatory.
    pub submission: Vec<String>,
    /// Message submission over implicit TLS (RFC 8314). Authentication mandatory.
    pub submissions: Vec<String>,
    /// IMAP with mandatory STARTTLS before login.
    pub imap: Vec<String>,
    /// IMAP over implicit TLS.
    pub imaps: Vec<String>,
    /// HTTPS: CalDAV calendars, settings web page and API, mail-client autoconfig.
    pub https: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Limits {
    pub max_message_size: usize,
    pub max_recipients: usize,
    /// Total concurrent connections per listener.
    pub max_connections: usize,
    /// Concurrent connections from a single IP address.
    pub max_connections_per_ip: usize,
    /// Idle timeout for SMTP commands, seconds.
    pub smtp_timeout_secs: u64,
    /// Idle timeout for IMAP (RFC 3501 requires >= 30 minutes), seconds.
    pub imap_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct InboundPolicy {
    /// Verify SPF, DKIM and DMARC on inbound mail and add an Authentication-Results header.
    pub verify: bool,
    /// Reject mail whose DMARC evaluation fails and whose domain publishes p=reject.
    pub enforce_dmarc_reject: bool,
    /// Reject mail when SPF returns a hard fail (-all) and DMARC did not pass.
    pub reject_spf_fail: bool,
    /// Refuse MAIL FROM on port 25 until the client has used STARTTLS.
    pub require_tls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SubmissionPolicy {
    /// Require the header From: address to belong to the authenticated user (anti-spoofing).
    pub enforce_from_header: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct QueueConfig {
    /// Parallel outbound deliveries.
    pub concurrency: usize,
    /// How often the queue is scanned, seconds.
    pub scan_interval_secs: u64,
    /// Give up and bounce after this many hours.
    pub max_age_hours: u64,
    /// Require a valid, matching certificate on remote MX hosts. Most MTAs use
    /// opportunistic (unverified) TLS for server-to-server traffic, which is the default.
    pub require_valid_remote_tls: bool,
    /// Optional smarthost (e.g. an ISP relay if outbound port 25 is blocked): "host:port".
    pub relay_host: Option<String>,
    pub relay_username: Option<String>,
    pub relay_password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Failed logins from one IP before it is temporarily blocked.
    pub max_auth_failures: u32,
    /// Window and block length, seconds.
    pub auth_block_secs: u64,
    /// Networks (CIDR) the admin console and admin API may be used from. Defaults to
    /// loopback and private ranges, so administration isn't exposed to the internet.
    pub admin_networks: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            hostname: "mail.example.com".into(),
            data_dir: PathBuf::from("./data"),
            tls: TlsConfig::default(),
            listeners: Listeners::default(),
            limits: Limits::default(),
            inbound: InboundPolicy::default(),
            submission: SubmissionPolicy::default(),
            queue: QueueConfig::default(),
            security: SecurityConfig::default(),
            filter: crate::filter::FilterConfig::default(),
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert: PathBuf::from("./data/tls/cert.pem"),
            key: PathBuf::from("./data/tls/key.pem"),
        }
    }
}

impl Default for Listeners {
    fn default() -> Self {
        Self {
            smtp: vec!["0.0.0.0:25".into(), "[::]:25".into()],
            submission: vec!["0.0.0.0:587".into()],
            submissions: vec!["0.0.0.0:465".into()],
            imap: vec!["0.0.0.0:143".into()],
            imaps: vec!["0.0.0.0:993".into()],
            https: vec!["0.0.0.0:443".into()],
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_message_size: 50 * 1024 * 1024,
            max_recipients: 100,
            max_connections: 2000,
            max_connections_per_ip: 30,
            smtp_timeout_secs: 300,
            imap_timeout_secs: 1860,
        }
    }
}

impl Default for InboundPolicy {
    fn default() -> Self {
        Self { verify: true, enforce_dmarc_reject: true, reject_spf_fail: false, require_tls: false }
    }
}

impl Default for SubmissionPolicy {
    fn default() -> Self {
        Self { enforce_from_header: true }
    }
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            concurrency: 32,
            scan_interval_secs: 15,
            max_age_hours: 120,
            require_valid_remote_tls: false,
            relay_host: None,
            relay_username: None,
            relay_password: None,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_auth_failures: 5,
            auth_block_secs: 900,
            admin_networks: ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let mut cfg: Config = toml::from_str(&text).context("parsing config")?;
        // Relative paths are relative to the config file, not the current directory,
        // so the CLI and a service manager always see the same data.
        let base = path.parent().map(Path::to_path_buf).unwrap_or_default();
        for p in [&mut cfg.data_dir, &mut cfg.tls.cert, &mut cfg.tls.key] {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        }
        Ok(cfg)
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("postwright.db")
    }

    pub fn blob_dir(&self) -> PathBuf {
        self.data_dir.join("blobs")
    }
}
