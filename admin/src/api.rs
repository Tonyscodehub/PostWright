//! Blocking client for the Postwright admin API, with certificate pinning for servers
//! that use a self-signed certificate.

use base64::Engine;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone)]
pub struct Client {
    base: String,
    auth: String,
    agent: ureq::Agent,
}

pub enum ConnectError {
    /// The certificate isn't publicly trusted; here is its SHA-256 fingerprint.
    UntrustedCert(String),
    Other(String),
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub fn fingerprint(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der)).to_uppercase().as_bytes().chunks(2).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join(":")
}

/// Accepts exactly one certificate (by fingerprint), or records whatever it sees when
/// `pinned` is None (used once, to show the user the fingerprint to approve).
#[derive(Debug)]
struct Pinned {
    pinned: Option<String>,
    seen: Arc<Mutex<Option<String>>>,
    schemes: Vec<SignatureScheme>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fp = fingerprint(end_entity.as_ref());
        *self.seen.lock().unwrap() = Some(fp.clone());
        match &self.pinned {
            Some(p) if *p == fp => Ok(ServerCertVerified::assertion()),
            _ => Err(rustls::Error::General("certificate does not match the pinned fingerprint".into())),
        }
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &provider().signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &provider().signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

enum Verify {
    /// Normal public-CA verification.
    Public,
    /// Accept only this certificate fingerprint.
    Pinned(String),
    /// Record the presented certificate and refuse it.
    Capture(Arc<Mutex<Option<String>>>),
}

fn agent(mode: Verify) -> ureq::Agent {
    let builder = rustls::ClientConfig::builder_with_provider(provider()).with_safe_default_protocol_versions().unwrap();
    let schemes = provider().signature_verification_algorithms.supported_schemes();
    let cfg = match mode {
        Verify::Public => {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            builder.with_root_certificates(roots).with_no_client_auth()
        }
        Verify::Pinned(fp) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Pinned { pinned: Some(fp), seen: Arc::new(Mutex::new(None)), schemes }))
            .with_no_client_auth(),
        Verify::Capture(seen) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Pinned { pinned: None, seen, schemes }))
            .with_no_client_auth(),
    };
    ureq::AgentBuilder::new()
        .tls_config(Arc::new(cfg))
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .build()
}

pub fn normalise_url(s: &str) -> String {
    let s = s.trim().trim_end_matches('/');
    if s.starts_with("https://") {
        s.to_string()
    } else if let Some(rest) = s.strip_prefix("http://") {
        format!("https://{rest}")
    } else {
        format!("https://{s}")
    }
}

impl Client {
    /// Sign in. `pinned` is the approved fingerprint for a self-signed server, if any.
    pub fn connect(server: &str, email: &str, password: &str, pinned: Option<String>) -> Result<(Client, Value), ConnectError> {
        let base = normalise_url(server);
        let auth = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{}:{password}", email.trim())));
        let mode = match &pinned {
            Some(fp) => Verify::Pinned(fp.clone()),
            None => Verify::Public,
        };
        let c = Client { base: base.clone(), auth, agent: agent(mode) };
        match c.get("overview") {
            Ok(v) => Ok((c, v)),
            Err(e) if pinned.is_none() && looks_like_cert_error(&e) => {
                // Find out which certificate the server presented so the user can decide.
                let seen = Arc::new(Mutex::new(None));
                let probe = agent(Verify::Capture(seen.clone()));
                let _ = probe.get(&format!("{base}/")).call();
                let fp = seen.lock().unwrap().clone();
                match fp {
                    Some(fp) => Err(ConnectError::UntrustedCert(fp)),
                    None => Err(ConnectError::Other(e)),
                }
            }
            Err(e) => Err(ConnectError::Other(e)),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/api/v1/admin/{}", self.base, path.trim_start_matches('/'))
    }

    fn handle(r: Result<ureq::Response, ureq::Error>) -> Result<Value, String> {
        match r {
            Ok(resp) => resp.into_json::<Value>().map_err(|e| format!("bad response: {e}")),
            Err(ureq::Error::Status(code, resp)) => {
                let body: Value = resp.into_json().unwrap_or(Value::Null);
                let msg = body.get("error").and_then(|e| e.as_str()).map(String::from);
                Err(match (code, msg) {
                    (401, _) => "Wrong email address or password.".into(),
                    (_, Some(m)) => m,
                    (c, None) => format!("server returned HTTP {c}"),
                })
            }
            Err(ureq::Error::Transport(t)) => Err(t.to_string()),
        }
    }

    fn req(&self, method: &str, path: &str) -> ureq::Request {
        self.agent.request(method, &self.url(path)).set("Authorization", &self.auth).set("X-Requested-With", "postwright-admin")
    }

    pub fn get(&self, path: &str) -> Result<Value, String> {
        Self::handle(self.req("GET", path).call())
    }
    pub fn send(&self, method: &str, path: &str, body: &Value) -> Result<Value, String> {
        Self::handle(self.req(method, path).send_json(body.clone()))
    }
    pub fn delete(&self, path: &str) -> Result<Value, String> {
        Self::handle(self.req("DELETE", path).call())
    }
    pub fn base(&self) -> &str {
        &self.base
    }
}

fn looks_like_cert_error(e: &str) -> bool {
    let e = e.to_ascii_lowercase();
    e.contains("certificate") || e.contains("unknownissuer") || e.contains("invalid peer") || e.contains("tls")
}

/// Percent-encode a path segment (email addresses, domain names).
pub fn seg(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-_.~@+".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}
