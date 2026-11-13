//! Blocking client for the Postwright admin API, with certificate pinning for servers
//! that use a self-signed certificate.

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
    /// A previously trusted self-signed certificate was replaced by another untrusted one.
    CertChanged(String),
    /// Password accepted; the account has two-step verification and needs a code.
    NeedCode,
    Other(String),
}

/// What the caller should do with its stored pin after a successful connection.
pub enum Pin {
    Keep,
    /// The server now has a publicly trusted certificate; the pin is no longer needed.
    Drop,
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
    /// Sign in. `pinned` is the approved fingerprint for a self-signed server, if any;
    /// `code` is the authenticator (or recovery) code once the server has asked for one.
    pub fn connect(server: &str, email: &str, password: &str, code: Option<&str>, pinned: Option<String>) -> Result<(Client, Value, Pin), ConnectError> {
        let base = normalise_url(server);
        let try_mode = |mode: Verify| -> Result<(Client, Value), (bool, ConnectError)> {
            let agent = agent(mode);
            let device = std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).unwrap_or_else(|_| "this computer".into());
            let mut body = serde_json::json!({ "email": email.trim(), "password": password, "kind": "app", "name": format!("Postwright Admin on {device}") });
            if let Some(c) = code.filter(|c| !c.trim().is_empty()) {
                body["code"] = Value::String(c.trim().to_string());
            }
            let r = agent.post(&format!("{base}/api/v1/login")).set("X-Requested-With", "postwright-admin").send_json(body);
            let token = match r {
                Ok(resp) => {
                    let v: Value = resp.into_json().map_err(|e| (false, ConnectError::Other(format!("bad response: {e}"))))?;
                    v["token"].as_str().map(String::from).ok_or((false, ConnectError::Other("the server didn't return a token".into())))?
                }
                Err(ureq::Error::Status(code, resp)) => {
                    let v: Value = resp.into_json().unwrap_or(Value::Null);
                    if v["mfa_required"].as_bool() == Some(true) {
                        return Err((false, ConnectError::NeedCode));
                    }
                    let msg = v["error"].as_str().map(String::from).unwrap_or_else(|| format!("server returned HTTP {code}"));
                    return Err((false, ConnectError::Other(msg)));
                }
                Err(ureq::Error::Transport(t)) => {
                    let e = t.to_string();
                    return Err((looks_like_cert_error(&e), ConnectError::Other(e)));
                }
            };
            let c = Client { base: base.clone(), auth: format!("Bearer {token}"), agent };
            match c.get("overview") {
                Ok(v) => Ok((c, v)),
                Err(e) => {
                    let _ = c.logout();
                    Err((false, ConnectError::Other(e)))
                }
            }
        };
        if let Some(fp) = &pinned {
            match try_mode(Verify::Pinned(fp.clone())) {
                Ok((c, v)) => return Ok((c, v, Pin::Keep)),
                Err((false, e)) => return Err(e),
                Err((true, _)) => {} // certificate changed: see below
            }
        }
        match try_mode(Verify::Public) {
            Ok((c, v)) => Ok((c, v, if pinned.is_some() { Pin::Drop } else { Pin::Keep })),
            Err((true, ConnectError::Other(e))) => {
                // Find out which certificate the server presented so the user can decide.
                let seen = Arc::new(Mutex::new(None));
                let _ = agent(Verify::Capture(seen.clone())).get(&format!("{base}/login")).call();
                let fp = seen.lock().unwrap().clone();
                match (fp, pinned.is_some()) {
                    (Some(fp), true) => Err(ConnectError::CertChanged(fp)),
                    (Some(fp), false) => Err(ConnectError::UntrustedCert(fp)),
                    (None, _) => Err(ConnectError::Other(e)),
                }
            }
            Err((_, e)) => Err(e),
        }
    }

    /// End the session on the server.
    pub fn logout(&self) -> Result<(), String> {
        self.agent
            .post(&format!("{}/api/v1/logout", self.base))
            .set("Authorization", &self.auth)
            .set("Content-Type", "application/json")
            .send_string("{}")
            .map(|_| ())
            .map_err(|e| e.to_string())
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
                    (401, _) => "Your session has ended. Sign in again.".into(),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs against a live test server: PW_TEST_SERVER=127.0.0.1:8443 cargo test -p postwright-admin -- --ignored
    #[test]
    #[ignore]
    fn live_sign_in() {
        let server = std::env::var("PW_TEST_SERVER").unwrap();
        let fp = match Client::connect(&server, "tony@johncock.test", "CorrectHorse1", None, None) {
            Err(ConnectError::UntrustedCert(fp)) => fp,
            _ => panic!("expected the self-signed certificate to be reported"),
        };
        assert!(matches!(Client::connect(&server, "tony@johncock.test", "wrong", None, Some(fp.clone())), Err(ConnectError::Other(_))));
        let (c, v, _) = Client::connect(&server, "tony@johncock.test", "CorrectHorse1", None, Some(fp.clone())).ok().unwrap();
        assert_eq!(v["hostname"], "mail.test.local");
        assert!(c.get("delegations").unwrap().is_array());
        c.logout().unwrap();
        assert!(c.get("overview").unwrap_err().starts_with("Your session has ended"));
        if let Ok(code) = std::env::var("PW_TEST_MFA_USER") {
            // user:password with two-step verification on
            let (u, p) = code.split_once(':').unwrap();
            assert!(matches!(Client::connect(&server, u, p, None, Some(fp)), Err(ConnectError::NeedCode)));
        }
    }
}
