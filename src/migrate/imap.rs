//! Copying mail from any IMAP server: Exchange on-premises, Dovecot, Zimbra, Gmail,
//! Yahoo, Fastmail and so on.

use super::{clean_flags, map_folder, MailboxMap, Source, Special, Target, Tick};
use anyhow::{anyhow, bail, Context, Result};
use async_imap::types::{Fetch, NameAttribute};
use base64::Engine;
use futures_util::StreamExt;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + std::fmt::Debug {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + std::fmt::Debug> Io for T {}

type Conn = Box<dyn Io>;
type Session = async_imap::Session<Conn>;

#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

async fn tls(host: &str, tcp: Conn, insecure: bool) -> Result<Conn> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let b = rustls::ClientConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions()?;
    let cfg = if insecure {
        b.dangerous().with_custom_certificate_verifier(Arc::new(NoVerify(provider))).with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        b.with_root_certificates(roots).with_no_client_auth()
    };
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|_| anyhow!("invalid host name {host}"))?;
    let s = tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, tcp).await.map_err(|e| {
        if e.to_string().contains("certificate") || e.to_string().contains("UnknownIssuer") {
            anyhow!("the old server's certificate isn't trusted ({e}); tick \"accept a self-signed certificate\" if you know it's self-signed")
        } else {
            anyhow!("TLS: {e}")
        }
    })?;
    Ok(Box::new(s))
}

struct Plain {
    authzid: String,
    user: String,
    pass: String,
}

impl async_imap::Authenticator for Plain {
    type Response = Vec<u8>;
    fn process(&mut self, _: &[u8]) -> Vec<u8> {
        format!("{}\0{}\0{}", self.authzid, self.user, self.pass).into_bytes()
    }
}

async fn connect(src: &Source, m: &MailboxMap) -> Result<Session> {
    let Source::Imap { host, port, security, admin, insecure } = src else { bail!("not an IMAP source") };
    let host = host.trim();
    let tcp = tokio::time::timeout(std::time::Duration::from_secs(20), tokio::net::TcpStream::connect((host, *port)))
        .await
        .map_err(|_| anyhow!("timed out connecting to {host}:{port}"))?
        .with_context(|| format!("connecting to {host}:{port}"))?;
    let stream: Conn = Box::new(tcp);
    let client = match security.as_str() {
        "tls" | "ssl" => {
            let mut c = async_imap::Client::new(tls(host, stream, *insecure).await?);
            c.read_response().await.ok_or_else(|| anyhow!("no greeting from {host}"))??;
            c
        }
        "starttls" => {
            let mut c = async_imap::Client::new(stream);
            c.read_response().await.ok_or_else(|| anyhow!("no greeting from {host}"))??;
            c.run_command_and_check_ok("STARTTLS", None).await.context("STARTTLS")?;
            async_imap::Client::new(tls(host, c.into_inner(), *insecure).await?)
        }
        _ => {
            let mut c = async_imap::Client::new(stream);
            c.read_response().await.ok_or_else(|| anyhow!("no greeting from {host}"))??;
            c
        }
    };
    let r = match admin {
        Some(a) if a.style == "dovecot" => client.login(format!("{}*{}", m.source.trim(), a.user.trim()), &a.password).await,
        Some(a) => {
            client
                .authenticate("PLAIN", Plain { authzid: m.source.trim().to_string(), user: a.user.trim().to_string(), pass: a.password.clone() })
                .await
        }
        None => {
            let pw = m.password.clone().ok_or_else(|| anyhow!("no password for {} (or set an administrator account)", m.source))?;
            client.login(m.source.trim(), pw).await
        }
    };
    r.map_err(|(e, _)| anyhow!("sign-in to {host} as {} failed: {e}", m.source))
}

pub async fn test(src: &Source, m: &MailboxMap) -> Result<String> {
    let mut s = connect(src, m).await?;
    let n = {
        let list = s.list(Some(""), Some("*")).await?;
        list.filter_map(|r| async move { r.ok() }).collect::<Vec<_>>().await.len()
    };
    let _ = s.logout().await;
    Ok(format!("Signed in as {}: {n} folders found", m.source))
}

/// Decode IMAP's modified UTF-7 mailbox names (RFC 3501 5.1.3).
pub fn decode_mutf7(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        let Some(j) = after.find('-') else {
            out.push_str(&rest[i..]);
            return out;
        };
        let enc = &after[..j];
        if enc.is_empty() {
            out.push('&');
        } else {
            let b64 = enc.replace(',', "/");
            let pad = "=".repeat((4 - b64.len() % 4) % 4);
            match base64::engine::general_purpose::STANDARD.decode(format!("{b64}{pad}")) {
                Ok(bytes) => {
                    let units: Vec<u16> = bytes.chunks(2).filter(|c| c.len() == 2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
                    out.push_str(&String::from_utf16_lossy(&units));
                }
                Err(_) => out.push_str(&rest[i..i + 2 + j]),
            }
        }
        rest = &after[j + 1..];
    }
    out.push_str(rest);
    out
}

/// Encode a folder name in IMAP's modified UTF-7, which is how mail apps store
/// non-ASCII folder names on Postwright.
pub fn encode_mutf7(s: &str) -> String {
    let mut out = String::new();
    let mut buf: Vec<u16> = Vec::new();
    let flush = |buf: &mut Vec<u16>, out: &mut String| {
        if buf.is_empty() {
            return;
        }
        let bytes: Vec<u8> = buf.iter().flat_map(|u| u.to_be_bytes()).collect();
        let b = base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes).replace('/', ",");
        out.push('&');
        out.push_str(&b);
        out.push('-');
        buf.clear();
    };
    for ch in s.chars() {
        if (' '..='~').contains(&ch) {
            flush(&mut buf, &mut out);
            if ch == '&' {
                out.push_str("&-");
            } else {
                out.push(ch);
            }
        } else {
            let mut tmp = [0u16; 2];
            buf.extend_from_slice(ch.encode_utf16(&mut tmp));
        }
    }
    flush(&mut buf, &mut out);
    out
}

fn special(attrs: &[NameAttribute<'_>]) -> Option<Special> {
    for a in attrs {
        match a {
            NameAttribute::Sent => return Some(Special::Sent),
            NameAttribute::Drafts => return Some(Special::Drafts),
            NameAttribute::Trash => return Some(Special::Trash),
            NameAttribute::Junk => return Some(Special::Junk),
            NameAttribute::Archive => return Some(Special::Archive),
            NameAttribute::All | NameAttribute::Flagged => return Some(Special::Virtual),
            NameAttribute::Extension(x) if x.eq_ignore_ascii_case("\\Important") => return Some(Special::Virtual),
            _ => {}
        }
    }
    None
}

fn flags_of(f: &Fetch) -> Vec<String> {
    use async_imap::types::Flag;
    clean_flags(f.flags().map(|x| match x {
        Flag::Seen => "\\Seen".to_string(),
        Flag::Answered => "\\Answered".to_string(),
        Flag::Flagged => "\\Flagged".to_string(),
        Flag::Deleted => "\\Deleted".to_string(),
        Flag::Draft => "\\Draft".to_string(),
        Flag::Recent => "\\Recent".to_string(),
        Flag::MayCreate => "\\*".to_string(),
        Flag::Custom(c) => c.to_string(),
    }))
}

/// One folder on the old server: (raw name, display path, special use).
struct Folder {
    raw: String,
    path: Vec<String>,
    special: Option<Special>,
}

async fn folders(s: &mut Session) -> Result<Vec<Folder>> {
    let names: Vec<_> = s.list(Some(""), Some("*")).await?.filter_map(|r| async move { r.ok() }).collect().await;
    let mut out = Vec::new();
    for n in &names {
        if n.attributes().iter().any(|a| matches!(a, NameAttribute::NoSelect)) {
            continue;
        }
        let delim = n.delimiter().unwrap_or("/").to_string();
        let raw = n.name().to_string();
        let mut path: Vec<String> = if delim.is_empty() { vec![decode_mutf7(&raw)] } else { decode_mutf7(&raw).split(delim.as_str()).map(String::from).collect() };
        // Courier/old Dovecot put everything under "INBOX.": treat those as top level.
        if delim == "." && path.len() > 1 && path[0].eq_ignore_ascii_case("INBOX") {
            path.remove(0);
        }
        out.push(Folder { raw, path, special: special(n.attributes()) });
    }
    Ok(out)
}

pub async fn migrate(src: &Source, m: &MailboxMap, t: &Target, tick: &Tick) -> Result<()> {
    if !t.opts.mail {
        return Ok(());
    }
    tick.step("signing in");
    let mut s = connect(src, m).await?;
    let list = folders(&mut s).await?;
    let Source::Imap { host, .. } = src else { unreachable!() };
    for f in list {
        if super::cancelled() {
            break;
        }
        if f.path.iter().any(|p| t.skip_folder(p)) || t.skip_folder(&f.path.join("/")) {
            continue;
        }
        let Some(dest) = map_folder(&f.path, f.special) else { continue };
        tick.step(format!("mail: {}", f.path.join("/")));
        if let Err(e) = copy_folder(&mut s, host, m, &f, &dest, t, tick).await {
            tick.error(&format!("folder {}", f.path.join("/")), &e);
            // The connection may be unusable after an error: start a fresh one.
            let _ = s.logout().await;
            s = connect(src, m).await?;
        }
    }
    let _ = s.logout().await;
    Ok(())
}

async fn copy_folder(s: &mut Session, host: &str, m: &MailboxMap, f: &Folder, dest: &str, t: &Target, tick: &Tick) -> Result<()> {
    let mb = s.examine(&f.raw).await?;
    if mb.exists == 0 {
        return Ok(());
    }
    let validity = mb.uid_validity.unwrap_or(0);
    let set = match t.since() {
        Some(since) => {
            let d = chrono::DateTime::from_timestamp(since, 0).unwrap_or_default().format("%d-%b-%Y").to_string();
            let mut v: Vec<u32> = s.uid_search(format!("SINCE {d}")).await?.into_iter().collect();
            v.sort_unstable();
            if v.is_empty() {
                return Ok(());
            }
            v.iter().map(|u| u.to_string()).collect::<Vec<_>>().join(",")
        }
        None => "1:*".to_string(),
    };
    // Metadata for everything first, then the bodies of what's new, in batches.
    let metas: Vec<(u32, Vec<String>, i64, u32)> = {
        let stream = s.uid_fetch(&set, "(UID FLAGS INTERNALDATE RFC822.SIZE)").await?;
        stream
            .filter_map(|r| async move { r.ok() })
            .filter_map(|f| async move { Some((f.uid?, flags_of(&f), f.internal_date().map(|d| d.timestamp()).unwrap_or_else(|| chrono::Utc::now().timestamp()), f.size.unwrap_or(0))) })
            .collect()
            .await
    };
    let key = |uid: u32| format!("imap:{host}:{}:{}:{validity}:{uid}", m.source.to_ascii_lowercase(), f.raw);
    let mut todo = Vec::new();
    for (uid, flags, date, size) in metas {
        if flags.iter().any(|x| x == "\\Deleted") {
            continue;
        }
        if t.seen(&key(uid)).await? {
            tick.skipped();
        } else {
            todo.push((uid, flags, date, size));
        }
    }
    // Batches of up to 50 messages or ~20 MB.
    let mut i = 0;
    while i < todo.len() {
        if super::cancelled() {
            break;
        }
        let mut j = i;
        let mut bytes = 0u64;
        while j < todo.len() && j - i < 50 && (bytes < 20_000_000 || j == i) {
            bytes += todo[j].3 as u64;
            j += 1;
        }
        let batch = &todo[i..j];
        let uids = batch.iter().map(|b| b.0.to_string()).collect::<Vec<_>>().join(",");
        let bodies: Vec<(u32, Vec<u8>)> = {
            let stream = s.uid_fetch(&uids, "(UID BODY.PEEK[])").await?;
            stream.filter_map(|r| async move { r.ok() }).filter_map(|f| async move { Some((f.uid?, f.body()?.to_vec())) }).collect().await
        };
        for (uid, flags, date, _) in batch {
            let Some((_, raw)) = bodies.iter().find(|(u, _)| u == uid) else {
                tick.error("message", &anyhow!("UID {uid} in {} couldn't be read", f.path.join("/")));
                continue;
            };
            let n = raw.len();
            t.add_message(&key(*uid), dest, raw.clone(), *date, flags.clone()).await?;
            tick.message(n);
        }
        i = j;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn mutf7() {
        assert_eq!(super::decode_mutf7("Entw&APw-rfe"), "Entwürfe");
        assert_eq!(super::decode_mutf7("&ZeVnLIqe-"), "日本語");
        assert_eq!(super::decode_mutf7("Tom &- Jerry"), "Tom & Jerry");
        assert_eq!(super::decode_mutf7("plain"), "plain");
        for x in ["Entwürfe", "日本語", "Tom & Jerry", "Ünïcödé/ünd", "😀 emoji"] {
            assert_eq!(super::decode_mutf7(&super::encode_mutf7(x)), x);
        }
        assert_eq!(super::encode_mutf7("Entwürfe"), "Entw&APw-rfe");
    }
}
