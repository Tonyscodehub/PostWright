//! Connection plumbing shared by SMTP and IMAP: plain/TLS streams, STARTTLS upgrade,
//! bounded line reading and listener management.

use anyhow::{anyhow, bail, Result};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

pub fn load_tls(cert: &Path, key: &Path) -> Result<TlsAcceptor> {
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(cert).map_err(|e| anyhow!("{}: {e}", cert.display()))?.collect::<Result<_, _>>()?;
    if certs.is_empty() {
        bail!("no certificates found in {}", cert.display());
    }
    let key: PrivateKeyDer<'static> =
        PrivateKeyDer::from_pem_file(key).map_err(|e| anyhow!("no usable private key in {}: {e}", key.display()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

pub enum Stream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
    Upgrading,
}

impl Stream {
    pub fn is_tls(&self) -> bool {
        matches!(self, Stream::Tls(_))
    }

    pub fn tls_info(&self) -> Option<String> {
        match self {
            Stream::Tls(s) => {
                let (_, c) = s.get_ref();
                Some(format!(
                    "{} {}",
                    c.protocol_version().map(|v| format!("{v:?}")).unwrap_or_default(),
                    c.negotiated_cipher_suite().map(|s| format!("{:?}", s.suite())).unwrap_or_default()
                ))
            }
            _ => None,
        }
    }
}

macro_rules! dispatch {
    ($self:ident, $s:ident => $e:expr) => {
        match $self.get_mut() {
            Stream::Plain($s) => { let $s = Pin::new($s); $e }
            Stream::Tls($s) => { let $s = Pin::new($s.as_mut()); $e }
            Stream::Upgrading => Poll::Ready(Err(io::Error::other("stream upgrading"))),
        }
    };
}

impl AsyncRead for Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        dispatch!(self, s => s.poll_read(cx, buf))
    }
}

impl AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        dispatch!(self, s => s.poll_write(cx, buf))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        dispatch!(self, s => s.poll_flush(cx))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        dispatch!(self, s => s.poll_shutdown(cx))
    }
}

/// A buffered connection with a hard cap on line length (defends against memory
/// exhaustion) and an idle timeout on every read.
pub struct Conn {
    pub stream: Stream,
    buf: Vec<u8>,
    pub timeout: Duration,
}

pub const MAX_LINE: usize = 64 * 1024;

impl Conn {
    pub fn new(stream: Stream, timeout: Duration) -> Self {
        Self { stream, buf: Vec::with_capacity(4096), timeout }
    }

    async fn fill(&mut self) -> Result<()> {
        let mut tmp = [0u8; 16384];
        let n = tokio::time::timeout(self.timeout, self.stream.read(&mut tmp))
            .await
            .map_err(|_| anyhow!("idle timeout"))??;
        if n == 0 {
            bail!("connection closed");
        }
        self.buf.extend_from_slice(&tmp[..n]);
        Ok(())
    }

    /// Read one CRLF (or bare LF) terminated line, without the terminator.
    pub async fn read_line(&mut self) -> Result<Vec<u8>> {
        Ok(self.read_line_ex().await?.0)
    }

    /// Like `read_line`, also reporting whether the line ended in a proper CRLF.
    pub async fn read_line_ex(&mut self) -> Result<(Vec<u8>, bool)> {
        let mut scanned = 0;
        loop {
            if let Some(pos) = self.buf[scanned..].iter().position(|&b| b == b'\n') {
                let end = scanned + pos;
                let mut line: Vec<u8> = self.buf.drain(..=end).collect();
                line.pop();
                let crlf = line.last() == Some(&b'\r');
                if crlf {
                    line.pop();
                }
                return Ok((line, crlf));
            }
            scanned = self.buf.len();
            if self.buf.len() > MAX_LINE {
                bail!("line too long");
            }
            self.fill().await?;
        }
    }

    pub async fn read_exact_bytes(&mut self, n: usize) -> Result<Vec<u8>> {
        while self.buf.len() < n {
            self.fill().await?;
        }
        Ok(self.buf.drain(..n).collect())
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        tokio::time::timeout(self.timeout, async {
            self.stream.write_all(data).await?;
            self.stream.flush().await
        })
        .await
        .map_err(|_| anyhow!("write timeout"))??;
        Ok(())
    }

    pub async fn send(&mut self, line: &str) -> Result<()> {
        let mut v = Vec::with_capacity(line.len() + 2);
        v.extend_from_slice(line.as_bytes());
        v.extend_from_slice(b"\r\n");
        self.write(&v).await
    }

    /// Wait up to `dur` before the banner; returns true if the client spoke first.
    pub async fn early_talk(&mut self, dur: Duration) -> bool {
        let mut tmp = [0u8; 1024];
        match tokio::time::timeout(dur, self.stream.read(&mut tmp)).await {
            Ok(Ok(n)) if n > 0 => {
                self.buf.extend_from_slice(&tmp[..n]);
                true
            }
            _ => false,
        }
    }

    pub fn has_buffered(&self) -> bool {
        !self.buf.is_empty()
    }

    /// Perform the server side of STARTTLS. Any plaintext pipelined after the command is
    /// discarded (CVE-2011-0411 style command injection defence).
    pub async fn upgrade(&mut self, acceptor: &TlsAcceptor) -> Result<()> {
        self.buf.clear();
        let Stream::Plain(tcp) = std::mem::replace(&mut self.stream, Stream::Upgrading) else {
            bail!("already TLS");
        };
        let tls = tokio::time::timeout(Duration::from_secs(30), acceptor.accept(tcp))
            .await
            .map_err(|_| anyhow!("TLS handshake timeout"))??;
        self.stream = Stream::Tls(Box::new(tls));
        Ok(())
    }
}

pub async fn accept_tls(acceptor: &TlsAcceptor, tcp: TcpStream) -> Result<Stream> {
    let tls = tokio::time::timeout(Duration::from_secs(30), acceptor.accept(tcp))
        .await
        .map_err(|_| anyhow!("TLS handshake timeout"))??;
    Ok(Stream::Tls(Box::new(tls)))
}

/// Read a PROXY protocol header (v1 text or v2 binary) from a connection that came
/// through a trusted reverse proxy. Returns the original client's address, or `None`
/// for the proxy's own connections (v1 `UNKNOWN`, v2 `LOCAL`, or a non-IP family).
pub async fn read_proxy_header(tcp: &mut TcpStream) -> Result<Option<std::net::SocketAddr>> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    const V2: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
    let mut head = [0u8; 12];
    tcp.read_exact(&mut head).await?;
    if head == V2 {
        let mut h = [0u8; 4];
        tcp.read_exact(&mut h).await?;
        if h[0] >> 4 != 2 {
            bail!("unsupported PROXY v2 version");
        }
        let len = u16::from_be_bytes([h[2], h[3]]) as usize;
        let mut body = vec![0u8; len];
        tcp.read_exact(&mut body).await?;
        if h[0] & 0x0f == 0 {
            return Ok(None); // LOCAL
        }
        if h[0] & 0x0f != 1 {
            bail!("unsupported PROXY v2 command");
        }
        return Ok(match h[1] >> 4 {
            1 if body.len() >= 12 => {
                let ip = Ipv4Addr::new(body[0], body[1], body[2], body[3]);
                Some(SocketAddr::new(IpAddr::V4(ip), u16::from_be_bytes([body[8], body[9]])))
            }
            2 if body.len() >= 36 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(&body[..16]);
                Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(a)), u16::from_be_bytes([body[32], body[33]])))
            }
            0 => None,
            _ => bail!("short or unsupported PROXY v2 address block"),
        });
    }
    if !head.starts_with(b"PROXY ") {
        bail!("connection didn't start with a PROXY header");
    }
    // v1: the whole line is at most 107 bytes, ending in CRLF.
    let mut line = head.to_vec();
    while !line.ends_with(b"\r\n") {
        if line.len() >= 107 {
            bail!("PROXY v1 header too long");
        }
        line.push(tcp.read_u8().await?);
    }
    let text = std::str::from_utf8(&line[..line.len() - 2]).map_err(|_| anyhow!("PROXY v1 header isn't text"))?;
    let parts: Vec<&str> = text.split(' ').collect();
    match parts.as_slice() {
        ["PROXY", "UNKNOWN", ..] => Ok(None),
        ["PROXY", fam @ ("TCP4" | "TCP6"), src, _dst, sport, _dport] => {
            let ip: IpAddr = src.parse().map_err(|_| anyhow!("bad source address in PROXY header"))?;
            if (*fam == "TCP4") != ip.is_ipv4() {
                bail!("PROXY header address doesn't match its family");
            }
            let port: u16 = sport.parse().map_err(|_| anyhow!("bad source port in PROXY header"))?;
            Ok(Some(SocketAddr::new(ip, port)))
        }
        _ => bail!("malformed PROXY v1 header"),
    }
}
