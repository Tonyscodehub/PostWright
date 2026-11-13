//! Shared server state and listener supervision.

use crate::auth::Guard;
use crate::config::Config;
use crate::net::{self, Stream};
use crate::store::Store;
use anyhow::{Context, Result};
use mail_auth::MessageAuthenticator;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, Notify, Semaphore};
use tokio_rustls::TlsAcceptor;

pub struct Server {
    pub cfg: Config,
    pub store: Store,
    tls: RwLock<TlsAcceptor>,
    pub guard: Guard,
    pub dns: MessageAuthenticator,
    /// Broadcast of user ids whose mailboxes changed (drives IMAP IDLE).
    pub changes: broadcast::Sender<i64>,
    /// Wakes the outbound queue when new mail is queued.
    pub queue_wake: Notify,
}

pub type Shared = Arc<Server>;

impl Server {
    pub fn new(cfg: Config) -> Result<Shared> {
        let store = Store::open(&cfg.db_path(), &cfg.blob_dir(), 16)?;
        let tls = net::load_tls(&cfg.tls.cert, &cfg.tls.key).context("loading TLS certificate")?;
        let guard = Guard::new(cfg.security.max_auth_failures, cfg.security.auth_block_secs, cfg.limits.max_connections_per_ip);
        let dns = MessageAuthenticator::new_system_conf()
            .or_else(|_| MessageAuthenticator::new_cloudflare())
            .map_err(|e| anyhow::anyhow!("DNS resolver: {e}"))?;
        let (changes, _) = broadcast::channel(1024);
        Ok(Arc::new(Self { cfg, store, tls: RwLock::new(tls), guard, dns, changes, queue_wake: Notify::new() }))
    }

    pub fn tls(&self) -> TlsAcceptor {
        self.tls.read().unwrap().clone()
    }

    /// Re-read the certificate from disk (e.g. after a Let's Encrypt renewal).
    pub fn reload_tls(&self) -> Result<()> {
        let t = net::load_tls(&self.cfg.tls.cert, &self.cfg.tls.key)?;
        *self.tls.write().unwrap() = t;
        tracing::info!("TLS certificate reloaded");
        Ok(())
    }

    pub fn notify_user(&self, user_id: i64) {
        let _ = self.changes.send(user_id);
    }
}

/// Bind every address in `addrs` and spawn `handler` for each accepted connection,
/// enforcing the global and per-IP connection limits. When `implicit_tls` is set the
/// TLS handshake happens before the handler sees the stream.
pub async fn listen<F, Fut>(srv: Shared, name: &'static str, addrs: &[String], implicit_tls: bool, handler: F) -> Result<()>
where
    F: Fn(Shared, Stream, SocketAddr) -> Fut + Send + Sync + Clone + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    let sem = Arc::new(Semaphore::new(srv.cfg.limits.max_connections));
    for addr in addrs {
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                // "[::]" may fail on hosts without IPv6, and dual-stack hosts may already
                // have the port via 0.0.0.0; don't treat that as fatal.
                tracing::warn!("{name}: cannot bind {addr}: {e}");
                continue;
            }
        };
        tracing::info!("{name} listening on {addr}");
        let srv = srv.clone();
        let sem = sem.clone();
        let handler = handler.clone();
        tokio::spawn(async move {
            loop {
                let (tcp, peer) = match listener.accept().await {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::warn!("{name}: accept error: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let Ok(permit) = sem.clone().try_acquire_owned() else {
                    tracing::warn!("{name}: connection limit reached, dropping {peer}");
                    continue;
                };
                let Some(slot) = srv.guard.connect(peer.ip()) else {
                    tracing::warn!("{name}: per-IP limit reached for {}", peer.ip());
                    continue;
                };
                let _ = tcp.set_nodelay(true);
                let srv = srv.clone();
                let handler = handler.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let _slot = slot;
                    let res = async {
                        let stream = if implicit_tls { net::accept_tls(&srv.tls(), tcp).await? } else { Stream::Plain(tcp) };
                        handler(srv, stream, peer).await
                    }
                    .await;
                    if let Err(e) = res {
                        tracing::debug!("{name} {peer}: {e:#}");
                    }
                });
            }
        });
    }
    Ok(())
}
