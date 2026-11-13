//! HTTPS front end: CalDAV, the JSON settings API, the settings web page and
//! Thunderbird-style autoconfig (which Mailwright can use for email-only sign-in).

use crate::auth;
use crate::caldav;
use crate::net::Stream;
use crate::prefs;
use crate::server::Shared;
use crate::store::{self, User};
use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::HeaderMap;
use hyper::{Request, Response, StatusCode};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

pub type Resp = Response<Full<Bytes>>;

pub struct Req {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl Req {
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers.get(name).and_then(|v| v.to_str().ok()).map(|s| s.trim().to_string())
    }
}

pub fn builder(code: StatusCode) -> hyper::http::response::Builder {
    Response::builder()
        .status(code)
        .header("Strict-Transport-Security", "max-age=31536000")
        .header("X-Content-Type-Options", "nosniff")
        .header("Server", "Postwright")
}

pub fn text(code: StatusCode, s: &str) -> Resp {
    builder(code).header("Content-Type", "text/plain; charset=utf-8").body(Full::new(Bytes::from(s.to_string()))).unwrap()
}

pub fn xml_resp(code: StatusCode, s: String) -> Resp {
    builder(code).header("Content-Type", "application/xml; charset=utf-8").body(Full::new(Bytes::from(s))).unwrap()
}

pub(crate) fn json<T: serde::Serialize>(code: StatusCode, v: &T) -> Resp {
    builder(code)
        .header("Content-Type", "application/json")
        .header("Cache-Control", "no-store")
        .body(Full::new(Bytes::from(serde_json::to_vec(v).unwrap_or_default())))
        .unwrap()
}

pub(crate) fn json_err(code: StatusCode, msg: &str) -> Resp {
    json(code, &serde_json::json!({ "error": msg }))
}

fn unauthorised() -> Resp {
    builder(StatusCode::UNAUTHORIZED)
        .header("WWW-Authenticate", "Basic realm=\"Postwright\", charset=\"UTF-8\"")
        .body(Full::new(Bytes::from_static(b"Authentication required")))
        .unwrap()
}

pub fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Some(v) = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn enc_path(s: &str) -> String {
    let mut out = String::new();
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~@+:".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

// ------------------------------------------------------------------ server

pub async fn handle(srv: Shared, stream: Stream, peer: SocketAddr) -> Result<()> {
    let io = hyper_util::rt::TokioIo::new(stream);
    let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
        let srv = srv.clone();
        async move { Ok::<_, Infallible>(route(srv, peer, req).await) }
    });
    hyper::server::conn::http1::Builder::new()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(Duration::from_secs(30))
        .keep_alive(true)
        .serve_connection(io, svc)
        .await?;
    Ok(())
}

const MAX_BODY: usize = 10 * 1024 * 1024;

async fn route(srv: Shared, peer: SocketAddr, req: Request<Incoming>) -> Resp {
    let (parts, body) = req.into_parts();
    let body = match Limited::new(body, MAX_BODY).collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => return text(StatusCode::PAYLOAD_TOO_LARGE, "Request too large"),
    };
    let r = Req {
        method: parts.method.as_str().to_ascii_uppercase(),
        path: pct_decode(parts.uri.path()),
        query: parts.uri.query().unwrap_or("").to_string(),
        headers: parts.headers,
        body,
    };
    let p = r.path.clone();
    // Unauthenticated routes.
    if p.eq_ignore_ascii_case("/.well-known/caldav") {
        return builder(StatusCode::MOVED_PERMANENTLY).header("Location", "/dav/").body(Full::default()).unwrap();
    }
    if p.ends_with("/mail/config-v1.1.xml") {
        return autoconfig(&srv, &r);
    }
    if p == "/admin.js" {
        return builder(StatusCode::OK)
            .header("Content-Type", "application/javascript; charset=utf-8")
            .body(Full::new(Bytes::from_static(ADMIN_JS.as_bytes())))
            .unwrap();
    }
    if p == "/settings.js" {
        return builder(StatusCode::OK)
            .header("Content-Type", "application/javascript; charset=utf-8")
            .body(Full::new(Bytes::from_static(SETTINGS_JS.as_bytes())))
            .unwrap();
    }
    if p == "/favicon.ico" {
        return builder(StatusCode::NO_CONTENT).body(Full::default()).unwrap();
    }
    if r.method == "OPTIONS" && (p == "/" || p.starts_with("/dav")) {
        // Some clients probe OPTIONS before authenticating.
        if let Some(u) = authenticate(&srv, peer, &r).await {
            return caldav::handle(srv, u, r).await;
        }
    }
    let Some(user) = authenticate(&srv, peer, &r).await else {
        if srv.guard.is_blocked(peer.ip()) {
            return text(StatusCode::TOO_MANY_REQUESTS, "Too many failed logins, try later");
        }
        return unauthorised();
    };
    if p == "/" && r.method == "GET" || p == "/settings" {
        return builder(StatusCode::OK)
            .header("Content-Type", "text/html; charset=utf-8")
            .header("Cache-Control", "no-store")
            .header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
            .header("X-Frame-Options", "DENY")
            .header("Referrer-Policy", "no-referrer")
            .body(Full::new(Bytes::from_static(SETTINGS_HTML.as_bytes())))
            .unwrap();
    }
    if p == "/admin" || p == "/admin/" {
        if !user.is_admin || !crate::admin::in_networks(peer.ip(), &srv.cfg.security.admin_networks) {
            return text(StatusCode::FORBIDDEN, "Administration is not available for this account or from this network.");
        }
        return builder(StatusCode::OK)
            .header("Content-Type", "text/html; charset=utf-8")
            .header("Cache-Control", "no-store")
            .header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
            .header("X-Frame-Options", "DENY")
            .header("Referrer-Policy", "no-referrer")
            .body(Full::new(Bytes::from_static(ADMIN_HTML.as_bytes())))
            .unwrap();
    }
    if let Some(rest) = p.strip_prefix("/api/v1/admin/") {
        if r.method != "GET" && r.method != "DELETE" && !r.header("content-type").unwrap_or_default().starts_with("application/json") {
            return json_err(StatusCode::UNSUPPORTED_MEDIA_TYPE, "Content-Type must be application/json");
        }
        return crate::admin::handle(&srv, peer.ip(), user, &r, rest).await;
    }
    if let Some(rest) = p.strip_prefix("/api/v1/") {
        return api(&srv, user, &r, rest).await;
    }
    if p == "/" || p.starts_with("/dav") {
        return caldav::handle(srv, user, r).await;
    }
    text(StatusCode::NOT_FOUND, "Not found")
}

// ------------------------------------------------------------ authentication

struct CacheEntry {
    user_id: i64,
    at: Instant,
}

fn auth_cache() -> &'static Mutex<HashMap<String, CacheEntry>> {
    static C: OnceLock<Mutex<HashMap<String, CacheEntry>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Basic auth over TLS. Successful logins are cached for a few minutes keyed by a hash of
/// the credentials, because calendar clients make many requests and Argon2 is deliberately slow.
async fn authenticate(srv: &Shared, peer: SocketAddr, r: &Req) -> Option<User> {
    let h = r.header("authorization")?;
    let b64 = h.strip_prefix("Basic ").or_else(|| h.strip_prefix("basic "))?;
    let decoded = auth::b64d(b64)?;
    let (user, pass) = decoded.split_once(':')?;
    let key = hex::encode(Sha256::digest(format!("{}\0{pass}", user.to_ascii_lowercase()).as_bytes()));
    let cached = {
        let mut c = auth_cache().lock().unwrap();
        c.retain(|_, e| e.at.elapsed() < Duration::from_secs(300));
        c.get(&key).map(|e| e.user_id)
    };
    if let Some(id) = cached {
        let u = srv.store.call(move |c| store::user_by_id(c, id)).await.ok().flatten();
        if let Some(u) = u.filter(|u| u.enabled) {
            return Some(u);
        }
    }
    if srv.guard.is_blocked(peer.ip()) {
        return None;
    }
    match auth::authenticate(&srv.store, user, pass).await {
        Ok(Some(u)) => {
            srv.guard.record_success(peer.ip());
            auth_cache().lock().unwrap().insert(key, CacheEntry { user_id: u.id, at: Instant::now() });
            Some(u)
        }
        _ => {
            srv.guard.record_failure(peer.ip());
            tracing::warn!("HTTP login failed for {user} from {}", peer.ip());
            tokio::time::sleep(Duration::from_secs(1)).await;
            None
        }
    }
}

fn forget_cached_logins(user_id: i64) {
    auth_cache().lock().unwrap().retain(|_, e| e.user_id != user_id);
}

/// Drop cached logins for an account (after an admin changes or removes it). Cached
/// entries are keyed by credential hash, so clear any for this address's user id.
pub fn forget_cached_logins_for(_email: &str) {
    // Entries expire within five minutes anyway; clearing all is cheap and simplest.
    auth_cache().lock().unwrap().clear();
}

// --------------------------------------------------------------------- API

#[derive(Deserialize)]
struct NewCalendar {
    name: String,
    color: Option<String>,
}

#[derive(Deserialize)]
struct ShareReq {
    user: String,
    #[serde(default)]
    write: bool,
}

#[derive(Deserialize)]
struct PasswordReq {
    current: String,
    new: String,
}

async fn api(srv: &Shared, user: User, r: &Req, rest: &str) -> Resp {
    // CSRF defence: state-changing calls must be JSON, which a cross-site form can't send.
    if r.method != "GET" && r.method != "DELETE" {
        let ct = r.header("content-type").unwrap_or_default();
        if !ct.starts_with("application/json") {
            return json_err(StatusCode::UNSUPPORTED_MEDIA_TYPE, "Content-Type must be application/json");
        }
    }
    if r.method == "DELETE" && r.header("x-requested-with").is_none() && r.header("origin").is_some() {
        return json_err(StatusCode::FORBIDDEN, "cross-origin request refused");
    }
    match api_inner(srv, user, r, rest).await {
        Ok(resp) => resp,
        Err(e) => json_err(StatusCode::BAD_REQUEST, &format!("{e:#}")),
    }
}

async fn api_inner(srv: &Shared, user: User, r: &Req, rest: &str) -> Result<Resp> {
    let segs: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    let uid = user.id;
    match (r.method.as_str(), segs.as_slice()) {
        ("GET", ["me"]) => {
            let used = srv.store.call(move |c| store::user_usage(c, uid)).await?;
            let host = srv.cfg.hostname.clone();
            Ok(json(
                StatusCode::OK,
                &serde_json::json!({
                    "email": user.email, "quota_bytes": user.quota_bytes, "used_bytes": used, "is_admin": user.is_admin,
                    "imap": { "host": host, "port": first_port(&srv.cfg.listeners.imaps, 993), "security": "tls" },
                    "smtp": { "host": host, "port": first_port(&srv.cfg.listeners.submissions, 465), "security": "tls" },
                    "caldav": format!("https://{host}{}/dav/", https_port_suffix(srv)),
                }),
            ))
        }
        ("GET", ["settings"]) => {
            let s = srv.store.call(move |c| prefs::load(c, uid)).await?;
            Ok(json(StatusCode::OK, &s))
        }
        ("PUT", ["settings"]) => {
            let s: prefs::Settings = serde_json::from_slice(&r.body)?;
            if s.vacation.body.len() > 20_000 || s.signature.text.len() > 20_000 || s.signature.html.len() > 100_000 {
                anyhow::bail!("text too long");
            }
            let s2 = s.clone();
            srv.store.call(move |c| prefs::save(c, uid, &s2)).await?;
            Ok(json(StatusCode::OK, &s))
        }
        ("POST", ["password"]) => {
            let p: PasswordReq = serde_json::from_slice(&r.body)?;
            if auth::authenticate(&srv.store, &user.email, &p.current).await?.is_none() {
                return Ok(json_err(StatusCode::FORBIDDEN, "current password is wrong"));
            }
            if p.new.chars().count() < 10 {
                anyhow::bail!("new password must be at least 10 characters");
            }
            let hash = auth::hash_password(&p.new)?;
            let email = user.email.clone();
            srv.store.call(move |c| store::set_password(c, &email, &hash)).await?;
            forget_cached_logins(uid);
            Ok(json(StatusCode::OK, &serde_json::json!({ "ok": true })))
        }
        ("GET", ["calendars"]) => {
            let list = srv
                .store
                .call(move |c| {
                    let mut out = Vec::new();
                    for cal in caldav::list_calendars(c, uid)? {
                        let shares = if cal.is_owner { caldav::shares_of(c, cal.id)? } else { vec![] };
                        let mut v = serde_json::to_value(&cal)?;
                        v["shares"] = serde_json::json!(shares.iter().map(|(u, w)| serde_json::json!({"user": u, "write": w})).collect::<Vec<_>>());
                        out.push(v);
                    }
                    Ok(out)
                })
                .await?;
            Ok(json(StatusCode::OK, &list))
        }
        ("POST", ["calendars"]) => {
            let n: NewCalendar = serde_json::from_slice(&r.body)?;
            let slug = srv
                .store
                .call(move |c| {
                    let slug = caldav::slug_for(c, uid, &n.name)?;
                    caldav::create_calendar(c, uid, &slug, &n.name, n.color.as_deref())?;
                    Ok(slug)
                })
                .await?;
            Ok(json(StatusCode::CREATED, &serde_json::json!({ "slug": slug })))
        }
        ("DELETE", ["calendars", slug]) => {
            let slug = slug.to_string();
            let email = user.email.clone();
            srv.store
                .call(move |c| {
                    let cal = caldav::resolve(c, uid, &slug)?.ok_or_else(|| anyhow::anyhow!("no such calendar"))?;
                    if cal.is_owner {
                        c.execute("DELETE FROM calendars WHERE id = ?1", [cal.id])?;
                    } else {
                        caldav::unshare(c, cal.id, &email)?;
                    }
                    Ok(())
                })
                .await?;
            Ok(json(StatusCode::OK, &serde_json::json!({ "ok": true })))
        }
        ("POST", ["calendars", slug, "shares"]) => {
            let s: ShareReq = serde_json::from_slice(&r.body)?;
            let slug = slug.to_string();
            srv.store
                .call(move |c| {
                    let cal = caldav::resolve(c, uid, &slug)?.filter(|c| c.is_owner).ok_or_else(|| anyhow::anyhow!("you can only share calendars you own"))?;
                    caldav::share(c, cal.id, &s.user, s.write)
                })
                .await?;
            Ok(json(StatusCode::OK, &serde_json::json!({ "ok": true })))
        }
        ("DELETE", ["calendars", slug, "shares", who]) => {
            let (slug, who) = (slug.to_string(), who.to_string());
            srv.store
                .call(move |c| {
                    let cal = caldav::resolve(c, uid, &slug)?.filter(|c| c.is_owner).ok_or_else(|| anyhow::anyhow!("no such calendar"))?;
                    caldav::unshare(c, cal.id, &who)
                })
                .await?;
            Ok(json(StatusCode::OK, &serde_json::json!({ "ok": true })))
        }
        _ => Ok(json_err(StatusCode::NOT_FOUND, "unknown endpoint")),
    }
}

fn first_port(addrs: &[String], default: u16) -> u16 {
    addrs.first().and_then(|a| a.rsplit(':').next()).and_then(|p| p.parse().ok()).unwrap_or(default)
}

fn https_port_suffix(srv: &Shared) -> String {
    match first_port(&srv.cfg.listeners.https, 443) {
        443 => String::new(),
        p => format!(":{p}"),
    }
}

// --------------------------------------------------------------- autoconfig

fn autoconfig(srv: &Shared, r: &Req) -> Resp {
    let email = r
        .query
        .split('&')
        .find_map(|kv| kv.strip_prefix("emailaddress="))
        .map(pct_decode)
        .unwrap_or_default();
    let domain = email.rsplit_once('@').map(|x| x.1.to_string()).unwrap_or_else(|| srv.cfg.hostname.clone());
    let host = crate::xml::esc(&srv.cfg.hostname);
    let d = crate::xml::esc(&domain);
    let imap = first_port(&srv.cfg.listeners.imaps, 993);
    let smtp = first_port(&srv.cfg.listeners.submissions, 465);
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
  <emailProvider id="{d}">
    <domain>{d}</domain>
    <displayName>{d} (Postwright)</displayName>
    <incomingServer type="imap">
      <hostname>{host}</hostname><port>{imap}</port><socketType>SSL</socketType>
      <authentication>password-cleartext</authentication><username>%EMAILADDRESS%</username>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>{host}</hostname><port>{smtp}</port><socketType>SSL</socketType>
      <authentication>password-cleartext</authentication><username>%EMAILADDRESS%</username>
    </outgoingServer>
  </emailProvider>
  <calendar type="caldav"><username>%EMAILADDRESS%</username><authentication>http-basic</authentication><serverURL>https://{host}{}/dav/</serverURL></calendar>
</clientConfig>
"#,
        https_port_suffix(srv)
    );
    builder(StatusCode::OK).header("Content-Type", "application/xml; charset=utf-8").body(Full::new(Bytes::from(body))).unwrap()
}

// --------------------------------------------------------------- web page

const SETTINGS_HTML: &str = include_str!("web/settings.html");
const SETTINGS_JS: &str = include_str!("web/settings.js");
const ADMIN_HTML: &str = include_str!("web/admin.html");
const ADMIN_JS: &str = include_str!("web/admin.js");
