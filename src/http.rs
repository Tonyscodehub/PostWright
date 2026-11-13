//! HTTPS front end: CalDAV, the JSON settings API, the settings web page and
//! Thunderbird-style autoconfig (which Mailwright can use for email-only sign-in).

use crate::auth;
use crate::caldav;
use crate::identity;
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
    if p == "/login" {
        return page(LOGIN_HTML);
    }
    if p == "/login.js" {
        return builder(StatusCode::OK)
            .header("Content-Type", "application/javascript; charset=utf-8")
            .body(Full::new(Bytes::from_static(LOGIN_JS.as_bytes())))
            .unwrap();
    }
    if p == "/api/v1/login" && r.method == "POST" {
        return login(&srv, peer, &r).await;
    }
    if p == "/api/v1/logout" && r.method == "POST" {
        if let Some(t) = session_token(&r) {
            let _ = srv.store.call(move |c| identity::end_session(c, &t)).await;
        }
        return builder(StatusCode::OK)
            .header("Set-Cookie", "pw_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0")
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from_static(b"{\"ok\":true}")))
            .unwrap();
    }

    // Calendars (CalDAV) use HTTP Basic: account password, or an app password once
    // two-factor authentication is on. Mailwright may also use its device token.
    let is_dav = p == "/" && r.method != "GET" || p.starts_with("/dav");
    if is_dav {
        let user = match session_user(&srv, &r, &["device"]).await {
            Some(u) => Some(u),
            None => basic_user(&srv, peer, &r).await,
        };
        return match user {
            Some(u) => caldav::handle(srv, u, r).await,
            None if srv.guard.is_blocked(peer.ip()) => text(StatusCode::TOO_MANY_REQUESTS, "Too many failed logins, try later"),
            None => unauthorised(),
        };
    }

    // Everything else uses a sign-in session: a cookie for the web pages, or a bearer
    // token for the desktop app and Mailwright.
    let user = session_user(&srv, &r, &["web", "app", "device"]).await;
    let is_page = r.method == "GET" && (p == "/" || p == "/settings" || p == "/admin" || p == "/admin/");
    let Some(user) = user else {
        if is_page {
            let next = if p == "/" { String::new() } else { format!("?next={}", enc_path(&p)) };
            return builder(StatusCode::SEE_OTHER).header("Location", format!("/login{next}")).body(Full::default()).unwrap();
        }
        return json_err(StatusCode::UNAUTHORIZED, "sign in required");
    };
    if p == "/" || p == "/settings" {
        return page(SETTINGS_HTML);
    }
    if p == "/admin" || p == "/admin/" {
        if !user.is_admin || !crate::admin::in_networks(peer.ip(), &srv.cfg.security.admin_networks) {
            return text(StatusCode::FORBIDDEN, "Administration is not available for this account or from this network.");
        }
        return page(ADMIN_HTML);
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
    text(StatusCode::NOT_FOUND, "Not found")
}

fn page(html: &'static str) -> Resp {
    builder(StatusCode::OK)
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
        .header("X-Frame-Options", "DENY")
        .header("Referrer-Policy", "no-referrer")
        .body(Full::new(Bytes::from_static(html.as_bytes())))
        .unwrap()
}

/// Session token from the Authorization: Bearer header or the pw_session cookie.
pub fn session_token(r: &Req) -> Option<String> {
    if let Some(h) = r.header("authorization") {
        if let Some(t) = h.strip_prefix("Bearer ").or_else(|| h.strip_prefix("bearer ")) {
            return Some(t.trim().to_string());
        }
    }
    let cookies = r.header("cookie")?;
    cookies.split(';').find_map(|c| c.trim().strip_prefix("pw_session=").map(|v| v.to_string())).filter(|v| !v.is_empty())
}

async fn session_user(srv: &Shared, r: &Req, kinds: &'static [&'static str]) -> Option<User> {
    let t = session_token(r)?;
    srv.store.call(move |c| identity::session_user(c, &t, kinds)).await.ok().flatten()
}

#[derive(Deserialize)]
struct LoginReq {
    email: String,
    password: String,
    #[serde(default)]
    code: Option<String>,
    /// "web" (default, sets a cookie), "app" (admin desktop app) or "device" (mail app).
    #[serde(default)]
    kind: Option<String>,
    /// Shown on the user's "signed-in apps" list, e.g. "Mailwright on LEGION".
    #[serde(default)]
    name: Option<String>,
}

async fn login(srv: &Shared, peer: SocketAddr, r: &Req) -> Resp {
    let ip = peer.ip();
    if srv.guard.is_blocked(ip) {
        return json_err(StatusCode::TOO_MANY_REQUESTS, "Too many failed sign-ins. Try again later.");
    }
    let Ok(req) = serde_json::from_slice::<LoginReq>(&r.body) else { return json_err(StatusCode::BAD_REQUEST, "invalid request") };
    let kind = match req.kind.as_deref().unwrap_or("web") {
        k @ ("web" | "app" | "device") => k,
        _ => return json_err(StatusCode::BAD_REQUEST, "unknown kind"),
    };
    let res = match auth::web_login(&srv.store, &req.email, &req.password, req.code.as_deref()).await {
        Ok(x) => x,
        Err(e) => {
            tracing::error!("login error: {e:#}");
            return json_err(StatusCode::INTERNAL_SERVER_ERROR, "sign-in failed");
        }
    };
    let user = match res {
        auth::WebLogin::Ok(u) => u,
        auth::WebLogin::NeedCode => {
            return json(StatusCode::UNAUTHORIZED, &serde_json::json!({ "mfa_required": true, "error": "Enter the code from your authenticator app." }));
        }
        auth::WebLogin::Fail => {
            srv.guard.record_failure(ip);
            tracing::warn!("sign-in failed for {} from {ip}", req.email);
            tokio::time::sleep(Duration::from_secs(1)).await;
            let msg = if req.code.as_deref().map(|c| !c.trim().is_empty()).unwrap_or(false) {
                "That code isn't right, or it has already been used."
            } else {
                "Wrong email address or password."
            };
            return json(StatusCode::UNAUTHORIZED, &serde_json::json!({ "error": msg }));
        }
    };
    srv.guard.record_success(ip);
    let (uid, name) = (user.id, req.name.clone());
    let kind_s = kind.to_string();
    let token = match srv.store.call(move |c| identity::create_session(c, uid, &kind_s, name.as_deref())).await {
        Ok(t) => t,
        Err(_) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, "sign-in failed"),
    };
    tracing::info!("{} signed in ({kind}) from {ip}", user.email);
    let body = serde_json::json!({ "email": user.email, "is_admin": user.is_admin, "token": if kind == "web" { None } else { Some(&token) } });
    let mut b = builder(StatusCode::OK).header("Content-Type", "application/json").header("Cache-Control", "no-store");
    if kind == "web" {
        b = b.header("Set-Cookie", format!("pw_session={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=604800"));
    }
    b.body(Full::new(Bytes::from(serde_json::to_vec(&body).unwrap_or_default()))).unwrap()
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

/// Basic auth over TLS, for calendar apps. Successful logins are cached for a few minutes
/// keyed by a hash of the credentials, because calendar apps make many requests and Argon2
/// is deliberately slow.
async fn basic_user(srv: &Shared, peer: SocketAddr, r: &Req) -> Option<User> {
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
            if auth::verify_password(&srv.store, &user.email, &p.current).await?.is_none() {
                return Ok(json_err(StatusCode::FORBIDDEN, "current password is wrong"));
            }
            if p.new.chars().count() < 10 {
                anyhow::bail!("new password must be at least 10 characters");
            }
            let hash = auth::hash_password(&p.new)?;
            let email = user.email.clone();
            let keep = session_token(r);
            srv.store
                .call(move |c| {
                    store::set_password(c, &email, &hash)?;
                    // Sign out everywhere else.
                    let h = keep.as_deref().map(identity::sha256_hex).unwrap_or_default();
                    c.execute("DELETE FROM sessions WHERE user_id = ?1 AND token_hash != ?2", rusqlite::params![uid, h])?;
                    Ok(())
                })
                .await?;
            forget_cached_logins(uid);
            Ok(json(StatusCode::OK, &serde_json::json!({ "ok": true })))
        }
        // ---------------------------------------------------- two-factor authentication
        ("GET", ["mfa"]) => {
            let st = srv.store.call(move |c| identity::status(c, uid)).await?;
            Ok(json(StatusCode::OK, &st))
        }
        ("POST", ["mfa", "setup"]) => {
            let issuer = srv.cfg.hostname.clone();
            let u = user.clone();
            let e = srv.store.call(move |c| identity::begin_enrolment(c, &u, &issuer)).await?;
            Ok(json(StatusCode::OK, &e))
        }
        ("POST", ["mfa", "confirm"]) => {
            #[derive(Deserialize)]
            struct C {
                code: String,
            }
            let b: C = serde_json::from_slice(&r.body)?;
            let keep = session_token(r);
            let codes = srv
                .store
                .call(move |c| {
                    let codes = identity::confirm_enrolment(c, uid, &b.code)?;
                    // Other browsers signed in with just a password are signed out.
                    let h = keep.as_deref().map(identity::sha256_hex).unwrap_or_default();
                    c.execute("DELETE FROM sessions WHERE user_id = ?1 AND token_hash != ?2", rusqlite::params![uid, h])?;
                    Ok(codes)
                })
                .await?;
            forget_cached_logins(uid);
            tracing::info!("{} turned on two-factor authentication", user.email);
            Ok(json(StatusCode::OK, &serde_json::json!({ "recovery_codes": codes })))
        }
        ("POST", ["mfa", "recovery-codes"]) => {
            // New recovery codes (old ones stop working). Needs a current code.
            #[derive(Deserialize)]
            struct C {
                code: String,
            }
            let b: C = serde_json::from_slice(&r.body)?;
            let codes = srv
                .store
                .call(move |c| {
                    if !identity::verify_code(c, uid, &b.code)? {
                        anyhow::bail!("that code isn't right");
                    }
                    identity::new_recovery_codes(c, uid)
                })
                .await?;
            Ok(json(StatusCode::OK, &serde_json::json!({ "recovery_codes": codes })))
        }
        ("POST", ["mfa", "disable"]) => {
            #[derive(Deserialize)]
            struct D {
                password: String,
                code: String,
            }
            let b: D = serde_json::from_slice(&r.body)?;
            if auth::verify_password(&srv.store, &user.email, &b.password).await?.is_none() {
                return Ok(json_err(StatusCode::FORBIDDEN, "password is wrong"));
            }
            let ok = srv
                .store
                .call(move |c| {
                    if !identity::verify_code(c, uid, &b.code)? {
                        return Ok(false);
                    }
                    identity::disable(c, uid)?;
                    Ok(true)
                })
                .await?;
            if !ok {
                return Ok(json_err(StatusCode::FORBIDDEN, "that code isn't right"));
            }
            forget_cached_logins(uid);
            tracing::warn!("{} turned off two-factor authentication", user.email);
            Ok(json(StatusCode::OK, &serde_json::json!({ "ok": true })))
        }
        // ---------------------------------------------------------------- app passwords
        ("GET", ["app-passwords"]) => {
            let v = srv.store.call(move |c| identity::list_app_passwords(c, uid)).await?;
            Ok(json(StatusCode::OK, &v))
        }
        ("POST", ["app-passwords"]) => {
            #[derive(Deserialize)]
            struct N {
                name: String,
            }
            let b: N = serde_json::from_slice(&r.body)?;
            let name = b.name.trim().to_string();
            if name.is_empty() || name.chars().count() > 60 {
                anyhow::bail!("give the app password a name of up to 60 characters");
            }
            let n2 = name.clone();
            let pw = srv.store.call(move |c| identity::create_app_password(c, uid, &n2)).await?;
            tracing::info!("{} created app password {name:?}", user.email);
            Ok(json(StatusCode::OK, &serde_json::json!({ "name": name, "password": pw })))
        }
        ("DELETE", ["app-passwords", id]) => {
            let id: i64 = id.parse()?;
            let ok = srv.store.call(move |c| identity::delete_app_password(c, uid, id)).await?;
            forget_cached_logins(uid);
            if !ok {
                return Ok(json_err(StatusCode::NOT_FOUND, "no such app password"));
            }
            Ok(json(StatusCode::OK, &serde_json::json!({ "ok": true })))
        }
        // ------------------------------------------------------------ signed-in devices
        ("GET", ["devices"]) => {
            let cur = session_token(r);
            let v = srv.store.call(move |c| identity::list_sessions(c, uid, cur.as_deref())).await?;
            Ok(json(StatusCode::OK, &v))
        }
        ("DELETE", ["devices", id]) => {
            let id = id.to_string();
            let ok = srv.store.call(move |c| identity::end_session_by_id(c, uid, &id)).await?;
            if !ok {
                return Ok(json_err(StatusCode::NOT_FOUND, "no such sign-in"));
            }
            Ok(json(StatusCode::OK, &serde_json::json!({ "ok": true })))
        }
        // ---------------------------------------------------------- delegated mailboxes
        ("GET", ["shared"]) => {
            let v = srv.store.call(move |c| identity::granted_to(c, uid)).await?;
            Ok(json(StatusCode::OK, &v))
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
const LOGIN_HTML: &str = include_str!("web/login.html");
const LOGIN_JS: &str = include_str!("web/login.js");
const SETTINGS_JS: &str = include_str!("web/settings.js");
const ADMIN_HTML: &str = include_str!("web/admin.html");
const ADMIN_JS: &str = include_str!("web/admin.js");
