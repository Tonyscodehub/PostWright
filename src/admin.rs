//! Admin API (`/api/v1/admin/...`), used by the web console and the desktop app.
//!
//! Access requires an account with the admin flag (`postwright user admin <email>`) and a
//! connection from one of `security.admin_networks` (private ranges by default).

use crate::http::{json, json_err, Req, Resp};
use crate::server::Shared;
use crate::store::{self, User};
use crate::{auth, delivery, iredmail, logbuf};
use anyhow::{anyhow, bail, Result};
use hyper::StatusCode;
use mail_auth::common::cache::NoCache;
use serde::Deserialize;
use serde_json::{json as j, Value};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

static STARTED: OnceLock<Instant> = OnceLock::new();

pub fn mark_start() {
    STARTED.get_or_init(Instant::now);
}

// ------------------------------------------------------------ access control

fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let (ip, bits) = match s.split_once('/') {
        Some((a, b)) => (a.parse::<IpAddr>().ok()?, b.parse::<u8>().ok()?),
        None => {
            let ip: IpAddr = s.parse().ok()?;
            (ip, if ip.is_ipv4() { 32 } else { 128 })
        }
    };
    Some((ip, bits))
}

pub fn in_networks(ip: IpAddr, nets: &[String]) -> bool {
    // Treat IPv4-mapped IPv6 (::ffff:a.b.c.d) as IPv4.
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    };
    nets.iter().filter_map(|n| parse_cidr(n)).any(|(net, bits)| match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let bits = bits.min(32) as u32;
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let bits = bits.min(128) as u32;
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
    })
}

pub async fn handle(srv: &Shared, peer: IpAddr, user: User, r: &Req, rest: &str) -> Resp {
    if !in_networks(peer, &srv.cfg.security.admin_networks) {
        tracing::warn!("admin API refused for {} from {peer} (not in admin_networks)", user.email);
        return json_err(StatusCode::FORBIDDEN, "administration is not allowed from this network");
    }
    if !user.is_admin {
        return json_err(StatusCode::FORBIDDEN, "this account is not an administrator");
    }
    if r.method == "DELETE" && r.header("x-requested-with").is_none() {
        return json_err(StatusCode::FORBIDDEN, "missing X-Requested-With header");
    }
    match route(srv, &user, r, rest).await {
        Ok(v) => json(StatusCode::OK, &v),
        Err(e) => json_err(StatusCode::BAD_REQUEST, &format!("{e:#}")),
    }
}

fn query(r: &Req, key: &str) -> Option<String> {
    r.query.split('&').find_map(|kv| kv.strip_prefix(&format!("{key}="))).map(crate::http::pct_decode)
}

fn body<T: for<'de> Deserialize<'de>>(r: &Req) -> Result<T> {
    serde_json::from_slice(&r.body).map_err(|e| anyhow!("invalid request: {e}"))
}

#[derive(Deserialize)]
struct NewDomain {
    name: String,
    #[serde(default)]
    selector: Option<String>,
}

#[derive(Deserialize)]
struct NewAliasDomain {
    alias: String,
    target: String,
}

#[derive(Deserialize)]
struct DomainUpdate {
    catch_all: Option<String>,
}

#[derive(Deserialize)]
struct NewUser {
    email: String,
    password: String,
    #[serde(default)]
    quota_mb: i64,
    #[serde(default)]
    admin: bool,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct UserUpdate {
    password: Option<String>,
    quota_mb: Option<i64>,
    enabled: Option<bool>,
    admin: Option<bool>,
}

#[derive(Deserialize)]
struct NewAlias {
    source: String,
    target: String,
}

#[derive(Deserialize)]
struct NewKey {
    key: String,
}

#[derive(Deserialize)]
struct CertUpload {
    fullchain: String,
    key: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ImportReq {
    dry_run: bool,
    no_mail: bool,
    no_calendars: bool,
    user: Option<String>,
    backend: Option<String>,
}

async fn route(srv: &Shared, me: &User, r: &Req, rest: &str) -> Result<Value> {
    let segs: Vec<String> = rest.split('/').filter(|s| !s.is_empty()).map(String::from).collect();
    let segs: Vec<&str> = segs.iter().map(|s| s.as_str()).collect();
    match (r.method.as_str(), segs.as_slice()) {
        ("GET", ["overview"]) => overview(srv).await,

        // ------------------------------------------------------------ certificate
        ("GET", ["certs"]) => {
            let (cur, err) = match crate::certs::current(&srv.cfg) {
                Ok(i) => (Some(i), None),
                Err(e) => (None, Some(format!("{e:#}"))),
            };
            let keys = srv.store.call(|c| crate::certs::list_keys(c)).await?;
            let last = crate::certs::LAST_INSTALL.lock().unwrap().clone();
            Ok(j!({
                "current": cur, "error": err, "hostname": srv.cfg.hostname,
                "receiver": crate::certs::receiver_info(&srv.cfg)?,
                "keys": keys,
                "require_hostname_match": srv.cfg.certs.require_hostname_match,
                "last_install": last.map(|(t, s)| j!({"at": t, "source": s})),
            }))
        }
        ("POST", ["certs", "keys"]) => {
            let k: NewKey = body(r)?;
            let fp = srv.store.call(move |c| crate::certs::add_key(c, &k.key)).await?;
            tracing::info!("admin {} allowed key {fp} to push certificates", me.email);
            Ok(j!({ "fingerprint": fp }))
        }
        ("DELETE", ["certs", "keys"]) => {
            let fp = query(r, "fp").ok_or_else(|| anyhow!("missing fp"))?;
            let f2 = fp.clone();
            if !srv.store.call(move |c| crate::certs::remove_key(c, &f2)).await? {
                bail!("no such key");
            }
            tracing::info!("admin {} removed certificate push key {fp}", me.email);
            Ok(j!({ "ok": true }))
        }
        ("POST", ["certs", "upload"]) => {
            let u: CertUpload = body(r)?;
            let srv2 = srv.clone();
            let who = format!("admin {}", me.email);
            let info = tokio::task::spawn_blocking(move || crate::certs::install(&srv2, u.fullchain.as_bytes(), u.key.as_bytes(), &who)).await??;
            Ok(j!({ "installed": info }))
        }

        // ---------------------------------------------------------------- domains
        ("GET", ["domains"]) => {
            srv.store
                .call(|c| {
                    let mut out = Vec::new();
                    for d in store::list_domains(c)? {
                        let users: i64 = c.query_row("SELECT COUNT(*) FROM users WHERE email LIKE '%@' || ?1", [&d.name], |r| r.get(0))?;
                        let aliases: i64 = c.query_row("SELECT COUNT(DISTINCT source) FROM aliases WHERE source LIKE '%@' || ?1", [&d.name], |r| r.get(0))?;
                        out.push(j!({
                            "name": d.name, "alias_of": d.alias_of, "catch_all": d.catch_all,
                            "dkim_selector": d.dkim_selector, "has_dkim": d.dkim_key.is_some(),
                            "users": users, "aliases": aliases,
                        }));
                    }
                    Ok(Value::Array(out))
                })
                .await
        }
        ("POST", ["domains"]) => {
            let n: NewDomain = body(r)?;
            let name = n.name.trim().to_ascii_lowercase();
            if !name.contains('.') || name.contains('@') || name.contains(' ') {
                bail!("'{name}' is not a valid domain");
            }
            let sel = n.selector.filter(|s| !s.trim().is_empty()).unwrap_or_else(|| "pw1".into());
            let (pem, _) = tokio::task::spawn_blocking(delivery::generate_dkim_key).await??;
            let nm = name.clone();
            srv.store.call(move |c| store::add_domain(c, &nm, &sel, &pem)).await?;
            tracing::info!("admin {} added domain {name}", me.email);
            Ok(j!({ "ok": true }))
        }
        ("POST", ["domains", "alias"]) => {
            let a: NewAliasDomain = body(r)?;
            srv.store.call(move |c| store::add_alias_domain(c, a.alias.trim(), a.target.trim(), None)).await?;
            Ok(j!({ "ok": true }))
        }
        ("PUT", ["domains", name]) => {
            let u: DomainUpdate = body(r)?;
            let name = name.to_string();
            let ca = u.catch_all.filter(|s| !s.trim().is_empty());
            if let Some(t) = &ca {
                if !crate::smtp::valid_address(t) {
                    bail!("invalid catch-all address");
                }
            }
            srv.store.call(move |c| store::set_catch_all(c, &name, ca.as_deref())).await?;
            Ok(j!({ "ok": true }))
        }
        ("DELETE", ["domains", name]) => {
            let name = name.to_string();
            let n2 = name.clone();
            if !srv.store.call(move |c| store::delete_domain(c, &n2)).await? {
                bail!("no such domain");
            }
            tracing::info!("admin {} removed domain {name}", me.email);
            Ok(j!({ "ok": true }))
        }
        ("GET", ["domains", name, "dns"]) => dns_check(srv, name).await,

        // ------------------------------------------------------------------ users
        ("GET", ["users"]) => {
            srv.store
                .call(|c| {
                    let mut out = Vec::new();
                    for u in store::list_users(c)? {
                        let used = store::user_usage(c, u.id)?;
                        let addrs = store::sender_addresses(c, &u)?;
                        let fwd = store::alias_targets(c, &u.email)?;
                        let vac = crate::prefs::load(c, u.id)?.vacation;
                        out.push(j!({
                            "email": u.email, "quota_bytes": u.quota_bytes, "used_bytes": used,
                            "enabled": u.enabled, "admin": u.is_admin,
                            "legacy_password": auth::is_legacy(&u.password),
                            "addresses": addrs.into_iter().filter(|a| *a != u.email).collect::<Vec<_>>(),
                            "forwards_to": fwd,
                            "out_of_office": vac.active(store::now()),
                        }));
                    }
                    Ok(Value::Array(out))
                })
                .await
        }
        ("POST", ["users"]) => {
            let n: NewUser = body(r)?;
            let email = n.email.trim().to_ascii_lowercase();
            if !crate::smtp::valid_address(&email) {
                bail!("invalid email address");
            }
            if n.password.chars().count() < 10 {
                bail!("password must be at least 10 characters");
            }
            let hash = auth::hash_password(&n.password)?;
            let e2 = email.clone();
            srv.store
                .call(move |c| {
                    store::create_user(c, &e2, &hash, n.quota_mb.max(0) * 1024 * 1024)?;
                    store::set_admin(c, &e2, n.admin)?;
                    Ok(())
                })
                .await?;
            tracing::info!("admin {} created user {email}", me.email);
            Ok(j!({ "ok": true }))
        }
        ("PUT", ["users", email]) => {
            let u: UserUpdate = body(r)?;
            let email = email.to_ascii_lowercase();
            if email == me.email && (u.admin == Some(false) || u.enabled == Some(false)) {
                bail!("you can't remove your own admin access or disable yourself");
            }
            let hash = match &u.password {
                Some(p) if !p.is_empty() => {
                    if p.chars().count() < 10 {
                        bail!("password must be at least 10 characters");
                    }
                    Some(auth::hash_password(p)?)
                }
                _ => None,
            };
            let e2 = email.clone();
            srv.store
                .call(move |c| {
                    if store::find_user(c, &e2)?.is_none() {
                        bail!("no such user");
                    }
                    if let Some(h) = hash {
                        store::set_password(c, &e2, &h)?;
                    }
                    if let Some(q) = u.quota_mb {
                        store::set_quota(c, &e2, q.max(0) * 1024 * 1024)?;
                    }
                    if let Some(en) = u.enabled {
                        store::set_enabled(c, &e2, en)?;
                    }
                    if let Some(a) = u.admin {
                        store::set_admin(c, &e2, a)?;
                    }
                    Ok(())
                })
                .await?;
            crate::http::forget_cached_logins_for(&email);
            Ok(j!({ "ok": true }))
        }
        ("DELETE", ["users", email]) => {
            let email = email.to_ascii_lowercase();
            if email == me.email {
                bail!("you can't delete your own account");
            }
            let e2 = email.clone();
            if !srv.store.call(move |c| store::delete_user(c, &e2)).await? {
                bail!("no such user");
            }
            crate::http::forget_cached_logins_for(&email);
            tracing::info!("admin {} deleted user {email}", me.email);
            Ok(j!({ "ok": true }))
        }

        // ---------------------------------------------------------------- aliases
        ("GET", ["aliases"]) => {
            srv.store
                .call(|c| Ok(Value::Array(store::list_aliases(c)?.into_iter().map(|(s, t)| j!({"source": s, "target": t})).collect())))
                .await
        }
        ("POST", ["aliases"]) => {
            let a: NewAlias = body(r)?;
            if !crate::smtp::valid_address(a.source.trim()) || !crate::smtp::valid_address(a.target.trim()) {
                bail!("invalid address");
            }
            srv.store.call(move |c| store::add_alias(c, a.source.trim(), a.target.trim())).await?;
            Ok(j!({ "ok": true }))
        }
        ("DELETE", ["aliases", source, rest @ ..]) => {
            let (s, t) = (source.to_string(), rest.first().map(|t| t.to_string()));
            let n = srv.store.call(move |c| store::remove_alias(c, &s, t.as_deref())).await?;
            Ok(j!({ "removed": n }))
        }

        // ------------------------------------------------------------------ queue
        ("GET", ["queue"]) => {
            srv.store
                .call(|c| {
                    Ok(Value::Array(
                        store::list_queue(c)?
                            .into_iter()
                            .map(|q| {
                                j!({"id": q.id, "from": q.mail_from, "domain": q.domain, "recipients": q.rcpts,
                                    "attempts": q.attempts, "created": q.created, "next_attempt": q.next_attempt,
                                    "last_error": q.last_error})
                            })
                            .collect(),
                    ))
                })
                .await
        }
        ("POST", ["queue", "flush"]) => {
            let n = srv.store.call(|c| store::queue_flush(c)).await?;
            srv.queue_wake.notify_one();
            Ok(j!({ "rescheduled": n }))
        }
        ("DELETE", ["queue", id]) => {
            let id: i64 = id.parse()?;
            srv.store.call(move |c| store::delete_queue_item(c, id)).await?;
            tracing::info!("admin {} deleted queued message {id}", me.email);
            Ok(j!({ "ok": true }))
        }

        // ------------------------------------------------------------ logs/import
        ("GET", ["logs"]) => {
            let n = query(r, "n").and_then(|n| n.parse().ok()).unwrap_or(300usize).min(2000);
            let q = query(r, "q").filter(|q| !q.is_empty());
            Ok(j!({ "lines": logbuf::recent(n, q.as_deref()) }))
        }
        ("GET", ["filters"]) => {
            let f = &srv.cfg.filter;
            Ok(j!({
                "enabled": f.enabled, "junk_score": f.junk_score, "reject_score": f.reject_score,
                "greet_pause_ms": f.greet_pause_ms, "scan_outbound": f.scan_outbound,
                "dnsbl": f.dnsbl.iter().map(|d| j!({"zone": d.zone, "score": d.score})).collect::<Vec<_>>(),
                "scanners": crate::filter::health(srv).await,
            }))
        }
        ("GET", ["import"]) => {
            let st = IMPORT.lock().unwrap().clone();
            let out = iredmail::OUTPUT.lock().unwrap().clone();
            Ok(j!({ "running": st.running, "finished": st.finished, "ok": st.ok, "error": st.error, "output": out }))
        }
        ("POST", ["import", "iredmail"]) => {
            let req: ImportReq = body(r)?;
            {
                let mut st = IMPORT.lock().unwrap();
                if st.running {
                    bail!("an import is already running");
                }
                *st = ImportState { running: true, ..Default::default() };
            }
            iredmail::OUTPUT.lock().unwrap().clear();
            let store = srv.store.clone();
            tracing::info!("admin {} started iRedMail import (dry run: {})", me.email, req.dry_run);
            tokio::task::spawn_blocking(move || {
                let opts = iredmail::Opts {
                    backend: req.backend.filter(|b| !b.is_empty()),
                    postfix_dir: "/etc/postfix".into(),
                    dry_run: req.dry_run,
                    mail: !req.no_mail,
                    calendars: !req.no_calendars,
                    only_user: req.user.filter(|u| !u.is_empty()),
                    sql_cmd: None,
                };
                let res = iredmail::run(&store, &opts);
                let mut st = IMPORT.lock().unwrap();
                st.running = false;
                st.finished = true;
                st.ok = res.is_ok();
                st.error = res.err().map(|e| format!("{e:#}"));
            });
            Ok(j!({ "started": true }))
        }
        _ => Err(anyhow!("unknown admin endpoint")),
    }
}

#[derive(Default, Clone)]
struct ImportState {
    running: bool,
    finished: bool,
    ok: bool,
    error: Option<String>,
}

static IMPORT: Mutex<ImportState> = Mutex::new(ImportState { running: false, finished: false, ok: false, error: None });

// --------------------------------------------------------------- overview

async fn overview(srv: &Shared) -> Result<Value> {
    let counts = srv
        .store
        .call(|c| {
            let q = |sql: &str| -> Result<i64> { Ok(c.query_row(sql, [], |r| r.get(0))?) };
            Ok(j!({
                "domains": q("SELECT COUNT(*) FROM domains WHERE alias_of IS NULL")?,
                "alias_domains": q("SELECT COUNT(*) FROM domains WHERE alias_of IS NOT NULL")?,
                "users": q("SELECT COUNT(*) FROM users")?,
                "disabled_users": q("SELECT COUNT(*) FROM users WHERE enabled = 0")?,
                "aliases": q("SELECT COUNT(DISTINCT source) FROM aliases")?,
                "messages": q("SELECT COUNT(*) FROM messages")?,
                "storage_bytes": q("SELECT COALESCE(SUM(size), 0) FROM messages")?,
                "unique_bytes": q("SELECT COALESCE(SUM(size), 0) FROM (SELECT DISTINCT blob, size FROM messages)")?,
                "queue": q("SELECT COUNT(*) FROM queue")?,
                "queue_failing": q("SELECT COUNT(*) FROM queue WHERE attempts > 0")?,
                "calendars": q("SELECT COUNT(*) FROM calendars")?,
                "events": q("SELECT COUNT(*) FROM calendar_objects")?,
            }))
        })
        .await?;
    let host = srv.cfg.hostname.clone();
    let (ips, ptr_ok, ptrs) = server_dns(srv, &host).await;
    let warnings = logbuf::recent(2000, None).into_iter().filter(|l| l.contains(" WARN ") || l.contains(" ERROR ")).count();
    Ok(j!({
        "version": env!("CARGO_PKG_VERSION"),
        "hostname": host,
        "uptime_secs": STARTED.get().map(|s| s.elapsed().as_secs()).unwrap_or(0),
        "counts": counts,
        "server_dns": { "addresses": ips, "ptr": ptrs, "ptr_matches": ptr_ok },
        "scanners": crate::filter::health(srv).await,
        "certificate": crate::certs::current(&srv.cfg).ok(),
        "filter_enabled": srv.cfg.filter.enabled,
        "recent_warnings": warnings,
        "listeners": {
            "smtp": srv.cfg.listeners.smtp, "submission": srv.cfg.listeners.submission,
            "submissions": srv.cfg.listeners.submissions, "imap": srv.cfg.listeners.imap,
            "imaps": srv.cfg.listeners.imaps, "https": srv.cfg.listeners.https,
        },
    }))
}

/// A/AAAA for the host name, and whether reverse DNS for each points back to it.
async fn server_dns(srv: &Shared, host: &str) -> (Vec<String>, bool, Vec<String>) {
    let mut ips: Vec<IpAddr> = Vec::new();
    if let Ok(v4) = srv.dns.ipv4_lookup(host, None::<&NoCache<String, Arc<Vec<std::net::Ipv4Addr>>>>).await {
        ips.extend(v4.iter().map(|a| IpAddr::V4(*a)));
    }
    if let Ok(v6) = srv.dns.ipv6_lookup(host, None::<&NoCache<String, Arc<Vec<std::net::Ipv6Addr>>>>).await {
        ips.extend(v6.iter().map(|a| IpAddr::V6(*a)));
    }
    let mut ptrs = Vec::new();
    let mut ok = !ips.is_empty();
    for ip in &ips {
        match srv.dns.ptr_lookup(*ip, None::<&NoCache<IpAddr, Arc<Vec<String>>>>).await {
            Ok(names) => {
                let names: Vec<String> = names.iter().map(|n| n.trim_end_matches('.').to_ascii_lowercase()).collect();
                if !names.iter().any(|n| n == host) {
                    ok = false;
                }
                ptrs.extend(names.iter().map(|n| format!("{ip} -> {n}")));
            }
            Err(_) => {
                ok = false;
                ptrs.push(format!("{ip} -> (none)"));
            }
        }
    }
    (ips.iter().map(|i| i.to_string()).collect(), ok, ptrs)
}

// -------------------------------------------------------------- DNS check

async fn txt(srv: &Shared, name: &str) -> Option<String> {
    srv.dns.txt_raw_lookup(name).await.ok().map(|b| String::from_utf8_lossy(&b).into_owned()).filter(|s| !s.is_empty())
}

/// Expected records for a domain and what DNS currently says.
async fn dns_check(srv: &Shared, name: &str) -> Result<Value> {
    let name = name.to_ascii_lowercase();
    let n2 = name.clone();
    let d = srv.store.call(move |c| store::find_domain(c, &n2)).await?.ok_or_else(|| anyhow!("no such domain"))?;
    let host = srv.cfg.hostname.clone();
    let mut rows = Vec::new();
    let mut push = |kind: &str, rname: String, expected: String, found: Option<String>, status: &str| {
        rows.push(j!({"type": kind, "name": rname, "expected": expected, "found": found, "status": status}));
    };

    // MX
    let mx = srv.dns.mx_lookup(name.as_str(), None::<&NoCache<String, Arc<Vec<mail_auth::MX>>>>).await;
    let mx_hosts: Vec<String> = mx.map(|m| m.iter().flat_map(|x| x.exchanges.iter().map(|h| h.trim_end_matches('.').to_string())).collect()).unwrap_or_default();
    let mx_ok = mx_hosts.iter().any(|h| h.eq_ignore_ascii_case(&host));
    push(
        "MX",
        name.clone(),
        format!("10 {host}."),
        if mx_hosts.is_empty() { None } else { Some(mx_hosts.join(", ")) },
        if mx_ok { "ok" } else if mx_hosts.is_empty() { "missing" } else { "different" },
    );

    // SPF
    let apex = txt(srv, &name).await;
    let spf = apex.as_ref().and_then(|t| t.find("v=spf1").map(|i| t[i..].split("v=").take(2).collect::<Vec<_>>().join("v=").trim().to_string()));
    push("TXT", name.clone(), "v=spf1 mx -all".into(), spf.clone(), if spf.is_some() { "ok" } else { "missing" });

    // DKIM
    if let (Some(sel), Some(key)) = (&d.dkim_selector, &d.dkim_key) {
        let pubkey = delivery::dkim_public_from_pem(key)?;
        let rname = format!("{sel}._domainkey.{name}");
        let found = txt(srv, &rname).await;
        let status = match &found {
            None => "missing",
            Some(f) if f.replace([' ', '"'], "").contains(&pubkey) => "ok",
            Some(_) => "different",
        };
        push("TXT", rname, format!("v=DKIM1; k=rsa; p={pubkey}"), found, status);
    }

    // DMARC
    let rname = format!("_dmarc.{name}");
    let dmarc = txt(srv, &rname).await.filter(|t| t.contains("v=DMARC1"));
    push(
        "TXT",
        rname,
        format!("v=DMARC1; p=quarantine; adkim=s; aspf=s; rua=mailto:postmaster@{name}"),
        dmarc.clone(),
        if dmarc.is_some() { "ok" } else { "missing" },
    );
    Ok(j!({ "domain": name, "alias_of": d.alias_of, "records": rows }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cidr() {
        let nets: Vec<String> = ["192.168.0.0/16", "10.0.0.0/8", "::1/128", "fc00::/7"].iter().map(|s| s.to_string()).collect();
        assert!(in_networks("192.168.1.62".parse().unwrap(), &nets));
        assert!(!in_networks("81.2.69.160".parse().unwrap(), &nets));
        assert!(in_networks("::ffff:10.1.2.3".parse().unwrap(), &nets));
        assert!(in_networks("::1".parse().unwrap(), &nets));
        assert!(in_networks("fd00::5".parse().unwrap(), &nets));
        assert!(!in_networks("2a00::1".parse().unwrap(), &nets));
    }
}
