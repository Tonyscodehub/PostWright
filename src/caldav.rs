//! CalDAV (RFC 4791) with calendar sharing. Works with Thunderbird, Apple Calendar,
//! DAVx5 (Android) and any standards-based client.
//!
//! URL layout (everything is scoped to the signed-in user):
//!   /dav/principals/{email}/
//!   /dav/calendars/{email}/                 calendar home
//!   /dav/calendars/{email}/{slug}/          own calendar
//!   /dav/calendars/{email}/shared-{id}/     calendar shared with this user
//!   /dav/calendars/{email}/{slug}/{name}.ics

use crate::http::{enc_path, Req, Resp};
use crate::server::Shared;
use crate::store::{self, now, User};
use crate::xml::{self, esc, qname, Elem, APPLE, CALDAV, CS, DAV};
use anyhow::{bail, Result};
use hyper::StatusCode;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};

// ------------------------------------------------------------------ storage

#[derive(Debug, Clone, Serialize)]
pub struct Calendar {
    #[serde(skip)]
    pub id: i64,
    #[serde(skip)]
    #[allow(dead_code)]
    pub owner_id: i64,
    pub owner: String,
    /// Path segment as seen by the current user.
    pub slug: String,
    pub name: String,
    pub color: Option<String>,
    pub description: Option<String>,
    #[serde(skip)]
    pub ctag: i64,
    pub write: bool,
    pub is_owner: bool,
}

#[derive(Debug, Clone)]
pub struct Obj {
    pub name: String,
    pub etag: String,
    pub data: String,
    pub component: Option<String>,
    pub dtstart: Option<i64>,
    pub dtend: Option<i64>,
    pub recurring: bool,
}

const CAL_COLS: &str = "c.id, c.owner_id, u.email, c.slug, c.name, c.color, c.description, c.ctag";

fn row_cal(r: &rusqlite::Row, viewer: i64, write: Option<bool>) -> rusqlite::Result<Calendar> {
    let id: i64 = r.get(0)?;
    let owner_id: i64 = r.get(1)?;
    let is_owner = owner_id == viewer;
    let slug: String = r.get(3)?;
    Ok(Calendar {
        id,
        owner_id,
        owner: r.get(2)?,
        slug: if is_owner { slug } else { format!("shared-{id}") },
        name: r.get(4)?,
        color: r.get(5)?,
        description: r.get(6)?,
        ctag: r.get(7)?,
        write: is_owner || write.unwrap_or(false),
        is_owner,
    })
}

pub fn ensure_default(c: &Connection, user_id: i64) -> Result<()> {
    let n: i64 = c.query_row("SELECT COUNT(*) FROM calendars WHERE owner_id = ?1", [user_id], |r| r.get(0))?;
    if n == 0 {
        c.execute(
            "INSERT OR IGNORE INTO calendars(owner_id, slug, name, color) VALUES(?1, 'calendar', 'Calendar', '#2E7D32FF')",
            [user_id],
        )?;
    }
    Ok(())
}

pub fn list_calendars(c: &Connection, user_id: i64) -> Result<Vec<Calendar>> {
    ensure_default(c, user_id)?;
    let mut out = Vec::new();
    let mut st = c.prepare(&format!(
        "SELECT {CAL_COLS} FROM calendars c JOIN users u ON u.id = c.owner_id WHERE c.owner_id = ?1 ORDER BY c.name"
    ))?;
    out.extend(st.query_map([user_id], |r| row_cal(r, user_id, None))?.collect::<Result<Vec<_>, _>>()?);
    let mut st = c.prepare(&format!(
        "SELECT {CAL_COLS}, s.write FROM calendars c JOIN users u ON u.id = c.owner_id
         JOIN calendar_shares s ON s.calendar_id = c.id WHERE s.user_id = ?1 ORDER BY c.name"
    ))?;
    out.extend(
        st.query_map([user_id], |r| {
            let w: i64 = r.get(8)?;
            row_cal(r, user_id, Some(w != 0))
        })?
        .collect::<Result<Vec<_>, _>>()?,
    );
    Ok(out)
}

pub fn resolve(c: &Connection, user_id: i64, slug: &str) -> Result<Option<Calendar>> {
    if let Some(id) = slug.strip_prefix("shared-").and_then(|s| s.parse::<i64>().ok()) {
        return Ok(c
            .query_row(
                &format!(
                    "SELECT {CAL_COLS}, s.write FROM calendars c JOIN users u ON u.id = c.owner_id
                     JOIN calendar_shares s ON s.calendar_id = c.id WHERE s.user_id = ?1 AND c.id = ?2"
                ),
                params![user_id, id],
                |r| {
                    let w: i64 = r.get(8)?;
                    row_cal(r, user_id, Some(w != 0))
                },
            )
            .optional()?);
    }
    Ok(c
        .query_row(
            &format!("SELECT {CAL_COLS} FROM calendars c JOIN users u ON u.id = c.owner_id WHERE c.owner_id = ?1 AND c.slug = ?2"),
            params![user_id, slug],
            |r| row_cal(r, user_id, None),
        )
        .optional()?)
}

pub fn valid_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && !s.starts_with("shared-")
        && !s.starts_with('.')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
}

pub fn create_calendar(c: &Connection, user_id: i64, slug: &str, name: &str, color: Option<&str>) -> Result<()> {
    if !valid_slug(slug) {
        bail!("invalid calendar id");
    }
    c.execute(
        "INSERT INTO calendars(owner_id, slug, name, color) VALUES(?1, ?2, ?3, ?4)",
        params![user_id, slug, if name.trim().is_empty() { slug } else { name.trim() }, color],
    )?;
    Ok(())
}

/// Generate a unique slug from a display name.
pub fn slug_for(c: &Connection, user_id: i64, name: &str) -> Result<String> {
    let mut base: String = name
        .to_ascii_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    if base.is_empty() || base.starts_with("shared") {
        base = "calendar".into();
    }
    base.truncate(60);
    let mut slug = base.clone();
    let mut n = 2;
    while resolve(c, user_id, &slug)?.is_some() {
        slug = format!("{base}-{n}");
        n += 1;
    }
    Ok(slug)
}

pub fn share(c: &Connection, cal_id: i64, with: &str, write: bool) -> Result<()> {
    let user = store::find_user(c, with)?.ok_or_else(|| anyhow::anyhow!("no such user {with}"))?;
    let owner: i64 = c.query_row("SELECT owner_id FROM calendars WHERE id = ?1", [cal_id], |r| r.get(0))?;
    if owner == user.id {
        bail!("cannot share a calendar with its owner");
    }
    c.execute(
        "INSERT INTO calendar_shares(calendar_id, user_id, write) VALUES(?1, ?2, ?3)
         ON CONFLICT(calendar_id, user_id) DO UPDATE SET write = ?3",
        params![cal_id, user.id, write as i64],
    )?;
    Ok(())
}

pub fn unshare(c: &Connection, cal_id: i64, with: &str) -> Result<bool> {
    let Some(user) = store::find_user(c, with)? else { return Ok(false) };
    Ok(c.execute("DELETE FROM calendar_shares WHERE calendar_id = ?1 AND user_id = ?2", params![cal_id, user.id])? > 0)
}

pub fn shares_of(c: &Connection, cal_id: i64) -> Result<Vec<(String, bool)>> {
    let mut st = c.prepare(
        "SELECT u.email, s.write FROM calendar_shares s JOIN users u ON u.id = s.user_id WHERE s.calendar_id = ?1 ORDER BY u.email",
    )?;
    let v = st.query_map([cal_id], |r| Ok((r.get(0)?, r.get::<_, i64>(1)? != 0)))?.collect::<Result<Vec<_>, _>>()?;
    Ok(v)
}

fn row_obj(r: &rusqlite::Row) -> rusqlite::Result<Obj> {
    Ok(Obj {
        name: r.get(0)?,
        etag: r.get(1)?,
        data: r.get(2)?,
        component: r.get(3)?,
        dtstart: r.get(4)?,
        dtend: r.get(5)?,
        recurring: r.get::<_, i64>(6)? != 0,
    })
}

const OBJ_COLS: &str = "name, etag, data, component, dtstart, dtend, recurring";

pub fn list_objects(c: &Connection, cal_id: i64) -> Result<Vec<Obj>> {
    let mut st = c.prepare(&format!("SELECT {OBJ_COLS} FROM calendar_objects WHERE calendar_id = ?1 ORDER BY name"))?;
    let v = st.query_map([cal_id], row_obj)?.collect::<Result<Vec<_>, _>>()?;
    Ok(v)
}

pub fn get_object(c: &Connection, cal_id: i64, name: &str) -> Result<Option<Obj>> {
    Ok(c
        .query_row(&format!("SELECT {OBJ_COLS} FROM calendar_objects WHERE calendar_id = ?1 AND name = ?2"), params![cal_id, name], row_obj)
        .optional()?)
}

fn bump(c: &Connection, cal_id: i64) -> Result<()> {
    c.execute("UPDATE calendars SET ctag = ctag + 1 WHERE id = ?1", [cal_id])?;
    Ok(())
}

// --------------------------------------------------------------------- iCal

/// Unfolded content lines.
fn ics_lines(data: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in data.split('\n') {
        let l = raw.strip_suffix('\r').unwrap_or(raw);
        if (l.starts_with(' ') || l.starts_with('\t')) && !out.is_empty() {
            out.last_mut().unwrap().push_str(&l[1..]);
        } else {
            out.push(l.to_string());
        }
    }
    out
}

/// Parse an iCalendar date/date-time value to a Unix timestamp (local times treated as UTC;
/// the time-range filter adds a day of slack to compensate).
pub fn ical_time(v: &str) -> Option<i64> {
    let v = v.trim();
    if v.len() >= 15 {
        let dt = chrono::NaiveDateTime::parse_from_str(&v[..15], "%Y%m%dT%H%M%S").ok()?;
        Some(dt.and_utc().timestamp())
    } else if v.len() == 8 {
        let d = chrono::NaiveDate::parse_from_str(v, "%Y%m%d").ok()?;
        Some(d.and_hms_opt(0, 0, 0)?.and_utc().timestamp())
    } else {
        None
    }
}

pub struct IcsMeta {
    pub component: String,
    pub uid: Option<String>,
    pub dtstart: Option<i64>,
    pub dtend: Option<i64>,
    pub recurring: bool,
}

pub fn ics_meta(data: &str) -> Result<IcsMeta> {
    let lines = ics_lines(data);
    if !lines.first().map(|l| l.trim().eq_ignore_ascii_case("BEGIN:VCALENDAR")).unwrap_or(false) {
        bail!("not an iCalendar object");
    }
    let mut comp: Option<String> = None;
    let mut depth_in = false;
    let (mut uid, mut start, mut end, mut recurring) = (None, None, None, false);
    for l in &lines {
        let up = l.to_ascii_uppercase();
        if let Some(c) = up.strip_prefix("BEGIN:") {
            if comp.is_none() && ["VEVENT", "VTODO", "VJOURNAL"].contains(&c.trim()) {
                comp = Some(c.trim().to_string());
                depth_in = true;
            }
            continue;
        }
        if up.starts_with("END:") && comp.as_deref() == Some(up[4..].trim()) {
            depth_in = false;
            continue;
        }
        if !depth_in {
            if up.starts_with("RRULE") || up.starts_with("RDATE") {
                recurring = true;
            }
            continue;
        }
        let Some((key, val)) = l.split_once(':') else { continue };
        let name = key.split(';').next().unwrap_or("").to_ascii_uppercase();
        match name.as_str() {
            "UID" => uid = Some(val.trim().to_string()),
            "DTSTART" => start = ical_time(val),
            "DTEND" | "DUE" => end = ical_time(val),
            "RRULE" | "RDATE" => recurring = true,
            _ => {}
        }
    }
    let component = comp.ok_or_else(|| anyhow::anyhow!("no VEVENT, VTODO or VJOURNAL"))?;
    if end.is_none() {
        end = start.map(|s| s + 86400);
    }
    Ok(IcsMeta { component, uid, dtstart: start, dtend: end, recurring })
}

fn etag_of(data: &str) -> String {
    format!("\"{}\"", &hex::encode(Sha256::digest(data.as_bytes()))[..32])
}

// ------------------------------------------------------------------ routing

enum Res {
    Root,
    Principal,
    Home,
    Cal(Calendar),
    Obj(Calendar, Obj),
}

fn status(code: StatusCode) -> Resp {
    crate::http::text(code, "")
}

pub async fn handle(srv: Shared, user: User, req: Req) -> Resp {
    match handle_inner(srv, user, req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("CalDAV error: {e:#}");
            status(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

fn principal_href(email: &str) -> String {
    format!("/dav/principals/{}/", enc_path(email))
}
fn home_href(email: &str) -> String {
    format!("/dav/calendars/{}/", enc_path(email))
}
fn cal_href(email: &str, slug: &str) -> String {
    format!("/dav/calendars/{}/{}/", enc_path(email), enc_path(slug))
}

async fn handle_inner(srv: Shared, user: User, req: Req) -> Result<Resp> {
    let segs: Vec<String> = req.path.split('/').filter(|s| !s.is_empty()).map(String::from).collect();
    let segs: Vec<&str> = segs.iter().map(|s| s.as_str()).collect();
    if req.method == "OPTIONS" {
        return Ok(crate::http::builder(StatusCode::OK)
            .header("DAV", "1, 3, access-control, calendar-access, extended-mkcol")
            .header("Allow", "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, REPORT, MKCALENDAR, MKCOL")
            .body(Default::default())
            .unwrap());
    }
    // Which user's namespace is addressed? Only the signed-in user's is accessible.
    let ns_user = match segs.as_slice() {
        [] | ["dav"] | ["dav", "principals"] | ["dav", "calendars"] => None,
        ["dav", _, email, ..] => Some(email.to_ascii_lowercase()),
        _ => return Ok(status(StatusCode::NOT_FOUND)),
    };
    if let Some(e) = &ns_user {
        if *e != user.email {
            return Ok(status(StatusCode::FORBIDDEN));
        }
    }
    let uid = user.id;
    let res = {
        let segs: Vec<String> = segs.iter().map(|s| s.to_string()).collect();
        srv.store
            .call(move |c| {
                let s: Vec<&str> = segs.iter().map(|x| x.as_str()).collect();
                Ok(match s.as_slice() {
                    [] | ["dav"] | ["dav", "principals"] | ["dav", "calendars"] => Some(Res::Root),
                    ["dav", "principals", _] => Some(Res::Principal),
                    ["dav", "calendars", _] => Some(Res::Home),
                    ["dav", "calendars", _, slug] => resolve(c, uid, slug)?.map(Res::Cal),
                    ["dav", "calendars", _, slug, name] => match resolve(c, uid, slug)? {
                        Some(cal) => get_object(c, cal.id, name)?.map(|o| Res::Obj(cal, o)),
                        None => None,
                    },
                    _ => None,
                })
            })
            .await?
    };
    let m = req.method.as_str();
    match (m, res) {
        ("PROPFIND", Some(r)) => propfind(&srv, &user, &req, r).await,
        ("PROPFIND", None) => Ok(status(StatusCode::NOT_FOUND)),
        ("REPORT", Some(Res::Cal(cal))) => report(&srv, &user, &req, cal).await,
        ("REPORT", Some(Res::Home | Res::Principal | Res::Root)) => {
            Ok(crate::http::xml_resp(StatusCode::MULTI_STATUS, format!("{}</D:multistatus>", xml::MULTISTATUS_OPEN)))
        }
        ("GET" | "HEAD", Some(Res::Obj(_, o))) => Ok(crate::http::builder(StatusCode::OK)
            .header("Content-Type", "text/calendar; charset=utf-8")
            .header("ETag", o.etag.clone())
            .body(if m == "HEAD" { Default::default() } else { o.data.into_bytes().into() })
            .unwrap()),
        ("GET" | "HEAD", Some(Res::Cal(cal))) => {
            let id = cal.id;
            let objs = srv.store.call(move |c| list_objects(c, id)).await?;
            Ok(crate::http::builder(StatusCode::OK)
                .header("Content-Type", "text/calendar; charset=utf-8")
                .header("Content-Disposition", format!("attachment; filename=\"{}.ics\"", cal.slug))
                .body(export(&cal, &objs).into_bytes().into())
                .unwrap())
        }
        ("GET" | "HEAD", None) => Ok(status(StatusCode::NOT_FOUND)),
        ("GET" | "HEAD", Some(_)) => Ok(crate::http::text(StatusCode::OK, "Postwright CalDAV. Point your calendar app at this server.")),
        ("PUT", res) => put(&srv, &user, &req, &segs, res).await,
        ("DELETE", Some(Res::Obj(cal, o))) => {
            if !cal.write {
                return Ok(status(StatusCode::FORBIDDEN));
            }
            if let Some(im) = req.header("if-match") {
                if im != "*" && im != o.etag {
                    return Ok(status(StatusCode::PRECONDITION_FAILED));
                }
            }
            let (id, name) = (cal.id, o.name.clone());
            srv.store
                .call(move |c| {
                    c.execute("DELETE FROM calendar_objects WHERE calendar_id = ?1 AND name = ?2", params![id, name])?;
                    bump(c, id)
                })
                .await?;
            Ok(status(StatusCode::NO_CONTENT))
        }
        ("DELETE", Some(Res::Cal(cal))) => {
            let (id, email) = (cal.id, user.email.clone());
            if cal.is_owner {
                srv.store.call(move |c| Ok(c.execute("DELETE FROM calendars WHERE id = ?1", [id])?)).await?;
            } else {
                // A sharee "deleting" a shared calendar just unsubscribes from it.
                srv.store.call(move |c| unshare(c, id, &email)).await?;
            }
            Ok(status(StatusCode::NO_CONTENT))
        }
        ("DELETE", _) => Ok(status(StatusCode::NOT_FOUND)),
        ("MKCALENDAR" | "MKCOL", None) => {
            let ["dav", "calendars", _, slug] = segs.as_slice() else { return Ok(status(StatusCode::FORBIDDEN)) };
            if !valid_slug(slug) {
                return Ok(status(StatusCode::FORBIDDEN));
            }
            let body = xml::parse(&req.body);
            let mut name = slug.to_string();
            let mut color = None;
            if let Some(b) = &body {
                let mut v = Vec::new();
                b.find_all(DAV, "displayname", &mut v);
                if let Some(d) = v.first() {
                    name = d.text.clone();
                }
                let mut v = Vec::new();
                b.find_all(APPLE, "calendar-color", &mut v);
                color = v.first().map(|e| e.text.clone());
            }
            let slug = slug.to_string();
            srv.store.call(move |c| create_calendar(c, uid, &slug, &name, color.as_deref())).await?;
            Ok(status(StatusCode::CREATED))
        }
        ("MKCALENDAR" | "MKCOL", Some(_)) => Ok(status(StatusCode::METHOD_NOT_ALLOWED)),
        ("PROPPATCH", Some(Res::Cal(cal))) => proppatch(&srv, &req, cal).await,
        ("PROPPATCH", Some(_)) => Ok(status(StatusCode::FORBIDDEN)),
        _ => Ok(status(StatusCode::METHOD_NOT_ALLOWED)),
    }
}

fn export(cal: &Calendar, objs: &[Obj]) -> String {
    let mut out = format!("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Postwright//CalDAV//EN\r\nX-WR-CALNAME:{}\r\n", cal.name);
    for o in objs {
        for l in o.data.split('\n') {
            let l = l.strip_suffix('\r').unwrap_or(l);
            let u = l.to_ascii_uppercase();
            if l.is_empty()
                || u == "BEGIN:VCALENDAR"
                || u == "END:VCALENDAR"
                || u.starts_with("VERSION:")
                || u.starts_with("PRODID:")
                || u.starts_with("CALSCALE:")
                || u.starts_with("METHOD:")
            {
                continue;
            }
            out.push_str(l);
            out.push_str("\r\n");
        }
    }
    out.push_str("END:VCALENDAR\r\n");
    out
}

async fn put(srv: &Shared, user: &User, req: &Req, segs: &[&str], res: Option<Res>) -> Result<Resp> {
    let ["dav", "calendars", _, slug, name] = segs else { return Ok(status(StatusCode::FORBIDDEN)) };
    if name.len() > 255 || name.starts_with('.') {
        return Ok(status(StatusCode::FORBIDDEN));
    }
    let data = match String::from_utf8(req.body.to_vec()) {
        Ok(d) => d,
        Err(_) => return Ok(crate::http::text(StatusCode::UNSUPPORTED_MEDIA_TYPE, "iCalendar must be UTF-8")),
    };
    let meta = match ics_meta(&data) {
        Ok(m) => m,
        Err(e) => return Ok(crate::http::text(StatusCode::UNSUPPORTED_MEDIA_TYPE, &e.to_string())),
    };
    let existing = match &res {
        Some(Res::Obj(_, o)) => Some(o.etag.clone()),
        _ => None,
    };
    if let Some(inm) = req.header("if-none-match") {
        if inm == "*" && existing.is_some() {
            return Ok(status(StatusCode::PRECONDITION_FAILED));
        }
    }
    if let Some(im) = req.header("if-match") {
        match &existing {
            Some(e) if im == "*" || im == *e => {}
            _ => return Ok(status(StatusCode::PRECONDITION_FAILED)),
        }
    }
    let (uid, slug, name) = (user.id, slug.to_string(), name.to_string());
    let etag = etag_of(&data);
    let et = etag.clone();
    let created = srv
        .store
        .call(move |c| {
            let Some(cal) = resolve(c, uid, &slug)? else { return Ok(None) };
            if !cal.write {
                return Ok(Some(Err(StatusCode::FORBIDDEN)));
            }
            // RFC 4791 5.3.2.1: UIDs must be unique within a calendar.
            if let Some(u) = &meta.uid {
                let clash: Option<String> = c
                    .query_row(
                        "SELECT name FROM calendar_objects WHERE calendar_id = ?1 AND name != ?2 AND data LIKE '%UID:' || ?3 || '%'",
                        params![cal.id, name, u],
                        |r| r.get(0),
                    )
                    .optional()?;
                if clash.is_some() {
                    return Ok(Some(Err(StatusCode::CONFLICT)));
                }
            }
            let n = c.execute(
                "INSERT INTO calendar_objects(calendar_id, name, etag, data, component, dtstart, dtend, recurring, modified)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(calendar_id, name) DO UPDATE SET etag = ?3, data = ?4, component = ?5, dtstart = ?6, dtend = ?7,
                    recurring = ?8, modified = ?9",
                params![cal.id, name, et, data, meta.component, meta.dtstart, meta.dtend, meta.recurring as i64, now()],
            )?;
            bump(c, cal.id)?;
            Ok(Some(Ok(n)))
        })
        .await?;
    match created {
        None => Ok(status(StatusCode::CONFLICT)), // parent collection missing
        Some(Err(code)) => Ok(status(code)),
        Some(Ok(_)) => Ok(crate::http::builder(if existing.is_some() { StatusCode::NO_CONTENT } else { StatusCode::CREATED })
            .header("ETag", etag)
            .body(Default::default())
            .unwrap()),
    }
}

/// Requested properties, or None for allprop.
fn requested(body: Option<&Elem>) -> Option<Vec<(String, String)>> {
    let b = body?;
    if b.child(DAV, "allprop").is_some() {
        return None;
    }
    let p = b.child(DAV, "prop")?;
    Some(p.children.iter().map(|c| (c.ns.clone(), c.name.clone())).collect())
}

fn privileges(write: bool) -> String {
    let mut s = String::from("<D:privilege><D:read/></D:privilege><D:privilege><C:read-free-busy/></D:privilege><D:privilege><D:read-current-user-privilege-set/></D:privilege>");
    if write {
        s.push_str("<D:privilege><D:write/></D:privilege><D:privilege><D:write-content/></D:privilege><D:privilege><D:write-properties/></D:privilege><D:privilege><D:bind/></D:privilege><D:privilege><D:unbind/></D:privilege>");
    }
    s
}

/// All properties we know for a resource: (ns, name, value-xml).
fn known_props(user: &User, r: &Res, with_data: bool) -> Vec<(&'static str, &'static str, String)> {
    let me = &user.email;
    let mut v: Vec<(&str, &str, String)> = vec![
        (DAV, "current-user-principal", format!("<D:href>{}</D:href>", principal_href(me))),
        (DAV, "principal-collection-set", "<D:href>/dav/principals/</D:href>".into()),
    ];
    match r {
        Res::Root => {
            v.push((DAV, "resourcetype", "<D:collection/>".into()));
            v.push((DAV, "displayname", "Postwright".into()));
        }
        Res::Principal | Res::Home => {
            if matches!(r, Res::Principal) {
                v.push((DAV, "resourcetype", "<D:collection/><D:principal/>".into()));
            } else {
                v.push((DAV, "resourcetype", "<D:collection/>".into()));
            }
            v.push((DAV, "displayname", esc(me)));
            v.push((DAV, "principal-URL", format!("<D:href>{}</D:href>", principal_href(me))));
            v.push((DAV, "owner", format!("<D:href>{}</D:href>", principal_href(me))));
            v.push((CALDAV, "calendar-home-set", format!("<D:href>{}</D:href>", home_href(me))));
            v.push((CALDAV, "calendar-user-address-set", format!("<D:href>mailto:{}</D:href>", esc(me))));
            v.push((DAV, "current-user-privilege-set", privileges(true)));
        }
        Res::Cal(cal) => {
            v.push((DAV, "resourcetype", "<D:collection/><C:calendar/>".into()));
            let name = if cal.is_owner { cal.name.clone() } else { format!("{} ({})", cal.name, cal.owner) };
            v.push((DAV, "displayname", esc(&name)));
            v.push((CS, "getctag", format!("\"{}\"", cal.ctag)));
            v.push((DAV, "getetag", format!("\"ctag-{}\"", cal.ctag)));
            v.push((APPLE, "calendar-color", esc(cal.color.as_deref().unwrap_or("#2E7D32FF"))));
            if let Some(d) = &cal.description {
                v.push((CALDAV, "calendar-description", esc(d)));
            }
            v.push((
                CALDAV,
                "supported-calendar-component-set",
                "<C:comp name=\"VEVENT\"/><C:comp name=\"VTODO\"/><C:comp name=\"VJOURNAL\"/>".into(),
            ));
            v.push((
                DAV,
                "supported-report-set",
                "<D:supported-report><D:report><C:calendar-multiget/></D:report></D:supported-report><D:supported-report><D:report><C:calendar-query/></D:report></D:supported-report>".into(),
            ));
            v.push((DAV, "current-user-privilege-set", privileges(cal.write)));
            v.push((DAV, "owner", format!("<D:href>{}</D:href>", principal_href(&cal.owner))));
            v.push((CALDAV, "supported-calendar-data", "<C:calendar-data content-type=\"text/calendar\" version=\"2.0\"/>".into()));
        }
        Res::Obj(cal, o) => {
            v.push((DAV, "resourcetype", String::new()));
            v.push((DAV, "getetag", esc(&o.etag)));
            let comp = o.component.as_deref().unwrap_or("VEVENT").to_ascii_lowercase();
            v.push((DAV, "getcontenttype", format!("text/calendar; charset=utf-8; component={comp}")));
            v.push((DAV, "getcontentlength", o.data.len().to_string()));
            v.push((DAV, "current-user-privilege-set", privileges(cal.write)));
            if with_data {
                v.push((CALDAV, "calendar-data", esc(&o.data)));
            }
        }
    }
    v
}

fn response_xml(href: &str, user: &User, r: &Res, req: &Option<Vec<(String, String)>>) -> String {
    let wants_data = req.as_ref().map(|v| v.iter().any(|(ns, n)| ns == CALDAV && n == "calendar-data")).unwrap_or(false);
    let known = known_props(user, r, wants_data);
    let mut ok = String::new();
    let mut missing = String::new();
    let mut emit = |ns: &str, name: &str, val: Option<&String>| {
        let (open, close) = qname(ns, name);
        match val {
            Some(v) if v.is_empty() => ok.push_str(&format!("<{open}/>")),
            Some(v) => ok.push_str(&format!("<{open}>{v}</{close}>")),
            None => missing.push_str(&format!("<{open}/>")),
        }
    };
    match req {
        None => {
            for (ns, n, v) in &known {
                emit(ns, n, Some(v));
            }
        }
        Some(list) => {
            for (ns, n) in list {
                let v = known.iter().find(|(kn, kname, _)| kn == ns && kname == n).map(|x| &x.2);
                emit(ns, n, v);
            }
        }
    }
    let mut s = format!("<D:response><D:href>{}</D:href>", esc(href));
    if !ok.is_empty() || missing.is_empty() {
        s.push_str(&format!("<D:propstat><D:prop>{ok}</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>"));
    }
    if !missing.is_empty() {
        s.push_str(&format!("<D:propstat><D:prop>{missing}</D:prop><D:status>HTTP/1.1 404 Not Found</D:status></D:propstat>"));
    }
    s.push_str("</D:response>\n");
    s
}

async fn propfind(srv: &Shared, user: &User, req: &Req, r: Res) -> Result<Resp> {
    let body = xml::parse(&req.body);
    let wanted = requested(body.as_ref());
    let depth1 = req.header("depth").map(|d| d != "0").unwrap_or(true);
    let me = user.email.clone();
    let mut out = String::from(xml::MULTISTATUS_OPEN);
    let self_href = match &r {
        Res::Root => req.path.clone(),
        Res::Principal => principal_href(&me),
        Res::Home => home_href(&me),
        Res::Cal(c) => cal_href(&me, &c.slug),
        Res::Obj(c, o) => format!("{}{}", cal_href(&me, &c.slug), enc_path(&o.name)),
    };
    out.push_str(&response_xml(&self_href, user, &r, &wanted));
    if depth1 {
        let uid = user.id;
        match &r {
            Res::Root => {
                out.push_str(&response_xml(&principal_href(&me), user, &Res::Principal, &wanted));
                out.push_str(&response_xml(&home_href(&me), user, &Res::Home, &wanted));
            }
            Res::Home => {
                let cals = srv.store.call(move |c| list_calendars(c, uid)).await?;
                for cal in cals {
                    let href = cal_href(&me, &cal.slug);
                    out.push_str(&response_xml(&href, user, &Res::Cal(cal), &wanted));
                }
            }
            Res::Cal(cal) => {
                let id = cal.id;
                let objs = srv.store.call(move |c| list_objects(c, id)).await?;
                for o in objs {
                    let href = format!("{}{}", cal_href(&me, &cal.slug), enc_path(&o.name));
                    out.push_str(&response_xml(&href, user, &Res::Obj(cal.clone(), o), &wanted));
                }
            }
            _ => {}
        }
    }
    out.push_str("</D:multistatus>\n");
    Ok(crate::http::xml_resp(StatusCode::MULTI_STATUS, out))
}

async fn report(srv: &Shared, user: &User, req: &Req, cal: Calendar) -> Result<Resp> {
    let Some(body) = xml::parse(&req.body) else { return Ok(status(StatusCode::BAD_REQUEST)) };
    let wanted = requested(Some(&body)).or_else(|| Some(vec![(DAV.into(), "getetag".into())]));
    let id = cal.id;
    let objs = srv.store.call(move |c| list_objects(c, id)).await?;
    let base = cal_href(&user.email, &cal.slug);
    let mut out = String::from(xml::MULTISTATUS_OPEN);
    if body.is(CALDAV, "calendar-multiget") {
        let mut hrefs = Vec::new();
        body.find_all(DAV, "href", &mut hrefs);
        for h in hrefs {
            let decoded = crate::http::pct_decode(h.text.trim());
            let name = decoded.rsplit('/').next().unwrap_or("").to_string();
            match objs.iter().find(|o| o.name == name) {
                Some(o) => out.push_str(&response_xml(&format!("{base}{}", enc_path(&o.name)), user, &Res::Obj(cal.clone(), o.clone()), &wanted)),
                None => out.push_str(&format!(
                    "<D:response><D:href>{}</D:href><D:status>HTTP/1.1 404 Not Found</D:status></D:response>\n",
                    esc(h.text.trim())
                )),
            }
        }
    } else if body.is(CALDAV, "calendar-query") {
        let mut comps = Vec::new();
        body.find_all(CALDAV, "comp-filter", &mut comps);
        let comp: Option<String> = comps.iter().filter_map(|c| c.attr("name")).find(|n| !n.eq_ignore_ascii_case("VCALENDAR")).map(|s| s.to_ascii_uppercase());
        let mut ranges = Vec::new();
        body.find_all(CALDAV, "time-range", &mut ranges);
        let range = ranges.first().map(|r| (r.attr("start").and_then(ical_time), r.attr("end").and_then(ical_time)));
        for o in &objs {
            if let Some(c) = &comp {
                if o.component.as_deref().map(|x| x != c).unwrap_or(false) {
                    continue;
                }
            }
            if let Some((start, end)) = range {
                if !o.recurring {
                    if let (Some(s), Some(e)) = (o.dtstart, o.dtend) {
                        let slack = 86400;
                        if end.map(|end| s > end + slack).unwrap_or(false) || start.map(|st| e < st - slack).unwrap_or(false) {
                            continue;
                        }
                    }
                }
            }
            out.push_str(&response_xml(&format!("{base}{}", enc_path(&o.name)), user, &Res::Obj(cal.clone(), o.clone()), &wanted));
        }
    } else {
        return Ok(crate::http::text(StatusCode::FORBIDDEN, "unsupported report"));
    }
    out.push_str("</D:multistatus>\n");
    Ok(crate::http::xml_resp(StatusCode::MULTI_STATUS, out))
}

async fn proppatch(srv: &Shared, req: &Req, cal: Calendar) -> Result<Resp> {
    let body = xml::parse(&req.body);
    let mut props: Vec<(String, String, String)> = Vec::new();
    if let Some(b) = &body {
        for set in b.children.iter().filter(|c| c.is(DAV, "set") || c.is(DAV, "remove")) {
            if let Some(p) = set.child(DAV, "prop") {
                for c in &p.children {
                    props.push((c.ns.clone(), c.name.clone(), if set.name == "set" { c.text.clone() } else { String::new() }));
                }
            }
        }
    }
    if cal.is_owner {
        let id = cal.id;
        let upd = props.clone();
        srv.store
            .call(move |c| {
                for (ns, n, v) in &upd {
                    match (ns.as_str(), n.as_str()) {
                        (DAV, "displayname") if !v.trim().is_empty() => {
                            c.execute("UPDATE calendars SET name = ?2 WHERE id = ?1", params![id, v.trim()])?;
                        }
                        (APPLE, "calendar-color") => {
                            c.execute("UPDATE calendars SET color = ?2 WHERE id = ?1", params![id, v.trim()])?;
                        }
                        (CALDAV, "calendar-description") => {
                            c.execute("UPDATE calendars SET description = ?2 WHERE id = ?1", params![id, v.trim()])?;
                        }
                        _ => {}
                    }
                }
                bump(c, id)
            })
            .await?;
    }
    // Accept everything: clients store cosmetic properties (order, colour) and a failed
    // PROPPATCH can block calendar creation in some of them.
    let mut ok = String::new();
    for (ns, n, _) in &props {
        ok.push_str(&format!("<{}/>", qname(ns, n).0));
    }
    let out = format!(
        "{}<D:response><D:href>{}</D:href><D:propstat><D:prop>{ok}</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>",
        xml::MULTISTATUS_OPEN,
        esc(&req.path)
    );
    Ok(crate::http::xml_resp(StatusCode::MULTI_STATUS, out))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn meta() {
        let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:abc\r\nDTSTART;TZID=Europe/London:20261120T090000\r\nDTEND:20261120T100000Z\r\nSUMMARY:Stand\r\n up\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let m = ics_meta(ics).unwrap();
        assert_eq!(m.component, "VEVENT");
        assert_eq!(m.uid.as_deref(), Some("abc"));
        assert_eq!(m.dtstart, ical_time("20261120T090000"));
        assert!(!m.recurring);
        assert!(ics_meta("hello").is_err());
    }
}
