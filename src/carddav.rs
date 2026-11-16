//! CardDAV (RFC 6352) contacts, with address-book sharing and a read-only organisation
//! directory. Works with iPhone/macOS Contacts, DAVx5 (Android), Thunderbird and Mailwright.
//!
//! URL layout (scoped to the signed-in user):
//!   /dav/addressbooks/{email}/                 address-book home
//!   /dav/addressbooks/{email}/{slug}/          own address book
//!   /dav/addressbooks/{email}/shared-{id}/     address book shared with this user
//!   /dav/addressbooks/{email}/directory/       everyone in the organisation (read only)
//!   /dav/addressbooks/{email}/{slug}/{name}.vcf

use crate::http::{enc_path, Req, Resp};
use crate::server::Shared;
use crate::store::{self, now, User};
use crate::xml::{self, esc, qname, Elem, CARDDAV, CS, DAV};
use anyhow::{bail, Result};
use hyper::StatusCode;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS addressbooks(
    id INTEGER PRIMARY KEY,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    ctag INTEGER NOT NULL DEFAULT 1,
    UNIQUE(owner_id, slug)
);
CREATE TABLE IF NOT EXISTS contacts(
    id INTEGER PRIMARY KEY,
    addressbook_id INTEGER NOT NULL REFERENCES addressbooks(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    etag TEXT NOT NULL,
    data TEXT NOT NULL,
    uid TEXT,
    fn TEXT,
    emails TEXT,
    modified INTEGER NOT NULL,
    UNIQUE(addressbook_id, name)
);
CREATE TABLE IF NOT EXISTS addressbook_shares(
    addressbook_id INTEGER NOT NULL REFERENCES addressbooks(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    write INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(addressbook_id, user_id)
);
"#;

pub const DIRECTORY: &str = "directory";

// ------------------------------------------------------------------ storage

#[derive(Debug, Clone, Serialize)]
pub struct Book {
    #[serde(skip)]
    pub id: i64,
    pub owner: String,
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    #[serde(skip)]
    pub ctag: String,
    pub write: bool,
    pub is_owner: bool,
    /// The generated organisation directory.
    pub directory: bool,
}

#[derive(Debug, Clone)]
pub struct Card {
    pub name: String,
    pub etag: String,
    pub data: String,
}

const BOOK_COLS: &str = "b.id, b.owner_id, u.email, b.slug, b.name, b.description, b.ctag";

fn row_book(r: &rusqlite::Row, viewer: i64, write: Option<bool>) -> rusqlite::Result<Book> {
    let id: i64 = r.get(0)?;
    let owner_id: i64 = r.get(1)?;
    let is_owner = owner_id == viewer;
    let slug: String = r.get(3)?;
    Ok(Book {
        id,
        owner: r.get(2)?,
        slug: if is_owner { slug } else { format!("shared-{id}") },
        name: r.get(4)?,
        description: r.get(5)?,
        ctag: r.get::<_, i64>(6)?.to_string(),
        write: is_owner || write.unwrap_or(false),
        is_owner,
        directory: false,
    })
}

pub fn ensure_default(c: &Connection, user_id: i64) -> Result<()> {
    let n: i64 = c.query_row("SELECT COUNT(*) FROM addressbooks WHERE owner_id = ?1", [user_id], |r| r.get(0))?;
    if n == 0 {
        c.execute("INSERT OR IGNORE INTO addressbooks(owner_id, slug, name) VALUES(?1, 'contacts', 'Contacts')", [user_id])?;
    }
    Ok(())
}

/// Users listed in this user's organisation directory: everyone with an address in the
/// same domain (or an alias of it), unless the directory is turned off.
fn directory_members(c: &Connection, user: &User, scope: &str) -> Result<Vec<(i64, String, Option<String>, Vec<String>)>> {
    if scope == "off" {
        return Ok(vec![]);
    }
    let dom = user.email.rsplit_once('@').map(|x| x.1.to_string()).unwrap_or_default();
    let mut st = c.prepare("SELECT id, email, display_name FROM users WHERE enabled = 1 ORDER BY email")?;
    let users = st
        .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    let mut out = Vec::new();
    for (id, email, name) in users {
        if scope != "all" && email.rsplit_once('@').map(|x| x.1) != Some(dom.as_str()) {
            continue;
        }
        let mut st = c.prepare("SELECT source FROM aliases WHERE target = ?1 ORDER BY source")?;
        let aliases = st
            .query_map([&email], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|a| !a.starts_with('@') && *a != email)
            .collect();
        out.push((id, email, name, aliases));
    }
    Ok(out)
}

fn directory_cards(c: &Connection, user: &User, scope: &str) -> Result<Vec<Card>> {
    Ok(directory_members(c, user, scope)?
        .into_iter()
        .map(|(id, email, name, aliases)| {
            let display = name.clone().unwrap_or_else(|| email.split('@').next().unwrap_or(&email).to_string());
            let mut v = format!(
                "BEGIN:VCARD\r\nVERSION:3.0\r\nPRODID:-//Postwright//Directory//EN\r\nUID:postwright-directory-{id}\r\nFN:{}\r\n",
                vesc(&display)
            );
            let (first, last) = match display.rsplit_once(' ') {
                Some((f, l)) if name.is_some() => (f.to_string(), l.to_string()),
                _ => (display.clone(), String::new()),
            };
            v.push_str(&format!("N:{};{};;;\r\n", vesc(&last), vesc(&first)));
            v.push_str(&format!("EMAIL;TYPE=INTERNET,WORK,PREF:{email}\r\n"));
            for a in aliases {
                v.push_str(&format!("EMAIL;TYPE=INTERNET,WORK:{a}\r\n"));
            }
            v.push_str("END:VCARD\r\n");
            Card { name: format!("{id}.vcf"), etag: etag_of(&v), data: v }
        })
        .collect())
}

fn directory_book(c: &Connection, user: &User, scope: &str) -> Result<Option<Book>> {
    if scope == "off" {
        return Ok(None);
    }
    let cards = directory_cards(c, user, scope)?;
    let mut h = Sha256::new();
    for card in &cards {
        h.update(card.etag.as_bytes());
    }
    Ok(Some(Book {
        id: 0,
        owner: user.email.clone(),
        slug: DIRECTORY.into(),
        name: "Directory".into(),
        description: Some("Everyone in your organisation".into()),
        ctag: hex::encode(&h.finalize()[..8]),
        write: false,
        is_owner: false,
        directory: true,
    }))
}

pub fn list_books(c: &Connection, user: &User, scope: &str) -> Result<Vec<Book>> {
    ensure_default(c, user.id)?;
    let mut out = Vec::new();
    let mut st = c.prepare(&format!("SELECT {BOOK_COLS} FROM addressbooks b JOIN users u ON u.id = b.owner_id WHERE b.owner_id = ?1 ORDER BY b.name"))?;
    out.extend(st.query_map([user.id], |r| row_book(r, user.id, None))?.collect::<Result<Vec<_>, _>>()?);
    let mut st = c.prepare(&format!(
        "SELECT {BOOK_COLS}, s.write FROM addressbooks b JOIN users u ON u.id = b.owner_id
         JOIN addressbook_shares s ON s.addressbook_id = b.id WHERE s.user_id = ?1 ORDER BY b.name"
    ))?;
    out.extend(
        st.query_map([user.id], |r| {
            let w: i64 = r.get(7)?;
            row_book(r, user.id, Some(w != 0))
        })?
        .collect::<Result<Vec<_>, _>>()?,
    );
    out.extend(directory_book(c, user, scope)?);
    Ok(out)
}

pub fn resolve(c: &Connection, user: &User, slug: &str, scope: &str) -> Result<Option<Book>> {
    if slug == DIRECTORY {
        return directory_book(c, user, scope);
    }
    if let Some(id) = slug.strip_prefix("shared-").and_then(|s| s.parse::<i64>().ok()) {
        return Ok(c
            .query_row(
                &format!(
                    "SELECT {BOOK_COLS}, s.write FROM addressbooks b JOIN users u ON u.id = b.owner_id
                     JOIN addressbook_shares s ON s.addressbook_id = b.id WHERE s.user_id = ?1 AND b.id = ?2"
                ),
                params![user.id, id],
                |r| {
                    let w: i64 = r.get(7)?;
                    row_book(r, user.id, Some(w != 0))
                },
            )
            .optional()?);
    }
    Ok(c
        .query_row(
            &format!("SELECT {BOOK_COLS} FROM addressbooks b JOIN users u ON u.id = b.owner_id WHERE b.owner_id = ?1 AND b.slug = ?2"),
            params![user.id, slug],
            |r| row_book(r, user.id, None),
        )
        .optional()?)
}

pub fn valid_slug(s: &str) -> bool {
    crate::caldav::valid_slug(s) && s != DIRECTORY
}

pub fn create_book(c: &Connection, user_id: i64, slug: &str, name: &str) -> Result<()> {
    if !valid_slug(slug) {
        bail!("invalid address book id");
    }
    c.execute(
        "INSERT INTO addressbooks(owner_id, slug, name) VALUES(?1, ?2, ?3)",
        params![user_id, slug, if name.trim().is_empty() { slug } else { name.trim() }],
    )?;
    Ok(())
}

/// Unique slug from a display name.
pub fn slug_for(c: &Connection, user: &User, name: &str) -> Result<String> {
    let mut base: String = name
        .to_ascii_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    if base.is_empty() || base.starts_with("shared") || base == DIRECTORY {
        base = "contacts".into();
    }
    base.truncate(60);
    let mut slug = base.clone();
    let mut n = 2;
    while resolve(c, user, &slug, "off")?.is_some() {
        slug = format!("{base}-{n}");
        n += 1;
    }
    Ok(slug)
}

/// Find or create an address book by display name (used by migrations).
pub fn book_named(c: &Connection, user: &User, name: &str) -> Result<i64> {
    ensure_default(c, user.id)?;
    if let Some(id) = c
        .query_row("SELECT id FROM addressbooks WHERE owner_id = ?1 AND name = ?2", params![user.id, name], |r| r.get(0))
        .optional()?
    {
        return Ok(id);
    }
    let slug = slug_for(c, user, name)?;
    create_book(c, user.id, &slug, name)?;
    Ok(c.query_row("SELECT id FROM addressbooks WHERE owner_id = ?1 AND slug = ?2", params![user.id, slug], |r| r.get(0))?)
}

pub fn share(c: &Connection, book_id: i64, with: &str, write: bool) -> Result<()> {
    let user = store::find_user(c, with)?.ok_or_else(|| anyhow::anyhow!("no such user {with}"))?;
    let owner: i64 = c.query_row("SELECT owner_id FROM addressbooks WHERE id = ?1", [book_id], |r| r.get(0))?;
    if owner == user.id {
        bail!("cannot share an address book with its owner");
    }
    c.execute(
        "INSERT INTO addressbook_shares(addressbook_id, user_id, write) VALUES(?1, ?2, ?3)
         ON CONFLICT(addressbook_id, user_id) DO UPDATE SET write = ?3",
        params![book_id, user.id, write as i64],
    )?;
    Ok(())
}

pub fn unshare(c: &Connection, book_id: i64, with: &str) -> Result<bool> {
    let Some(user) = store::find_user(c, with)? else { return Ok(false) };
    Ok(c.execute("DELETE FROM addressbook_shares WHERE addressbook_id = ?1 AND user_id = ?2", params![book_id, user.id])? > 0)
}

pub fn shares_of(c: &Connection, book_id: i64) -> Result<Vec<(String, bool)>> {
    let mut st = c.prepare(
        "SELECT u.email, s.write FROM addressbook_shares s JOIN users u ON u.id = s.user_id WHERE s.addressbook_id = ?1 ORDER BY u.email",
    )?;
    let v = st.query_map([book_id], |r| Ok((r.get(0)?, r.get::<_, i64>(1)? != 0)))?.collect::<Result<Vec<_>, _>>()?;
    Ok(v)
}

pub fn count(c: &Connection, book_id: i64) -> Result<i64> {
    Ok(c.query_row("SELECT COUNT(*) FROM contacts WHERE addressbook_id = ?1", [book_id], |r| r.get(0))?)
}

fn list_cards(c: &Connection, user: &User, book: &Book, scope: &str) -> Result<Vec<Card>> {
    if book.directory {
        return directory_cards(c, user, scope);
    }
    let mut st = c.prepare("SELECT name, etag, data FROM contacts WHERE addressbook_id = ?1 ORDER BY name")?;
    let v = st.query_map([book.id], |r| Ok(Card { name: r.get(0)?, etag: r.get(1)?, data: r.get(2)? }))?.collect::<Result<Vec<_>, _>>()?;
    Ok(v)
}

fn get_card(c: &Connection, user: &User, book: &Book, name: &str, scope: &str) -> Result<Option<Card>> {
    if book.directory {
        return Ok(directory_cards(c, user, scope)?.into_iter().find(|x| x.name == name));
    }
    Ok(c
        .query_row("SELECT name, etag, data FROM contacts WHERE addressbook_id = ?1 AND name = ?2", params![book.id, name], |r| {
            Ok(Card { name: r.get(0)?, etag: r.get(1)?, data: r.get(2)? })
        })
        .optional()?)
}

fn bump(c: &Connection, book_id: i64) -> Result<()> {
    c.execute("UPDATE addressbooks SET ctag = ctag + 1 WHERE id = ?1", [book_id])?;
    Ok(())
}

/// Store a vCard (insert or replace by resource name). Returns the new ETag.
pub fn put_card(c: &Connection, book_id: i64, name: &str, data: &str) -> Result<String> {
    let m = vcard_meta(data)?;
    let etag = etag_of(data);
    c.execute(
        "INSERT INTO contacts(addressbook_id, name, etag, data, uid, fn, emails, modified) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(addressbook_id, name) DO UPDATE SET etag = ?3, data = ?4, uid = ?5, fn = ?6, emails = ?7, modified = ?8",
        params![book_id, name, etag, data, m.uid, m.full_name, m.emails.join(","), now()],
    )?;
    bump(c, book_id)?;
    Ok(etag)
}

/// Store a vCard from an import, replacing any card with the same UID. Returns false
/// if it was unchanged.
pub fn import_card(c: &Connection, book_id: i64, data: &str) -> Result<bool> {
    let m = vcard_meta(data)?;
    let uid = m.uid.clone().unwrap_or_else(|| hex::encode(&Sha256::digest(data.as_bytes())[..12]));
    let existing: Option<(String, String)> = c
        .query_row("SELECT name, data FROM contacts WHERE addressbook_id = ?1 AND uid = ?2", params![book_id, uid], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?;
    let data = if m.uid.is_none() { add_uid(data, &uid) } else { data.to_string() };
    match existing {
        Some((_, d)) if d == data => Ok(false),
        Some((name, _)) => {
            put_card(c, book_id, &name, &data)?;
            Ok(true)
        }
        None => {
            let name = format!("{}.vcf", safe_name(&uid));
            put_card(c, book_id, &name, &data)?;
            Ok(true)
        }
    }
}

fn safe_name(uid: &str) -> String {
    let s: String = uid.chars().filter(|c| c.is_ascii_alphanumeric() || "-_.".contains(*c)).take(120).collect();
    if s.is_empty() {
        hex::encode(&Sha256::digest(uid.as_bytes())[..12])
    } else {
        s
    }
}

fn add_uid(data: &str, uid: &str) -> String {
    let mut out = String::new();
    let mut done = false;
    for l in data.split_inclusive('\n') {
        out.push_str(l);
        if !done && l.trim_end().eq_ignore_ascii_case("BEGIN:VCARD") {
            out.push_str(&format!("UID:{uid}\r\n"));
            done = true;
        }
    }
    out
}

// -------------------------------------------------------------------- vCard

pub fn vesc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\n', "\\n").replace('\r', "").replace(',', "\\,").replace(';', "\\;")
}

/// Unfolded content lines.
pub fn lines(data: &str) -> Vec<String> {
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

pub struct VcardMeta {
    pub uid: Option<String>,
    pub full_name: Option<String>,
    pub emails: Vec<String>,
}

pub fn vcard_meta(data: &str) -> Result<VcardMeta> {
    let ls = lines(data);
    if !ls.iter().find(|l| !l.trim().is_empty()).map(|l| l.trim().eq_ignore_ascii_case("BEGIN:VCARD")).unwrap_or(false) {
        bail!("not a vCard");
    }
    let mut m = VcardMeta { uid: None, full_name: None, emails: vec![] };
    for l in &ls {
        let Some((key, val)) = l.split_once(':') else { continue };
        let name = key.split(';').next().unwrap_or("");
        let name = name.rsplit('.').next().unwrap_or(name).to_ascii_uppercase(); // item1.EMAIL
        match name.as_str() {
            "UID" => m.uid = Some(val.trim().to_string()).filter(|u| !u.is_empty()),
            "FN" => m.full_name = Some(val.trim().replace("\\,", ",").replace("\\;", ";")),
            "EMAIL" => m.emails.push(val.trim().to_ascii_lowercase()),
            _ => {}
        }
    }
    Ok(m)
}

/// Split a file holding several vCards into individual cards.
pub fn split_vcards(data: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut inside = false;
    for raw in data.split('\n') {
        let l = raw.strip_suffix('\r').unwrap_or(raw);
        if l.trim().eq_ignore_ascii_case("BEGIN:VCARD") {
            inside = true;
            cur.clear();
        }
        if inside {
            cur.push_str(l);
            cur.push_str("\r\n");
        }
        if inside && l.trim().eq_ignore_ascii_case("END:VCARD") {
            inside = false;
            out.push(std::mem::take(&mut cur));
        }
    }
    out
}

fn etag_of(data: &str) -> String {
    format!("\"{}\"", &hex::encode(Sha256::digest(data.as_bytes()))[..32])
}

// ------------------------------------------------------------------ routing

enum Res {
    Home,
    Book(Book),
    Card(Book, Card),
}

fn status(code: StatusCode) -> Resp {
    crate::http::text(code, "")
}

pub fn home_href(email: &str) -> String {
    format!("/dav/addressbooks/{}/", enc_path(email))
}
fn book_href(email: &str, slug: &str) -> String {
    format!("/dav/addressbooks/{}/{}/", enc_path(email), enc_path(slug))
}
fn principal_href(email: &str) -> String {
    format!("/dav/principals/{}/", enc_path(email))
}

pub async fn handle(srv: Shared, user: User, req: Req) -> Resp {
    match handle_inner(srv, user, req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("CardDAV error: {e:#}");
            status(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn handle_inner(srv: Shared, user: User, req: Req) -> Result<Resp> {
    let segs: Vec<String> = req.path.split('/').filter(|s| !s.is_empty()).map(crate::http::pct_decode).collect();
    let segs: Vec<&str> = segs.iter().map(|s| s.as_str()).collect();
    if req.method == "OPTIONS" {
        return Ok(crate::http::builder(StatusCode::OK)
            .header("DAV", "1, 3, access-control, addressbook, extended-mkcol")
            .header("Allow", "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, REPORT, MKCOL")
            .body(Default::default())
            .unwrap());
    }
    match segs.as_slice() {
        ["dav", "addressbooks"] => {}
        ["dav", "addressbooks", email, ..] if email.eq_ignore_ascii_case(&user.email) => {}
        ["dav", "addressbooks", ..] => return Ok(status(StatusCode::FORBIDDEN)),
        _ => return Ok(status(StatusCode::NOT_FOUND)),
    }
    let scope = srv.cfg.contacts.directory.clone();
    let res = {
        let segs: Vec<String> = segs.iter().map(|s| s.to_string()).collect();
        let (u, sc) = (user.clone(), scope.clone());
        srv.store
            .call(move |c| {
                let s: Vec<&str> = segs.iter().map(|x| x.as_str()).collect();
                Ok(match s.as_slice() {
                    ["dav", "addressbooks"] | ["dav", "addressbooks", _] => Some(Res::Home),
                    ["dav", "addressbooks", _, slug] => resolve(c, &u, slug, &sc)?.map(Res::Book),
                    ["dav", "addressbooks", _, slug, name] => match resolve(c, &u, slug, &sc)? {
                        Some(b) => get_card(c, &u, &b, name, &sc)?.map(|x| Res::Card(b, x)),
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
        ("REPORT", Some(Res::Book(b))) => report(&srv, &user, &req, b).await,
        ("REPORT", Some(_)) => Ok(crate::http::xml_resp(StatusCode::MULTI_STATUS, format!("{}</D:multistatus>", xml::MULTISTATUS_OPEN))),
        ("GET" | "HEAD", Some(Res::Card(_, x))) => Ok(crate::http::builder(StatusCode::OK)
            .header("Content-Type", "text/vcard; charset=utf-8")
            .header("ETag", x.etag.clone())
            .body(if m == "HEAD" { Default::default() } else { x.data.into_bytes().into() })
            .unwrap()),
        ("GET" | "HEAD", Some(Res::Book(b))) => {
            // Whole address book as one .vcf, handy for backups.
            let (u, sc) = (user.clone(), scope.clone());
            let bb = b.clone();
            let cards = srv.store.call(move |c| list_cards(c, &u, &bb, &sc)).await?;
            let all: String = cards.into_iter().map(|x| x.data).collect();
            Ok(crate::http::builder(StatusCode::OK)
                .header("Content-Type", "text/vcard; charset=utf-8")
                .header("Content-Disposition", format!("attachment; filename=\"{}.vcf\"", b.slug))
                .body(all.into_bytes().into())
                .unwrap())
        }
        ("GET" | "HEAD", None) => Ok(status(StatusCode::NOT_FOUND)),
        ("GET" | "HEAD", Some(_)) => Ok(crate::http::text(StatusCode::OK, "Postwright CardDAV. Point your contacts app at this server.")),
        ("PUT", res) => put(&srv, &user, &req, &segs, res).await,
        ("DELETE", Some(Res::Card(b, x))) => {
            if !b.write {
                return Ok(status(StatusCode::FORBIDDEN));
            }
            if let Some(im) = req.header("if-match") {
                if im != "*" && im != x.etag {
                    return Ok(status(StatusCode::PRECONDITION_FAILED));
                }
            }
            let (id, name) = (b.id, x.name.clone());
            srv.store
                .call(move |c| {
                    c.execute("DELETE FROM contacts WHERE addressbook_id = ?1 AND name = ?2", params![id, name])?;
                    bump(c, id)
                })
                .await?;
            Ok(status(StatusCode::NO_CONTENT))
        }
        ("DELETE", Some(Res::Book(b))) => {
            if b.directory {
                return Ok(status(StatusCode::FORBIDDEN));
            }
            let (id, email) = (b.id, user.email.clone());
            if b.is_owner {
                srv.store.call(move |c| Ok(c.execute("DELETE FROM addressbooks WHERE id = ?1", [id])?)).await?;
            } else {
                srv.store.call(move |c| unshare(c, id, &email)).await?;
            }
            Ok(status(StatusCode::NO_CONTENT))
        }
        ("DELETE", _) => Ok(status(StatusCode::NOT_FOUND)),
        ("MKCOL", None) => {
            let ["dav", "addressbooks", _, slug] = segs.as_slice() else { return Ok(status(StatusCode::FORBIDDEN)) };
            if !valid_slug(slug) {
                return Ok(status(StatusCode::FORBIDDEN));
            }
            let mut name = slug.to_string();
            if let Some(b) = xml::parse(&req.body) {
                let mut v = Vec::new();
                b.find_all(DAV, "displayname", &mut v);
                if let Some(d) = v.first() {
                    name = d.text.clone();
                }
            }
            let (slug, uid) = (slug.to_string(), user.id);
            srv.store.call(move |c| create_book(c, uid, &slug, &name)).await?;
            Ok(status(StatusCode::CREATED))
        }
        ("MKCOL", Some(_)) => Ok(status(StatusCode::METHOD_NOT_ALLOWED)),
        ("PROPPATCH", Some(Res::Book(b))) => proppatch(&srv, &req, b).await,
        ("PROPPATCH", Some(_)) => Ok(status(StatusCode::FORBIDDEN)),
        _ => Ok(status(StatusCode::METHOD_NOT_ALLOWED)),
    }
}

async fn put(srv: &Shared, user: &User, req: &Req, segs: &[&str], res: Option<Res>) -> Result<Resp> {
    let ["dav", "addressbooks", _, slug, name] = segs else { return Ok(status(StatusCode::FORBIDDEN)) };
    if name.len() > 255 || name.starts_with('.') {
        return Ok(status(StatusCode::FORBIDDEN));
    }
    let Ok(data) = String::from_utf8(req.body.to_vec()) else {
        return Ok(crate::http::text(StatusCode::UNSUPPORTED_MEDIA_TYPE, "vCard must be UTF-8"));
    };
    if let Err(e) = vcard_meta(&data) {
        return Ok(crate::http::text(StatusCode::UNSUPPORTED_MEDIA_TYPE, &e.to_string()));
    }
    let existing = match &res {
        Some(Res::Card(_, x)) => Some(x.etag.clone()),
        _ => None,
    };
    if req.header("if-none-match").as_deref() == Some("*") && existing.is_some() {
        return Ok(status(StatusCode::PRECONDITION_FAILED));
    }
    if let Some(im) = req.header("if-match") {
        match &existing {
            Some(e) if im == "*" || im == *e => {}
            _ => return Ok(status(StatusCode::PRECONDITION_FAILED)),
        }
    }
    let (u, slug, name, scope) = (user.clone(), slug.to_string(), name.to_string(), srv.cfg.contacts.directory.clone());
    let r = srv
        .store
        .call(move |c| {
            let Some(b) = resolve(c, &u, &slug, &scope)? else { return Ok(None) };
            if !b.write {
                return Ok(Some(Err(StatusCode::FORBIDDEN)));
            }
            Ok(Some(Ok(put_card(c, b.id, &name, &data)?)))
        })
        .await?;
    match r {
        None => Ok(status(StatusCode::CONFLICT)),
        Some(Err(code)) => Ok(status(code)),
        Some(Ok(etag)) => Ok(crate::http::builder(if existing.is_some() { StatusCode::NO_CONTENT } else { StatusCode::CREATED })
            .header("ETag", etag)
            .body(Default::default())
            .unwrap()),
    }
}

fn requested(body: Option<&Elem>) -> Option<Vec<(String, String)>> {
    let b = body?;
    if b.child(DAV, "allprop").is_some() {
        return None;
    }
    let p = b.child(DAV, "prop")?;
    Some(p.children.iter().map(|c| (c.ns.clone(), c.name.clone())).collect())
}

fn privileges(write: bool) -> String {
    let mut s = String::from("<D:privilege><D:read/></D:privilege><D:privilege><D:read-current-user-privilege-set/></D:privilege>");
    if write {
        s.push_str("<D:privilege><D:write/></D:privilege><D:privilege><D:write-content/></D:privilege><D:privilege><D:write-properties/></D:privilege><D:privilege><D:bind/></D:privilege><D:privilege><D:unbind/></D:privilege>");
    }
    s
}

fn known_props(user: &User, r: &Res, with_data: bool) -> Vec<(&'static str, &'static str, String)> {
    let me = &user.email;
    let mut v: Vec<(&str, &str, String)> = vec![
        (DAV, "current-user-principal", format!("<D:href>{}</D:href>", principal_href(me))),
        (DAV, "principal-collection-set", "<D:href>/dav/principals/</D:href>".into()),
    ];
    match r {
        Res::Home => {
            v.push((DAV, "resourcetype", "<D:collection/>".into()));
            v.push((DAV, "displayname", esc(me)));
            v.push((DAV, "owner", format!("<D:href>{}</D:href>", principal_href(me))));
            v.push((CARDDAV, "addressbook-home-set", format!("<D:href>{}</D:href>", home_href(me))));
            v.push((DAV, "current-user-privilege-set", privileges(true)));
        }
        Res::Book(b) => {
            v.push((DAV, "resourcetype", "<D:collection/><R:addressbook/>".into()));
            let name = if b.is_owner || b.directory { b.name.clone() } else { format!("{} ({})", b.name, b.owner) };
            v.push((DAV, "displayname", esc(&name)));
            v.push((CS, "getctag", format!("\"{}\"", b.ctag)));
            v.push((DAV, "getetag", format!("\"ctag-{}\"", b.ctag)));
            v.push((DAV, "sync-token", format!("http://postwright/ns/sync/{}", b.ctag)));
            if let Some(d) = &b.description {
                v.push((CARDDAV, "addressbook-description", esc(d)));
            }
            v.push((
                DAV,
                "supported-report-set",
                "<D:supported-report><D:report><R:addressbook-multiget/></D:report></D:supported-report><D:supported-report><D:report><R:addressbook-query/></D:report></D:supported-report>".into(),
            ));
            v.push((CARDDAV, "supported-address-data", "<R:address-data-type content-type=\"text/vcard\" version=\"3.0\"/><R:address-data-type content-type=\"text/vcard\" version=\"4.0\"/>".into()));
            v.push((CARDDAV, "max-resource-size", "1048576".into()));
            v.push((DAV, "current-user-privilege-set", privileges(b.write)));
            v.push((DAV, "owner", format!("<D:href>{}</D:href>", principal_href(&b.owner))));
        }
        Res::Card(b, x) => {
            v.push((DAV, "resourcetype", String::new()));
            v.push((DAV, "getetag", esc(&x.etag)));
            v.push((DAV, "getcontenttype", "text/vcard; charset=utf-8".into()));
            v.push((DAV, "getcontentlength", x.data.len().to_string()));
            v.push((DAV, "current-user-privilege-set", privileges(b.write)));
            if with_data {
                v.push((CARDDAV, "address-data", esc(&x.data)));
            }
        }
    }
    v
}

fn response_xml(href: &str, user: &User, r: &Res, req: &Option<Vec<(String, String)>>) -> String {
    let wants_data = req.as_ref().map(|v| v.iter().any(|(ns, n)| ns == CARDDAV && n == "address-data")).unwrap_or(false);
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
    let scope = srv.cfg.contacts.directory.clone();
    let mut out = String::from(xml::MULTISTATUS_OPEN);
    let self_href = match &r {
        Res::Home => home_href(&me),
        Res::Book(b) => book_href(&me, &b.slug),
        Res::Card(b, x) => format!("{}{}", book_href(&me, &b.slug), enc_path(&x.name)),
    };
    out.push_str(&response_xml(&self_href, user, &r, &wanted));
    if depth1 {
        match &r {
            Res::Home => {
                let u = user.clone();
                let books = srv.store.call(move |c| list_books(c, &u, &scope)).await?;
                for b in books {
                    let href = book_href(&me, &b.slug);
                    out.push_str(&response_xml(&href, user, &Res::Book(b), &wanted));
                }
            }
            Res::Book(b) => {
                let (u, bb) = (user.clone(), b.clone());
                let cards = srv.store.call(move |c| list_cards(c, &u, &bb, &scope)).await?;
                for x in cards {
                    let href = format!("{}{}", book_href(&me, &b.slug), enc_path(&x.name));
                    out.push_str(&response_xml(&href, user, &Res::Card(b.clone(), x), &wanted));
                }
            }
            _ => {}
        }
    }
    out.push_str("</D:multistatus>\n");
    Ok(crate::http::xml_resp(StatusCode::MULTI_STATUS, out))
}

/// Does a card match an addressbook-query filter? Supports prop-filter with text-match
/// (contains / equals / starts-with / ends-with), anyof/allof.
fn matches(card: &str, filter: &Elem) -> bool {
    let props: Vec<&Elem> = filter.children.iter().filter(|c| c.is(CARDDAV, "prop-filter")).collect();
    if props.is_empty() {
        return true;
    }
    let all = filter.attr("test").map(|t| t.eq_ignore_ascii_case("allof")).unwrap_or(false);
    let ls = lines(card);
    let test = |pf: &Elem| -> bool {
        let pname = pf.attr("name").unwrap_or("").to_ascii_uppercase();
        let values: Vec<String> = ls
            .iter()
            .filter_map(|l| {
                let (k, v) = l.split_once(':')?;
                let n = k.split(';').next()?;
                let n = n.rsplit('.').next().unwrap_or(n);
                (n.eq_ignore_ascii_case(&pname)).then(|| v.to_lowercase())
            })
            .collect();
        if pf.child(CARDDAV, "is-not-defined").is_some() {
            return values.is_empty();
        }
        let Some(tm) = pf.child(CARDDAV, "text-match") else { return !values.is_empty() };
        let needle = tm.text.to_lowercase();
        let negate = tm.attr("negate-condition").map(|v| v == "yes").unwrap_or(false);
        let hit = values.iter().any(|v| match tm.attr("match-type").unwrap_or("contains") {
            "equals" => *v == needle,
            "starts-with" => v.starts_with(&needle),
            "ends-with" => v.ends_with(&needle),
            _ => v.contains(&needle),
        });
        hit != negate
    };
    if all {
        props.iter().all(|p| test(p))
    } else {
        props.iter().any(|p| test(p))
    }
}

async fn report(srv: &Shared, user: &User, req: &Req, b: Book) -> Result<Resp> {
    let Some(body) = xml::parse(&req.body) else { return Ok(status(StatusCode::BAD_REQUEST)) };
    let wanted = requested(Some(&body)).or_else(|| Some(vec![(DAV.into(), "getetag".into())]));
    let (u, bb, scope) = (user.clone(), b.clone(), srv.cfg.contacts.directory.clone());
    let cards = srv.store.call(move |c| list_cards(c, &u, &bb, &scope)).await?;
    let base = book_href(&user.email, &b.slug);
    let mut out = String::from(xml::MULTISTATUS_OPEN);
    if body.is(CARDDAV, "addressbook-multiget") {
        let mut hrefs = Vec::new();
        body.find_all(DAV, "href", &mut hrefs);
        for h in hrefs {
            let decoded = crate::http::pct_decode(h.text.trim());
            let name = decoded.rsplit('/').next().unwrap_or("").to_string();
            match cards.iter().find(|x| x.name == name) {
                Some(x) => out.push_str(&response_xml(&format!("{base}{}", enc_path(&x.name)), user, &Res::Card(b.clone(), x.clone()), &wanted)),
                None => out.push_str(&format!("<D:response><D:href>{}</D:href><D:status>HTTP/1.1 404 Not Found</D:status></D:response>\n", esc(h.text.trim()))),
            }
        }
    } else if body.is(CARDDAV, "addressbook-query") {
        let filter = body.child(CARDDAV, "filter").cloned().unwrap_or_default();
        let limit = body
            .child(CARDDAV, "limit")
            .and_then(|l| l.child(CARDDAV, "nresults"))
            .and_then(|n| n.text.trim().parse::<usize>().ok())
            .unwrap_or(usize::MAX);
        for x in cards.iter().filter(|x| matches(&x.data, &filter)).take(limit) {
            out.push_str(&response_xml(&format!("{base}{}", enc_path(&x.name)), user, &Res::Card(b.clone(), x.clone()), &wanted));
        }
    } else if body.is(DAV, "sync-collection") {
        // No change log is kept: always answer with the full set and the current token.
        for x in &cards {
            out.push_str(&response_xml(&format!("{base}{}", enc_path(&x.name)), user, &Res::Card(b.clone(), x.clone()), &wanted));
        }
        out.push_str(&format!("<D:sync-token>http://postwright/ns/sync/{}</D:sync-token>", b.ctag));
    } else {
        return Ok(crate::http::text(StatusCode::FORBIDDEN, "unsupported report"));
    }
    out.push_str("</D:multistatus>\n");
    Ok(crate::http::xml_resp(StatusCode::MULTI_STATUS, out))
}

async fn proppatch(srv: &Shared, req: &Req, b: Book) -> Result<Resp> {
    let body = xml::parse(&req.body);
    let mut props: Vec<(String, String, String)> = Vec::new();
    if let Some(e) = &body {
        for set in e.children.iter().filter(|c| c.is(DAV, "set") || c.is(DAV, "remove")) {
            if let Some(p) = set.child(DAV, "prop") {
                for c in &p.children {
                    props.push((c.ns.clone(), c.name.clone(), if set.name == "set" { c.text.clone() } else { String::new() }));
                }
            }
        }
    }
    if b.is_owner && !b.directory {
        let (id, upd) = (b.id, props.clone());
        srv.store
            .call(move |c| {
                for (ns, n, v) in &upd {
                    match (ns.as_str(), n.as_str()) {
                        (DAV, "displayname") if !v.trim().is_empty() => {
                            c.execute("UPDATE addressbooks SET name = ?2 WHERE id = ?1", params![id, v.trim()])?;
                        }
                        (CARDDAV, "addressbook-description") => {
                            c.execute("UPDATE addressbooks SET description = ?2 WHERE id = ?1", params![id, v.trim()])?;
                        }
                        _ => {}
                    }
                }
                bump(c, id)
            })
            .await?;
    }
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
    fn meta_and_split() {
        let two = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:a1\r\nFN:Amy Poffles\r\nitem1.EMAIL;TYPE=INTERNET:Amy@Poffles.test\r\nEND:VCARD\r\nBEGIN:VCARD\nVERSION:3.0\nFN:No Uid\nEND:VCARD\n";
        let v = split_vcards(two);
        assert_eq!(v.len(), 2);
        let m = vcard_meta(&v[0]).unwrap();
        assert_eq!(m.uid.as_deref(), Some("a1"));
        assert_eq!(m.full_name.as_deref(), Some("Amy Poffles"));
        assert_eq!(m.emails, vec!["amy@poffles.test"]);
        assert!(vcard_meta(&v[1]).unwrap().uid.is_none());
        assert!(add_uid(&v[1], "x").contains("BEGIN:VCARD\r\nUID:x\r\n"));
        assert!(vcard_meta("BEGIN:VCALENDAR").is_err());
    }

    #[test]
    fn query_filter() {
        let card = "BEGIN:VCARD\r\nFN:Amy Poffles\r\nEMAIL:amy@poffles.test\r\nEND:VCARD\r\n";
        let f = xml::parse(br#"<C:filter xmlns:C="urn:ietf:params:xml:ns:carddav"><C:prop-filter name="EMAIL"><C:text-match match-type="starts-with">AMY</C:text-match></C:prop-filter></C:filter>"#).unwrap();
        assert!(matches(card, &f));
        let f = xml::parse(br#"<C:filter xmlns:C="urn:ietf:params:xml:ns:carddav" test="allof"><C:prop-filter name="FN"><C:text-match>tony</C:text-match></C:prop-filter><C:prop-filter name="EMAIL"/></C:filter>"#).unwrap();
        assert!(!matches(card, &f));
    }
}
