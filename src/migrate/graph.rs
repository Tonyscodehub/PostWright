//! Exchange Online / Microsoft 365 through Microsoft Graph (app-only access).
//!
//! Needs an app registration in Entra ID with these *application* permissions, granted
//! admin consent: User.Read.All, Mail.Read, Calendars.Read, Contacts.Read.

use super::net::{enc, Body, Http};
use super::{ical, map_folder, Discovered, MailboxMap, Source, Special, Target, Tick};
use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use std::collections::HashMap;
use tokio::sync::Mutex;

pub struct Graph {
    http: Http,
    base: String,
    token_url: String,
    client_id: String,
    secret: String,
    token: Mutex<Option<(String, std::time::Instant)>>,
}

impl Graph {
    pub fn new(src: &Source) -> Result<Self> {
        let Source::ExchangeOnline { tenant, client_id, client_secret, graph_url, login_url } = src else { return Err(anyhow!("not an Exchange Online source")) };
        let tenant = tenant.trim();
        if tenant.is_empty() || client_id.trim().is_empty() || client_secret.trim().is_empty() {
            return Err(anyhow!("enter the tenant (e.g. contoso.onmicrosoft.com), application (client) ID and client secret"));
        }
        let login = login_url.clone().unwrap_or_else(|| "https://login.microsoftonline.com".into());
        Ok(Self {
            http: Http::new(),
            base: graph_url.clone().unwrap_or_else(|| "https://graph.microsoft.com/v1.0".into()).trim_end_matches('/').to_string(),
            token_url: format!("{}/{}/oauth2/v2.0/token", login.trim_end_matches('/'), enc(tenant)),
            client_id: client_id.trim().to_string(),
            secret: client_secret.trim().to_string(),
            token: Mutex::new(None),
        })
    }

    async fn token(&self) -> Result<String> {
        let mut t = self.token.lock().await;
        if let Some((tok, exp)) = t.as_ref() {
            if *exp > std::time::Instant::now() {
                return Ok(tok.clone());
            }
        }
        let scope = if self.base.contains("graph.microsoft.com") { "https://graph.microsoft.com/.default".to_string() } else { format!("{}/.default", self.base) };
        let v = self
            .http
            .json(
                "POST",
                &self.token_url,
                vec![],
                Body::Form(vec![
                    ("client_id".into(), self.client_id.clone()),
                    ("client_secret".into(), self.secret.clone()),
                    ("scope".into(), scope),
                    ("grant_type".into(), "client_credentials".into()),
                ]),
            )
            .await
            .context("signing in to Microsoft (check the tenant, client ID and secret)")?;
        let tok = v["access_token"].as_str().ok_or_else(|| anyhow!("no access token in Microsoft's reply"))?.to_string();
        let life = v["expires_in"].as_u64().unwrap_or(3600).saturating_sub(300).max(60);
        *t = Some((tok.clone(), std::time::Instant::now() + std::time::Duration::from_secs(life)));
        Ok(tok)
    }

    async fn headers(&self) -> Result<Vec<(String, String)>> {
        Ok(vec![
            ("Authorization".into(), format!("Bearer {}", self.token().await?)),
            ("Prefer".into(), "IdType=\"ImmutableId\", outlook.timezone=\"UTC\", outlook.body-content-type=\"text\"".into()),
        ])
    }

    fn url(&self, path: &str) -> String {
        if path.starts_with("http") {
            path.to_string()
        } else {
            format!("{}{path}", self.base)
        }
    }

    pub async fn get(&self, path: &str) -> Result<Value> {
        let h = self.headers().await?;
        self.http.json("GET", &self.url(path), h, Body::None).await
    }

    pub async fn bytes(&self, path: &str) -> Result<Vec<u8>> {
        let h = self.headers().await?;
        self.http.send("GET", &self.url(path), h, Body::None).await
    }

    /// Follow @odata.nextLink pages, handing each item to `f`.
    pub async fn each(&self, path: &str, mut f: impl FnMut(Value)) -> Result<()> {
        let mut next = Some(path.to_string());
        while let Some(p) = next.take() {
            let v = self.get(&p).await?;
            for item in v["value"].as_array().cloned().unwrap_or_default() {
                f(item);
            }
            next = v["@odata.nextLink"].as_str().map(String::from);
            if super::cancelled() {
                break;
            }
        }
        Ok(())
    }

    pub async fn all(&self, path: &str) -> Result<Vec<Value>> {
        let mut out = Vec::new();
        self.each(path, |v| out.push(v)).await?;
        Ok(out)
    }
}

pub async fn discover(src: &Source) -> Result<Vec<Discovered>> {
    let g = Graph::new(src)?;
    let users = g.all("/users?$select=id,displayName,mail,userPrincipalName,accountEnabled&$top=999").await.context("listing mailboxes")?;
    let mut out: Vec<Discovered> = users
        .iter()
        .filter_map(|u| {
            let mail = u["mail"].as_str().filter(|m| !m.is_empty())?.to_ascii_lowercase();
            let enabled = u["accountEnabled"].as_bool().unwrap_or(true);
            Some(Discovered {
                source: u["userPrincipalName"].as_str().unwrap_or(&mail).to_string(),
                name: u["displayName"].as_str().map(String::from),
                target: mail,
                kind: if enabled { "user".into() } else { "shared or disabled".into() },
                exists_here: false,
            })
        })
        .collect();
    out.sort_by(|a, b| a.target.cmp(&b.target));
    Ok(out)
}

async fn well_known(g: &Graph, user: &str) -> HashMap<String, Special> {
    let mut m = HashMap::new();
    for (wk, sp) in [
        ("inbox", Some(Special::Inbox)),
        ("sentitems", Some(Special::Sent)),
        ("drafts", Some(Special::Drafts)),
        ("deleteditems", Some(Special::Trash)),
        ("junkemail", Some(Special::Junk)),
        ("archive", Some(Special::Archive)),
        ("outbox", Some(Special::NotMail)),
        ("syncissues", Some(Special::NotMail)),
        ("searchfolders", Some(Special::NotMail)),
        ("recoverableitemsdeletions", Some(Special::NotMail)),
        ("scheduled", None),
        ("conversationhistory", None),
    ] {
        if let Ok(v) = g.get(&format!("/users/{}/mailFolders/{wk}?$select=id", enc(user))).await {
            if let (Some(id), Some(sp)) = (v["id"].as_str(), sp) {
                m.insert(id.to_string(), sp);
            }
        }
    }
    m
}

/// Folder tree: (id, path, special).
async fn folders(g: &Graph, user: &str) -> Result<Vec<(String, Vec<String>, Option<Special>)>> {
    let specials = well_known(g, user).await;
    let mut out = Vec::new();
    let mut stack: Vec<(String, Vec<String>)> = Vec::new();
    for f in g.all(&format!("/users/{}/mailFolders?$top=250&$select=id,displayName,childFolderCount", enc(user))).await? {
        stack.push((f["id"].as_str().unwrap_or("").to_string(), vec![f["displayName"].as_str().unwrap_or("").to_string()]));
    }
    while let Some((id, path)) = stack.pop() {
        let sp = specials.get(&id).copied();
        if sp == Some(Special::NotMail) {
            continue;
        }
        for c in g.all(&format!("/users/{}/mailFolders/{}/childFolders?$top=250&$select=id,displayName", enc(user), enc(&id))).await.unwrap_or_default() {
            let mut p = path.clone();
            p.push(c["displayName"].as_str().unwrap_or("").to_string());
            stack.push((c["id"].as_str().unwrap_or("").to_string(), p));
        }
        out.push((id, path, sp));
    }
    Ok(out)
}

pub async fn migrate(src: &Source, m: &MailboxMap, t: &Target, tick: &Tick) -> Result<()> {
    let g = Graph::new(src)?;
    let user = m.source.trim().to_string();
    if t.opts.mail {
        mail(&g, &user, t, tick).await?;
    }
    if t.opts.calendars && !super::cancelled() {
        if let Err(e) = calendars(&g, &user, t, tick).await {
            tick.error("calendars", &e);
        }
    }
    if t.opts.contacts && !super::cancelled() {
        if let Err(e) = contacts(&g, &user, t, tick).await {
            tick.error("contacts", &e);
        }
    }
    Ok(())
}

async fn mail(g: &Graph, user: &str, t: &Target, tick: &Tick) -> Result<()> {
    tick.step("reading folders");
    let list = folders(g, user).await.map_err(|e| {
        if format!("{e:#}").contains("MailboxNotEnabledForRESTAPI") {
            anyhow!("this account has no Exchange Online mailbox")
        } else {
            e
        }
    })?;
    let since = t.since().and_then(|s| DateTime::from_timestamp(s, 0));
    for (id, path, sp) in list {
        if super::cancelled() {
            break;
        }
        if path.iter().any(|p| t.skip_folder(p)) || t.skip_folder(&path.join("/")) {
            continue;
        }
        let Some(dest) = map_folder(&path, sp) else { continue };
        tick.step(format!("mail: {}", path.join("/")));
        let mut q = format!("/users/{}/mailFolders/{}/messages?$top=100&$select=id,isRead,isDraft,flag,receivedDateTime,createdDateTime", enc(user), enc(&id));
        if let Some(s) = since {
            q.push_str(&format!("&$filter=receivedDateTime%20ge%20{}", s.format("%Y-%m-%dT%H:%M:%SZ")));
        }
        let mut items = Vec::new();
        if let Err(e) = g.each(&q, |v| items.push(v)).await {
            tick.error(&format!("folder {}", path.join("/")), &e);
            continue;
        }
        for msg in items {
            if super::cancelled() {
                break;
            }
            let mid = msg["id"].as_str().unwrap_or("").to_string();
            let key = format!("graph:{user}:{mid}:{dest}");
            if t.seen(&key).await? {
                tick.skipped();
                continue;
            }
            let raw = match g.bytes(&format!("/users/{}/messages/{}/$value", enc(user), enc(&mid))).await {
                Ok(r) => r,
                Err(e) => {
                    tick.error("message", &e);
                    continue;
                }
            };
            let date = msg["receivedDateTime"]
                .as_str()
                .or(msg["createdDateTime"].as_str())
                .and_then(|d| DateTime::parse_from_rfc3339(d).ok())
                .map(|d| d.timestamp())
                .unwrap_or_else(|| Utc::now().timestamp());
            let mut flags = Vec::new();
            if msg["isRead"].as_bool().unwrap_or(false) {
                flags.push("\\Seen".to_string());
            }
            if msg["isDraft"].as_bool().unwrap_or(false) {
                flags.push("\\Draft".to_string());
            }
            if msg["flag"]["flagStatus"].as_str() == Some("flagged") {
                flags.push("\\Flagged".to_string());
            }
            let n = raw.len();
            t.add_message(&key, &dest, raw, date, flags).await?;
            tick.message(n);
        }
    }
    Ok(())
}

async fn calendars(g: &Graph, user: &str, t: &Target, tick: &Tick) -> Result<()> {
    tick.step("calendars");
    let cals = g.all(&format!("/users/{}/calendars?$top=100&$select=id,name,isDefaultCalendar,owner,canEdit", enc(user))).await?;
    let now = Utc::now();
    for cal in cals {
        if super::cancelled() {
            break;
        }
        // Skip other people's calendars that appear in this user's list.
        let owner = cal["owner"]["address"].as_str().unwrap_or("").to_ascii_lowercase();
        if !owner.is_empty() && owner != user.to_ascii_lowercase() && owner != t.user.email {
            continue;
        }
        let default = cal["isDefaultCalendar"].as_bool().unwrap_or(false);
        let name = if default { "Calendar".to_string() } else { cal["name"].as_str().unwrap_or("Calendar").to_string() };
        if t.skip_folder(&name) {
            continue;
        }
        let cid = cal["id"].as_str().unwrap_or("").to_string();
        tick.step(format!("calendar: {name}"));
        let events = g.all(&format!("/users/{}/calendars/{}/events?$top=100", enc(user), enc(&cid))).await?;
        for ev in events {
            if super::cancelled() {
                break;
            }
            let mut instances = Vec::new();
            let mut window = (now - Duration::days(365 * 3), now + Duration::days(365 * 2));
            if ev["type"].as_str() == Some("seriesMaster") {
                if let Some(st) = ev["start"]["dateTime"].as_str().and_then(|s| chrono::NaiveDateTime::parse_from_str(s.split('.').next().unwrap_or(s), "%Y-%m-%dT%H:%M:%S").ok()) {
                    let st = st.and_utc();
                    if st > window.0 {
                        window.0 = st - Duration::hours(1);
                    }
                }
                let q = format!(
                    "/users/{}/events/{}/instances?startDateTime={}&endDateTime={}&$top=500",
                    enc(user),
                    enc(ev["id"].as_str().unwrap_or("")),
                    window.0.format("%Y-%m-%dT%H:%M:%SZ"),
                    window.1.format("%Y-%m-%dT%H:%M:%SZ")
                );
                match g.all(&q).await {
                    Ok(v) => instances = v,
                    Err(e) => tick.error("repeating event", &e),
                }
            }
            let ics = ical::graph_event_ics(&ev, &instances, window);
            match t.add_event(&name, ics).await {
                Ok(true) => tick.event(),
                Ok(false) => {}
                Err(e) => tick.error(&format!("event {:?}", ev["subject"].as_str().unwrap_or("")), &e),
            }
        }
    }
    Ok(())
}

async fn contacts(g: &Graph, user: &str, t: &Target, tick: &Tick) -> Result<()> {
    tick.step("contacts");
    let mut books: Vec<(String, String)> = vec![("Contacts".into(), format!("/users/{}/contacts?$top=100", enc(user)))];
    for f in g.all(&format!("/users/{}/contactFolders?$top=100", enc(user))).await.unwrap_or_default() {
        let name = f["displayName"].as_str().unwrap_or("Contacts").to_string();
        books.push((name, format!("/users/{}/contactFolders/{}/contacts?$top=100", enc(user), enc(f["id"].as_str().unwrap_or("")))));
    }
    for (name, path) in books {
        if t.skip_folder(&name) {
            continue;
        }
        for c in g.all(&path).await? {
            match t.add_contact(&name, ical::graph_contact_vcard(&c)).await {
                Ok(true) => tick.contact(),
                Ok(false) => {}
                Err(e) => tick.error("contact", &e),
            }
        }
    }
    Ok(())
}
