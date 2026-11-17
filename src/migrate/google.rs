//! Google Workspace through a service account with domain-wide delegation.
//!
//! The service account's client ID must be allowed these scopes in the Admin console
//! (Security → API controls → Domain-wide delegation):
//!   https://www.googleapis.com/auth/admin.directory.user.readonly
//!   https://www.googleapis.com/auth/gmail.readonly
//!   https://www.googleapis.com/auth/calendar.readonly
//!   https://www.googleapis.com/auth/contacts.readonly

use super::net::{enc, Body, Http};
use super::{ical, map_folder, Discovered, MailboxMap, Source, Target, Tick};
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use serde_json::{json, Value};
use std::collections::HashMap;

const DIRECTORY: &str = "https://www.googleapis.com/auth/admin.directory.user.readonly";
const GMAIL: &str = "https://www.googleapis.com/auth/gmail.readonly";
const CALENDAR: &str = "https://www.googleapis.com/auth/calendar.readonly";
const CONTACTS: &str = "https://www.googleapis.com/auth/contacts.readonly";

pub struct Google {
    http: Http,
    email: String,
    key: ring::rsa::KeyPair,
    token_uri: String,
    /// Base for all APIs; real Google uses a different host per API.
    api: Option<String>,
    admin: String,
}

struct Session<'a> {
    g: &'a Google,
    token: String,
}

impl Google {
    pub fn new(src: &Source) -> Result<Self> {
        let Source::Google { service_account, admin_email, api_url } = src else { bail!("not a Google source") };
        let sa: Value = serde_json::from_str(service_account.trim()).context("the service account key must be the JSON file Google gave you")?;
        let email = sa["client_email"].as_str().ok_or_else(|| anyhow!("no client_email in the service account key"))?.to_string();
        let pem = sa["private_key"].as_str().ok_or_else(|| anyhow!("no private_key in the service account key"))?;
        let der = <rsa::RsaPrivateKey as rsa::pkcs8::DecodePrivateKey>::from_pkcs8_pem(pem)
            .and_then(|k| rsa::pkcs8::EncodePrivateKey::to_pkcs8_der(&k))
            .map_err(|e| anyhow!("reading the service account's private key: {e}"))?;
        let key = ring::rsa::KeyPair::from_pkcs8(der.as_bytes()).map_err(|e| anyhow!("reading the service account's private key: {e}"))?;
        if !admin_email.contains('@') {
            bail!("enter a Workspace administrator's address (used to list users)");
        }
        let token_uri = match api_url {
            Some(base) => format!("{}/token", base.trim_end_matches('/')),
            None => sa["token_uri"].as_str().unwrap_or("https://oauth2.googleapis.com/token").to_string(),
        };
        Ok(Self { http: Http::new(), email, key, token_uri, api: api_url.as_ref().map(|u| u.trim_end_matches('/').to_string()), admin: admin_email.trim().to_string() })
    }

    fn url(&self, host: &str, path: &str) -> String {
        match &self.api {
            Some(b) => format!("{b}{path}"),
            None => format!("https://{host}{path}"),
        }
    }

    /// A token acting as `subject` with the given scope.
    async fn session(&self, subject: &str, scope: &str) -> Result<Session<'_>> {
        let now = chrono::Utc::now().timestamp();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = b64.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = b64.encode(serde_json::to_vec(&json!({
            "iss": self.email, "sub": subject, "scope": scope, "aud": self.token_uri, "iat": now, "exp": now + 3600,
        }))?);
        let signing_input = format!("{header}.{claims}");
        let mut sig = vec![0u8; self.key.public().modulus_len()];
        self.key
            .sign(&ring::signature::RSA_PKCS1_SHA256, &ring::rand::SystemRandom::new(), signing_input.as_bytes(), &mut sig)
            .map_err(|_| anyhow!("signing the Google sign-in request failed"))?;
        let jwt = format!("{signing_input}.{}", b64.encode(&sig));
        let v = self
            .http
            .json(
                "POST",
                &self.token_uri,
                vec![],
                Body::Form(vec![("grant_type".into(), "urn:ietf:params:oauth:grant-type:jwt-bearer".into()), ("assertion".into(), jwt)]),
            )
            .await
            .map_err(|e| {
                let t = format!("{e:#}");
                if t.contains("unauthorized_client") {
                    anyhow!("Google refused access for {subject}: allow the service account's client ID these scopes under Domain-wide delegation: {scope}")
                } else {
                    e.context(format!("signing in to Google as {subject}"))
                }
            })?;
        Ok(Session { g: self, token: v["access_token"].as_str().ok_or_else(|| anyhow!("no access token from Google"))?.to_string() })
    }
}

impl Session<'_> {
    async fn get(&self, host: &str, path: &str) -> Result<Value> {
        self.g.http.json("GET", &self.g.url(host, path), vec![("Authorization".into(), format!("Bearer {}", self.token))], Body::None).await
    }

    /// Follow nextPageToken pages of `key`.
    async fn all(&self, host: &str, path: &str, key: &str) -> Result<Vec<Value>> {
        let mut out = Vec::new();
        let mut page: Option<String> = None;
        loop {
            let sep = if path.contains('?') { '&' } else { '?' };
            let p = match &page {
                Some(t) => format!("{path}{sep}pageToken={}", enc(t)),
                None => path.to_string(),
            };
            let v = self.get(host, &p).await?;
            out.extend(v[key].as_array().cloned().unwrap_or_default());
            page = v["nextPageToken"].as_str().map(String::from);
            if page.is_none() || super::cancelled() {
                break;
            }
        }
        Ok(out)
    }
}

pub async fn discover(src: &Source) -> Result<Vec<Discovered>> {
    let g = Google::new(src)?;
    let s = g.session(&g.admin, DIRECTORY).await?;
    let users = s.all("admin.googleapis.com", "/admin/directory/v1/users?customer=my_customer&maxResults=500&projection=basic", "users").await.context("listing users")?;
    let mut out: Vec<Discovered> = users
        .iter()
        .filter_map(|u| {
            let mail = u["primaryEmail"].as_str()?.to_ascii_lowercase();
            Some(Discovered {
                source: mail.clone(),
                name: u["name"]["fullName"].as_str().map(String::from),
                target: mail,
                kind: if u["suspended"].as_bool().unwrap_or(false) { "suspended".into() } else { "user".into() },
                exists_here: false,
            })
        })
        .collect();
    out.sort_by(|a, b| a.target.cmp(&b.target));
    Ok(out)
}

pub async fn migrate(src: &Source, m: &MailboxMap, t: &Target, tick: &Tick) -> Result<()> {
    let g = Google::new(src)?;
    let user = m.source.trim().to_ascii_lowercase();
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

/// Postwright folders for a Gmail message's labels. Gmail labels aren't folders: a
/// message can have several, so it's filed in each (the stored copy is shared).
pub fn label_folders(labels: &[String], names: &HashMap<String, String>, t: &Target) -> Vec<String> {
    let mut out = Vec::new();
    let has = |l: &str| labels.iter().any(|x| x == l);
    if has("DRAFT") {
        return vec!["Drafts".into()];
    }
    if has("SPAM") {
        return vec!["Junk".into()];
    }
    if has("TRASH") {
        return vec!["Trash".into()];
    }
    if has("INBOX") {
        out.push("INBOX".into());
    }
    if has("SENT") {
        out.push("Sent".into());
    }
    for l in labels {
        if let Some(n) = names.get(l) {
            if t.skip_folder(n) {
                continue;
            }
            let path: Vec<String> = n.split('/').map(String::from).collect();
            if let Some(f) = map_folder(&path, None) {
                if !out.contains(&f) {
                    out.push(f);
                }
            }
        }
    }
    if out.is_empty() {
        out.push("Archive".into());
    }
    out
}

async fn mail(g: &Google, user: &str, t: &Target, tick: &Tick) -> Result<()> {
    tick.step("signing in");
    let s = g.session(user, GMAIL).await?;
    let base = format!("/gmail/v1/users/{}", enc(user));
    let mut names = HashMap::new();
    for l in s.all("gmail.googleapis.com", &format!("{base}/labels"), "labels").await? {
        if l["type"].as_str() == Some("user") {
            names.insert(l["id"].as_str().unwrap_or("").to_string(), l["name"].as_str().unwrap_or("").to_string());
        }
    }
    tick.step("listing messages");
    let mut q = format!("{base}/messages?maxResults=500&includeSpamTrash=true");
    if let Some(since) = t.since() {
        q.push_str(&format!("&q=after%3A{since}"));
    }
    let ids = s.all("gmail.googleapis.com", &q, "messages").await?;
    tick.step(format!("mail: {} messages", ids.len()));
    let mut s = s;
    let mut issued = std::time::Instant::now();
    for m in ids {
        if super::cancelled() {
            break;
        }
        if issued.elapsed() > std::time::Duration::from_secs(50 * 60) {
            s = g.session(user, GMAIL).await?;
            issued = std::time::Instant::now();
        }
        let id = m["id"].as_str().unwrap_or("").to_string();
        let key = format!("gmail:{user}:{id}");
        if t.seen(&key).await? {
            tick.skipped();
            continue;
        }
        let v = match s.get("gmail.googleapis.com", &format!("{base}/messages/{}?format=raw", enc(&id))).await {
            Ok(v) => v,
            Err(e) => {
                tick.error("message", &e);
                continue;
            }
        };
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(v["raw"].as_str().unwrap_or("").trim_end_matches('='))?;
        let labels: Vec<String> = v["labelIds"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
        let date = v["internalDate"].as_str().and_then(|d| d.parse::<i64>().ok()).map(|ms| ms / 1000).unwrap_or_else(|| chrono::Utc::now().timestamp());
        let mut flags = Vec::new();
        if !labels.iter().any(|l| l == "UNREAD") {
            flags.push("\\Seen".to_string());
        }
        if labels.iter().any(|l| l == "STARRED") {
            flags.push("\\Flagged".to_string());
        }
        if labels.iter().any(|l| l == "DRAFT") {
            flags.push("\\Draft".to_string());
        }
        let folders = label_folders(&labels, &names, t);
        let n = raw.len();
        for (i, f) in folders.iter().enumerate() {
            // The first folder carries the "done" key; the rest get their own.
            let k = if i == 0 { key.clone() } else { format!("{key}:{f}") };
            t.add_message(&k, f, raw.clone(), date, flags.clone()).await?;
        }
        tick.message(n);
    }
    Ok(())
}

async fn calendars(g: &Google, user: &str, t: &Target, tick: &Tick) -> Result<()> {
    tick.step("calendars");
    let s = g.session(user, CALENDAR).await?;
    let cals = s.all("www.googleapis.com", "/calendar/v3/users/me/calendarList?maxResults=250", "items").await?;
    for cal in cals {
        if super::cancelled() {
            break;
        }
        // Only calendars this user owns; subscriptions (holidays, colleagues) stay behind.
        if cal["accessRole"].as_str() != Some("owner") {
            continue;
        }
        let primary = cal["primary"].as_bool().unwrap_or(false);
        let name = if primary { "Calendar".to_string() } else { cal["summaryOverride"].as_str().or(cal["summary"].as_str()).unwrap_or("Calendar").to_string() };
        if t.skip_folder(&name) {
            continue;
        }
        tick.step(format!("calendar: {name}"));
        let id = cal["id"].as_str().unwrap_or("");
        let events = s.all("www.googleapis.com", &format!("/calendar/v3/calendars/{}/events?maxResults=2500&showDeleted=true&singleEvents=false", enc(id)), "items").await?;
        for ics in ical::google_calendar_ics(&events, cal["timeZone"].as_str().unwrap_or("UTC")) {
            match t.add_event(&name, ics).await {
                Ok(true) => tick.event(),
                Ok(false) => {}
                Err(e) => tick.error("event", &e),
            }
        }
    }
    Ok(())
}

async fn contacts(g: &Google, user: &str, t: &Target, tick: &Tick) -> Result<()> {
    tick.step("contacts");
    let s = g.session(user, CONTACTS).await?;
    let people = s
        .all(
            "people.googleapis.com",
            "/v1/people/me/connections?pageSize=1000&personFields=names,nicknames,emailAddresses,phoneNumbers,addresses,organizations,birthdays,biographies,urls",
            "connections",
        )
        .await?;
    for p in people {
        if let Some(v) = ical::google_person_vcard(&p) {
            match t.add_contact("Contacts", v).await {
                Ok(true) => tick.contact(),
                Ok(false) => {}
                Err(e) => tick.error("contact", &e),
            }
        }
    }
    Ok(())
}
