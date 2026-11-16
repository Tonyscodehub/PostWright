//! A small HTTPS client for the Microsoft Graph and Google APIs, with retries on
//! throttling (429) and server errors.

use anyhow::{anyhow, bail, Result};
use serde_json::Value;
use std::time::Duration;

#[derive(Clone)]
pub struct Http {
    agent: ureq::Agent,
}

pub enum Body {
    None,
    Form(Vec<(String, String)>),
}

impl Http {
    pub fn new() -> Self {
        Self {
            agent: ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(20))
                .timeout(Duration::from_secs(300))
                .user_agent(concat!("Postwright/", env!("CARGO_PKG_VERSION"), " (migration)"))
                .build(),
        }
    }

    /// Make a request; returns the body bytes. Retries throttling and server errors.
    pub async fn send(&self, method: &'static str, url: &str, headers: Vec<(String, String)>, body: Body) -> Result<Vec<u8>> {
        let mut wait = 2u64;
        let body = std::sync::Arc::new(body);
        for attempt in 0..8 {
            let (agent, url2, headers2, body2) = (self.agent.clone(), url.to_string(), headers.clone(), body.clone());
            let r = tokio::task::spawn_blocking(move || {
                let mut req = agent.request(method, &url2);
                for (k, v) in &headers2 {
                    req = req.set(k, v);
                }
                let resp = match &*body2 {
                    Body::None => req.call(),
                    Body::Form(f) => req.send_form(&f.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect::<Vec<_>>()),
                };
                match resp {
                    Ok(r) => {
                        let mut buf = Vec::new();
                        std::io::Read::read_to_end(&mut r.into_reader(), &mut buf)?;
                        Ok(Ok(buf))
                    }
                    Err(ureq::Error::Status(code, r)) => {
                        let retry_after = r.header("retry-after").and_then(|v| v.parse::<u64>().ok());
                        let text = r.into_string().unwrap_or_default();
                        Ok(Err((code, retry_after, text)))
                    }
                    Err(ureq::Error::Transport(t)) => Err(anyhow!("{t}")),
                }
            })
            .await?;
            match r {
                Ok(Ok(b)) => return Ok(b),
                Ok(Err((code, ra, text))) if (code == 429 || code >= 500) && attempt < 7 => {
                    let secs = ra.unwrap_or(wait).min(120);
                    tracing::debug!("HTTP {code} from {url}, retrying in {secs}s");
                    tokio::time::sleep(Duration::from_secs(secs)).await;
                    wait = (wait * 2).min(60);
                    let _ = text;
                }
                Ok(Err((code, _, text))) => bail!("HTTP {code}: {}", api_error(&text)),
                Err(e) if attempt < 3 => {
                    tracing::debug!("{url}: {e:#}, retrying");
                    tokio::time::sleep(Duration::from_secs(wait)).await;
                    wait *= 2;
                }
                Err(e) => return Err(e),
            }
        }
        bail!("gave up after repeated errors")
    }

    pub async fn json(&self, method: &'static str, url: &str, headers: Vec<(String, String)>, body: Body) -> Result<Value> {
        let b = self.send(method, url, headers, body).await?;
        Ok(serde_json::from_slice(&b)?)
    }
}

/// The readable part of a Graph or Google error body.
fn api_error(text: &str) -> String {
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        let e = &v["error"];
        if let Some(m) = e["message"].as_str() {
            let code = e["code"].as_str().or_else(|| e["status"].as_str()).unwrap_or("");
            return if code.is_empty() { m.to_string() } else { format!("{code}: {m}") };
        }
        if let Some(d) = v["error_description"].as_str() {
            return d.lines().next().unwrap_or(d).to_string();
        }
        if let Some(m) = e.as_str() {
            return m.to_string();
        }
    }
    text.chars().take(300).collect()
}

/// Percent-encode a URL component.
pub fn enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
