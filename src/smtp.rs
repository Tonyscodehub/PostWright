//! SMTP server: inbound MX (port 25) and authenticated submission (587/465).

use crate::auth;
use crate::delivery::{self, RcptCheck};
use crate::net::{Conn, Stream};
use crate::server::Shared;
use crate::store::{self, User};
use anyhow::Result;
use mail_auth::dmarc::verify::DmarcParameters;
use mail_auth::spf::verify::SpfParameters;
use mail_auth::common::headers::HeaderWriter;
use mail_auth::{AuthenticatedMessage, AuthenticationResults, DkimResult, DmarcResult, SpfResult};
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// Port 25: receives mail for hosted domains only. No AUTH, never relays.
    Inbound,
    /// Port 587 (STARTTLS) or 465 (implicit TLS): AUTH is mandatory.
    Submission,
}

struct Session {
    srv: Shared,
    conn: Conn,
    peer: SocketAddr,
    mode: Mode,
    helo: Option<String>,
    user: Option<User>,
    sender_addrs: Vec<String>,
    mail_from: Option<String>,
    rcpts: Vec<String>,
    declared_size: i64,
    errors: u32,
    /// Connection-level spam evidence gathered before the banner (DNSBL, early talking).
    pre: crate::filter::Verdict,
}

pub async fn handle(srv: Shared, stream: Stream, peer: SocketAddr, mode: Mode) -> Result<()> {
    let timeout = Duration::from_secs(srv.cfg.limits.smtp_timeout_secs);
    let mut s = Session {
        conn: Conn::new(stream, timeout),
        srv,
        peer,
        mode,
        helo: None,
        user: None,
        sender_addrs: vec![],
        mail_from: None,
        rcpts: vec![],
        declared_size: 0,
        errors: 0,
        pre: Default::default(),
    };
    if mode == Mode::Submission && s.srv.guard.is_blocked(peer.ip()) {
        s.conn.send("421 4.7.0 Too many failed logins, try later").await?;
        return Ok(());
    }
    let f = &s.srv.cfg.filter;
    if mode == Mode::Inbound && f.enabled {
        // Pause before the banner (spambots talk first) while the DNSBL lookups run.
        let srv = s.srv.clone();
        let ip = peer.ip();
        let bl = tokio::spawn(async move {
            let mut v = crate::filter::Verdict::default();
            crate::filter::dnsbl(&srv, ip, &mut v).await;
            v
        });
        if f.greet_pause_ms > 0 && !crate::filter::is_private(ip) && s.conn.early_talk(Duration::from_millis(f.greet_pause_ms)).await {
            s.pre.add(6.0, "EARLY_TALKER");
        }
        if let Ok(v) = bl.await {
            s.pre.score += v.score;
            s.pre.reasons.extend(v.reasons);
        }
        if s.pre.score >= f.reject_score {
            tracing::info!("refused {}: {}", ip, s.pre.reasons.join(" "));
            s.conn.send(&format!("554 5.7.1 {} is listed on a blocklist", ip)).await?;
            return Ok(());
        }
    }
    let banner = format!("220 {} ESMTP Postwright", s.srv.cfg.hostname);
    s.conn.send(&banner).await?;
    s.run().await
}

impl Session {
    fn reset(&mut self) {
        self.mail_from = None;
        self.rcpts.clear();
        self.declared_size = 0;
    }

    async fn reply(&mut self, line: &str) -> Result<()> {
        if line.starts_with('5') || line.starts_with('4') {
            self.errors += 1;
        }
        self.conn.send(line).await
    }

    async fn run(&mut self) -> Result<()> {
        loop {
            if self.errors > 20 {
                self.conn.send("421 4.7.0 Too many errors, closing connection").await?;
                return Ok(());
            }
            let raw = self.conn.read_line().await?;
            let line = String::from_utf8_lossy(&raw).to_string();
            let (verb, arg) = match line.split_once(' ') {
                Some((v, a)) => (v.to_ascii_uppercase(), a.trim().to_string()),
                None => (line.trim().to_ascii_uppercase(), String::new()),
            };
            match verb.as_str() {
                "EHLO" | "HELO" => self.ehlo(&verb, &arg).await?,
                "STARTTLS" => {
                    if self.conn.stream.is_tls() {
                        self.reply("503 5.5.1 TLS already active").await?;
                        continue;
                    }
                    if self.conn.has_buffered() {
                        // Pipelined plaintext after STARTTLS is an injection attempt.
                        self.reply("554 5.5.1 Pipelining not allowed with STARTTLS").await?;
                        return Ok(());
                    }
                    self.conn.send("220 2.0.0 Ready to start TLS").await?;
                    let acceptor = self.srv.tls();
                    self.conn.upgrade(&acceptor).await?;
                    self.helo = None;
                    self.reset();
                }
                "AUTH" => {
                    if !self.auth(&arg).await? {
                        return Ok(());
                    }
                }
                "MAIL" => self.mail(&arg).await?,
                "RCPT" => self.rcpt(&arg).await?,
                "DATA" => self.data().await?,
                "RSET" => {
                    self.reset();
                    self.reply("250 2.0.0 OK").await?;
                }
                "NOOP" => self.reply("250 2.0.0 OK").await?,
                "VRFY" | "EXPN" => self.reply("252 2.5.2 Cannot verify, but will attempt delivery").await?,
                "HELP" => self.reply("214 2.0.0 See RFC 5321").await?,
                "QUIT" => {
                    self.conn.send("221 2.0.0 Bye").await?;
                    return Ok(());
                }
                "BDAT" => self.reply("502 5.5.1 CHUNKING not supported").await?,
                _ => self.reply("500 5.5.2 Command not recognised").await?,
            }
        }
    }

    fn auth_available(&self) -> bool {
        self.mode == Mode::Submission && self.conn.stream.is_tls()
    }

    async fn ehlo(&mut self, verb: &str, arg: &str) -> Result<()> {
        if arg.is_empty() {
            return self.reply("501 5.5.4 Hostname required").await;
        }
        self.helo = Some(arg.split_whitespace().next().unwrap_or(arg).to_string());
        self.reset();
        let host = self.srv.cfg.hostname.clone();
        if verb == "HELO" {
            return self.reply(&format!("250 {host}")).await;
        }
        let mut caps = vec![
            host,
            "PIPELINING".into(),
            format!("SIZE {}", self.srv.cfg.limits.max_message_size),
            "8BITMIME".into(),
            "ENHANCEDSTATUSCODES".into(),
            "SMTPUTF8".into(),
        ];
        if !self.conn.stream.is_tls() {
            caps.push("STARTTLS".into());
        }
        if self.auth_available() && self.user.is_none() {
            caps.push("AUTH PLAIN LOGIN".into());
        }
        let n = caps.len();
        for (i, c) in caps.iter().enumerate() {
            let sep = if i + 1 == n { ' ' } else { '-' };
            self.conn.send(&format!("250{sep}{c}")).await?;
        }
        Ok(())
    }

    /// Returns false if the connection should be closed.
    async fn auth(&mut self, arg: &str) -> Result<bool> {
        if self.mode != Mode::Submission {
            self.reply("502 5.5.1 AUTH not available on this port; use submission (587/465)").await?;
            return Ok(true);
        }
        if !self.conn.stream.is_tls() {
            self.reply("538 5.7.11 Encryption required for requested authentication mechanism").await?;
            return Ok(true);
        }
        if self.user.is_some() {
            self.reply("503 5.5.1 Already authenticated").await?;
            return Ok(true);
        }
        if self.helo.is_none() {
            self.reply("503 5.5.1 EHLO first").await?;
            return Ok(true);
        }
        let ip = self.peer.ip();
        if self.srv.guard.is_blocked(ip) {
            self.conn.send("421 4.7.0 Too many failed logins, try later").await?;
            return Ok(false);
        }
        let mut parts = arg.splitn(2, ' ');
        let mech = parts.next().unwrap_or("").to_ascii_uppercase();
        let initial = parts.next().map(|s| s.trim().to_string());
        let creds = match mech.as_str() {
            "PLAIN" => {
                let resp = match initial {
                    Some(r) if r != "=" => r,
                    _ => {
                        self.conn.send("334 ").await?;
                        String::from_utf8_lossy(&self.conn.read_line().await?).to_string()
                    }
                };
                if resp.trim() == "*" {
                    self.reply("501 5.0.0 Authentication cancelled").await?;
                    return Ok(true);
                }
                auth::decode_plain(&resp)
            }
            "LOGIN" => {
                let user_b64 = match initial {
                    Some(r) => r,
                    None => {
                        self.conn.send("334 VXNlcm5hbWU6").await?;
                        String::from_utf8_lossy(&self.conn.read_line().await?).to_string()
                    }
                };
                self.conn.send("334 UGFzc3dvcmQ6").await?;
                let pass_b64 = String::from_utf8_lossy(&self.conn.read_line().await?).to_string();
                match (auth::b64d(&user_b64), auth::b64d(&pass_b64)) {
                    (Some(u), Some(p)) => Some((u, p)),
                    _ => None,
                }
            }
            _ => {
                self.reply("504 5.5.4 Unrecognised authentication mechanism").await?;
                return Ok(true);
            }
        };
        let user = match creds {
            Some((u, p)) => auth::authenticate(&self.srv.store, &u, &p).await?,
            None => None,
        };
        match user {
            Some(u) => {
                self.srv.guard.record_success(ip);
                let uu = u.clone();
                self.sender_addrs = self.srv.store.call(move |c| store::sender_addresses(c, &uu)).await?;
                tracing::info!("SMTP AUTH ok for {} from {}", u.email, ip);
                self.user = Some(u);
                self.conn.send("235 2.7.0 Authentication successful").await?;
            }
            None => {
                self.srv.guard.record_failure(ip);
                tracing::warn!("SMTP AUTH failed from {ip}");
                tokio::time::sleep(Duration::from_secs(2)).await;
                self.reply("535 5.7.8 Authentication credentials invalid").await?;
            }
        }
        Ok(true)
    }

    async fn mail(&mut self, arg: &str) -> Result<()> {
        if self.helo.is_none() {
            return self.reply("503 5.5.1 EHLO/HELO first").await;
        }
        if self.mail_from.is_some() {
            return self.reply("503 5.5.1 Sender already specified").await;
        }
        if self.mode == Mode::Submission && self.user.is_none() {
            return self.reply("530 5.7.0 Authentication required").await;
        }
        if self.mode == Mode::Inbound && self.srv.cfg.inbound.require_tls && !self.conn.stream.is_tls() {
            return self.reply("530 5.7.0 Must issue a STARTTLS command first").await;
        }
        let Some((addr, params)) = parse_path(arg, "FROM:") else {
            return self.reply("501 5.5.4 Syntax: MAIL FROM:<address>").await;
        };
        if !addr.is_empty() && !valid_address(&addr) {
            return self.reply("553 5.1.7 Invalid sender address").await;
        }
        for p in params.split_whitespace() {
            if let Some(v) = p.to_ascii_uppercase().strip_prefix("SIZE=") {
                let size: i64 = v.parse().unwrap_or(0);
                if size as usize > self.srv.cfg.limits.max_message_size {
                    return self.reply("552 5.3.4 Message size exceeds fixed limit").await;
                }
                self.declared_size = size;
            }
        }
        if self.mode == Mode::Submission {
            let a = addr.to_ascii_lowercase();
            if a.is_empty() || !self.sender_addrs.contains(&a) {
                return self.reply("553 5.7.1 Sender address not owned by authenticated user").await;
            }
        }
        self.mail_from = Some(addr.to_ascii_lowercase());
        self.reply("250 2.1.0 OK").await
    }

    async fn rcpt(&mut self, arg: &str) -> Result<()> {
        if self.mail_from.is_none() {
            return self.reply("503 5.5.1 MAIL first").await;
        }
        if self.rcpts.len() >= self.srv.cfg.limits.max_recipients {
            return self.reply("452 4.5.3 Too many recipients").await;
        }
        let Some((addr, _)) = parse_path(arg, "TO:") else {
            return self.reply("501 5.5.4 Syntax: RCPT TO:<address>").await;
        };
        let addr = addr.to_ascii_lowercase();
        if !valid_address(&addr) {
            return self.reply("501 5.1.3 Invalid recipient address").await;
        }
        let size = self.declared_size;
        let a = addr.clone();
        let check = self.srv.store.call(move |c| delivery::check_local_rcpt(c, &a, size)).await?;
        let resp = match (self.mode, check) {
            (_, RcptCheck::Ok) => None,
            (_, RcptCheck::Unknown) => Some("550 5.1.1 Mailbox does not exist"),
            (_, RcptCheck::OverQuota) => Some("452 4.2.2 Mailbox full"),
            (Mode::Inbound, RcptCheck::NotLocal) => Some("554 5.7.1 Relay access denied"),
            (Mode::Submission, RcptCheck::NotLocal) => None, // authenticated relay
        };
        if let Some(r) = resp {
            if self.mode == Mode::Inbound {
                tracing::info!("rejected RCPT {addr} from {}: {r}", self.peer.ip());
            }
            return self.reply(r).await;
        }
        if !self.rcpts.contains(&addr) {
            self.rcpts.push(addr);
        }
        self.reply("250 2.1.5 OK").await
    }

    async fn data(&mut self) -> Result<()> {
        if self.mail_from.is_none() {
            return self.reply("503 5.5.1 MAIL first").await;
        }
        if self.rcpts.is_empty() {
            return self.reply("554 5.5.1 No valid recipients").await;
        }
        self.conn.send("354 End data with <CR><LF>.<CR><LF>").await?;
        let max = self.srv.cfg.limits.max_message_size;
        let mut body = Vec::with_capacity(64 * 1024);
        let mut too_big = false;
        let mut prev_crlf = true;
        // Long timeout for slow uploads of large messages.
        let saved = self.conn.timeout;
        self.conn.timeout = Duration::from_secs(600);
        loop {
            let (line, crlf) = self.conn.read_line_ex().await?;
            // Only <CRLF>.<CRLF> ends the data; bare-LF variants are treated as content.
            // This closes the "SMTP smuggling" class of attacks.
            if line == b"." && crlf && prev_crlf {
                break;
            }
            prev_crlf = crlf;
            let content = if line.first() == Some(&b'.') { &line[1..] } else { &line[..] };
            if !too_big {
                body.extend_from_slice(content);
                body.extend_from_slice(b"\r\n");
                if body.len() > max {
                    too_big = true;
                    body = Vec::new();
                }
            }
        }
        self.conn.timeout = saved;
        if too_big {
            self.reset();
            return self.reply("552 5.3.4 Message size exceeds fixed limit").await;
        }
        let result = match self.mode {
            Mode::Inbound => self.finish_inbound(body).await,
            Mode::Submission => self.finish_submission(body).await,
        };
        self.reset();
        match result {
            Ok(r) => self.reply(&r).await,
            Err(e) => {
                tracing::error!("delivery error: {e:#}");
                self.reply("451 4.3.0 Local error in processing").await
            }
        }
    }

    fn received_header(&self, with: &str, rcpt: Option<&str>) -> String {
        let helo = self.helo.clone().unwrap_or_default();
        let id = format!("{:x}", rand::random::<u64>());
        let tls = self.conn.stream.tls_info().map(|t| format!("\r\n\t(using {t})")).unwrap_or_default();
        let auth = match &self.user {
            Some(u) => format!("\r\n\t(Authenticated sender: {})", u.email),
            None => String::new(),
        };
        let for_ = rcpt.map(|r| format!("\r\n\tfor <{r}>")).unwrap_or_default();
        format!(
            "Received: from {helo} ([{ip}]){tls}{auth}\r\n\tby {host} (Postwright) with {with} id {id}{for_};\r\n\t{date}\r\n",
            ip = self.peer.ip(),
            host = self.srv.cfg.hostname,
            date = chrono::Utc::now().to_rfc2822()
        )
    }

    async fn finish_inbound(&mut self, body: Vec<u8>) -> Result<String> {
        let mail_from = self.mail_from.clone().unwrap_or_default();
        let helo = self.helo.clone().unwrap_or_default();
        let host = self.srv.cfg.hostname.clone();
        let ip = self.peer.ip();
        // Remove any Authentication-Results forged with our own authserv-id.
        let body = strip_forged_auth_results(&body, &host);
        let mut prefix = String::new();
        let fcfg = self.srv.cfg.filter.clone();
        let mut verdict = self.pre.clone();
        if self.srv.cfg.inbound.verify {
            let Some(msg) = AuthenticatedMessage::parse(&body) else {
                return Ok("550 5.6.0 Malformed message".into());
            };
            let dkim = self.srv.dns.verify_dkim(&msg).await;
            let spf = if mail_from.is_empty() {
                self.srv.dns.verify_spf(SpfParameters::verify_ehlo(ip, &helo, &host)).await
            } else {
                self.srv.dns.verify_spf(SpfParameters::verify_mail_from(ip, &helo, &host, &mail_from)).await
            };
            let mf_domain = if mail_from.is_empty() { helo.clone() } else { delivery::domain_of(&mail_from) };
            let dmarc = self.srv.dns.verify_dmarc(DmarcParameters::new(&msg, &dkim, &mf_domain, &spf)).await;
            let header_from = msg.from.first().cloned().unwrap_or_default();
            let ar = AuthenticationResults::new(&host)
                .with_dkim_results(&dkim, &header_from)
                .with_spf_mailfrom_result(&spf, ip, &mail_from, &helo)
                .with_dmarc_result(&dmarc);
            let dmarc_pass = *dmarc.dkim_result() == DmarcResult::Pass || *dmarc.spf_result() == DmarcResult::Pass;
            let dmarc_failed = !dmarc_pass
                && (matches!(dmarc.dkim_result(), DmarcResult::Fail(_)) || matches!(dmarc.spf_result(), DmarcResult::Fail(_)));
            if self.srv.cfg.inbound.enforce_dmarc_reject
                && dmarc_failed
                && dmarc.policy() == mail_auth::dmarc::Policy::Reject
            {
                tracing::info!("rejected message from {ip} ({mail_from}): DMARC policy reject");
                return Ok("550 5.7.1 Rejected by DMARC policy".into());
            }
            if self.srv.cfg.inbound.reject_spf_fail && spf.result() == SpfResult::Fail && !dmarc_pass {
                return Ok("550 5.7.23 SPF validation failed".into());
            }
            let dkim_ok = dkim.iter().any(|d| *d.result() == DkimResult::Pass);
            if fcfg.enabled {
                match spf.result() {
                    SpfResult::Fail => verdict.add(3.0, "SPF_FAIL"),
                    SpfResult::SoftFail => verdict.add(1.0, "SPF_SOFTFAIL"),
                    SpfResult::PermError => verdict.add(0.5, "SPF_PERMERROR"),
                    _ => {}
                }
                if !dkim_ok && dkim.iter().any(|d| matches!(d.result(), DkimResult::Fail(_))) {
                    verdict.add(1.0, "DKIM_INVALID");
                }
                if dmarc_pass {
                    verdict.add(-1.0, "DMARC_PASS");
                } else if dmarc_failed {
                    match dmarc.policy() {
                        mail_auth::dmarc::Policy::Reject => verdict.add(6.0, "DMARC_REJECT"),
                        mail_auth::dmarc::Policy::Quarantine => verdict.add(3.0, "DMARC_QUARANTINE"),
                        _ => verdict.add(1.5, "DMARC_NONE_FAIL"),
                    }
                }
                if !crate::filter::is_private(ip) {
                    let iprev = self.srv.dns.verify_iprev(ip).await;
                    match iprev.result() {
                        mail_auth::IprevResult::Pass => {}
                        mail_auth::IprevResult::TempError(_) => {}
                        _ => verdict.add(1.5, "FCRDNS_FAIL"),
                    }
                }
            }
            tracing::info!(
                "accepted from {ip} <{mail_from}> spf={:?} dkim={} dmarc={}",
                spf.result(),
                if dkim_ok { "pass" } else { "none/fail" },
                if dmarc_pass { "pass" } else { "none/fail" }
            );
            prefix.push_str(&ar.to_header());
        }
        let mut junk = false;
        if fcfg.enabled {
            if !crate::filter::is_private(ip) {
                crate::filter::helo_score(&helo, &mut verdict);
            }
            let rcpts = self.rcpts.clone();
            let env = crate::filter::Envelope { ip, helo: &helo, mail_from: &mail_from, rcpts: &rcpts, user: None };
            crate::filter::scan_content(&self.srv, &env, &body, &mut verdict).await;
            match verdict.action(&fcfg) {
                crate::filter::Action::Reject(r) | crate::filter::Action::Tempfail(r) => {
                    tracing::info!("refused message from {ip} <{mail_from}>: {} [{}]", r, verdict.reasons.join(" "));
                    return Ok(r);
                }
                crate::filter::Action::Junk => junk = true,
                crate::filter::Action::Deliver => {}
            }
            if fcfg.add_headers {
                prefix.push_str(&verdict.headers(&fcfg, &host));
            }
        }
        let with = if self.conn.stream.is_tls() { "ESMTPS" } else { "ESMTP" };
        let rcpt = if self.rcpts.len() == 1 { Some(self.rcpts[0].clone()) } else { None };
        let mut data = self.received_header(with, rcpt.as_deref()).into_bytes();
        data.extend_from_slice(prefix.as_bytes());
        data.extend_from_slice(&body);
        if junk {
            tracing::info!("filed as junk: <{mail_from}> score {:.1} [{}]", verdict.score, verdict.reasons.join(" "));
        }
        let failed = delivery::deliver_to(&self.srv, &mail_from, &self.rcpts.clone(), data, junk).await?;
        if failed.len() == self.rcpts.len() {
            return Ok("452 4.2.2 Could not deliver to any recipient".into());
        }
        Ok("250 2.0.0 OK: queued".into())
    }

    async fn finish_submission(&mut self, body: Vec<u8>) -> Result<String> {
        let user = self.user.clone().expect("authenticated");
        let mail_from = self.mail_from.clone().unwrap_or_default();
        let parsed = mail_parser::MessageParser::default().parse_headers(&body);
        let header_from: Option<String> = parsed
            .as_ref()
            .and_then(|m| m.from())
            .and_then(|a| a.first())
            .and_then(|a| a.address())
            .map(|s| s.to_ascii_lowercase());
        if self.srv.cfg.submission.enforce_from_header {
            match &header_from {
                Some(f) if self.sender_addrs.contains(f) => {}
                _ => return Ok("550 5.7.1 From: header must be an address you own".into()),
            }
        }
        let mut extra = String::new();
        let has_date = parsed.as_ref().map(|m| m.date().is_some()).unwrap_or(false);
        let has_msgid = parsed.as_ref().map(|m| m.message_id().is_some()).unwrap_or(false);
        if !has_date {
            extra.push_str(&format!("Date: {}\r\n", chrono::Utc::now().to_rfc2822()));
        }
        if !has_msgid {
            extra.push_str(&format!(
                "Message-ID: <{}.{:x}@{}>\r\n",
                store::now(),
                rand::random::<u64>(),
                delivery::domain_of(&mail_from)
            ));
        }
        let fcfg = self.srv.cfg.filter.clone();
        if fcfg.enabled && fcfg.scan_outbound {
            let mut v = crate::filter::Verdict::default();
            let rcpts = self.rcpts.clone();
            let helo = self.helo.clone().unwrap_or_default();
            let env = crate::filter::Envelope { ip: self.peer.ip(), helo: &helo, mail_from: &mail_from, rcpts: &rcpts, user: Some(&user.email) };
            crate::filter::scan_content(&self.srv, &env, &body, &mut v).await;
            // Outbound: block malware and anything the spam engine says to reject (a
            // compromised account), but never junk-file a user's own mail.
            if let Some(virus) = &v.virus {
                tracing::warn!("blocked outbound malware from {}: {virus}", user.email);
                return Ok(format!("554 5.7.1 Message contains malware ({virus})"));
            }
            if v.force_reject {
                tracing::warn!("blocked outbound spam from {} [{}]", user.email, v.reasons.join(" "));
                return Ok("550 5.7.1 Message rejected as spam".into());
            }
            if let Some(t) = v.tempfail {
                return Ok(format!("451 4.7.1 {t}, try again later"));
            }
        }
        let uid = user.id;
        let settings = self.srv.store.call(move |c| crate::prefs::load(c, uid)).await?;
        let body = crate::prefs::apply_signature(body, &settings.signature);
        let mut data = self.received_header("ESMTPSA", None).into_bytes();
        data.extend_from_slice(extra.as_bytes());
        data.extend_from_slice(&body);

        // Sign with the From: domain's key (aligned for DMARC), falling back to the envelope domain.
        let sign_domain = header_from.as_deref().map(delivery::domain_of).unwrap_or_else(|| delivery::domain_of(&mail_from));
        let env_domain = delivery::domain_of(&mail_from);
        let dom = self
            .srv
            .store
            .call(move |c| Ok(store::find_domain(c, &sign_domain)?.or(store::find_domain(c, &env_domain)?)))
            .await?;
        if let Some(d) = dom {
            data = delivery::dkim_sign(&d, data)?;
        }
        let failed = delivery::deliver(&self.srv, &mail_from, &self.rcpts.clone(), data).await?;
        tracing::info!("submission from {} to {} recipient(s)", user.email, self.rcpts.len());
        if failed.len() == self.rcpts.len() {
            return Ok("550 5.1.1 Could not deliver to any recipient".into());
        }
        Ok("250 2.0.0 OK: queued".into())
    }
}

/// Parse "FROM:<addr> PARAMS" / "TO:<addr> PARAMS".
pub fn parse_path(arg: &str, prefix: &str) -> Option<(String, String)> {
    let a = arg.trim();
    if a.len() < prefix.len() || !a[..prefix.len()].eq_ignore_ascii_case(prefix) {
        return None;
    }
    let rest = a[prefix.len()..].trim_start();
    if let Some(r) = rest.strip_prefix('<') {
        let end = r.find('>')?;
        let addr = &r[..end];
        // Strip source routes (@a,@b:user@host).
        let addr = addr.rsplit_once(':').map(|x| x.1).unwrap_or(addr);
        Some((addr.to_string(), r[end + 1..].trim().to_string()))
    } else {
        let mut it = rest.splitn(2, ' ');
        let addr = it.next()?.to_string();
        Some((addr, it.next().unwrap_or("").to_string()))
    }
}

pub fn valid_address(a: &str) -> bool {
    a.len() <= 254
        && !a.chars().any(|c| c.is_whitespace() || c.is_control() || c == '<' || c == '>' || c == ',')
        && delivery::split_addr(a).is_some()
        && a.matches('@').count() == 1
}

fn strip_forged_auth_results(data: &[u8], host: &str) -> Vec<u8> {
    let end = delivery::find_header_end(data);
    let headers = &data[..end];
    let mut out = Vec::with_capacity(data.len());
    let mut skipping = false;
    for line in headers.split_inclusive(|&b| b == b'\n') {
        let cont = matches!(line.first(), Some(b' ') | Some(b'\t'));
        if !cont {
            skipping = false;
            let lower = String::from_utf8_lossy(line).to_ascii_lowercase();
            if let Some(v) = lower.strip_prefix("authentication-results:") {
                if v.trim_start().starts_with(&host.to_ascii_lowercase()) {
                    skipping = true;
                }
            }
            // Senders must not be able to pre-label their own mail as clean.
            if lower.starts_with("x-spam-") {
                skipping = true;
            }
        }
        if !skipping {
            out.extend_from_slice(line);
        }
    }
    out.extend_from_slice(&data[end..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(parse_path("FROM:<a@b.com> SIZE=10", "FROM:"), Some(("a@b.com".into(), "SIZE=10".into())));
        assert_eq!(parse_path("from: <>", "FROM:"), Some(("".into(), "".into())));
        assert_eq!(parse_path("TO:<@x.com:u@y.org>", "TO:"), Some(("u@y.org".into(), "".into())));
        assert!(valid_address("tony@example.co.uk"));
        assert!(!valid_address("bad address@x.com"));
        assert!(!valid_address("a@b@c.com"));
    }

    #[test]
    fn strips_forged_ar() {
        let m = b"Authentication-Results: mx.me.com; dkim=pass\r\n\tspf=pass\r\nSubject: hi\r\n\r\nbody";
        let out = strip_forged_auth_results(m, "mx.me.com");
        assert_eq!(out, b"Subject: hi\r\n\r\nbody");
    }
}
