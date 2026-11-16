//! Importing exported files that have been copied to the server: Google Takeout
//! (mbox with X-Gmail-Labels, .ics, .vcf), Thunderbird/Apple Mail mbox, Outlook .ics
//! calendar exports, and .vcf contact exports.

use super::{log, map_folder, prepare_target, MailboxMap, Options, Target, Tick};
use crate::server::Shared;
use anyhow::{anyhow, bail, Result};
use sha2::{Digest, Sha256};
use std::io::BufRead;
use std::path::{Path, PathBuf};

/// Import a file or a folder of files for one user, in the background with the same
/// progress reporting as other migrations.
pub fn start(srv: Shared, path: String, target: String, folder: Option<String>) -> Result<()> {
    let p = PathBuf::from(path.trim());
    if !p.exists() {
        bail!("{} doesn't exist on the server", p.display());
    }
    let files = collect(&p)?;
    if files.is_empty() {
        bail!("no .mbox, .ics or .vcf files found in {}", p.display());
    }
    let m = MailboxMap { source: p.display().to_string(), password: None, target: target.trim().to_ascii_lowercase(), name: None };
    super::begin(&format!("files in {}", p.display()), &[m.clone()])?;
    tokio::spawn(async move {
        let tick = Tick(0);
        let r = async {
            let (user, pw) = prepare_target(&srv, &m, true).await?;
            if let Some(pw) = pw {
                super::with(|pr| pr.created.push((user.email.clone(), pw)));
            }
            let t = Target::new(srv.clone(), user, Options::default());
            for f in &files {
                if super::cancelled() {
                    break;
                }
                let r = import_file(&t, f, folder.as_deref(), &tick).await;
                if let Err(e) = r {
                    tick.error(&f.display().to_string(), &e);
                }
            }
            t.notify();
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if let Err(e) = r {
            tick.error("failed", &e);
        }
        super::finish_one(0);
        super::end();
    });
    Ok(())
}

fn collect(p: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    fn walk(p: &Path, depth: usize, out: &mut Vec<PathBuf>) -> Result<()> {
        if p.is_file() {
            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
            if ["mbox", "mbx", "ics", "vcf"].contains(&ext.as_str()) {
                out.push(p.to_path_buf());
            }
            return Ok(());
        }
        if depth > 6 {
            return Ok(());
        }
        let mut entries: Vec<_> = std::fs::read_dir(p)?.filter_map(|e| e.ok()).map(|e| e.path()).collect();
        entries.sort();
        for e in entries {
            walk(&e, depth + 1, out)?;
        }
        Ok(())
    }
    walk(p, 0, &mut out)?;
    Ok(out)
}

async fn import_file(t: &Target, f: &Path, folder: Option<&str>, tick: &Tick) -> Result<()> {
    let ext = f.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
    let stem = f.file_stem().and_then(|s| s.to_str()).unwrap_or("Imported").to_string();
    tick.step(format!("importing {}", f.file_name().and_then(|s| s.to_str()).unwrap_or("")));
    log(format!("importing {} for {}", f.display(), t.user.email));
    match ext.as_str() {
        "mbox" | "mbx" => {
            let default = folder.map(String::from).unwrap_or_else(|| if stem.to_ascii_lowercase().starts_with("all mail") { "Archive".into() } else { stem.clone() });
            mbox(t, f, &default, tick).await
        }
        "ics" => {
            let data = tokio::fs::read(f).await?;
            let data = String::from_utf8_lossy(&data).into_owned();
            // Takeout names the main calendar after the address; Outlook after the user.
            let name = if stem.contains('@') || stem.eq_ignore_ascii_case("calendar") { "Calendar".to_string() } else { stem };
            for obj in super::ical::split_ics(&data)? {
                match t.add_event(&name, obj).await {
                    Ok(true) => tick.event(),
                    Ok(false) => {}
                    Err(e) => tick.error("event", &e),
                }
            }
            Ok(())
        }
        "vcf" => {
            let data = tokio::fs::read(f).await?;
            let data = String::from_utf8_lossy(&data).into_owned();
            let book = if ["all contacts", "my contacts", "contacts"].contains(&stem.to_ascii_lowercase().as_str()) { "Contacts".to_string() } else { stem };
            for card in crate::carddav::split_vcards(&data) {
                match t.add_contact(&book, card).await {
                    Ok(true) => tick.contact(),
                    Ok(false) => {}
                    Err(e) => tick.error("contact", &e),
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Header value from a raw message (unfolded), case-insensitive.
fn header(raw: &[u8], name: &str) -> Option<String> {
    let end = crate::delivery::find_header_end(raw);
    let head = String::from_utf8_lossy(&raw[..end]);
    let mut val: Option<String> = None;
    for line in head.split('\n') {
        let line = line.trim_end_matches('\r');
        if let Some(v) = val.as_mut() {
            if line.starts_with([' ', '\t']) {
                v.push(' ');
                v.push_str(line.trim());
                continue;
            }
            return val;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(name) {
                val = Some(v.trim().to_string());
            }
        }
    }
    val
}

/// Split a Takeout label list: `Inbox,"Work, 2026",Opened`.
pub fn parse_labels(v: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut q = false;
    for ch in v.chars() {
        match ch {
            '"' => q = !q,
            ',' if !q => {
                out.push(cur.trim().to_string());
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    out.push(cur.trim().to_string());
    out.into_iter().filter(|s| !s.is_empty()).collect()
}

/// (folders, flags, skip) for Takeout's X-Gmail-Labels.
pub fn takeout_placement(labels: &[String], t: &Target) -> (Vec<String>, Vec<String>, bool) {
    let has = |l: &str| labels.iter().any(|x| x.eq_ignore_ascii_case(l));
    if has("Chat") {
        return (vec![], vec![], true);
    }
    let mut flags = Vec::new();
    if !has("Unread") {
        flags.push("\\Seen".to_string());
    }
    if has("Starred") {
        flags.push("\\Flagged".to_string());
    }
    if has("Drafts") {
        flags.push("\\Draft".to_string());
        return (vec!["Drafts".into()], flags, false);
    }
    if has("Spam") {
        return (vec!["Junk".into()], flags, false);
    }
    if has("Trash") {
        return (vec!["Trash".into()], flags, false);
    }
    const SYSTEM: &[&str] = &["Inbox", "Sent", "Drafts", "Spam", "Trash", "Starred", "Important", "Unread", "Opened", "Archived", "Chat"];
    let mut folders = Vec::new();
    if has("Inbox") {
        folders.push("INBOX".to_string());
    }
    if has("Sent") {
        folders.push("Sent".to_string());
    }
    for l in labels {
        if SYSTEM.iter().any(|s| s.eq_ignore_ascii_case(l)) || l.starts_with("Category ") || l.starts_with("CATEGORY_") || t.skip_folder(l) {
            continue;
        }
        let path: Vec<String> = l.split('/').map(String::from).collect();
        if let Some(f) = map_folder(&path, None) {
            if !folders.contains(&f) {
                folders.push(f);
            }
        }
    }
    if folders.is_empty() {
        folders.push("Archive".into());
    }
    (folders, flags, false)
}

async fn mbox(t: &Target, path: &Path, default_folder: &str, tick: &Tick) -> Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
    let p = path.to_path_buf();
    // Read in a blocking thread; mbox files can be many gigabytes.
    let reader = tokio::task::spawn_blocking(move || -> Result<()> {
        let f = std::io::BufReader::with_capacity(1 << 20, std::fs::File::open(&p)?);
        let mut cur: Vec<u8> = Vec::new();
        let mut started = false;
        let mut prev_blank = true;
        for line in f.split(b'\n') {
            let mut line = line?;
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.starts_with(b"From ") && prev_blank {
                if started && !cur.is_empty() {
                    while cur.ends_with(b"\r\n\r\n") {
                        cur.truncate(cur.len() - 2);
                    }
                    if tx.blocking_send(std::mem::take(&mut cur)).is_err() {
                        return Ok(());
                    }
                }
                started = true;
                prev_blank = false;
                continue;
            }
            if !started {
                bail!("not an mbox file (it should start with a \"From \" line)");
            }
            prev_blank = line.is_empty();
            // mboxrd: ">From " (and ">>From ") had one ">" added.
            let body = if line.starts_with(b">") && line.iter().skip_while(|&&b| b == b'>').take(5).eq(b"From ".iter()) { &line[1..] } else { &line[..] };
            cur.extend_from_slice(body);
            cur.extend_from_slice(b"\r\n");
        }
        if started && !cur.is_empty() {
            let _ = tx.blocking_send(cur);
        }
        Ok(())
    });
    let parser = mail_parser::MessageParser::default();
    while let Some(raw) = rx.recv().await {
        if super::cancelled() {
            break;
        }
        let digest = hex::encode(&Sha256::digest(&raw)[..16]);
        let (folders, flags, skip) = match header(&raw, "X-Gmail-Labels") {
            Some(l) => takeout_placement(&parse_labels(&l), t),
            None => (vec![map_folder(&default_folder.split('/').map(String::from).collect::<Vec<_>>(), None).unwrap_or_else(|| "INBOX".into())], {
                // Thunderbird's X-Mozilla-Status bit 0x0001 = read.
                let read = header(&raw, "X-Mozilla-Status").and_then(|v| u32::from_str_radix(v.trim(), 16).ok()).map(|v| v & 1 == 1).unwrap_or(true);
                if read { vec!["\\Seen".to_string()] } else { vec![] }
            }, false),
        };
        if skip {
            continue;
        }
        let date = parser.parse_headers(&raw[..]).and_then(|m| m.date().map(|d| d.to_timestamp())).unwrap_or_else(|| chrono::Utc::now().timestamp());
        let n = raw.len();
        let mut any = false;
        for f in &folders {
            let key = format!("file:{digest}:{f}");
            if t.seen(&key).await? {
                continue;
            }
            t.add_message(&key, f, raw.clone(), date, flags.clone()).await?;
            any = true;
        }
        if any {
            tick.message(n);
        } else {
            tick.skipped();
        }
    }
    reader.await?.map_err(|e| anyhow!("{}: {e:#}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn labels() {
        assert_eq!(parse_labels("Inbox,\"Work, 2026\",Opened"), vec!["Inbox", "Work, 2026", "Opened"]);
    }
    #[test]
    fn headers() {
        let raw = b"Subject: x\r\nX-Gmail-Labels: Inbox,\r\n Important\r\nFrom: a@b\r\n\r\nbody";
        assert_eq!(header(raw, "x-gmail-labels").as_deref(), Some("Inbox, Important"));
        assert_eq!(header(raw, "from").as_deref(), Some("a@b"));
    }
}
