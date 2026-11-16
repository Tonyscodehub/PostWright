//! Moving to a new version on Windows, where each version is usually unzipped into a
//! folder of its own: find the previous version's settings and keep using its data, and
//! switch an installed service over to the new program.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Settings of an earlier installation: the one the installed service uses, then any
/// postwright.toml in neighbouring version folders or ProgramData. Newest wins.
pub fn find_previous(mine: &Path) -> Option<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    if let Some(p) = crate::service::installed_config() {
        found.push(p);
    }
    if let Some(pd) = std::env::var_os("ProgramData") {
        found.push(PathBuf::from(pd).join("Postwright").join("postwright.toml"));
    }
    // Up to two levels above this folder (e.g. C:\postwright\postwright-0.5.5\windows),
    // searching a few levels down.
    let mut roots = Vec::new();
    let mut d = mine.parent().map(Path::to_path_buf);
    for _ in 0..3 {
        if let Some(x) = d.clone() {
            roots.push(x.clone());
            d = x.parent().map(Path::to_path_buf);
        }
    }
    if let Some(top) = roots.last().cloned() {
        walk(&top, 0, &mut found);
    }
    found.retain(|p| p.exists() && p != mine && crate::config::Config::load(p).map(|c| c.db_path().exists()).unwrap_or(false));
    found.sort_by_key(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok());
    found.pop()
}

fn walk(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > 3 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
            if depth == 0 || name.contains("postwright") || name == "windows" || name == "linux" {
                walk(&p, depth + 1, out);
            }
        } else if p.file_name().map(|n| n == "postwright.toml").unwrap_or(false) {
            out.push(p);
        }
    }
}

/// Write settings for this version that point at the previous version's data, wherever
/// it is. Everything else is copied unchanged.
pub fn adopt(prev: &Path, mine: &Path) -> Result<()> {
    let mut cfg = crate::config::Config::load(prev)?;
    // Tidy "C:\x\./data" into "C:\x\data".
    let tidy = |p: &Path| -> PathBuf { p.components().filter(|c| !matches!(c, std::path::Component::CurDir)).collect() };
    cfg.data_dir = tidy(&cfg.data_dir);
    cfg.tls.cert = tidy(&cfg.tls.cert);
    cfg.tls.key = tidy(&cfg.tls.key);
    let text = std::fs::read_to_string(prev)?;
    let mut t: toml::Table = text.parse().context("reading the earlier settings")?;
    t.insert("data_dir".into(), toml::Value::String(cfg.data_dir.display().to_string()));
    let tls = t.entry("tls").or_insert_with(|| toml::Value::Table(Default::default()));
    if let Some(tls) = tls.as_table_mut() {
        tls.insert("cert".into(), toml::Value::String(cfg.tls.cert.display().to_string()));
        tls.insert("key".into(), toml::Value::String(cfg.tls.key.display().to_string()));
    }
    let out = format!(
        "# Postwright configuration, carried over from {} by version {}.\n{}",
        prev.display(),
        env!("CARGO_PKG_VERSION"),
        toml::to_string_pretty(&t)?
    );
    std::fs::write(mine, out)?;
    crate::config::Config::load(mine).context("checking the carried-over settings")?;
    Ok(())
}

/// Double-clicked a newer version while the service runs an older one: offer to switch
/// the service to this program. Returns true if it handled things.
pub fn offer_service_upgrade(config: &Path) -> Result<bool> {
    let Some(svc_exe) = crate::service::installed_exe() else { return Ok(false) };
    let me = std::env::current_exe()?;
    let same = |a: &Path, b: &Path| {
        let n = |p: &Path| p.display().to_string().trim_start_matches(r"\\?\").to_ascii_lowercase();
        n(a) == n(b) || a.canonicalize().ok().zip(b.canonicalize().ok()).map(|(x, y)| x == y).unwrap_or(false)
    };
    if same(&svc_exe, &me) || !config.exists() {
        return Ok(false);
    }
    println!(
        "\nThe Postwright service is running an older copy:\n  {}\n\nSwitch the service to this version ({}) now? It will be stopped for a few seconds. [Y/n] ",
        svc_exe.display(),
        env!("CARGO_PKG_VERSION")
    );
    let mut ans = String::new();
    let _ = std::io::stdin().read_line(&mut ans);
    if ans.trim().to_ascii_lowercase().starts_with('n') {
        return Ok(false);
    }
    crate::service::stop()?;
    std::thread::sleep(std::time::Duration::from_secs(2));
    println!("{}", crate::service::install(config)?);
    crate::service::start()?;
    println!("\nDone: the service now runs version {}. Press Enter to close.", env!("CARGO_PKG_VERSION"));
    let _ = std::io::stdin().read_line(&mut String::new());
    Ok(true)
}
