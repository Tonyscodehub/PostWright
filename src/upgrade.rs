//! Moving to a new version on Windows, where each version is usually unzipped into a
//! folder of its own: find the previous version's settings and keep using its data, and
//! switch an installed service over to the new program.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Settings of an earlier installation: the one the installed service uses, then any
/// postwright.toml in neighbouring version folders or ProgramData. Newest wins.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn find_previous(mine: &Path) -> Option<PathBuf> {
    // Settings left in the current folder or next to the program count too.
    let mut here = vec![PathBuf::from("postwright.toml"), mine.to_path_buf()];
    let mut found: Vec<PathBuf> = Vec::new();
    found.append(&mut here);
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
    found.retain(|p| p.exists() && crate::config::Config::load(p).map(|c| c.db_path().exists()).unwrap_or(false));
    found.sort_by_key(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok());
    found.pop()
}

#[cfg_attr(not(windows), allow(dead_code))]
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

fn tidy(p: &Path) -> PathBuf {
    // "C:\\x\\.\\data" into "C:\\x\\data".
    p.components().filter(|c| !matches!(c, std::path::Component::CurDir)).collect()
}

fn same(a: &Path, b: &Path) -> bool {
    let n = |p: &Path| p.display().to_string().trim_start_matches(r"\\?\").to_ascii_lowercase();
    n(a) == n(b) || a.canonicalize().ok().zip(b.canonicalize().ok()).map(|(x, y)| x == y).unwrap_or(false)
}

/// Move an earlier version's settings file into the registry, and its mail and
/// certificates into C:\ProgramData\Postwright, so later versions find everything
/// wherever they're unzipped. The old file is kept as postwright.toml.migrated. An
/// installed service that used it is stopped for the move and switched over.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn import_legacy(prev: &Path) -> Result<()> {
    use crate::configloc::{program_data, Loc};
    let cfg = crate::config::Config::load(prev)?;
    let text = std::fs::read_to_string(prev)?;
    let mut t: toml::Table = text.parse().context("reading the earlier settings")?;

    let service_used_it = crate::service::installed_config().map(|c| same(&c, prev)).unwrap_or(false);
    let was_running = service_used_it && crate::service::state() == crate::service::State::Running;
    if was_running {
        println!("Stopping the Postwright service while its mail is moved...");
        crate::service::stop()?;
        std::thread::sleep(std::time::Duration::from_secs(2));
    }

    let home = program_data();
    std::fs::create_dir_all(&home).with_context(|| format!("creating {}", home.display()))?;
    let old_data = tidy(&cfg.data_dir);
    let new_data = home.join("data");
    let mut data = old_data.clone();
    if !old_data.starts_with(&home) && old_data.exists() && !new_data.exists() {
        match std::fs::rename(&old_data, &new_data) {
            Ok(()) => {
                println!("Moved the mail and data from {} to {}.", old_data.display(), new_data.display());
                data = new_data;
            }
            Err(e) => println!("Couldn't move {} ({e}), so Postwright keeps using it where it is.", old_data.display()),
        }
    }
    // Certificates inside the data folder moved with it; any elsewhere are copied in.
    let place = |p: &Path, name: &str| -> PathBuf {
        let p = tidy(p);
        if let Ok(rel) = p.strip_prefix(&old_data) {
            return data.join(rel);
        }
        if p.starts_with(&home) {
            return p;
        }
        let dest = data.join("tls").join(name);
        if p.exists() && !dest.exists() {
            let _ = std::fs::create_dir_all(data.join("tls"));
            let _ = std::fs::copy(&p, &dest);
        }
        if dest.exists() {
            dest
        } else {
            p
        }
    };
    let cert = place(&cfg.tls.cert, "cert.pem");
    let key = place(&cfg.tls.key, "key.pem");
    t.insert("data_dir".into(), toml::Value::String(data.display().to_string()));
    let tls = t.entry("tls").or_insert_with(|| toml::Value::Table(Default::default()));
    if let Some(tls) = tls.as_table_mut() {
        tls.insert("cert".into(), toml::Value::String(cert.display().to_string()));
        tls.insert("key".into(), toml::Value::String(key.display().to_string()));
    }
    let out = toml::to_string_pretty(&t)?;
    crate::config::Config::from_toml(&out, &home).context("checking the carried-over settings")?;
    Loc::Registry.write(&out)?;
    let kept = PathBuf::from(format!("{}.migrated", prev.display()));
    if let Err(e) = std::fs::rename(prev, &kept) {
        println!("(Couldn't rename {}: {e}. It isn't used any more.)", prev.display());
    }
    println!(
        "\nSettings from {} are now in the registry (HKEY_LOCAL_MACHINE\\{}), and Postwright keeps its data in {}.\nNew versions find them automatically, wherever they're unzipped.\n",
        prev.display(),
        crate::configloc::REG_KEY,
        home.display()
    );
    if service_used_it {
        println!("{}", crate::service::install(&Loc::Registry)?);
        if was_running {
            crate::service::start()?;
            println!("The service is running again.");
        }
    }
    Ok(())
}

/// Double-clicked a newer version while the service runs an older one: offer to switch
/// the service to this program. Returns true if it handled things.
pub fn offer_service_upgrade(config: &crate::configloc::Loc) -> Result<bool> {
    let Some(svc_exe) = crate::service::installed_exe() else { return Ok(false) };
    let me = std::env::current_exe()?;
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
