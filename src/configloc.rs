//! Where Postwright keeps its settings.
//!
//! * Windows: the registry, under HKEY_LOCAL_MACHINE\SOFTWARE\Postwright. Mail, logs and
//!   certificates live in C:\ProgramData\Postwright, so nothing depends on the folder the
//!   program was unzipped into.
//! * Linux: /etc/postwright/postwright.toml, with data in /var/lib/postwright. Someone
//!   running it without root gets ~/.config/postwright and ~/.local/share/postwright.
//! * Anywhere: `-c FILE` uses that settings file instead, as earlier versions did.
//!
//! The registry holds the same settings as the file: each [section] is a subkey, text is
//! REG_SZ, lists of text are REG_MULTI_SZ, on/off settings (0 or 1) and whole numbers are
//! REG_DWORD, decimals are REG_SZ, and a list of sections is a subkey with one numbered
//! subkey per item. Settings that aren't there take their defaults.

use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const REG_KEY: &str = r"SOFTWARE\Postwright";
#[cfg(unix)]
pub const ETC_FILE: &str = "/etc/postwright/postwright.toml";
#[cfg(unix)]
pub const VAR_DIR: &str = "/var/lib/postwright";

/// Where the running server's settings came from (for saving changes made in the
/// admin console).
pub static ACTIVE: std::sync::OnceLock<Loc> = std::sync::OnceLock::new();

#[derive(Clone, Debug, PartialEq)]
pub enum Loc {
    File(PathBuf),
    Registry,
}

impl Loc {
    /// The standard place for this platform, ignoring any earlier layout.
    pub fn standard() -> Loc {
        #[cfg(windows)]
        {
            Loc::Registry
        }
        #[cfg(unix)]
        {
            let etc = PathBuf::from(ETC_FILE);
            if etc.exists() || is_root() {
                return Loc::File(etc);
            }
            Loc::File(user_config_dir().join("postwright.toml"))
        }
    }

    pub fn exists(&self) -> bool {
        match self {
            Loc::File(p) => p.exists(),
            Loc::Registry => read_registry().ok().flatten().map(|n| !n.values.is_empty() || !n.keys.is_empty()).unwrap_or(false),
        }
    }

    /// The settings as TOML text.
    pub fn read(&self) -> Result<String> {
        match self {
            Loc::File(p) => std::fs::read_to_string(p).with_context(|| format!("reading config {}", p.display())),
            Loc::Registry => {
                let node = read_registry()?.ok_or_else(|| anyhow::anyhow!("no settings in the registry yet (HKLM\\{REG_KEY})"))?;
                let schema = toml::Table::try_from(crate::config::Config::default()).unwrap_or_default();
                Ok(toml::to_string_pretty(&from_reg(&node, Some(&schema))?)?)
            }
        }
    }

    /// Replace the settings. The text must already have been checked.
    pub fn write(&self, text: &str) -> Result<()> {
        match self {
            Loc::File(p) => {
                if let Some(d) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
                    std::fs::create_dir_all(d).with_context(|| format!("creating {}", d.display()))?;
                }
                let new = !p.exists();
                std::fs::write(p, text).with_context(|| format!("writing {}", p.display()))?;
                // Settings can hold passwords (scanner controllers and the like), so a new
                // file isn't world-readable. An existing file keeps the owner and mode it has.
                #[cfg(unix)]
                if new {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o640));
                }
                #[cfg(not(unix))]
                let _ = new;
                Ok(())
            }
            Loc::Registry => {
                let t: toml::Table = text.parse().context("parsing settings")?;
                write_registry(&to_reg(&t)?)?;
                // A plain copy for disaster recovery ("postwright config import").
                let home = self.data_home();
                let _ = std::fs::create_dir_all(&home);
                let _ = std::fs::write(
                    home.join("settings-backup.toml"),
                    format!("# Copy of the settings in HKLM\\{REG_KEY}, for reference and recovery only.\n# Postwright reads the registry, not this file. To restore it: postwright config import <file>\n{text}"),
                );
                Ok(())
            }
        }
    }

    /// Relative paths in the settings are relative to this folder.
    pub fn base_dir(&self) -> PathBuf {
        match self {
            Loc::File(p) => p.parent().map(Path::to_path_buf).unwrap_or_default(),
            Loc::Registry => self.data_home(),
        }
    }

    /// Where mail, certificates, logs and the setup code go for a new installation.
    pub fn data_home(&self) -> PathBuf {
        match self {
            Loc::Registry => program_data(),
            Loc::File(p) => {
                #[cfg(unix)]
                {
                    if p == Path::new(ETC_FILE) {
                        return PathBuf::from(VAR_DIR);
                    }
                    if Some(p.as_path()) == Some(user_config_dir().join("postwright.toml").as_path()) {
                        return user_data_dir();
                    }
                }
                p.parent().filter(|d| !d.as_os_str().is_empty()).map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."))
            }
        }
    }

    /// The data folder a new installation should use.
    pub fn new_data_dir(&self) -> PathBuf {
        match self {
            Loc::Registry => program_data().join("data"),
            Loc::File(_) if self.is_standard() => self.data_home(),
            // Portable: next to the settings file, as before.
            Loc::File(_) => PathBuf::from("data"),
        }
    }

    pub fn is_standard(&self) -> bool {
        *self == Loc::standard() || matches!(self, Loc::Registry)
    }

    pub fn describe(&self) -> String {
        match self {
            Loc::File(p) => std::path::absolute(p).unwrap_or(p.clone()).display().to_string(),
            Loc::Registry => format!("HKEY_LOCAL_MACHINE\\{REG_KEY} (registry)"),
        }
    }

    pub fn file(&self) -> Option<&Path> {
        match self {
            Loc::File(p) => Some(p),
            Loc::Registry => None,
        }
    }
}

pub fn program_data() -> PathBuf {
    std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData")).join("Postwright")
}

#[cfg(unix)]
fn is_root() -> bool {
    std::fs::metadata("/proc/self").map(|m| std::os::unix::fs::MetadataExt::uid(&m) == 0).unwrap_or(false)
}

#[cfg(unix)]
fn home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(unix)]
fn user_config_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()).map(PathBuf::from).unwrap_or_else(|| home().join(".config")).join("postwright")
}

#[cfg(unix)]
fn user_data_dir() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()).map(PathBuf::from).unwrap_or_else(|| home().join(".local/share")).join("postwright")
}

// ------------------------------------------------------------ registry form

#[derive(Clone, Debug, PartialEq)]
pub enum RegVal {
    Sz(String),
    MultiSz(Vec<String>),
    Dword(u32),
    Qword(u64),
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct RegNode {
    pub values: BTreeMap<String, RegVal>,
    pub keys: BTreeMap<String, RegNode>,
}

pub fn to_reg(t: &toml::Table) -> Result<RegNode> {
    let mut n = RegNode::default();
    for (k, v) in t {
        match v {
            toml::Value::Table(sub) => {
                n.keys.insert(k.clone(), to_reg(sub)?);
            }
            toml::Value::String(s) => {
                n.values.insert(k.clone(), RegVal::Sz(s.clone()));
            }
            toml::Value::Boolean(b) => {
                n.values.insert(k.clone(), RegVal::Dword(*b as u32));
            }
            // DWORD where it fits, as regedit users expect; QWORD otherwise.
            toml::Value::Integer(i) => {
                let v = u32::try_from(*i).map(RegVal::Dword).unwrap_or(RegVal::Qword(*i as u64));
                n.values.insert(k.clone(), v);
            }
            toml::Value::Float(f) => {
                n.values.insert(k.clone(), RegVal::Sz(f.to_string()));
            }
            // A list of sections: a subkey per item, named 1, 2, 3...
            toml::Value::Array(a) if !a.is_empty() && a.iter().all(|x| x.is_table()) => {
                let mut list = RegNode::default();
                for (i, x) in a.iter().enumerate() {
                    list.keys.insert(format!("{}", i + 1), to_reg(x.as_table().unwrap())?);
                }
                n.keys.insert(k.clone(), list);
            }
            toml::Value::Array(a) => {
                let mut list = Vec::new();
                for x in a {
                    match x.as_str() {
                        Some(s) if !s.is_empty() => list.push(s.to_string()),
                        Some(_) => {}
                        None => bail!("setting \"{k}\": only lists of text or of sections can be kept in the registry"),
                    }
                }
                n.values.insert(k.clone(), RegVal::MultiSz(list));
            }
            other => bail!("setting \"{k}\": a {} can't be kept in the registry", other.type_str()),
        }
    }
    Ok(n)
}

/// Back to settings. `schema` (the defaults) says which type a value should be, so a
/// value someone typed into regedit as the "wrong" kind still works.
pub fn from_reg(n: &RegNode, schema: Option<&toml::Table>) -> Result<toml::Table> {
    let mut t = toml::Table::new();
    for (k, v) in &n.values {
        let want = schema.and_then(|s| s.get(k));
        let val = match (v, want) {
            (RegVal::Sz(s), Some(toml::Value::Integer(_))) => {
                toml::Value::Integer(s.trim().parse().with_context(|| format!("setting \"{k}\" should be a number, not \"{s}\""))?)
            }
            (RegVal::Sz(s), Some(toml::Value::Float(_))) => {
                toml::Value::Float(s.trim().parse().with_context(|| format!("setting \"{k}\" should be a number, not \"{s}\""))?)
            }
            (RegVal::Dword(d), Some(toml::Value::Float(_))) => toml::Value::Float(*d as f64),
            (RegVal::Qword(q), Some(toml::Value::Float(_))) => toml::Value::Float(*q as f64),
            (RegVal::Sz(s), Some(toml::Value::Boolean(_))) => toml::Value::Boolean(matches!(s.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")),
            (RegVal::Sz(s), Some(toml::Value::Array(_))) => {
                toml::Value::Array(s.split([',', ';', '\n']).map(str::trim).filter(|x| !x.is_empty()).map(|x| toml::Value::String(x.into())).collect())
            }
            (RegVal::Sz(s), _) => toml::Value::String(s.clone()),
            (RegVal::MultiSz(l), _) => toml::Value::Array(l.iter().map(|s| toml::Value::String(s.clone())).collect()),
            (RegVal::Dword(d), Some(toml::Value::Integer(_))) => toml::Value::Integer(*d as i64),
            (RegVal::Dword(d), Some(toml::Value::String(_))) => toml::Value::String(d.to_string()),
            (RegVal::Dword(d), None) if *d > 1 => toml::Value::Integer(*d as i64),
            (RegVal::Dword(d), _) => toml::Value::Boolean(*d != 0),
            (RegVal::Qword(q), Some(toml::Value::Boolean(_))) => toml::Value::Boolean(*q != 0),
            (RegVal::Qword(q), Some(toml::Value::String(_))) => toml::Value::String(q.to_string()),
            (RegVal::Qword(q), _) => toml::Value::Integer(*q as i64),
        };
        t.insert(k.clone(), val);
    }
    for (k, sub) in &n.keys {
        let want = schema.and_then(|s| s.get(k));
        let numbered = sub.values.is_empty() && !sub.keys.is_empty() && sub.keys.keys().all(|x| x.parse::<u32>().is_ok());
        let val = match want {
            Some(toml::Value::Array(items)) => Some(items.iter().find_map(|x| x.as_table())),
            None if numbered => Some(None),
            _ => None,
        };
        let v = match val {
            Some(item_schema) => {
                let mut items: Vec<(u32, &RegNode)> = sub.keys.iter().filter_map(|(n, x)| n.parse().ok().map(|n| (n, x))).collect();
                items.sort_by_key(|x| x.0);
                toml::Value::Array(items.into_iter().map(|(_, x)| from_reg(x, item_schema).map(toml::Value::Table)).collect::<Result<_>>()?)
            }
            None => toml::Value::Table(from_reg(sub, want.and_then(|v| v.as_table()))?),
        };
        t.insert(k.clone(), v);
    }
    Ok(t)
}

#[cfg(windows)]
fn read_registry() -> Result<Option<RegNode>> {
    win::read(REG_KEY)
}
#[cfg(windows)]
fn write_registry(n: &RegNode) -> Result<()> {
    win::write(REG_KEY, n)
}
#[cfg(not(windows))]
fn read_registry() -> Result<Option<RegNode>> {
    Ok(None)
}
#[cfg(not(windows))]
fn write_registry(_: &RegNode) -> Result<()> {
    bail!("the registry is only used on Windows")
}

#[cfg(windows)]
pub mod win {
    use super::{RegNode, RegVal};
    use anyhow::{Context, Result};
    use winreg::enums::*;
    use winreg::types::FromRegValue;
    use winreg::RegKey;

    fn denied(e: std::io::Error) -> anyhow::Error {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            anyhow::anyhow!("Windows refused to change the settings in the registry: start Postwright with \"Run as administrator\"")
        } else {
            e.into()
        }
    }

    pub fn read_in(root: &RegKey, path: &str) -> Result<Option<RegNode>> {
        match root.open_subkey(path) {
            Ok(k) => Ok(Some(node(&k)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).context("reading the settings from the registry"),
        }
    }

    pub fn read(path: &str) -> Result<Option<RegNode>> {
        read_in(&RegKey::predef(HKEY_LOCAL_MACHINE), path)
    }

    fn node(k: &RegKey) -> Result<RegNode> {
        let mut n = RegNode::default();
        for item in k.enum_values() {
            let (name, raw) = item?;
            let v = match raw.vtype {
                REG_SZ | REG_EXPAND_SZ => RegVal::Sz(String::from_reg_value(&raw)?),
                REG_MULTI_SZ => RegVal::MultiSz(Vec::<String>::from_reg_value(&raw)?),
                REG_DWORD => RegVal::Dword(u32::from_reg_value(&raw)?),
                REG_QWORD => RegVal::Qword(u64::from_reg_value(&raw)?),
                _ => continue,
            };
            n.values.insert(name, v);
        }
        for name in k.enum_keys() {
            let name = name?;
            let sub = k.open_subkey(&name)?;
            n.keys.insert(name, node(&sub)?);
        }
        Ok(n)
    }

    /// Replace everything under `path` with `n` (other subkeys of HKLM\SOFTWARE are
    /// untouched).
    pub fn write_in(root: &RegKey, path: &str, n: &RegNode) -> Result<()> {
        let (k, _) = root.create_subkey(path).map_err(denied)?;
        clear(&k).map_err(denied)?;
        put(&k, n).map_err(denied)
    }

    pub fn write(path: &str, n: &RegNode) -> Result<()> {
        write_in(&RegKey::predef(HKEY_LOCAL_MACHINE), path, n)
    }

    fn clear(k: &RegKey) -> std::io::Result<()> {
        let names: Vec<String> = k.enum_values().filter_map(|v| v.ok().map(|v| v.0)).collect();
        for n in names {
            k.delete_value(&n)?;
        }
        let keys: Vec<String> = k.enum_keys().filter_map(|v| v.ok()).collect();
        for n in keys {
            k.delete_subkey_all(&n)?;
        }
        Ok(())
    }

    fn put(k: &RegKey, n: &RegNode) -> std::io::Result<()> {
        for (name, v) in &n.values {
            match v {
                RegVal::Sz(s) => k.set_value(name, s)?,
                RegVal::MultiSz(l) => k.set_value(name, l)?,
                RegVal::Dword(d) => k.set_value(name, d)?,
                RegVal::Qword(q) => k.set_value(name, q)?,
            }
        }
        for (name, sub) in &n.keys {
            let (s, _) = k.create_subkey(name)?;
            put(&s, sub)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let cfg = crate::config::Config::default();
        let t = toml::Table::try_from(&cfg).unwrap();
        let back = from_reg(&to_reg(&t).unwrap(), Some(&t)).unwrap();
        // Empty strings in lists can't be stored, but the defaults have none.
        assert_eq!(t, back);
        let reparsed: crate::config::Config = toml::from_str(&toml::to_string(&back).unwrap()).unwrap();
        assert_eq!(toml::to_string(&reparsed).unwrap(), toml::to_string(&cfg).unwrap());
    }

    #[test]
    fn hand_edits() {
        let schema = toml::Table::try_from(crate::config::Config::default()).unwrap();
        let mut n = RegNode::default();
        n.values.insert("hostname".into(), RegVal::Sz("mail.example.org".into()));
        let mut sec = RegNode::default();
        // Typed into regedit as a DWORD and a comma list.
        sec.values.insert("admin_networks".into(), RegVal::Sz("10.0.0.0/8, 192.168.0.0/16".into()));
        sec.values.insert("require_mfa_for_admins".into(), RegVal::Dword(1));
        n.keys.insert("security".into(), sec);
        let t = from_reg(&n, Some(&schema)).unwrap();
        let cfg: crate::config::Config = toml::from_str(&toml::to_string(&t).unwrap()).unwrap();
        assert_eq!(cfg.hostname, "mail.example.org");
        assert_eq!(cfg.security.admin_networks, vec!["10.0.0.0/8", "192.168.0.0/16"]);
        assert!(cfg.security.require_mfa_for_admins);
    }

    #[test]
    fn integers_survive() {
        let t: toml::Table = "[limits]\nmax_message_size = 52428800\nflag = true\n".parse().unwrap();
        let back = from_reg(&to_reg(&t).unwrap(), None).unwrap();
        assert_eq!(t, back);
    }
}
