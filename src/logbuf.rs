//! Keeps the most recent log lines in memory for the admin console.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::Mutex;

const MAX_LINES: usize = 2000;
static LINES: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

pub fn recent(n: usize, filter: Option<&str>) -> Vec<String> {
    let l = LINES.lock().unwrap();
    let f = filter.map(|f| f.to_ascii_lowercase());
    let mut v: Vec<String> = l
        .iter()
        .rev()
        .filter(|line| f.as_ref().map(|f| line.to_ascii_lowercase().contains(f)).unwrap_or(true))
        .take(n)
        .cloned()
        .collect();
    v.reverse();
    v
}

static FILE: Mutex<Option<(std::path::PathBuf, std::fs::File)>> = Mutex::new(None);

/// Also write the log to a file (used when running as a Windows service, which has no
/// console). Rotated to .old at 10 MB.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn log_to_file(path: &std::path::Path) {
    if let Ok(f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        *FILE.lock().unwrap() = Some((path.to_path_buf(), f));
    }
}

pub fn write_line(line: &str) {
    let _ = Tee.write_all(format!("{} {line}\n", chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ")).as_bytes());
}

/// A writer that sends each log line to stdout and the ring buffer.
pub struct Tee;

impl Write for Tee {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let _ = std::io::stdout().write_all(buf);
        if let Some((path, f)) = FILE.lock().unwrap().as_mut() {
            let _ = f.write_all(buf);
            if f.metadata().map(|m| m.len() > 10 * 1024 * 1024).unwrap_or(false) {
                let old = path.with_extension("log.old");
                let _ = std::fs::rename(&*path, &old);
                if let Ok(n) = std::fs::OpenOptions::new().create(true).append(true).open(&*path) {
                    *f = n;
                }
            }
        }
        let text = String::from_utf8_lossy(buf);
        let mut l = LINES.lock().unwrap();
        for line in text.lines().filter(|x| !x.trim().is_empty()) {
            if l.len() >= MAX_LINES {
                l.pop_front();
            }
            l.push_back(line.to_string());
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        let _ = std::io::stdout().flush();
        Ok(())
    }
}
