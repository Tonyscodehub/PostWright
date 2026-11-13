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

/// A writer that sends each log line to stdout and the ring buffer.
pub struct Tee;

impl Write for Tee {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::stdout().write_all(buf)?;
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
        std::io::stdout().flush()
    }
}
