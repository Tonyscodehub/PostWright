//! Minimal namespace-aware XML tree for WebDAV request bodies.

use quick_xml::events::Event;
use quick_xml::Reader;
use std::collections::HashMap;

pub const DAV: &str = "DAV:";
pub const CALDAV: &str = "urn:ietf:params:xml:ns:caldav";
pub const CS: &str = "http://calendarserver.org/ns/";
pub const APPLE: &str = "http://apple.com/ns/ical/";

#[derive(Debug, Clone, Default)]
pub struct Elem {
    pub ns: String,
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Elem>,
    pub text: String,
}

impl Elem {
    pub fn is(&self, ns: &str, name: &str) -> bool {
        self.ns == ns && self.name == name
    }
    pub fn child(&self, ns: &str, name: &str) -> Option<&Elem> {
        self.children.iter().find(|c| c.is(ns, name))
    }
    /// Depth-first search for all descendants with this name.
    pub fn find_all<'a>(&'a self, ns: &str, name: &str, out: &mut Vec<&'a Elem>) {
        for c in &self.children {
            if c.is(ns, name) {
                out.push(c);
            }
            c.find_all(ns, name, out);
        }
    }
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

fn split(q: &str) -> (&str, &str) {
    match q.split_once(':') {
        Some((p, l)) => (p, l),
        None => ("", q),
    }
}

pub fn parse(data: &[u8]) -> Option<Elem> {
    if data.iter().all(|b| b.is_ascii_whitespace()) {
        return None;
    }
    let mut r = Reader::from_reader(data);
    r.config_mut().trim_text(true);
    let mut stack: Vec<(Elem, HashMap<String, String>)> = Vec::new();
    let mut root_ns: HashMap<String, String> = HashMap::new();
    let mut done: Option<Elem> = None;
    let mut depth = 0;
    loop {
        let ev = r.read_event().ok()?;
        let (start, empty) = match &ev {
            Event::Start(s) => (Some(s.clone()), false),
            Event::Empty(s) => (Some(s.clone()), true),
            _ => (None, false),
        };
        if let Some(s) = start {
            depth += 1;
            if depth > 64 {
                return None;
            }
            let mut ns_map = stack.last().map(|x| x.1.clone()).unwrap_or_else(|| root_ns.clone());
            let mut attrs = Vec::new();
            for a in s.attributes().flatten() {
                let k: String = { let r: &str = a.key.as_ref(); r.to_string() };
                #[allow(deprecated)]
                let v = a.unescape_value().map(|v| v.into_owned()).unwrap_or_default();
                if k == "xmlns" {
                    ns_map.insert(String::new(), v);
                } else if let Some(p) = k.strip_prefix("xmlns:") {
                    ns_map.insert(p.to_string(), v);
                } else {
                    attrs.push((split(&k).1.to_string(), v));
                }
            }
            let qn: String = { let n = s.name(); let r: &str = n.as_ref(); r.to_string() };
            let (p, l) = split(&qn);
            let el = Elem { ns: ns_map.get(p).cloned().unwrap_or_default(), name: l.to_string(), attrs, ..Default::default() };
            if empty {
                depth -= 1;
                match stack.last_mut() {
                    Some(parent) => parent.0.children.push(el),
                    None => return Some(el),
                }
            } else {
                stack.push((el, ns_map));
            }
            continue;
        }
        match ev {
            Event::End(_) => {
                depth -= 1;
                let (el, _) = stack.pop()?;
                match stack.last_mut() {
                    Some(parent) => parent.0.children.push(el),
                    None => {
                        done = Some(el);
                    }
                }
            }
            Event::Text(t) => {
                if let Some(top) = stack.last_mut() {
                    top.0.text.push_str(&t.xml10_content());
                }
            }
            Event::CData(t) => {
                if let Some(top) = stack.last_mut() {
                    { let r: &str = t.as_ref(); top.0.text.push_str(r); }
                }
            }
            Event::GeneralRef(g) => {
                if let Some(top) = stack.last_mut() {
                    if let Ok(Some(c)) = g.resolve_char_ref() {
                        top.0.text.push(c);
                    } else {
                        let name: String = { let r: &str = g.as_ref(); r.to_string() };
                        top.0.text.push_str(match name.as_str() {
                            "amp" => "&",
                            "lt" => "<",
                            "gt" => ">",
                            "quot" => "\"",
                            "apos" => "'",
                            _ => "",
                        });
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
        if done.is_some() {
            break;
        }
    }
    root_ns.clear();
    done
}

pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// Qualified element name for output, using the prefixes declared on the multistatus root.
pub fn qname(ns: &str, name: &str) -> (String, String) {
    let prefix = match ns {
        DAV => "D",
        CALDAV => "C",
        CS => "CS",
        APPLE => "A",
        _ => "",
    };
    if prefix.is_empty() {
        (format!("X:{name} xmlns:X=\"{}\"", esc(ns)), format!("X:{name}"))
    } else {
        (format!("{prefix}:{name}"), format!("{prefix}:{name}"))
    }
}

pub const MULTISTATUS_OPEN: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\" xmlns:CS=\"http://calendarserver.org/ns/\" xmlns:A=\"http://apple.com/ns/ical/\">\n";

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn propfind() {
        let x = br#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><d:displayname/><c:calendar-home-set/><x:foo xmlns:x="urn:x"/></d:prop></d:propfind>"#;
        let e = parse(x).unwrap();
        assert!(e.is(DAV, "propfind"));
        let p = e.child(DAV, "prop").unwrap();
        assert!(p.children[1].is(CALDAV, "calendar-home-set"));
        assert_eq!(p.children[2].ns, "urn:x");
        let x = br#"<C:calendar-multiget xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:prop><D:getetag/></D:prop><D:href>/dav/a&amp;b.ics</D:href></C:calendar-multiget>"#;
        let e = parse(x).unwrap();
        assert_eq!(e.child(DAV, "href").unwrap().text, "/dav/a&b.ics");
    }
}
