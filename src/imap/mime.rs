//! Lightweight MIME structure parser for IMAP: works on raw bytes and never decodes,
//! because ENVELOPE, BODYSTRUCTURE and BODY[] all return the original encoded form.

use super::parse::{istr, nstr, Section, SectionKind};

pub struct Part<'a> {
    pub raw: &'a [u8],
    /// Header block including the terminating blank line.
    pub header: &'a [u8],
    pub body: &'a [u8],
    pub headers: Vec<(String, Vec<u8>)>,
    pub ctype: String,
    pub subtype: String,
    pub params: Vec<(String, String)>,
    pub children: Vec<Part<'a>>,
    pub message: Option<Box<Part<'a>>>,
}

const MAX_DEPTH: usize = 24;

pub fn parse(raw: &[u8]) -> Part<'_> {
    parse_part(raw, ("text", "plain"), 0)
}

fn split_header(raw: &[u8]) -> usize {
    // Header ends after the first empty line (CRLF CRLF, or bare LF LF).
    if raw.starts_with(b"\r\n") {
        return 2;
    }
    if raw.starts_with(b"\n") {
        return 1;
    }
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'\n' {
            if raw[i + 1..].starts_with(b"\r\n") {
                return i + 3;
            }
            if raw[i + 1..].starts_with(b"\n") {
                return i + 2;
            }
        }
        i += 1;
    }
    raw.len()
}

pub fn header_fields(header: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    for line in header.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        if line[0] == b' ' || line[0] == b'\t' {
            if let Some(last) = out.last_mut() {
                last.1.push(b' ');
                last.1.extend_from_slice(trim(line));
            }
            continue;
        }
        if let Some(p) = line.iter().position(|&b| b == b':') {
            let name = String::from_utf8_lossy(&line[..p]).trim().to_string();
            out.push((name, trim(&line[p + 1..]).to_vec()));
        }
    }
    out
}

fn trim(b: &[u8]) -> &[u8] {
    let s = b.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(b.len());
    let e = b.iter().rposition(|c| !c.is_ascii_whitespace()).map(|x| x + 1).unwrap_or(s);
    &b[s..e]
}

/// Parse `type/subtype; a=b; c="d"`.
pub fn parse_ctype(v: &str) -> (String, String, Vec<(String, String)>) {
    let mut parts = split_params(v);
    let first = if parts.is_empty() { String::new() } else { parts.remove(0) };
    let (t, s) = first.split_once('/').unwrap_or((first.as_str(), ""));
    let params = parts
        .into_iter()
        .filter_map(|p| {
            let (k, v) = p.split_once('=')?;
            Some((k.trim().to_ascii_lowercase(), v.trim().trim_matches('"').to_string()))
        })
        .collect();
    (t.trim().to_ascii_lowercase(), s.trim().to_ascii_lowercase(), params)
}

fn split_params(v: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut comment = 0;
    let mut esc = false;
    for c in v.chars() {
        if esc {
            cur.push(c);
            esc = false;
            continue;
        }
        match c {
            '\\' if quoted => {
                esc = true;
                continue;
            }
            '"' if comment == 0 => quoted = !quoted,
            '(' if !quoted => {
                comment += 1;
                continue;
            }
            ')' if !quoted && comment > 0 => {
                comment -= 1;
                continue;
            }
            ';' if !quoted && comment == 0 => {
                out.push(cur.trim().to_string());
                cur.clear();
                continue;
            }
            _ => {}
        }
        if comment == 0 {
            cur.push(c);
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

fn parse_part<'a>(raw: &'a [u8], default: (&str, &str), depth: usize) -> Part<'a> {
    let hend = split_header(raw);
    let header = &raw[..hend];
    let body = &raw[hend..];
    let headers = header_fields(header);
    let ct = headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("Content-Type"))
        .map(|(_, v)| String::from_utf8_lossy(v).into_owned());
    let (mut ctype, mut subtype, params) = match ct {
        Some(v) => parse_ctype(&v),
        None => (default.0.into(), default.1.into(), vec![]),
    };
    if ctype.is_empty() || subtype.is_empty() {
        ctype = default.0.into();
        subtype = default.1.into();
    }
    let mut p = Part { raw, header, body, headers, ctype, subtype, params, children: vec![], message: None };
    if depth >= MAX_DEPTH {
        return p;
    }
    if p.ctype == "multipart" {
        if let Some(b) = p.params.iter().find(|(k, _)| k == "boundary").map(|(_, v)| v.clone()) {
            let child_default = if p.subtype == "digest" { ("message", "rfc822") } else { ("text", "plain") };
            for chunk in split_multipart(body, b.as_bytes()) {
                p.children.push(parse_part(chunk, child_default, depth + 1));
            }
        }
        if p.children.is_empty() {
            // Malformed multipart: treat as opaque text.
            p.ctype = "text".into();
            p.subtype = "plain".into();
        }
    } else if p.ctype == "message" && (p.subtype == "rfc822" || p.subtype == "global") {
        p.message = Some(Box::new(parse_part(body, ("text", "plain"), depth + 1)));
    }
    p
}

fn split_multipart<'a>(body: &'a [u8], boundary: &[u8]) -> Vec<&'a [u8]> {
    let mut delim = b"--".to_vec();
    delim.extend_from_slice(boundary);
    let mut starts: Vec<(usize, usize, bool)> = Vec::new(); // (line start, content start, is_close)
    let mut i = 0;
    while i < body.len() {
        let line_end = body[i..].iter().position(|&b| b == b'\n').map(|p| i + p + 1).unwrap_or(body.len());
        let line = &body[i..line_end];
        if line.starts_with(&delim) {
            let rest = &line[delim.len()..];
            let close = rest.starts_with(b"--");
            let tail = if close { &rest[2..] } else { rest };
            if tail.iter().all(|c| c.is_ascii_whitespace()) {
                starts.push((i, line_end, close));
                if close {
                    break;
                }
            }
        }
        i = line_end;
    }
    let mut parts = Vec::new();
    for w in starts.windows(2) {
        let (_, content_start, close) = w[0];
        if close {
            break;
        }
        let mut end = w[1].0;
        // The CRLF before a delimiter belongs to the delimiter.
        if end > content_start && body[end - 1] == b'\n' {
            end -= 1;
            if end > content_start && body[end - 1] == b'\r' {
                end -= 1;
            }
        }
        parts.push(&body[content_start..end.max(content_start)]);
    }
    parts
}

impl<'a> Part<'a> {
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_slice())
    }

    fn header_str(&self, name: &str) -> Option<String> {
        self.header(name).map(|v| String::from_utf8_lossy(v).into_owned())
    }

    pub fn is_multipart(&self) -> bool {
        !self.children.is_empty()
    }

    fn child(&self, n: u32) -> Option<&Part<'a>> {
        if self.is_multipart() {
            self.children.get(n as usize - 1)
        } else if n == 1 {
            Some(self)
        } else {
            None
        }
    }

    pub fn find(&self, path: &[u32]) -> Option<&Part<'a>> {
        let mut cur = self;
        for (i, &n) in path.iter().enumerate() {
            let base: &Part = if i == 0 { cur } else { cur.message.as_deref().unwrap_or(cur) };
            cur = base.child(n)?;
        }
        Some(cur)
    }

    /// Extract the bytes for a BODY[section] fetch.
    pub fn section(&self, s: &Section) -> Vec<u8> {
        let Some(part) = self.find(&s.path) else { return Vec::new() };
        // For HEADER/TEXT variants on a sub-part, the target is the encapsulated message.
        let msg: &Part = if s.path.is_empty() { self } else { part.message.as_deref().unwrap_or(part) };
        match &s.kind {
            SectionKind::Full => {
                if s.path.is_empty() {
                    self.raw.to_vec()
                } else {
                    part.body.to_vec()
                }
            }
            SectionKind::Mime => part.header.to_vec(),
            SectionKind::Header => msg.header.to_vec(),
            SectionKind::Text => msg.body.to_vec(),
            SectionKind::HeaderFields(f) => filter_headers(msg.header, f, true),
            SectionKind::HeaderFieldsNot(f) => filter_headers(msg.header, f, false),
        }
    }

    pub fn envelope(&self, out: &mut Vec<u8>) {
        out.push(b'(');
        nstr(out, self.header("Date"));
        out.push(b' ');
        nstr(out, self.header("Subject"));
        let from = self.header("From");
        for name in ["From", "Sender", "Reply-To", "To", "Cc", "Bcc"] {
            out.push(b' ');
            let v = self.header(name).or(if name == "Sender" || name == "Reply-To" { from } else { None });
            addresses(out, v);
        }
        out.push(b' ');
        nstr(out, self.header("In-Reply-To"));
        out.push(b' ');
        nstr(out, self.header("Message-ID"));
        out.push(b')');
    }

    pub fn bodystructure(&self, out: &mut Vec<u8>, extended: bool) {
        out.push(b'(');
        if self.is_multipart() {
            for c in &self.children {
                c.bodystructure(out, extended);
            }
            out.push(b' ');
            istr(out, self.subtype.to_ascii_uppercase().as_bytes());
            if extended {
                out.push(b' ');
                params(out, &self.params);
                out.push(b' ');
                self.disposition(out);
                out.push(b' ');
                nstr(out, self.header("Content-Language"));
                out.push(b' ');
                nstr(out, self.header("Content-Location"));
            }
        } else {
            istr(out, self.ctype.to_ascii_uppercase().as_bytes());
            out.push(b' ');
            istr(out, self.subtype.to_ascii_uppercase().as_bytes());
            out.push(b' ');
            let mut p = self.params.clone();
            if self.ctype == "text" && !p.iter().any(|(k, _)| k == "charset") {
                p.push(("charset".into(), "us-ascii".into()));
            }
            params(out, &p);
            out.push(b' ');
            nstr(out, self.header("Content-ID"));
            out.push(b' ');
            nstr(out, self.header("Content-Description"));
            out.push(b' ');
            let enc = self.header_str("Content-Transfer-Encoding").unwrap_or_else(|| "7BIT".into());
            istr(out, enc.trim().to_ascii_uppercase().as_bytes());
            out.extend_from_slice(format!(" {}", self.body.len()).as_bytes());
            if let Some(m) = &self.message {
                out.push(b' ');
                m.envelope(out);
                out.push(b' ');
                m.bodystructure(out, extended);
                out.extend_from_slice(format!(" {}", count_lines(self.body)).as_bytes());
            } else if self.ctype == "text" {
                out.extend_from_slice(format!(" {}", count_lines(self.body)).as_bytes());
            }
            if extended {
                out.push(b' ');
                nstr(out, self.header("Content-MD5"));
                out.push(b' ');
                self.disposition(out);
                out.push(b' ');
                nstr(out, self.header("Content-Language"));
                out.push(b' ');
                nstr(out, self.header("Content-Location"));
            }
        }
        out.push(b')');
    }

    fn disposition(&self, out: &mut Vec<u8>) {
        match self.header_str("Content-Disposition") {
            Some(v) => {
                let parts = split_params(&v);
                let kind = parts.first().cloned().unwrap_or_default();
                let ps: Vec<(String, String)> = parts[1..]
                    .iter()
                    .filter_map(|p| {
                        let (k, v) = p.split_once('=')?;
                        Some((k.trim().to_ascii_lowercase(), v.trim().trim_matches('"').to_string()))
                    })
                    .collect();
                out.push(b'(');
                istr(out, kind.to_ascii_uppercase().as_bytes());
                out.push(b' ');
                params(out, &ps);
                out.push(b')');
            }
            None => out.extend_from_slice(b"NIL"),
        }
    }
}

fn params(out: &mut Vec<u8>, p: &[(String, String)]) {
    if p.is_empty() {
        out.extend_from_slice(b"NIL");
        return;
    }
    out.push(b'(');
    for (i, (k, v)) in p.iter().enumerate() {
        if i > 0 {
            out.push(b' ');
        }
        istr(out, k.to_ascii_uppercase().as_bytes());
        out.push(b' ');
        istr(out, v.as_bytes());
    }
    out.push(b')');
}

fn count_lines(b: &[u8]) -> usize {
    let n = b.iter().filter(|&&c| c == b'\n').count();
    if !b.is_empty() && !b.ends_with(b"\n") {
        n + 1
    } else {
        n
    }
}

fn filter_headers(header: &[u8], fields: &[String], include: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut keep = false;
    for line in header.split_inclusive(|&b| b == b'\n') {
        let bare = line.strip_suffix(b"\n").unwrap_or(line);
        let bare = bare.strip_suffix(b"\r").unwrap_or(bare);
        if bare.is_empty() {
            continue;
        }
        if bare[0] != b' ' && bare[0] != b'\t' {
            let name = bare.iter().position(|&b| b == b':').map(|p| String::from_utf8_lossy(&bare[..p]).trim().to_ascii_uppercase());
            keep = match name {
                Some(n) => fields.contains(&n) == include,
                None => false,
            };
        }
        if keep {
            out.extend_from_slice(line);
        }
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Parse an address-list header into IMAP address structures.
fn addresses(out: &mut Vec<u8>, v: Option<&[u8]>) {
    let Some(v) = v else {
        out.extend_from_slice(b"NIL");
        return;
    };
    let s = String::from_utf8_lossy(v);
    let list = split_addresses(&s);
    if list.is_empty() {
        out.extend_from_slice(b"NIL");
        return;
    }
    out.push(b'(');
    for (name, addr) in list {
        let (mbox, host) = match addr.rsplit_once('@') {
            Some((m, h)) => (m.to_string(), Some(h.to_string())),
            None => (addr.clone(), None),
        };
        out.push(b'(');
        nstr(out, name.as_deref().map(|n| n.as_bytes()));
        out.extend_from_slice(b" NIL ");
        istr(out, mbox.as_bytes());
        out.push(b' ');
        nstr(out, host.as_deref().map(|h| h.as_bytes()));
        out.push(b')');
    }
    out.push(b')');
}

pub fn split_addresses(s: &str) -> Vec<(Option<String>, String)> {
    let mut items = Vec::new();
    let mut cur = String::new();
    let (mut q, mut angle, mut paren) = (false, false, 0);
    for c in s.chars() {
        match c {
            '"' if paren == 0 => q = !q,
            '<' if !q && paren == 0 => angle = true,
            '>' if !q && paren == 0 => angle = false,
            '(' if !q => paren += 1,
            ')' if !q && paren > 0 => paren -= 1,
            // Group syntax "Name: a, b;" – flatten the group.
            ':' if !q && !angle && paren == 0 && !cur.contains('@') => {
                cur.clear();
                continue;
            }
            ',' | ';' if !q && !angle && paren == 0 => {
                items.push(std::mem::take(&mut cur));
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    items.push(cur);
    items
        .into_iter()
        .filter_map(|it| {
            let it = it.trim();
            if it.is_empty() {
                return None;
            }
            if let (Some(a), Some(b)) = (it.find('<'), it.rfind('>')) {
                let addr = it[a + 1..b].trim().to_string();
                let name = strip_comments(&it[..a]).trim().trim_matches('"').trim().to_string();
                Some((if name.is_empty() { None } else { Some(name) }, addr))
            } else {
                // "addr (Name)" form.
                let name = it.find('(').and_then(|a| it.rfind(')').map(|b| it[a + 1..b].trim().to_string()));
                Some((name.filter(|n| !n.is_empty()), strip_comments(it).trim().to_string()))
            }
        })
        .collect()
}

fn strip_comments(s: &str) -> String {
    let mut out = String::new();
    let mut depth = 0;
    for c in s.chars() {
        match c {
            '(' => depth += 1,
            ')' if depth > 0 => depth -= 1,
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSG: &[u8] = b"From: \"Tony J\" <tony@example.com>\r\nTo: a@b.com, Bob <bob@c.org>\r\nSubject: Hi\r\nContent-Type: multipart/mixed; boundary=\"XX\"\r\n\r\npreamble\r\n--XX\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello\r\nworld\r\n--XX\r\nContent-Type: application/pdf; name=a.pdf\r\nContent-Disposition: attachment; filename=\"a.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\nQUJD\r\n--XX--\r\n";

    #[test]
    fn structure() {
        let p = parse(MSG);
        assert_eq!(p.children.len(), 2);
        assert_eq!(p.children[0].body, b"Hello\r\nworld");
        assert_eq!(p.children[1].body, b"QUJD");
        let s = Section { path: vec![2], kind: SectionKind::Full };
        assert_eq!(p.section(&s), b"QUJD");
        let s = Section { path: vec![], kind: SectionKind::HeaderFields(vec!["SUBJECT".into()]) };
        assert_eq!(p.section(&s), b"Subject: Hi\r\n\r\n");
        let mut bs = Vec::new();
        p.bodystructure(&mut bs, true);
        let bs = String::from_utf8(bs).unwrap();
        assert!(bs.starts_with("((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"utf-8\") NIL NIL \"7BIT\" 12 2"), "{bs}");
        assert!(bs.contains("(\"ATTACHMENT\" (\"FILENAME\" \"a.pdf\"))"), "{bs}");
        let mut env = Vec::new();
        p.envelope(&mut env);
        let env = String::from_utf8(env).unwrap();
        assert!(env.contains("((\"Tony J\" NIL \"tony\" \"example.com\"))"), "{env}");
        assert!(env.contains("((NIL NIL \"a\" \"b.com\")(\"Bob\" NIL \"bob\" \"c.org\"))"), "{env}");
    }
}
