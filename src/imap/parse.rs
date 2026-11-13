//! IMAP command tokenizer, sequence sets and FETCH attribute parsing.

use anyhow::{anyhow, bail, Result};

#[derive(Debug, Clone, PartialEq)]
pub enum Tok {
    Atom(String),
    Str(Vec<u8>),
    List(Vec<Tok>),
}

impl Tok {
    pub fn as_str(&self) -> Option<String> {
        match self {
            Tok::Atom(a) => Some(a.clone()),
            Tok::Str(s) => Some(String::from_utf8_lossy(s).into_owned()),
            Tok::List(_) => None,
        }
    }
    pub fn atom_upper(&self) -> Option<String> {
        match self {
            Tok::Atom(a) => Some(a.to_ascii_uppercase()),
            _ => None,
        }
    }
}

/// Tokenise an assembled command (literals inline as `{n}\r\n<bytes>`).
pub fn tokenize(buf: &[u8]) -> Result<Vec<Tok>> {
    let mut pos = 0;
    let v = parse_seq(buf, &mut pos, 0)?;
    if pos < buf.len() {
        bail!("unexpected ')'");
    }
    Ok(v)
}

fn parse_seq(buf: &[u8], pos: &mut usize, depth: usize) -> Result<Vec<Tok>> {
    if depth > 16 {
        bail!("nesting too deep");
    }
    let mut out = Vec::new();
    loop {
        while *pos < buf.len() && buf[*pos] == b' ' {
            *pos += 1;
        }
        if *pos >= buf.len() {
            if depth > 0 {
                bail!("unterminated list");
            }
            return Ok(out);
        }
        match buf[*pos] {
            b')' => {
                if depth == 0 {
                    return Ok(out);
                }
                *pos += 1;
                return Ok(out);
            }
            b'(' => {
                *pos += 1;
                out.push(Tok::List(parse_seq(buf, pos, depth + 1)?));
            }
            b'"' => {
                *pos += 1;
                let mut s = Vec::new();
                loop {
                    let c = *buf.get(*pos).ok_or_else(|| anyhow!("unterminated string"))?;
                    *pos += 1;
                    match c {
                        b'"' => break,
                        b'\\' => {
                            let n = *buf.get(*pos).ok_or_else(|| anyhow!("bad escape"))?;
                            *pos += 1;
                            s.push(n);
                        }
                        b'\r' | b'\n' => bail!("newline in quoted string"),
                        _ => s.push(c),
                    }
                }
                out.push(Tok::Str(s));
            }
            b'{' => {
                let start = *pos + 1;
                let end = buf[start..].iter().position(|&b| b == b'}').ok_or_else(|| anyhow!("bad literal"))? + start;
                let spec = std::str::from_utf8(&buf[start..end])?.trim_end_matches('+');
                let n: usize = spec.parse()?;
                let data_start = end + 3; // "}\r\n"
                if buf.get(end + 1..data_start) != Some(b"\r\n") || data_start + n > buf.len() {
                    bail!("bad literal");
                }
                out.push(Tok::Str(buf[data_start..data_start + n].to_vec()));
                *pos = data_start + n;
            }
            _ => {
                let start = *pos;
                let mut bracket = 0i32;
                while *pos < buf.len() {
                    let c = buf[*pos];
                    if bracket == 0 && (c == b' ' || c == b'(' || c == b')') {
                        break;
                    }
                    if c == b'[' {
                        bracket += 1;
                    } else if c == b']' {
                        bracket -= 1;
                    }
                    *pos += 1;
                }
                out.push(Tok::Atom(String::from_utf8_lossy(&buf[start..*pos]).into_owned()));
            }
        }
    }
}

/// Inclusive ranges; `u32::MAX` stands for `*`.
#[derive(Debug, Clone)]
pub struct SeqSet(pub Vec<(u32, u32)>);

impl SeqSet {
    pub fn parse(s: &str) -> Result<Self> {
        let mut v = Vec::new();
        for part in s.split(',') {
            let num = |x: &str| -> Result<u32> {
                if x == "*" {
                    Ok(u32::MAX)
                } else {
                    let n: u32 = x.parse().map_err(|_| anyhow!("bad sequence set"))?;
                    if n == 0 {
                        bail!("sequence number 0");
                    }
                    Ok(n)
                }
            };
            match part.split_once(':') {
                Some((a, b)) => v.push((num(a)?, num(b)?)),
                None => {
                    let n = num(part)?;
                    v.push((n, n));
                }
            }
        }
        if v.is_empty() {
            bail!("empty sequence set");
        }
        Ok(SeqSet(v))
    }

    /// Does `n` fall in the set, where `*` means `max`?
    pub fn contains(&self, n: u32, max: u32) -> bool {
        self.0.iter().any(|&(a, b)| {
            let a = if a == u32::MAX { max } else { a };
            let b = if b == u32::MAX { max } else { b };
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            n >= lo && n <= hi
        })
    }
}

/// Compact a sorted list of numbers into IMAP set syntax.
pub fn compact(nums: &[u32]) -> String {
    let mut out = Vec::new();
    let mut i = 0;
    while i < nums.len() {
        let start = nums[i];
        let mut end = start;
        while i + 1 < nums.len() && nums[i + 1] == end + 1 {
            i += 1;
            end = nums[i];
        }
        out.push(if start == end { start.to_string() } else { format!("{start}:{end}") });
        i += 1;
    }
    out.join(",")
}

#[derive(Debug, Clone, PartialEq)]
pub enum SectionKind {
    Full,
    Header,
    HeaderFields(Vec<String>),
    HeaderFieldsNot(Vec<String>),
    Text,
    Mime,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Section {
    pub path: Vec<u32>,
    pub kind: SectionKind,
}

impl Section {
    pub fn label(&self) -> String {
        let mut parts: Vec<String> = self.path.iter().map(|n| n.to_string()).collect();
        match &self.kind {
            SectionKind::Full => {}
            SectionKind::Header => parts.push("HEADER".into()),
            SectionKind::Text => parts.push("TEXT".into()),
            SectionKind::Mime => parts.push("MIME".into()),
            SectionKind::HeaderFields(f) => parts.push(format!("HEADER.FIELDS ({})", f.join(" "))),
            SectionKind::HeaderFieldsNot(f) => parts.push(format!("HEADER.FIELDS.NOT ({})", f.join(" "))),
        }
        parts.join(".")
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum FetchAtt {
    Flags,
    Uid,
    InternalDate,
    Rfc822Size,
    Envelope,
    BodyStructure,
    Body,
    Rfc822,
    Rfc822Header,
    Rfc822Text,
    Section { peek: bool, section: Section, partial: Option<(u32, u32)> },
}

pub fn parse_fetch_atts(tok: &Tok) -> Result<Vec<FetchAtt>> {
    let items: Vec<String> = match tok {
        Tok::Atom(a) => match a.to_ascii_uppercase().as_str() {
            "ALL" => return Ok(vec![FetchAtt::Flags, FetchAtt::InternalDate, FetchAtt::Rfc822Size, FetchAtt::Envelope]),
            "FAST" => return Ok(vec![FetchAtt::Flags, FetchAtt::InternalDate, FetchAtt::Rfc822Size]),
            "FULL" => {
                return Ok(vec![FetchAtt::Flags, FetchAtt::InternalDate, FetchAtt::Rfc822Size, FetchAtt::Envelope, FetchAtt::Body])
            }
            _ => vec![a.clone()],
        },
        Tok::List(l) => l.iter().map(|t| t.as_str().ok_or_else(|| anyhow!("bad fetch item"))).collect::<Result<_>>()?,
        Tok::Str(_) => bail!("bad fetch item"),
    };
    items.iter().map(|s| parse_one_att(s)).collect()
}

fn parse_one_att(s: &str) -> Result<FetchAtt> {
    let up = s.to_ascii_uppercase();
    Ok(match up.as_str() {
        "FLAGS" => FetchAtt::Flags,
        "UID" => FetchAtt::Uid,
        "INTERNALDATE" => FetchAtt::InternalDate,
        "RFC822.SIZE" => FetchAtt::Rfc822Size,
        "ENVELOPE" => FetchAtt::Envelope,
        "BODYSTRUCTURE" => FetchAtt::BodyStructure,
        "BODY" => FetchAtt::Body,
        "RFC822" => FetchAtt::Rfc822,
        "RFC822.HEADER" => FetchAtt::Rfc822Header,
        "RFC822.TEXT" => FetchAtt::Rfc822Text,
        "MODSEQ" => FetchAtt::Uid, // tolerated; we don't do CONDSTORE
        _ => {
            let (peek, rest) = if let Some(r) = up.strip_prefix("BODY.PEEK[") {
                (true, r)
            } else if let Some(r) = up.strip_prefix("BODY[") {
                (false, r)
            } else if let Some(r) = up.strip_prefix("BINARY.PEEK[") {
                (true, r)
            } else if let Some(r) = up.strip_prefix("BINARY[") {
                (false, r)
            } else {
                bail!("unknown fetch attribute {s}");
            };
            let close = rest.rfind(']').ok_or_else(|| anyhow!("missing ]"))?;
            let spec = &rest[..close];
            let tail = &rest[close + 1..];
            let partial = if let Some(p) = tail.strip_prefix('<') {
                let p = p.strip_suffix('>').ok_or_else(|| anyhow!("bad partial"))?;
                let (a, b) = p.split_once('.').ok_or_else(|| anyhow!("bad partial"))?;
                Some((a.parse()?, b.parse()?))
            } else {
                None
            };
            FetchAtt::Section { peek, section: parse_section(spec)?, partial }
        }
    })
}

fn parse_section(spec: &str) -> Result<Section> {
    let mut path = Vec::new();
    let mut rest = spec.trim();
    loop {
        let (head, tail) = match rest.find('.') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, ""),
        };
        match head.parse::<u32>() {
            Ok(n) if n > 0 => {
                path.push(n);
                rest = tail;
                if rest.is_empty() {
                    return Ok(Section { path, kind: SectionKind::Full });
                }
            }
            _ => break,
        }
    }
    let kind = if rest.is_empty() {
        SectionKind::Full
    } else if rest == "HEADER" {
        SectionKind::Header
    } else if rest == "TEXT" {
        SectionKind::Text
    } else if rest == "MIME" {
        SectionKind::Mime
    } else if let Some(f) = rest.strip_prefix("HEADER.FIELDS.NOT") {
        SectionKind::HeaderFieldsNot(field_list(f))
    } else if let Some(f) = rest.strip_prefix("HEADER.FIELDS") {
        SectionKind::HeaderFields(field_list(f))
    } else {
        bail!("bad section {spec}");
    };
    Ok(Section { path, kind })
}

fn field_list(s: &str) -> Vec<String> {
    s.trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .split_whitespace()
        .map(|f| f.trim_matches('"').to_ascii_uppercase())
        .collect()
}

/// Quote a string for an IMAP response, using a literal where quoting isn't possible.
pub fn istr(out: &mut Vec<u8>, s: &[u8]) {
    let quotable = s.len() < 1024 && s.iter().all(|&b| (0x20..0x7f).contains(&b));
    if quotable {
        out.push(b'"');
        for &b in s {
            if b == b'"' || b == b'\\' {
                out.push(b'\\');
            }
            out.push(b);
        }
        out.push(b'"');
    } else {
        lit(out, s);
    }
}

pub fn lit(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(format!("{{{}}}\r\n", s.len()).as_bytes());
    out.extend_from_slice(s);
}

pub fn nstr(out: &mut Vec<u8>, s: Option<&[u8]>) {
    match s {
        Some(v) => istr(out, v),
        None => out.extend_from_slice(b"NIL"),
    }
}

/// Quote a mailbox name or other short text for a response line.
pub fn q(s: &str) -> String {
    let mut out = Vec::new();
    istr(&mut out, s.as_bytes());
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens() {
        let t = tokenize(b"FETCH 1:* (FLAGS BODY.PEEK[HEADER.FIELDS (FROM TO)]<0.100>)").unwrap();
        assert_eq!(t[0], Tok::Atom("FETCH".into()));
        let Tok::List(l) = &t[2] else { panic!() };
        assert_eq!(l[1], Tok::Atom("BODY.PEEK[HEADER.FIELDS (FROM TO)]<0.100>".into()));
        let atts = parse_fetch_atts(&t[2]).unwrap();
        assert_eq!(
            atts[1],
            FetchAtt::Section {
                peek: true,
                section: Section { path: vec![], kind: SectionKind::HeaderFields(vec!["FROM".into(), "TO".into()]) },
                partial: Some((0, 100))
            }
        );
        let t = tokenize(b"APPEND \"Sent Items\" (\\Seen) {5}\r\nhello").unwrap();
        assert_eq!(t[1], Tok::Str(b"Sent Items".to_vec()));
        assert_eq!(t[3], Tok::Str(b"hello".to_vec()));
    }

    #[test]
    fn sets() {
        let s = SeqSet::parse("1:3,7,10:*").unwrap();
        assert!(s.contains(2, 20) && s.contains(7, 20) && s.contains(20, 20) && !s.contains(5, 20));
        assert_eq!(compact(&[1, 2, 3, 5, 7, 8]), "1:3,5,7:8");
        let s = parse_section("1.2.MIME").unwrap();
        assert_eq!(s.path, vec![1, 2]);
        assert_eq!(s.kind, SectionKind::Mime);
    }
}
