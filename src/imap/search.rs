//! IMAP SEARCH criteria parsing and evaluation.

use super::parse::{SeqSet, Tok};
use crate::store::MsgMeta;
use anyhow::{anyhow, bail, Result};
use chrono::{NaiveDate, TimeZone, Utc};
use mail_parser::{HeaderValue, MessageParser};

#[derive(Debug, Clone)]
pub enum Crit {
    All,
    Flag(String, bool),
    New,
    Old,
    Recent,
    Seq(SeqSet),
    Uid(SeqSet),
    Header(String, String),
    Body(String),
    Text(String),
    Before(NaiveDate),
    On(NaiveDate),
    Since(NaiveDate),
    SentBefore(NaiveDate),
    SentOn(NaiveDate),
    SentSince(NaiveDate),
    Larger(i64),
    Smaller(i64),
    Not(Box<Crit>),
    Or(Box<Crit>, Box<Crit>),
    And(Vec<Crit>),
}

pub fn parse(toks: &[Tok]) -> Result<Crit> {
    let mut i = 0;
    let mut v = Vec::new();
    // Optional CHARSET (we search on decoded UTF-8 regardless).
    if toks.first().and_then(|t| t.atom_upper()).as_deref() == Some("CHARSET") {
        i = 2;
    }
    while i < toks.len() {
        v.push(parse_one(toks, &mut i)?);
    }
    Ok(if v.len() == 1 { v.pop().unwrap() } else { Crit::And(v) })
}

fn date_arg(toks: &[Tok], i: &mut usize) -> Result<NaiveDate> {
    let s = toks.get(*i).and_then(|t| t.as_str()).ok_or_else(|| anyhow!("missing date"))?;
    *i += 1;
    NaiveDate::parse_from_str(s.trim(), "%d-%b-%Y").map_err(|_| anyhow!("bad date {s}"))
}

fn str_arg(toks: &[Tok], i: &mut usize) -> Result<String> {
    let s = toks.get(*i).and_then(|t| t.as_str()).ok_or_else(|| anyhow!("missing argument"))?;
    *i += 1;
    Ok(s)
}

fn parse_one(toks: &[Tok], i: &mut usize) -> Result<Crit> {
    let t = toks.get(*i).ok_or_else(|| anyhow!("missing search key"))?;
    *i += 1;
    if let Tok::List(l) = t {
        let mut j = 0;
        let mut v = Vec::new();
        while j < l.len() {
            v.push(parse_one(l, &mut j)?);
        }
        return Ok(Crit::And(v));
    }
    let key = t.as_str().ok_or_else(|| anyhow!("bad search key"))?;
    let up = key.to_ascii_uppercase();
    let flag = |f: &str, has: bool| Ok(Crit::Flag(f.into(), has));
    match up.as_str() {
        "ALL" => Ok(Crit::All),
        "ANSWERED" => flag("\\Answered", true),
        "UNANSWERED" => flag("\\Answered", false),
        "DELETED" => flag("\\Deleted", true),
        "UNDELETED" => flag("\\Deleted", false),
        "DRAFT" => flag("\\Draft", true),
        "UNDRAFT" => flag("\\Draft", false),
        "FLAGGED" => flag("\\Flagged", true),
        "UNFLAGGED" => flag("\\Flagged", false),
        "SEEN" => flag("\\Seen", true),
        "UNSEEN" => flag("\\Seen", false),
        "KEYWORD" => Ok(Crit::Flag(str_arg(toks, i)?, true)),
        "UNKEYWORD" => Ok(Crit::Flag(str_arg(toks, i)?, false)),
        "NEW" => Ok(Crit::New),
        "OLD" => Ok(Crit::Old),
        "RECENT" => Ok(Crit::Recent),
        "UID" => Ok(Crit::Uid(SeqSet::parse(&str_arg(toks, i)?)?)),
        "FROM" | "TO" | "CC" | "BCC" | "SUBJECT" => Ok(Crit::Header(up.clone(), str_arg(toks, i)?)),
        "HEADER" => {
            let name = str_arg(toks, i)?;
            Ok(Crit::Header(name.to_ascii_uppercase(), str_arg(toks, i)?))
        }
        "BODY" => Ok(Crit::Body(str_arg(toks, i)?)),
        "TEXT" => Ok(Crit::Text(str_arg(toks, i)?)),
        "BEFORE" => Ok(Crit::Before(date_arg(toks, i)?)),
        "ON" => Ok(Crit::On(date_arg(toks, i)?)),
        "SINCE" => Ok(Crit::Since(date_arg(toks, i)?)),
        "SENTBEFORE" => Ok(Crit::SentBefore(date_arg(toks, i)?)),
        "SENTON" => Ok(Crit::SentOn(date_arg(toks, i)?)),
        "SENTSINCE" => Ok(Crit::SentSince(date_arg(toks, i)?)),
        "LARGER" => Ok(Crit::Larger(str_arg(toks, i)?.parse()?)),
        "SMALLER" => Ok(Crit::Smaller(str_arg(toks, i)?.parse()?)),
        "NOT" => Ok(Crit::Not(Box::new(parse_one(toks, i)?))),
        "OR" => {
            let a = parse_one(toks, i)?;
            let b = parse_one(toks, i)?;
            Ok(Crit::Or(Box::new(a), Box::new(b)))
        }
        _ => {
            if key.chars().all(|c| c.is_ascii_digit() || c == ':' || c == ',' || c == '*') {
                Ok(Crit::Seq(SeqSet::parse(&key)?))
            } else {
                bail!("unsupported search key {key}")
            }
        }
    }
}

impl Crit {
    pub fn needs_content(&self) -> bool {
        match self {
            Crit::Header(..) | Crit::Body(_) | Crit::Text(_) | Crit::SentBefore(_) | Crit::SentOn(_) | Crit::SentSince(_) => true,
            Crit::Not(c) => c.needs_content(),
            Crit::Or(a, b) => a.needs_content() || b.needs_content(),
            Crit::And(v) => v.iter().any(|c| c.needs_content()),
            _ => false,
        }
    }
}

pub struct Ctx<'a> {
    pub meta: &'a MsgMeta,
    pub seq: u32,
    pub max_seq: u32,
    pub max_uid: u32,
    pub raw: Option<&'a [u8]>,
}

fn contains_ci(hay: &str, needle: &str) -> bool {
    hay.to_lowercase().contains(&needle.to_lowercase())
}

fn hv_text(v: &HeaderValue) -> String {
    match v {
        HeaderValue::Text(t) => t.to_string(),
        HeaderValue::TextList(l) => l.join(" "),
        HeaderValue::Address(a) => a
            .iter()
            .map(|x| format!("{} <{}>", x.name().unwrap_or(""), x.address().unwrap_or("")))
            .collect::<Vec<_>>()
            .join(", "),
        _ => String::new(),
    }
}

fn day(ts: i64) -> NaiveDate {
    Utc.timestamp_opt(ts, 0).single().unwrap_or_default().date_naive()
}

pub fn eval(c: &Crit, x: &Ctx) -> bool {
    let has = |f: &str| x.meta.flags.iter().any(|g| g.eq_ignore_ascii_case(f));
    match c {
        Crit::All => true,
        Crit::Flag(f, want) => has(f) == *want,
        Crit::New => false, // we don't track \Recent
        Crit::Recent => false,
        Crit::Old => true,
        Crit::Seq(s) => s.contains(x.seq, x.max_seq),
        Crit::Uid(s) => s.contains(x.meta.uid, x.max_uid),
        Crit::Larger(n) => x.meta.size > *n,
        Crit::Smaller(n) => x.meta.size < *n,
        Crit::Before(d) => day(x.meta.internal_date) < *d,
        Crit::On(d) => day(x.meta.internal_date) == *d,
        Crit::Since(d) => day(x.meta.internal_date) >= *d,
        Crit::Not(c) => !eval(c, x),
        Crit::Or(a, b) => eval(a, x) || eval(b, x),
        Crit::And(v) => v.iter().all(|c| eval(c, x)),
        Crit::Header(..) | Crit::Body(_) | Crit::Text(_) | Crit::SentBefore(_) | Crit::SentOn(_) | Crit::SentSince(_) => {
            let Some(raw) = x.raw else { return false };
            let Some(msg) = MessageParser::default().parse(raw) else { return false };
            match c {
                Crit::Header(name, val) => {
                    let raw_hit = msg.header_raw(name.as_str()).map(|r| contains_ci(r, val)).unwrap_or(false);
                    raw_hit || msg.header_values(name.as_str()).any(|v| contains_ci(&hv_text(v), val))
                        || (val.is_empty() && msg.header_raw(name.as_str()).is_some())
                }
                Crit::Body(s) | Crit::Text(s) => {
                    let mut body = String::new();
                    for i in 0..msg.text_body.len() {
                        if let Some(t) = msg.body_text(i) {
                            body.push_str(&t);
                        }
                    }
                    for i in 0..msg.html_body.len() {
                        if let Some(t) = msg.body_html(i) {
                            body.push_str(&t);
                        }
                    }
                    if matches!(c, Crit::Text(_)) {
                        let hdr_end = crate::delivery::find_header_end(raw);
                        body.push_str(&String::from_utf8_lossy(&raw[..hdr_end]));
                        if let Some(s) = msg.subject() {
                            body.push_str(s);
                        }
                    }
                    contains_ci(&body, s)
                }
                Crit::SentBefore(d) | Crit::SentOn(d) | Crit::SentSince(d) => {
                    let Some(dt) = msg.date() else { return false };
                    let sd = day(dt.to_timestamp());
                    match c {
                        Crit::SentBefore(_) => sd < *d,
                        Crit::SentOn(_) => sd == *d,
                        _ => sd >= *d,
                    }
                }
                _ => unreachable!(),
            }
        }
    }
}
