//! Turning Microsoft Graph and Google API objects into iCalendar and vCard.

use anyhow::Result;
use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
use serde_json::Value;
use std::collections::BTreeSet;

/// Escape a TEXT value (RFC 5545 3.3.11 / RFC 6350 3.4).
pub fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace(';', "\\;").replace(',', "\\,").replace("\r\n", "\\n").replace(['\n', '\r'], "\\n")
}

/// Fold a content line at 75 octets without splitting a UTF-8 character.
pub fn fold(line: &str) -> String {
    let mut out = String::new();
    let mut len = 0;
    for ch in line.chars() {
        let w = ch.len_utf8();
        if len + w > 75 {
            out.push_str("\r\n ");
            len = 1;
        }
        out.push(ch);
        len += w;
    }
    out.push_str("\r\n");
    out
}

pub struct Lines(String);

impl Lines {
    pub fn new() -> Self {
        Lines(String::new())
    }
    pub fn raw(&mut self, l: impl AsRef<str>) {
        self.0.push_str(&fold(l.as_ref()));
    }
    pub fn text(&mut self, name: &str, v: &str) {
        if !v.trim().is_empty() {
            self.raw(format!("{name}:{}", esc(v.trim())));
        }
    }
    pub fn done(self) -> String {
        self.0
    }
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("")
}

// ------------------------------------------------------------- time zones

/// Windows time-zone names (as used by Exchange) to IANA names.
pub fn windows_tz(name: &str) -> Option<&'static str> {
    const MAP: &[(&str, &str)] = &[
        ("Dateline Standard Time", "Etc/GMT+12"),
        ("UTC-11", "Etc/GMT+11"),
        ("Aleutian Standard Time", "America/Adak"),
        ("Hawaiian Standard Time", "Pacific/Honolulu"),
        ("Alaskan Standard Time", "America/Anchorage"),
        ("Pacific Standard Time (Mexico)", "America/Tijuana"),
        ("Pacific Standard Time", "America/Los_Angeles"),
        ("US Mountain Standard Time", "America/Phoenix"),
        ("Mountain Standard Time (Mexico)", "America/Mazatlan"),
        ("Mountain Standard Time", "America/Denver"),
        ("Central America Standard Time", "America/Guatemala"),
        ("Central Standard Time", "America/Chicago"),
        ("Central Standard Time (Mexico)", "America/Mexico_City"),
        ("Canada Central Standard Time", "America/Regina"),
        ("SA Pacific Standard Time", "America/Bogota"),
        ("Eastern Standard Time (Mexico)", "America/Cancun"),
        ("Eastern Standard Time", "America/New_York"),
        ("US Eastern Standard Time", "America/Indiana/Indianapolis"),
        ("Venezuela Standard Time", "America/Caracas"),
        ("Paraguay Standard Time", "America/Asuncion"),
        ("Atlantic Standard Time", "America/Halifax"),
        ("Central Brazilian Standard Time", "America/Cuiaba"),
        ("SA Western Standard Time", "America/La_Paz"),
        ("Pacific SA Standard Time", "America/Santiago"),
        ("Newfoundland Standard Time", "America/St_Johns"),
        ("E. South America Standard Time", "America/Sao_Paulo"),
        ("SA Eastern Standard Time", "America/Cayenne"),
        ("Argentina Standard Time", "America/Buenos_Aires"),
        ("Greenland Standard Time", "America/Godthab"),
        ("Montevideo Standard Time", "America/Montevideo"),
        ("UTC-02", "Etc/GMT+2"),
        ("Azores Standard Time", "Atlantic/Azores"),
        ("Cape Verde Standard Time", "Atlantic/Cape_Verde"),
        ("UTC", "Etc/UTC"),
        ("Coordinated Universal Time", "Etc/UTC"),
        ("GMT Standard Time", "Europe/London"),
        ("Greenwich Standard Time", "Atlantic/Reykjavik"),
        ("Morocco Standard Time", "Africa/Casablanca"),
        ("W. Europe Standard Time", "Europe/Berlin"),
        ("Central Europe Standard Time", "Europe/Budapest"),
        ("Romance Standard Time", "Europe/Paris"),
        ("Central European Standard Time", "Europe/Warsaw"),
        ("W. Central Africa Standard Time", "Africa/Lagos"),
        ("Jordan Standard Time", "Asia/Amman"),
        ("GTB Standard Time", "Europe/Bucharest"),
        ("Middle East Standard Time", "Asia/Beirut"),
        ("Egypt Standard Time", "Africa/Cairo"),
        ("E. Europe Standard Time", "Europe/Chisinau"),
        ("Syria Standard Time", "Asia/Damascus"),
        ("South Africa Standard Time", "Africa/Johannesburg"),
        ("FLE Standard Time", "Europe/Kiev"),
        ("Israel Standard Time", "Asia/Jerusalem"),
        ("Kaliningrad Standard Time", "Europe/Kaliningrad"),
        ("Arabic Standard Time", "Asia/Baghdad"),
        ("Turkey Standard Time", "Europe/Istanbul"),
        ("Arab Standard Time", "Asia/Riyadh"),
        ("Belarus Standard Time", "Europe/Minsk"),
        ("Russian Standard Time", "Europe/Moscow"),
        ("E. Africa Standard Time", "Africa/Nairobi"),
        ("Iran Standard Time", "Asia/Tehran"),
        ("Arabian Standard Time", "Asia/Dubai"),
        ("Azerbaijan Standard Time", "Asia/Baku"),
        ("Mauritius Standard Time", "Indian/Mauritius"),
        ("Georgian Standard Time", "Asia/Tbilisi"),
        ("Caucasus Standard Time", "Asia/Yerevan"),
        ("Afghanistan Standard Time", "Asia/Kabul"),
        ("West Asia Standard Time", "Asia/Tashkent"),
        ("Ekaterinburg Standard Time", "Asia/Yekaterinburg"),
        ("Pakistan Standard Time", "Asia/Karachi"),
        ("India Standard Time", "Asia/Calcutta"),
        ("Sri Lanka Standard Time", "Asia/Colombo"),
        ("Nepal Standard Time", "Asia/Katmandu"),
        ("Central Asia Standard Time", "Asia/Almaty"),
        ("Bangladesh Standard Time", "Asia/Dhaka"),
        ("Myanmar Standard Time", "Asia/Rangoon"),
        ("SE Asia Standard Time", "Asia/Bangkok"),
        ("N. Central Asia Standard Time", "Asia/Novosibirsk"),
        ("China Standard Time", "Asia/Shanghai"),
        ("North Asia Standard Time", "Asia/Krasnoyarsk"),
        ("Singapore Standard Time", "Asia/Singapore"),
        ("W. Australia Standard Time", "Australia/Perth"),
        ("Taipei Standard Time", "Asia/Taipei"),
        ("Tokyo Standard Time", "Asia/Tokyo"),
        ("Korea Standard Time", "Asia/Seoul"),
        ("Cen. Australia Standard Time", "Australia/Adelaide"),
        ("AUS Central Standard Time", "Australia/Darwin"),
        ("E. Australia Standard Time", "Australia/Brisbane"),
        ("AUS Eastern Standard Time", "Australia/Sydney"),
        ("West Pacific Standard Time", "Pacific/Port_Moresby"),
        ("Tasmania Standard Time", "Australia/Hobart"),
        ("Vladivostok Standard Time", "Asia/Vladivostok"),
        ("Central Pacific Standard Time", "Pacific/Guadalcanal"),
        ("New Zealand Standard Time", "Pacific/Auckland"),
        ("Fiji Standard Time", "Pacific/Fiji"),
        ("Tonga Standard Time", "Pacific/Tongatapu"),
        ("Samoa Standard Time", "Pacific/Apia"),
    ];
    MAP.iter().find(|(w, _)| w.eq_ignore_ascii_case(name.trim())).map(|(_, i)| *i)
}

/// An IANA zone from either an IANA or a Windows name.
pub fn zone(name: &str) -> Option<Tz> {
    let n = name.trim();
    if n.is_empty() {
        return None;
    }
    n.parse::<Tz>().ok().or_else(|| windows_tz(n).and_then(|i| i.parse().ok()))
}

/// Graph's "2026-11-20T09:00:00.0000000" (UTC, because we ask for UTC).
fn graph_utc(v: &Value) -> Option<DateTime<Utc>> {
    let t = v.get("dateTime")?.as_str()?;
    let t = t.split('.').next()?;
    let n = NaiveDateTime::parse_from_str(t, "%Y-%m-%dT%H:%M:%S").ok()?;
    Some(Utc.from_utc_datetime(&n))
}

fn utc_fmt(t: DateTime<Utc>) -> String {
    t.format("%Y%m%dT%H%M%SZ").to_string()
}

fn local_fmt(t: DateTime<Utc>, tz: Tz) -> String {
    t.with_timezone(&tz).format("%Y%m%dT%H%M%S").to_string()
}

fn date_fmt(d: NaiveDate) -> String {
    d.format("%Y%m%d").to_string()
}

// ------------------------------------------------------------ Graph events

const DAYS: &[(&str, &str)] =
    &[("monday", "MO"), ("tuesday", "TU"), ("wednesday", "WE"), ("thursday", "TH"), ("friday", "FR"), ("saturday", "SA"), ("sunday", "SU")];

fn day(d: &str) -> Option<&'static str> {
    DAYS.iter().find(|(n, _)| n.eq_ignore_ascii_case(d)).map(|(_, c)| *c)
}

/// RRULE (without the "RRULE:" prefix) for a Graph recurrence.
pub fn graph_rrule(rec: &Value, tz: Tz) -> Option<String> {
    let p = rec.get("pattern")?;
    let r = rec.get("range")?;
    let interval = p.get("interval").and_then(|v| v.as_i64()).unwrap_or(1).max(1);
    let days: Vec<&str> = p.get("daysOfWeek").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|d| d.as_str().and_then(day)).collect()).unwrap_or_default();
    let setpos = match s(p, "index") {
        "second" => 2,
        "third" => 3,
        "fourth" => 4,
        "last" => -1,
        _ => 1,
    };
    let month = p.get("month").and_then(|v| v.as_i64()).unwrap_or(0);
    let mday = p.get("dayOfMonth").and_then(|v| v.as_i64()).unwrap_or(0);
    let mut rule = match s(p, "type") {
        "daily" => format!("FREQ=DAILY;INTERVAL={interval}"),
        "weekly" => {
            let mut x = format!("FREQ=WEEKLY;INTERVAL={interval}");
            if !days.is_empty() {
                x.push_str(&format!(";BYDAY={}", days.join(",")));
            }
            if let Some(w) = day(s(p, "firstDayOfWeek")) {
                x.push_str(&format!(";WKST={w}"));
            }
            x
        }
        "absoluteMonthly" => format!("FREQ=MONTHLY;INTERVAL={interval};BYMONTHDAY={mday}"),
        "relativeMonthly" => format!("FREQ=MONTHLY;INTERVAL={interval};BYDAY={};BYSETPOS={setpos}", days.join(",")),
        "absoluteYearly" => format!("FREQ=YEARLY;INTERVAL={interval};BYMONTH={month};BYMONTHDAY={mday}"),
        "relativeYearly" => format!("FREQ=YEARLY;INTERVAL={interval};BYMONTH={month};BYDAY={};BYSETPOS={setpos}", days.join(",")),
        _ => return None,
    };
    match s(r, "type") {
        "endDate" => {
            if let Ok(d) = NaiveDate::parse_from_str(s(r, "endDate"), "%Y-%m-%d") {
                let end = tz.from_local_datetime(&d.and_hms_opt(23, 59, 59)?).latest()?.with_timezone(&Utc);
                rule.push_str(&format!(";UNTIL={}", utc_fmt(end)));
            }
        }
        "numbered" => {
            if let Some(n) = r.get("numberOfOccurrences").and_then(|v| v.as_i64()) {
                rule.push_str(&format!(";COUNT={n}"));
            }
        }
        _ => {}
    }
    Some(rule)
}

fn graph_tz(ev: &Value) -> Tz {
    zone(s(ev, "originalStartTimeZone"))
        .or_else(|| ev.get("recurrence").and_then(|r| r.get("range")).map(|r| s(r, "recurrenceTimeZone")).and_then(zone))
        .unwrap_or(Tz::UTC)
}

fn partstat(r: &str) -> &'static str {
    match r {
        "accepted" | "organizer" => "ACCEPTED",
        "declined" => "DECLINED",
        "tentativelyAccepted" | "tentative" => "TENTATIVE",
        _ => "NEEDS-ACTION",
    }
}

/// One VEVENT for a Graph event. `master_tz` is set for exceptions of a series (so
/// RECURRENCE-ID matches the master's DTSTART form).
fn graph_vevent(l: &mut Lines, ev: &Value, uid: &str, recurring_master: bool, exdates: &[DateTime<Utc>], recurrence_id: Option<(DateTime<Utc>, Tz, bool)>) {
    let tz = graph_tz(ev);
    let all_day = ev.get("isAllDay").and_then(|v| v.as_bool()).unwrap_or(false);
    l.raw("BEGIN:VEVENT");
    l.raw(format!("UID:{uid}"));
    let stamp = ev.get("lastModifiedDateTime").and_then(|v| v.as_str()).and_then(|t| DateTime::parse_from_rfc3339(t).ok()).map(|t| t.with_timezone(&Utc)).unwrap_or_else(Utc::now);
    l.raw(format!("DTSTAMP:{}", utc_fmt(stamp)));
    if let Some(c) = ev.get("createdDateTime").and_then(|v| v.as_str()).and_then(|t| DateTime::parse_from_rfc3339(t).ok()) {
        l.raw(format!("CREATED:{}", utc_fmt(c.with_timezone(&Utc))));
    }
    let (start, end) = (ev.get("start").and_then(graph_utc), ev.get("end").and_then(graph_utc));
    if let (Some(st), Some(en)) = (start, end) {
        if all_day {
            l.raw(format!("DTSTART;VALUE=DATE:{}", date_fmt(st.with_timezone(&tz).date_naive())));
            l.raw(format!("DTEND;VALUE=DATE:{}", date_fmt(en.with_timezone(&tz).date_naive())));
        } else if recurring_master || recurrence_id.as_ref().map(|r| r.2).unwrap_or(false) {
            let name = tz.name();
            l.raw(format!("DTSTART;TZID={name}:{}", local_fmt(st, tz)));
            l.raw(format!("DTEND;TZID={name}:{}", local_fmt(en, tz)));
        } else {
            l.raw(format!("DTSTART:{}", utc_fmt(st)));
            l.raw(format!("DTEND:{}", utc_fmt(en)));
        }
    }
    if let Some((orig, mtz, local)) = recurrence_id {
        if all_day {
            l.raw(format!("RECURRENCE-ID;VALUE=DATE:{}", date_fmt(orig.with_timezone(&mtz).date_naive())));
        } else if local {
            l.raw(format!("RECURRENCE-ID;TZID={}:{}", mtz.name(), local_fmt(orig, mtz)));
        } else {
            l.raw(format!("RECURRENCE-ID:{}", utc_fmt(orig)));
        }
    }
    if recurring_master {
        if let Some(r) = ev.get("recurrence").and_then(|r| graph_rrule(r, tz)) {
            l.raw(format!("RRULE:{r}"));
        }
        for x in exdates {
            if all_day {
                l.raw(format!("EXDATE;VALUE=DATE:{}", date_fmt(x.with_timezone(&tz).date_naive())));
            } else {
                l.raw(format!("EXDATE;TZID={}:{}", tz.name(), local_fmt(*x, tz)));
            }
        }
    }
    l.text("SUMMARY", s(ev, "subject"));
    if let Some(loc) = ev.get("location") {
        l.text("LOCATION", s(loc, "displayName"));
    }
    let body = ev.get("body").map(|b| s(b, "content")).unwrap_or("");
    let body = if ev.get("body").map(|b| s(b, "contentType")) == Some("html") { strip_html(body) } else { body.to_string() };
    l.text("DESCRIPTION", body.trim());
    if let Some(u) = ev.get("onlineMeeting").and_then(|m| m.get("joinUrl")).and_then(|v| v.as_str()) {
        l.raw(format!("URL:{u}"));
    }
    if let Some(o) = ev.get("organizer").and_then(|o| o.get("emailAddress")) {
        if !s(o, "address").is_empty() {
            l.raw(format!("ORGANIZER;CN={}:mailto:{}", param(s(o, "name")), s(o, "address")));
        }
    }
    for a in ev.get("attendees").and_then(|v| v.as_array()).into_iter().flatten() {
        let e = a.get("emailAddress").cloned().unwrap_or_default();
        if s(&e, "address").is_empty() {
            continue;
        }
        let role = match s(a, "type") {
            "optional" => "OPT-PARTICIPANT",
            "resource" => "NON-PARTICIPANT",
            _ => "REQ-PARTICIPANT",
        };
        let ps = a.get("status").map(|x| partstat(s(x, "response"))).unwrap_or("NEEDS-ACTION");
        l.raw(format!("ATTENDEE;CN={};ROLE={role};PARTSTAT={ps}:mailto:{}", param(s(&e, "name")), s(&e, "address")));
    }
    match s(ev, "showAs") {
        "free" | "workingElsewhere" => l.raw("TRANSP:TRANSPARENT"),
        "tentative" => l.raw("STATUS:TENTATIVE"),
        _ => {}
    }
    if ev.get("isCancelled").and_then(|v| v.as_bool()).unwrap_or(false) {
        l.raw("STATUS:CANCELLED");
    }
    if matches!(s(ev, "sensitivity"), "private" | "confidential" | "personal") {
        l.raw("CLASS:PRIVATE");
    }
    let cats: Vec<String> = ev.get("categories").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|c| c.as_str()).map(esc).collect()).unwrap_or_default();
    if !cats.is_empty() {
        l.raw(format!("CATEGORIES:{}", cats.join(",")));
    }
    if ev.get("isReminderOn").and_then(|v| v.as_bool()).unwrap_or(false) {
        let m = ev.get("reminderMinutesBeforeStart").and_then(|v| v.as_i64()).unwrap_or(15);
        l.raw("BEGIN:VALARM");
        l.raw("ACTION:DISPLAY");
        l.text("DESCRIPTION", if s(ev, "subject").is_empty() { "Reminder" } else { s(ev, "subject") });
        l.raw(format!("TRIGGER:-PT{m}M"));
        l.raw("END:VALARM");
    }
    l.raw("END:VEVENT");
}

fn param(v: &str) -> String {
    let v = v.replace('"', "'");
    if v.contains([':', ';', ',']) {
        format!("\"{v}\"")
    } else if v.is_empty() {
        "\"\"".into()
    } else {
        v
    }
}

pub fn strip_html(h: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    let mut tag = String::new();
    for ch in h.chars() {
        match ch {
            '<' => {
                in_tag = true;
                tag.clear();
            }
            '>' if in_tag => {
                in_tag = false;
                let t = tag.to_ascii_lowercase();
                if t.starts_with("br") || t.starts_with("/p") || t.starts_with("/div") || t.starts_with("/li") || t.starts_with("/tr") {
                    out.push('\n');
                }
            }
            _ if in_tag => tag.push(ch),
            _ => out.push(ch),
        }
    }
    let out = out.replace("&nbsp;", " ").replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&#39;", "'");
    let mut lines: Vec<&str> = out.lines().map(str::trim_end).collect();
    lines.dedup_by(|a, b| a.is_empty() && b.is_empty());
    lines.join("\n").trim().to_string()
}

/// Occurrences an RRULE produces between `from` and `to` (UTC).
pub fn expand(dtstart_local: &str, tz: Tz, rrule: &str, from: DateTime<Utc>, to: DateTime<Utc>) -> Vec<DateTime<Utc>> {
    let text = if tz == Tz::UTC {
        format!("DTSTART:{dtstart_local}Z\nRRULE:{rrule}")
    } else {
        format!("DTSTART;TZID={}:{dtstart_local}\nRRULE:{rrule}", tz.name())
    };
    let Ok(set) = text.parse::<rrule::RRuleSet>() else { return vec![] };
    let set = set.after(from.with_timezone(&rrule::Tz::UTC)).before(to.with_timezone(&rrule::Tz::UTC));
    set.all(2000).dates.into_iter().map(|d| d.with_timezone(&Utc)).collect()
}

/// A repeating Graph series (or a single event) as one iCalendar object. `instances`
/// are the series' occurrences and exceptions in a window, used to find deleted
/// occurrences (EXDATE) and moved/changed ones (RECURRENCE-ID).
pub fn graph_event_ics(ev: &Value, instances: &[Value], window: (DateTime<Utc>, DateTime<Utc>)) -> String {
    let uid = ev.get("iCalUId").and_then(|v| v.as_str()).filter(|u| !u.is_empty()).map(String::from).unwrap_or_else(|| format!("graph-{}", s(ev, "id")));
    let mut l = Lines::new();
    l.raw("BEGIN:VCALENDAR");
    l.raw("VERSION:2.0");
    l.raw("PRODID:-//Postwright//Migration//EN");
    let master = s(ev, "type") == "seriesMaster";
    let tz = graph_tz(ev);
    let mut exdates = Vec::new();
    if master && !instances.is_empty() {
        if let (Some(st), Some(rule)) = (ev.get("start").and_then(graph_utc), ev.get("recurrence").and_then(|r| graph_rrule(r, tz))) {
            let expected = expand(&local_fmt(st, tz), tz, &rule, window.0, window.1);
            let present: BTreeSet<i64> = instances
                .iter()
                .filter_map(|i| {
                    i.get("originalStart")
                        .and_then(|v| v.as_str())
                        .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
                        .map(|t| t.timestamp())
                        .or_else(|| i.get("start").and_then(graph_utc).map(|t| t.timestamp()))
                })
                .collect();
            let all_day = ev.get("isAllDay").and_then(|v| v.as_bool()).unwrap_or(false);
            for x in expected {
                let hit = if all_day {
                    present.iter().any(|p| (p - x.timestamp()).abs() < 86400)
                } else {
                    present.contains(&x.timestamp())
                };
                if !hit {
                    exdates.push(x);
                }
            }
        }
    }
    graph_vevent(&mut l, ev, &uid, master, &exdates, None);
    for i in instances.iter().filter(|i| s(i, "type") == "exception") {
        if let Some(orig) = i.get("originalStart").and_then(|v| v.as_str()).and_then(|t| DateTime::parse_from_rfc3339(t).ok()) {
            graph_vevent(&mut l, i, &uid, false, &[], Some((orig.with_timezone(&Utc), tz, true)));
        }
    }
    l.raw("END:VCALENDAR");
    l.done()
}

// ----------------------------------------------------------- Google events

/// Google event start/end: (value-with-params, utc instant) for DTSTART/DTEND.
fn google_time(v: &Value, tz: Tz, local: bool) -> Option<(String, DateTime<Utc>)> {
    if let Some(d) = v.get("date").and_then(|x| x.as_str()) {
        let d = NaiveDate::parse_from_str(d, "%Y-%m-%d").ok()?;
        return Some((format!(";VALUE=DATE:{}", date_fmt(d)), Utc.from_utc_datetime(&d.and_hms_opt(0, 0, 0)?)));
    }
    let t = DateTime::parse_from_rfc3339(v.get("dateTime")?.as_str()?).ok()?.with_timezone(&Utc);
    if local {
        let tz = v.get("timeZone").and_then(|x| x.as_str()).and_then(zone).unwrap_or(tz);
        Some((format!(";TZID={}:{}", tz.name(), local_fmt(t, tz)), t))
    } else {
        Some((format!(":{}", utc_fmt(t)), t))
    }
}

fn google_vevent(l: &mut Lines, ev: &Value, uid: &str, cal_tz: Tz, exdates: &[String]) {
    let recurring = ev.get("recurrence").map(|r| r.is_array()).unwrap_or(false);
    let is_exception = ev.get("recurringEventId").is_some();
    let local = recurring || is_exception;
    l.raw("BEGIN:VEVENT");
    l.raw(format!("UID:{uid}"));
    let stamp = ev.get("updated").and_then(|v| v.as_str()).and_then(|t| DateTime::parse_from_rfc3339(t).ok()).map(|t| t.with_timezone(&Utc)).unwrap_or_else(Utc::now);
    l.raw(format!("DTSTAMP:{}", utc_fmt(stamp)));
    if let Some((v, _)) = ev.get("start").and_then(|x| google_time(x, cal_tz, local)) {
        l.raw(format!("DTSTART{v}"));
    }
    if let Some((v, _)) = ev.get("end").and_then(|x| google_time(x, cal_tz, local)) {
        l.raw(format!("DTEND{v}"));
    }
    if let Some((v, _)) = ev.get("originalStartTime").and_then(|x| google_time(x, cal_tz, true)) {
        l.raw(format!("RECURRENCE-ID{v}"));
    }
    for r in ev.get("recurrence").and_then(|v| v.as_array()).into_iter().flatten() {
        if let Some(r) = r.as_str() {
            l.raw(r);
        }
    }
    for x in exdates {
        l.raw(x);
    }
    l.text("SUMMARY", s(ev, "summary"));
    l.text("LOCATION", s(ev, "location"));
    let desc = s(ev, "description");
    l.text("DESCRIPTION", &if desc.contains('<') { strip_html(desc) } else { desc.to_string() });
    if let Some(h) = ev.get("hangoutLink").and_then(|v| v.as_str()) {
        l.raw(format!("URL:{h}"));
    }
    if let Some(o) = ev.get("organizer") {
        if !s(o, "email").is_empty() {
            l.raw(format!("ORGANIZER;CN={}:mailto:{}", param(s(o, "displayName")), s(o, "email")));
        }
    }
    for a in ev.get("attendees").and_then(|v| v.as_array()).into_iter().flatten() {
        if s(a, "email").is_empty() {
            continue;
        }
        let role = if a.get("resource").and_then(|v| v.as_bool()).unwrap_or(false) {
            "NON-PARTICIPANT"
        } else if a.get("optional").and_then(|v| v.as_bool()).unwrap_or(false) {
            "OPT-PARTICIPANT"
        } else {
            "REQ-PARTICIPANT"
        };
        l.raw(format!("ATTENDEE;CN={};ROLE={role};PARTSTAT={}:mailto:{}", param(s(a, "displayName")), partstat(s(a, "responseStatus")), s(a, "email")));
    }
    if s(ev, "transparency") == "transparent" {
        l.raw("TRANSP:TRANSPARENT");
    }
    match s(ev, "status") {
        "tentative" => l.raw("STATUS:TENTATIVE"),
        "cancelled" => l.raw("STATUS:CANCELLED"),
        _ => {}
    }
    if matches!(s(ev, "visibility"), "private" | "confidential") {
        l.raw("CLASS:PRIVATE");
    }
    for r in ev.get("reminders").and_then(|r| r.get("overrides")).and_then(|v| v.as_array()).into_iter().flatten() {
        let m = r.get("minutes").and_then(|v| v.as_i64()).unwrap_or(10);
        l.raw("BEGIN:VALARM");
        l.raw("ACTION:DISPLAY");
        l.text("DESCRIPTION", if s(ev, "summary").is_empty() { "Reminder" } else { s(ev, "summary") });
        l.raw(format!("TRIGGER:-PT{m}M"));
        l.raw("END:VALARM");
    }
    l.raw("END:VEVENT");
}

/// Group a Google calendar's events (singleEvents=false, showDeleted=true) into
/// iCalendar objects: each series with its changed occurrences, cancelled occurrences
/// as EXDATEs, plus one object per standalone event.
pub fn google_calendar_ics(events: &[Value], cal_tz: &str) -> Vec<String> {
    let tz = zone(cal_tz).unwrap_or(Tz::UTC);
    let mut out = Vec::new();
    let masters: Vec<&Value> = events.iter().filter(|e| e.get("recurringEventId").is_none() && s(e, "status") != "cancelled").collect();
    for m in masters {
        let id = s(m, "id");
        let uid = m.get("iCalUID").and_then(|v| v.as_str()).filter(|u| !u.is_empty()).unwrap_or(id).to_string();
        let kids: Vec<&Value> = events.iter().filter(|e| s(e, "recurringEventId") == id).collect();
        let exdates: Vec<String> = kids
            .iter()
            .filter(|e| s(e, "status") == "cancelled")
            .filter_map(|e| e.get("originalStartTime").and_then(|x| google_time(x, tz, true)).map(|(v, _)| format!("EXDATE{v}")))
            .collect();
        let mut l = Lines::new();
        l.raw("BEGIN:VCALENDAR");
        l.raw("VERSION:2.0");
        l.raw("PRODID:-//Postwright//Migration//EN");
        google_vevent(&mut l, m, &uid, tz, &exdates);
        for k in kids.iter().filter(|e| s(e, "status") != "cancelled") {
            google_vevent(&mut l, k, &uid, tz, &[]);
        }
        l.raw("END:VCALENDAR");
        out.push(l.done());
    }
    out
}

// --------------------------------------------------------------- contacts

fn adr(l: &mut Lines, kind: &str, street: &str, city: &str, region: &str, postcode: &str, country: &str) {
    if [street, city, region, postcode, country].iter().all(|x| x.trim().is_empty()) {
        return;
    }
    l.raw(format!("ADR;TYPE={kind}:;;{};{};{};{};{}", esc(street), esc(city), esc(region), esc(postcode), esc(country)));
}

/// A Microsoft Graph contact as a vCard 3.0.
pub fn graph_contact_vcard(c: &Value) -> String {
    let mut l = Lines::new();
    l.raw("BEGIN:VCARD");
    l.raw("VERSION:3.0");
    l.raw("PRODID:-//Postwright//Migration//EN");
    l.raw(format!("UID:graph-{}", hex::encode(&sha2::Digest::finalize(<sha2::Sha256 as sha2::Digest>::new_with_prefix(s(c, "id").as_bytes()))[..12])));
    let first = s(c, "givenName");
    let last = s(c, "surname");
    let mut fname = s(c, "displayName").to_string();
    if fname.trim().is_empty() {
        fname = format!("{first} {last}").trim().to_string();
    }
    if fname.is_empty() {
        fname = c.get("emailAddresses").and_then(|v| v.get(0)).map(|e| s(e, "address").to_string()).unwrap_or_else(|| s(c, "companyName").to_string());
    }
    l.raw(format!("FN:{}", esc(&fname)));
    l.raw(format!("N:{};{};{};{};{}", esc(last), esc(first), esc(s(c, "middleName")), esc(s(c, "title")), esc(s(c, "generation"))));
    l.text("NICKNAME", s(c, "nickName"));
    let org = s(c, "companyName");
    if !org.is_empty() || !s(c, "department").is_empty() {
        l.raw(format!("ORG:{};{}", esc(org), esc(s(c, "department"))));
    }
    l.text("TITLE", s(c, "jobTitle"));
    for e in c.get("emailAddresses").and_then(|v| v.as_array()).into_iter().flatten() {
        if !s(e, "address").is_empty() {
            l.raw(format!("EMAIL;TYPE=INTERNET:{}", s(e, "address")));
        }
    }
    for (k, t) in [("businessPhones", "WORK,VOICE"), ("homePhones", "HOME,VOICE")] {
        for p in c.get(k).and_then(|v| v.as_array()).into_iter().flatten() {
            if let Some(p) = p.as_str().filter(|p| !p.is_empty()) {
                l.raw(format!("TEL;TYPE={t}:{}", esc(p)));
            }
        }
    }
    if !s(c, "mobilePhone").is_empty() {
        l.raw(format!("TEL;TYPE=CELL:{}", esc(s(c, "mobilePhone"))));
    }
    for (k, t) in [("businessAddress", "WORK"), ("homeAddress", "HOME"), ("otherAddress", "OTHER")] {
        if let Some(a) = c.get(k) {
            adr(&mut l, t, s(a, "street"), s(a, "city"), s(a, "state"), s(a, "postalCode"), s(a, "countryOrRegion"));
        }
    }
    if let Some(b) = c.get("birthday").and_then(|v| v.as_str()).and_then(|t| DateTime::parse_from_rfc3339(t).ok()) {
        l.raw(format!("BDAY:{}", b.format("%Y-%m-%d")));
    }
    l.text("URL", s(c, "businessHomePage"));
    l.text("NOTE", s(c, "personalNotes"));
    let cats: Vec<String> = c.get("categories").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str()).map(esc).collect()).unwrap_or_default();
    if !cats.is_empty() {
        l.raw(format!("CATEGORIES:{}", cats.join(",")));
    }
    l.raw("END:VCARD");
    l.done()
}

/// A Google People API person as a vCard 3.0.
pub fn google_person_vcard(p: &Value) -> Option<String> {
    let first_of = |k: &str| p.get(k).and_then(|v| v.as_array()).and_then(|a| a.first()).cloned().unwrap_or_default();
    let all_of = |k: &str| p.get(k).and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let name = first_of("names");
    let emails = all_of("emailAddresses");
    let orgs = all_of("organizations");
    let mut fname = s(&name, "displayName").to_string();
    if fname.is_empty() {
        fname = emails.first().map(|e| s(e, "value").to_string()).or_else(|| orgs.first().map(|o| s(o, "name").to_string())).unwrap_or_default();
    }
    if fname.is_empty() && all_of("phoneNumbers").is_empty() {
        return None;
    }
    let mut l = Lines::new();
    l.raw("BEGIN:VCARD");
    l.raw("VERSION:3.0");
    l.raw("PRODID:-//Postwright//Migration//EN");
    l.raw(format!("UID:google-{}", s(p, "resourceName").trim_start_matches("people/")));
    l.raw(format!("FN:{}", esc(&fname)));
    l.raw(format!(
        "N:{};{};{};{};{}",
        esc(s(&name, "familyName")),
        esc(s(&name, "givenName")),
        esc(s(&name, "middleName")),
        esc(s(&name, "honorificPrefix")),
        esc(s(&name, "honorificSuffix"))
    ));
    for n in all_of("nicknames") {
        l.text("NICKNAME", s(&n, "value"));
    }
    if let Some(o) = orgs.first() {
        if !s(o, "name").is_empty() || !s(o, "department").is_empty() {
            l.raw(format!("ORG:{};{}", esc(s(o, "name")), esc(s(o, "department"))));
        }
        l.text("TITLE", s(o, "title"));
    }
    for e in &emails {
        let t = match s(e, "type") {
            "home" => "INTERNET,HOME",
            "work" => "INTERNET,WORK",
            _ => "INTERNET",
        };
        if !s(e, "value").is_empty() {
            l.raw(format!("EMAIL;TYPE={t}:{}", s(e, "value")));
        }
    }
    for ph in all_of("phoneNumbers") {
        let t = match s(&ph, "type") {
            "mobile" => "CELL",
            "home" => "HOME,VOICE",
            "work" => "WORK,VOICE",
            "homeFax" | "workFax" => "FAX",
            _ => "VOICE",
        };
        if !s(&ph, "value").is_empty() {
            l.raw(format!("TEL;TYPE={t}:{}", esc(s(&ph, "value"))));
        }
    }
    for a in all_of("addresses") {
        let t = match s(&a, "type") {
            "home" => "HOME",
            "work" => "WORK",
            _ => "OTHER",
        };
        let street = [s(&a, "streetAddress"), s(&a, "extendedAddress")].iter().filter(|x| !x.is_empty()).cloned().collect::<Vec<_>>().join("\n");
        adr(&mut l, t, &street, s(&a, "city"), s(&a, "region"), s(&a, "postalCode"), s(&a, "country"));
    }
    if let Some(b) = all_of("birthdays").first().and_then(|b| b.get("date")) {
        let (y, m, d) = (b.get("year").and_then(|v| v.as_i64()), b.get("month").and_then(|v| v.as_i64()), b.get("day").and_then(|v| v.as_i64()));
        match (y, m, d) {
            (Some(y), Some(m), Some(d)) => l.raw(format!("BDAY:{y:04}-{m:02}-{d:02}")),
            (None, Some(m), Some(d)) => l.raw(format!("BDAY:--{m:02}{d:02}")),
            _ => {}
        }
    }
    for u in all_of("urls") {
        l.text("URL", s(&u, "value"));
    }
    if let Some(b) = all_of("biographies").first() {
        l.text("NOTE", s(b, "value"));
    }
    l.raw("END:VCARD");
    Some(l.done())
}

/// Split an .ics file with many events into one object per UID, carrying the
/// VTIMEZONE definitions along.
pub fn split_ics(data: &str) -> Result<Vec<String>> {
    let lines = crate::carddav::lines(data);
    let mut timezones = String::new();
    let mut comps: Vec<(String, String)> = Vec::new(); // (uid, text)
    let mut cur: Option<(String, String, Option<String>)> = None; // (kind, text, uid)
    let mut depth = 0;
    for l in lines {
        let up = l.trim().to_ascii_uppercase();
        if depth == 0 && up.starts_with("BEGIN:") && up != "BEGIN:VCALENDAR" {
            let kind = up[6..].to_string();
            cur = Some((kind, String::new(), None));
        }
        let mut finished = false;
        if let Some((_, text, uid)) = cur.as_mut() {
            if up.starts_with("BEGIN:") {
                depth += 1;
            }
            text.push_str(&fold(&l));
            if depth == 1 && up.starts_with("UID") && l.contains(':') {
                *uid = Some(l.split_once(':').unwrap().1.trim().to_string());
            }
            if up.starts_with("END:") {
                depth -= 1;
                finished = depth == 0;
            }
        }
        if finished {
            let (kind, text, uid) = cur.take().unwrap();
            if kind == "VTIMEZONE" {
                timezones.push_str(&text);
            } else if ["VEVENT", "VTODO", "VJOURNAL"].contains(&kind.as_str()) {
                let uid = uid.unwrap_or_else(|| format!("import-{}", hex::encode(&<sha2::Sha256 as sha2::Digest>::digest(text.as_bytes())[..12])));
                match comps.iter_mut().find(|(u, _)| *u == uid) {
                    Some((_, t)) => t.push_str(&text),
                    None => comps.push((uid, text)),
                }
            }
        }
    }
    Ok(comps
        .into_iter()
        .map(|(uid, text)| {
            let has_uid = text.lines().any(|l| l.to_ascii_uppercase().starts_with("UID"));
            let text = if has_uid { text } else { text.replacen("\r\n", &format!("\r\nUID:{uid}\r\n"), 1) };
            format!("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Postwright//Import//EN\r\n{timezones}{text}END:VCALENDAR\r\n")
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn graph_weekly_series_with_deleted_and_moved_occurrence() {
        let ev = json!({
            "id": "AAA", "type": "seriesMaster", "iCalUId": "uid-1", "subject": "Stand-up",
            "originalStartTimeZone": "GMT Standard Time",
            "start": {"dateTime": "2026-10-02T08:00:00.0000000", "timeZone": "UTC"},
            "end": {"dateTime": "2026-10-02T08:15:00.0000000", "timeZone": "UTC"},
            "recurrence": {"pattern": {"type": "weekly", "interval": 1, "daysOfWeek": ["friday"], "firstDayOfWeek": "monday"},
                           "range": {"type": "numbered", "startDate": "2026-10-02", "numberOfOccurrences": 4}},
            "isReminderOn": true, "reminderMinutesBeforeStart": 5
        });
        // 2 Oct (BST, 09:00 local = 08:00Z), 9 Oct, 16 Oct deleted, 23 Oct moved; 30 Oct is GMT again.
        let inst = vec![
            json!({"type": "occurrence", "originalStart": "2026-10-02T08:00:00Z"}),
            json!({"type": "occurrence", "originalStart": "2026-10-09T08:00:00Z"}),
            json!({"type": "exception", "originalStart": "2026-10-23T08:00:00Z", "subject": "Stand-up (moved)",
                   "originalStartTimeZone": "GMT Standard Time",
                   "start": {"dateTime": "2026-10-23T10:00:00.0000000"}, "end": {"dateTime": "2026-10-23T10:15:00.0000000"}}),
        ];
        let from = Utc.with_ymd_and_hms(2026, 9, 1, 0, 0, 0).unwrap();
        let to = Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap();
        let ics = graph_event_ics(&ev, &inst, (from, to));
        assert!(ics.contains("DTSTART;TZID=Europe/London:20261002T090000"), "{ics}");
        assert!(ics.contains("RRULE:FREQ=WEEKLY;INTERVAL=1;BYDAY=FR;WKST=MO;COUNT=4"), "{ics}");
        assert!(ics.contains("EXDATE;TZID=Europe/London:20261016T090000"), "{ics}");
        assert!(!ics.contains("EXDATE;TZID=Europe/London:20261023"), "{ics}");
        assert!(ics.contains("RECURRENCE-ID;TZID=Europe/London:20261023T090000"), "{ics}");
        assert!(ics.contains("TRIGGER:-PT5M"));
        assert!(crate::caldav::ics_meta(&ics).unwrap().recurring);
    }

    #[test]
    fn google_series() {
        let evs = vec![
            json!({"id": "m1", "iCalUID": "m1@google.com", "status": "confirmed", "summary": "Gym",
                   "start": {"dateTime": "2026-11-02T18:00:00Z", "timeZone": "Europe/London"},
                   "end": {"dateTime": "2026-11-02T19:00:00Z", "timeZone": "Europe/London"},
                   "recurrence": ["RRULE:FREQ=WEEKLY;BYDAY=MO"]}),
            json!({"id": "m1_x", "recurringEventId": "m1", "status": "cancelled",
                   "originalStartTime": {"dateTime": "2026-11-09T18:00:00Z", "timeZone": "Europe/London"}}),
            json!({"id": "s1", "status": "confirmed", "summary": "Lunch, with Amy", "start": {"date": "2026-11-20"}, "end": {"date": "2026-11-21"}}),
        ];
        let v = google_calendar_ics(&evs, "Europe/London");
        assert_eq!(v.len(), 2);
        assert!(v[0].contains("EXDATE;TZID=Europe/London:20261109T180000"), "{}", v[0]);
        assert!(v[1].contains("DTSTART;VALUE=DATE:20261120"));
        assert!(v[1].contains("SUMMARY:Lunch\\, with Amy"));
    }

    #[test]
    fn contacts() {
        let c = json!({"id": "x", "displayName": "Bob Smith", "givenName": "Bob", "surname": "Smith",
            "emailAddresses": [{"address": "bob@example.com"}], "mobilePhone": "+44 7700 900000",
            "businessAddress": {"city": "Mansfield", "countryOrRegion": "UK"}, "companyName": "Acme; Ltd"});
        let v = graph_contact_vcard(&c);
        assert!(v.contains("FN:Bob Smith") && v.contains("N:Smith;Bob;;;") && v.contains("EMAIL;TYPE=INTERNET:bob@example.com"));
        assert!(v.contains("ORG:Acme\\; Ltd;") && v.contains("ADR;TYPE=WORK:;;;Mansfield;;;UK"));
        let m = crate::carddav::vcard_meta(&v).unwrap();
        assert_eq!(m.emails, vec!["bob@example.com"]);
        let p = json!({"resourceName": "people/c1", "names": [{"displayName": "Ann Lee", "givenName": "Ann", "familyName": "Lee"}],
            "phoneNumbers": [{"value": "01623 000000", "type": "home"}], "birthdays": [{"date": {"month": 3, "day": 9}}]});
        let v = google_person_vcard(&p).unwrap();
        assert!(v.contains("UID:google-c1") && v.contains("BDAY:--0309") && v.contains("TEL;TYPE=HOME,VOICE:01623 000000"));
    }

    #[test]
    fn split() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VTIMEZONE\r\nTZID:Europe/London\r\nEND:VTIMEZONE\r\nBEGIN:VEVENT\r\nUID:a\r\nRRULE:FREQ=DAILY\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:a\r\nRECURRENCE-ID:20260101T000000Z\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nSUMMARY:no uid\r\nBEGIN:VALARM\r\nTRIGGER:-PT5M\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let v = split_ics(ics).unwrap();
        assert_eq!(v.len(), 2);
        assert!(v[0].contains("TZID:Europe/London") && v[0].matches("BEGIN:VEVENT").count() == 2);
        assert!(v[1].contains("UID:import-") && v[1].contains("BEGIN:VALARM"));
        assert!(crate::caldav::ics_meta(&v[1]).is_ok());
    }
}
