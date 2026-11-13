"""End-to-end tests for out of office, signatures, CalDAV sharing, settings API and autoconfig."""
import base64, imaplib, json, smtplib, ssl, subprocess, sys, time, http.client

ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
H = "127.0.0.1"
TONY = ("tony@johncock.test", "CorrectHorse1")
AMY = ("amy@poffles.test", "BatteryStaple2")
results = []

def check(name, cond, info=""):
    results.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{info}]" if info and not cond else ""))

TOKENS = {}
def token(who):
    if who not in TOKENS:
        c = http.client.HTTPSConnection(H, 8443, context=ctx)
        c.request("POST", "/api/v1/login", body=json.dumps({"email": who[0], "password": who[1], "kind": "app"}), headers={"Content-Type": "application/json"})
        r = c.getresponse(); TOKENS[who] = json.loads(r.read())["token"]; c.close()
    return TOKENS[who]

def req(method, path, who=TONY, body=None, headers=None):
    c = http.client.HTTPSConnection(H, 8443, context=ctx)
    h = dict(headers or {})
    if who and (path.startswith("/dav") or path.startswith("/.well-known")):
        h["Authorization"] = "Basic " + base64.b64encode(f"{who[0]}:{who[1]}".encode()).decode()
    elif who:
        h["Authorization"] = "Bearer " + token(who)
    if isinstance(body, (dict, list)):
        body = json.dumps(body); h.setdefault("Content-Type", "application/json")
    c.request(method, path, body=body, headers=h)
    r = c.getresponse(); data = r.read(); c.close()
    return r.status, {k.lower(): v for k, v in r.getheaders()}, data

def inbox(who, search="ALL"):
    m = imaplib.IMAP4_SSL(H, 1993, ssl_context=ctx); m.login(*who); m.select("INBOX")
    typ, d = m.search(None, *search.split(" ", 1)) if " " in search else m.search(None, search)
    out = [m.fetch(n, "(BODY.PEEK[])")[1][0][1] for n in d[0].split()]
    m.logout(); return out

def queue():
    return subprocess.run(["/home/claude/postwright-repo/target/release/postwright", "-c", "/tmp/pwtest/postwright.toml", "queue", "list"], capture_output=True, text=True).stdout

# --- Settings page / API / autoconfig
s, h, _ = req("GET", "/", who=None)
check("settings page requires sign-in", s == 303 and h.get("location") == "/login")
s, h, body = req("GET", "/")
check("settings page served with CSP", s == 200 and b"Out of office" in body and "content-security-policy" in h)
s, _, body = req("GET", "/.well-known/autoconfig/mail/config-v1.1.xml?emailaddress=tony%40johncock.test", who=None)
check("Thunderbird autoconfig", s == 200 and b"<hostname>mail.test.local</hostname>" in body and b"1993" in body, body[:200])
s, _, body = req("PUT", "/api/v1/settings", body="x", headers={"Content-Type": "text/plain"})
check("API refuses non-JSON writes (CSRF guard)", s == 415)

# --- Out of office
s, _, body = req("PUT", "/api/v1/settings", body={
    "vacation": {"enabled": True, "subject": "Away until Monday", "body": "Back Monday – Tony", "start": None, "end": None, "internal_only": False},
    "signature": {"text": "Tony Johncock\nPoffles", "html": "", "append": True}})
check("save settings via API", s == 200, body)
s, _, body = req("GET", "/api/v1/settings")
check("settings round-trip", json.loads(body)["vacation"]["subject"] == "Away until Monday")

smtp = smtplib.SMTP_SSL(H, 4465, context=ctx); smtp.login(*AMY)
smtp.sendmail(AMY[0], [TONY[0]], f"From: {AMY[0]}\r\nTo: {TONY[0]}\r\nSubject: Lunch?\r\nMessage-ID: <lunch@poffles.test>\r\n\r\nFancy lunch?\r\n")
smtp.sendmail(AMY[0], [TONY[0]], f"From: {AMY[0]}\r\nTo: {TONY[0]}\r\nSubject: Lunch again\r\n\r\nSecond mail\r\n")
smtp.quit()
s25 = smtplib.SMTP(H, 2525); s25.ehlo("lists.example.org")
s25.sendmail("news@lists.example.org", [TONY[0]], "From: news@lists.example.org\r\nList-Id: <news.example.org>\r\nSubject: Newsletter\r\n\r\nx\r\n")
s25.sendmail("bob@example.org", [TONY[0]], "From: bob@example.org\r\nSubject: External\r\n\r\nhi\r\n")
s25.quit()
time.sleep(2)
replies = inbox(AMY, "SUBJECT Away")
check("OOO reply delivered to local sender", len(replies) == 1, len(replies))
r = replies[0] if replies else b""
check("OOO reply is RFC 3834 compliant", b"Auto-Submitted: auto-replied" in r and b"In-Reply-To: <lunch@poffles.test>" in r and b"DKIM-Signature" in r, r[:600])
check("only one OOO reply per sender", len(replies) == 1)
q = queue()
log = open("/tmp/pwtest/server.log").read()
check("OOO reply sent to external sender", "out-of-office reply from tony@johncock.test to bob@example.org" in log)
check("no OOO reply to mailing list", "to news@lists.example.org" not in log)

# --- Signature append (Tony has append=true)
smtp = smtplib.SMTP_SSL(H, 4465, context=ctx); smtp.login(*TONY)
smtp.sendmail(TONY[0], [AMY[0]], f"From: {TONY[0]}\r\nTo: {AMY[0]}\r\nSubject: Sig test\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello Amy\r\n")
smtp.quit()
time.sleep(0.5)
m = inbox(AMY, "SUBJECT Sig")
check("server appended signature", m and b"Hello Amy\r\n\r\n-- \r\nTony Johncock\r\nPoffles" in m[0], m[0][-200:] if m else m)
req("PUT", "/api/v1/settings", body={"vacation": {"enabled": False}, "signature": {"text": "Tony Johncock\nPoffles", "append": True}})

# --- CalDAV discovery
s, h, _ = req("PROPFIND", "/.well-known/caldav", headers={"Depth": "0"})
check(".well-known/caldav redirects", s == 301 and h.get("location") == "/dav/")
pf = '<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><d:current-user-principal/></d:prop></d:propfind>'
s, _, body = req("PROPFIND", "/dav/", body=pf, headers={"Depth": "0", "Content-Type": "application/xml"})
check("current-user-principal", s == 207 and b"/dav/principals/tony@johncock.test/" in body, body)
pf = '<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><c:calendar-home-set/><x:unknown xmlns:x="urn:x"/></d:prop></d:propfind>'
s, _, body = req("PROPFIND", "/dav/principals/tony@johncock.test/", body=pf, headers={"Depth": "0"})
check("calendar-home-set + 404 for unknown prop", b"/dav/calendars/tony@johncock.test/" in body and b"404 Not Found" in body, body)
pf = '<d:propfind xmlns:d="DAV:" xmlns:cs="http://calendarserver.org/ns/"><d:prop><d:resourcetype/><d:displayname/><cs:getctag/></d:prop></d:propfind>'
s, _, body = req("PROPFIND", "/dav/calendars/tony@johncock.test/", body=pf, headers={"Depth": "1"})
check("home lists default calendar", b"/dav/calendars/tony@johncock.test/calendar/" in body and b"<C:calendar/>" in body, body)
s, _, _ = req("PROPFIND", "/dav/calendars/amy@poffles.test/", body=pf, headers={"Depth": "1"})
check("cannot browse another user's calendars", s == 403)

ev = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\nBEGIN:VEVENT\r\nUID:ev1@test\r\nDTSTAMP:20261113T100000Z\r\nDTSTART:20261120T090000Z\r\nDTEND:20261120T100000Z\r\nSUMMARY:Supplier meeting\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
s, h, _ = req("PUT", "/dav/calendars/tony@johncock.test/calendar/ev1.ics", body=ev, headers={"Content-Type": "text/calendar", "If-None-Match": "*"})
etag = h.get("etag")
check("PUT event", s == 201 and etag, (s, h))
s, _, _ = req("PUT", "/dav/calendars/tony@johncock.test/calendar/ev1.ics", body=ev, headers={"If-None-Match": "*"})
check("If-None-Match prevents overwrite", s == 412)
s, _, _ = req("PUT", "/dav/calendars/tony@johncock.test/calendar/dupe.ics", body=ev)
check("duplicate UID rejected", s == 409)
s, h, body = req("GET", "/dav/calendars/tony@johncock.test/calendar/ev1.ics")
check("GET event", s == 200 and b"Supplier meeting" in body and h.get("etag") == etag)
rq = '<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><d:getetag/><c:calendar-data/></d:prop><c:filter><c:comp-filter name="VCALENDAR"><c:comp-filter name="VEVENT"><c:time-range start="20261119T000000Z" end="20261121T000000Z"/></c:comp-filter></c:comp-filter></c:filter></c:calendar-query>'
s, _, body = req("REPORT", "/dav/calendars/tony@johncock.test/calendar/", body=rq, headers={"Depth": "1"})
check("calendar-query in range", s == 207 and b"Supplier meeting" in body, body[:300])
s, _, body = req("REPORT", "/dav/calendars/tony@johncock.test/calendar/", body=rq.replace("20261119", "20270101").replace("20261121", "20270201"), headers={"Depth": "1"})
check("calendar-query out of range excludes", b"Supplier" not in body)
mg = '<c:calendar-multiget xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><d:getetag/><c:calendar-data/></d:prop><d:href>/dav/calendars/tony@johncock.test/calendar/ev1.ics</d:href><d:href>/dav/calendars/tony@johncock.test/calendar/missing.ics</d:href></c:calendar-multiget>'
s, _, body = req("REPORT", "/dav/calendars/tony@johncock.test/calendar/", body=mg, headers={"Depth": "1"})
check("calendar-multiget", b"Supplier meeting" in body and b"404 Not Found" in body)
mk = '<c:mkcalendar xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:set><d:prop><d:displayname>Poffles rota</d:displayname></d:prop></d:set></c:mkcalendar>'
s, _, _ = req("MKCALENDAR", "/dav/calendars/tony@johncock.test/rota/", body=mk)
check("MKCALENDAR", s == 201)

# --- Sharing
s, _, body = req("POST", "/api/v1/calendars/rota/shares", body={"user": AMY[0], "write": False})
check("share calendar (view only)", s == 200, body)
s, _, body = req("PROPFIND", "/dav/calendars/amy@poffles.test/", who=AMY, body=pf, headers={"Depth": "1"})
shared = [l for l in body.decode().split("<D:href>") if "shared-" in l]
check("sharee sees shared calendar", b"Poffles rota (tony@johncock.test)" in body and shared, body[:500])
shared_href = shared[0].split("</D:href>")[0] if shared else ""
s, _, _ = req("PUT", shared_href + "x.ics", who=AMY, body=ev.replace("ev1@test", "amy1@test"))
check("view-only sharee cannot write", s == 403)
req("POST", "/api/v1/calendars/rota/shares", body={"user": AMY[0], "write": True})
s, _, _ = req("PUT", shared_href + "x.ics", who=AMY, body=ev.replace("ev1@test", "amy1@test"))
check("edit sharee can write", s == 201)
s, _, body = req("GET", "/dav/calendars/tony@johncock.test/rota/x.ics")
check("owner sees sharee's event", s == 200 and b"amy1@test" in body)
s, _, body = req("GET", "/api/v1/calendars")
cals = json.loads(body)
check("API lists calendars and shares", any(c["slug"] == "rota" and c["shares"][0]["user"] == AMY[0] for c in cals), cals)
s, _, _ = req("DELETE", "/api/v1/calendars/rota/shares/amy@poffles.test", headers={"X-Requested-With": "postwright"})
s, _, _ = req("GET", shared_href + "x.ics", who=AMY)
check("unshare revokes access", s == 404)

# --- brute-force on HTTP
def bad_login(i):
    c = http.client.HTTPSConnection(H, 8443, context=ctx)
    c.request("POST", "/api/v1/login", body=json.dumps({"email": TONY[0], "password": f"bad{i}"}), headers={"Content-Type": "application/json"})
    r = c.getresponse(); r.read(); c.close(); return r.status
fails = [bad_login(i) for i in range(6)]
check("HTTP brute force blocked", fails[-1] == 429, fails)

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
