"""Migrations (IMAP, Exchange Online via a fake Graph, Google via fake APIs, Takeout files)
and CardDAV contacts. Expects run_migrate.sh's fixture: tony (admin) and amy, server on
the usual test ports, fake_clouds.py on 9911."""
import base64, http.client as httpc, imaplib, json, os, smtplib, ssl, subprocess, sys, time

ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
H = "127.0.0.1"; R = []
TONY = ("tony@johncock.test", "CorrectHorse1")
AMY = ("amy@poffles.test", "BatteryStaple2")
BIN = os.environ.get("PWBIN", "/home/claude/postwright-repo/target/release/postwright")
CFG = "/tmp/pwtest/postwright.toml"

def check(n, c, i=""):
    R.append(bool(c)); print(("PASS " if c else "FAIL ") + n + (f"  [{str(i)[:600]}]" if i and not c else ""))

def http(method, path, body=None, token=None, basic=None, headers=None, raw=None):
    c = httpc.HTTPSConnection(H, 8443, context=ctx)
    h = {"X-Requested-With": "test"}; h.update(headers or {})
    if token: h["Authorization"] = "Bearer " + token
    if basic: h["Authorization"] = "Basic " + base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()
    if body is not None:
        raw = json.dumps(body).encode(); h["Content-Type"] = "application/json"
    c.request(method, path, body=raw, headers=h)
    r = c.getresponse(); d = r.read(); c.close()
    try: d = json.loads(d)
    except Exception: d = d.decode(errors="replace")
    return r.status, d

def login(who):
    return http("POST", "/api/v1/login", {"email": who[0], "password": who[1], "kind": "app"})[1]["token"]

TOK = login(TONY)
def admin(method, path, body=None):
    return http(method, "/api/v1/admin/migrate/" + path, body, token=TOK)

def wait():
    for _ in range(240):
        s, d = admin("GET", "status")
        if not d["progress"]["running"]:
            return d["progress"]
        time.sleep(0.5)
    raise SystemExit("migration didn't finish")

def imap(who):
    m = imaplib.IMAP4_SSL(H, 1993, ssl_context=ctx); m.login(*who); return m

def count(m, folder, crit="ALL"):
    typ, _ = m.select(f'"{folder}"', readonly=True)
    if typ != "OK":
        return -1
    return len(m.search(None, crit)[1][0].split())

# ----------------------------------------------------------------- seed tony
sm = smtplib.SMTP_SSL(H, 4465, context=ctx); sm.login(*TONY)
for i in range(3):
    sm.sendmail(TONY[0], [TONY[0]], f"From: {TONY[0]}\r\nTo: {TONY[0]}\r\nSubject: Seed {i}\r\nMessage-ID: <seed{i}@test>\r\n\r\nbody {i}\r\n")
sm.quit(); time.sleep(1.5)
m = imap(TONY)
m.create('"Projects/2026"')
m.append('"Projects/2026"', "(\\Seen \\Flagged)", imaplib.Time2Internaldate(time.mktime((2025, 3, 1, 12, 0, 0, 0, 0, 0))), b"From: a@b.test\r\nSubject: Old project\r\n\r\nplan\r\n")
m.append('"Caf&AOk-"', "(\\Seen)", None, b"Subject: Draft-ish\r\n\r\nx\r\n") if m.create('"Caf&AOk-"')[0] == "OK" else None
m.select("INBOX"); m.store("1", "+FLAGS", "\\Seen")
m.logout()

# --------------------------------------------------------------- IMAP source
src = {"kind": "imap", "host": "127.0.0.1", "port": 1993, "security": "tls", "insecure": False}
s, d = admin("POST", "test", {"source": src, "mailboxes": [{"source": TONY[0], "password": TONY[1], "target": "x@johncock.test"}], "options": {}})
check("untrusted certificate is reported clearly", s == 400 and "self-signed" in str(d), d)
src["insecure"] = True
s, d = admin("POST", "test", {"source": src, "mailboxes": [{"source": TONY[0], "password": "wrong", "target": "x@johncock.test"}], "options": {}})
check("wrong password reported", s == 400 and "sign-in" in str(d), d)
s, d = admin("POST", "test", {"source": src, "mailboxes": [{"source": TONY[0], "password": TONY[1], "target": "x@johncock.test"}], "options": {}})
check("IMAP test signs in and counts folders", s == 200 and "folders found" in d["message"], d)
job = {"source": src, "mailboxes": [{"source": TONY[0], "password": TONY[1], "target": "copy@johncock.test"}],
       "options": {"mail": True, "calendars": False, "contacts": False, "create_users": True}}
s, d = admin("POST", "start", job)
check("IMAP migration starts", s == 200, d)
p = wait()
mb = p["mailboxes"][0]
check("IMAP migration finished cleanly", mb["state"] == "done" and mb["messages"] == 5, mb)
check("new account's password is listed", len(p["created"]) == 1 and p["created"][0][0] == "copy@johncock.test")
newpw = p["created"][0][1]
s, csv = admin("GET", "created.csv")
check("passwords download as CSV", "copy@johncock.test," + newpw in csv, csv)
c = imap(("copy@johncock.test", newpw))
check("INBOX copied", count(c, "INBOX") == 3)
check("read status kept", count(c, "INBOX", "SEEN") == 1)
check("nested folder copied with flags", count(c, "Projects/2026", "FLAGGED") == 1)
c.select('"Projects/2026"', readonly=True)
typ, dd = c.fetch("1", "(INTERNALDATE)")
check("original date kept", b"01-Mar-2025" in dd[0], dd)
check("non-ASCII folder name decoded and recreated", count(c, "Caf&AOk-") == 1)
c.logout()
s, st = admin("GET", "status")
check("saved job is shown without the password", st["last_job"]["mailboxes"][0]["password"] == "(saved)", st["last_job"])
sm = smtplib.SMTP_SSL(H, 4465, context=ctx); sm.login(*TONY)
sm.sendmail(TONY[0], [TONY[0]], f"From: {TONY[0]}\r\nTo: {TONY[0]}\r\nSubject: Arrived later\r\n\r\nnew\r\n"); sm.quit(); time.sleep(1.5)
s, d = admin("POST", "rerun", {})
p = wait()
mb = p["mailboxes"][0]
check("catch-up copies only what's new", mb["messages"] == 1 and mb["skipped"] == 5, mb)
c = imap(("copy@johncock.test", newpw))
check("no duplicates after catch-up", count(c, "INBOX") == 4); c.logout()

# ----------------------------------------------------------- Exchange Online
exo = {"kind": "exchange_online", "tenant": "fake.onmicrosoft.com", "client_id": "cid", "client_secret": "wrong",
       "graph_url": "http://127.0.0.1:9911/graph", "login_url": "http://127.0.0.1:9911/login"}
s, d = admin("POST", "discover", {"source": exo})
check("bad client secret explained", s == 400 and "Invalid client secret" in str(d), d)
exo["client_secret"] = "s3cret"
s, d = admin("POST", "discover", {"source": exo})
check("Graph lists mailboxes across pages", s == 200 and [x["target"] for x in d] == ["carol@graph.test", "sales@graph.test"], d)
check("shared/disabled mailboxes are marked", d[1]["kind"] != "user" and d[0]["name"] == "Carol Graph", d)
s, d = admin("POST", "start", {"source": exo, "mailboxes": [{"source": "carol@graph.test", "target": "carol@graph.test", "name": "Carol Graph"},
                                                           {"source": "nomail@graph.test", "target": "nomail@graph.test"}], "options": {}})
p = wait()
carol = p["mailboxes"][0]
check("Graph mail copied", carol["messages"] == 4 and carol["state"] == "done", carol)
check("Graph calendar and contacts copied", carol["events"] == 2 and carol["contacts"] == 1, carol)
check("mailbox without Exchange explained", p["mailboxes"][1]["state"] == "failed" and "no Exchange Online mailbox" in (p["mailboxes"][1]["last_error"] or ""), p["mailboxes"][1])
check("new domain added for the migrated address", any("added domain graph.test" in l for l in p["log"]), p["log"][-5:])
cpw = dict(p["created"])["carol@graph.test"]
c = imap(("carol@graph.test", cpw))
check("Inbox, subfolder and Sent mapped", count(c, "INBOX") == 2 and count(c, "INBOX/Projects") == 1 and count(c, "Sent") == 1)
check("Sync Issues left behind", count(c, "Sync Issues") == -1)
check("Graph read and flagged status", count(c, "INBOX", "SEEN") == 1 and count(c, "INBOX", "FLAGGED") == 1); c.logout()
cbasic = ("carol@graph.test", cpw)
s, d = http("PROPFIND", "/dav/calendars/carol@graph.test/calendar/", basic=cbasic, headers={"Depth": "1"},
            raw=b'<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><c:calendar-data/></d:prop></d:propfind>')
check("Graph events landed in the default calendar", s == 207 and "Dentist" in d and "Team call" in d, str(d)[:300])
check("deleted occurrence became EXDATE (DST-correct)", "EXDATE;TZID=Europe/London:20261009T090000" in d, d)
check("other people's calendars not copied", "Boss" not in str(http("GET", "/api/v1/calendars", token=login(cbasic))[1]))
s, d = http("GET", "/api/v1/me", token=login(cbasic))
check("display name taken from Microsoft 365", d.get("name") == "Carol Graph", d)

# ------------------------------------------------------------ Google Workspace
sa = json.dumps({"type": "service_account", "client_email": "mig@proj.iam.gserviceaccount.com", "private_key": open("/tmp/sa_key.pem").read(),
                 "token_uri": "https://oauth2.googleapis.com/token"})
gsrc = {"kind": "google", "service_account": sa, "admin_email": "boss@gw.test", "api_url": "http://127.0.0.1:9911/google"}
s, d = admin("POST", "discover", {"source": gsrc})
check("Google lists users via the admin", s == 200 and d[0]["target"] == "erin@gw.test" and d[0]["name"] == "Erin Google", d)
s, d = admin("POST", "start", {"source": gsrc, "mailboxes": [{"source": "erin@gw.test", "target": "erin@gw.test"}], "options": {}})
p = wait()
erin = p["mailboxes"][0]
check("Gmail copied", erin["messages"] == 5 and erin["state"] == "done", erin)
check("Google calendar and contacts copied", erin["events"] == 1 and erin["contacts"] == 1, erin)
epw = dict(p["created"])["erin@gw.test"]
c = imap(("erin@gw.test", epw))
check("labels became folders", count(c, "INBOX") == 2 and count(c, "Sent") == 1 and count(c, "Receipts/2026") == 1 and count(c, "Archive") == 1 and count(c, "Junk") == 1)
check("Gmail unread/starred kept", count(c, "INBOX", "UNSEEN") == 1 and count(c, "INBOX", "FLAGGED") == 1); c.logout()
s, d = http("GET", "/dav/calendars/erin@gw.test/calendar/", basic=("erin@gw.test", epw))
check("cancelled Google occurrence became EXDATE", "EXDATE;TZID=Europe/London:20261110T180000" in str(d), d)

# --------------------------------------------------------------- Takeout files
os.makedirs("/tmp/takeout/Mail", exist_ok=True); os.makedirs("/tmp/takeout/Calendar", exist_ok=True); os.makedirs("/tmp/takeout/Contacts/My Contacts", exist_ok=True)
open("/tmp/takeout/Mail/All mail Including Spam and Trash.mbox", "w").write(
    "From 1234@xxx Mon Nov 02 09:00:00 +0000 2026\nX-Gmail-Labels: Inbox,Unread,\"Work, 2026\"\nSubject: Takeout one\nDate: Mon, 02 Nov 2026 09:00:00 +0000\n\n>From the start\nline\n\n"
    "From 5678@xxx Mon Nov 02 10:00:00 +0000 2026\nX-Gmail-Labels: Sent,Opened\nSubject: Takeout two\n\nhi\n\n"
    "From 9@xxx Mon Nov 02 10:00:00 +0000 2026\nX-Gmail-Labels: Chat\nSubject: chat\n\nhi\n")
open("/tmp/takeout/Calendar/amy@poffles.test.ics", "w").write(
    "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:tk1\r\nDTSTART:20261201T100000Z\r\nDTEND:20261201T110000Z\r\nSUMMARY:Takeout event\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
open("/tmp/takeout/Contacts/My Contacts/My Contacts.vcf", "w").write(
    "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Gina Card\r\nEMAIL:gina@ext.test\r\nEND:VCARD\r\nBEGIN:VCARD\r\nVERSION:3.0\r\nFN:Hal Card\r\nEND:VCARD\r\n")
s, d = admin("POST", "files", {"path": "/tmp/takeout", "target": AMY[0]})
p = wait()
fm = p["mailboxes"][0]
check("Takeout imported", fm["messages"] == 2 and fm["events"] == 1 and fm["contacts"] == 2 and fm["state"] == "done", fm)
c = imap(AMY)
check("Takeout labels and unread kept", count(c, "Work, 2026") == 1 and count(c, "INBOX", "UNSEEN") >= 1 and count(c, "Sent") == 1)
c.select("INBOX", readonly=True); t, dd = c.search(None, "SUBJECT", '"Takeout one"'); body = c.fetch(dd[0].split()[0], "(BODY[TEXT])")[1][0][1]
check("mboxrd >From unescaped", body.startswith(b"From the start"), body); c.logout()
s, d = admin("POST", "files", {"path": "/tmp/takeout", "target": AMY[0]})
p = wait()
check("importing the same files again adds nothing", p["mailboxes"][0]["messages"] == 0 and p["mailboxes"][0]["contacts"] == 0, p["mailboxes"][0])
s, d = admin("POST", "files", {"path": "/nope", "target": AMY[0]})
check("missing path explained", s == 400 and "doesn't exist" in str(d), d)

# ---------------------------------------------------------------- CardDAV
s, d = http("PROPFIND", "/dav/principals/amy@poffles.test/", basic=AMY, headers={"Depth": "0"},
            raw=b'<d:propfind xmlns:d="DAV:" xmlns:r="urn:ietf:params:xml:ns:carddav"><d:prop><r:addressbook-home-set/></d:prop></d:propfind>')
check("principal advertises the address-book home", s == 207 and "/dav/addressbooks/amy@poffles.test/" in d, d)
s, d = http("PROPFIND", "/dav/addressbooks/amy@poffles.test/", basic=AMY, headers={"Depth": "1"})
check("address books listed (Contacts + Directory)", s == 207 and "R:addressbook" in d and "Directory" in d and ">Contacts<" in d, d)
vc = b"BEGIN:VCARD\r\nVERSION:3.0\r\nUID:ian-1\r\nFN:Ian Phone\r\nEMAIL:ian@ext.test\r\nEND:VCARD\r\n"
s, _ = http("PUT", "/dav/addressbooks/amy@poffles.test/contacts/ian-1.vcf", basic=AMY, headers={"Content-Type": "text/vcard", "If-None-Match": "*"}, raw=vc)
check("PUT a contact", s == 201)
s, d = http("REPORT", "/dav/addressbooks/amy@poffles.test/contacts/", basic=AMY, headers={"Depth": "1"},
            raw=b'<r:addressbook-query xmlns:d="DAV:" xmlns:r="urn:ietf:params:xml:ns:carddav"><d:prop><d:getetag/><r:address-data/></d:prop><r:filter><r:prop-filter name="EMAIL"><r:text-match match-type="starts-with">ian</r:text-match></r:prop-filter></r:filter></r:addressbook-query>')
check("addressbook-query filters", s == 207 and "Ian Phone" in d and "Gina" not in d, d)
s, d = http("REPORT", "/dav/addressbooks/amy@poffles.test/contacts/", basic=AMY, headers={"Depth": "1"},
            raw=b'<r:addressbook-multiget xmlns:d="DAV:" xmlns:r="urn:ietf:params:xml:ns:carddav"><d:prop><r:address-data/></d:prop><d:href>/dav/addressbooks/amy@poffles.test/contacts/ian-1.vcf</d:href></r:addressbook-multiget>')
check("addressbook-multiget", s == 207 and "Ian Phone" in d, d)
s, d = http("GET", "/dav/addressbooks/amy@poffles.test/directory/", basic=AMY)
check("Directory lists people in the same domain only", "amy@poffles.test" in d and "tony@johncock.test" not in d and "hello@poffles.test" in d, d)
s, _ = http("PUT", "/dav/addressbooks/amy@poffles.test/directory/x.vcf", basic=AMY, raw=vc)
check("Directory is read only", s == 403, s)
s, _ = http("GET", "/dav/addressbooks/tony@johncock.test/contacts/", basic=AMY)
check("can't read someone else's address book", s == 403, s)
atok = login(AMY)
s, d = http("POST", "/api/v1/addressbooks/contacts/shares", {"user": TONY[0], "write": False}, token=atok)
s, d = http("PROPFIND", "/dav/addressbooks/tony@johncock.test/", basic=TONY, headers={"Depth": "1"})
check("shared address book appears for the sharee", "Contacts (amy@poffles.test)" in d, d)
s, d = http("GET", "/api/v1/addressbooks", token=atok)
check("settings API lists address books with counts", any(b["slug"] == "contacts" and b["count"] == 3 for b in d) and any(b["directory"] for b in d), d)
s, d = http("POST", "/api/v1/addressbooks/contacts/import", {"vcf": "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Jo Import\r\nEND:VCARD\r\n"}, token=atok)
check(".vcf import from the settings page", d.get("imported") == 1, d)
s, d = http("PUT", "/api/v1/name", {"name": "Amy Poffles"}, token=atok)
s, d = http("GET", "/dav/addressbooks/tony@johncock.test/directory/", basic=TONY)
s2, d2 = http("GET", "/dav/addressbooks/amy@poffles.test/directory/", basic=AMY)
check("display name appears in the directory", "FN:Amy Poffles" in d2, d2)
s, d = http("GET", "/.well-known/carddav")
check("/.well-known/carddav redirects", s == 301)

# -------------------------------------------------------------------- CLI
open("/tmp/job.json", "w").write(json.dumps({"source": gsrc, "mailboxes": [{"source": "erin@gw.test", "target": "erin@gw.test"}]}))
r = subprocess.run([BIN, "-c", CFG, "migrate", "run", "/tmp/job.json"], capture_output=True, text=True, timeout=120)
check("CLI catch-up run", r.returncode == 0 and "0 messages" in r.stdout, r.stdout + r.stderr)
r = subprocess.run([BIN, "-c", CFG, "migrate", "discover", "/tmp/job.json"], capture_output=True, text=True, timeout=60)
check("CLI discover", "erin@gw.test" in r.stdout and "Erin Google" in r.stdout, r.stdout + r.stderr)

print(f"\n{sum(R)}/{len(R)} passed"); sys.exit(0 if all(R) else 1)
