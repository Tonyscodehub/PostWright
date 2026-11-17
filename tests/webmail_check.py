"""Webmail API checks: mail, sending, drafts, calendar with invitations, contacts."""
import base64, http.client, json, smtplib, ssl, sys, time, urllib.parse
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
H = "127.0.0.1"; R = []
TONY = ("tony@johncock.test", "CorrectHorse1")
AMY = ("amy@poffles.test", "BatteryStaple2")

def check(n, c, i=""):
    R.append(bool(c)); print(("PASS " if c else "FAIL ") + n + (f"  [{str(i)[:400]}]" if i and not c else ""))

TOK = {}
def token(who):
    if who not in TOK:
        c = http.client.HTTPSConnection(H, 8443, context=ctx)
        c.request("POST", "/api/v1/login", body=json.dumps({"email": who[0], "password": who[1], "kind": "app", "name": "webmail_check"}), headers={"Content-Type": "application/json"})
        TOK[who] = json.loads(c.getresponse().read())["token"]
    return TOK[who]

def api(method, path, body=None, who=TONY, raw=False, ctype="application/json"):
    c = http.client.HTTPSConnection(H, 8443, context=ctx, timeout=60)
    h = {"Authorization": "Bearer " + token(who), "X-Requested-With": "t"}
    if body is not None:
        body = json.dumps(body) if ctype == "application/json" else body; h["Content-Type"] = ctype
    c.request(method, "/api/v1/" + path, body=body, headers=h)
    r = c.getresponse(); d = r.read()
    if raw: return r.status, {k.lower(): v for k, v in r.getheaders()}, d
    try: return r.status, json.loads(d)
    except Exception: return r.status, d

q = lambda **k: urllib.parse.urlencode(k)

def inbound(msg, to="tony@johncock.test"):
    s = smtplib.SMTP(H, 2525); s.ehlo("mx.sender.example")
    s.sendmail("carol@sender.example", [to], msg.encode()); s.quit()

def wait_for(who, folder, pred, tries=30):
    for _ in range(tries):
        s, d = api("GET", "mail/messages?" + q(folder=folder), who=who)
        hits = [m for m in d.get("messages", []) if pred(m)] if s == 200 else []
        if hits: return hits[0]
        time.sleep(0.3)
    return None

png = base64.b64encode(bytes.fromhex("89504e470d0a1a0a0000000d4948445200000001000000010806000000" "1f15c4890000000d49444154789c6360000002000154a24f5d0000000049454e44ae426082")).decode()
tag = str(int(time.time()))
html_mail = f"""From: Carol <carol@sender.example>\r
To: tony@johncock.test\r
Cc: amy@poffles.test\r
Subject: Lunch plans {tag}\r
Message-ID: <lunch-{tag}@sender.example>\r
MIME-Version: 1.0\r
Content-Type: multipart/mixed; boundary=outer\r
\r
--outer\r
Content-Type: multipart/related; boundary=rel\r
\r
--rel\r
Content-Type: text/html; charset=utf-8\r
\r
<p>Hi Tony,</p><p>Lunch on <b>Friday</b>? <img src="cid:logo1"> <img src="https://tracker.example/p.gif"></p><script>alert(1)</script>\r
--rel\r
Content-Type: image/png\r
Content-ID: <logo1>\r
Content-Transfer-Encoding: base64\r
\r
{png}\r
--rel--\r
--outer\r
Content-Type: text/html; name="menu.html"\r
Content-Disposition: attachment; filename="menu.html"\r
\r
<script>alert('xss')</script>\r
--outer--\r
"""
inbound(html_mail)
s, d = api("GET", "mail/folders")
check("folders listed with special-use roles", s == 200 and {"inbox", "sent", "drafts", "trash", "junk"} <= {f["special"] for f in d}, d)
m = wait_for(TONY, "INBOX", lambda m: m["subject"] == f"Lunch plans {tag}")
check("message list shows the new mail with sender and preview", m and m["from"] == "Carol" and "Lunch on Friday" in m["preview"] and not m["seen"] and m["attach"], m)
uid = m["uid"]
s, full = api("GET", "mail/message?" + q(folder="INBOX", uid=uid))
check("message opens with addresses", s == 200 and full["from"][0]["email"] == "carol@sender.example" and full["cc"][0]["email"] == "amy@poffles.test", full)
check("inline cid image embedded as data: URL", "data:image/png;base64," in (full["html"] or "") and "cid:logo1" not in full["html"], (full["html"] or "")[:200])
check("remote image left for the client to block", "https://tracker.example/p.gif" in full["html"])
att = [a for a in full["attachments"] if a["name"] == "menu.html"]
check("attachment listed (inline image not listed)", len(att) == 1 and not any(a["type"] == "image/png" for a in full["attachments"]), full["attachments"])
s, hd, body = api("GET", "mail/part?" + q(folder="INBOX", uid=uid, part=att[0]["part"], view=1), raw=True)
check("HTML attachment downloads as octet-stream, never rendered", s == 200 and hd.get("content-type") == "application/octet-stream" and hd.get("content-disposition", "").startswith("attachment") and hd.get("x-content-type-options") == "nosniff" and b"<script>" in body, hd)
s, d = api("GET", "mail/messages?" + q(folder="INBOX"))
check("opening marks it read", any(x["uid"] == uid and x["seen"] for x in d["messages"]))
s, hd, body = api("GET", "mail/raw?" + q(folder="INBOX", uid=uid), raw=True)
check(".eml download", s == 200 and b"Subject: Lunch plans" in body and ".eml" in hd.get("content-disposition", ""), hd)

# flags, search, unread filter
s, _ = api("POST", "mail/flags", {"folder": "INBOX", "uids": [uid], "add": ["\\Flagged"], "remove": ["\\Seen"]})
s, d = api("GET", "mail/messages?" + q(folder="INBOX", unread=1))
check("flag and mark unread", any(x["uid"] == uid and x["flagged"] and not x["seen"] for x in d["messages"]), d)
s, d = api("POST", "mail/flags", {"folder": "INBOX", "uids": [uid], "add": ["\\Deleted"]})
check("arbitrary flags refused", s == 400)
s, d = api("GET", "mail/messages?" + q(folder="INBOX", q=f"lunch {tag}"))
check("search finds it", d["total"] >= 1 and d["messages"][0]["uid"] == uid, d)
s, d = api("GET", "mail/messages?" + q(folder="INBOX", q="zzznothingzzz"))
check("search with no hits", d["total"] == 0)

# move to Junk and back, delete to Trash then for good
s, _ = api("POST", "mail/move", {"folder": "INBOX", "uids": [uid], "to": "Junk"})
j = wait_for(TONY, "Junk", lambda m: m["subject"] == f"Lunch plans {tag}", 5)
check("moved to Junk", s == 200 and j, s)
s, _ = api("POST", "mail/move", {"folder": "Junk", "uids": [j["uid"]], "to": "INBOX"})
back = wait_for(TONY, "INBOX", lambda m: m["subject"] == f"Lunch plans {tag}", 5)
check("rescued from Junk", back)
s, _ = api("POST", "mail/delete", {"folder": "INBOX", "uids": [back["uid"]]})
t = wait_for(TONY, "Trash", lambda m: m["subject"] == f"Lunch plans {tag}", 5)
check("delete moves to Trash", t)
s, _ = api("POST", "mail/delete", {"folder": "Trash", "uids": [t["uid"]]})
s, d = api("GET", "mail/messages?" + q(folder="Trash"))
check("delete in Trash removes for good", not any(x["subject"] == f"Lunch plans {tag}" for x in d["messages"]))

# folders
s, _ = api("POST", "mail/folders", {"action": "create", "name": f"Receipts{tag}"})
s2, _ = api("POST", "mail/folders", {"action": "rename", "name": f"Receipts{tag}", "to": f"Bills{tag}"})
s3, d = api("GET", "mail/folders")
check("create and rename folder", s == 200 and s2 == 200 and any(f["name"] == f"Bills{tag}" for f in d), d)
s, d = api("POST", "mail/folders", {"action": "delete", "name": "Sent"})
check("standard folders can't be deleted", s == 400)
s, _ = api("POST", "mail/folders", {"action": "delete", "name": f"Bills{tag}"})
check("delete folder", s == 200)

# identities, sending, Sent copy, threading
s, d = api("GET", "mail/identities")
check("identities include own address", s == 200 and any(i["email"] == "tony@johncock.test" for i in d["identities"]), d)
s, d = api("POST", "mail/send", {"from": "amy@poffles.test", "to": ["amy@poffles.test"], "subject": "spoof", "text": "x"})
check("can't send from someone else's address", s == 400 and "can't send from" in d.get("error", ""), d)
s, d = api("POST", "mail/send", {"from": "tony@johncock.test", "to": [], "subject": "x", "text": "x"})
check("needs a recipient", s == 400)
attach = base64.b64encode(b"Quarterly,Figures\n1,2\n").decode()
s, d = api("POST", "mail/send", {"from": "\"Tony\" <tony@johncock.test>", "to": ["Amy <amy@poffles.test>"], "bcc": ["tony@johncock.test"], "subject": f"Figures {tag}",
                                 "text": "Hi Amy,\nFigures attached.\n", "html": "<p>Hi Amy,</p><p><b>Figures</b> attached.</p>",
                                 "in_reply_to": f"<lunch-{tag}@sender.example>", "references": [f"<lunch-{tag}@sender.example>"],
                                 "attachments": [{"name": "figures.csv", "type": "text/csv", "data": attach}]})
check("send with HTML, attachment and Bcc", s == 200 and d.get("ok"), d)
got = wait_for(AMY, "INBOX", lambda m: m["subject"] == f"Figures {tag}")
check("recipient receives it", got and got["attach"], got)
s, af = api("GET", "mail/message?" + q(folder="INBOX", uid=got["uid"]), who=AMY)
check("threading headers and attachment intact", f"lunch-{tag}@sender.example" in json.dumps(af["references"]) and any(a["name"] == "figures.csv" for a in af["attachments"]) and "<b>Figures</b>" in (af["html"] or ""), af)
s, hd, raw_amy = api("GET", "mail/raw?" + q(folder="INBOX", uid=got["uid"]), who=AMY, raw=True)
check("Bcc not visible to recipients; DKIM-signed", b"Bcc:" not in raw_amy and b"DKIM-Signature:" in raw_amy, raw_amy[:600])
sent = wait_for(TONY, "Sent", lambda m: m["subject"] == f"Figures {tag}", 10)
check("copy saved in Sent, marked read", sent and sent["seen"], sent)
bccself = wait_for(TONY, "INBOX", lambda m: m["subject"] == f"Figures {tag}", 10)
check("Bcc recipient gets it", bccself)

# Reply marks the original answered
s, d = api("POST", "mail/send", {"from": "amy@poffles.test", "to": ["tony@johncock.test"], "subject": f"Re: Figures {tag}", "text": "Thanks!\n",
                                 "answering": {"folder": "INBOX", "uid": got["uid"], "forwarded": False}}, who=AMY)
s, d = api("GET", "mail/messages?" + q(folder="INBOX"), who=AMY)
check("replied message marked answered", any(x["uid"] == got["uid"] and x["answered"] for x in d["messages"]), d)

# Forward keeps original attachments
s, d = api("POST", "mail/send", {"from": "amy@poffles.test", "to": ["tony@johncock.test"], "subject": f"Fwd: Figures {tag}", "text": "FYI\n",
                                 "keep": {"folder": "INBOX", "uid": got["uid"], "parts": [a["part"] for a in af["attachments"]]}}, who=AMY)
fw = wait_for(TONY, "INBOX", lambda m: m["subject"] == f"Fwd: Figures {tag}")
check("forward carries the attachments", s == 200 and fw and fw["attach"], (s, d, fw))

# Drafts: save, replace, then send removes it
s, d = api("POST", "mail/draft", {"from": "tony@johncock.test", "to": ["amy@poffles.test"], "subject": f"Draft {tag}", "text": "v1"})
d1 = d.get("draft_uid")
s, d = api("POST", "mail/draft", {"from": "tony@johncock.test", "to": ["amy@poffles.test"], "subject": f"Draft {tag}", "text": "v2", "draft_uid": d1})
d2 = d.get("draft_uid")
s, dl = api("GET", "mail/messages?" + q(folder="Drafts"))
drafts = [m for m in dl["messages"] if m["subject"] == f"Draft {tag}"]
check("draft saved and replaced (one copy)", len(drafts) == 1 and drafts[0]["uid"] == d2 and "v2" in drafts[0]["preview"], drafts)
s, d = api("POST", "mail/send", {"from": "tony@johncock.test", "to": ["amy@poffles.test"], "subject": f"Draft {tag}", "text": "final", "draft_uid": d2})
s, dl = api("GET", "mail/messages?" + q(folder="Drafts"))
check("sending a draft removes it from Drafts", not any(m["subject"] == f"Draft {tag}" for m in dl["messages"]))

# CSRF: form posts refused
s, d = api("POST", "mail/send", "from=x", ctype="application/x-www-form-urlencoded")
check("non-JSON POST refused", s == 415, s)

# Contacts
s, d = api("GET", "contacts")
mybook = [b for b in d["books"] if b["write"]][0]["slug"]
s, d = api("POST", "contacts", {"book": mybook, "name": "Zara Quill", "emails": ["zara@quill.example"], "phones": ["+44 7700 900123"], "org": "Quill Ltd", "note": "Met at the expo"})
cid = d.get("id")
check("create contact", s == 200 and cid, d)
s, d = api("GET", "contacts")
z = [c for c in d.get("contacts", []) if c["name"] == "Zara Quill"]
check("contact listed with fields", z and z[0]["emails"][0]["value"] == "zara@quill.example" and z[0]["org"] == "Quill Ltd" and z[0]["write"], z)
s, d = api("GET", "mail/contacts?" + q(q="zar"))
check("compose suggestions find contacts", any(x["email"] == "zara@quill.example" for x in d), d)
s, d = api("POST", "contacts", {"book": mybook, "id": cid, "name": "Zara Quill-Smith", "emails": ["zara@quill.example"]})
s, d = api("GET", "contacts")
check("edit contact", any(c["name"] == "Zara Quill-Smith" for c in d["contacts"]))
s, d = api("DELETE", "contacts?" + q(book=mybook, id=cid))
s, d2 = api("GET", "contacts")
check("delete contact", s == 200 and not any(c["name"].startswith("Zara") for c in d2["contacts"]))
dirbook = [b["slug"] for b in api("GET", "contacts")[1]["books"] if b["directory"]]
s, d = api("POST", "contacts", {"book": dirbook[0] if dirbook else "directory", "name": "Nope"})
check("directory is read-only", s == 400)

# Calendar
now = int(time.time())
s, d = api("GET", "cal/events?" + q(**{"from": now - 86400, "to": now + 30 * 86400, "tz": "Europe/London"}))
check("calendars and events listed", s == 200 and d["calendars"] and any(c["write"] for c in d["calendars"]), d)
cal = [c for c in d["calendars"] if c["is_owner"]][0]["slug"]
s, d = api("POST", "cal/event", {"calendar": cal, "title": f"Dentist {tag}", "allday": False, "start": "2026-12-03T09:30", "end": "2026-12-03T10:15", "tz": "Europe/London", "location": "High St", "repeat": "none"})
check("create event", s == 200, d)
s, d = api("GET", "cal/events?" + q(**{"from": 1796256000, "to": 1796342400, "tz": "Europe/London"}))  # 3 Dec 2026 UTC day
ev = [e for e in d["events"] if e["title"] == f"Dentist {tag}"]
check("event read back at the right time (09:30 GMT)", ev and ev[0]["start"] == 1796290200 and ev[0]["end"] - ev[0]["start"] == 2700 and ev[0]["location"] == "High St", ev)
s, d = api("POST", "cal/event", {"calendar": cal, "id": ev[0]["id"], "title": f"Dentist {tag}", "allday": False, "start": "2026-12-03T11:00", "end": "2026-12-03T11:45", "tz": "Europe/London", "repeat": "none"})
s, d = api("GET", "cal/events?" + q(**{"from": 1796256000, "to": 1796342400, "tz": "Europe/London"}))
ev = [e for e in d["events"] if e["title"] == f"Dentist {tag}"]
check("edit event (moved, not duplicated)", len(ev) == 1 and ev[0]["start"] == 1796290200 + 5400, ev)
s, d = api("DELETE", "cal/event?" + q(calendar=cal, id=ev[0]["id"]))
s, d = api("GET", "cal/events?" + q(**{"from": 1796256000, "to": 1796342400, "tz": "Europe/London"}))
check("delete event", not any(e["title"] == f"Dentist {tag}" for e in d["events"]))
s, d = api("POST", "cal/event", {"calendar": cal, "title": f"Holiday {tag}", "allday": True, "start": "2026-12-24", "end": "2026-12-26", "tz": "Europe/London", "repeat": "none"})
s, d = api("GET", "cal/events?" + q(**{"from": 1797897600, "to": 1798416000, "tz": "Europe/London"}))
hol = [e for e in d["events"] if e["title"] == f"Holiday {tag}"]
check("all-day event spans the right days", hol and hol[0]["allday"] and hol[0]["start"] == "2026-12-24" and hol[0]["end"] == "2026-12-27", hol)

# Weekly meeting with Amy invited: invitation email, accept, reply back, delete one occurrence
s, d = api("POST", "cal/event", {"calendar": cal, "title": f"Weekly sync {tag}", "allday": False, "start": "2026-11-23T10:00", "end": "2026-11-23T10:30", "tz": "Europe/London", "repeat": "weekly", "attendees": ["amy@poffles.test"]})
check("create repeating meeting with a guest", s == 200, d)
s, d = api("GET", "cal/events?" + q(**{"from": 1795392000, "to": 1797984000, "tz": "Europe/London"}))  # 23 Nov - 23 Dec 2026
occ = [e for e in d["events"] if e["title"] == f"Weekly sync {tag}"]
check("weekly meeting repeats (5 in the month)", len(occ) == 5 and all(e["recurring"] for e in occ) and occ[0]["attendees"], len(occ))
inv = wait_for(AMY, "INBOX", lambda m: m["subject"] == f"Invitation: Weekly sync {tag}")
check("guest receives the invitation", inv)
s, im = api("GET", "mail/message?" + q(folder="INBOX", uid=inv["uid"]), who=AMY)
check("invitation recognised with method and organiser", im.get("invite") and im["invite"]["method"] == "REQUEST" and im["invite"]["organizer"]["email"] == "tony@johncock.test" and im["invite"]["recurring"], im.get("invite"))
s, d = api("POST", "mail/invite", {"folder": "INBOX", "uid": inv["uid"], "response": "accepted"}, who=AMY)
check("guest accepts", s == 200, d)
s, d = api("GET", "cal/events?" + q(**{"from": 1795392000, "to": 1797984000, "tz": "Europe/London"}), who=AMY)
amy_occ = [e for e in d["events"] if e["title"] == f"Weekly sync {tag}"]
check("accepted meeting appears in the guest's calendar", len(amy_occ) == 5, len(amy_occ))
rep = wait_for(TONY, "INBOX", lambda m: m["subject"] == f"Accepted: Weekly sync {tag}")
check("organiser receives the acceptance", rep)
if rep:
    s, rm = api("GET", "mail/message?" + q(folder="INBOX", uid=rep["uid"]))
    check("acceptance carries an iTIP REPLY", rm["invite"] and rm["invite"]["method"] == "REPLY" and rm["invite"]["attendees"][0]["status"] == "accepted", rm.get("invite"))
second = occ[1]
s, d = api("DELETE", "cal/event?" + q(calendar=cal, id=second["id"], occurrence=second["occurrence"]))
s, d = api("GET", "cal/events?" + q(**{"from": 1795392000, "to": 1797984000, "tz": "Europe/London"}))
occ2 = [e for e in d["events"] if e["title"] == f"Weekly sync {tag}"]
check("delete one occurrence leaves the rest", len(occ2) == 4 and second["occurrence"] not in [e["occurrence"] for e in occ2], len(occ2))
s, d = api("POST", "cal/event", {"calendar": cal, "id": second["id"], "title": f"Weekly sync {tag}", "allday": False, "start": "2026-11-23T10:00", "end": "2026-11-23T10:45", "tz": "Europe/London", "repeat": "keep", "attendees": ["amy@poffles.test"]})
s, d = api("GET", "cal/events?" + q(**{"from": 1795392000, "to": 1797984000, "tz": "Europe/London"}))
occ3 = [e for e in d["events"] if e["title"] == f"Weekly sync {tag}"]
check("editing the series keeps the pattern and the deleted occurrence", len(occ3) == 4 and all(e["end"] - e["start"] == 2700 for e in occ3), [(e["start"], e["end"]) for e in occ3])
check("guest's answer kept after the organiser edits", any(a["email"] == "amy@poffles.test" and a["status"] == "accepted" for a in occ3[0]["attendees"]), occ3[0]["attendees"])
s, d = api("DELETE", "cal/event?" + q(calendar=cal, id=second["id"]))
can = wait_for(AMY, "INBOX", lambda m: m["subject"] == f"Cancelled: Weekly sync {tag}")
check("deleting the meeting sends a cancellation", can)
if can:
    s, cm = api("GET", "mail/message?" + q(folder="INBOX", uid=can["uid"]), who=AMY)
    s, d = api("POST", "mail/invite", {"folder": "INBOX", "uid": can["uid"], "response": "remove"}, who=AMY)
    s, d = api("GET", "cal/events?" + q(**{"from": 1795392000, "to": 1797984000, "tz": "Europe/London"}), who=AMY)
    check("guest removes the cancelled meeting", cm["invite"]["method"] == "CANCEL" and not any(e["title"] == f"Weekly sync {tag}" for e in d["events"]), cm.get("invite"))

# Pages
c = http.client.HTTPSConnection(H, 8443, context=ctx)
c.request("GET", "/"); r = c.getresponse(); r.read()
check("signed-out visitors are sent to sign in", r.status == 303 and r.getheader("Location").startswith("/login"), r.status)
c = http.client.HTTPSConnection(H, 8443, context=ctx)
c.request("GET", "/", headers={"Authorization": "Bearer " + token(TONY)}); r = c.getresponse(); page = r.read()
csp = r.getheader("Content-Security-Policy") or ""
check("webmail page served with a strict script policy", r.status == 200 and b"/webmail.js" in page and "script-src 'self'" in csp and "unsafe-eval" not in csp, csp)
c = http.client.HTTPSConnection(H, 8443, context=ctx)
c.request("GET", "/webmail.js"); r = c.getresponse(); js = r.read()
check("webmail script served", r.status == 200 and b"sandbox" in js)

print(f"\n{sum(R)}/{len(R)} passed"); sys.exit(0 if all(R) else 1)
