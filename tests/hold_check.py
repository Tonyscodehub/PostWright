"""Spam & antivirus settings from the admin console, and holding mail while a scanner is down."""
import http.client, json, smtplib, ssl, sys, time
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
H = "127.0.0.1"; R = []
TONY = ("tony@johncock.test", "CorrectHorse1"); AMY = ("amy@poffles.test", "BatteryStaple2")
def check(n, c, i=""):
    R.append(bool(c)); print(("PASS " if c else "FAIL ") + n + (f"  [{str(i)[:400]}]" if i and not c else ""))
TOK = {}
def token(who):
    if who not in TOK:
        c = http.client.HTTPSConnection(H, 8443, context=ctx)
        c.request("POST", "/api/v1/login", body=json.dumps({"email": who[0], "password": who[1], "kind": "app", "name": "hold"}), headers={"Content-Type": "application/json"})
        TOK[who] = json.loads(c.getresponse().read())["token"]
    return TOK[who]
def api(m, path, body=None, who=TONY):
    c = http.client.HTTPSConnection(H, 8443, context=ctx, timeout=90)
    h = {"Authorization": "Bearer " + token(who), "X-Requested-With": "t"}
    if body is not None: body = json.dumps(body); h["Content-Type"] = "application/json"
    c.request(m, "/api/v1/" + path, body=body, headers=h); r = c.getresponse(); d = r.read()
    try: return r.status, json.loads(d)
    except Exception: return r.status, d
def inbox(who=TONY):
    return api("GET", "mail/messages?folder=INBOX", who=who)[1]["messages"]

s, f = api("GET", "admin/filters")
check("settings readable by administrators", s == 200 and "settings" in f and f["settings"]["junk_score"] < f["settings"]["reject_score"], f)
orig = f["settings"]
s, d = api("GET", "admin/filters", who=AMY)
check("not by other users", s == 403, s)
bad = dict(orig, junk_score=20, reject_score=10)
s, d = api("PUT", "admin/filters", bad)
check("junk score above reject score refused", s == 400 and "lower" in d.get("error", ""), d)
s, d = api("PUT", "admin/filters", dict(orig, clamav={"address": "nonsense", "on_fail": "hold"}))
check("bad scanner address refused", s == 400, d)

down = dict(orig, clamav={"address": "127.0.0.1:3399", "on_fail": "hold"}, rspamd=None, spamassassin=None)
s, d = api("PUT", "admin/filters", down)
check("save: ClamAV at an address that isn't answering, set to hold", s == 200, d)
cfg = open("/tmp/pwtest/postwright.toml").read()
check("saved to the settings file", "127.0.0.1:3399" in cfg and 'on_fail = "hold"' in cfg, cfg[-400:])
s, t = api("POST", "admin/filters/test", down)
check("scanner test reports it unreachable", t["results"][0]["name"] == "ClamAV" and not t["results"][0]["ok"], t)

tag = str(int(time.time()))
sm = smtplib.SMTP(H, 2525); sm.ehlo("mx.sender.example")
sm.mail("bob@sender.example"); sm.rcpt("tony@johncock.test")
code, msg = sm.data(f"From: bob@sender.example\r\nTo: tony@johncock.test\r\nSubject: Held {tag}\r\n\r\nhello\r\n".encode())
sm.quit()
check("incoming mail accepted while the scanner is down", code == 250 and b"held" in msg, (code, msg))
check("…but not delivered yet", not any(m["subject"] == f"Held {tag}" for m in inbox()))
s, f = api("GET", "admin/filters")
check("listed as held", any(m["subject"] == f"Held {tag}" and m["direction"] == "in" and m["waiting_for"] == "ClamAV" for m in f["held"]), f["held"])
s, me = api("GET", "me")
check("administrators get a warning banner", any(a["level"] == "warn" and "held" in a["text"] and "ClamAV" in a["text"] for a in me.get("alerts", [])), me.get("alerts"))
s, me2 = api("GET", "me", who=AMY)
check("other users don't", me2.get("alerts") == [], me2.get("alerts"))
s, d = api("POST", "admin/held/retry", {})
check("retrying while still down keeps it held", d.get("delivered") == 0 and len(api("GET", "admin/filters")[1]["held"]) >= 1, d)

# Outgoing, from the webmail, then deleted by an admin
s, d = api("POST", "mail/send", {"from": "amy@poffles.test", "to": ["tony@johncock.test"], "subject": f"Out held {tag}", "text": "x"}, who=AMY)
check("webmail send held, not refused", s == 200 and d.get("held"), d)
s, f = api("GET", "admin/filters")
out = [m for m in f["held"] if m["subject"] == f"Out held {tag}"]
check("outgoing message listed as held", out and out[0]["direction"] == "out", f["held"])
s, d = api("DELETE", f"admin/held/{out[0]['id']}")
check("admin deletes a held message", s == 200 and not any(m["subject"] == f"Out held {tag}" for m in api("GET", "admin/filters")[1]["held"]))
# Another, released without scanning
s, d = api("POST", "mail/send", {"from": "amy@poffles.test", "to": ["tony@johncock.test"], "subject": f"Released {tag}", "text": "x"}, who=AMY)
rid = [m for m in api("GET", "admin/filters")[1]["held"] if m["subject"] == f"Released {tag}"][0]["id"]
s, d = api("POST", f"admin/held/{rid}/release", {})
time.sleep(1)
check("admin releases one without scanning: delivered", s == 200 and any(m["subject"] == f"Released {tag}" for m in inbox()), d)

# Scanner back: held mail is scanned and delivered
up = dict(down, clamav={"address": "127.0.0.1:3310", "on_fail": "hold"})
s, d = api("PUT", "admin/filters", up)
s, t = api("POST", "admin/filters/test", {})
check("scanner test catches the EICAR test virus", t["results"] and t["results"][0]["ok"] and "EICAR" in t["results"][0]["detail"].upper(), t)
for _ in range(20):
    if any(m["subject"] == f"Held {tag}" for m in inbox()): break
    time.sleep(0.5)
check("held mail scanned and delivered once the scanner is back", any(m["subject"] == f"Held {tag}" for m in inbox()))
s, f = api("GET", "admin/filters")
check("nothing left held", f["held"] == [], f["held"])
time.sleep(31)  # banner cache
s, me = api("GET", "me")
check("banner goes away", me.get("alerts") == [], me.get("alerts"))

s, d = api("PUT", "admin/filters", orig)
check("settings put back", s == 200)
print(f"\n{sum(R)}/{len(R)} passed"); sys.exit(0 if all(R) else 1)
