"""Two-step codes checked by a RADIUS server (real FreeRADIUS on 127.0.0.1:1812, secret testing123).
Tokens: amy@poffles.test 135790, tony@johncock.test 246810, tony 112233."""
import http.client, imaplib, json, ssl, subprocess, sys, time
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
H = "127.0.0.1"; R = []
TONY = ("tony@johncock.test", "CorrectHorse1"); AMY = ("amy@poffles.test", "BatteryStaple2")
def check(n, c, i=""):
    R.append(bool(c)); print(("PASS " if c else "FAIL ") + n + (f"  [{str(i)[:300]}]" if i and not c else ""))
def login(who, code=None):
    c = http.client.HTTPSConnection(H, 8443, context=ctx, timeout=30)
    b = {"email": who[0], "password": who[1], "kind": "app", "name": "radius"}
    if code: b["code"] = code
    c.request("POST", "/api/v1/login", body=json.dumps(b), headers={"Content-Type": "application/json"})
    r = c.getresponse(); return r.status, json.loads(r.read() or b"{}")
ADMIN = login(TONY)[1]["token"]
def api(m, path, body=None, tok=ADMIN):
    c = http.client.HTTPSConnection(H, 8443, context=ctx, timeout=60)
    h = {"Authorization": "Bearer " + tok, "X-Requested-With": "t"}
    if body is not None: body = json.dumps(body); h["Content-Type"] = "application/json"
    c.request(m, "/api/v1/" + path, body=body, headers=h); r = c.getresponse(); d = r.read()
    try: return r.status, json.loads(d)
    except Exception: return r.status, d
def imap_ok(who):
    try:
        m = imaplib.IMAP4_SSL(H, 1993, ssl_context=ctx); m.login(*who); m.logout(); return True
    except imaplib.IMAP4.error: return False

S = {"server": "127.0.0.1:1812", "backup_server": "", "secret": "testing123", "users": "selected", "username": "email", "send": "code", "nas_identifier": "postwright", "timeout_secs": 3, "mail_apps_keep_password": False}
s, d = api("GET", "admin/two-step")
check("off to begin with", s == 200 and d["enabled"] is False, d)
s, d = api("POST", "admin/two-step/test", {"email": "amy@poffles.test", "code": "135790", "settings": S})
check("test: real code accepted by FreeRADIUS", d.get("result") == "accepted", d)
s, d = api("POST", "admin/two-step/test", {"email": "amy@poffles.test", "code": "000000", "settings": S})
check("test: wrong code refused (connection and secret fine)", d.get("result") == "rejected", d)
s, d = api("POST", "admin/two-step/test", {"email": "amy@poffles.test", "code": "135790", "settings": dict(S, secret="not-the-secret")})
check("test: wrong shared secret reported, never accepted", d.get("result") == "error", d)
s, d = api("POST", "admin/two-step/test", {"email": "amy@poffles.test", "code": "135790", "settings": dict(S, server="127.0.0.1:1999", timeout_secs=1)})
check("test: unreachable server reported", d.get("result") == "error" and ("nothing is answering" in d.get("detail", "") or "no answer" in d.get("detail", "")), d)
s, d = api("PUT", "admin/two-step", {"enabled": True, "settings": dict(S, secret="short")})
check("short secret refused", s == 400, d)
s, d = api("PUT", "admin/two-step", {"enabled": True, "settings": S})
check("turn on (selected users)", s == 200, d)
cfg = open("/tmp/pwtest/postwright.toml").read()
check("saved to the settings", "[radius]" in cfg and "127.0.0.1:1812" in cfg, cfg[-300:])
s, d = api("GET", "admin/two-step")
check("secret never sent back", d["settings"]["secret"] == "" and d["settings"]["secret_set"] is True, d["settings"])

s, d = login(AMY)
check("not selected yet: no code needed", s == 200 and "token" in d, d)
s, d = api("PUT", "admin/two-step/users", {"email": "amy@poffles.test", "selected": True})
check("select amy", s == 200)
s, d = login(AMY)
check("now a code is required", s == 401 and d.get("mfa_required"), d)
s, d = login(AMY, "000000")
check("wrong code refused", s == 401 and not d.get("token"), d)
s, d = login(AMY, "135790")
check("RADIUS code signs her in", s == 200 and "token" in d, d)
amy_tok = d.get("token")
s, d = api("GET", "mfa", tok=amy_tok)
check("her settings page says RADIUS is in use", d.get("radius") is True, d)
check("mail apps now need an app password", not imap_ok(AMY))
s, d = api("PUT", "admin/two-step", {"enabled": True, "settings": dict(S, secret="", mail_apps_keep_password=True)})
check("save without retyping the secret keeps it", s == 200 and login(AMY, "135790")[0] == 200, d)
check("option: mail apps may keep the password", imap_ok(AMY))
s, d = login(TONY)
check("tony not selected: no code", s == 200)

# Everyone, and the name sent
s, d = api("PUT", "admin/two-step", {"enabled": True, "settings": dict(S, secret="", users="all")})
check("everyone: tony needs a code", login(TONY)[0] == 401 and login(TONY, "246810")[0] == 200)
s, d = api("PUT", "admin/two-step", {"enabled": True, "settings": dict(S, secret="", users="all", username="local")})
check("send just the name before @", login(TONY, "112233")[0] == 200 and login(TONY, "246810")[0] == 401)
s, d = api("GET", "admin/two-step", tok=amy_tok)
check("non-admins can't see the settings", s == 403)

# Server down: sign-in fails closed, nobody gets in without a code
subprocess.run(["pkill", "freeradius"]); time.sleep(1)
s, d = login(AMY, "135790")
check("RADIUS server down: sign-in refused (fails closed)", s == 401 and not d.get("token"), d)
subprocess.Popen(["freeradius", "-f", "-l", "/tmp/radius.log"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, start_new_session=True); time.sleep(2)

s, d = api("PUT", "admin/two-step", {"enabled": False})
check("turn off", s == 200 and "[radius]" not in open("/tmp/pwtest/postwright.toml").read())
check("codes no longer asked for", login(AMY)[0] == 200 and login(TONY)[0] == 200)
check("mail apps back to the password", imap_ok(AMY))
api("PUT", "admin/two-step/users", {"email": "amy@poffles.test", "selected": False})
print(f"\n{sum(R)}/{len(R)} passed"); sys.exit(0 if all(R) else 1)
