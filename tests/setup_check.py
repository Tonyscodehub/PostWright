"""First-run wizard: start with no config, drive the setup API, finish, check the
server comes up for real. Uses default ports (needs root) in /tmp/wiz."""
import http.client as httpc, imaplib, json, os, re, shutil, ssl, subprocess, sys, time

ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
BIN = os.environ.get("PWBIN", "/home/claude/postwright-repo/target/release/postwright")
R = []
def check(n, c, i=""):
    R.append(bool(c)); print(("PASS " if c else "FAIL ") + n + (f"  [{str(i)[:400]}]" if i and not c else ""))

def http(method, path, body=None, code=None, raw=False):
    c = httpc.HTTPSConnection("127.0.0.1", 443, context=ctx, timeout=30)
    h = {}
    if code: h["X-Setup-Code"] = code
    if body is not None: h["Content-Type"] = "application/json"
    c.request(method, path, body=json.dumps(body) if body is not None else None, headers=h)
    r = c.getresponse(); d = r.read(); hd = {k.lower(): v for k, v in r.getheaders()}; c.close()
    if raw: return r.status, d.decode(errors="replace"), hd
    try: d = json.loads(d)
    except Exception: d = d.decode(errors="replace")
    return r.status, d

shutil.rmtree("/tmp/wiz", ignore_errors=True); os.makedirs("/tmp/wiz")
log = open("/tmp/wiz/out.log", "w")
p = subprocess.Popen([BIN, "-c", "/tmp/wiz/postwright.toml"], stdout=log, stderr=subprocess.STDOUT, cwd="/tmp/wiz")
code = None
for _ in range(60):
    time.sleep(0.5)
    m = re.search(r"Setup code \(if the page asks\): ([A-Z0-9-]+)", open("/tmp/wiz/out.log").read())
    if m: code = m.group(1); break
check("first start prints a setup code and link", code and "https://localhost/setup#" in open("/tmp/wiz/out.log").read(), open("/tmp/wiz/out.log").read()[-800:])
check("starting config written", os.path.exists("/tmp/wiz/postwright.toml") and os.path.exists("/tmp/wiz/data/tls/cert.pem"))
s, body, hd = http("GET", "/setup", raw=True)
check("setup page served", s == 200 and "setup.js" in body and "frame-ancestors" in hd.get("content-security-policy", ""))
s, _ = http("GET", "/anything")
check("other paths go to the wizard", s == 302)
s, d = http("GET", "/setup/api/state")
check("API needs the code", s == 401, d)
s, d = http("GET", "/setup/api/state", code="AAAA-BBBB-CCCC")
check("wrong code refused", s == 401)
s, d = http("GET", "/setup/api/state", code=code.lower())
check("state with the code (case-insensitive)", s == 200 and d["admins"] == [] and d["domains"] == [], d)
s, d = http("POST", "/setup/api/hostname", {"hostname": "not a name"}, code=code)
check("bad server name explained", s == 400 and "full name" in d["error"], d)
s, d = http("POST", "/setup/api/hostname", {"hostname": "mail.wiz.test"}, code=code)
check("server name saved; temporary certificate remade", s == 200 and d["certificate_regenerated"], d)
check("config updated", 'hostname = "mail.wiz.test"' in open("/tmp/wiz/postwright.toml").read())
s, d = http("POST", "/setup/api/check-host", {"hostname": "mail.wiz.test"}, code=code)
check("DNS check runs", s == 200 and "ptr_matches" in d and d["addresses"] == [], d)
s, d = http("POST", "/setup/api/admin/domains", {"name": "typo.wiz.test"}, code=code)
s, d = http("DELETE", "/setup/api/admin/domains/typo.wiz.test", code=code)
check("remove a mistyped domain in the wizard", s == 200 and http("GET", "/setup/api/state", code=code)[1]["domains"] == [], d)
s, d = http("POST", "/setup/api/admin/domains", {"name": "wiz.test"}, code=code)
check("add domain through the wizard", s == 200, d)
s, d = http("GET", "/setup/api/admin/domains/wiz.test/dns", code=code)
check("DNS records listed", s == 200 and any(r["type"] == "MX" and "mail.wiz.test" in r["expected"] for r in d["records"]), d)
s, d = http("POST", "/setup/api/finish", {}, code=code)
check("can't finish without an administrator", s == 400 and "administrator" in d["error"], d)
s, d = http("POST", "/setup/api/admin/users", {"email": "boss@wiz.test", "password": "WizardPass99", "admin": True}, code=code)
check("create administrator", s == 200, d)
s, d = http("PUT", "/setup/api/admin/users/boss@wiz.test", {"name": "The Boss"}, code=code)
s, d = http("GET", "/setup/api/scanners", code=code)
check("scanner detection", s == 200 and {x["name"] for x in d["detected"]} == {"clamav", "rspamd", "spamassassin"}, d)
s, d = http("POST", "/setup/api/scanners", {"clamav": True, "rspamd": False, "spamassassin": False}, code=code)
check("scanner choice saved to config", s == 200 and "[filter.clamav]" in open("/tmp/wiz/postwright.toml").read(), open("/tmp/wiz/postwright.toml").read())
s, d = http("GET", "/setup/api/migrate/status", code=code)
check("migration API available in the wizard", s == 200 and d["progress"]["running"] is False, d)
s, d = http("GET", "/setup/api/admin/certs", code=code)
check("certificate status for the new name", s == 200 and d["current"]["self_signed"] and "mail.wiz.test" in d["current"]["names"], d)
s, d = http("POST", "/setup/api/finish", {"start_service": False}, code=code)
check("finish", s == 200, d)
ok = False
for _ in range(40):
    time.sleep(0.5)
    try:
        s, body, _ = http("GET", "/login", raw=True)
        if s == 200: ok = True; break
    except Exception:
        pass
check("normal server comes up after the wizard", ok, open("/tmp/wiz/out.log").read()[-1500:])
try:
    m = imaplib.IMAP4_SSL("127.0.0.1", 993, ssl_context=ctx); m.login("boss@wiz.test", "WizardPass99"); m.logout(); im = True
except Exception as e:
    im = e
check("mail services running for the new admin", im is True, im)
s, d = http("GET", "/setup/api/state", code=code)
check("wizard is gone once finished", s != 200)
p.terminate(); p.wait(timeout=10)
log2 = open("/tmp/wiz/out2.log", "w")
p = subprocess.Popen([BIN, "-c", "/tmp/wiz/postwright.toml"], stdout=log2, stderr=subprocess.STDOUT, cwd="/tmp/wiz")
time.sleep(2.5)
check("second start goes straight to normal mode", "Setup code" not in open("/tmp/wiz/out2.log").read() and "running as mail.wiz.test" in open("/tmp/wiz/out2.log").read(), open("/tmp/wiz/out2.log").read()[-600:])
p.terminate(); p.wait(timeout=10)
r = subprocess.run([BIN, "-c", "/tmp/nowhere/postwright.toml", "user", "list"], capture_output=True, text=True)
check("commands before setup explain what to do", r.returncode != 0 and "setup wizard" in r.stderr, r.stderr)
print(f"\n{sum(R)}/{len(R)} passed"); sys.exit(0 if all(R) else 1)
