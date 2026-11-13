"""Admin API and web console checks. Expects run_all-style fixture with tony as admin."""
import base64, http.client, json, ssl, sys, time
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
H = "127.0.0.1"; R = []
TONY = ("tony@johncock.test", "CorrectHorse1")
AMY = ("amy@poffles.test", "BatteryStaple2")

def check(n, c, i=""):
    R.append(bool(c)); print(("PASS " if c else "FAIL ") + n + (f"  [{i}]" if i and not c else ""))

TOKENS = {}
def token(who):
    if who not in TOKENS:
        c = http.client.HTTPSConnection(H, 8443, context=ctx)
        c.request("POST", "/api/v1/login", body=json.dumps({"email": who[0], "password": who[1], "kind": "app", "name": "admin_check"}), headers={"Content-Type": "application/json"})
        r = c.getresponse(); TOKENS[who] = json.loads(r.read())["token"]; c.close()
    return TOKENS[who]

def req(method, path, who=TONY, body=None, xrw=True):
    c = http.client.HTTPSConnection(H, 8443, context=ctx)
    h = {"Authorization": "Bearer " + token(who)}
    if xrw: h["X-Requested-With"] = "test"
    if body is not None:
        body = json.dumps(body); h["Content-Type"] = "application/json"
    c.request(method, "/api/v1/admin/" + path, body=body, headers=h)
    r = c.getresponse(); d = r.read(); c.close()
    try: return r.status, json.loads(d)
    except Exception: return r.status, d

s, d = req("GET", "overview", who=AMY)
check("non-admin refused", s == 403 and "administrator" in d["error"], (s, d))
s, d = req("GET", "overview")
check("overview", s == 200 and d["counts"]["users"] == 2 and d["hostname"] == "mail.test.local", d)
s, d = req("POST", "domains", body={"name": "newco.test"})
check("add domain (DKIM generated)", s == 200, d)
s, d = req("GET", "domains")
check("list domains", any(x["name"] == "newco.test" and x["has_dkim"] for x in d), d)
s, d = req("POST", "domains/alias", body={"alias": "newco-alias.test", "target": "newco.test"})
check("add alias domain", s == 200, d)
s, d = req("GET", "domains/newco.test/dns")
check("DNS check lists MX/SPF/DKIM/DMARC with status", s == 200 and [r["type"] for r in d["records"]] == ["MX", "TXT", "TXT", "TXT"]
      and all(r["status"] in ("ok", "missing", "different") for r in d["records"]) and "p=" in d["records"][2]["expected"], d)
s, d = req("POST", "users", body={"email": "boss@newco.test", "password": "short", "quota_mb": 10})
check("weak password refused", s == 400 and "10 characters" in d["error"], d)
s, d = req("POST", "users", body={"email": "boss@newco.test", "password": "LongEnough123", "quota_mb": 10})
check("create user", s == 200, d)
s, d = req("PUT", "users/boss@newco.test", body={"quota_mb": 20, "admin": True})
check("edit user quota/admin", s == 200, d)
s, d = req("GET", "users")
b = [u for u in d if u["email"] == "boss@newco.test"][0]
check("user list reflects changes", b["quota_bytes"] == 20 * 1048576 and b["admin"], b)
s, d = req("PUT", "users/tony@johncock.test", body={"admin": False})
check("can't remove own admin", s == 400, d)
s, d = req("DELETE", "users/tony@johncock.test")
check("can't delete self", s == 400, d)
s, d = req("POST", "aliases", body={"source": "hi@newco.test", "target": "boss@newco.test"})
check("add alias", s == 200, d)
s, d = req("DELETE", "aliases/hi@newco.test/boss@newco.test", xrw=False)
check("DELETE without X-Requested-With refused (CSRF)", s == 403, d)
s, d = req("DELETE", "aliases/hi@newco.test/boss@newco.test")
check("remove alias", s == 200 and d["removed"] == 1, d)
s, d = req("PUT", "domains/newco.test", body={"catch_all": "boss@newco.test"})
check("set catch-all", s == 200, d)
s, d = req("GET", "queue")
check("queue list", s == 200 and isinstance(d, list), d)
s, d = req("POST", "queue/flush", body={})
check("queue flush", s == 200 and "rescheduled" in d, d)
s, d = req("GET", "logs?n=50&q=admin")
check("logs (filtered)", s == 200 and any("added domain newco.test" in l for l in d["lines"]), d)
s, d = req("GET", "filters")
check("filters summary", s == 200 and "junk_score" in d, d)
s, d = req("POST", "import/iredmail", body={"dry_run": True})
check("import job starts", s == 200 and d["started"], d)
for _ in range(30):
    s, d = req("GET", "import")
    if not d["running"]: break
    time.sleep(0.5)
check("import dry run output captured", d["finished"] and any("Dry run" in l for l in d["output"]), d)
s, d = req("DELETE", "users/boss@newco.test")
check("delete user", s == 200, d)
s, d = req("DELETE", "domains/newco-alias.test")
s, d = req("DELETE", "domains/newco.test")
check("remove domain", s == 200, d)

# Console page access
c = http.client.HTTPSConnection(H, 8443, context=ctx)
c.request("GET", "/admin", headers={"Authorization": "Bearer " + token(AMY)})
r = c.getresponse(); r.read()
check("console page refused for non-admin", r.status == 403)
print(f"\n{sum(R)}/{len(R)} passed"); sys.exit(0 if all(R) else 1)
