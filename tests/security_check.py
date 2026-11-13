"""Two-step verification, app passwords, sessions, delegated mailboxes, send on behalf / as,
and OAUTHBEARER token sign-in. Expects the run_all fixture with tony as an administrator."""
import base64, hashlib, hmac, http.client as httpc, imaplib, json, smtplib, ssl, struct, subprocess, sys, time

ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
H = "127.0.0.1"; R = []
TONY = ("tony@johncock.test", "CorrectHorse1")
AMY = ("amy@poffles.test", "BatteryStaple2")
BIN = "/home/claude/postwright-repo/target/release/postwright"

def check(n, c, i=""):
    R.append(bool(c)); print(("PASS " if c else "FAIL ") + n + (f"  [{i}]" if i and not c else ""))

def http(method, path, body=None, token=None, basic=None, cookie=None, headers=None):
    c = httpc.HTTPSConnection(H, 8443, context=ctx)
    h = {"X-Requested-With": "test"}
    h.update(headers or {})
    if token: h["Authorization"] = "Bearer " + token
    if basic: h["Authorization"] = "Basic " + base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()
    if cookie: h["Cookie"] = cookie
    if body is not None:
        body = json.dumps(body); h["Content-Type"] = "application/json"
    c.request(method, path, body=body, headers=h)
    r = c.getresponse(); d = r.read(); hd = {k.lower(): v for k, v in r.getheaders()}; c.close()
    try: d = json.loads(d)
    except Exception: pass
    return r.status, d, hd

def login(who, code=None, kind="app", name=None):
    b = {"email": who[0], "password": who[1], "kind": kind}
    if code: b["code"] = code
    if name: b["name"] = name
    return http("POST", "/api/v1/login", b)

def totp(secret, t=None):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    step = int((t or time.time()) // 30)
    h = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    o = h[19] & 15
    return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 1000000)

def next_step():
    time.sleep(30 - time.time() % 30 + 0.5)

def imap_ok(user, pw):
    try:
        m = imaplib.IMAP4_SSL(H, 1993, ssl_context=ctx); m.login(user, pw); m.logout(); return True
    except imaplib.IMAP4.error:
        return False

def smtp_ok(user, pw):
    try:
        s = smtplib.SMTP_SSL(H, 4465, context=ctx); s.login(user, pw); s.quit(); return True
    except smtplib.SMTPAuthenticationError:
        return False

def cli(*a):
    return subprocess.run([BIN, "-c", "/tmp/pwtest/security.toml", *a], capture_output=True, text=True)

# ------------------------------------------------------------------ sign-in
s, d, h = login(TONY, kind="web")
check("web sign-in sets HttpOnly SameSite cookie", s == 200 and "HttpOnly" in h.get("set-cookie", "") and "SameSite=Strict" in h.get("set-cookie", "") and d["token"] is None, (s, d, h))
cookie = h["set-cookie"].split(";")[0]
s, d, _ = http("GET", "/api/v1/me", cookie=cookie)
check("cookie session works", s == 200 and d["email"] == TONY[0], d)
s, d, _ = http("GET", "/api/v1/me", basic=TONY)
check("API no longer accepts Basic auth", s == 401, s)
s, d, _ = login((TONY[0], "wrong-password"))
check("wrong password refused", s == 401 and "mfa_required" not in d, d)
s, _, h = http("GET", "/admin")
check("pages redirect to sign-in", s == 303 and h["location"] == "/login?next=%2Fadmin", (s, h))
s, _, _ = http("GET", "/login")
check("sign-in page served", s == 200)
s, d, _ = http("POST", "/api/v1/logout", {}, cookie=cookie)
s, d, _ = http("GET", "/api/v1/me", cookie=cookie)
check("sign-out ends the session", s == 401)

# ------------------------------------------------------------- set up 2FA
s, d, _ = login(AMY, name="test")
amy_tok = d["token"]
s, e, _ = http("POST", "/api/v1/mfa/setup", {}, token=amy_tok)
check("setup returns QR SVG and otpauth URI", s == 200 and "<svg" in e["qr_svg"] and e["uri"].startswith("otpauth://totp/"), e)
check("otpauth URI names the account and issuer", "amy%40poffles.test" in e["uri"] and "issuer=mail.test.local" in e["uri"], e["uri"])
secret = e["secret"]
s, d, _ = http("POST", "/api/v1/mfa/confirm", {"code": "000000" if totp(secret) != "000000" else "111111"}, token=amy_tok)
check("wrong confirmation code refused", s == 400, d)
check("2FA not on before confirming", http("GET", "/api/v1/mfa", token=amy_tok)[1]["enabled"] is False)
s, d, _ = http("POST", "/api/v1/mfa/confirm", {"code": totp(secret)}, token=amy_tok)
codes = d.get("recovery_codes", [])
check("confirm turns it on and gives 10 recovery codes", s == 200 and len(codes) == 10, d)
s, d, _ = http("GET", "/api/v1/me", token=amy_tok)
check("the session that turned it on stays signed in", s == 200)

s, d, _ = login(AMY)
check("password alone now asks for a code", s == 401 and d.get("mfa_required") is True, d)
s, d, _ = login(AMY, code="123456" if totp(secret) != "123456" else "654321")
check("wrong code refused", s == 401 and not d.get("mfa_required"), d)
next_step()  # the code used to confirm can't be reused
s, d, _ = login(AMY, code=totp(secret), name="Mailwright on TEST")
check("password + code signs in", s == 200 and d["token"], d)
code_now = totp(secret)
s, d, _ = login(AMY, code=code_now)
check("the same code can't be used twice", s == 401, d)
s, d, _ = login(AMY, code=codes[0])
check("recovery code signs in", s == 200, d)
s, d, _ = login(AMY, code=codes[0])
check("recovery code works only once", s == 401, d)
st = http("GET", "/api/v1/mfa", token=amy_tok)[1]
check("recovery codes left counts down", st["recovery_codes_left"] == 9, st)

# --------------------------------------------------------- app passwords
check("IMAP refuses the account password once 2FA is on", not imap_ok(*AMY))
check("SMTP refuses the account password once 2FA is on", not smtp_ok(*AMY))
s, _, _ = http("PROPFIND", "/dav/", basic=AMY, headers={"Depth": "0"})
check("CalDAV refuses the account password once 2FA is on", s == 401, s)
s, d, _ = http("POST", "/api/v1/app-passwords", {"name": "Thunderbird"}, token=amy_tok)
ap = d.get("password", "")
check("create app password", s == 200 and len(ap) == 19, d)
check("IMAP accepts the app password", imap_ok(AMY[0], ap))
check("IMAP accepts it without dashes or case", imap_ok(AMY[0], ap.replace("-", "").upper()))
check("SMTP accepts the app password", smtp_ok(AMY[0], ap))
s, _, _ = http("PROPFIND", "/dav/", basic=(AMY[0], ap), headers={"Depth": "0"})
check("CalDAV accepts the app password", s == 207, s)
check("app password doesn't work for another user", not imap_ok(TONY[0], ap))
s, d, _ = login((AMY[0], ap))
check("app password can't sign in to the web pages", s == 401, d)
lst = http("GET", "/api/v1/app-passwords", token=amy_tok)[1]
check("app password listed with last-used time", len(lst) == 1 and lst[0]["name"] == "Thunderbird" and lst[0]["last_used"], lst)
s, _, _ = http("DELETE", f"/api/v1/app-passwords/{lst[0]['id']}", token=amy_tok)
check("removed app password stops working", s == 200 and not imap_ok(AMY[0], ap))

# ------------------------------------------------------- signed-in devices
devs = http("GET", "/api/v1/devices", token=amy_tok)[1]
check("signed-in list shows named device", any(x["name"] == "Mailwright on TEST" for x in devs) and any(x["current"] for x in devs), devs)
other = [x for x in devs if not x["current"]][0]
s, _, _ = http("DELETE", f"/api/v1/devices/{other['id']}", token=amy_tok)
check("sign out another device", s == 200 and len(http("GET", "/api/v1/devices", token=amy_tok)[1]) == len(devs) - 1)

# -------------------------------------------------- OAUTHBEARER device token
next_step()
s, d, _ = login(AMY, code=totp(secret), kind="device", name="Mailwright")
dev = d["token"]
m = imaplib.IMAP4_SSL(H, 1993, ssl_context=ctx)
caps = m.capabilities
check("IMAP advertises OAUTHBEARER and XOAUTH2", "AUTH=OAUTHBEARER" in caps and "AUTH=XOAUTH2" in caps, caps)
ob = f"n,a={AMY[0]},\x01host=mail.test.local\x01port=993\x01auth=Bearer {dev}\x01\x01"
typ, _ = m.authenticate("OAUTHBEARER", lambda _: ob.encode())
check("IMAP OAUTHBEARER sign-in with device token", typ == "OK")
m.logout()
m = imaplib.IMAP4_SSL(H, 1993, ssl_context=ctx)
typ, _ = m.authenticate("XOAUTH2", lambda _: f"user={AMY[0]}\x01auth=Bearer {dev}\x01\x01".encode())
check("IMAP XOAUTH2 sign-in", typ == "OK"); m.logout()
m = imaplib.IMAP4_SSL(H, 1993, ssl_context=ctx)
try:
    m.authenticate("XOAUTH2", lambda _: f"user={TONY[0]}\x01auth=Bearer {dev}\x01\x01".encode()); bad = True
except imaplib.IMAP4.error:
    bad = False
check("token for one user can't sign in as another", not bad)
sm = smtplib.SMTP_SSL(H, 4465, context=ctx); sm.ehlo("t")
check("SMTP advertises OAUTHBEARER", "OAUTHBEARER" in sm.esmtp_features.get("auth", "").upper())
code, _ = sm.docmd("AUTH", "OAUTHBEARER " + base64.b64encode(ob.encode()).decode())
check("SMTP OAUTHBEARER sign-in", code == 235, code); sm.quit()
s, d, _ = http("GET", "/api/v1/app-passwords", token=amy_tok)
s2, d2, _ = http("GET", "/api/v1/me", token=dev)
check("device token also works for the settings API", s2 == 200)

# ------------------------------------------------------------- admin reset
s, d, _ = login(TONY)
tony_tok = d["token"]
s, d, _ = http("GET", "/api/v1/admin/users", token=tony_tok)
check("admin users list shows 2FA status", any(u["email"] == AMY[0] and u["mfa"] for u in d), d)
s, d, _ = http("POST", f"/api/v1/admin/users/{AMY[0]}/mfa-reset", {}, token=tony_tok)
check("admin resets 2FA", s == 200, d)
check("reset signs the user out everywhere", http("GET", "/api/v1/me", token=amy_tok)[0] == 401 and http("GET", "/api/v1/me", token=dev)[0] == 401)
check("password works again after reset", login(AMY)[0] == 200 and imap_ok(*AMY))

# ------------------------------------------------------- disable by the user
s, d, _ = login(TONY)
tt = d["token"]
e = http("POST", "/api/v1/mfa/setup", {}, token=tt)[1]
http("POST", "/api/v1/mfa/confirm", {"code": totp(e["secret"])}, token=tt)
s, d, _ = http("POST", "/api/v1/mfa/disable", {"password": TONY[1], "code": "000000"}, token=tt)
check("turning off needs a valid code", s == 403, d)
s, d, _ = http("POST", "/api/v1/mfa/disable", {"password": "nope", "code": totp(e["secret"])}, token=tt)
check("turning off needs the password", s == 403, d)
next_step()
s, d, _ = http("POST", "/api/v1/mfa/disable", {"password": TONY[1], "code": totp(e["secret"])}, token=tt)
check("user turns 2FA off", s == 200 and login(TONY)[0] == 200, d)

# ------------------------------------------------------------- delegation
tony_tok = login(TONY)[1]["token"]
smtp = smtplib.SMTP_SSL(H, 4465, context=ctx); smtp.login(*TONY)
smtp.sendmail(TONY[0], [AMY[0]], f"From: {TONY[0]}\r\nTo: {AMY[0]}\r\nSubject: For Amy only\r\n\r\nprivate\r\n"); smtp.quit()
time.sleep(1.5)
m = imaplib.IMAP4_SSL(H, 1993, ssl_context=ctx); m.login(*TONY)
typ, _ = m.select('"Other Users/amy@poffles.test/INBOX"')
check("no access to another mailbox without a grant", typ == "NO")
m.logout()

s, d, _ = http("POST", "/api/v1/admin/delegations", {"owner": AMY[0], "grantee": TONY[0], "mailbox": "read", "send": "none"}, token=tony_tok)
check("admin grants read access", s == 200, d)
m = imaplib.IMAP4_SSL(H, 1993, ssl_context=ctx); m.login(*TONY)
typ, ns = m.namespace()
check("NAMESPACE advertises Other Users", b"Other Users/" in ns[0], ns)
typ, lst = m.list('""', "*")
names = b"\n".join(lst)
check("LIST includes the shared mailbox's folders", b'"Other Users/amy@poffles.test/INBOX"' in names and b"\\Noselect" in names, names)
try:
    m.select('"Other Users/amy@poffles.test/INBOX"'); rw = True
except imaplib.IMAP4.readonly:
    rw = False
check("read access opens read-only", not rw)
m.shutdown(); m = imaplib.IMAP4_SSL(H, 1993, ssl_context=ctx); m.login(*TONY)
typ, d = m.select('"Other Users/amy@poffles.test/INBOX"', readonly=True)
check("read access can open the shared inbox", typ == "OK", d)
typ, d = m.search(None, "SUBJECT", '"For Amy only"')
check("can search the shared inbox", typ == "OK" and d[0].split(), d)
n = d[0].split()[0]
typ, _ = m.store(n, "+FLAGS", "\\Deleted")
check("read access can't change flags", typ == "NO")
typ, d = m.fetch(n, "(BODY[])")
typ, fl = m.fetch(n, "(FLAGS)")
check("reading doesn't mark Amy's mail as read", b"\\Seen" not in fl[0], fl)
typ, _ = m.create('"Other Users/amy@poffles.test/Hack"')
check("can't create folders in someone else's mailbox", typ == "NO")
typ, _ = m.append('"Other Users/amy@poffles.test/INBOX"', None, None, b"Subject: x\r\n\r\ny\r\n")
check("read access can't add mail", typ == "NO")
m.logout()
log = open("/tmp/pwtest/server.log").read()
check("opening someone else's mailbox is logged", "tony@johncock.test opened amy@poffles.test's folder INBOX (read only)" in log)

http("POST", "/api/v1/admin/delegations", {"owner": AMY[0], "grantee": TONY[0], "mailbox": "full", "send": "on_behalf"}, token=tony_tok)
m = imaplib.IMAP4_SSL(H, 1993, ssl_context=ctx); m.login(*TONY)
typ, _ = m.select('"Other Users/amy@poffles.test/INBOX"')
typ, d = m.search(None, "SUBJECT", '"For Amy only"'); n = d[0].split()[0]
typ, _ = m.store(n, "+FLAGS", "\\Flagged")
check("full access can flag mail", typ == "OK")
typ, _ = m.copy(n, '"Other Users/amy@poffles.test/Archive"')
check("full access can file into the owner's folders", typ == "OK")
typ, st = m.status('"Other Users/amy@poffles.test/Archive"', "(MESSAGES)")
check("STATUS works on shared folders", typ == "OK" and b"MESSAGES 1" in st[0], st)
m.logout()
ma = imaplib.IMAP4_SSL(H, 1993, ssl_context=ctx); ma.login(*AMY); ma.select("INBOX")
typ, fl = ma.search(None, "FLAGGED")
check("owner sees the delegate's changes", fl[0].split(), fl); ma.logout()
s, d, _ = http("GET", "/api/v1/shared", token=tony_tok)
check("settings API lists mailboxes shared with me", d and d[0]["owner"] == AMY[0] and d[0]["send"] == "on_behalf", d)

# ---------------------------------------------------- send on behalf / as
smtp = smtplib.SMTP_SSL(H, 4465, context=ctx); smtp.login(*TONY)
smtp.sendmail(TONY[0], ["bob@johncock.test" if False else TONY[0]],
    f"From: Amy <{AMY[0]}>\r\nSender: someone@else.test\r\nTo: {TONY[0]}\r\nSubject: On behalf\r\n\r\nhello\r\n")
smtp.quit(); time.sleep(1.5)
m = imaplib.IMAP4_SSL(H, 1993, ssl_context=ctx); m.login(*TONY); m.select("INBOX")
typ, d = m.search(None, "SUBJECT", '"On behalf"'); msg = m.fetch(d[0].split()[-1], "(BODY.PEEK[HEADER])")[1][0][1]
check("on behalf: Sender header names the real author", f"Sender: <{TONY[0]}>".encode() in msg, msg)
check("on behalf: a forged Sender header is removed", b"someone@else.test" not in msg, msg)
check("on behalf: From stays as the mailbox owner", f"From: Amy <{AMY[0]}>".encode() in msg)
check("on behalf: DKIM-signed for the From domain", b"d=poffles.test" in msg, msg[:600])
m.logout()

http("POST", "/api/v1/admin/delegations", {"owner": AMY[0], "grantee": TONY[0], "mailbox": "full", "send": "as"}, token=tony_tok)
smtp = smtplib.SMTP_SSL(H, 4465, context=ctx); smtp.login(*TONY)
smtp.sendmail(AMY[0], [TONY[0]], f"From: {AMY[0]}\r\nTo: {TONY[0]}\r\nSubject: Sent as\r\n\r\nhello\r\n"); smtp.quit(); time.sleep(1.5)
m = imaplib.IMAP4_SSL(H, 1993, ssl_context=ctx); m.login(*TONY); m.select("INBOX")
typ, d = m.search(None, "SUBJECT", '"Sent as"'); msg = m.fetch(d[0].split()[-1], "(BODY.PEEK[HEADER])")[1][0][1]
check("send as: no Sender header, envelope may use the owner's address", b"\nSender:" not in msg and msg.count(b"From: amy@poffles.test") == 1, msg)
m.logout()

http("DELETE", f"/api/v1/admin/delegations?owner={AMY[0]}&grantee={TONY[0]}", token=tony_tok)
smtp = smtplib.SMTP_SSL(H, 4465, context=ctx); smtp.login(*TONY)
try:
    smtp.sendmail(TONY[0], [TONY[0]], f"From: {AMY[0]}\r\nTo: {TONY[0]}\r\nSubject: Spoof\r\n\r\nx\r\n"); refused = False
except smtplib.SMTPDataError:
    refused = True
smtp.quit()
check("without send rights, From: someone else is refused", refused)
m = imaplib.IMAP4_SSL(H, 1993, ssl_context=ctx); m.login(*TONY)
typ, lst = m.list('""', "*")
check("revoked access disappears from the folder list", b"Other Users" not in b"\n".join(lst)); m.logout()

# --------------------------------------------------------------------- CLI
r = cli("delegate", "grant", AMY[0], TONY[0], "--mailbox", "read", "--send", "on-behalf")
r2 = cli("delegate", "list")
check("CLI grant and list", r.returncode == 0 and "amy@poffles.test" in r2.stdout and "on_behalf" in r2.stdout, r.stderr + r2.stdout)
r = cli("delegate", "revoke", AMY[0], TONY[0])
check("CLI revoke", r.returncode == 0 and AMY[0] not in cli("delegate", "list").stdout)

print(f"\n{sum(R)}/{len(R)} passed"); sys.exit(0 if all(R) else 1)
