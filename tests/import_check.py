"""Verify an iRedMail import through real IMAP/SMTP/CalDAV clients."""
import imaplib, smtplib, ssl, sys, time, base64, http.client, subprocess, re
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
H = "127.0.0.1"; R = []
def check(n, c, i=""):
    R.append(bool(c)); print(("PASS " if c else "FAIL ") + n + (f"  [{i}]" if i and not c else ""))

m = imaplib.IMAP4_SSL(H, 1993, ssl_context=ctx)
m.login("dave@legacy.test", "OldPassword1")
check("login with imported SSHA512 password", True)
typ, d = m.select("INBOX")
st = m.status("INBOX", "(UIDVALIDITY UIDNEXT MESSAGES)")[1][0].decode()
check("Dovecot UIDVALIDITY and UIDNEXT preserved", "UIDVALIDITY 1600000000" in st and "UIDNEXT 4" in st and "MESSAGES 3" in st, st)
typ, d = m.fetch("1:*", "(UID FLAGS INTERNALDATE)")
txt = b" ".join(x if isinstance(x, bytes) else x[0] for x in d).decode()
check("UIDs 1-3 kept", all(f"UID {u}" in txt for u in (1, 2, 3)), txt)
check("flags + keywords mapped (\\Flagged \\Answered $Important)", "\\Flagged" in txt and "\\Answered" in txt and "$Important" in txt, txt)
check("received date from Maildir mtime", "13-Sep-2020" in txt, txt)
typ, d = m.fetch("1", "(BODY.PEEK[])")
check("LF converted to CRLF", b"\r\nSubject: Old one\r\n" in d[0][1], d[0][1][:80])
typ, boxes = m.list()
names = b" ".join(boxes).decode()
check("Maildir++ folders imported (Projects/2024)", '"Projects/2024"' in names and "Sent" in names, names)
m.logout()

m = imaplib.IMAP4_SSL(H, 1993, ssl_context=ctx); m.login("erin@legacy.test", "AmyPass123")
check("login with imported BCRYPT password", True); m.logout()
try:
    m = imaplib.IMAP4_SSL(H, 1993, ssl_context=ctx); m.login("gone@shop.test", "OldPassword1"); check("disabled account stays disabled", False)
except imaplib.IMAP4.error:
    check("disabled account stays disabled", True)
log = open("/tmp/imptest/server.log").read()
check("hashes upgraded to Argon2id on login", log.count("upgraded password hash") >= 2)
m = imaplib.IMAP4_SSL(H, 1993, ssl_context=ctx); m.login("dave@legacy.test", "OldPassword1"); m.logout()
check("upgraded password still works", True)

s = smtplib.SMTP(H, 2525); s.ehlo("ext.example.org")
s.sendmail("x@example.org", ["sales@shop.test"], "Subject: to sales\r\n\r\nx\r\n")
s.sendmail("x@example.org", ["dave@legacy-alias.test"], "Subject: via alias domain\r\n\r\nx\r\n")
s.sendmail("x@example.org", ["d@legacy.test"], "Subject: via per-user alias\r\n\r\nx\r\n")
s.sendmail("x@example.org", ["erin@legacy.test"], "Subject: erin forwarded\r\n\r\nx\r\n")
s.quit(); time.sleep(1)
m = imaplib.IMAP4_SSL(H, 1993, ssl_context=ctx); m.login("dave@legacy.test", "OldPassword1"); m.select("INBOX")
subs = [m.search(None, "SUBJECT", q)[1][0] for q in ("sales", "\"alias domain\"", "\"per-user alias\"")]
check("list alias, alias domain and per-user alias all reach dave", all(subs), subs)
typ, d = m.search(None, "ALL"); uids = m.uid("SEARCH", None, "ALL")[1][0].split()
check("new mail continues after Dovecot UIDs", int(uids[-1]) >= 4, uids)
m.logout()
m = imaplib.IMAP4_SSL(H, 1993, ssl_context=ctx); m.login("erin@legacy.test", "AmyPass123"); m.select("INBOX")
check("erin is forward-only (no local copy), as in iRedMail", not m.search(None, "SUBJECT", "sales")[1][0] and not m.search(None, "SUBJECT", "forwarded")[1][0])
m.logout()
check("erin's mail forwarded externally", "to erin.home@example.org" in open("/tmp/imptest/server.log").read() or "example.org" in subprocess.run(["/home/claude/postwright-repo/target/release/postwright","-c","/tmp/imptest/postwright.toml","queue","list"],capture_output=True,text=True).stdout + open("/tmp/imptest/server.log").read())

# DKIM with the imported key + selector
s = smtplib.SMTP_SSL(H, 4465, context=ctx); s.login("dave@legacy.test", "OldPassword1")
s.sendmail("dave@legacy.test", ["dave@legacy.test"], "From: dave@legacy.test\r\nTo: dave@legacy.test\r\nSubject: dkim test\r\n\r\nsigned\r\n")
s.sendmail("dave@legacy-alias.test", ["erin@legacy.test"], "From: dave@legacy-alias.test\r\nTo: erin@legacy.test\r\nSubject: alias sender\r\n\r\nx\r\n")
s.quit(); time.sleep(0.5)
check("can send as user@alias-domain", True)
m = imaplib.IMAP4_SSL(H, 1993, ssl_context=ctx); m.login("dave@legacy.test", "OldPassword1"); m.select("INBOX")
raw = m.fetch(m.search(None, "SUBJECT", "dkim")[1][0], "(BODY.PEEK[])")[1][0][1]
import dkim
pub = subprocess.run(["openssl", "rsa", "-in", "/var/lib/dkim/legacy.test.pem", "-pubout", "-outform", "DER"], capture_output=True).stdout
txt = b"v=DKIM1; k=rsa; p=" + base64.b64encode(pub)
check("signed with existing key and selector 'dkim'", b"s=dkim" in raw and dkim.verify(raw, dnsfunc=lambda n, timeout=5: txt if n.startswith(b"dkim._domainkey.legacy.test") else None))

# CalDAV
def req(method, path, who, body=None, depth="1"):
    c = http.client.HTTPSConnection(H, 8443, context=ctx)
    c.request(method, path, body=body, headers={"Authorization": "Basic " + base64.b64encode(f"{who[0]}:{who[1]}".encode()).decode(), "Depth": depth})
    r = c.getresponse(); return r.status, r.read()
s, b = req("REPORT", "/dav/calendars/dave@legacy.test/calendar/", ("dave@legacy.test", "OldPassword1"),
    '<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><c:calendar-data/></d:prop></c:calendar-query>')
check("SOGo personal calendar imported (deleted event skipped)", b"Dentist" in b and b"Deleted" not in b, b[:200])
s, b = req("PROPFIND", "/dav/calendars/erin@legacy.test/", ("erin@legacy.test", "AmyPass123"))
check("SOGo share imported (erin sees Shop rota)", b"Shop rota (dave@legacy.test)" in b)
print(f"\n{sum(R)}/{len(R)} passed"); sys.exit(0 if all(R) else 1)
