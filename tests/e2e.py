"""End-to-end test of Postwright using Python's standard SMTP and IMAP clients."""
import imaplib, smtplib, ssl, socket, time, sys, threading

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
H = "127.0.0.1"
results = []

def check(name, cond, info=""):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{info}]" if info and not cond else ""))

def raw_smtp(port, lines):
    s = socket.create_connection((H, port)); f = s.makefile("rb")
    out = [f.readline().decode()]
    for l in lines:
        s.sendall(l.encode() + b"\r\n")
        resp = f.readline().decode()
        while resp[3:4] == "-":
            resp = f.readline().decode()
        out.append(resp)
    s.close(); return out

# --- Inbound MX (port 25 equivalent)
r = raw_smtp(2525, ["EHLO relay.example.org", "MAIL FROM:<spammer@evil.example>", "RCPT TO:<victim@gmail.com>"])
check("inbound refuses open relay", r[3].startswith("554"), r[3])
r = raw_smtp(2525, ["EHLO x.example.org", "AUTH PLAIN AHRvbnlAam9obmNvY2sudGVzdABDb3JyZWN0SG9yc2Ux"])
check("no AUTH on inbound port", r[2].startswith("502"), r[2])
r = raw_smtp(2525, ["EHLO x.example.org", "MAIL FROM:<a@example.org>", "RCPT TO:<nobody@johncock.test>"])
check("unknown local user rejected", r[3].startswith("550"), r[3])

s = smtplib.SMTP(H, 2525); s.ehlo("sender.example.org"); s.starttls(context=ctx); s.ehlo("sender.example.org")
msg = "From: Bob <bob@example.org>\r\nTo: tony@johncock.test\r\nSubject: Inbound test\r\nMessage-ID: <1@example.org>\r\n\r\nHello Tony\r\n.leading dot line\r\n"
s.sendmail("bob@example.org", ["tony@johncock.test", "info@poffles.test", "hello@poffles.test", "random+tag@poffles.test"], msg)
s.quit()
check("inbound delivery with STARTTLS, alias, catch-all", True)

# SMTP smuggling: bare-LF "." must not end DATA
sock = socket.create_connection((H, 2525)); f = sock.makefile("rb"); f.readline()
def cmd(c):
    sock.sendall(c); l = f.readline()
    while l[3:4] == b"-": l = f.readline()
    return l.decode()
cmd(b"EHLO a.example.org\r\n"); cmd(b"MAIL FROM:<x@example.org>\r\n"); cmd(b"RCPT TO:<tony@johncock.test>\r\n"); cmd(b"DATA\r\n")
sock.sendall(b"Subject: smuggle\r\n\r\nbody\n.\nMAIL FROM:<admin@johncock.test>\r\n.\r\n")
r = f.readline().decode()
check("bare-LF dot does not end DATA (anti-smuggling)", r.startswith("250"), r)
check("smuggled command not executed separately", cmd(b"QUIT\r\n").startswith("221"))
sock.close()

# --- Submission
r = raw_smtp(5587, ["EHLO c", "AUTH PLAIN AHRvbnlAam9obmNvY2sudGVzdABDb3JyZWN0SG9yc2Ux"])
check("AUTH refused before STARTTLS", r[2].startswith("538"), r[2])
r = raw_smtp(5587, ["EHLO c", "MAIL FROM:<tony@johncock.test>"])
check("MAIL refused without auth on submission", r[2].startswith("530"), r[2])

s = smtplib.SMTP(H, 5587); s.starttls(context=ctx); s.ehlo()
try:
    s.login("tony@johncock.test", "wrong-password-x"); check("bad password rejected", False)
except smtplib.SMTPAuthenticationError:
    check("bad password rejected", True)
s.login("tony@johncock.test", "CorrectHorse1")
try:
    s.sendmail("amy@poffles.test", ["amy@poffles.test"], "From: amy@poffles.test\r\nSubject: spoof\r\n\r\nx\r\n")
    check("cannot send as someone else", False)
except smtplib.SMTPSenderRefused:
    check("cannot send as someone else", True)
s.rset()
s.sendmail("info@poffles.test", ["amy@poffles.test", "someone@external.example"],
           "From: Tony <info@poffles.test>\r\nTo: amy@poffles.test\r\nSubject: Via alias\r\n\r\nSent from an alias I own\r\n")
s.quit()
check("submission STARTTLS + auth + alias sender + external queue", True)

s = smtplib.SMTP_SSL(H, 4465, context=ctx); s.login("amy@poffles.test", "BatteryStaple2")
s.sendmail("amy@poffles.test", ["tony@johncock.test"], "From: amy@poffles.test\r\nTo: tony@johncock.test\r\nSubject: Implicit TLS\r\n\r\nHi from 465\r\n")
s.quit()
check("implicit TLS submission (465)", True)

# --- IMAP
try:
    m = imaplib.IMAP4(H, 1143); m.login("tony@johncock.test", "CorrectHorse1"); check("IMAP login refused before STARTTLS", False)
except imaplib.IMAP4.error as e:
    check("IMAP login refused before STARTTLS", "PRIVACYREQUIRED" in str(e) or "disabled" in str(e).lower(), str(e))

m = imaplib.IMAP4(H, 1143); m.starttls(ssl_context=ctx); m.login("tony@johncock.test", "CorrectHorse1")
typ, boxes = m.list()
names = b" ".join(boxes).decode()
check("LIST shows special-use folders", "\\Sent" in names and "\\Trash" in names, names)
typ, d = m.select("INBOX")
n = int(d[0])
check("INBOX has 4 messages (inbound, 465, alias, bounce for nonexistent domain)", n == 4, n)
typ, d = m.search(None, "SUBJECT", "Undelivered")
check("nonexistent domain bounced immediately to sender", d[0] != b"", d)
typ, d = m.search(None, "SUBJECT", "Inbound")
check("SEARCH SUBJECT", d[0] == b"1", d)
typ, d = m.uid("SEARCH", None, "UNSEEN")
check("UID SEARCH UNSEEN", len(d[0].split()) == 4, d)
typ, d = m.fetch("1", "(UID FLAGS RFC822.SIZE INTERNALDATE ENVELOPE BODYSTRUCTURE BODY.PEEK[HEADER.FIELDS (SUBJECT FROM)])")
blob = b"".join(x if isinstance(x, bytes) else x[0] + x[1] for x in d)
check("FETCH envelope/bodystructure", b"ENVELOPE" in blob and b"BODYSTRUCTURE" in blob and b"Subject: Inbound test" in blob, blob[:300])
typ, d = m.fetch("1", "(BODY[])")
body = d[0][1]
check("BODY[] has Received header and dot-unstuffed text", body.startswith(b"Received: from") and b"\r\n.leading dot line\r\n" in body and b".." not in body, body[:200])
check("BODY[] fetch set \\Seen", b"\\Seen" in d[0][0] or b"\\Seen" in (d[1] if len(d) > 1 and isinstance(d[1], bytes) else b""), d)
typ, d = m.search(None, "SUBJECT", "Implicit")
typ, d = m.fetch(d[0].split()[0], "(BODY.PEEK[])")
check("submitted mail is DKIM signed", d[0][1].find(b"DKIM-Signature: v=1; a=rsa-sha256") >= 0 and b"d=poffles.test" in d[0][1], d[0][1][:400])
m.store("2", "+FLAGS", "(\\Flagged)")
typ, d = m.search(None, "FLAGGED")
check("STORE +FLAGS / SEARCH FLAGGED", d[0] == b"2", d)
typ, d = m.uid("COPY", "1", "Archive")
cu = m.response("COPYUID")
check("UID COPY with COPYUID", typ == "OK" and cu[1][0] is not None, cu)
typ, d = m._simple_command("MOVE", "2", "Trash"); m._untagged_response(typ, d, "MOVE")
check("MOVE", typ == "OK", d)
typ, d = m.status("Trash", "(MESSAGES UNSEEN UIDNEXT)")
check("STATUS Trash", b"MESSAGES 1" in d[0], d)
typ, d = m.append("Sent", "(\\Seen)", None, b"From: tony@johncock.test\r\nSubject: draft copy\r\n\r\nappended\r\n")
check("APPEND with APPENDUID", typ == "OK" and b"APPENDUID" in d[0], d)
m.create("Projects/Postwright"); typ, d = m.list("", "Projects/*")
check("CREATE nested + LIST pattern", b"Projects/Postwright" in d[0], d)
m.rename("Projects", "Work"); typ, d = m.list("", "Work/%")
check("RENAME moves children", d and d[0] and b"Work/Postwright" in d[0], d)
m.store("1", "+FLAGS", "(\\Deleted)"); typ, d = m.expunge()
check("MOVE then EXPUNGE report correct sequence numbers", typ == "OK" and d == [b"2", b"1"], d)

# IDLE push: second connection delivers mail while the first idles
m.select("INBOX")
tag = m._new_tag().decode()
m.send(f"{tag} IDLE\r\n".encode()); assert m.readline().startswith(b"+")
def later():
    time.sleep(1)
    s = smtplib.SMTP(H, 2525); s.ehlo("x.example.org")
    s.sendmail("bob@example.org", ["tony@johncock.test"], "Subject: idle push\r\n\r\nping\r\n"); s.quit()
threading.Thread(target=later).start()
m.sock.settimeout(10)
line = m.readline()
check("IDLE receives EXISTS push", b"EXISTS" in line, line)
m.send(b"DONE\r\n")
while True:
    l = m.readline()
    if l.startswith(tag.encode()): break
check("IDLE terminated with DONE", l.split()[1] == b"OK", l)
m.logout()

m = imaplib.IMAP4_SSL(H, 1993, ssl_context=ctx); m.login("amy@poffles.test", "BatteryStaple2"); m.select("INBOX")
typ, d = m.search(None, "ALL")
check("Amy got inbound copies (hello alias + catch-all deduped) + submission", len(d[0].split()) == 2, d)
m.logout()

# Brute force throttle
fails = 0
for i in range(6):
    try:
        x = imaplib.IMAP4_SSL(H, 1993, ssl_context=ctx); x.login("tony@johncock.test", f"nope{i}")
    except Exception as e:
        fails += 1
        last = str(e)
check("IP blocked after repeated failures", "UNAVAILABLE" in last or "BYE" in last or "Too many" in last, last)

print(f"\n{sum(r for _, r in results)}/{len(results)} passed")
sys.exit(0 if all(r for _, r in results) else 1)
