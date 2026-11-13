"""Verify Postwright's DKIM signatures with dkimpy, using the public key from `domain dns`."""
import dkim, imaplib, ssl, subprocess, sys, re
out = subprocess.run(["/home/claude/postwright/target/debug/postwright", "-c", "/tmp/pwtest/postwright.toml", "domain", "dns", "poffles.test"], capture_output=True, text=True).stdout
txt = out.strip().splitlines()[-1].encode()
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
m = imaplib.IMAP4_SSL("127.0.0.1", 1993, ssl_context=ctx); m.login("tony@johncock.test", "CorrectHorse1"); m.select("INBOX")
typ, d = m.search(None, "SUBJECT", "Implicit")
raw = m.fetch(d[0].split()[0], "(BODY.PEEK[])")[1][0][1]
# Strip our own Received header (added before signing but not signed) - keeps the test honest either way.
ok = dkim.verify(raw, dnsfunc=lambda name, timeout=5: txt if name.startswith(b"pw1._domainkey.poffles.test") else None)
print("dkimpy verification:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
