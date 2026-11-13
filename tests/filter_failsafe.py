"""With ClamAV down, mail is deferred (451), not let through unscanned. Junk filing check."""
import smtplib, imaplib, ssl, sys, subprocess, time
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
mode = sys.argv[1]
s = smtplib.SMTP("127.0.0.1", 2525); s.ehlo("mx.sender.example")
try:
    s.sendmail("bob@sender.example", ["tony@johncock.test"], "From: bob@sender.example\r\nSubject: while scanner down\r\nDate: Fri, 13 Nov 2026 10:00:00 +0000\r\nMessage-ID: <z@sender.example>\r\n\r\nhello\r\n")
    code = 250
except smtplib.SMTPDataError as e:
    code = e.smtp_code
s.quit()
if mode == "down":
    ok = code == 451
    print(("PASS" if ok else "FAIL") + " ClamAV down -> 451 tempfail (fail closed)", code)
else:
    m = imaplib.IMAP4_SSL("127.0.0.1", 1993, ssl_context=ctx); m.login("tony@johncock.test", "CorrectHorse1")
    m.select("Junk"); hit = m.search(None, "SUBJECT", '"while scanner down"')[1][0]
    ok = code == 250 and bool(hit)
    print(("PASS" if ok else "FAIL") + " score above junk threshold -> filed in Junk", code, hit)
sys.exit(0 if ok else 1)
