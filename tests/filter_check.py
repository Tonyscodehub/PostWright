"""Antispam / antivirus checks against real ClamAV, Rspamd and SpamAssassin."""
import imaplib, smtplib, ssl, sys, time, subprocess
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
H = "127.0.0.1"; R = []
TONY = ("tony@johncock.test", "CorrectHorse1")
EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
GTUBE = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"
def check(n, c, i=""):
    R.append(bool(c)); print(("PASS " if c else "FAIL ") + n + (f"  [{i}]" if i and not c else ""))
def send25(body, rcpt="tony@johncock.test"):
    s = smtplib.SMTP(H, 2525); s.ehlo("mx.sender.example")
    try:
        s.sendmail("bob@sender.example", [rcpt], body); return (250, "")
    except smtplib.SMTPDataError as e:
        return (e.smtp_code, e.smtp_error.decode())
    finally:
        s.quit()
attach = ("From: bob@sender.example\r\nTo: tony@johncock.test\r\nSubject: invoice\r\nMIME-Version: 1.0\r\n"
          "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n"
          "--b\r\nContent-Type: application/octet-stream; name=x.com\r\nContent-Disposition: attachment; filename=x.com\r\n\r\n" + EICAR + "\r\n--b--\r\n")
code, msg = send25(attach)
check("inbound virus rejected in-session (ClamAV)", code == 554 and "Eicar" in msg, (code, msg))
s = smtplib.SMTP_SSL(H, 4465, context=ctx); s.login(*TONY)
try:
    s.sendmail(TONY[0], ["amy@poffles.test"], attach.replace("bob@sender.example", TONY[0])); check("outbound virus blocked", False)
except smtplib.SMTPDataError as e:
    check("outbound virus blocked", e.smtp_code == 554, e)
s.quit()
code, msg = send25(f"From: bob@sender.example\r\nTo: tony@johncock.test\r\nSubject: cheap pills\r\n\r\n{GTUBE}\r\n")
check("GTUBE spam rejected (Rspamd/SpamAssassin)", code == 550, (code, msg))
code, _ = send25("From: Bob <bob@sender.example>\r\nTo: tony@johncock.test\r\nSubject: Quarterly figures\r\nDate: Fri, 13 Nov 2026 10:00:00 +0000\r\n"
                 "Message-ID: <q1@sender.example>\r\nX-Spam-Flag: NO\r\nX-Spam-Score: -100\r\n\r\nHi Tony, figures attached next week.\r\n")
check("clean mail accepted", code == 250)
m = imaplib.IMAP4_SSL(H, 1993, ssl_context=ctx); m.login(*TONY); m.select("INBOX")
n = m.search(None, "SUBJECT", "Quarterly")[1][0].split()
raw = m.fetch(n[-1], "(BODY.PEEK[HEADER])")[1][0][1] if n else b""
check("X-Spam headers added with scanner scores", b"X-Spam-Status: No" in raw and b"RSPAMD" in raw and b"SPAMASSASSIN" in raw, raw[:600])
check("sender's forged X-Spam headers stripped", raw.count(b"X-Spam-Flag") == 1 and b"-100" not in raw, raw[:600])
# learning: move into Junk
typ, d = m._simple_command("MOVE", n[-1].decode(), "Junk")
time.sleep(3)
log = open("/tmp/pwtest/server.log").read()
check("moving to Junk teaches the filters", "learnt spam for tony@johncock.test" in log)
m.logout()
print(f"\n{sum(R)}/{len(R)} passed"); sys.exit(0 if all(R) else 1)
