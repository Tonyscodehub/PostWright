"""Load test: concurrent authenticated submissions plus many idle IMAP sessions."""
import smtplib, imaplib, ssl, time, threading, sys
from concurrent.futures import ThreadPoolExecutor
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
H = "127.0.0.1"
idle = []
def hold():
    m = imaplib.IMAP4_SSL(H, 1993, ssl_context=ctx); m.login("amy@poffles.test", "BatteryStaple2"); m.select("INBOX"); idle.append(m)
with ThreadPoolExecutor(25) as ex:
    list(ex.map(lambda _: hold(), range(25)))   # per-IP cap is 30 by default
def worker(n):
    s = smtplib.SMTP(H, 2525); s.ehlo("load.example.org"); s.starttls(context=ctx); s.ehlo("load.example.org")
    for i in range(40):
        s.sendmail("load@example.org", ["tony@johncock.test"], f"Subject: load {n}-{i}\r\n\r\n" + "x" * 2000 + "\r\n")
    s.quit()
t = time.time()
with ThreadPoolExecutor(4) as ex:
    list(ex.map(worker, range(4)))
dt = time.time() - t
print(f"160 messages over 4 parallel TLS connections in {dt:.2f}s = {160/dt:.0f} msg/s, with {len(idle)} IMAP sessions open")
m = imaplib.IMAP4_SSL(H, 1993, ssl_context=ctx); m.login("tony@johncock.test", "CorrectHorse1")
print("Tony INBOX:", m.select("INBOX")[1][0].decode())
t = time.time(); typ, d = m.fetch("1:*", "(FLAGS ENVELOPE)"); print(f"FETCH ENVELOPE of all in {time.time()-t:.2f}s")
