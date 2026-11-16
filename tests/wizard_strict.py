"""Wizard in a browser that trusts only the certificate it first accepted (like a user
clicking through the warning once), not one that ignores certificate errors."""
import base64, hashlib, os, re, shutil, subprocess, sys, time
from playwright.sync_api import sync_playwright
BIN = os.environ.get("PWBIN", "/home/claude/postwright-repo/target/release/postwright")
shutil.rmtree("/tmp/wiz", ignore_errors=True); os.makedirs("/tmp/wiz")
p = subprocess.Popen([BIN, "-c", "/tmp/wiz/postwright.toml"], stdout=open("/tmp/wiz/out.log", "w"), stderr=subprocess.STDOUT, cwd="/tmp/wiz")
code = None
for _ in range(60):
    time.sleep(0.5)
    m = re.search(r"Setup code \(if the page asks\): ([A-Z0-9-]+)", open("/tmp/wiz/out.log").read())
    if m: code = m.group(1); break
spki = subprocess.run("openssl x509 -in /tmp/wiz/data/tls/cert.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64",
                      shell=True, capture_output=True, text=True).stdout.strip()
R = []
def check(n, c, i=""):
    R.append(bool(c)); print(("PASS " if c else "FAIL ") + n + (f"  [{i}]" if i and not c else ""))
with sync_playwright() as pw:
    b = pw.chromium.launch(args=[f"--ignore-certificate-errors-spki-list={spki}"])
    page = b.new_context(viewport={"width": 1280, "height": 860}).new_page()
    toasts = []
    page.on("dialog", lambda d: d.accept())
    page.goto(f"https://127.0.0.1/setup#{code}"); page.wait_for_timeout(1200)
    page.click("text=Start"); page.wait_for_timeout(800)
    page.fill("input[placeholder='mail.yourcompany.com']", "mail.throwaway.test")
    page.click("text=Save and continue"); page.wait_for_timeout(2500)
    check("saving the server name keeps the page working", page.is_visible("text=Where is your mail now?"), page.inner_text("main")[:300])
    check("no error toast", not page.is_visible(".toast.err"), page.inner_text("body")[-200:])
    page.click("text=Starting fresh"); page.click("button:has-text('Continue')"); page.wait_for_timeout(800)
    page.fill("input[placeholder='yourcompany.com']", "throaway.test"); page.click("text=Add domain"); page.wait_for_timeout(2500)
    page.click("text=Remove"); page.wait_for_timeout(1500)
    check("typo domain removed", not page.is_visible("text=throaway.test"))
    page.fill("input[placeholder='yourcompany.com']", "throwaway.test"); page.click("text=Add domain"); page.wait_for_timeout(2500)
    page.click("button:has-text('Continue')"); page.wait_for_timeout(800)
    page.fill("input[placeholder='tony']", "tony")
    pws = page.query_selector_all("input[type=password]"); pws[0].fill("WizardPass99"); pws[1].fill("WizardPass99")
    page.click("text=Create account"); page.wait_for_timeout(1500)
    for _ in range(5):
        page.click("button:has-text('Continue'), button:has-text('Save and continue'), button:has-text('Skip')"); page.wait_for_timeout(2500)
    check("reached the finish step", page.is_visible("text=Ready to go"), page.inner_text("main")[:200])
    page.click("text=Finish and start Postwright"); page.wait_for_timeout(8000)
    check("browser sent on to the sign-in page", "/login" in page.url, page.url)
    b.close()
log = open("/tmp/wiz/out.log").read()
check("server started normally", "running as mail.throwaway.test" in log, log[-500:])
p.terminate()
print(f"\n{sum(R)}/{len(R)} passed"); sys.exit(0 if all(R) else 1)
