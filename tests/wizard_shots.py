import os, re, shutil, subprocess, time
from playwright.sync_api import sync_playwright
BIN = "/home/claude/postwright-repo/target/release/postwright"
shutil.rmtree("/tmp/wiz", ignore_errors=True); os.makedirs("/tmp/wiz"); os.makedirs("/home/claude/shots/wiz", exist_ok=True)
log = open("/tmp/wiz/out.log", "w")
p = subprocess.Popen([BIN, "-c", "/tmp/wiz/postwright.toml"], stdout=log, stderr=subprocess.STDOUT, cwd="/tmp/wiz")
for _ in range(40):
    time.sleep(0.5)
    m = re.search(r"Setup code \(if the page asks\): ([A-Z0-9-]+)", open("/tmp/wiz/out.log").read())
    if m: code = m.group(1); break
def shot(page, n):
    page.wait_for_timeout(900); page.screenshot(path=f"/home/claude/shots/wiz/{n}.png", full_page=True)
with sync_playwright() as pw:
    b = pw.chromium.launch()
    page = b.new_context(ignore_https_errors=True, viewport={"width": 1280, "height": 860}).new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.goto("https://127.0.0.1/setup"); shot(page, "00-code")
    page.fill("input.code-in", code); page.click("text=Continue"); shot(page, "01-welcome")
    page.click("text=Start"); shot(page, "02-server")
    page.fill("input[placeholder='mail.yourcompany.com']", "mail.wiz.test"); page.click("text=Check DNS"); page.wait_for_timeout(7000); shot(page, "02b-server-check")
    page.click("text=Save and continue"); shot(page, "03-from")
    page.click("text=Microsoft 365, Google, Exchange or another server"); page.click("button:has-text('Continue')"); shot(page, "04-domains")
    page.fill("input[placeholder='yourcompany.com']", "wiz.test"); page.click("text=Add domain"); page.wait_for_timeout(2500); shot(page, "04b-domains")
    page.click("button:has-text('Continue')"); shot(page, "05-admin")
    page.fill("input[placeholder='tony']", "tony"); page.fill("input[placeholder='Tony Johncock']", "Tony Johncock")
    pws = page.query_selector_all("input[type=password]"); pws[0].fill("WizardPass99"); pws[1].fill("WizardPass99")
    page.click("text=Create account"); page.wait_for_timeout(1500); shot(page, "05b-admin")
    page.click("button:has-text('Continue')"); shot(page, "06-cert")
    page.click("button:has-text('Continue')"); page.wait_for_timeout(2500); shot(page, "07-spam")
    page.click("text=Save and continue"); page.wait_for_timeout(3000); shot(page, "08-dns")
    page.click("button:has-text('Continue')"); shot(page, "09-migrate")
    page.click("text=Microsoft 365 / Exchange Online"); shot(page, "09b-migrate-exo")
    page.click("text=Another mail server (IMAP)"); shot(page, "09c-migrate-imap")
    page.click("button:has-text('Continue')"); shot(page, "10-finish")
    page.click("text=Finish and start Postwright"); page.wait_for_timeout(9000); shot(page, "11-after")
    print("url after finish:", page.url)
    print("errors:", errors)
    b.close()
p.terminate()
