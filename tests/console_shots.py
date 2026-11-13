"""Open every admin console page in Chrome, check for JS errors, and screenshot it."""
import sys
from playwright.sync_api import sync_playwright
errors = []
with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/usr/bin/google-chrome", args=["--no-sandbox"])
    ctx = b.new_context(ignore_https_errors=True, viewport={"width": 1360, "height": 900},
                        http_credentials={"username": "tony@johncock.test", "password": "CorrectHorse1"})
    page = ctx.new_page()
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("console", lambda m: m.type == "error" and errors.append(m.text))
    for name in ["overview", "domains", "users", "aliases", "queue", "filters", "import", "logs"]:
        page.goto(f"https://127.0.0.1:8443/admin#{name}")
        page.wait_for_timeout(1200)
        if name == "domains":
            page.get_by_role("button", name="Check DNS").first.click(); page.wait_for_timeout(1500)
        if name == "users":
            page.get_by_role("button", name="Edit").first.click(); page.wait_for_timeout(300)
        page.screenshot(path=f"/home/claude/shots/{name}.png", full_page=True)
        h2 = page.locator("main h2").inner_text()
        print(f"{name}: '{h2}'")
    page.goto("https://127.0.0.1:8443/"); page.wait_for_timeout(1000)
    print("settings page has admin link:", page.get_by_role("link", name="Administration").count() == 1)
    b.close()
print("JS errors:", errors or "none")
sys.exit(1 if errors else 0)
