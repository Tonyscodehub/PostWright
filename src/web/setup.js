"use strict";
// Postwright first-run setup wizard. Built with textContent only.

const main = document.getElementById("main");
let code = (location.hash || "").slice(1) || sessionStorage.getItem("pw-setup-code") || "";
if (location.hash) history.replaceState(null, "", location.pathname);
let S = null;            // server state
let migrateFrom = sessionStorage.getItem("pw-from") || "";
let current = 0;
let mounted = null;

function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (v === true) e.setAttribute(k, "");
    else if (v !== false && v != null) e.setAttribute(k, v);
  }
  for (const k of kids.flat()) if (k != null && k !== false) e.append(k instanceof Node ? k : document.createTextNode(String(k)));
  return e;
}
const pill = (t, c) => h("span", { class: "pill " + c }, t);
const txt = (a) => h("input", { type: "text", ...a });
const field = (label, el, hint) => h("div", { class: "field" }, h("label", {}, label), el, hint ? h("div", { class: "muted small" }, hint) : null);
function toast(msg, ok = true) {
  const t = h("div", { class: "toast " + (ok ? "ok" : "err") }, msg);
  document.body.append(t);
  setTimeout(() => t.remove(), ok ? 2500 : 7000);
}

async function api(method, path, body) {
  const opts = { method, headers: { "X-Setup-Code": code, "X-Requested-With": "setup" } };
  if (body !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
  const r = await fetch("/setup/api/" + path, opts);
  const data = await r.json().catch(() => ({}));
  if (r.status === 401) { sessionStorage.removeItem("pw-setup-code"); code = ""; askCode(data.error); throw new Error(data.error || "setup code needed"); }
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}
const adm = (m, p, b) => api(m, "admin/" + p, b);

async function busy(btn, fn) {
  const was = btn.textContent;
  btn.disabled = true; btn.textContent = "Working…";
  try { return await fn(); } catch (e) { toast(e.message, false); return undefined; } finally { btn.disabled = false; btn.textContent = was; }
}

// -------------------------------------------------------------------- steps
const STEPS = [
  { id: "welcome", title: "Welcome", view: welcome },
  { id: "server", title: "Server name", view: server, done: () => S.hostname !== "mail.example.com" && sessionStorage.getItem("pw-host-ok") },
  { id: "from", title: "Your mail today", view: from, done: () => !!migrateFrom },
  { id: "domains", title: "Domains", view: domains, done: () => S.domains.length > 0 },
  { id: "admin", title: "Your admin account", view: adminStep, done: () => S.admins.length > 0 },
  { id: "cert", title: "Certificate", view: cert, done: () => sessionStorage.getItem("pw-cert-ok") },
  { id: "spam", title: "Spam & viruses", view: spam, done: () => sessionStorage.getItem("pw-spam-ok") },
  { id: "dns", title: "DNS records", view: dns, done: () => sessionStorage.getItem("pw-dns-ok") },
  { id: "migrate", title: "Bring mail across", view: migrateStep, done: () => sessionStorage.getItem("pw-migrate-ok") },
  { id: "finish", title: "Finish", view: finish },
];

function rail() {
  const ol = document.getElementById("steps");
  ol.replaceChildren(...STEPS.map((s, i) => {
    const done = i < current && (!s.done || s.done());
    const li = h("li", { class: (i === current ? "cur" : done ? "done" : i < current ? "skip" : "") }, s.title);
    if (i < current || done) li.addEventListener("click", () => go(i));
    return li;
  }));
}

async function refresh() { S = await api("GET", "state"); document.getElementById("ver").textContent = `Setup · v${S.version}`; }

async function go(i) {
  if (mounted) { mounted.stop(); mounted = null; }
  current = Math.max(0, Math.min(STEPS.length - 1, i));
  sessionStorage.setItem("pw-step", String(current));
  try { await refresh(); } catch (e) { return; }
  rail();
  main.replaceChildren(h("div", { class: "center muted" }, "Loading…"));
  try { await STEPS[current].view(); } catch (e) { main.replaceChildren(h("div", { class: "card" }, h("h3", {}, "Something went wrong"), e.message)); }
  window.scrollTo(0, 0);
}
const next = () => go(current + 1);
const back = () => go(current - 1);
const navRow = (...right) => h("div", { class: "nav" }, current > 0 ? h("button", { class: "ghost", onclick: back }, "Back") : h("span"), h("div", { class: "row" }, ...right));
const page = (title, lead, ...content) => main.replaceChildren(h("h2", {}, title), h("p", { class: "sub lead" }, lead), ...content.filter((c) => c != null && c !== false && c !== ""));

// --------------------------------------------------------------- the code
function askCode(msg) {
  document.getElementById("steps").replaceChildren();
  const inp = h("input", { type: "text", class: "code-in", placeholder: "XXXX-XXXX-XXXX", autocomplete: "off" });
  const go1 = async () => {
    code = inp.value.trim().toUpperCase();
    sessionStorage.setItem("pw-setup-code", code);
    try { await refresh(); start(); } catch (e) { /* askCode shown again */ }
  };
  inp.addEventListener("keydown", (e) => { if (e.key === "Enter") go1(); });
  main.replaceChildren(h("div", { class: "center" }, h("h2", {}, "Enter the setup code"),
    h("p", { class: "lead" }, "It's shown in the window (or log) where Postwright is running."),
    msg ? h("p", { class: "err pill" }, msg) : null, h("p", {}, inp), h("button", { onclick: go1 }, "Continue")));
  inp.focus();
}

// --------------------------------------------------------------- 1 welcome
async function welcome() {
  const linuxNotRoot = S.platform === "linux" && !S.is_root;
  page("Let's set up your mail server", "This takes about 15 minutes. You can come back to any step later, and everything here can be changed afterwards in the admin console.",
    h("div", { class: "card" }, h("h3", {}, "You'll need"),
      h("ul", {},
        h("li", {}, "A name for this server that points at it, such as ", h("b", {}, "mail.yourcompany.com"), " (you'll check this in the next step)."),
        h("li", {}, "Access to your domain's DNS, to add a few records."),
        h("li", {}, "Ports 25, 465, 587, 993 and 443 forwarded to this machine from the internet (for OPNsense: Firewall → NAT → Port Forward)."),
        h("li", {}, "If you're moving from another system: its admin details (Microsoft 365 or Google), or the users' passwords."))),
    linuxNotRoot ? h("div", { class: "card note" }, h("b", {}, "Postwright isn't running as root. "), "It needs root (or the CAP_NET_BIND_SERVICE capability) to use the mail ports. Stop it and start it again with sudo.") : null,
    h("div", { class: "card" }, h("table", { class: "kv" },
      h("tr", {}, h("td", {}, "Settings file"), h("td", {}, h("code", {}, S.config_path))),
      h("tr", {}, h("td", {}, "Mail is stored in"), h("td", {}, h("code", {}, S.data_dir))),
      h("tr", {}, h("td", {}, "This machine"), h("td", {}, `${S.platform}${S.local_ips.length ? " · " + S.local_ips.join(", ") : ""}`)))),
    navRow(h("button", { onclick: next }, "Start")));
}

// ---------------------------------------------------------------- 2 server
async function server() {
  const host = txt({ value: S.hostname === "mail.example.com" ? "" : S.hostname, placeholder: "mail.yourcompany.com", size: 36 });
  const out = h("div");
  const check = async (btn) => {
    const r = await busy(btn, () => api("POST", "check-host", { hostname: host.value.trim() }));
    if (!r) return;
    const line = (ok, okText, badText) => h("div", { class: "check" }, pill(ok ? "OK" : "Check", ok ? "ok" : "warn"), h("div", {}, ok ? okText : badText));
    out.replaceChildren(h("div", { class: "card" }, h("h3", {}, "What the internet sees"),
      line(r.addresses.length > 0, `${host.value} points to ${r.addresses.join(", ")}.`, `${host.value} doesn't resolve yet. Add an A record for it pointing at your public IP address.`),
      line(r.ptr_matches, "Reverse DNS matches the name, which big providers like Gmail and Microsoft check.",
        r.addresses.length ? `Reverse DNS: ${r.ptr.join("; ") || "none"}. Ask your ISP to set it to ${host.value}. Mail usually still works, but is more likely to be marked as spam.` : "Reverse DNS can't be checked until the name resolves."),
      line(r.outbound_25, "This machine can reach other mail servers on port 25.", "This machine can't connect out on port 25. Some ISPs block it; check your firewall, or ask your ISP.")));
  };
  const btnCheck = h("button", { class: "ghost", onclick: (e) => check(e.target) }, "Check DNS");
  const save = h("button", { onclick: async (e) => {
    const r = await busy(e.target, () => api("POST", "hostname", { hostname: host.value.trim() }));
    if (!r) return;
    sessionStorage.setItem("pw-host-ok", "1");
    if (r.certificate_regenerated) toast("Saved. The temporary certificate was remade for this name, so your browser may warn again.", true);
    next();
  } }, "Save and continue");
  page("What's this server called?", "The name mail apps and other mail servers use to reach it. It doesn't have to match your email domain: one server can host many domains.",
    h("div", { class: "card big" }, field("Server name", host, "Usually mail. followed by your main domain, e.g. mail.johncock.com"), h("div", { class: "row" }, btnCheck)),
    out, navRow(save));
  if (host.value) check(btnCheck);
}

// ------------------------------------------------------------------ 3 from
async function from() {
  const opts = [
    { id: "fresh", title: "Starting fresh", sub: "No mail to bring across, or I'll set it up later." },
    { id: "iredmail", title: "iRedMail on this machine", sub: S.iredmail_detected ? "Detected here. Brings users with their passwords, aliases, DKIM keys, mail and calendars." : "Not detected: run this setup on the iRedMail server to use it.", disabled: !S.iredmail_detected },
    { id: "other", title: "Microsoft 365, Google, Exchange or another server", sub: "You'll copy mail, calendars and contacts after the accounts are set up (step 9)." },
  ];
  const box = h("div");
  const choose = (id) => { migrateFrom = id; sessionStorage.setItem("pw-from", id); from(); };
  const cards = opts.map((o) => h("button", { class: "choice" + (migrateFrom === o.id ? " sel" : ""), disabled: !!o.disabled, onclick: () => choose(o.id) }, h("b", {}, o.title), h("span", {}, o.sub)));
  page("Where is your mail now?", "Nothing is changed or deleted on the old system.", h("div", { class: "card" }, h("div", { class: "choices" }, cards)), box,
    navRow(h("button", { disabled: !migrateFrom, onclick: next }, "Continue")));
  if (migrateFrom === "iredmail") iredmail(box);
}

async function iredmail(box) {
  const st = await adm("GET", "import");
  const out = h("pre", {}, st.output.length ? st.output.join("\n") : "Start with a dry run: it shows what would be imported without changing anything.");
  const status = st.running ? pill("Running…", "info") : st.finished ? (st.ok ? pill("Finished", "ok") : pill("Failed: " + (st.error || ""), "err")) : "";
  const run = (dry) => async (e) => {
    if (!dry && !confirm("Import everything from iRedMail now? It can take a while for large mailboxes. It's safe to run again later to pick up new mail.")) return;
    await busy(e.target, () => adm("POST", "import/iredmail", { dry_run: dry }));
    iredmail(box);
  };
  box.replaceChildren(h("div", { class: "card" }, h("h3", {}, "Import from iRedMail"),
    h("div", { class: "row" }, h("button", { class: "ghost", disabled: st.running, onclick: run(true) }, "Dry run"), h("button", { disabled: st.running, onclick: run(false) }, "Import everything"), status),
    h("p", { class: "muted small" }, "Run it again just before switching over to bring across mail that arrived in the meantime."), out));
  if (st.running) setTimeout(() => { if (STEPS[current].id === "from") iredmail(box); }, 2000);
}

// --------------------------------------------------------------- 4 domains
async function domains() {
  const list = await adm("GET", "domains");
  const name = txt({ placeholder: "yourcompany.com", size: 30 });
  const add = async (e) => {
    if (!name.value.trim()) return;
    if (await busy(e.target, () => adm("POST", "domains", { name: name.value.trim() })) !== undefined) domains();
  };
  name.addEventListener("keydown", (e) => { if (e.key === "Enter") add({ target: e.target.nextSibling || e.target }); });
  const rows = list.map((d) => h("tr", {}, h("td", {}, h("b", {}, d.name)), h("td", {}, d.alias_of ? `alias of ${d.alias_of}` : `${d.users} user(s), ${d.aliases} alias(es)`),
    h("td", { style: "text-align:right" }, h("button", { class: "danger", onclick: async (e) => { if (confirm(`Remove ${d.name}?`)) { await busy(e.target, () => adm("DELETE", "domains/" + encodeURIComponent(d.name))); domains(); } } }, "Remove"))));
  page("Which domains will this server handle?", "Add every domain you receive mail for, e.g. johncock.com and poffles.co.uk. A DKIM signing key is made for each one.",
    h("div", { class: "card" }, list.length ? h("table", {}, h("tbody", {}, rows)) : h("p", { class: "muted" }, "No domains yet."),
      h("div", { class: "row", style: "margin-top:10px" }, name, h("button", { onclick: add }, "Add domain"))),
    migrateFrom === "other" ? h("p", { class: "muted" }, "Tip: migrations can also add domains for you, but adding them here first lets you choose.") : null,
    navRow(h("button", { disabled: !list.length, onclick: next }, "Continue")));
  name.focus();
}

// ------------------------------------------------------------- 5 admin
async function adminStep() {
  const [users, doms] = await Promise.all([adm("GET", "users"), adm("GET", "domains")]);
  const admins = users.filter((u) => u.admin);
  const local = txt({ placeholder: "tony", size: 14 });
  const dom = h("select", {}, doms.filter((d) => !d.alias_of).map((d) => h("option", {}, d.name)));
  const nm = txt({ placeholder: "Tony Johncock", size: 24 });
  const pw = h("input", { type: "password", size: 22, autocomplete: "new-password" });
  const pw2 = h("input", { type: "password", size: 22, autocomplete: "new-password" });
  const create = async (e) => {
    if (pw.value !== pw2.value) return toast("The passwords don't match", false);
    if (pw.value.length < 10) return toast("Use at least 10 characters", false);
    const email = `${local.value.trim()}@${dom.value}`;
    const ok = await busy(e.target, async () => {
      await adm("POST", "users", { email, password: pw.value, admin: true });
      if (nm.value.trim()) await adm("PUT", "users/" + encodeURIComponent(email), { name: nm.value.trim() });
      return true;
    });
    if (ok) adminStep();
  };
  const existing = users.filter((u) => !u.admin);
  const pick = h("select", {}, existing.map((u) => h("option", {}, u.email)));
  const pickPw = h("input", { type: "password", size: 22, placeholder: "keep current password" });
  const promote = async (e) => {
    const body = { admin: true };
    if (pickPw.value) body.password = pickPw.value;
    if (await busy(e.target, () => adm("PUT", "users/" + encodeURIComponent(pick.value), body)) !== undefined) adminStep();
  };
  page("Create your administrator account", "This is a normal mailbox that can also open the admin console. Use it for your own mail if you like.",
    admins.length ? h("div", { class: "card" }, h("h3", {}, "Administrators"), h("ul", {}, admins.map((u) => h("li", {}, u.email))),
      h("p", { class: "muted small" }, "After setup, sign in and turn on two-step verification for these accounts under My settings.")) : null,
    h("div", { class: "card" }, h("h3", {}, admins.length ? "Add another administrator" : "New account"),
      h("div", { class: "form" }, field("Address", h("div", { class: "row" }, local, "@", dom)), field("Your name", nm), field("Password (10+ characters)", pw), field("Password again", pw2)),
      h("button", { onclick: create }, "Create account")),
    existing.length ? h("div", { class: "card" }, h("h3", {}, "Or make an existing (imported) account an administrator"),
      h("div", { class: "row" }, pick, pickPw, h("button", { class: "ghost", onclick: promote }, "Make administrator"))) : null,
    navRow(h("button", { disabled: !admins.length, onclick: next }, "Continue")));
}

// --------------------------------------------------------------- 6 cert
async function cert() {
  const c = await adm("GET", "certs");
  const cur = c.current;
  const status = cur ? (cur.self_signed ? pill("Temporary (self-signed)", "warn") : pill("Trusted certificate", "ok")) : pill("Missing", "err");
  const tabs = h("div");
  const show = (which) => {
    if (which === "opnsense") {
      const r = c.receiver || S.receiver || {};
      const key = h("textarea", { rows: 3, placeholder: "ssh-ed25519 AAAA… root@opnsense" });
      tabs.replaceChildren(h("ol", { class: "steps" },
        h("li", {}, "In OPNsense: Services → ACME Client → Automations → add ", h("b", {}, "Upload certificate via SFTP"), "."),
        h("li", {}, "Host: ", h("code", {}, S.local_ips[0] || "this machine's address"), "  Port: ", h("code", {}, (r.listen && r.listen[0] || "2222").split(":").pop()), "  User: ", h("code", {}, r.user || "acme")),
        h("li", {}, "OPNsense shows its public key on that page (Show identity). Paste it here:", key),
        h("li", {}, "If OPNsense asks for the host key fingerprint: ", h("code", {}, r.host_key_fingerprint || "")),
        h("li", {}, "Add the automation to your certificate and click Issue/Renew. Postwright picks the certificate up straight away.")),
        h("div", { class: "row" }, h("button", { onclick: async (e) => { if (await busy(e.target, () => adm("POST", "certs/keys", { key: key.value })) !== undefined) { toast("OPNsense's key added", true); sessionStorage.setItem("pw-cert-ok", "1"); } } }, "Allow this key")));
    } else if (which === "upload") {
      const chain = h("textarea", { rows: 5, placeholder: "-----BEGIN CERTIFICATE-----  (full chain)" });
      const key = h("textarea", { rows: 4, placeholder: "-----BEGIN PRIVATE KEY-----" });
      tabs.replaceChildren(h("div", { class: "form" }, field("Certificate (full chain, PEM)", chain), field("Private key (PEM)", key)),
        h("button", { onclick: async (e) => { if (await busy(e.target, () => adm("POST", "certs/upload", { fullchain: chain.value, key: key.value })) !== undefined) { toast("Certificate installed", true); sessionStorage.setItem("pw-cert-ok", "1"); cert(); } } }, "Install"));
    } else {
      tabs.replaceChildren(h("p", {}, "Mail apps will warn about the temporary certificate until a real one is installed. You can set it up later under Administration → Certificate."));
    }
  };
  const choice = h("select", { onchange: () => show(choice.value) }, h("option", { value: "opnsense" }, "OPNsense pushes it automatically (ACME)"), h("option", { value: "upload" }, "Paste a certificate I already have"), h("option", { value: "later" }, "Later"));
  page("Certificate", "Mail apps need a trusted certificate for " + S.hostname + ". Let's Encrypt via OPNsense's ACME client is the easiest way, and renews itself.",
    h("div", { class: "card" }, h("div", { class: "row" }, "Now: ", status, cur ? h("span", { class: "muted" }, `${(cur.names || []).join(", ")}, expires ${new Date(cur.not_after * 1000).toLocaleDateString()}`) : null)),
    h("div", { class: "card" }, h("div", { class: "row", style: "margin-bottom:10px" }, choice), tabs),
    navRow(h("button", { onclick: () => { sessionStorage.setItem("pw-cert-ok", "1"); next(); } }, "Continue")));
  show("opnsense");
}

// --------------------------------------------------------------- 7 spam
async function spam() {
  const s = await api("GET", "scanners");
  const boxes = {};
  const rows = s.detected.map((d) => {
    boxes[d.name] = h("input", { type: "checkbox", checked: s.configured[d.name] || d.found, disabled: !d.found && !s.configured[d.name] });
    return h("label", { class: "check" }, boxes[d.name], h("div", {}, h("b", {}, d.title), " ", d.found ? pill("found at " + d.address, "ok") : pill("not running here", ""), ));
  });
  page("Spam and virus protection", "Built-in checks are always on: blocklists, sender verification (SPF, DKIM, DMARC), greylisting and connection checks. Add scanners for stronger filtering.",
    h("div", { class: "card" }, rows,
      h("p", { class: "muted small" }, "None found? On Rocky/RHEL: dnf install clamd rspamd, then come back. On Windows, ClamAV can run in WSL or Docker on port 3310; you can set its address later in the admin console.")),
    navRow(h("button", { onclick: async (e) => {
      const ok = await busy(e.target, () => api("POST", "scanners", { clamav: boxes.clamav.checked, rspamd: boxes.rspamd.checked, spamassassin: boxes.spamassassin.checked }));
      if (ok) { sessionStorage.setItem("pw-spam-ok", "1"); next(); }
    } }, "Save and continue")));
}

// ---------------------------------------------------------------- 8 dns
async function dns() {
  const list = (await adm("GET", "domains")).filter((d) => !d.alias_of);
  const cards = [];
  for (const d of list) {
    const card = h("div", { class: "card" }, h("h3", {}, d.name), h("p", { class: "muted" }, "Checking…"));
    cards.push(card);
    adm("GET", `domains/${encodeURIComponent(d.name)}/dns`).then((r) => {
      const rows = r.records.map((x) => h("tr", {}, h("td", {}, x.type), h("td", {}, h("code", {}, x.name)),
        h("td", {}, h("div", { class: "copyrow" }, h("code", {}, x.expected), h("button", { class: "ghost", onclick: () => navigator.clipboard.writeText(x.expected).then(() => toast("Copied", true)) }, "Copy"))),
        h("td", {}, pill(x.status === "ok" ? "Published" : x.status === "different" ? "Different" : "Missing", x.status === "ok" ? "ok" : x.status === "different" ? "warn" : "err"))));
      card.replaceChildren(h("h3", {}, d.name), h("table", { class: "dns" }, h("tbody", {}, rows)));
    }).catch((e) => card.replaceChildren(h("h3", {}, d.name), h("p", {}, e.message)));
  }
  page("Publish the DNS records", "Add these at your DNS provider. MX is what moves mail to this server, so if you're migrating, you can leave it until the mail has been copied. Changes can take an hour to appear.",
    ...cards,
    h("div", { class: "card" }, h("p", {}, "Also check your firewall forwards ports 25, 465, 587, 993 and 443 to ", h("code", {}, S.local_ips[0] || "this machine"), ".")),
    navRow(h("button", { class: "ghost", onclick: () => dns() }, "Check again"), h("button", { onclick: () => { sessionStorage.setItem("pw-dns-ok", "1"); next(); } }, "Continue")));
}

// ----------------------------------------------------------- 9 migrate
async function migrateStep() {
  const box = h("div");
  page("Bring mail across", migrateFrom === "other"
      ? "Copy mail, calendars and contacts into the new accounts. It runs in the background: you can finish setup while it works, and follow it under Administration → Migration."
      : "Nothing to bring across? Skip this. You can migrate later from the admin console.", box,
    navRow(h("button", { onclick: () => { sessionStorage.setItem("pw-migrate-ok", "1"); next(); } }, migrateFrom === "other" ? "Continue" : "Skip")));
  mounted = window.PostwrightMigration(box, { api: (m, p, b) => api(m, "migrate/" + p, b), toast });
}

// ------------------------------------------------------------- 10 finish
async function finish() {
  const st = await api("GET", "migrate/status");
  const migrating = st.progress.running;
  const issues = [];
  if (!S.admins.length) issues.push("Create an administrator account (step 5).");
  if (!S.domains.length) issues.push("Add at least one domain (step 4).");
  const svcOut = h("div");
  let installed = false;
  const svcBtn = h("button", { class: "ghost", onclick: async (e) => {
    const r = await busy(e.target, () => api("POST", "service", {}));
    if (r) { installed = true; svcOut.replaceChildren(pill("Installed", "ok"), " ", r.how); startSvc.disabled = migrating; }
  } }, S.platform === "windows" ? "Start automatically with Windows" : "Install as a system service");
  const done = async (useService, btn) => {
    const r = await busy(btn, () => api("POST", "finish", { start_service: useService }));
    if (!r) return;
    ["pw-step", "pw-from", "pw-host-ok", "pw-cert-ok", "pw-spam-ok", "pw-dns-ok", "pw-migrate-ok", "pw-setup-code"].forEach((k) => sessionStorage.removeItem(k));
    main.replaceChildren(h("div", { class: "center" }, h("h2", {}, "Starting Postwright…"), h("p", { class: "lead" }, "You'll be taken to the sign-in page in a moment.")));
    document.getElementById("steps").replaceChildren();
    for (let i = 0; i < 60; i++) {
      await new Promise((res) => setTimeout(res, 2000));
      try { const p = await fetch("/login", { cache: "no-store" }); if (p.ok) { location.replace("/login?next=%2Fadmin"); return; } } catch (_) { /* restarting */ }
    }
    main.replaceChildren(h("div", { class: "center" }, h("h2", {}, "Postwright is running"), h("p", {}, "Sign in at ", h("a", { href: "/login?next=%2Fadmin" }, "/login"), ".")));
  };
  const startHere = h("button", { disabled: issues.length > 0, onclick: (e) => done(false, e.target) }, "Finish and start Postwright");
  const startSvc = h("button", { disabled: true, onclick: (e) => done(true, e.target) }, "Finish and start the service");
  page("Ready to go", "Postwright will start its mail services now.",
    issues.length ? h("div", { class: "card note" }, h("b", {}, "Before you finish:"), h("ul", {}, issues.map((i) => h("li", {}, i)))) : null,
    h("div", { class: "card" }, h("h3", {}, "Keep it running"),
      h("p", {}, S.platform === "windows"
        ? "Have Postwright start in the background whenever Windows starts, even when nobody is signed in. Needs Postwright to have been started with \"Run as administrator\"."
        : "Install Postwright as a systemd service so it starts at boot and restarts if it stops."),
      h("div", { class: "row" }, svcBtn, svcOut),
      migrating ? h("p", { class: "muted small" }, "A migration is running in this window, so the service will take over at the next restart instead of now.") : null),
    h("div", { class: "card" }, h("h3", {}, "After you finish"),
      h("ol", { class: "steps" },
        h("li", {}, "Sign in to the admin console with your administrator account."),
        h("li", {}, "Under My settings, turn on two-step verification."),
        h("li", {}, "Set up your mail app: server ", h("b", {}, S.hostname), ", IMAP 993 and SMTP 465, both SSL/TLS, with your full email address."),
        migrateFrom === "other" || migrateFrom === "iredmail" ? h("li", {}, "When the mail has been copied, change your MX records, then run the migration again to catch up.") : null)),
    navRow(startHere, startSvc));
  void installed;
}

// --------------------------------------------------------------------- go
function start() {
  const saved = +(sessionStorage.getItem("pw-step") || 0);
  go(saved);
}

if (!code) askCode();
else { sessionStorage.setItem("pw-setup-code", code); refresh().then(start).catch(() => {}); }
