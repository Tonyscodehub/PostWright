"use strict";
// Migration screens, shared by the admin console (Migration page) and the setup wizard.
// Everything is built with textContent; nothing from a server becomes markup.

window.PostwrightMigration = function mount(root, opt) {
  // opt.api(method, path, body) -> Promise<json>; opt.toast(msg, ok); opt.compact: bool
  const api = opt.api, toast = opt.toast || ((m) => alert(m));
  const h = (tag, attrs, ...kids) => {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "class") e.className = v;
      else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
      else if (v === true) e.setAttribute(k, "");
      else if (v !== false && v != null) e.setAttribute(k, v);
    }
    for (const k of kids.flat()) if (k != null && k !== false) e.append(k instanceof Node ? k : document.createTextNode(String(k)));
    return e;
  };
  const pill = (t, c) => h("span", { class: "pill " + c }, t);
  const field = (label, el, hint) => h("div", { class: "field" }, h("label", {}, label), el, hint ? h("div", { class: "muted small" }, hint) : null);
  const txt = (attrs) => h("input", { type: "text", ...attrs });
  const fmtBytes = (b) => { if (!b) return "0 B"; const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; while (b >= 1024 && i < 4) { b /= 1024; i++; } return (i ? b.toFixed(1) : b) + " " + u[i]; };
  let timer = null;

  const SOURCES = [
    { id: "exo", title: "Microsoft 365 / Exchange Online", sub: "All mailboxes at once: mail, calendars and contacts." },
    { id: "google", title: "Google Workspace", sub: "All users at once: Gmail, Calendar and Contacts." },
    { id: "exchange", title: "Exchange Server (on-premises)", sub: "Mail over IMAP using an administrator account." },
    { id: "imap", title: "Another mail server (IMAP)", sub: "cPanel, Plesk, Dovecot, Zimbra, Gmail, Yahoo, iCloud…" },
    { id: "files", title: "Exported files", sub: "Google Takeout, mbox, .ics calendars and .vcf contacts." },
  ];
  if (opt.iredmail) SOURCES.push({ id: "iredmail", title: "iRedMail", sub: "Everything, including passwords and DKIM keys." });

  const IMAP_PRESETS = {
    "": ["", 993, "tls", ""],
    gmail: ["imap.gmail.com", 993, "tls", "Each user needs 2-Step Verification on and an app password (myaccount.google.com/apppasswords)."],
    yahoo: ["imap.mail.yahoo.com", 993, "tls", "Each user needs an app password from Yahoo Account Security."],
    icloud: ["imap.mail.me.com", 993, "tls", "Each user needs an app-specific password from appleid.apple.com. The sign-in name is the part before @icloud.com."],
    fastmail: ["imap.fastmail.com", 993, "tls", "Each user needs an app password (Settings → Privacy & Security)."],
    zoho: ["imap.zoho.eu", 993, "tls", "Use imap.zoho.com for US accounts. App passwords are needed if 2FA is on."],
    ionos: ["imap.ionos.co.uk", 993, "tls", ""],
  };

  let state = { kind: null, discovered: [], source: null };

  async function render() {
    clearTimeout(timer);
    let st;
    try { st = await api("GET", "status"); } catch (e) { root.replaceChildren(h("div", { class: "card" }, e.message)); return; }
    const p = st.progress;
    if (p.running || p.finished) {
      showProgress(st);
      return;
    }
    chooser(st);
  }

  // ------------------------------------------------------------------ step 1
  function chooser(st) {
    const cards = SOURCES.map((s) => h("button", { class: "choice" + (state.kind === s.id ? " sel" : ""), onclick: () => { state.kind = s.id; state.discovered = []; chooser(st); } },
      h("b", {}, s.title), h("span", {}, s.sub)));
    const kids = [h("div", { class: "card" }, h("h3", {}, "Where is your mail now?"), h("div", { class: "choices" }, cards))];
    if (st.last_job && !state.kind) {
      kids.push(h("div", { class: "card" }, h("h3", {}, "Previous migration"),
        h("p", {}, `From ${describe(st.last_job)}: ${st.last_job.mailboxes.length} mailbox(es). Running it again copies only what's arrived since.`),
        h("div", { class: "row" },
          h("button", { onclick: () => run(() => api("POST", "rerun", {}), "Catch-up started") }, "Run again (catch up)"),
          h("button", { class: "ghost", onclick: () => run(() => api("POST", "forget", {}), "Saved sign-in details forgotten") }, "Forget saved sign-in details"))));
    }
    if (state.kind) kids.push(details());
    root.replaceChildren(...kids);
  }

  function describe(job) {
    const s = job.source;
    return s.kind === "exchange_online" ? `Exchange Online (${s.tenant})` : s.kind === "google" ? `Google Workspace (${s.admin_email})` : `IMAP server ${s.host}`;
  }

  async function run(fn, msg) {
    try { await fn(); if (msg) toast(msg, true); render(); } catch (e) { toast(e.message, false); }
  }

  // ------------------------------------------------------------------ step 2
  function details() {
    const k = state.kind;
    if (k === "iredmail") return h("div", { class: "card" }, h("h3", {}, "iRedMail"), h("p", {}, "Use the iRedMail importer: it brings passwords, aliases, DKIM keys, mail and calendars across."),
      opt.iredmail);
    if (k === "files") return filesForm();
    if (k === "exo") return exoForm();
    if (k === "google") return googleForm();
    return imapForm(k === "exchange");
  }

  function exoForm() {
    const tenant = txt({ placeholder: "contoso.onmicrosoft.com", size: 34 });
    const cid = txt({ placeholder: "00000000-0000-0000-0000-000000000000", size: 40 });
    const secret = h("input", { type: "password", size: 40, placeholder: "client secret value" });
    const go = h("button", { onclick: async () => {
      state.source = { kind: "exchange_online", tenant: tenant.value.trim(), client_id: cid.value.trim(), client_secret: secret.value };
      await discover(go);
    } }, "Connect and list mailboxes");
    return h("div", { class: "card" }, h("h3", {}, "Connect to Microsoft 365"),
      h("p", {}, "Postwright reads the mailboxes with an app registration, so nobody needs to give you their password. Create one (about 5 minutes):"),
      h("ol", { class: "steps" },
        h("li", {}, "Go to ", h("b", {}, "entra.microsoft.com"), " → Applications → App registrations → New registration. Name it \"Postwright migration\" and register it."),
        h("li", {}, "Copy the ", h("b", {}, "Application (client) ID"), " and your ", h("b", {}, "Directory (tenant) ID"), " (or use your onmicrosoft.com domain)."),
        h("li", {}, "API permissions → Add a permission → Microsoft Graph → ", h("b", {}, "Application permissions"), ": User.Read.All, Mail.Read, Calendars.Read, Contacts.Read. Then click ", h("b", {}, "Grant admin consent"), "."),
        h("li", {}, "Certificates & secrets → New client secret. Copy its ", h("b", {}, "Value"), " (not the ID)."),
        h("li", {}, "When you've finished migrating, delete the app registration.")),
      h("div", { class: "form" }, field("Tenant", tenant), field("Application (client) ID", cid), field("Client secret", secret)),
      h("div", { class: "row" }, go));
  }

  function googleForm() {
    const key = h("textarea", { placeholder: "{ \"type\": \"service_account\", ... }", rows: 5 });
    const file = h("input", { type: "file", accept: ".json,application/json", onchange: async () => { if (file.files.length) key.value = await file.files[0].text(); } });
    const admin = h("input", { type: "email", placeholder: "admin@yourcompany.com", size: 30 });
    const go = h("button", { onclick: async () => {
      state.source = { kind: "google", service_account: key.value, admin_email: admin.value.trim() };
      await discover(go);
    } }, "Connect and list users");
    return h("div", { class: "card" }, h("h3", {}, "Connect to Google Workspace"),
      h("p", {}, "Postwright reads the accounts with a service account, so nobody needs to give you their password. Set one up (about 10 minutes):"),
      h("ol", { class: "steps" },
        h("li", {}, "In ", h("b", {}, "console.cloud.google.com"), " create a project, then enable the Gmail API, Google Calendar API, People API and Admin SDK API."),
        h("li", {}, "IAM & Admin → Service accounts → Create. Open it → Keys → Add key → JSON. A file downloads."),
        h("li", {}, "Copy the service account's ", h("b", {}, "Unique ID"), " (client ID)."),
        h("li", {}, "In ", h("b", {}, "admin.google.com"), " → Security → Access and data control → API controls → Domain-wide delegation → Add new. Paste the client ID and these scopes:",
          h("pre", { class: "scopes" }, "https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/gmail.readonly,https://www.googleapis.com/auth/calendar.readonly,https://www.googleapis.com/auth/contacts.readonly")),
        h("li", {}, "When you've finished migrating, delete the key and the delegation.")),
      h("div", { class: "form" }, field("Service account key (JSON file)", h("div", {}, file, key)), field("A Workspace administrator's address", admin, "Used only to list the users.")),
      h("div", { class: "row" }, go));
  }

  function imapForm(exchange) {
    const host = txt({ placeholder: exchange ? "mail.yourcompany.com" : "imap.example.com", size: 30 });
    const port = h("input", { type: "number", value: 993, style: "width:90px" });
    const sec = h("select", {}, h("option", { value: "tls" }, "SSL/TLS (993)"), h("option", { value: "starttls" }, "STARTTLS (143)"));
    sec.addEventListener("change", () => { port.value = sec.value === "tls" ? 993 : 143; });
    const insecure = h("input", { type: "checkbox", checked: exchange });
    const note = h("div", { class: "muted small" });
    const preset = h("select", { onchange: () => { const p = IMAP_PRESETS[preset.value]; if (p[0]) host.value = p[0]; port.value = p[1]; sec.value = p[2]; note.textContent = p[3]; } },
      h("option", { value: "" }, "Other / my own server"), h("option", { value: "gmail" }, "Gmail (personal)"), h("option", { value: "yahoo" }, "Yahoo Mail"),
      h("option", { value: "icloud" }, "iCloud Mail"), h("option", { value: "fastmail" }, "Fastmail"), h("option", { value: "zoho" }, "Zoho Mail"), h("option", { value: "ionos" }, "IONOS"));
    const mode = h("select", {}, h("option", { value: "admin" }, "One administrator account for every mailbox"), h("option", { value: "own" }, "Each person's own password"));
    if (!exchange) mode.value = "own";
    const auser = txt({ placeholder: exchange ? "DOMAIN\\administrator or admin@company.com" : "admin", size: 30 });
    const apass = h("input", { type: "password", size: 24 });
    const astyle = h("select", {}, h("option", { value: "plain" }, "Exchange, Zimbra, Cyrus (SASL PLAIN)"), h("option", { value: "dovecot" }, "Dovecot master user (mailbox*admin)"));
    const adminBox = h("div", { class: "form" }, field("Administrator sign-in", auser), field("Password", apass), exchange ? null : field("Server type", astyle));
    const list = h("textarea", { rows: 6, placeholder: "" });
    const setPh = () => {
      list.placeholder = mode.value === "admin"
        ? "One mailbox per line, optionally with its new address:\namy@oldcompany.com\nbob@oldcompany.com, bob@newcompany.com"
        : "One per line: old sign-in, new address, password\namy@oldcompany.com, amy@newcompany.com, her-password";
      adminBox.style.display = mode.value === "admin" ? "" : "none";
    };
    mode.addEventListener("change", setPh); setPh();
    const csv = h("input", { type: "file", accept: ".csv,.txt", onchange: async () => { if (csv.files.length) list.value = await csv.files[0].text(); } });
    const domain = txt({ placeholder: "newcompany.com (optional)", size: 24 });
    const build = () => {
      const src = { kind: "imap", host: host.value.trim(), port: +port.value || 993, security: sec.value, insecure: insecure.checked };
      if (mode.value === "admin") src.admin = { user: auser.value.trim(), password: apass.value, style: exchange ? "plain" : astyle.value };
      state.source = src;
      state.discovered = parseList(list.value, domain.value.trim());
      return state.discovered.length;
    };
    const test = h("button", { class: "ghost", onclick: async () => {
      if (!build()) return toast("Enter at least one mailbox", false);
      test.disabled = true;
      try { const r = await api("POST", "test", { source: state.source, mailboxes: [state.discovered[0]], options: {} }); toast(r.message, true); }
      catch (e) { toast(e.message, false); }
      test.disabled = false;
    } }, "Test the first mailbox");
    const next = h("button", { onclick: () => { if (!build()) return toast("Enter at least one mailbox", false); pick(); } }, "Next");
    return h("div", { class: "card" }, h("h3", {}, exchange ? "Connect to Exchange Server" : "Connect to the old server"),
      exchange ? h("p", {}, "Make sure IMAP is running on the Exchange server (Services → Microsoft Exchange IMAP4 Backend, set to Automatic) and that the administrator account has Full Access to every mailbox, for example: ",
        h("code", {}, "Get-Mailbox | Add-MailboxPermission -User migrate-admin -AccessRights FullAccess -AutoMapping $false"), ". Calendars and contacts: export them from Outlook as .ics and .vcf files and import them with \"Exported files\".")
        : h("p", {}, "Copies every folder with read and flagged status. Calendars and contacts aren't available over IMAP: export them as .ics and .vcf files and use \"Exported files\"."),
      h("div", { class: "form" },
        exchange ? null : field("Provider", preset, null), exchange ? null : note,
        field("Server", h("div", { class: "row" }, host, sec, port)),
        field("", h("label", { class: "c" }, insecure, "Accept a self-signed certificate on the old server")),
        field("Sign in with", mode)),
      adminBox,
      h("div", { class: "form" }, field("Mailboxes", h("div", {}, list, h("div", { class: "row small" }, "or load a CSV file: ", csv)), null),
        field("New domain for names without one", domain)),
      h("div", { class: "row" }, test, next));
  }

  function parseList(text, domain) {
    return text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#") && !/^source\b/i.test(l)).map((l) => {
      const p = l.split(/[,;\t]/).map((x) => x.trim());
      let target = p[1] || p[0];
      if (!target.includes("@") && domain) target = target + "@" + domain;
      return { source: p[0], target: target.toLowerCase(), password: p[2] || null, name: null, exists_here: null, kind: "" };
    });
  }

  function filesForm() {
    const path = txt({ placeholder: "/root/takeout  or  C:\\Migration\\amy", size: 44 });
    const user = h("input", { type: "email", placeholder: "amy@yourcompany.com", size: 30 });
    const folder = txt({ placeholder: "(file name)", size: 20 });
    return h("div", { class: "card" }, h("h3", {}, "Import exported files"),
      h("p", {}, "Copy the files to this server first, then give the path to a file or a folder. Folders are searched for .mbox, .ics and .vcf files."),
      h("ul", {},
        h("li", {}, h("b", {}, "Google Takeout:"), " extract the zip; Gmail labels become folders and read/starred status is kept."),
        h("li", {}, h("b", {}, "Outlook:"), " File → Save Calendar (.ics), and People → Manage contacts → Export (.vcf)."),
        h("li", {}, h("b", {}, "Thunderbird / Apple Mail:"), " their folder files are mbox; each file becomes a folder of the same name.")),
      h("div", { class: "form" }, field("Path on this server", path), field("Into the account", user, "Created if it doesn't exist yet."), field("Folder for mbox files (optional)", folder)),
      h("div", { class: "row" }, h("button", { onclick: () => run(() => api("POST", "files", { path: path.value, target: user.value, folder: folder.value || null }), "Import started") }, "Start import")));
  }

  async function discover(btn) {
    btn.disabled = true;
    const was = btn.textContent;
    btn.textContent = "Connecting…";
    try {
      state.discovered = (await api("POST", "discover", { source: state.source })).map((d) => ({ ...d, use: d.kind === "user" }));
      pick();
    } catch (e) { toast(e.message, false); }
    btn.disabled = false;
    btn.textContent = was;
  }

  // ------------------------------------------------------------------ step 3
  function pick() {
    const rows = state.discovered.map((d) => {
      if (d.use === undefined) d.use = true;
      const cb = h("input", { type: "checkbox", checked: d.use, onchange: () => { d.use = cb.checked; } });
      const tgt = txt({ value: d.target, size: 30, onchange: () => { d.target = tgt.value.trim().toLowerCase(); } });
      return h("tr", {}, h("td", {}, cb), h("td", {}, h("div", {}, d.source), d.name ? h("div", { class: "muted small" }, d.name) : null),
        h("td", {}, tgt), h("td", {}, d.kind && d.kind !== "user" ? pill(d.kind, "warn") : "", d.exists_here ? pill("exists here", "info") : d.exists_here === false ? pill("will be created", "ok") : ""));
    });
    const all = (v) => { state.discovered.forEach((d) => (d.use = v)); pick(); };
    const domains = [...new Set(state.discovered.map((d) => d.target.split("@")[1]).filter(Boolean))];
    const rename = h("select", {}, h("option", { value: "" }, "Change domain…"), domains.map((d) => h("option", { value: d }, d)));
    const to = txt({ placeholder: "newdomain.com", size: 18 });
    const mail = h("input", { type: "checkbox", checked: true }), cal = h("input", { type: "checkbox", checked: state.kind !== "imap" && state.kind !== "exchange" });
    const con = h("input", { type: "checkbox", checked: state.kind !== "imap" && state.kind !== "exchange" });
    const create = h("input", { type: "checkbox", checked: true });
    const since = h("input", { type: "date" });
    const skip = txt({ placeholder: "e.g. Old Archive, Newsletters", size: 34 });
    const start = h("button", { onclick: () => {
      const mbs = state.discovered.filter((d) => d.use).map((d) => ({ source: d.source, target: d.target, password: d.password || null, name: d.name || null }));
      if (!mbs.length) return toast("Choose at least one mailbox", false);
      const options = { mail: mail.checked, calendars: cal.checked, contacts: con.checked, create_users: create.checked, since: since.value || null,
        skip_folders: skip.value.split(",").map((x) => x.trim()).filter(Boolean) };
      run(() => api("POST", "start", { source: state.source, mailboxes: mbs, options }), "Migration started");
    } }, `Start migrating`);
    const card = h("div", { class: "card" }, h("h3", {}, `Mailboxes (${state.discovered.length})`),
      h("div", { class: "row", style: "margin-bottom:8px" }, h("button", { class: "ghost", onclick: () => all(true) }, "All"), h("button", { class: "ghost", onclick: () => all(false) }, "None"),
        domains.length ? [rename, "→", to, h("button", { class: "ghost", onclick: () => {
          if (!rename.value || !to.value.trim()) return;
          state.discovered.forEach((d) => { if (d.target.endsWith("@" + rename.value)) d.target = d.target.split("@")[0] + "@" + to.value.trim().toLowerCase(); d.exists_here = null; });
          pick();
        } }, "Apply")] : null),
      h("div", { class: "scroll" }, h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, ""), h("th", {}, "On the old system"), h("th", {}, "New address here"), h("th", {}, ""))), h("tbody", {}, rows))));
    const opts = h("div", { class: "card" }, h("h3", {}, "What to copy"),
      h("div", { class: "row" }, h("label", { class: "c" }, mail, "Mail"), h("label", { class: "c" }, cal, "Calendars"), h("label", { class: "c" }, con, "Contacts"),
        h("label", { class: "c" }, create, "Create accounts that don't exist yet")),
      h("div", { class: "form" }, field("Only mail since (optional)", since), field("Leave these folders behind (optional)", skip)),
      h("p", { class: "muted small" }, "Nothing is changed or deleted on the old system. You can run this again later to copy only what's new, so it's fine to start now and catch up after switching your MX records."),
      h("div", { class: "row" }, h("button", { class: "ghost", onclick: () => { state.discovered = []; render(); } }, "Back"), start));
    root.replaceChildren(card, opts);
  }

  // ------------------------------------------------------------------ step 4
  const statePill = (s) => pill(s, s === "done" ? "ok" : s === "failed" ? "err" : s === "done with errors" ? "warn" : s === "running" ? "info" : "");

  function showProgress(st) {
    const p = st.progress;
    const tot = p.mailboxes.reduce((a, m) => ({ msg: a.msg + m.messages, ev: a.ev + m.events, ct: a.ct + m.contacts, b: a.b + m.bytes, e: a.e + m.errors, sk: a.sk + m.skipped }), { msg: 0, ev: 0, ct: 0, b: 0, e: 0, sk: 0 });
    const done = p.mailboxes.filter((m) => !["waiting", "running"].includes(m.state)).length;
    const head = h("div", { class: "card" },
      h("h3", {}, p.running ? `Migrating from ${p.source}…` : p.cancelled ? "Migration stopped" : "Migration finished"),
      h("div", { class: "stats" },
        stat(`${done} / ${p.mailboxes.length}`, "mailboxes"), stat(tot.msg.toLocaleString(), "messages"), stat(fmtBytes(tot.b), "copied"),
        stat(tot.ev.toLocaleString(), "calendar items"), stat(tot.ct.toLocaleString(), "contacts"), stat(tot.e.toLocaleString(), "errors")),
      tot.sk ? h("p", { class: "muted small" }, `${tot.sk.toLocaleString()} message(s) were already here from an earlier run and were skipped.`) : null,
      h("div", { class: "row" },
        p.running ? h("button", { class: "danger", onclick: () => run(() => api("POST", "cancel", {}), "Stopping after the current messages…") }, "Stop") : null,
        !p.running && st.last_job ? h("button", { onclick: () => run(() => api("POST", "rerun", {}), "Catch-up started") }, "Run again (catch up)") : null,
        !p.running ? h("button", { class: "ghost", onclick: () => { state = { kind: null, discovered: [], source: null }; chooser(st); } }, "New migration") : null,
        p.created.length ? h("button", { class: "ghost", onclick: downloadCsv }, `Download new passwords (${p.created.length})`) : null));
    const rows = p.mailboxes.map((m) => h("tr", {}, h("td", {}, h("div", {}, m.target), m.source !== m.target ? h("div", { class: "muted small" }, "from " + m.source) : null),
      h("td", {}, statePill(m.state), m.step ? h("div", { class: "muted small" }, m.step) : null),
      h("td", {}, m.messages.toLocaleString()), h("td", {}, fmtBytes(m.bytes)), h("td", {}, m.events.toLocaleString()), h("td", {}, m.contacts.toLocaleString()),
      h("td", {}, m.errors ? h("span", { title: m.last_error || "" }, pill(String(m.errors), "err"), h("div", { class: "muted small" }, m.last_error || "")) : "")));
    const table = h("div", { class: "card" }, h("div", { class: "scroll" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Account", "Status", "Messages", "Size", "Events", "Contacts", "Errors"].map((x) => h("th", {}, x)))), h("tbody", {}, rows))));
    const logCard = h("div", { class: "card" }, h("h3", {}, "Log"), h("pre", {}, p.log.slice(-200).join("\n")));
    const notes = !p.running && p.created.length ? h("div", { class: "card note" }, h("b", {}, "New accounts were created. "),
      "Download their passwords now: they're only kept until the server restarts. Give each person theirs, or set your own on the Users page.") : null;
    root.replaceChildren(head, notes || "", table, logCard);
    if (p.running) timer = setTimeout(render, 2000);
    if (opt.onProgress) opt.onProgress(p);
  }

  const stat = (n, l) => h("div", { class: "stat" }, h("div", { class: "n" }, n), h("div", { class: "l" }, l));

  async function downloadCsv() {
    try {
      const csv = await api("GET", "created.csv");
      const a = h("a", { href: URL.createObjectURL(new Blob([csv], { type: "text/csv" })), download: "postwright-new-passwords.csv" });
      document.body.append(a); a.click(); a.remove();
    } catch (e) { toast(e.message, false); }
  }

  render();
  return { stop: () => clearTimeout(timer), refresh: render };
};
