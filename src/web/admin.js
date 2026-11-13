"use strict";
// Postwright admin console. Builds all content with textContent, never innerHTML,
// so nothing from the server can inject markup.

const main = document.getElementById("main");
let timer = null;

async function api(method, path, body) {
  const opts = { method, headers: { "X-Requested-With": "postwright" }, credentials: "same-origin" };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const r = await fetch("/api/v1/admin/" + path, opts);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (v === true) e.setAttribute(k, "");
    else if (v !== false && v != null) e.setAttribute(k, v);
  }
  for (const k of kids.flat()) {
    if (k == null || k === false) continue;
    e.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return e;
}

function toast(msg, ok = true) {
  const t = h("div", { class: "toast " + (ok ? "ok" : "err") }, msg);
  document.body.append(t);
  setTimeout(() => t.remove(), ok ? 2500 : 6000);
}

async function act(fn, okMsg) {
  try { await fn(); if (okMsg) toast(okMsg); route(); }
  catch (e) { toast(e.message, false); }
}

const fmtBytes = (b) => {
  if (!b) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return (i ? b.toFixed(1) : b) + " " + u[i];
};
const fmtTime = (t) => t ? new Date(t * 1000).toLocaleString() : "";
const fmtUptime = (s) => {
  const d = Math.floor(s / 86400), hh = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${d}d ${hh}h` : hh ? `${hh}h ${m}m` : `${m}m`;
};
const pill = (text, cls) => h("span", { class: "pill " + cls }, text);
const input = (attrs) => h("input", { type: "text", ...attrs });
const page = (title, sub, ...content) => { main.replaceChildren(h("h2", {}, title), h("p", { class: "sub" }, sub), ...content); };

// ------------------------------------------------------------------ overview
async function overview() {
  const o = await api("GET", "overview");
  document.getElementById("host").textContent = o.hostname;
  document.getElementById("ver").textContent = "v" + o.version;
  const c = o.counts;
  const stat = (n, l) => h("div", { class: "stat" }, h("div", { class: "n" }, n), h("div", { class: "l" }, l));
  const scanners = o.scanners.length
    ? o.scanners.map((s) => h("tr", {}, h("td", {}, s.name), h("td", {}, h("code", {}, s.address)),
        h("td", {}, pill(s.ok ? "Responding" : "Down", s.ok ? "ok" : "err"), s.ok ? "" : h("span", { class: "muted" }, s.detail))))
    : [h("tr", {}, h("td", { colspan: 3, class: "muted" }, "No ClamAV, Rspamd or SpamAssassin configured. Built-in checks are " + (o.filter_enabled ? "on." : "off.")))];
  const dns = o.server_dns;
  page("Overview", `Up ${fmtUptime(o.uptime_secs)}`,
    h("div", { class: "stats" },
      stat(c.users, "Users"), stat(c.domains + (c.alias_domains ? ` +${c.alias_domains}` : ""), "Domains"),
      stat(c.aliases, "Aliases"), stat(c.messages.toLocaleString(), "Messages"),
      stat(fmtBytes(c.unique_bytes), "Storage used"), stat(c.queue, "In outbound queue"),
      stat(c.calendars, "Calendars"), stat(o.recent_warnings, "Recent warnings")),
    h("div", { class: "card" }, h("h3", {}, "Server identity"),
      h("table", {},
        h("tr", {}, h("td", {}, "Host name"), h("td", {}, h("code", {}, o.hostname))),
        h("tr", {}, h("td", {}, "Addresses"), h("td", {}, dns.addresses.length ? dns.addresses.join(", ") : pill("No A/AAAA record", "err"))),
        h("tr", {}, h("td", {}, "Reverse DNS"), h("td", {}, pill(dns.ptr_matches ? "Matches host name" : "Doesn't match", dns.ptr_matches ? "ok" : "warn"), " ", h("span", { class: "muted" }, dns.ptr.join(", ")))),
        h("tr", {}, h("td", {}, "TLS certificate"), h("td", {}, o.certificate
          ? [pill(`${o.certificate.days_left} days left`, o.certificate.days_left < 14 ? "err" : o.certificate.days_left < 30 ? "warn" : "ok"), " ", h("a", { href: "#certificate" }, o.certificate.names.join(", "))]
          : pill("Unreadable", "err"))))),
    h("div", { class: "card" }, h("h3", {}, "Scanners"), h("table", {}, scanners)),
    c.queue_failing ? h("div", { class: "card" }, pill(`${c.queue_failing} message(s) retrying`, "warn"), " ", h("a", { href: "#queue" }, "View queue")) : "");
}

// ------------------------------------------------------------------- domains
async function domains() {
  const list = await api("GET", "domains");
  const rows = [];
  for (const d of list) {
    const tr = h("tr", {},
      h("td", {}, h("b", {}, d.name)),
      h("td", {}, d.alias_of ? pill("Alias of " + d.alias_of, "info") : pill("Domain", "ok")),
      h("td", {}, d.users), h("td", {}, d.aliases),
      h("td", {}, d.has_dkim ? h("code", {}, d.dkim_selector) : h("span", { class: "muted" }, "none")),
      h("td", {}, d.catch_all || h("span", { class: "muted" }, "–")),
      h("td", { style: "text-align:right;white-space:nowrap" },
        h("button", { class: "ghost", onclick: () => showDns(d.name, tr) }, "Check DNS"), " ",
        d.alias_of ? "" : h("button", { class: "ghost", onclick: () => {
          const t = prompt(`Catch-all address for ${d.name} (blank to turn off):`, d.catch_all || "");
          if (t !== null) act(() => api("PUT", "domains/" + encodeURIComponent(d.name), { catch_all: t }), "Catch-all updated");
        } }, "Catch-all"), " ",
        h("button", { class: "danger", onclick: () => confirm(`Remove ${d.name}? It must have no users left.`) &&
          act(() => api("DELETE", "domains/" + encodeURIComponent(d.name)), "Domain removed") }, "Remove")));
    rows.push(tr);
  }
  const name = input({ placeholder: "example.com", class: "grow" });
  const sel = input({ placeholder: "pw1", size: 6 });
  const alias = input({ placeholder: "example.net", class: "grow" });
  const target = h("select", {}, list.filter((d) => !d.alias_of).map((d) => h("option", {}, d.name)));
  page("Domains", "Each domain gets its own DKIM key. Check DNS shows what to publish and what's live.",
    h("div", { class: "card" }, h("table", {},
      h("tr", {}, ["Domain", "Type", "Users", "Aliases", "DKIM selector", "Catch-all", ""].map((x) => h("th", {}, x))),
      rows.length ? rows : h("tr", {}, h("td", { colspan: 7, class: "muted" }, "No domains yet.")))),
    h("div", { class: "card" }, h("h3", {}, "Add a domain"),
      h("div", { class: "row" }, name, h("span", { class: "muted" }, "DKIM selector"), sel,
        h("button", { onclick: () => act(() => api("POST", "domains", { name: name.value, selector: sel.value }), "Domain added; now publish its DNS records") }, "Add domain"))),
    h("div", { class: "card" }, h("h3", {}, "Add an alias domain"),
      h("p", { class: "muted" }, "Mail to anyone@alias goes to the same mailbox at the target domain."),
      h("div", { class: "row" }, alias, h("span", {}, "→"), target,
        h("button", { onclick: () => act(() => api("POST", "domains/alias", { alias: alias.value, target: target.value }), "Alias domain added") }, "Add alias domain"))));
}

async function showDns(name, tr) {
  if (tr.nextSibling && tr.nextSibling.classList && tr.nextSibling.classList.contains("edit")) { tr.nextSibling.remove(); return; }
  const cell = h("td", { colspan: 7 }, h("span", { class: "muted" }, "Checking DNS…"));
  const row = h("tr", { class: "edit dns" }, cell);
  tr.after(row);
  try {
    const d = await api("GET", "domains/" + encodeURIComponent(name) + "/dns");
    const cls = { ok: "ok", missing: "err", different: "warn" };
    const label = { ok: "Live", missing: "Missing", different: "Different" };
    cell.replaceChildren(h("table", {},
      h("tr", {}, ["Type", "Name", "Publish this", "Currently", ""].map((x) => h("th", {}, x))),
      d.records.map((r) => h("tr", {},
        h("td", {}, r.type), h("td", {}, h("code", {}, r.name)),
        h("td", {}, h("code", {}, r.expected)),
        h("td", {}, r.found ? h("code", {}, r.found) : h("span", { class: "muted" }, "nothing")),
        h("td", { style: "white-space:nowrap" }, pill(label[r.status], cls[r.status]), " ",
          h("button", { class: "ghost", onclick: () => navigator.clipboard.writeText(r.expected).then(() => toast("Copied")) }, "Copy"))))));
  } catch (e) { cell.replaceChildren(pill(e.message, "err")); }
}

// --------------------------------------------------------------------- users
async function users() {
  const [list, doms] = await Promise.all([api("GET", "users"), api("GET", "domains")]);
  const search = input({ placeholder: "Search users", class: "grow" });
  const tbody = h("tbody");
  const draw = () => {
    const q = search.value.toLowerCase();
    tbody.replaceChildren(...list.filter((u) => !q || u.email.includes(q) || u.addresses.some((a) => a.includes(q))).map((u) => {
      const pct = u.quota_bytes ? Math.min(100, (u.used_bytes / u.quota_bytes) * 100) : 0;
      const tr = h("tr", {},
        h("td", {}, h("b", {}, u.email), u.addresses.length ? h("div", { class: "muted" }, "also " + u.addresses.join(", ")) : "",
          u.forwards_to.length ? h("div", { class: "muted" }, "forwards to " + u.forwards_to.join(", ")) : ""),
        h("td", { style: "white-space:nowrap" }, u.quota_bytes ? h("span", { class: "bar" }, h("span", { class: pct > 90 ? "full" : "", style: `width:${pct}%` })) : "",
          fmtBytes(u.used_bytes), " / ", u.quota_bytes ? fmtBytes(u.quota_bytes) : "unlimited"),
        h("td", {}, u.enabled ? pill("Active", "ok") : pill("Disabled", "err"), u.admin ? pill("Admin", "info") : "",
          u.out_of_office ? pill("Out of office", "warn") : "", u.legacy_password ? pill("Imported password", "info") : ""),
        h("td", { style: "text-align:right;white-space:nowrap" },
          h("button", { class: "ghost", onclick: () => editUser(u, tr) }, "Edit"), " ",
          h("button", { class: "danger", onclick: () => confirm(`Delete ${u.email} and ALL their mail and calendars? This can't be undone.`) &&
            act(() => api("DELETE", "users/" + encodeURIComponent(u.email)), "User deleted") }, "Delete")));
      return tr;
    }));
  };
  search.addEventListener("input", draw);
  draw();
  const local = input({ placeholder: "name", size: 14 });
  const dom = h("select", {}, doms.filter((d) => !d.alias_of).map((d) => h("option", {}, d.name)));
  const pw = h("input", { type: "password", placeholder: "Password (10+ characters)", autocomplete: "new-password" });
  const quota = h("input", { type: "number", min: 0, placeholder: "Quota MB", title: "0 = unlimited" });
  const admin = h("input", { type: "checkbox" });
  page("Users", `${list.length} mailbox${list.length === 1 ? "" : "es"}`,
    h("div", { class: "card" }, h("div", { class: "row", style: "margin-bottom:8px" }, search),
      h("table", {}, h("thead", {}, h("tr", {}, ["User", "Storage", "Status", ""].map((x) => h("th", {}, x)))), tbody)),
    h("div", { class: "card" }, h("h3", {}, "Add a user"),
      doms.length ? h("div", { class: "row" }, local, "@", dom, pw, quota, h("label", { class: "c" }, admin, "Administrator"),
        h("button", { onclick: () => act(() => api("POST", "users", { email: `${local.value}@${dom.value}`, password: pw.value, quota_mb: +quota.value || 0, admin: admin.checked }), "User created") }, "Add user"))
        : h("p", { class: "muted" }, "Add a domain first.")));
}

function editUser(u, tr) {
  if (tr.nextSibling && tr.nextSibling.classList && tr.nextSibling.classList.contains("edit")) { tr.nextSibling.remove(); return; }
  const quota = h("input", { type: "number", min: 0, value: Math.round(u.quota_bytes / 1048576) });
  const pw = h("input", { type: "password", placeholder: "New password (leave blank to keep)", autocomplete: "new-password", size: 30 });
  const en = h("input", { type: "checkbox", checked: u.enabled });
  const ad = h("input", { type: "checkbox", checked: u.admin });
  tr.after(h("tr", { class: "edit" }, h("td", { colspan: 4 }, h("div", { class: "row" },
    h("span", {}, "Quota MB (0 = unlimited)"), quota, pw,
    h("label", { class: "c" }, en, "Enabled"), h("label", { class: "c" }, ad, "Administrator"),
    h("button", { onclick: () => act(() => api("PUT", "users/" + encodeURIComponent(u.email), { quota_mb: +quota.value || 0, password: pw.value || null, enabled: en.checked, admin: ad.checked }), "Saved") }, "Save")))));
}

// ------------------------------------------------------------------- aliases
async function aliases() {
  const list = await api("GET", "aliases");
  const search = input({ placeholder: "Search aliases", class: "grow" });
  const tbody = h("tbody");
  const draw = () => {
    const q = search.value.toLowerCase();
    tbody.replaceChildren(...list.filter((a) => !q || a.source.includes(q) || a.target.includes(q)).map((a) =>
      h("tr", {}, h("td", {}, a.source === a.target ? h("span", {}, a.source, " ", pill("keeps a copy", "info")) : a.source),
        h("td", {}, "→ ", a.target),
        h("td", { style: "text-align:right" }, h("button", { class: "danger", onclick: () =>
          act(() => api("DELETE", "aliases/" + encodeURIComponent(a.source) + "/" + encodeURIComponent(a.target)), "Alias removed") }, "Remove")))));
  };
  search.addEventListener("input", draw);
  draw();
  const src = input({ placeholder: "sales@example.com", class: "grow" });
  const dst = input({ placeholder: "tony@example.com or an external address", class: "grow" });
  page("Aliases", "Addresses that deliver to mailboxes or forward elsewhere. One address can go to several targets.",
    h("div", { class: "card" }, h("div", { class: "row", style: "margin-bottom:8px" }, search),
      h("table", {}, h("thead", {}, h("tr", {}, ["Address", "Delivers to", ""].map((x) => h("th", {}, x)))), tbody)),
    h("div", { class: "card" }, h("h3", {}, "Add an alias"),
      h("div", { class: "row" }, src, "→", dst, h("button", { onclick: () => act(() => api("POST", "aliases", { source: src.value, target: dst.value }), "Alias added") }, "Add"))));
}

// --------------------------------------------------------------------- queue
async function queue() {
  const list = await api("GET", "queue");
  page("Mail queue", list.length ? `${list.length} message(s) waiting for delivery` : "Nothing waiting – all outbound mail has been delivered.",
    h("div", { class: "row", style: "margin-bottom:12px" },
      h("button", { onclick: () => act(() => api("POST", "queue/flush", {}), "Retrying now"), disabled: !list.length }, "Retry all now")),
    list.length ? h("div", { class: "card" }, h("table", {},
      h("tr", {}, ["From", "To", "Attempts", "Next try", "Last error", ""].map((x) => h("th", {}, x))),
      list.map((q) => h("tr", {}, h("td", {}, q.from || h("span", { class: "muted" }, "<> (bounce)")),
        h("td", {}, q.recipients.join(", ")), h("td", {}, q.attempts), h("td", {}, fmtTime(q.next_attempt)),
        h("td", { class: "muted" }, q.last_error || ""),
        h("td", {}, h("button", { class: "danger", onclick: () => confirm("Delete this message without delivering it?") &&
          act(() => api("DELETE", "queue/" + q.id), "Deleted") }, "Delete")))))) : "");
}

// ------------------------------------------------------------------- filters
async function filters() {
  const f = await api("GET", "filters");
  page("Spam & antivirus", f.enabled ? "Filtering is on." : "Filtering is off (filter.enabled = false).",
    h("div", { class: "stats" },
      h("div", { class: "stat" }, h("div", { class: "n" }, f.junk_score), h("div", { class: "l" }, "Junk folder at score")),
      h("div", { class: "stat" }, h("div", { class: "n" }, f.reject_score), h("div", { class: "l" }, "Reject at score")),
      h("div", { class: "stat" }, h("div", { class: "n" }, f.greet_pause_ms + " ms"), h("div", { class: "l" }, "Greeting pause")),
      h("div", { class: "stat" }, h("div", { class: "n" }, f.scan_outbound ? "Yes" : "No"), h("div", { class: "l" }, "Scan outgoing mail"))),
    h("div", { class: "card" }, h("h3", {}, "Scanners"),
      f.scanners.length ? h("table", {}, f.scanners.map((s) => h("tr", {}, h("td", {}, s.name), h("td", {}, h("code", {}, s.address)),
        h("td", {}, pill(s.ok ? "Responding" : "Down", s.ok ? "ok" : "err"), " ", h("span", { class: "muted" }, s.ok ? "" : s.detail)))))
        : h("p", { class: "muted" }, "No plugins configured. Add [filter.clamav], [filter.rspamd] or [filter.spamassassin] to postwright.toml.")),
    h("div", { class: "card" }, h("h3", {}, "DNS blocklists"),
      h("table", {}, f.dnsbl.map((d) => h("tr", {}, h("td", {}, h("code", {}, d.zone)), h("td", {}, "+" + d.score))))),
    h("p", { class: "muted" }, "These settings live in postwright.toml; restart the server after changing them."));
}

// --------------------------------------------------------------- certificate
async function certificate() {
  const d = await api("GET", "certs");
  const c = d.current, rv = d.receiver;
  const days = c ? c.days_left : 0;
  const expiry = c ? pill(`${days} days left`, days < 14 ? "err" : days < 30 ? "warn" : "ok") : "";
  const copyBtn = (text) => h("button", { class: "ghost", onclick: () => navigator.clipboard.writeText(text).then(() => toast("Copied")) }, "Copy");
  const keyBox = h("textarea", { placeholder: 'Paste OPNsense\'s identity here, e.g.  from="192.168.1.1",restrict ssh-rsa AAAA… root@OPNsense' });
  const chain = h("textarea", { placeholder: "-----BEGIN CERTIFICATE-----  (full chain: certificate then intermediates)" });
  const key = h("textarea", { placeholder: "-----BEGIN PRIVATE KEY-----" });
  const port = rv.listen.length ? rv.listen[0].split(":").pop() : "";
  page("Certificate", "Renewed certificates are picked up automatically: pushed by OPNsense, or copied into place any other way.",
    h("div", { class: "card" }, h("h3", {}, "Current certificate"),
      c ? h("table", { class: "kv" },
        h("tr", {}, h("td", {}, "Names"), h("td", {}, c.names.join(", "), " ", c.covers_hostname ? pill("Covers " + d.hostname, "ok") : pill("Doesn't cover " + d.hostname, "err"))),
        h("tr", {}, h("td", {}, "Issued by"), h("td", {}, c.issuer, " ", c.self_signed ? pill("Self-signed", "warn") : "")),
        h("tr", {}, h("td", {}, "Expires"), h("td", {}, fmtTime(c.not_after), " ", expiry)),
        h("tr", {}, h("td", {}, "SHA-256"), h("td", {}, h("code", {}, c.sha256))),
        d.last_install ? h("tr", {}, h("td", {}, "Last installed"), h("td", {}, fmtTime(d.last_install.at), " – ", d.last_install.source)) : "")
        : pill(d.error || "No certificate", "err")),
    h("div", { class: "card" }, h("h3", {}, "Push renewals from OPNsense"),
      rv.listen.length ? [
        h("p", { class: "muted" }, "Postwright has a built-in, upload-only SFTP receiver, so OPNsense's ACME client can deliver renewals directly – no SSH server needed, on Windows or Linux."),
        h("ol", { class: "steps" },
          h("li", {}, "In OPNsense go to ", h("b", {}, "Services › ACME Client › Automations"), " and add one with ", h("b", {}, "Run Command: Upload certificate via SFTP"), "."),
          h("li", {}, "Fill in: ", h("table", { class: "kv" },
            h("tr", {}, h("td", {}, "Host"), h("td", {}, h("code", {}, "this server's LAN address (or " + d.hostname + ")"))),
            h("tr", {}, h("td", {}, "Port"), h("td", {}, h("code", {}, port), " ", copyBtn(port))),
            h("tr", {}, h("td", {}, "Username"), h("td", {}, h("code", {}, rv.user), " ", copyBtn(rv.user))),
            h("tr", {}, h("td", {}, "Remote path"), h("td", {}, h("span", { class: "muted" }, "anything (leave blank)"))),
            h("tr", {}, h("td", {}, "Identity type"), h("td", {}, h("span", { class: "muted" }, "any (ed25519 or RSA)"))))),
          h("li", {}, "Click ", h("b", {}, "Show identity"), " in OPNsense, copy the key it shows, and paste it below."),
          h("li", {}, "Click ", h("b", {}, "Test Connect"), ". When OPNsense records the host key, it should match: ", h("code", {}, rv.host_key_fingerprint), " ", copyBtn(rv.host_key)),
          h("li", {}, "Attach the automation to your certificate under ", h("b", {}, "Certificates"), ", then use ", h("b", {}, "Run automations"), " once to test."))
      ] : h("p", {}, pill("Receiver disabled", "warn"), " Set [certs] sftp_listen in postwright.toml to enable it.")),
    h("div", { class: "card" }, h("h3", {}, "Keys allowed to push certificates"),
      d.keys.length ? h("table", {}, d.keys.map((k) => h("tr", {}, h("td", {}, h("code", {}, k.fingerprint)), h("td", {}, k.algorithm), h("td", {}, k.comment),
        h("td", { class: "muted" }, fmtTime(k.added)),
        h("td", { style: "text-align:right" }, h("button", { class: "danger", onclick: () => confirm("Stop this key pushing certificates?") &&
          act(() => api("DELETE", "certs/keys?fp=" + encodeURIComponent(k.fingerprint)), "Key removed") }, "Remove")))))
        : h("p", { class: "muted" }, "None yet."),
      keyBox, h("div", { class: "row", style: "margin-top:8px" }, h("button", { onclick: () => act(() => api("POST", "certs/keys", { key: keyBox.value }), "Key allowed") }, "Allow this key"))),
    h("div", { class: "card" }, h("h3", {}, "Install a certificate by hand"),
      h("p", { class: "muted" }, "Checked before use: the key must match, it must not be expired" + (d.require_hostname_match ? ", and it must cover " + d.hostname : "") + "."),
      h("div", { class: "row" }, h("div", { class: "grow" }, h("b", {}, "Full chain"), chain), h("div", { class: "grow" }, h("b", {}, "Private key"), key)),
      h("div", { class: "row", style: "margin-top:8px" }, h("button", { onclick: () => act(() => api("POST", "certs/upload", { fullchain: chain.value, key: key.value }), "Certificate installed") }, "Install"))));
}

// -------------------------------------------------------------------- import
async function importPage() {
  const st = await api("GET", "import");
  const dry = h("input", { type: "checkbox", checked: !st.finished || !st.ok });
  const noMail = h("input", { type: "checkbox" });
  const noCal = h("input", { type: "checkbox" });
  const user = input({ placeholder: "only this user (optional)", size: 28 });
  const backend = h("select", {}, h("option", { value: "" }, "Detect automatically"), h("option", { value: "mysql" }, "MariaDB / MySQL"),
    h("option", { value: "pgsql" }, "PostgreSQL"), h("option", { value: "ldap" }, "OpenLDAP"));
  const out = h("pre", {}, st.output.length ? st.output.join("\n") : "No import has run yet.");
  const status = st.running ? pill("Running…", "warn") : st.finished ? (st.ok ? pill("Finished", "ok") : pill("Failed: " + (st.error || ""), "err")) : "";
  page("Import from iRedMail", "Runs on this server, so Postwright must be installed on the iRedMail machine (as root). Safe to run more than once.",
    h("div", { class: "card" },
      h("div", { class: "row" }, h("label", { class: "c" }, dry, "Dry run (just show what would be imported)"),
        h("label", { class: "c" }, noMail, "Accounts only (skip mail)"), h("label", { class: "c" }, noCal, "Skip calendars")),
      h("div", { class: "row", style: "margin-top:10px" }, backend, user,
        h("button", { disabled: st.running, onclick: () => {
          if (!dry.checked && !confirm("Run the real import now?")) return;
          act(() => api("POST", "import/iredmail", { dry_run: dry.checked, no_mail: noMail.checked, no_calendars: noCal.checked, user: user.value, backend: backend.value }), "Import started");
        } }, "Start"), status)),
    h("div", { class: "card" }, h("h3", {}, "Output"), out));
  if (st.running) timer = setTimeout(route, 2000);
}

// ---------------------------------------------------------------------- logs
async function logs() {
  const q = input({ placeholder: "Filter, e.g. WARN or an address", class: "grow", value: sessionStorage.getItem("logq") || "" });
  const live = h("input", { type: "checkbox", checked: sessionStorage.getItem("loglive") !== "0" });
  const pre = h("pre", {}, "Loading…");
  const load = async () => {
    try {
      const d = await api("GET", "logs?n=500&q=" + encodeURIComponent(q.value));
      const atBottom = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 20;
      pre.textContent = d.lines.length ? d.lines.join("\n") : "Nothing matches.";
      if (atBottom) pre.scrollTop = pre.scrollHeight;
    } catch (e) { pre.textContent = e.message; }
    if (live.checked && location.hash === "#logs") timer = setTimeout(load, 3000);
  };
  q.addEventListener("change", () => { sessionStorage.setItem("logq", q.value); clearTimeout(timer); load(); });
  live.addEventListener("change", () => { sessionStorage.setItem("loglive", live.checked ? "1" : "0"); clearTimeout(timer); load(); });
  page("Logs", "The most recent 2,000 lines are kept in memory.", h("div", { class: "row", style: "margin-bottom:10px" }, q, h("label", { class: "c" }, live, "Live")), pre);
  await load();
  pre.scrollTop = pre.scrollHeight;
}

// -------------------------------------------------------------------- router
const pages = { overview, domains, users, aliases, queue, filters, certificate, import: importPage, logs };
async function route() {
  clearTimeout(timer);
  const name = (location.hash || "#overview").slice(1);
  document.querySelectorAll("nav a[href^='#']").forEach((a) => a.classList.toggle("active", a.getAttribute("href") === "#" + name));
  try { await (pages[name] || overview)(); }
  catch (e) { page("Something went wrong", e.message); }
}
window.addEventListener("hashchange", route);
api("GET", "overview").then((o) => {
  document.getElementById("host").textContent = o.hostname;
  document.getElementById("ver").textContent = "v" + o.version;
}).catch(() => {});
route();
