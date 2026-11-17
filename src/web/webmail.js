"use strict";
// Postwright webmail: mail, calendar and contacts. No frameworks; talks to /api/v1.

const $ = (id) => document.getElementById(id);
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "style" && typeof v === "object") Object.assign(el.style, v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat()) if (k !== null && k !== undefined && k !== false) el.append(k instanceof Node ? k : String(k));
  return el;
}

async function call(method, path, body) {
  const opts = { method, headers: { "X-Requested-With": "postwright" }, credentials: "same-origin" };
  if (body !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
  const r = await fetch("/api/v1/" + path, opts);
  if (r.status === 401) { location.replace("/login?next=" + encodeURIComponent(location.pathname + location.hash)); throw new Error("signed out"); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}
const qs = (o) => Object.entries(o).filter(([, v]) => v !== undefined && v !== null && v !== "").map(([k, v]) => encodeURIComponent(k) + "=" + encodeURIComponent(v)).join("&");

let toastTimer;
function toast(msg, opts = {}) {
  const t = $("toast");
  t.replaceChildren(h("span", {}, msg));
  if (opts.action) t.append(h("button", { onclick: () => { t.classList.add("hidden"); opts.action.run(); } }, opts.action.label));
  t.className = opts.err ? "err" : "";
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add("hidden"), opts.err ? 7000 : 4500);
}
const fail = (e) => toast(e.message || String(e), { err: true });

const TZ = Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
const LOCALE = navigator.language || "en-GB";
const fmtTime = (d) => d.toLocaleTimeString(LOCALE, { hour: "2-digit", minute: "2-digit" });
function shortDate(ts) {
  const d = new Date(ts * 1000), now = new Date();
  if (d.toDateString() === now.toDateString()) return fmtTime(d);
  const diff = (now - d) / 86400000;
  if (diff < 6 && diff > 0) return d.toLocaleDateString(LOCALE, { weekday: "short" }) + " " + fmtTime(d);
  if (d.getFullYear() === now.getFullYear()) return d.toLocaleDateString(LOCALE, { day: "numeric", month: "short" });
  return d.toLocaleDateString(LOCALE, { day: "numeric", month: "short", year: "numeric" });
}
const longDate = (ts) => new Date(ts * 1000).toLocaleString(LOCALE, { weekday: "short", day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
const size = (n) => n < 1024 ? n + " B" : n < 1048576 ? Math.round(n / 1024) + " KB" : (n / 1048576).toFixed(1) + " MB";
const initials = (s) => (s || "?").replace(/[^\p{L}\p{N} ]/gu, "").split(/\s+/).filter(Boolean).slice(0, 2).map((w) => w[0]).join("").toUpperCase() || "?";
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const fmtAddr = (a) => a.name ? `${a.name} <${a.email}>` : a.email;

let me = null;
let ids = null;

// ===================================================================== app shell

const state = { app: "mail" };
function show(app) {
  state.app = app;
  for (const b of document.querySelectorAll("#apps button")) b.classList.toggle("on", b.dataset.app === app);
  for (const v of ["mail", "cal", "contacts"]) $("v-" + v).classList.toggle("hidden", v !== app);
  $("search").classList.toggle("hidden", app === "cal");
  $("q").placeholder = app === "contacts" ? "Search contacts" : "Search mail";
  $("q").value = app === "mail" ? mail.search : contactsState.search;
  document.body.classList.remove("reading", "side-open");
  if (location.hash.slice(1).split("/")[0] !== app) history.replaceState(null, "", "#" + app);
  if (app === "cal") calendar.render();
  if (app === "contacts") contacts.load();
}
for (const b of document.querySelectorAll("#apps button")) b.onclick = () => show(b.dataset.app);
$("hamb").onclick = () => document.body.classList.toggle("side-open");
$("me-btn").onclick = (e) => { e.stopPropagation(); $("me-menu").classList.toggle("hidden"); };
document.addEventListener("click", () => $("me-menu").classList.add("hidden"));
$("signout").onclick = async () => { await fetch("/api/v1/logout", { method: "POST", credentials: "same-origin" }); location.replace("/login"); };
$("search").onsubmit = (e) => {
  e.preventDefault();
  if (state.app === "mail") { mail.search = $("q").value.trim(); mail.page = 0; mail.loadList(); }
  else { contactsState.search = $("q").value.trim(); contacts.renderList(); }
};
$("q").oninput = () => { if (state.app === "contacts") { contactsState.search = $("q").value.trim(); contacts.renderList(); } };

// ========================================================================== mail

const ICON = { inbox: "📥", sent: "📤", drafts: "📝", trash: "🗑", junk: "⚠", archive: "🗄" };
const ORDER = ["inbox", "drafts", "sent", "archive", "junk", "trash"];

const mail = {
  folders: [], folder: "INBOX", list: [], total: 0, page: 0, search: "", unread: false,
  selected: new Set(), current: null, allowImages: new Set(),

  special(name) { return (this.folders.find((f) => f.name === name) || {}).special; },
  bySpecial(s) { return (this.folders.find((f) => f.special === s) || {}).name; },
  label(f) {
    if (f.special) return { inbox: "Inbox", sent: "Sent", drafts: "Drafts", trash: "Deleted", junk: "Junk", archive: "Archive" }[f.special];
    return f.name;
  },

  async loadFolders() {
    this.folders = await call("GET", "mail/folders");
    this.folders.sort((a, b) => {
      const ia = a.special ? ORDER.indexOf(a.special) : 99, ib = b.special ? ORDER.indexOf(b.special) : 99;
      return ia - ib || a.name.localeCompare(b.name);
    });
    const ul = $("folders");
    ul.replaceChildren(...this.folders.map((f) => {
      const li = h("li", { class: f.name === this.folder ? "on" : "", title: f.name },
        h("span", { class: "ico" }, ICON[f.special] || "📁"),
        h("span", {}, this.label(f)),
        f.special === "drafts" ? (f.total ? h("span", { class: "n" }, f.total) : null)
          : f.unread ? h("span", { class: "n unread" }, f.unread) : null);
      li.onclick = () => { this.open(f.name); document.body.classList.remove("side-open"); };
      li.oncontextmenu = (e) => { if (!f.special && f.name !== "INBOX") { e.preventDefault(); this.folderMenu(f); } };
      // Drop messages onto a folder to move them.
      li.ondragover = (e) => { e.preventDefault(); li.classList.add("drop"); };
      li.ondragleave = () => li.classList.remove("drop");
      li.ondrop = (e) => { e.preventDefault(); li.classList.remove("drop"); const uids = JSON.parse(e.dataTransfer.getData("text/x-uids") || "[]"); if (uids.length) this.move(uids, f.name); };
      return li;
    }));
    const inbox = this.folders.find((f) => f.special === "inbox");
    document.title = (inbox && inbox.unread ? `(${inbox.unread}) ` : "") + "Mail – Postwright";
    const cur = this.folders.find((f) => f.name === this.folder);
    $("folder-title").textContent = cur ? this.label(cur) : this.folder;
  },

  open(name) {
    this.folder = name; this.page = 0; this.selected.clear(); this.current = null;
    this.search = ""; $("q").value = "";
    history.replaceState(null, "", "#mail/" + encodeURIComponent(name));
    this.loadFolders().catch(fail);
    this.loadList();
    this.clearReader();
  },

  async loadList(append) {
    try {
      const r = await call("GET", "mail/messages?" + qs({ folder: this.folder, page: this.page, q: this.search, unread: this.unread ? 1 : "" }));
      this.total = r.total;
      this.list = append ? this.list.concat(r.messages) : r.messages;
      this.renderList();
    } catch (e) { fail(e); }
  },

  renderList() {
    const box = $("msgs");
    if (!this.list.length) {
      box.replaceChildren(h("div", { class: "empty" }, this.search ? "Nothing matches your search." : this.unread ? "No unread messages." : "This folder is empty."));
      return;
    }
    const sent = ["sent", "drafts"].includes(this.special(this.folder));
    const rows = this.list.map((m) => {
      const cb = h("input", { type: "checkbox", title: "Select" });
      cb.checked = this.selected.has(m.uid);
      cb.onclick = (e) => { e.stopPropagation(); cb.checked ? this.selected.add(m.uid) : this.selected.delete(m.uid); this.selBar(); };
      const row = h("div", { class: "msg" + (m.seen ? "" : " unread") + (this.current && this.current.uid === m.uid ? " sel" : ""), draggable: "true" },
        cb,
        h("span", { class: "who" }, (sent ? "To: " + (m.to || "(no recipients)") : m.from || m.from_addr || "(unknown)")),
        h("span", { class: "when" }, shortDate(m.date),
          h("span", { class: "badges" }, m.flagged ? h("span", { class: "flag" }, "⚑") : null, m.attach ? " 📎" : null, m.answered ? " ↩" : null)),
        h("span", {}), h("span", { class: "subj" }, m.subject || "(no subject)"),
        h("span", {}), h("span", { class: "prev" }, m.preview));
      row.onclick = () => this.read(m);
      row.ondragstart = (e) => {
        const uids = this.selected.has(m.uid) ? [...this.selected] : [m.uid];
        e.dataTransfer.setData("text/x-uids", JSON.stringify(uids));
      };
      return row;
    });
    const out = [...rows];
    if (this.list.length < this.total) out.push(h("button", { class: "btn", id: "more", onclick: () => { this.page++; this.loadList(true); } }, `Show more (${this.total - this.list.length} left)`));
    box.replaceChildren(...out);
    this.selBar();
  },

  selBar() {
    $("sel-bar").classList.toggle("hidden", this.selected.size === 0);
    $("all").checked = this.selected.size > 0 && this.selected.size === this.list.length;
  },

  clearReader() {
    $("read-bar").classList.add("hidden");
    $("read-body").replaceChildren(h("div", { class: "empty" }, "Select a message to read it."));
    document.body.classList.remove("reading");
  },

  async read(m) {
    if (this.special(this.folder) === "drafts") {
      try { const full = await call("GET", "mail/message?" + qs({ folder: this.folder, uid: m.uid })); compose.openDraft(full); } catch (e) { fail(e); }
      return;
    }
    this.current = m;
    document.body.classList.add("reading");
    for (const r of document.querySelectorAll("#msgs .msg")) r.classList.remove("sel");
    const idx = this.list.indexOf(m);
    const row = document.querySelectorAll("#msgs .msg")[idx];
    if (row) { row.classList.add("sel"); row.classList.remove("unread"); }
    $("read-bar").classList.remove("hidden");
    $("read-body").replaceChildren(h("div", { class: "empty" }, "Loading…"));
    try {
      const full = await call("GET", "mail/message?" + qs({ folder: this.folder, uid: m.uid }));
      if (this.current !== m) return;
      this.current.full = full;
      if (!m.seen) { m.seen = true; this.loadFolders().catch(() => {}); }
      $("r-flag").textContent = full.flagged ? "Unflag" : "Flag";
      this.renderMessage(full);
    } catch (e) { $("read-body").replaceChildren(h("div", { class: "empty" }, e.message)); }
  },

  renderMessage(full) {
    const from = full.from[0] || { name: "", email: "" };
    const who = (l) => l.map((a) => a.name || a.email).join(", ");
    const kids = [h("h1", {}, full.subject || "(no subject)")];
    kids.push(h("div", { class: "hdr" },
      h("div", { class: "avatar" }, initials(from.name || from.email)),
      h("div", { style: { minWidth: 0 } },
        h("div", {}, h("span", { class: "from" }, from.name || from.email), " ", h("span", { class: "addr" }, from.name ? `<${from.email}>` : "")),
        full.to.length ? h("div", { class: "rcpt", title: full.to.map(fmtAddr).join(", ") }, "To: " + who(full.to)) : null,
        full.cc.length ? h("div", { class: "rcpt", title: full.cc.map(fmtAddr).join(", ") }, "Cc: " + who(full.cc)) : null),
      h("div", { class: "date" }, longDate(full.date))));
    if (full.invite) kids.push(this.inviteCard(full));
    if (this.special(this.folder) === "junk") kids.push(h("div", { class: "notice" }, "This message was filed as junk, so its pictures stay hidden.", h("button", { onclick: () => this.notJunk() }, "Not junk")));
    if (full.html) {
      const remote = /<img[^>]+src=["']?https?:/i.test(full.html) || /url\(["']?https?:/i.test(full.html);
      const allowed = this.allowImages.has(full.folder + "/" + full.uid);
      if (remote && !allowed && this.special(this.folder) !== "junk")
        kids.push(h("div", { class: "notice" }, "Pictures from the internet are hidden to protect your privacy.", h("button", { onclick: () => { this.allowImages.add(full.folder + "/" + full.uid); this.renderMessage(full); } }, "Show pictures")));
      kids.push(this.frame(full.html, allowed));
    } else {
      kids.push(h("pre", { class: "body" }, linkify(full.text)));
    }
    if (full.attachments.length) {
      kids.push(h("div", { class: "atts" }, full.attachments.map((a) => {
        const view = /^image\/(png|jpeg|gif|webp)$|^application\/pdf$/.test(a.type);
        return h("a", { class: "att", href: "/api/v1/mail/part?" + qs({ folder: full.folder, uid: full.uid, part: a.part, view: view ? 1 : "" }), target: view ? "_blank" : null, rel: "noopener", title: a.name },
          "📎", h("span", {}, a.name), h("small", {}, size(a.size)));
      })));
    }
    $("read-body").replaceChildren(...kids);
    $("read-body").scrollTop = 0;
  },

  frame(html, allowImages) {
    // The message runs in a sandbox with no scripts and its own strict policy.
    const csp = `default-src 'none'; style-src 'unsafe-inline'; font-src data:; img-src data: ${allowImages ? "https: http:" : ""}; media-src data:`;
    const doc = `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="${csp}"><meta name="referrer" content="no-referrer"><base target="_blank"><style>body{margin:0;font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;color:#1b2130;word-wrap:break-word;overflow-wrap:anywhere}img{max-width:100%;height:auto}table{max-width:100%}blockquote{margin:6px 0 6px 4px;padding-left:10px;border-left:3px solid #ccd}pre{white-space:pre-wrap}</style></head><body>${html}</body></html>`;
    const f = h("iframe", { class: "body", sandbox: "allow-popups allow-popups-to-escape-sandbox allow-same-origin", referrerpolicy: "no-referrer" });
    // allow-same-origin (without allow-scripts) lets us size the frame to its content;
    // scripts in the message still can't run.
    f.srcdoc = doc;
    f.onload = () => {
      try {
        const b = f.contentDocument.documentElement;
        const fit = () => { f.style.height = Math.max(120, b.scrollHeight + 8) + "px"; };
        fit();
        new ResizeObserver(fit).observe(f.contentDocument.body);
        for (const a of f.contentDocument.querySelectorAll("a[href]")) { a.target = "_blank"; a.rel = "noopener noreferrer"; }
      } catch (_) { f.style.height = "70vh"; }
    };
    return f;
  },

  inviteCard(full) {
    const inv = full.invite;
    const when = fmtRange(inv);
    const box = h("div", { class: "invite" },
      h("h3", {}, (inv.method === "CANCEL" ? "Cancelled: " : inv.method === "REPLY" ? "Reply: " : "") + (inv.title || "(no title)")),
      h("div", {}, when), inv.location ? h("div", {}, "📍 " + inv.location) : null,
      inv.organizer ? h("div", { class: "rcpt" }, "Organiser: " + (inv.organizer.name || inv.organizer.email)) : null);
    const answer = async (response) => {
      try { await call("POST", "mail/invite", { folder: full.folder, uid: full.uid, response }); toast(response === "remove" ? "Removed from your calendar" : "Answer sent, and your calendar updated"); calendar.dirty = true; } catch (e) { fail(e); }
    };
    if (inv.method === "REQUEST" || inv.method === "") {
      const mine = inv.my_status ? ` (you: ${inv.my_status})` : "";
      box.append(h("div", { class: "row" },
        h("button", { class: "yes", onclick: () => answer("accepted") }, "Accept"),
        h("button", { onclick: () => answer("tentative") }, "Maybe"),
        h("button", { onclick: () => answer("declined") }, "Decline"),
        h("span", { class: "rcpt" }, mine)));
    } else if (inv.method === "CANCEL") {
      box.append(h("div", { class: "row" }, h("button", { onclick: () => answer("remove") }, "Remove from calendar")));
    } else if (inv.method === "REPLY" && inv.attendees.length) {
      box.append(h("div", { class: "rcpt" }, inv.attendees.map((a) => `${a.name || a.email}: ${a.status}`).join(", ")));
    }
    return box;
  },

  async flag(uids, add, remove) {
    await call("POST", "mail/flags", { folder: this.folder, uids, add, remove });
    for (const m of this.list) if (uids.includes(m.uid)) {
      if (add.includes("\\Seen")) m.seen = true;
      if (remove.includes("\\Seen")) m.seen = false;
      if (add.includes("\\Flagged")) m.flagged = true;
      if (remove.includes("\\Flagged")) m.flagged = false;
    }
    this.renderList();
    this.loadFolders().catch(() => {});
  },

  async move(uids, to, quiet) {
    if (!uids.length) return;
    const from = this.folder;
    await call("POST", "mail/move", { folder: from, uids, to });
    this.afterRemove(uids);
    if (!quiet) toast(`Moved ${uids.length === 1 ? "1 message" : uids.length + " messages"} to ${this.label(this.folders.find((f) => f.name === to) || { name: to })}`);
  },

  async remove(uids) {
    if (!uids.length) return;
    const sp = this.special(this.folder);
    if ((sp === "trash" || sp === "junk") && !confirm(`Delete ${uids.length === 1 ? "this message" : uids.length + " messages"} for good?`)) return;
    await call("POST", "mail/delete", { folder: this.folder, uids });
    this.afterRemove(uids);
    toast(sp === "trash" || sp === "junk" ? "Deleted" : "Moved to Deleted");
  },

  afterRemove(uids) {
    const idx = this.current ? this.list.findIndex((m) => m.uid === this.current.uid) : -1;
    this.list = this.list.filter((m) => !uids.includes(m.uid));
    this.total -= uids.length;
    for (const u of uids) this.selected.delete(u);
    const wasOpen = this.current && uids.includes(this.current.uid);
    this.renderList();
    this.loadFolders().catch(() => {});
    if (wasOpen) {
      const next = this.list[Math.min(idx, this.list.length - 1)];
      if (next && window.innerWidth > 900) this.read(next); else { this.current = null; this.clearReader(); }
    }
  },

  async notJunk() {
    const inbox = this.bySpecial("inbox") || "INBOX";
    if (this.current) await this.move([this.current.uid], inbox).catch(fail);
  },

  pickFolder(title) {
    return new Promise((resolve) => {
      const sel = h("select", {}, this.folders.filter((f) => f.name !== this.folder).map((f) => h("option", { value: f.name }, this.label(f))));
      const d = dialog(h("h2", {}, title), h("label", {}, "Folder"), sel,
        h("div", { class: "acts" }, h("button", { class: "btn", onclick: () => { d.close(); resolve(null); } }, "Cancel"),
          h("button", { class: "btn ok", onclick: () => { d.close(); resolve(sel.value); } }, "Move")));
    });
  },

  folderMenu(f) {
    const name = h("input", { type: "text", value: f.name });
    const d = dialog(h("h2", {}, "Folder"), h("label", {}, "Name"), name,
      h("div", { class: "acts" },
        h("button", { class: "btn danger", onclick: async () => {
          if (!confirm(`Delete the folder "${f.name}" and everything in it?`)) return;
          try { await call("POST", "mail/folders", { action: "delete", name: f.name }); d.close(); if (this.folder === f.name) this.open("INBOX"); else this.loadFolders(); } catch (e) { fail(e); }
        } }, "Delete folder"),
        h("button", { class: "btn", onclick: () => d.close() }, "Cancel"),
        h("button", { class: "btn ok", onclick: async () => {
          try { await call("POST", "mail/folders", { action: "rename", name: f.name, to: name.value.trim() }); d.close(); if (this.folder === f.name) this.folder = name.value.trim(); this.loadFolders(); } catch (e) { fail(e); }
        } }, "Rename")));
  },
};

function linkify(text) {
  const frag = document.createDocumentFragment();
  const re = /\bhttps?:\/\/[^\s<>"')\]]+/g;
  let last = 0, m;
  while ((m = re.exec(text))) {
    frag.append(text.slice(last, m.index));
    frag.append(h("a", { href: m[0], target: "_blank", rel: "noopener noreferrer" }, m[0]));
    last = m.index + m[0].length;
  }
  frag.append(text.slice(last));
  return frag;
}

$("all").onchange = () => {
  if ($("all").checked) for (const m of mail.list) mail.selected.add(m.uid); else mail.selected.clear();
  mail.renderList();
};
$("t-refresh").onclick = () => { mail.loadFolders().catch(fail); mail.page = 0; mail.loadList(); };
$("t-unread").onclick = () => { mail.unread = !mail.unread; $("t-unread").classList.toggle("on", mail.unread); mail.page = 0; mail.loadList(); };
$("new-folder").onclick = () => {
  const name = h("input", { type: "text", placeholder: "e.g. Receipts" });
  const d = dialog(h("h2", {}, "New folder"), h("label", {}, "Name"), name,
    h("div", { class: "acts" }, h("button", { class: "btn", onclick: () => d.close() }, "Cancel"),
      h("button", { class: "btn ok", onclick: async () => {
        try { await call("POST", "mail/folders", { action: "create", name: name.value.trim() }); d.close(); mail.loadFolders(); } catch (e) { fail(e); }
      } }, "Create")));
  name.focus();
};
for (const b of document.querySelectorAll("#sel-bar button")) b.onclick = async () => {
  const uids = [...mail.selected];
  try {
    switch (b.dataset.act) {
      case "read": await mail.flag(uids, ["\\Seen"], []); break;
      case "unread": await mail.flag(uids, [], ["\\Seen"]); break;
      case "flag": await mail.flag(uids, ["\\Flagged"], []); break;
      case "delete": await mail.remove(uids); break;
      case "junk": await mail.move(uids, mail.bySpecial("junk") || "Junk"); break;
      case "move": { const to = await mail.pickFolder("Move to"); if (to) await mail.move(uids, to); break; }
    }
  } catch (e) { fail(e); }
};
$("back").onclick = () => { document.body.classList.remove("reading"); mail.current = null; };
$("r-reply").onclick = () => mail.current && compose.reply(mail.current.full, false);
$("r-all").onclick = () => mail.current && compose.reply(mail.current.full, true);
$("r-fwd").onclick = () => mail.current && compose.forward(mail.current.full);
$("r-del").onclick = () => mail.current && mail.remove([mail.current.uid]).catch(fail);
$("r-junk").onclick = () => mail.current && mail.move([mail.current.uid], mail.bySpecial("junk") || "Junk").catch(fail);
$("r-move").onclick = async () => { if (!mail.current) return; const to = await mail.pickFolder("Move to"); if (to) mail.move([mail.current.uid], to).catch(fail); };
$("r-flag").onclick = async () => {
  const m = mail.current; if (!m) return;
  const on = !(m.full && m.full.flagged);
  try { await mail.flag([m.uid], on ? ["\\Flagged"] : [], on ? [] : ["\\Flagged"]); if (m.full) m.full.flagged = on; $("r-flag").textContent = on ? "Unflag" : "Flag"; } catch (e) { fail(e); }
};
$("r-unread").onclick = async () => { const m = mail.current; if (!m) return; try { await mail.flag([m.uid], [], ["\\Seen"]); toast("Marked unread"); } catch (e) { fail(e); } };
$("r-raw").onclick = () => { const m = mail.current; if (m) location.href = "/api/v1/mail/raw?" + qs({ folder: mail.folder, uid: m.uid }); };
$("new-msg").onclick = () => compose.open({});

// Keyboard: n new, r reply, a reply all, f forward, Delete, j/k next/previous.
document.addEventListener("keydown", (e) => {
  if (state.app !== "mail" || e.ctrlKey || e.metaKey || e.altKey) return;
  const t = e.target;
  if (t.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(t.tagName) || !$("compose").classList.contains("hidden") && !$("compose").classList.contains("min")) return;
  if (document.querySelector(".backdrop")) return;
  const cur = mail.current;
  const i = cur ? mail.list.findIndex((m) => m.uid === cur.uid) : -1;
  switch (e.key) {
    case "n": compose.open({}); break;
    case "r": if (cur && cur.full) compose.reply(cur.full, false); break;
    case "a": if (cur && cur.full) compose.reply(cur.full, true); break;
    case "f": if (cur && cur.full) compose.forward(cur.full); break;
    case "Delete": if (cur) mail.remove([cur.uid]).catch(fail); break;
    case "j": case "ArrowDown": if (mail.list[i + 1]) mail.read(mail.list[i + 1]); break;
    case "k": case "ArrowUp": if (i > 0) mail.read(mail.list[i - 1]); break;
    default: return;
  }
  e.preventDefault();
});

// ======================================================================= compose

/** Keep only harmless markup from a message we're quoting. */
function sanitise(html) {
  const doc = new DOMParser().parseFromString(html, "text/html");
  const okTags = new Set(["A", "B", "I", "U", "S", "EM", "STRONG", "P", "DIV", "SPAN", "BR", "HR", "UL", "OL", "LI", "BLOCKQUOTE", "PRE", "CODE", "H1", "H2", "H3", "H4", "H5", "H6", "TABLE", "THEAD", "TBODY", "TFOOT", "TR", "TD", "TH", "IMG", "FONT", "SMALL", "SUB", "SUP", "CENTER"]);
  const okAttr = new Set(["href", "src", "alt", "title", "style", "colspan", "rowspan", "align", "valign", "width", "height", "color", "face", "size", "border", "cellpadding", "cellspacing", "bgcolor"]);
  const walk = (node) => {
    for (const el of [...node.children]) {
      if (["SCRIPT", "STYLE", "IFRAME", "OBJECT", "EMBED", "FORM", "INPUT", "BUTTON", "TEXTAREA", "SELECT", "LINK", "META", "BASE", "SVG", "MATH", "TEMPLATE", "NOSCRIPT", "TITLE", "HEAD"].includes(el.tagName)) { el.remove(); continue; }
      walk(el);
      if (!okTags.has(el.tagName)) { el.replaceWith(...el.childNodes); continue; }
      for (const a of [...el.attributes]) {
        const n = a.name.toLowerCase(), v = a.value.trim();
        if (!okAttr.has(n)) el.removeAttribute(a.name);
        else if (n === "href" && !/^(https?:|mailto:|#)/i.test(v)) el.removeAttribute(a.name);
        else if (n === "src" && !/^data:image\//i.test(v)) { el.removeAttribute(a.name); }
        else if (n === "style" && /url\s*\(|expression|@import|position\s*:\s*fixed/i.test(v)) el.removeAttribute(a.name);
      }
      if (el.tagName === "IMG" && !el.getAttribute("src")) el.replaceWith(el.getAttribute("alt") ? `[${el.getAttribute("alt")}]` : "");
    }
  };
  walk(doc.body);
  return doc.body.innerHTML;
}
const textToHtml = (t) => esc(t).replace(/\r?\n/g, "<br>");

function chipInput(box, opts = {}) {
  const list = [];
  const input = h("input", { type: "text", autocomplete: "off", placeholder: opts.placeholder || "" });
  let sug = null, sugItems = [], sugIdx = -1, timer = null;
  const valid = (e) => /^[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]+$/.test(e);
  const render = () => {
    box.replaceChildren(...list.map((a, i) => h("span", { class: "chip" + (valid(a.email) ? "" : " bad"), title: a.email }, a.name || a.email,
      h("button", { type: "button", title: "Remove", onclick: () => { list.splice(i, 1); render(); input.focus(); } }, "×"))), input);
    if (sug) box.append(sug);
  };
  const parse = (s) => {
    const m = s.match(/^\s*"?([^"<]*?)"?\s*<([^>]+)>\s*$/);
    return m ? { name: m[1].trim(), email: m[2].trim() } : { name: "", email: s.trim() };
  };
  const add = (a) => { if (a.email && !list.some((x) => x.email.toLowerCase() === a.email.toLowerCase())) list.push(a); };
  const commit = () => {
    const v = input.value;
    if (v.trim()) { for (const part of v.split(/[,;]/)) if (part.trim()) add(parse(part)); }
    input.value = ""; closeSug(); render(); input.focus();
  };
  const closeSug = () => { if (sug) { sug.remove(); sug = null; } sugItems = []; sugIdx = -1; };
  const showSug = (items) => {
    closeSug();
    if (!items.length) return;
    sugItems = items; sugIdx = 0;
    sug = h("div", { class: "suggest" }, items.map((it, i) => {
      const d = h("div", { class: i === 0 ? "on" : "" }, it.name || it.email, it.name ? h("small", {}, it.email) : null);
      d.onmousedown = (e) => { e.preventDefault(); add({ name: it.name, email: it.email }); input.value = ""; closeSug(); render(); input.focus(); };
      return d;
    }));
    box.append(sug);
  };
  input.addEventListener("keydown", (e) => {
    if (sug && (e.key === "ArrowDown" || e.key === "ArrowUp")) {
      e.preventDefault();
      sugIdx = (sugIdx + (e.key === "ArrowDown" ? 1 : sugItems.length - 1)) % sugItems.length;
      [...sug.children].forEach((c, i) => c.classList.toggle("on", i === sugIdx));
      return;
    }
    if ((e.key === "Enter" || e.key === "Tab") && sug && sugIdx >= 0) { e.preventDefault(); const it = sugItems[sugIdx]; add(it); input.value = ""; closeSug(); render(); input.focus(); return; }
    if (e.key === "Enter" || e.key === "," || e.key === ";") { if (input.value.trim()) { e.preventDefault(); commit(); } return; }
    if (e.key === "Backspace" && !input.value && list.length) { list.pop(); render(); input.focus(); }
    if (e.key === "Escape") closeSug();
  });
  input.addEventListener("input", () => {
    clearTimeout(timer);
    const v = input.value.trim();
    if (v.length < 2) { closeSug(); return; }
    timer = setTimeout(async () => { try { showSug(await call("GET", "mail/contacts?" + qs({ q: v }))); } catch (_) {} }, 180);
  });
  input.addEventListener("blur", () => setTimeout(() => { if (input.value.trim()) commit(); else closeSug(); }, 150));
  input.addEventListener("paste", () => setTimeout(() => { if (/[,;]/.test(input.value)) commit(); }, 0));
  box.onclick = () => input.focus();
  render();
  return {
    get: () => { if (input.value.trim()) commit(); return list.map((a) => a.name ? `"${a.name.replace(/"/g, "")}" <${a.email}>` : a.email); },
    invalid: () => list.filter((a) => !valid(a.email)).map((a) => a.email),
    set: (arr) => { list.length = 0; for (const a of arr) add(typeof a === "string" ? parse(a) : a); render(); },
    count: () => list.length + (input.value.trim() ? 1 : 0),
    focus: () => input.focus(),
  };
}

const compose = {
  to: chipInput($("c-to")), cc: chipInput($("c-cc")), bcc: chipInput($("c-bcc")),
  files: [], keep: null, draftUid: null, inReplyTo: null, references: [], answering: null, dirty: false, timer: null,

  async open(o) {
    if (!$("compose").classList.contains("hidden") && this.dirty && !confirm("Discard the message you're writing?")) return;
    if (!ids) ids = await call("GET", "mail/identities").catch(() => ({ identities: [{ email: me.email, name: "", kind: "own" }], default: me.email }));
    $("c-from").replaceChildren(...ids.identities.map((i) => h("option", { value: i.name ? `"${i.name.replace(/"/g, "")}" <${i.email}>` : i.email },
      (i.name ? `${i.name} <${i.email}>` : i.email) + (i.kind === "on_behalf" ? " (on behalf)" : i.kind === "as" ? " (as)" : ""))));
    const pick = o.from && [...$("c-from").options].find((op) => op.value.toLowerCase().includes("<" + o.from.toLowerCase() + ">") || op.value.toLowerCase() === o.from.toLowerCase());
    if (pick) $("c-from").value = pick.value;
    this.to.set(o.to || []); this.cc.set(o.cc || []); this.bcc.set(o.bcc || []);
    $("f-cc").classList.toggle("hidden", !(o.cc && o.cc.length));
    $("f-bcc").classList.toggle("hidden", !(o.bcc && o.bcc.length));
    $("c-subject").value = o.subject || "";
    $("editor").innerHTML = o.html || "";
    this.files = []; this.keep = o.keep || null; this.draftUid = o.draftUid || null;
    this.inReplyTo = o.inReplyTo || null; this.references = o.references || []; this.answering = o.answering || null;
    this.renderAtts();
    $("c-title-bar").textContent = o.subject || "New message";
    $("c-status").textContent = "";
    $("compose").classList.remove("hidden", "min");
    this.dirty = false;
    clearInterval(this.timer);
    this.timer = setInterval(() => { if (this.dirty) this.save(true); }, 60000);
    if (!this.to.count()) this.to.focus(); else { const ed = $("editor"); ed.focus(); const r = document.createRange(); r.setStart(ed, 0); r.collapse(true); const s = getSelection(); s.removeAllRanges(); s.addRange(r); }
  },

  quoteHeader(full) {
    const from = full.from[0] || {};
    return `<br><br><div>On ${esc(longDate(full.date))}, ${esc(from.name || from.email || "")} wrote:</div>`;
  },
  quoted(full) {
    const body = full.html ? sanitise(full.html) : textToHtml(full.text);
    return `<blockquote>${body}</blockquote>`;
  },
  mine(addr) { return ids && ids.identities.some((i) => i.email.toLowerCase() === (addr || "").toLowerCase()) || (addr || "").toLowerCase() === me.email.toLowerCase(); },

  async reply(full, all) {
    if (!ids) ids = await call("GET", "mail/identities").catch(() => null);
    const sentFolder = mail.special(full.folder) === "sent";
    const target = sentFolder ? full.to : (full.reply_to.length ? full.reply_to : full.from);
    let cc = [];
    if (all) {
      cc = [...(sentFolder ? [] : full.to), ...full.cc].filter((a) => !this.mine(a.email) && !target.some((t) => t.email.toLowerCase() === a.email.toLowerCase()));
    }
    // Answer from whichever of my addresses the message was sent to.
    const to_me = [...full.to, ...full.cc].map((a) => a.email).find((e) => this.mine(e));
    const subj = /^re:/i.test(full.subject) ? full.subject : "Re: " + (full.subject || "");
    const refs = [...(full.references || []), full.message_id].filter(Boolean).map((r) => r.startsWith("<") ? r : `<${r}>`);
    this.open({ to: target, cc, subject: subj, from: to_me, html: this.quoteHeader(full) + this.quoted(full),
      inReplyTo: full.message_id ? (full.message_id.startsWith("<") ? full.message_id : `<${full.message_id}>`) : null, references: refs,
      answering: { folder: full.folder, uid: full.uid, forwarded: false } });
  },

  forward(full) {
    const from = full.from[0] || {};
    const head = `<br><br><div>---------- Forwarded message ----------<br>From: ${esc(fmtAddr(from))}<br>Date: ${esc(longDate(full.date))}<br>Subject: ${esc(full.subject)}<br>To: ${esc(full.to.map(fmtAddr).join(", "))}${full.cc.length ? "<br>Cc: " + esc(full.cc.map(fmtAddr).join(", ")) : ""}</div><br>`;
    const body = full.html ? sanitise(full.html) : textToHtml(full.text);
    const subj = /^fwd?:/i.test(full.subject) ? full.subject : "Fwd: " + (full.subject || "");
    this.open({ subject: subj, html: head + body,
      keep: full.attachments.length ? { folder: full.folder, uid: full.uid, parts: full.attachments.map((a) => a.part), names: full.attachments } : null,
      answering: { folder: full.folder, uid: full.uid, forwarded: true } });
  },

  openDraft(full) {
    this.open({ from: (full.from[0] || {}).email, to: full.to, cc: full.cc, subject: full.subject,
      html: full.html ? sanitise(full.html) : textToHtml(full.text), draftUid: full.uid,
      keep: full.attachments.length ? { folder: full.folder, uid: full.uid, parts: full.attachments.map((a) => a.part), names: full.attachments } : null });
  },

  renderAtts() {
    const chips = [];
    if (this.keep) this.keep.names.forEach((a, i) => chips.push(h("span", { class: "chip" }, "📎 " + a.name, h("small", {}, " " + size(a.size)),
      h("button", { type: "button", onclick: () => { this.keep.parts.splice(i, 1); this.keep.names.splice(i, 1); if (!this.keep.parts.length) this.keep = null; this.renderAtts(); } }, "×"))));
    this.files.forEach((f, i) => chips.push(h("span", { class: "chip" }, "📎 " + f.name, h("small", {}, " " + size(f.size)),
      h("button", { type: "button", onclick: () => { this.files.splice(i, 1); this.renderAtts(); } }, "×"))));
    $("c-atts").replaceChildren(...chips);
  },

  async addFiles(list) {
    for (const f of list) {
      const total = this.files.reduce((n, x) => n + x.size, 0) + f.size;
      if (total > 25 * 1048576) { toast("Attachments can be up to 25 MB in total.", { err: true }); break; }
      const data = await new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(String(r.result).split(",")[1] || ""); r.onerror = rej; r.readAsDataURL(f); });
      this.files.push({ name: f.name, type: f.type || "application/octet-stream", size: f.size, data });
      this.dirty = true;
    }
    this.renderAtts();
  },

  payload() {
    const ed = $("editor");
    const html = ed.innerHTML;
    const text = htmlToText(ed);
    return {
      from: $("c-from").value, to: this.to.get(), cc: this.cc.get(), bcc: this.bcc.get(),
      subject: $("c-subject").value, text, html: /<(b|i|u|a|ul|ol|blockquote|img|table|font|strong|em)\b/i.test(html) ? `<div style="font-family:system-ui,-apple-system,'Segoe UI',sans-serif;font-size:14px">${html}</div>` : null,
      in_reply_to: this.inReplyTo, references: this.references,
      attachments: this.files.map((f) => ({ name: f.name, type: f.type, data: f.data })),
      keep: this.keep ? { folder: this.keep.folder, uid: this.keep.uid, parts: this.keep.parts } : null,
      draft_uid: this.draftUid, answering: this.answering,
    };
  },

  async send() {
    const bad = [...this.to.invalid(), ...this.cc.invalid(), ...this.bcc.invalid()];
    if (bad.length) { toast(`Check ${bad.join(", ")}: ${bad.length === 1 ? "it doesn't look like an email address" : "these don't look like email addresses"}.`, { err: true }); return; }
    const p = this.payload();
    if (!p.to.length && !p.cc.length && !p.bcc.length) { toast("Add someone to send it to.", { err: true }); return; }
    if (!p.subject.trim() && !confirm("Send without a subject?")) return;
    $("c-send").disabled = true; $("c-status").textContent = "Sending…";
    try {
      const r = await call("POST", "mail/send", p);
      this.close(true);
      toast(r.held ? "Held for scanning: it will go out automatically once the scanner is back" : r.failed && r.failed.length ? `Sent, but not to ${r.failed.join(", ")}` : "Sent");
      if (["sent", "drafts"].includes(mail.special(mail.folder))) mail.loadList();
      mail.loadFolders().catch(() => {});
    } catch (e) { $("c-status").textContent = ""; fail(e); }
    finally { $("c-send").disabled = false; }
  },

  async save(auto) {
    try {
      const r = await call("POST", "mail/draft", this.payload());
      this.draftUid = r.draft_uid; this.dirty = false;
      $("c-status").textContent = (auto ? "Draft saved automatically at " : "Draft saved at ") + fmtTime(new Date());
      if (mail.special(mail.folder) === "drafts") mail.loadList();
      mail.loadFolders().catch(() => {});
    } catch (e) { if (!auto) fail(e); }
  },

  close(sent) {
    clearInterval(this.timer);
    $("compose").classList.add("hidden");
    $("compose").classList.remove("max");
    if (!sent && this.dirty) toast("Message discarded");
    this.dirty = false;
  },
};

function htmlToText(el) {
  // Plain-text alternative: block elements on their own lines, quotes with "> ".
  const out = [];
  const walk = (n, quote) => {
    for (const c of n.childNodes) {
      if (c.nodeType === 3) { out.push(c.textContent.replace(/\s+/g, " ")); continue; }
      if (c.nodeType !== 1) continue;
      const t = c.tagName;
      if (t === "BR") { out.push("\n" + quote); continue; }
      if (t === "BLOCKQUOTE") { out.push("\n" + quote + "> "); walk(c, quote + "> "); out.push("\n" + quote); continue; }
      const block = /^(DIV|P|LI|H\d|TR|TABLE|UL|OL|PRE)$/.test(t);
      if (block) out.push("\n" + quote);
      if (t === "LI") out.push("• ");
      if (t === "A" && c.getAttribute("href") && c.textContent.trim() !== c.getAttribute("href")) { walk(c, quote); out.push(` (${c.getAttribute("href")})`); continue; }
      walk(c, quote);
      if (block) out.push("\n" + quote);
    }
  };
  walk(el, "");
  return out.join("").replace(/[ \t]+\n/g, "\n").replace(/\n{3,}/g, "\n\n").trim() + "\n";
}

$("c-send").onclick = () => compose.send();
$("c-save").onclick = () => compose.save(false);
$("c-discard").onclick = () => { if (!compose.dirty || confirm("Discard this message?")) compose.close(); };
$("c-close").onclick = async () => { if (compose.dirty) await compose.save(true); compose.close(true); };
$("c-min").onclick = (e) => { e.stopPropagation(); $("compose").classList.toggle("min"); };
$("c-max").onclick = (e) => { e.stopPropagation(); $("compose").classList.toggle("max"); $("compose").classList.remove("min"); };
$("c-head").onclick = () => $("compose").classList.remove("min");
$("c-show-cc").onclick = () => { $("f-cc").classList.remove("hidden"); $("f-bcc").classList.remove("hidden"); compose.cc.focus(); };
$("c-attach").onclick = () => $("c-file").click();
$("c-file").onchange = () => { compose.addFiles([...$("c-file").files]); $("c-file").value = ""; };
$("c-subject").oninput = () => { compose.dirty = true; $("c-title-bar").textContent = $("c-subject").value || "New message"; };
$("editor").oninput = () => { compose.dirty = true; };
$("editor").addEventListener("paste", (e) => {
  // Pasted HTML is cleaned the same way as quoted mail.
  const html = e.clipboardData.getData("text/html");
  if (html) { e.preventDefault(); document.execCommand("insertHTML", false, sanitise(html)); }
});
for (const b of document.querySelectorAll("#edtools button")) b.onmousedown = (e) => {
  e.preventDefault();
  const cmd = b.dataset.cmd;
  if (cmd === "createLink") { const u = prompt("Link address", "https://"); if (u && /^(https?:|mailto:)/i.test(u)) document.execCommand("createLink", false, u); }
  else document.execCommand(cmd, false, null);
  compose.dirty = true;
};
const cbox = $("compose");
cbox.ondragover = (e) => { if ([...e.dataTransfer.types].includes("Files")) { e.preventDefault(); cbox.classList.add("drag"); } };
cbox.ondragleave = () => cbox.classList.remove("drag");
cbox.ondrop = (e) => { if (e.dataTransfer.files.length) { e.preventDefault(); cbox.classList.remove("drag"); compose.addFiles([...e.dataTransfer.files]); } };
window.addEventListener("beforeunload", (e) => { if (!$("compose").classList.contains("hidden") && compose.dirty) { e.preventDefault(); e.returnValue = ""; } });

// ====================================================================== dialogs

function dialog(...kids) {
  const box = h("div", { class: "dialog", role: "dialog" }, ...kids);
  const back = h("div", { class: "backdrop" }, box);
  const close = () => { back.remove(); document.removeEventListener("keydown", onKey); };
  const onKey = (e) => { if (e.key === "Escape") close(); };
  back.onmousedown = (e) => { if (e.target === back) close(); };
  document.addEventListener("keydown", onKey);
  document.body.append(back);
  return { close, box };
}

// ===================================================================== calendar

const DAY = 86400000;
const startOfDay = (d) => new Date(d.getFullYear(), d.getMonth(), d.getDate());
const addDays = (d, n) => new Date(d.getFullYear(), d.getMonth(), d.getDate() + n);
const weekStart = (d) => addDays(startOfDay(d), -((d.getDay() + 6) % 7)); // Monday
const ymd = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
const hm = (d) => `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
const parseYmd = (s) => { const [y, m, d] = s.split("-").map(Number); return new Date(y, m - 1, d); };
function evStart(e) { return e.allday ? parseYmd(e.start) : new Date(e.start * 1000); }
function evEnd(e) { return e.allday ? parseYmd(e.end) : new Date(e.end * 1000); }
function fmtRange(e) {
  const s = evStart(e), en = evEnd(e);
  if (e.allday) {
    const last = addDays(en, -1);
    const f = (d) => d.toLocaleDateString(LOCALE, { weekday: "short", day: "numeric", month: "short", year: "numeric" });
    return last <= s ? f(s) + " (all day)" : `${f(s)} – ${f(last)}`;
  }
  const same = s.toDateString() === en.toDateString();
  return s.toLocaleDateString(LOCALE, { weekday: "short", day: "numeric", month: "short", year: "numeric" }) + ", " + fmtTime(s) + " – " + (same ? fmtTime(en) : en.toLocaleDateString(LOCALE, { day: "numeric", month: "short" }) + " " + fmtTime(en));
}
const COLOURS = ["#2e7d32", "#1565c0", "#ad1457", "#ef6c00", "#6a1b9a", "#00838f", "#5d4037", "#c62828"];

const calendar = {
  view: "week", date: new Date(), cals: [], events: [], hidden: new Set(JSON.parse(localStorageGet("pw-hidden-cals") || "[]")), dirty: true,

  range() {
    if (this.view === "day") { const s = startOfDay(this.date); return [s, addDays(s, 1)]; }
    if (this.view === "week") { const s = weekStart(this.date); return [s, addDays(s, 7)]; }
    const first = new Date(this.date.getFullYear(), this.date.getMonth(), 1);
    const s = weekStart(first);
    return [s, addDays(s, 42)];
  },
  colour(slug) {
    const c = this.cals.find((x) => x.slug === slug);
    if (c && c.color && /^#[0-9a-f]{6}$/i.test(c.color)) return c.color;
    const i = Math.max(0, this.cals.findIndex((x) => x.slug === slug));
    return COLOURS[i % COLOURS.length];
  },

  async render() {
    const [s, e] = this.range();
    const title = this.view === "month" ? this.date.toLocaleDateString(LOCALE, { month: "long", year: "numeric" })
      : this.view === "week" ? `${s.toLocaleDateString(LOCALE, { day: "numeric", month: "short" })} – ${addDays(e, -1).toLocaleDateString(LOCALE, { day: "numeric", month: "short", year: "numeric" })}`
      : this.date.toLocaleDateString(LOCALE, { weekday: "long", day: "numeric", month: "long", year: "numeric" });
    $("c-title").textContent = title;
    for (const b of document.querySelectorAll("#c-views button")) b.classList.toggle("on", b.dataset.v === this.view);
    try {
      const r = await call("GET", "cal/events?" + qs({ from: Math.floor(s / 1000), to: Math.floor(e / 1000), tz: TZ }));
      this.cals = r.calendars; this.events = r.events; this.dirty = false;
    } catch (err) { fail(err); }
    this.renderCals();
    const visible = this.events.filter((x) => !this.hidden.has(x.calendar));
    if (this.view === "month") this.renderMonth(s, visible); else this.renderWeek(s, this.view === "day" ? 1 : 7, visible);
  },

  renderCals() {
    $("cal-list").replaceChildren(...this.cals.map((c) => {
      const li = h("li", { class: this.hidden.has(c.slug) ? "off" : "", title: c.is_owner ? c.name : `${c.name} (shared by ${c.owner})` },
        h("span", { class: "sw", style: { background: this.colour(c.slug) } }), h("span", {}, c.name), !c.is_owner ? h("span", { class: "n" }, "shared") : null);
      li.onclick = () => {
        this.hidden.has(c.slug) ? this.hidden.delete(c.slug) : this.hidden.add(c.slug);
        localStorageSet("pw-hidden-cals", JSON.stringify([...this.hidden]));
        this.render();
      };
      return li;
    }));
  },

  chip(ev, timedStyle) {
    const c = this.colour(ev.calendar);
    const el = h("div", { class: "ev" + (timedStyle ? " timed" : ""), style: timedStyle ? { "--c": c } : { background: c }, title: `${ev.title}\n${fmtRange(ev)}${ev.location ? "\n" + ev.location : ""}` },
      timedStyle ? fmtTime(evStart(ev)) + " " : "", ev.title || "(no title)");
    el.onclick = (e) => { e.stopPropagation(); this.details(ev); };
    return el;
  },

  renderMonth(start, evs) {
    const grid = h("div", { class: "month" });
    for (let i = 0; i < 7; i++) grid.append(h("div", { class: "dow" }, addDays(start, i).toLocaleDateString(LOCALE, { weekday: "short" })));
    const today = startOfDay(new Date()).getTime();
    for (let i = 0; i < 42; i++) {
      const d = addDays(start, i), next = addDays(d, 1);
      const dayEvs = evs.filter((e) => evStart(e) < next && evEnd(e) > d || (!e.allday && evStart(e) >= d && evStart(e) < next))
        .sort((a, b) => (b.allday - a.allday) || (evStart(a) - evStart(b)));
      const cell = h("div", { class: "day" + (d.getMonth() !== this.date.getMonth() ? " other" : "") + (d.getTime() === today ? " today" : "") },
        h("span", { class: "num" }, d.getDate()));
      dayEvs.slice(0, 4).forEach((e) => cell.append(this.chip(e, !e.allday)));
      if (dayEvs.length > 4) cell.append(h("div", { class: "more" }, `+${dayEvs.length - 4} more`));
      cell.onclick = () => this.edit(null, d, true);
      cell.ondblclick = () => { this.date = d; this.view = "day"; this.render(); };
      grid.append(cell);
    }
    $("cal-grid").replaceChildren(grid);
  },

  renderWeek(start, days, evs) {
    const grid = h("div", { class: "week", style: { gridTemplateColumns: `56px repeat(${days}, 1fr)` } });
    const today = startOfDay(new Date()).getTime();
    grid.append(h("div", { class: "colhead" }, ""));
    for (let i = 0; i < days; i++) {
      const d = addDays(start, i);
      const head = h("div", { class: "colhead" + (d.getTime() === today ? " today" : "") }, d.toLocaleDateString(LOCALE, { weekday: "short" }), h("b", {}, d.getDate()));
      head.onclick = () => { this.date = d; this.view = "day"; this.render(); };
      grid.append(head);
    }
    // All-day row
    grid.append(h("div", { class: "allday", style: { fontSize: "11px", color: "var(--faint)", textAlign: "right", paddingRight: "6px" } }, "all day"));
    for (let i = 0; i < days; i++) {
      const d = addDays(start, i), next = addDays(d, 1);
      const cell = h("div", { class: "allday" });
      evs.filter((e) => (e.allday || evEnd(e) - evStart(e) >= DAY) && evStart(e) < next && evEnd(e) > d).forEach((e) => cell.append(this.chip(e, false)));
      cell.onclick = () => this.edit(null, d, true);
      grid.append(cell);
    }
    // Hours
    const hours = h("div", { class: "hours" });
    for (let hr = 0; hr < 24; hr++) hours.append(h("div", { class: "hour" }, hr ? `${String(hr).padStart(2, "0")}:00` : ""));
    grid.append(hours);
    for (let i = 0; i < days; i++) {
      const d = addDays(start, i), next = addDays(d, 1);
      const col = h("div", { class: "col" });
      for (let s = 0; s < 48; s++) {
        const slot = h("div", { class: "slot" });
        slot.onclick = () => this.edit(null, new Date(d.getTime() + s * 1800000), false);
        col.append(slot);
      }
      const timed = evs.filter((e) => !e.allday && evEnd(e) - evStart(e) < DAY && evStart(e) < next && evEnd(e) > d).sort((a, b) => evStart(a) - evStart(b));
      // Side-by-side layout for overlaps.
      const lanes = [];
      const placed = timed.map((e) => {
        const s = Math.max(evStart(e), d), en = Math.min(Math.max(evEnd(e), evStart(e) + 1800000), next);
        let lane = lanes.findIndex((end) => end <= s);
        if (lane < 0) { lane = lanes.length; lanes.push(en); } else lanes[lane] = en;
        return { e, s, en, lane };
      });
      for (const p of placed) {
        const overlapping = placed.filter((q) => q.s < p.en && q.en > p.s);
        const width = Math.max(...overlapping.map((q) => q.lane)) + 1;
        const top = (p.s - d) / 3600000 * 48, height = Math.max(20, (p.en - p.s) / 3600000 * 48 - 2);
        const c = this.colour(p.e.calendar);
        const blk = h("div", { class: "blk", style: { top: top + "px", height: height + "px", background: c, left: `calc(${(p.lane / width) * 100}% + 2px)`, width: `calc(${100 / width}% - 4px)`, right: "auto" }, title: `${p.e.title}\n${fmtRange(p.e)}` },
          h("b", {}, p.e.title || "(no title)"), height > 34 ? h("small", {}, fmtTime(evStart(p.e)) + (p.e.location ? " · " + p.e.location : "")) : null);
        blk.onclick = (ev) => { ev.stopPropagation(); this.details(p.e); };
        col.append(blk);
      }
      if (d.getTime() === today) {
        const now = new Date();
        col.append(h("div", { class: "now", style: { top: ((now - d) / 3600000 * 48) + "px" } }));
      }
      grid.append(col);
    }
    $("cal-grid").replaceChildren(grid);
    // Start the day at 7:30 (or the current time today).
    const now = new Date();
    $("cal-grid").scrollTop = (this.view !== "month" && start <= now && now < addDays(start, days) ? Math.max(0, now.getHours() - 2) : 7.5) * 48;
  },

  details(ev) {
    const cal = this.cals.find((c) => c.slug === ev.calendar) || {};
    const rows = [h("div", {}, "When"), h("div", {}, fmtRange(ev) + (ev.recurring ? " (repeats)" : ""))];
    if (ev.location) rows.push(h("div", {}, "Where"), h("div", {}, linkify(ev.location)));
    rows.push(h("div", {}, "Calendar"), h("div", {}, cal.name || ev.calendar));
    if (ev.organizer) rows.push(h("div", {}, "Organiser"), h("div", {}, ev.organizer.name || ev.organizer.email));
    if (ev.attendees && ev.attendees.length) rows.push(h("div", {}, "Guests"), h("div", {}, ev.attendees.map((a) => `${a.name || a.email} (${a.status})`).join(", ")));
    const acts = [];
    if (cal.write) {
      acts.push(h("button", { class: "btn danger", onclick: async () => {
        let occurrence = null;
        if (ev.recurring) {
          const which = await choose("Delete a repeating event", "Delete just this occurrence, or the whole series?", ["This one", "Whole series"]);
          if (which === null) return;
          if (which === 0) occurrence = ev.occurrence;
        } else if (!confirm(`Delete "${ev.title}"?` + (ev.attendees && ev.attendees.length && ev.organizer && ev.organizer.email === me.email.toLowerCase() ? " Guests will be told it's cancelled." : ""))) return;
        try { await call("DELETE", "cal/event?" + qs({ calendar: ev.calendar, id: ev.id, occurrence })); d.close(); this.render(); toast("Deleted"); } catch (e) { fail(e); }
      } }, "Delete"));
      acts.push(h("button", { class: "btn", onclick: () => { d.close(); this.edit(ev); } }, ev.recurring ? "Edit series" : "Edit"));
    }
    acts.push(h("button", { class: "btn ok", onclick: () => d.close() }, "Close"));
    const d = dialog(h("h2", {}, ev.title || "(no title)"), h("div", { class: "kv" }, rows),
      ev.description ? h("pre", { class: "body", style: { marginTop: "14px", color: "var(--muted)" } }, linkify(ev.description)) : null,
      h("div", { class: "acts" }, acts));
  },

  edit(ev, at, allday) {
    const writable = this.cals.filter((c) => c.write);
    if (!writable.length) { toast("You don't have a calendar you can add to.", { err: true }); return; }
    const s = ev ? evStart(ev) : at || new Date();
    const en = ev ? (ev.allday ? addDays(evEnd(ev), -1) : evEnd(ev)) : allday ? s : new Date(s.getTime() + 3600000);
    const title = h("input", { type: "text", value: ev ? ev.title : "", placeholder: "Add a title" });
    const calSel = h("select", {}, writable.map((c) => h("option", { value: c.slug }, c.name + (c.is_owner ? "" : ` (${c.owner})`))));
    if (ev) calSel.value = ev.calendar;
    calSel.disabled = !!ev;
    const ad = h("input", { type: "checkbox" }); ad.checked = ev ? ev.allday : !!allday;
    const sd = h("input", { type: "date", value: ymd(s) }), st = h("input", { type: "time", value: hm(s), step: 300 });
    const ed = h("input", { type: "date", value: ymd(en) }), et = h("input", { type: "time", value: hm(en), step: 300 });
    const times = [st, et];
    const syncAllDay = () => times.forEach((t) => t.classList.toggle("hidden", ad.checked));
    ad.onchange = syncAllDay; syncAllDay();
    // Moving the start keeps the length.
    let length = en - s;
    sd.onchange = st.onchange = () => {
      const ns = new Date(`${sd.value}T${st.value || "00:00"}`);
      const ne = new Date(ns.getTime() + (ad.checked ? Math.max(0, length) : length));
      ed.value = ymd(ne); et.value = hm(ne);
    };
    ed.onchange = et.onchange = () => { length = new Date(`${ed.value}T${et.value || "00:00"}`) - new Date(`${sd.value}T${st.value || "00:00"}`); };
    const rep = h("select", {}, [["none", "Does not repeat"], ["daily", "Every day"], ["weekdays", "Every weekday (Mon–Fri)"], ["weekly", "Every week"], ["monthly", "Every month"], ["yearly", "Every year"]].map(([v, l]) => h("option", { value: v }, l)));
    if (ev && ev.rrule) {
      const known = { "FREQ=DAILY": "daily", "FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR": "weekdays", "FREQ=WEEKLY": "weekly", "FREQ=MONTHLY": "monthly", "FREQ=YEARLY": "yearly" }[ev.rrule];
      if (known) rep.value = known; else { rep.prepend(h("option", { value: "keep" }, "Keep the current pattern (" + ev.rrule.toLowerCase() + ")")); rep.value = "keep"; }
    }
    const loc = h("input", { type: "text", value: ev ? ev.location : "", placeholder: "Add a place or a meeting link" });
    const guestsBox = h("div", { class: "chips" });
    const guests = chipInput(guestsBox, { placeholder: "Add people to invite" });
    const organiser = ev && ev.organizer && ev.organizer.email;
    const theirs = organiser && organiser !== me.email.toLowerCase();
    if (ev && ev.attendees) guests.set(ev.attendees.filter((a) => a.email !== me.email.toLowerCase()).map((a) => ({ name: a.name, email: a.email })));
    const desc = h("textarea", { placeholder: "Notes" }); desc.value = ev ? ev.description : "";
    const save = async () => {
      if (!title.value.trim()) { title.focus(); return; }
      const body = {
        calendar: calSel.value, id: ev ? ev.id : null, title: title.value, location: loc.value, description: desc.value,
        allday: ad.checked, start: ad.checked ? sd.value : `${sd.value}T${st.value}`, end: ad.checked ? ed.value : `${ed.value}T${et.value}`,
        tz: TZ, repeat: rep.value, attendees: theirs ? [] : guests.get(),
      };
      try {
        await call("POST", "cal/event", body);
        d.close(); this.render();
        toast(body.attendees.length ? "Saved, and invitations sent" : "Saved");
      } catch (e) { fail(e); }
    };
    const d = dialog(h("h2", {}, ev ? "Edit event" : "New event"),
      title,
      h("div", { class: "when" }, h("span", {}, "Starts"), sd, st), h("div", { class: "when" }, h("span", {}, "Ends"), ed, et),
      h("label", { class: "check" }, ad, "All day"),
      h("div", { class: "two" }, h("div", {}, h("label", {}, "Repeat"), rep), h("div", {}, h("label", {}, "Calendar"), calSel)),
      h("label", {}, "Location"), loc,
      theirs ? h("p", { class: "rcpt" }, `Organised by ${ev.organizer.name || organiser}.`) : [h("label", {}, "Invite"), guestsBox],
      h("label", {}, "Description"), desc,
      h("div", { class: "acts" }, h("button", { class: "btn", onclick: () => d.close() }, "Cancel"), h("button", { class: "btn ok", onclick: save }, "Save")));
    title.focus();
    title.onkeydown = (e) => { if (e.key === "Enter") save(); };
  },
};

function choose(title, text, options) {
  return new Promise((resolve) => {
    const d = dialog(h("h2", {}, title), h("p", {}, text),
      h("div", { class: "acts" }, h("button", { class: "btn", onclick: () => { d.close(); resolve(null); } }, "Cancel"),
        options.map((o, i) => h("button", { class: "btn" + (i === options.length - 1 ? " ok" : ""), onclick: () => { d.close(); resolve(i); } }, o))));
  });
}

function localStorageGet(k) { try { return localStorage.getItem(k); } catch (_) { return null; } }
function localStorageSet(k, v) { try { localStorage.setItem(k, v); } catch (_) {} }

$("c-today").onclick = () => { calendar.date = new Date(); calendar.render(); };
$("c-prev").onclick = () => { calendar.date = calendar.view === "month" ? new Date(calendar.date.getFullYear(), calendar.date.getMonth() - 1, 1) : addDays(calendar.date, calendar.view === "week" ? -7 : -1); calendar.render(); };
$("c-next").onclick = () => { calendar.date = calendar.view === "month" ? new Date(calendar.date.getFullYear(), calendar.date.getMonth() + 1, 1) : addDays(calendar.date, calendar.view === "week" ? 7 : 1); calendar.render(); };
for (const b of document.querySelectorAll("#c-views button")) b.onclick = () => { calendar.view = b.dataset.v; localStorageSet("pw-cal-view", calendar.view); calendar.render(); };
$("new-ev").onclick = () => { const d = new Date(); d.setMinutes(d.getMinutes() < 30 ? 30 : 60, 0, 0); calendar.edit(null, d, false); };
calendar.view = localStorageGet("pw-cal-view") || (window.innerWidth < 700 ? "day" : "week");

// ===================================================================== contacts

const contactsState = { books: [], list: [], book: null, search: "", current: null };
const contacts = {
  async load() {
    try {
      const r = await call("GET", "contacts");
      contactsState.books = r.books; contactsState.list = r.contacts;
      this.renderBooks(); this.renderList();
    } catch (e) { fail(e); }
  },
  renderBooks() {
    const items = [{ slug: null, name: "All contacts" }, ...contactsState.books];
    $("books").replaceChildren(...items.map((b) => {
      const n = b.slug ? contactsState.list.filter((c) => c.book === b.slug).length : contactsState.list.length;
      const li = h("li", { class: contactsState.book === b.slug ? "on" : "" }, h("span", {}, b.name), h("span", { class: "n" }, n));
      li.onclick = () => { contactsState.book = b.slug; this.renderBooks(); this.renderList(); document.body.classList.remove("side-open"); };
      return li;
    }));
  },
  renderList() {
    const s = contactsState.search.toLowerCase();
    const list = contactsState.list
      .filter((c) => !contactsState.book || c.book === contactsState.book)
      .filter((c) => !s || [c.name, c.org, ...c.emails.map((e) => e.value), ...c.phones.map((p) => p.value)].join(" ").toLowerCase().includes(s))
      .sort((a, b) => (a.name || "").localeCompare(b.name || "", LOCALE, { sensitivity: "base" }));
    if (!list.length) { $("ct-list").replaceChildren(h("div", { class: "empty" }, s ? "No contacts match." : "No contacts yet.")); return; }
    const out = [];
    let letter = null;
    for (const c of list) {
      const l = (c.name || "#")[0].toUpperCase();
      if (l !== letter) { letter = l; out.push(h("div", { class: "letter" }, l)); }
      const row = h("div", { class: "msg" + (contactsState.current === c ? " sel" : "") },
        h("div", { class: "avatar" }, initials(c.name)),
        h("div", { style: { minWidth: 0 } }, h("div", { class: "who" }, c.name || "(no name)"), h("div", { class: "prev" }, (c.emails[0] || {}).value || c.org || "")));
      row.onclick = () => { contactsState.current = c; this.renderList(); this.show(c); };
      out.push(row);
    }
    $("ct-list").replaceChildren(...out);
  },
  show(c) {
    document.body.classList.add("reading");
    const kids = [h("button", { class: "tool", id: "ct-back", onclick: () => document.body.classList.remove("reading"), style: { display: window.innerWidth <= 900 ? "inline-block" : "none" } }, "← Back"),
      h("div", { class: "hdr" }, h("div", { class: "avatar", style: { width: "56px", height: "56px", fontSize: "20px" } }, initials(c.name)),
        h("div", {}, h("h1", {}, c.name || "(no name)"), h("div", { class: "rcpt" }, [c.title, c.org].filter(Boolean).join(", ")), h("div", { class: "rcpt" }, c.book_name)))];
    const rows = [];
    for (const e of c.emails) rows.push(h("div", {}, "Email" + (e.type ? ` (${e.type})` : "")), h("div", {}, h("a", { href: "#", onclick: (ev) => { ev.preventDefault(); compose.open({ to: [{ name: c.name, email: e.value }] }); } }, e.value)));
    for (const p of c.phones) rows.push(h("div", {}, "Phone" + (p.type ? ` (${p.type})` : "")), h("div", {}, h("a", { href: "tel:" + p.value.replace(/[^\d+]/g, "") }, p.value)));
    if (c.address) rows.push(h("div", {}, "Address"), h("div", {}, c.address));
    if (c.note) rows.push(h("div", {}, "Notes"), h("div", { style: { whiteSpace: "pre-wrap" } }, c.note));
    kids.push(h("div", { class: "kv" }, rows));
    if (c.write) kids.push(h("div", { class: "acts", style: { display: "flex", gap: "8px", marginTop: "18px" } },
      h("button", { class: "btn", onclick: () => this.edit(c) }, "Edit"),
      h("button", { class: "btn", style: { color: "var(--err)" }, onclick: async () => {
        if (!confirm(`Delete ${c.name}?`)) return;
        try { await call("DELETE", "contacts?" + qs({ book: c.book, id: c.id })); contactsState.current = null; $("ct-detail").replaceChildren(h("div", { class: "empty" }, "Deleted.")); this.load(); } catch (e) { fail(e); }
      } }, "Delete")));
    $("ct-detail").replaceChildren(...kids);
  },
  edit(c) {
    const books = contactsState.books.filter((b) => b.write);
    if (!books.length) { toast("You don't have an address book you can change.", { err: true }); return; }
    const name = h("input", { type: "text", value: c ? c.name : "" });
    const emails = h("input", { type: "text", value: c ? c.emails.map((e) => e.value).join(", ") : "", placeholder: "Separate several with commas" });
    const phones = h("input", { type: "text", value: c ? c.phones.map((p) => p.value).join(", ") : "" });
    const org = h("input", { type: "text", value: c ? c.org : "" }), title = h("input", { type: "text", value: c ? c.title : "" });
    const note = h("textarea", {}); note.value = c ? c.note : "";
    const book = h("select", {}, books.map((b) => h("option", { value: b.slug }, b.name)));
    if (c) book.value = c.book; else if (contactsState.book && books.some((b) => b.slug === contactsState.book)) book.value = contactsState.book;
    book.disabled = !!c;
    const d = dialog(h("h2", {}, c ? "Edit contact" : "New contact"),
      h("label", {}, "Name"), name, h("label", {}, "Email"), emails, h("label", {}, "Phone"), phones,
      h("div", { class: "two" }, h("div", {}, h("label", {}, "Company"), org), h("div", {}, h("label", {}, "Job title"), title)),
      h("label", {}, "Notes"), note, h("label", {}, "Address book"), book,
      h("div", { class: "acts" }, h("button", { class: "btn", onclick: () => d.close() }, "Cancel"),
        h("button", { class: "btn ok", onclick: async () => {
          const split = (s) => s.split(/[,;]/).map((x) => x.trim()).filter(Boolean);
          try {
            const r = await call("POST", "contacts", { book: book.value, id: c ? c.id : null, name: name.value, emails: split(emails.value), phones: split(phones.value), org: org.value, title: title.value, note: note.value });
            d.close(); await this.load();
            const now = contactsState.list.find((x) => x.id === r.id && x.book === book.value);
            if (now) { contactsState.current = now; this.renderList(); this.show(now); }
          } catch (e) { fail(e); }
        } }, "Save")));
    name.focus();
  },
};
$("new-ct").onclick = () => contacts.edit(null);

// ===================================================== administrator notices

const dismissed = new Set();
function renderAlerts(list) {
  const box = $("banner");
  box.replaceChildren(...(list || []).filter((a) => !dismissed.has(a.text)).map((a) =>
    h("div", { class: "tip " + a.level, role: "status" }, "⚠ " + a.text,
      h("a", { href: a.link || "/admin" }, "Open in Administration →"),
      h("button", { title: "Hide for now", onclick: () => { dismissed.add(a.text); renderAlerts(list); } }, "×"))));
}

// ========================================================================= start

async function start() {
  try { me = await call("GET", "me"); } catch (_) { return; }
  $("me-btn").replaceChildren(h("span", { class: "full" }, me.name || me.email), h("span", { class: "init" }, initials(me.name || me.email.split("@")[0])));
  $("me-btn").title = me.email;
  if (me.is_admin) {
    $("admin-link").classList.remove("hidden");
    renderAlerts(me.alerts);
    setInterval(async () => { try { const m = await call("GET", "me"); renderAlerts(m.alerts); } catch (_) {} }, 60000);
  }
  const [app, arg] = location.hash.slice(1).split("/");
  if (app === "mail" && arg) mail.folder = decodeURIComponent(arg);
  await mail.loadFolders().catch(fail);
  if (!mail.folders.some((f) => f.name === mail.folder)) mail.folder = "INBOX";
  mail.loadList();
  show(["cal", "contacts"].includes(app) ? app : "mail");
  // New mail: refresh every minute (and when the tab comes back into view).
  const refresh = () => {
    if (document.hidden) return;
    mail.loadFolders().catch(() => {});
    if (state.app === "mail" && mail.page === 0 && !mail.search && !mail.selected.size) mail.loadList();
  };
  setInterval(refresh, 60000);
  document.addEventListener("visibilitychange", refresh);
}
start();
