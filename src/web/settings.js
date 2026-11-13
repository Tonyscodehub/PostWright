"use strict";
const $ = (id) => document.getElementById(id);
let settings = null;

async function call(method, path, body) {
  const opts = { method, headers: { "X-Requested-With": "postwright" }, credentials: "same-origin" };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const r = await fetch("/api/v1/" + path, opts);
  if (r.status === 401) { location.replace("/login?next=" + encodeURIComponent(location.pathname)); throw new Error("signed out"); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

function flash(id, msg, ok) {
  const el = $(id);
  el.textContent = msg;
  el.className = "status " + (ok ? "ok" : "err");
  if (ok) setTimeout(() => { el.textContent = ""; }, 3000);
}

const toLocal = (ts) => {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
};
const fromLocal = (v) => (v ? Math.floor(new Date(v).getTime() / 1000) : null);

async function load() {
  const me = await call("GET", "me");
  $("who").textContent = me.email;
  if (me.is_admin) {
    const a = document.createElement("a");
    a.href = "/admin";
    a.textContent = "Administration";
    $("admin-link").append(a);
  }
  $("caldav-url").textContent = me.caldav;
  settings = await call("GET", "settings");
  const v = settings.vacation, s = settings.signature;
  $("v-enabled").checked = v.enabled;
  $("v-start").value = toLocal(v.start);
  $("v-end").value = toLocal(v.end);
  $("v-subject").value = v.subject;
  $("v-body").value = v.body;
  $("v-internal").checked = v.internal_only;
  $("s-text").value = s.text;
  $("s-html").value = s.html;
  $("s-append").checked = s.append;
  await loadCalendars(me.email);
  await Promise.all([loadMfa(), loadAppPasswords(), loadDevices(), loadShared()]);
}

async function save(statusId) {
  try {
    settings = await call("PUT", "settings", settings);
    flash(statusId, "Saved", true);
  } catch (e) { flash(statusId, e.message, false); }
}

$("save-vacation").onclick = () => {
  settings.vacation = {
    enabled: $("v-enabled").checked,
    start: fromLocal($("v-start").value),
    end: fromLocal($("v-end").value),
    subject: $("v-subject").value,
    body: $("v-body").value,
    internal_only: $("v-internal").checked,
  };
  save("vacation-status");
};

$("save-signature").onclick = () => {
  settings.signature = { text: $("s-text").value, html: $("s-html").value, append: $("s-append").checked };
  save("signature-status");
};

$("save-password").onclick = async () => {
  try {
    await call("POST", "password", { current: $("p-current").value, new: $("p-new").value });
    $("p-current").value = ""; $("p-new").value = "";
    flash("password-status", "Password changed. Update it in your mail apps too.", true);
  } catch (e) { flash("password-status", e.message, false); }
};

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

async function loadCalendars(me) {
  const cals = await call("GET", "calendars");
  const tbody = $("cal-rows");
  tbody.replaceChildren();
  for (const c of cals) {
    const tr = el("tr");
    const name = el("td");
    const sw = el("span", "", "swatch");
    sw.style.background = (c.color || "#2E7D32").slice(0, 7);
    name.append(sw, c.name);
    tr.append(name, el("td", c.is_owner ? "Me" : c.owner));
    const shares = el("td");
    if (c.is_owner) {
      for (const s of c.shares) {
        const line = el("div");
        line.append(`${s.user} (${s.write ? "can edit" : "view only"}) `);
        const rm = el("button", "Remove", "secondary");
        rm.onclick = async () => {
          try { await call("DELETE", `calendars/${encodeURIComponent(c.slug)}/shares/${encodeURIComponent(s.user)}`); loadCalendars(me); }
          catch (e) { flash("cal-status", e.message, false); }
        };
        line.append(rm);
        shares.append(line);
      }
      const form = el("div", undefined, "inline");
      const who = el("input"); who.type = "email"; who.placeholder = "colleague@yourdomain";
      const perm = el("select");
      perm.append(new Option("View only", "r"), new Option("Can edit", "w"));
      const add = el("button", "Share", "secondary");
      add.onclick = async () => {
        try { await call("POST", `calendars/${encodeURIComponent(c.slug)}/shares`, { user: who.value, write: perm.value === "w" }); loadCalendars(me); }
        catch (e) { flash("cal-status", e.message, false); }
      };
      form.append(who, perm, add);
      shares.append(form);
    } else {
      shares.textContent = c.write ? "Shared with me (can edit)" : "Shared with me (view only)";
    }
    tr.append(shares);
    const actions = el("td");
    const del = el("button", c.is_owner ? "Delete" : "Leave", "secondary");
    del.onclick = async () => {
      if (!confirm(c.is_owner ? `Delete "${c.name}" and all its events?` : `Stop seeing "${c.name}"?`)) return;
      try { await call("DELETE", `calendars/${encodeURIComponent(c.slug)}`); loadCalendars(me); }
      catch (e) { flash("cal-status", e.message, false); }
    };
    actions.append(del);
    tr.append(actions);
    tbody.append(tr);
  }
}

$("add-cal").onclick = async () => {
  const name = $("new-cal").value.trim();
  if (!name) return;
  try { await call("POST", "calendars", { name }); $("new-cal").value = ""; loadCalendars(); }
  catch (e) { flash("cal-status", e.message, false); }
};

// ------------------------------------------------------------ sign-in security
const when = (ts) => (ts ? new Date(ts * 1000).toLocaleString() : "never");

$("signout").onclick = async (ev) => {
  ev.preventDefault();
  await fetch("/api/v1/logout", { method: "POST", credentials: "same-origin" }).catch(() => {});
  location.replace("/login");
};

function showCodes(codes) {
  const list = $("mfa-code-list");
  list.replaceChildren(...codes.map((c) => el("div", c)));
  $("mfa-codes").classList.remove("hidden");
}

async function loadMfa() {
  const st = await call("GET", "mfa");
  $("mfa-badge").textContent = st.enabled ? "On" : "Off";
  $("mfa-badge").className = "badge" + (st.enabled ? " on" : "");
  $("mfa-off").classList.toggle("hidden", st.enabled);
  $("mfa-on").classList.toggle("hidden", !st.enabled);
  if (st.enabled) {
    $("mfa-info").textContent = `On since ${when(st.enabled_at)}. ${st.recovery_codes_left} unused recovery code${st.recovery_codes_left === 1 ? "" : "s"} left.`;
  }
}

$("mfa-start").onclick = async () => {
  try {
    const e = await call("POST", "mfa/setup", {});
    $("mfa-qr").src = "data:image/svg+xml;base64," + btoa(e.qr_svg);
    $("mfa-secret").textContent = e.secret.replace(/(.{4})/g, "$1 ").trim();
    $("mfa-enrol").classList.remove("hidden");
    $("mfa-start").classList.add("hidden");
    $("mfa-code").focus();
  } catch (e) { flash("mfa-status", e.message, false); }
};

$("mfa-confirm").onclick = async () => {
  try {
    const r = await call("POST", "mfa/confirm", { code: $("mfa-code").value });
    $("mfa-enrol").classList.add("hidden");
    $("mfa-start").classList.remove("hidden");
    $("mfa-code").value = "";
    showCodes(r.recovery_codes);
    await loadMfa();
    await loadDevices();
    flash("mfa-status", "Two-step verification is on", true);
  } catch (e) { flash("mfa-status", e.message, false); }
};

$("mfa-newcodes").onclick = async () => {
  try {
    const r = await call("POST", "mfa/recovery-codes", { code: $("mfa-dis-code").value });
    $("mfa-dis-code").value = "";
    showCodes(r.recovery_codes);
    await loadMfa();
  } catch (e) { flash("mfa-status", e.message === "that code isn't right" ? "Enter a current code from your app first" : e.message, false); }
};

$("mfa-disable").onclick = async () => {
  if (!confirm("Turn off two-step verification? Your account will be protected by your password only.")) return;
  try {
    await call("POST", "mfa/disable", { password: $("mfa-dis-pw").value, code: $("mfa-dis-code").value });
    $("mfa-dis-pw").value = ""; $("mfa-dis-code").value = "";
    $("mfa-codes").classList.add("hidden");
    await loadMfa();
    flash("mfa-status", "Two-step verification is off", true);
  } catch (e) { flash("mfa-status", e.message, false); }
};

async function loadAppPasswords() {
  const list = await call("GET", "app-passwords");
  const tbody = $("ap-rows");
  tbody.replaceChildren();
  if (!list.length) {
    const tr = el("tr"); const td = el("td", "None yet"); td.colSpan = 4; tr.append(td); tbody.append(tr);
  }
  for (const a of list) {
    const tr = el("tr");
    tr.append(el("td", a.name), el("td", when(a.created)), el("td", when(a.last_used)));
    const td = el("td");
    const rm = el("button", "Remove", "secondary");
    rm.onclick = async () => {
      if (!confirm(`Remove "${a.name}"? That app will stop being able to sign in.`)) return;
      try { await call("DELETE", `app-passwords/${a.id}`); loadAppPasswords(); }
      catch (e) { flash("ap-status", e.message, false); }
    };
    td.append(rm); tr.append(td); tbody.append(tr);
  }
}

$("ap-add").onclick = async () => {
  try {
    const r = await call("POST", "app-passwords", { name: $("ap-name").value });
    $("ap-name").value = "";
    $("ap-pw").textContent = r.password;
    $("ap-new").classList.remove("hidden");
    loadAppPasswords();
  } catch (e) { flash("ap-status", e.message, false); }
};

const kindName = { web: "Browser", app: "Postwright Admin app", device: "Mail app" };

async function loadDevices() {
  const list = await call("GET", "devices");
  const tbody = $("dev-rows");
  tbody.replaceChildren();
  for (const d of list) {
    const tr = el("tr");
    const what = el("td", d.name || kindName[d.kind] || d.kind);
    if (d.name) what.append(el("span", kindName[d.kind] || d.kind, "badge"));
    if (d.current) what.append(el("span", "this browser", "badge on"));
    tr.append(what, el("td", when(d.created)), el("td", when(d.last_seen)));
    const td = el("td");
    if (!d.current) {
      const rm = el("button", "Sign out", "secondary");
      rm.onclick = async () => {
        try { await call("DELETE", `devices/${d.id}`); loadDevices(); }
        catch (e) { flash("dev-status", e.message, false); }
      };
      td.append(rm);
    }
    tr.append(td); tbody.append(tr);
  }
}

const accessName = { none: "–", read: "Read only", full: "Full access" };
const sendName = { none: "–", on_behalf: "On behalf of", as: "Send as" };

async function loadShared() {
  const list = await call("GET", "shared");
  $("shared-section").classList.toggle("hidden", !list.length);
  const tbody = $("sh-rows");
  tbody.replaceChildren();
  for (const d of list) {
    const tr = el("tr");
    tr.append(el("td", d.owner), el("td", accessName[d.mailbox]), el("td", sendName[d.send]));
    tbody.append(tr);
  }
}

load().catch((e) => flash("vacation-status", e.message, false));
