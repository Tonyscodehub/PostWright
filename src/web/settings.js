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
    a.style.marginLeft = "16px";
    $("who").after(a);
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

load().catch((e) => flash("vacation-status", e.message, false));
