"use strict";
const $ = (id) => document.getElementById(id);
let needCode = false;

function next() {
  const n = new URLSearchParams(location.search).get("next") || "/";
  // Only same-site paths.
  return n.startsWith("/") && !n.startsWith("//") && !n.startsWith("/\\") ? n : "/";
}

$("f").onsubmit = async (ev) => {
  ev.preventDefault();
  $("err").textContent = "";
  $("go").disabled = true;
  const body = { email: $("email").value.trim(), password: $("password").value, kind: "web" };
  if (needCode) body.code = $("code").value.trim();
  try {
    const r = await fetch("/api/v1/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(body),
    });
    const data = await r.json().catch(() => ({}));
    if (r.ok) { location.replace(next()); return; }
    if (data.mfa_required) {
      needCode = true;
      $("step1").classList.add("hidden");
      $("step2").classList.remove("hidden");
      $("sub").textContent = "Two-step verification";
      $("go").textContent = "Verify";
      $("code").focus();
      return;
    }
    $("err").textContent = data.error || "Sign-in failed";
    if (needCode) { $("code").value = ""; $("code").focus(); }
  } catch (e) {
    $("err").textContent = "Couldn't reach the server.";
  } finally {
    $("go").disabled = false;
  }
};
