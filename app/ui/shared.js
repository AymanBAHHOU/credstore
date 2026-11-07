// Helpers shared by the main page (app.js) and the island (island.js). Every string
// that came from an agent, the daemon or the policy file goes on the page as text,
// never as HTML.
"use strict";

/** Build an element; children are elements or strings (inserted as text). */
function el(tag, props = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    e.append(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return e;
}

/** Read a passphrase field and clear it at once. */
function take(input) {
  const v = input.value;
  input.value = "";
  return v;
}

/** The daemon omits empty lists; the pages expect them. */
function normalize(f) {
  for (const a of f.activity) a.secrets = a.secrets || [];
  if (f.policy) for (const r of f.policy.secrets) r.allow_hosts = r.allow_hosts || [];
  for (const r of f.pending) {
    r.secrets = r.secrets || [];
    r.not_enforced = r.not_enforced || [];
  }
  return f;
}

/**
 * Windows Hello as far as this vault is concerned:
 * "none" (no credstore key in Windows Hello), "unknown" (not connected yet),
 * "locked" (the vault is locked: Hello cannot confirm, and the list of trusted keys is
 * inside the vault), "enrolled" (this vault trusts the key), or "stale" (a key left
 * from an older vault, for example after a reinstall).
 */
function helloStateOf(overview, feed) {
  if (!overview || !overview.hello) return "none";
  if (!feed) return "unknown";
  if (feed.locked || !feed.approval_keys) return "locked";
  return feed.approval_keys.includes(overview.hello_key_id) ? "enrolled" : "stale";
}

const STALE_HELLO = "This vault does not trust the Windows Hello key on this computer (it was made for an older vault). Turn Windows Hello on again on the Security page to replace it.";
const LOCKED_HELLO = "The vault is locked, so Windows Hello cannot confirm. Enter your passphrase.";

/** Daemon errors about Hello, in plain words. */
function helloError(text) {
  if (/unknown key/.test(text)) return STALE_HELLO;
  return text;
}

/** Where a request's secret would go, in a few words: the host, or the program. */
function requestTarget(r) {
  if (r.http) {
    try {
      return new URL(r.http.url).host;
    } catch {
      return r.http.url;
    }
  }
  if (r.program) return r.program.split(/[\\/]/).pop();
  return r.command.split(/\s+/)[0];
}

/** The secrets' names without their descriptions ("NAME (description)"). */
function secretNames(r) {
  return r.secrets.map((s) => s.replace(/\s+\(.*\)$/, ""));
}
