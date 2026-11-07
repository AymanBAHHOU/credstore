// credstore desktop app page. Every string that came from an agent, the daemon or the
// policy file is put on the page with textContent, never as HTML. Passphrase fields are
// never pre-filled and are cleared as soon as they are read.
"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);

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

function icon(id, size = 14) {
  const ns = "http://www.w3.org/2000/svg";
  const s = document.createElementNS(ns, "svg");
  s.setAttribute("width", size);
  s.setAttribute("height", size);
  s.setAttribute("aria-hidden", "true");
  const u = document.createElementNS(ns, "use");
  u.setAttribute("href", "#" + id);
  s.append(u);
  return s;
}

function say(target, text, ok) {
  const m = typeof target === "string" ? $(target) : target;
  m.textContent = text || "";
  m.className = m.className.replace(/\b(ok|bad)\b/g, "").trim() + (ok === undefined ? "" : ok ? " ok" : " bad");
}

function take(input) {
  const v = input.value;
  input.value = "";
  return v;
}

function plural(n, one, many) {
  return `${n} ${n === 1 ? one : many}`;
}

function duration(secs) {
  if (secs === 0) return "0";
  if (secs % 3600 === 0) return plural(secs / 3600, "hour", "hours");
  if (secs % 60 === 0) return plural(secs / 60, "minute", "minutes");
  return plural(secs, "second", "seconds");
}

function when(ts) {
  const d = new Date(ts);
  if (isNaN(d)) return ts;
  const time = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
  const today = new Date().toDateString() === d.toDateString();
  return today ? time : `${d.toLocaleDateString([], { month: "short", day: "numeric" })} ${time}`;
}

// ------------------------------------------------------------------ state

let overview = null;      // what `overview` returned
let feed = null;          // the last `feed` event, while watching
let watching = false;
let selected = null;      // secret shown on the Secrets page
const drafts = new Map(); // secret name -> {hosts, commands} not saved yet
const dismissed = new Set();
let activityFilter = "all";

// ------------------------------------------------------------------ navigation

function show(mod) {
  for (const m of document.querySelectorAll(".module")) m.hidden = m.id !== "m-" + mod;
  for (const b of document.querySelectorAll(".nav button")) {
    if (b.dataset.mod === mod) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  }
  window.scrollTo(0, 0);
  if (mod === "claude") refreshClaude();
}

function current() {
  const m = document.querySelector(".module:not([hidden])");
  return m ? m.id.slice(2) : "approvals";
}

for (const b of document.querySelectorAll(".nav button")) b.addEventListener("click", () => show(b.dataset.mod));
for (const b of document.querySelectorAll("[data-goto]")) b.addEventListener("click", () => show(b.dataset.goto));

// ------------------------------------------------------------------ passphrase dialog

/**
 * Ask for the passphrase, then run `action(pass)`. The dialog stays open while
 * `action` returns an error message, so a typo can be fixed. Resolves true if done.
 */
function ask(title, text, action, { allowEmpty = false, okLabel = "Confirm" } = {}) {
  return new Promise((resolve) => {
    const dlg = $("ask");
    $("ask-title").textContent = title;
    $("ask-text").textContent = text;
    $("ask-ok").textContent = okLabel;
    $("ask-pass").placeholder = allowEmpty ? "Passphrase, or leave empty for Windows Hello" : "Passphrase";
    say("ask-msg", "");
    const form = $("ask-form");
    const finish = (ok) => {
      form.onsubmit = null;
      dlg.onclose = null;
      $("ask-cancel").onclick = null;
      $("ask-pass").value = "";
      if (dlg.open) dlg.close();
      resolve(ok);
    };
    form.onsubmit = async (ev) => {
      ev.preventDefault();
      const pass = take($("ask-pass"));
      if (!pass && !allowEmpty) return say("ask-msg", "Enter your passphrase.", false);
      $("ask-ok").classList.add("busy");
      say("ask-msg", pass ? "Checking…" : "Confirm with Windows Hello…");
      try {
        const problem = await action(pass);
        if (problem) say("ask-msg", problem, false);
        else finish(true);
      } catch (e) {
        say("ask-msg", String(e), false);
      } finally {
        $("ask-ok").classList.remove("busy");
      }
    };
    dlg.onclose = () => finish(false);
    $("ask-cancel").onclick = () => finish(false);
    dlg.showModal();
    $("ask-pass").focus();
  });
}

// ------------------------------------------------------------------ overview and top bar

async function refresh() {
  const o = await invoke("overview");
  overview = o;
  const dot = $("service-dot");
  if (o.reachable) {
    $("service-text").textContent = o.mode === "dev" ? "Dev mode" : "Service running";
    dot.className = "dot on";
    $("service-pill").title = `${o.mode === "dev" ? "Dev mode: no separate account, weaker" : "Installed"} · ${o.os} · v${o.version}`;
  } else {
    $("service-text").textContent = "Not connected";
    dot.className = "dot red";
    $("service-pill").title = "";
  }
  $("unreachable").hidden = o.reachable;
  $("unreachable-detail").textContent = o.error || "";
  renderAll();
  return o;
}

$("retry").addEventListener("click", refresh);

function renderTop() {
  const pending = feed ? feed.pending.length : 0;
  $("badge").hidden = pending === 0;
  $("badge").textContent = String(pending);
  $("vault-pill").hidden = !feed;
  $("lock").hidden = !feed || feed.locked;
  if (feed) {
    $("vault-dot").className = feed.locked ? "dot" : "dot on";
    $("vault-text").textContent = feed.locked ? "Vault locked" : "Vault open";
    const p = feed.policy;
    $("vault-pill").title = feed.locked
      ? "The next approval unlocks it with your passphrase"
      : p ? `Locks after ${duration(p.session_idle_secs)} unused` : "";
  }
}

$("lock").addEventListener("click", () =>
  ask("Lock the vault", "Secrets are wiped from the service's memory. The next approval needs your passphrase.",
    async (pass) => { await invoke("lock", { passphrase: pass }); return null; }, { okLabel: "Lock" }));

function renderAll() {
  renderTop();
  renderConnect();
  renderApprovals();
  renderActivity();
  renderSecrets();
  renderSecurity();
}

// ------------------------------------------------------------------ connecting (the feed)

function renderConnect() {
  const need = overview && overview.reachable && !watching;
  for (const slot of document.querySelectorAll(".connect-slot")) {
    const onSecrets = slot.closest("#m-secrets");
    const want = need && (!onSecrets || (overview.secrets.length > 0));
    if (!want) {
      slot.replaceChildren();
      continue;
    }
    if (slot.firstElementChild) {
      slot.querySelector(".hello-btn").hidden = !overview.hello;
      continue;
    }
    const form = $("connect-tpl").content.firstElementChild.cloneNode(true);
    const pass = form.querySelector("input");
    const msg = form.querySelector(".msg");
    const helloBtn = form.querySelector(".hello-btn");
    helloBtn.hidden = !overview.hello;
    const go = async (passphrase) => {
      say(msg, passphrase ? "Connecting…" : "Confirm with Windows Hello…");
      for (const b of form.querySelectorAll(".btn")) b.classList.add("busy");
      try {
        await invoke("start_watching", { passphrase });
        watching = true;
        say(msg, "");
        renderAll();
      } catch (e) {
        let text = helloError(String(e));
        if (!passphrase && /locked/i.test(text)) text = "Windows Hello works while the vault is unlocked. Use your passphrase this time.";
        say(msg, text, false);
      } finally {
        for (const b of form.querySelectorAll(".btn")) b.classList.remove("busy");
      }
    };
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      const p = take(pass);
      if (!p) return say(msg, "Enter your passphrase, or use Windows Hello.", false);
      go(p);
    });
    helloBtn.addEventListener("click", () => go(""));
    slot.replaceChildren(form);
  }
}

/** The daemon leaves out empty lists; fill them in once here. */
function normalize(f) {
  for (const a of f.activity) a.secrets = a.secrets || [];
  if (f.policy) for (const r of f.policy.secrets) r.allow_hosts = r.allow_hosts || [];
  return f;
}

/**
 * Windows Hello as far as this vault is concerned:
 * "none" (no credstore key in Windows Hello), "unknown" (not connected yet),
 * "locked" (the vault is locked: Hello cannot confirm, and the list of trusted keys is
 * inside the vault), "enrolled" (this vault trusts the key), or "stale" (a key left
 * from an older vault, for example after a reinstall).
 */
function helloState() {
  if (!overview || !overview.hello) return "none";
  if (!feed) return "unknown";
  if (feed.locked || !feed.approval_keys) return "locked";
  return feed.approval_keys.includes(overview.hello_key_id) ? "enrolled" : "stale";
}

const STALE_HELLO = "This vault does not trust the Windows Hello key on this computer (it was made for an older vault). Turn Windows Hello on again on the Security page to replace it.";

/** Daemon errors about Hello, in plain words. */
function helloError(text) {
  if (/unknown key/.test(text)) return STALE_HELLO;
  return text;
}

listen("feed", (event) => {
  feed = normalize(event.payload);
  watching = true;
  renderAll();
});

listen("watch-ended", (event) => {
  watching = false;
  feed = null;
  renderAll();
  const slot = document.querySelector("#m-approvals .connect-slot .msg");
  if (slot) say(slot, "Stopped receiving requests: " + event.payload, false);
  refresh();
});

// ------------------------------------------------------------------ approvals

const cards = new Map(); // request id -> card element

function renderApprovals() {
  const list = feed ? feed.pending : [];
  const box = $("requests");
  for (const [id, card] of cards) {
    if (!list.some((r) => r.id === id)) {
      card.remove();
      cards.delete(id);
    }
  }
  for (const r of list) {
    if (!cards.has(r.id)) {
      const card = requestCard(r);
      cards.set(r.id, card);
      box.append(card);
    }
  }
  $("idle").hidden = !feed || list.length > 0;
  renderRefused();
}

function kvRows(r) {
  const code = (text, cls = "") => el("span", { class: "code " + cls }, text);
  const note = (text) => el("span", { class: "note" }, text);
  const rows = [
    ["Reason", [el("span", { class: "reason" }, `“${r.reason}”`),
      note("Written by the agent. It explains the request; it does not authorize it.")]],
  ];
  if (r.http) {
    rows.push(
      ["Request", [code(r.http.method, "em"), " ", code(r.http.url)]],
      ["Secret", [code(r.secrets.join(", "), "em"), note("credstore sends it; the agent never sees it.")]],
      ["Header", code(r.http.secret_header)],
      ["Other headers", r.http.headers.length ? code(r.http.headers.join("\n")) : null],
      ["Body", r.http.body ? code(r.http.body) : null],
      ["Hosts", r.network],
    );
  } else {
    rows.push(
      [r.is_shell ? "Shell" : "Command", code(r.command, "em")],
      ["Program", r.program ? code(r.program) : null],
      ["Folder", r.cwd ? code(r.cwd) : null],
      ["Secrets", [code(r.secrets.join(", "), "em"), note(`Given to the command as ${r.injection}.`)]],
      ["Sandbox", [r.sandbox, ...r.not_enforced.map((g) => el("span", { class: "gap-line" }, "Not enforced: " + g))]],
      ["Network", r.network],
    );
  }
  rows.push(["Asked by", r.from]);
  return rows.filter(([, v]) => v !== null && v !== "" && v !== undefined);
}

function requestCard(r) {
  const dl = el("dl", { class: "kv" },
    kvRows(r).flatMap(([k, v]) => [el("dt", { class: "label" }, k), el("dd", {}, v)]));
  const hello = helloState() === "enrolled";
  const pass = el("input", {
    class: "input", type: "password", autocomplete: "off", "aria-label": "Passphrase",
    placeholder: hello ? "Passphrase, or leave empty for Windows Hello" : "Passphrase to confirm",
  });
  const msg = el("p", { class: "msg" });
  const buttons = [];
  const decide = async (decision, label) => {
    if (!pass.value) {
      const h = helloState();
      if (h === "stale") return say(msg, STALE_HELLO, false);
      if (h === "locked") return say(msg, "The vault is locked, so Windows Hello cannot confirm. Enter your passphrase.", false);
      if (h !== "enrolled") return say(msg, "Enter your passphrase to confirm.", false);
    }
    const p = take(pass);
    say(msg, p ? "Checking…" : "Confirm with Windows Hello…");
    buttons.forEach((b) => b.classList.add("busy"));
    try {
      const out = await invoke("decide", { id: r.id, decision, passphrase: p });
      if (out.kind === "done") {
        msg.replaceChildren(el("span", { class: "tag " + (decision.kind === "deny" ? "no" : "ok") }, label));
        return;
      }
      if (out.kind === "wrong_passphrase") say(msg, "Wrong passphrase. The request is still waiting.", false);
      else if (!p && /locked/i.test(out.message)) say(msg, "The vault is locked, so Windows Hello cannot confirm. Enter your passphrase.", false);
      else say(msg, helloError(out.message), false);
    } catch (e) {
      say(msg, helloError(String(e)), false);
    }
    buttons.forEach((b) => b.classList.remove("busy"));
  };
  const deny = el("button", { class: "btn", "data-key": "d", onclick: () => decide({ kind: "deny" }, "denied") },
    "Deny ", el("kbd", {}, "D"));
  buttons.push(deny);
  if (r.max_grant_secs > 0) {
    buttons.push(el("button", { class: "btn", onclick: () => decide({ kind: "session", ttl_secs: r.max_grant_secs }, `approved for ${r.max_grant}`) },
      `Approve for ${r.max_grant}`));
  }
  buttons.push(el("button", { class: "btn primary", "data-key": "a", onclick: () => decide({ kind: "once" }, "approved once") },
    "Approve once ", el("kbd", {}, "A")));
  return el("article", { class: "box request", "aria-label": "Request " + r.id },
    el("div", { class: "req-band" }, el("b", {}, "Waiting for you"),
      el("div", { class: "meta" }, el("span", {}, r.http ? "http_request" : "run_with_secrets"), el("span", {}, r.id))),
    dl,
    el("div", { class: "decide" }, pass, ...buttons, msg));
}

document.addEventListener("keydown", (e) => {
  if (e.ctrlKey || e.metaKey || e.altKey) return;
  const t = e.target instanceof Element ? e.target : document.body;
  if (t.closest("input, select, textarea, dialog") || current() !== "approvals") return;
  const key = e.key.toLowerCase();
  if (key !== "a" && key !== "d") return;
  const first = $("requests").querySelector(".request");
  const b = first && first.querySelector(`[data-key="${key}"]`);
  if (b) {
    e.preventDefault();
    b.click();
  }
});

// Requests refused by policy in the last hour, with the fix.
function renderRefused() {
  const box = $("refused");
  if (!feed) return box.replaceChildren();
  const hour = Date.now() - 3600 * 1000;
  const recent = feed.activity
    .filter((a) => a.outcome === "refused" && !dismissed.has(a.id) && new Date(a.ts).getTime() > hour)
    .slice(0, 3);
  box.replaceChildren(...recent.map(refusedNotice));
}

/** The policy's reason, in plain words where it is a common one. */
function plainReason(a) {
  const d = a.detail || "";
  if (/needs the hosts .* may be sent to/.test(d)) return "this secret has no allowed hosts.";
  const m = d.match(/may not be sent to (\S+) \(allowed: (.*)\)/);
  if (m) return `it may only be sent to ${m[2]}.`;
  if (/no valid policy is loaded/.test(d)) return "the policy file has an error, so every request is refused until it is fixed.";
  return d;
}

function refusedNotice(a) {
  const name = a.secrets[0] || "";
  const what = a.kind === "http"
    ? ["A request to send ", el("span", { class: "mono" }, name), " to ", el("span", { class: "mono" }, a.host || "?"), " was blocked before reaching you: "]
    : ["A command using ", el("span", { class: "mono" }, a.secrets.join(", ")), " was blocked before reaching you: "];
  const msg = el("p", { class: "msg" });
  const acts = [el("button", { class: "btn sm", onclick: () => { dismissed.add(a.id); renderRefused(); } }, "Dismiss")];
  const fix = fixButton(a, msg, "btn sm primary");
  acts.push(fix || el("button", { class: "btn sm primary", onclick: () => openSecret(name) }, "Open its rules"));
  return el("article", { class: "box notice" },
    el("span", { class: "dot ring" }),
    el("p", {}, el("strong", {}, `Refused by policy at ${when(a.ts)}.`), " ", ...what, plainReason(a)),
    el("div", { class: "acts" }, acts),
    msg);
}

/** "Allow HOST" for a refused HTTP request, if the policy can be changed from here. */
function fixButton(a, msg, cls) {
  const p = feed && feed.policy;
  const name = a.secrets[0];
  if (a.kind !== "http" || !a.host || !name || !p || !p.editable) return null;
  const rules = p.secrets.find((s) => s.name === name);
  const hosts = rules ? rules.allow_hosts : [];
  if (hosts.includes(a.host)) return null;
  return el("button", {
    class: cls,
    onclick: () => ask(`Allow ${a.host}`,
      `${name} may then be sent to ${a.host} when an agent asks, and you still approve each request.`,
      async (pass) => {
        await invoke("set_secret_rules", { name, allowHosts: [...hosts, a.host], allowCommands: null, passphrase: pass });
        dismissed.add(a.id);
        const where = current() === "approvals" ? "approvals-msg" : msg;
        say(where, `${a.host} is now allowed for ${name}. Ask the agent to try again.`, true);
        return null;
      }, { okLabel: "Allow" }),
  }, "Allow this host");
}

// ------------------------------------------------------------------ activity

const TAGS = {
  waiting: ["", "waiting"],
  running: ["ok", "approved"],
  refused: ["ref", "refused"],
  denied: ["no", "denied"],
  changed: ["", "changed"],
};

function outcomeTag(a) {
  if (a.kind === "auth") return el("span", { class: "tag ref" }, "failed check");
  if ((a.outcome === "ok" || a.outcome === "failed") && a.via) {
    const label = { human: "approved", grant: "approved (for a while)", policy: "no approval needed", admin: "run by you" }[a.via] || "approved";
    return el("span", { class: "tag ok" }, label);
  }
  if (a.outcome === "failed") return el("span", { class: "tag ref" }, "failed");
  if (a.outcome === "ok") return el("span", { class: "tag ok" }, "done");
  const [cls, text] = TAGS[a.outcome] || ["", a.outcome];
  return el("span", { class: "tag " + cls }, text);
}

function matches(a) {
  switch (activityFilter) {
    case "approved": return !!a.via;
    case "denied": return a.outcome === "denied";
    case "refused": return a.outcome === "refused";
    case "changes": return a.kind === "vault" || a.kind === "policy" || a.kind === "auth";
    default: return true;
  }
}

function renderActivity() {
  $("activity-body").hidden = !feed;
  if (!feed) return;
  const rows = feed.activity.filter(matches).map((a) => {
    const reason = a.outcome === "refused" ? plainReason(a) : a.detail;
    const sub = [reason && reason[0].toUpperCase() + reason.slice(1), a.cwd].filter(Boolean).join(" · ");
    const msg = el("p", { class: "msg" });
    const fix = a.outcome === "refused" ? fixButton(a, msg, "btn sm fix") : null;
    return el("tr", {},
      el("td", { class: "t" }, when(a.ts)),
      el("td", {}, outcomeTag(a)),
      el("td", {}, el("span", { class: a.kind === "run" || a.kind === "http" ? "mono" : "" }, a.summary),
        sub ? el("span", { class: "sub" }, sub) : null, fix, msg),
      el("td", { class: "mono" }, a.secrets.join(", ")));
  });
  $("activity-rows").replaceChildren(...rows);
  $("activity-empty").hidden = rows.length > 0;
}

$("activity-filter").addEventListener("click", (e) => {
  const b = e.target.closest(".seg");
  if (!b) return;
  activityFilter = b.dataset.f;
  for (const s of $("activity-filter").querySelectorAll(".seg")) s.setAttribute("aria-pressed", String(s === b));
  renderActivity();
});

// ------------------------------------------------------------------ secrets

function rulesFor(name) {
  const p = feed && feed.policy;
  return p ? p.secrets.find((s) => s.name === name) || null : null;
}

function draftFor(name) {
  if (drafts.has(name)) return drafts.get(name);
  const r = rulesFor(name);
  return { hosts: r ? [...r.allow_hosts] : [], commands: r && r.allow_commands ? [...r.allow_commands] : [] };
}

function changes(name) {
  if (!drafts.has(name)) return 0;
  const r = rulesFor(name);
  const d = drafts.get(name);
  const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
  let n = 0;
  if (!same(d.hosts, r ? r.allow_hosts : [])) n++;
  if (!same(d.commands, r && r.allow_commands ? r.allow_commands : [])) n++;
  return n;
}

function openSecret(name) {
  selected = name;
  show("secrets");
  renderSecrets(true);
}

let detailKey = "";

function renderSecrets(force = false) {
  const o = overview;
  if (!o) return;
  const secrets = o.secrets;
  $("vault-form").hidden = !o.reachable || secrets.length > 0;
  $("no-secrets").hidden = !o.reachable || secrets.length > 0;
  $("secrets-split").hidden = secrets.length === 0;
  if (!secrets.some((s) => s.name === selected)) selected = secrets.length ? secrets[0].name : null;

  $("secret-list").replaceChildren(...secrets.map((s) => {
    const r = rulesFor(s.name);
    let line;
    if (!r) line = [el("span", { class: "dot" }), feed ? "follows the defaults" : "connect to see its rules"];
    else if (r.network === "deny") line = [el("span", { class: "dot" }), "network denied"];
    else if (r.allow_hosts.length) line = [el("span", { class: "dot on" }), plural(r.allow_hosts.length, "allowed host", "allowed hosts")];
    else line = [el("span", { class: "dot ring" }), "no allowed hosts"];
    return el("button", {
      class: "srow", "aria-current": s.name === selected ? "true" : "false",
      onclick: () => { selected = s.name; renderSecrets(true); },
    }, el("div", { class: "n" }, s.name), s.description ? el("div", { class: "d" }, s.description) : null, el("div", { class: "h" }, line));
  }));

  // Rebuild the detail only when what it shows changed, so typing is not interrupted.
  const key = JSON.stringify([selected, rulesFor(selected), !!feed, feed && feed.policy && feed.policy.editable, drafts.get(selected)]);
  if (!force && key === detailKey) return;
  detailKey = key;
  $("secret-detail").replaceChildren(...(selected ? secretDetail(secrets.find((s) => s.name === selected)) : []));
}

function chipList(items, onRemove, emptyText) {
  if (!items.length) return el("div", { class: "chips" }, el("span", { class: "chip muted" }, emptyText));
  return el("div", { class: "chips" }, items.map((h, i) =>
    el("span", { class: "chip" }, el("span", { title: h }, h),
      onRemove ? el("button", { type: "button", "aria-label": "Remove " + h, onclick: () => onRemove(i) }, icon("i-x", 12)) : null)));
}

function secretDetail(s) {
  const name = s.name;
  const r = rulesFor(name);
  const p = feed && feed.policy;
  const editable = !!(p && p.editable);
  const d = draftFor(name);
  const edit = (f) => {
    const next = { hosts: [...d.hosts], commands: [...d.commands] };
    f(next);
    drafts.set(name, next);
    if (!changes(name)) drafts.delete(name);
    renderSecrets(true);
  };

  const about = el("div", { class: "sec" },
    el("div", { class: "grid2" },
      el("div", {}, el("span", { class: "label field-l" }, "Name"), el("input", { class: "input mono", value: name, readonly: true, "aria-label": "Name" })),
      el("div", {}, el("span", { class: "label field-l" }, "Description · agents see this"),
        el("input", { class: "input", value: s.description || "", readonly: true, "aria-label": "Description", placeholder: "No description" }))),
    el("div", { class: "gap-top" }, el("span", { class: "label field-l" }, "Value"),
      el("div", { class: "value" }, el("span", {}, "stored · never shown"),
        el("button", { class: "btn sm", type: "button", onclick: () => openSecretForm(s) }, "Replace value"))));

  const parts = [about];
  if (!feed) {
    parts.push(el("div", { class: "sec" }, el("h2", {}, "Where it may be used"),
      el("p", { class: "help" }, "Connect above to see and change the hosts and commands this secret is allowed with.")));
  } else {
    const hostInput = el("input", { class: "input mono", placeholder: "api.example.com, *.example.com or host:8443", "aria-label": "Add a host", spellcheck: "false", disabled: !editable });
    const cmdInput = el("input", { class: "input mono", placeholder: "curl *api.example.com*", "aria-label": "Add a command pattern", spellcheck: "false", disabled: !editable });
    const add = (input, list) => (ev) => {
      ev.preventDefault();
      const v = input.value.trim();
      if (!v) return;
      edit((n) => { const l = n[list]; if (!l.includes(v)) l.push(list === "hosts" ? v.toLowerCase() : v); });
    };
    const denied = r && r.network === "deny" && !d.hosts.length;
    parts.push(
      el("div", { class: "sec" },
        el("h2", {}, "Where it may be sent"),
        el("p", { class: "help" }, "credstore sends this secret only to these hosts when an agent asks for an HTTPS request. Setting hosts also limits the network of commands that use it to them, where the sandbox can enforce that."),
        chipList(d.hosts, editable ? (i) => edit((n) => n.hosts.splice(i, 1)) : null,
          denied ? "network denied by the policy file" : "no hosts: HTTPS requests with it are refused"),
        el("form", { class: "addhost", onsubmit: add(hostInput, "hosts") }, hostInput, el("button", { class: "btn", disabled: !editable }, "Add"))),
      el("div", { class: "sec" },
        el("h2", {}, "Commands it may run with"),
        el("p", { class: "help" }, "Empty means any command you approve. A pattern like curl *api.example.com* refuses everything else before it reaches you."),
        chipList(d.commands, editable ? (i) => edit((n) => n.commands.splice(i, 1)) : null, "any command you approve"),
        el("form", { class: "addhost", onsubmit: add(cmdInput, "commands") }, cmdInput, el("button", { class: "btn", disabled: !editable }, "Add"))));
    if (r && r.allow_dirs) {
      parts.push(el("div", { class: "sec" }, el("h2", {}, "Folders"),
        el("p", { class: "help" }, "Set in the policy file. Requests from other folders are refused."),
        chipList(r.allow_dirs, null, "")));
    }
    const n = changes(name);
    if (!editable) {
      parts.push(el("p", { class: "readonly-note" }, `On this system the policy file belongs to root: edit ${p ? p.path : "it"} with sudo, then run credstore reload.`));
    } else if (n) {
      const pass = el("input", { class: "input", type: "password", autocomplete: "off", placeholder: "Passphrase to save", "aria-label": "Passphrase to save" });
      const msg = el("span", { class: "grow msg" }, el("span", { class: "dot red" }), plural(n, "unsaved change", "unsaved changes"));
      const save = el("button", { class: "btn primary" }, "Save");
      parts.push(el("form", {
        class: "savebar",
        onsubmit: async (ev) => {
          ev.preventDefault();
          const passphrase = take(pass);
          if (!passphrase) return say(msg, "Enter your passphrase to save.", false);
          save.classList.add("busy");
          try {
            await invoke("set_secret_rules", { name, allowHosts: d.hosts, allowCommands: d.commands, passphrase });
            drafts.delete(name);
            say("secrets-msg", `Saved the rules for ${name}.`, true);
            renderSecrets(true);
          } catch (e) {
            say(msg, String(e), false);
          }
          save.classList.remove("busy");
        },
      }, msg, pass, el("button", { class: "btn", type: "button", onclick: () => { drafts.delete(name); renderSecrets(true); } }, "Discard"), save));
    }
  }

  return [
    el("div", { class: "box" }, parts),
    el("div", { class: "danger-zone" },
      el("span", {}, "Remove ", el("span", { class: "mono" }, name), " from the vault. Agents using it will start failing."),
      el("button", {
        class: "btn sm danger",
        onclick: () => ask(`Remove ${name}`, "The value is deleted from the vault. This cannot be undone.", async (pass) => {
          await invoke("remove_secret", { name, passphrase: pass });
          drafts.delete(name);
          say("secrets-msg", `Removed ${name}.`, true);
          await refresh();
          return null;
        }, { okLabel: "Remove" }),
      }, "Remove secret")),
  ];
}

function openSecretForm(existing) {
  const f = $("secret-form");
  f.hidden = false;
  $("secret-form-title").textContent = existing ? `Replace ${existing.name}` : "Add a secret";
  $("secret-name").value = existing ? existing.name : "";
  $("secret-name").readOnly = !!existing;
  $("secret-desc").value = existing ? existing.description || "" : "";
  $("secret-value").value = "";
  say("secret-msg", "");
  (existing ? $("secret-value") : $("secret-name")).focus();
}

$("add-secret").addEventListener("click", () => openSecretForm(null));
$("secret-cancel").addEventListener("click", () => {
  $("secret-value").value = "";
  $("secret-pass").value = "";
  $("secret-form").hidden = true;
});

$("secret-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const name = $("secret-name").value.trim();
  const description = $("secret-desc").value.trim() || null;
  const value = take($("secret-value"));
  const pass = take($("secret-pass"));
  try {
    const saved = await invoke("set_secret", { name, description, value, passphrase: pass });
    $("secret-form").hidden = true;
    selected = name;
    say("secrets-msg",
      saved.too_short_to_redact
        ? `Saved ${name}. It is too short to redact safely, so it will not be masked in command output.`
        : `Saved ${name}. Tell your agent to use it by name.`,
      !saved.too_short_to_redact);
    await refresh();
  } catch (e) {
    say("secret-msg", String(e), false);
  }
});

$("vault-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const pass = take($("vault-pass"));
  const repeat = take($("vault-repeat"));
  try {
    const created = await invoke("create_vault", { passphrase: pass, repeat });
    say("vault-msg", created ? "Vault created. Add your first secret." : "A vault already exists; nothing changed.", true);
    if (created) openSecretForm(null);
  } catch (e) {
    say("vault-msg", String(e), false);
  }
});

// ------------------------------------------------------------------ security

const TIMER_CHOICES = {
  session_idle_secs: [[0, "every request"], [300, "5 minutes"], [600, "10 minutes"], [1800, "30 minutes"], [3600, "1 hour"]],
  grant_ttl_secs: [[0, "never (approve once only)"], [300, "5 minutes"], [600, "10 minutes"], [1800, "30 minutes"], [3600, "1 hour"]],
  approval_timeout_secs: [[60, "1 minute"], [120, "2 minutes"], [300, "5 minutes"], [600, "10 minutes"]],
};

function renderSecurity() {
  const o = overview;
  const windows = o && (o.hello_available || o.hello);
  $("hello-box").hidden = !windows;
  if (windows) {
    // Before connecting, or while locked, the app can only see Windows' side.
    const h = helloState();
    $("hello").setAttribute("aria-checked", String(h === "enrolled" || h === "locked" || h === "unknown"));
    $("hello-note").textContent = h === "stale"
      ? "Windows Hello has a credstore key from an older vault, which this vault does not trust. Turn the switch on to replace it."
      : h === "locked" ? "The vault is locked. Hello can confirm again once you unlock it with your passphrase." : "";
  }
  const p = feed && feed.policy;
  $("timers").hidden = !p;
  $("policy-path").textContent = p
    ? (p.editable ? `These settings are saved in ${p.path}.` : `On this system the policy file belongs to root: edit ${p.path} with sudo, then run credstore reload.`)
    : "";
  if (!p) return;
  for (const sel of document.querySelectorAll("#timers select")) {
    const key = sel.dataset.key;
    const value = p[key];
    if (document.activeElement === sel && sel.dataset.busy) continue;
    const choices = [...TIMER_CHOICES[key]];
    if (!choices.some(([v]) => v === value)) choices.push([value, duration(value)]);
    choices.sort((a, b) => a[0] - b[0]);
    sel.replaceChildren(...choices.map(([v, label]) => el("option", { value: String(v), selected: v === value }, label)));
    sel.value = String(value);
    sel.disabled = !p.editable;
  }
}

for (const sel of document.querySelectorAll("#timers select")) {
  sel.addEventListener("change", async () => {
    const key = sel.dataset.key;
    const value = Number(sel.value);
    const label = sel.selectedOptions[0].textContent;
    const title = sel.closest(".row").querySelector("h2").textContent;
    sel.dataset.busy = "1";
    const args = { sessionIdleSecs: null, grantTtlSecs: null, approvalTimeoutSecs: null };
    args[{ session_idle_secs: "sessionIdleSecs", grant_ttl_secs: "grantTtlSecs", approval_timeout_secs: "approvalTimeoutSecs" }[key]] = value;
    const done = await ask(`${title}: ${label}`, "Changing security settings needs your passphrase.", async (pass) => {
      await invoke("set_defaults", { ...args, passphrase: pass });
      return null;
    }, { okLabel: "Save" });
    delete sel.dataset.busy;
    say("timers-msg", done ? `Saved: ${title.toLowerCase()} ${label}.` : "", true);
    renderSecurity();
  });
}

$("hello").addEventListener("click", async () => {
  const on = $("hello").getAttribute("aria-checked") !== "true";
  if (on && overview && !overview.hello_available) {
    return say("hello-msg", "Windows Hello is not set up for this account. Set up a PIN, face or fingerprint in Settings > Accounts > Sign-in options first.", false);
  }
  const done = await ask(
    on ? "Turn on Windows Hello approval" : "Turn off Windows Hello approval",
    on ? "After your passphrase, Windows asks you to verify once to create credstore's key."
       : "credstore's key is removed from the vault and from Windows Hello. Approvals then need the passphrase.",
    async (pass) => { await invoke("set_hello", { on, passphrase: pass }); return null; },
    { okLabel: on ? "Turn on" : "Turn off" });
  if (done) {
    await refresh();
    say("hello-msg", on ? "Windows Hello approval is on. It works while the vault is unlocked." : "Windows Hello approval is off.", true);
  }
});

// ------------------------------------------------------------------ folders

let chosenFolder = null;

$("pick-folder").addEventListener("click", async () => {
  say("grant-msg", "");
  const dir = await invoke("pick_folder");
  if (!dir) return;
  chosenFolder = dir;
  $("folder-path").textContent = dir;
  $("pick-folder").textContent = "Choose another";
  if (overview && overview.mode === "dev") {
    $("grant-plan").hidden = true;
    say("grant-msg", "Dev mode: commands run as you, so there is nothing to grant.", true);
    return;
  }
  try {
    const plan = await invoke("grant_plan", { dir });
    $("grant-commands").textContent = plan.join("\n");
    $("grant-plan").hidden = false;
  } catch (e) {
    say("grant-msg", String(e), false);
  }
});

$("grant-go").addEventListener("click", async () => {
  if (!chosenFolder) return;
  try {
    await invoke("grant", { dir: chosenFolder });
    say("grant-msg", `Approved commands can now work in ${chosenFolder}.`, true);
    $("grant-plan").hidden = true;
  } catch (e) {
    say("grant-msg", String(e), false);
  }
});

// ------------------------------------------------------------------ Claude Code

function checkItem(dotClass, topic, text) {
  return el("li", {}, el("span", { class: "dot " + dotClass }), el("span", { class: "k" }, topic), el("span", {}, text));
}

async function refreshClaude() {
  const list = $("claude-state");
  try {
    const s = await invoke("claude");
    if (!s) {
      list.replaceChildren(checkItem("ring", "home", "No home directory found."));
      return;
    }
    list.replaceChildren(
      checkItem(s.found ? "on" : "ring", "installed", s.found ? "Claude Code is installed." : "claude was not found on PATH. Install Claude Code, then come back."),
      checkItem(s.registered ? "on" : "ring", "connected", s.registered ? "credstore is available to Claude Code in every folder." : "credstore is not connected to Claude Code yet."),
      checkItem(s.missing_rules.length ? "ring" : "on", "deny rules",
        s.missing_rules.length ? "Missing: " + s.missing_rules.join(", ") : ".env files and credstore's own files are blocked from reading."),
    );
    const done = s.registered && !s.missing_rules.length;
    $("claude-connect").textContent = done ? "Connected" : "Connect Claude Code";
    $("claude-connect").disabled = done;
  } catch (e) {
    say("claude-msg", String(e), false);
  }
}

$("claude-connect").addEventListener("click", async () => {
  try {
    await invoke("connect_claude");
    say("claude-msg", "Done. Restart Claude Code sessions to pick it up.", true);
  } catch (e) {
    say("claude-msg", String(e), false);
  }
  refreshClaude();
});

// ------------------------------------------------------------------ health

const LEVEL_DOT = { ok: "on", info: "", warn: "ring", fail: "red" };

$("doctor-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const pass = take($("doctor-pass"));
  say("doctor-summary", "Checking…");
  try {
    const report = await invoke("doctor", { passphrase: pass || null });
    const fails = report.checks.filter((c) => c.level === "fail").length;
    const warns = report.checks.filter((c) => c.level === "warn").length;
    say("doctor-summary",
      fails ? `${plural(fails, "failure", "failures")}, ${plural(warns, "warning", "warnings")}.`
            : warns ? `No failures; ${plural(warns, "warning", "warnings")}.` : "No failures, no warnings.",
      fails === 0);
    $("doctor-checks").hidden = false;
    $("doctor-checks").replaceChildren(...report.checks.map((c) =>
      el("li", {}, el("span", { class: "dot " + (LEVEL_DOT[c.level] || "") }), el("span", { class: "k" }, c.topic),
        el("span", {}, el("span", { class: "st" + (c.level === "fail" ? " fail" : "") }, c.level.toUpperCase()), c.detail))));
  } catch (e) {
    say("doctor-summary", String(e), false);
  }
});

// ------------------------------------------------------------------ start

refresh().then((o) => {
  if (!o.reachable) show("health");
  invoke("page_ready", { summary: `${o.mode} reachable=${o.reachable} secrets=${o.secrets.length}` });
}).catch((e) => {
  $("service-text").textContent = "Error";
  invoke("page_ready", { summary: "error: " + String(e) });
});
