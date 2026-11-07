// credstore desktop app page. Every string that came from an agent or the daemon is put
// on the page with textContent, never as HTML.
"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);

/** Build an element; children are elements or strings (inserted as text). */
function el(tag, props = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined) continue;
    e.append(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return e;
}

function say(id, text, ok) {
  const m = $(id);
  m.textContent = text;
  m.className = "msg " + (ok === undefined ? "" : ok ? "ok" : "bad");
}

function takePassphrase(input) {
  const v = input.value;
  input.value = "";
  return v;
}

// ------------------------------------------------------------------ tabs

function showTab(name) {
  for (const b of document.querySelectorAll("#tabs button")) {
    b.classList.toggle("active", b.dataset.tab === name);
  }
  for (const s of document.querySelectorAll(".tab")) {
    s.hidden = s.id !== "tab-" + name;
  }
  if (name === "claude") refreshClaude();
}

for (const b of document.querySelectorAll("#tabs button")) {
  b.addEventListener("click", () => showTab(b.dataset.tab));
}

// ------------------------------------------------------------------ overview

let mode = "installed";
let hello = false;

async function refresh() {
  const o = await invoke("overview");
  mode = o.mode;
  hello = o.hello;
  const status = $("status");
  if (o.reachable) {
    status.textContent = `${o.mode === "dev" ? "dev mode (weaker)" : "installed"} · ${o.os} · v${o.version}`;
    status.className = "pill " + (o.mode === "dev" ? "" : "ok");
  } else {
    status.textContent = "not connected";
    status.className = "pill bad";
  }
  $("unreachable").hidden = o.reachable;
  $("unreachable-detail").textContent = o.error || "";
  renderSecrets(o.secrets);
  $("create-vault").hidden = !o.reachable || o.secrets.length > 0;
  return o;
}

$("retry").addEventListener("click", refresh);

// ------------------------------------------------------------------ approvals

$("watch-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const pass = takePassphrase($("watch-pass"));
  say("watch-msg", "Connecting…");
  try {
    await invoke("start_watching", { passphrase: pass });
    $("watch-start").hidden = true;
    $("watch-on").hidden = false;
    say("watch-msg", "");
  } catch (e) {
    say("watch-msg", String(e), false);
  }
});

listen("pending", (event) => renderRequests(event.payload));
listen("watch-ended", (event) => {
  $("watch-start").hidden = false;
  $("watch-on").hidden = true;
  renderRequests([]);
  say("watch-msg", "Stopped receiving requests: " + event.payload, false);
});

function renderRequests(list) {
  const box = $("requests");
  box.replaceChildren(...list.map(requestCard));
  const count = $("pending-count");
  count.hidden = list.length === 0;
  count.textContent = String(list.length);
  $("watch-state").textContent = list.length
    ? "Read each request before deciding. The command runs exactly as shown."
    : "Waiting for requests. Closing the window keeps credstore running in the tray.";
}

function requestRows(r) {
  if (r.http) {
    return [
      ["Reason", r.reason],
      ["Request", el("span", { class: "command" }, `${r.http.method} ${r.http.url}`)],
      ["Secret", r.secrets.join(", ") + " (credstore sends it; the agent never sees it)"],
      ["Secret header", el("span", { class: "command" }, r.http.secret_header)],
      ["Other headers", r.http.headers.join("; ")],
      ["Body", r.http.body],
      ["Allowed hosts", r.network],
      ["Asked by", r.from],
    ];
  }
  return [
    ["Reason", r.reason],
    [r.is_shell ? "Shell" : "Command", el("span", { class: "command" }, r.command)],
    ["Program", r.program],
    ["Folder", r.cwd],
    ["Secrets", r.secrets.join(", ")],
    ["Injected as", r.injection],
    ["Sandbox", r.sandbox],
    ["Network", r.network],
    ["Asked by", r.from],
  ];
}

function requestCard(r) {
  const rows = requestRows(r).filter(([, v]) => v);
  const dl = el("dl", {}, rows.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)]));
  const gaps = r.not_enforced.map((g) => el("p", { class: "gap" }, "Not enforced: " + g));
  const pass = el("input", {
    type: "password", autocomplete: "off",
    placeholder: hello ? "Passphrase (or leave empty for Windows Hello)" : "Passphrase to confirm",
  });
  const msg = el("p", { class: "msg" });
  const decide = async (decision) => {
    if (!pass.value && !hello) {
      msg.textContent = "Enter your passphrase to confirm.";
      msg.className = "msg bad";
      return;
    }
    if (!pass.value) {
      msg.textContent = "Confirm with Windows Hello...";
      msg.className = "msg";
    }
    const p = takePassphrase(pass);
    try {
      const out = await invoke("decide", { id: r.id, decision, passphrase: p });
      if (out.kind === "done") {
        msg.textContent = decision.kind === "deny" ? "Denied." : "Approved.";
        msg.className = "msg ok";
      } else if (out.kind === "wrong_passphrase") {
        msg.textContent = "Wrong passphrase. The request is still pending.";
        msg.className = "msg bad";
      } else {
        msg.textContent = p ? out.message : out.message + " Enter your passphrase instead.";
        msg.className = "msg bad";
      }
    } catch (e) {
      msg.textContent = String(e);
      msg.className = "msg bad";
    }
  };
  const buttons = [el("button", { onclick: () => decide({ kind: "once" }) }, "Approve once")];
  if (r.max_grant_secs > 0) {
    buttons.push(
      el("button", { class: "secondary", onclick: () => decide({ kind: "session", ttl_secs: r.max_grant_secs }) },
        `Approve for ${r.max_grant}`)
    );
  }
  buttons.push(el("button", { class: "danger", onclick: () => decide({ kind: "deny" }) }, "Deny"));
  return el("div", { class: "card request" },
    el("h2", {}, "Request " + r.id),
    dl, gaps,
    el("div", { class: "row" }, pass, ...buttons),
    msg);
}

// ------------------------------------------------------------------ secrets

function renderSecrets(secrets) {
  const body = $("secrets-table").querySelector("tbody");
  body.replaceChildren(...secrets.map((s) => {
    const remove = el("button", { class: "danger" }, "Remove");
    remove.addEventListener("click", async () => {
      const pass = window.prompt(`Passphrase to remove ${s.name}:`);
      if (!pass) return;
      try {
        await invoke("remove_secret", { name: s.name, passphrase: pass });
        say("secret-msg", `Removed ${s.name}.`, true);
        refresh();
      } catch (e) {
        say("secret-msg", String(e), false);
      }
    });
    return el("tr", {}, el("td", { class: "name" }, s.name), el("td", {}, s.description), el("td", {}, remove));
  }));
  $("no-secrets").hidden = secrets.length > 0;
}

$("vault-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const pass = takePassphrase($("vault-pass"));
  const repeat = takePassphrase($("vault-repeat"));
  try {
    const created = await invoke("create_vault", { passphrase: pass, repeat });
    say("vault-msg", created ? "Vault created." : "A vault already exists; nothing changed.", true);
    $("create-vault").hidden = true;
  } catch (e) {
    say("vault-msg", String(e), false);
  }
});

$("secret-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const name = $("secret-name").value.trim();
  const description = $("secret-desc").value.trim() || null;
  const value = takePassphrase($("secret-value"));
  const pass = takePassphrase($("secret-pass"));
  try {
    const saved = await invoke("set_secret", { name, description, value, passphrase: pass });
    $("secret-name").value = "";
    $("secret-desc").value = "";
    say("secret-msg",
      saved.too_short_to_redact
        ? `Saved ${name}. It is too short to redact safely, so it will not be masked in command output.`
        : `Saved ${name}.`,
      !saved.too_short_to_redact);
    refresh();
  } catch (e) {
    say("secret-msg", String(e), false);
  }
});

// ------------------------------------------------------------------ folders

let chosenFolder = null;

$("pick-folder").addEventListener("click", async () => {
  say("grant-msg", "");
  const dir = await invoke("pick_folder");
  if (!dir) return;
  chosenFolder = dir;
  if (mode === "dev") {
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
    say("grant-msg", `Approved commands can now run in ${chosenFolder}.`, true);
    $("grant-plan").hidden = true;
  } catch (e) {
    say("grant-msg", String(e), false);
  }
});

// ------------------------------------------------------------------ Claude Code

async function refreshClaude() {
  const list = $("claude-state");
  try {
    const s = await invoke("claude");
    if (!s) {
      list.replaceChildren(el("li", {}, "No home directory found."));
      return;
    }
    const item = (level, text) => el("li", {}, el("span", { class: "level " + level }, level), el("span", { class: "topic" }, ""), el("span", {}, text));
    list.replaceChildren(
      item(s.found ? "ok" : "warn", s.found ? "Claude Code is installed." : "`claude` was not found on PATH."),
      item(s.registered ? "ok" : "warn", s.registered ? "credstore is registered for all folders." : "credstore is not registered for all folders."),
      item(s.missing_rules.length ? "warn" : "ok",
        s.missing_rules.length ? "Missing deny rules: " + s.missing_rules.join(", ") : "Deny rules are in place."),
    );
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

$("doctor-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const pass = takePassphrase($("doctor-pass"));
  say("doctor-summary", "Checking…");
  try {
    const report = await invoke("doctor", { passphrase: pass || null });
    const fails = report.checks.filter((c) => c.level === "fail").length;
    const warns = report.checks.filter((c) => c.level === "warn").length;
    say("doctor-summary", fails ? `${fails} failure(s), ${warns} warning(s).` : `No failures; ${warns} warning(s).`, fails === 0);
    $("doctor-checks").replaceChildren(...report.checks.map((c) =>
      el("li", {}, el("span", { class: "level " + c.level }, c.level), el("span", { class: "topic" }, c.topic), el("span", {}, c.detail))));
  } catch (e) {
    say("doctor-summary", String(e), false);
  }
});

// ------------------------------------------------------------------ start

refresh().then((o) => {
  if (!o.reachable) showTab("health");
  invoke("page_ready", { summary: `${o.mode} reachable=${o.reachable} secrets=${o.secrets.length}` });
}).catch((e) => {
  $("status").textContent = "error";
  invoke("page_ready", { summary: "error: " + String(e) });
});
