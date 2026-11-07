// The island: a waiting request at the top of the screen. Collapsed it is a pill
// ("Agent wants NAME → host"); hovering or clicking opens it with the request and the
// same Deny / Approve buttons as the Approvals page. The app shows it when a request
// arrives and hides it when none is waiting. Passphrase fields are never pre-filled
// and are cleared as soon as they are read.
"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const root = document.getElementById("island");

let overview = null;
let feed = null;
let open = false;      // expanded
let pinned = false;    // opened by a click: stays open when the mouse leaves
let busy = false;      // a decision is being sent
let currentId = null;  // the request shown
let done = null;       // {label, ok}: the decision just made, shown for a moment
let leaveTimer = null;
let doneTimer = null;
let built = "";        // what the open view was built for, so typing is not interrupted

const pending = () => (feed ? feed.pending : []);
const shown = () => pending().find((r) => r.id === currentId) || pending()[0] || null;

function render() {
  const r = shown();
  if (done) return renderDone();
  if (!r) {
    built = "";
    open = pinned = false;
    root.replaceChildren();
    root.className = "island";
    invoke("island_hide").catch(() => {});
    return;
  }
  const wasEmpty = !root.firstChild;
  if (r.id !== currentId) {
    currentId = r.id;
    refreshOverview();
  }
  const key = JSON.stringify([open, r.id, pending().length, helloStateOf(overview, feed)]);
  if (key === built) return;
  built = key;
  root.className = "island " + (open ? "open" : "pill") + (wasEmpty ? " arrive" : "");
  root.replaceChildren(...(open ? openView(r) : [pillView(r)]));
  fit();
}

function pillView(r) {
  const more = pending().length - 1;
  return el("button", { class: "pill-btn", type: "button", "aria-expanded": "false", onclick: () => setOpen(true, true) },
    el("span", { class: "dot", "aria-hidden": "true" }),
    el("span", { class: "pill-text" },
      el("span", { class: "who" }, "Agent wants "),
      el("span", { class: "name" }, secretNames(r).join(", ")),
      el("span", { class: "to" }, " → " + requestTarget(r))),
    more > 0 ? el("span", { class: "count", title: `${more} more waiting` }, "+" + more) : null,
    el("span", { class: "chev", "aria-hidden": "true" }, "›"));
}

function openView(r) {
  const list = pending();
  const i = list.findIndex((x) => x.id === r.id);
  const band = el("div", { class: "band" },
    el("span", {}, "Waiting for you"),
    list.length > 1 ? el("span", { class: "of" }, `${i + 1} of ${list.length}`) : null,
    el("span", { class: "grow" }),
    list.length > 1 ? el("button", { type: "button", onclick: () => { currentId = list[(i + 1) % list.length].id; built = ""; render(); } }, "Next") : null,
    el("button", { type: "button", "aria-label": "Collapse", onclick: () => setOpen(false) }, "Hide"));

  const code = (text, cls = "") => el("span", { class: "code " + cls }, text);
  const rows = [["Secret", code(secretNames(r).join(", "), "em")]];
  if (r.http) {
    rows.push(["Request", [code(r.http.method, "em"), " ", code(r.http.url)]]);
    if (r.http.body) rows.push(["Body", code(r.http.body)]);
  }
  else {
    rows.push([r.is_shell ? "Shell" : "Command", code(r.command, "em")]);
    if (r.cwd) rows.push(["Folder", code(r.cwd)]);
  }
  rows.push(["Reason", el("span", { class: "reason" }, `“${r.reason}”`)]);
  if (r.not_enforced.length) {
    rows.push(["Not enforced", r.not_enforced.map((g) => el("span", { class: "gap-line" }, g))]);
  }
  const dl = el("dl", { class: "kv" }, rows.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)]));

  const h = helloStateOf(overview, feed);
  const pass = el("input", {
    class: "input", type: "password", autocomplete: "off", "aria-label": "Passphrase",
    placeholder: h === "enrolled" ? "Passphrase, or leave empty for Windows Hello" : "Passphrase to confirm",
    onfocus: () => clearTimeout(leaveTimer),
    onkeydown: (e) => { if (e.key === "Enter") { e.preventDefault(); decide({ kind: "once" }, "Approved once"); } },
  });
  const msg = el("p", { class: "msg", role: "status" });
  const buttons = [];

  async function decide(decision, label) {
    if (!pass.value) {
      const s = helloStateOf(overview, feed);
      if (s === "stale") return say(STALE_HELLO);
      if (s === "locked") return say(LOCKED_HELLO);
      if (s !== "enrolled") return say("Enter your passphrase to confirm.");
    }
    const p = take(pass);
    busy = true;
    buttons.forEach((b) => b.classList.add("busy"));
    say(p ? "Checking…" : "Confirm with Windows Hello…", true);
    try {
      const out = await invoke("decide", { id: r.id, decision, passphrase: p });
      if (out.kind === "done") return finish(label, decision.kind !== "deny");
      if (out.kind === "wrong_passphrase") say("Wrong passphrase. The request is still waiting.");
      else if (!p && /locked/i.test(out.message)) say(LOCKED_HELLO);
      else say(helloError(out.message));
    } catch (e) {
      say(helloError(String(e)));
    } finally {
      busy = false;
      buttons.forEach((b) => b.classList.remove("busy"));
    }
  }
  function say(text, ok) {
    msg.textContent = text;
    msg.className = "msg" + (ok ? "" : " bad");
    fit();
  }

  buttons.push(el("button", { class: "btn", type: "button", onclick: () => decide({ kind: "deny" }, "Denied") }, "Deny"));
  if (r.max_grant_secs > 0) {
    buttons.push(el("button", { class: "btn", type: "button", onclick: () => decide({ kind: "session", ttl_secs: r.max_grant_secs }, `Approved for ${r.max_grant}`) },
      `Approve for ${r.max_grant}`));
  }
  buttons.push(el("button", { class: "btn primary", type: "button", onclick: () => decide({ kind: "once" }, "Approved once") }, "Approve once"));
  const openApp = el("button", { class: "btn link", type: "button", onclick: () => invoke("open_main") }, "Open credstore ›");

  return [band, dl, el("div", { class: "decide" }, pass, el("div", { class: "buttons" }, ...buttons, el("span", { class: "grow" }), openApp), msg)];
}

function finish(label, ok) {
  done = { label, ok };
  open = pinned = false;
  render();
  clearTimeout(doneTimer);
  doneTimer = setTimeout(() => {
    done = null;
    built = "";
    render();
  }, 1400);
}

function renderDone() {
  built = "";
  root.className = "island done" + (done.ok ? "" : " no");
  root.replaceChildren(el("span", { class: "tick", "aria-hidden": "true" }), el("span", {}, done.label));
  fit();
}

function setOpen(on, pin = false) {
  clearTimeout(leaveTimer);
  pinned = on && (pin || pinned);
  if (open === on) return;
  open = on;
  built = "";
  render();
}

// Hovering opens the island; leaving closes it again, unless it was opened by a click,
// a decision is being sent, or the passphrase field is in use.
root.addEventListener("mouseenter", () => {
  clearTimeout(leaveTimer);
  if (!done && shown()) setOpen(true);
});
root.addEventListener("mouseleave", () => {
  clearTimeout(leaveTimer);
  leaveTimer = setTimeout(() => {
    const typing = document.activeElement && document.activeElement.tagName === "INPUT" && document.activeElement.value;
    if (!pinned && !busy && !typing) setOpen(false);
  }, 700);
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") setOpen(false);
});

/** Fit the window to the island (after layout). */
function fit() {
  requestAnimationFrame(() => {
    const b = root.getBoundingClientRect();
    if (b.width && b.height) invoke("island_size", { width: b.width, height: b.height }).catch(() => {});
  });
}

async function refreshOverview() {
  try {
    overview = await invoke("overview");
  } catch {
    overview = null;
  }
  built = "";
  render();
}

listen("feed", (event) => {
  feed = normalize(event.payload);
  render();
});
listen("watch-ended", () => {
  feed = null;
  render();
});

(async () => {
  try {
    const f = await invoke("current_feed");
    if (f) feed = normalize(f);
  } catch {
    feed = null;
  }
  render();
})();
