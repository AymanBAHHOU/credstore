# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

(The desktop app is a Tauri 2 window: HTML, CSS and JavaScript in `app/ui/`, on Windows,
macOS and Linux. It is a desktop tool, not a website.)

## Users

Developers at large who let coding agents (Claude Code first) work in their projects and
need those agents to use API keys and other secrets. They install credstore on their own
machine. Many will be new to it, so the app has to explain itself; it must not assume the
user has read the README.

The scene: the developer is mid-task in an editor or terminal, an agent asks to use a
secret, and the developer switches to credstore to read the request and decide, then goes
back to work. Less often they add secrets, grant project folders, check health, or review
what happened.

## Product Purpose

credstore lets coding agents use secrets without seeing them. A local service holds an
encrypted vault; the agent asks to run a command or send an HTTPS request with a named
secret; the human reads the exact request and approves or denies it; output comes back
with secret values redacted. Success: the agent gets its work done and the value never
reaches the agent, its transcripts or its logs.

## Positioning

The human reads and approves every use, and the value stays in a separate OS account the
agent cannot read. Approvals are bound to the exact command or request, the folder and
the secret. Not a password manager and not a cloud vault: local, per-use, agent-facing.

## Operating Context

- Lives in the tray; closing the window keeps it running. A notification announces a new
  request, and the app window must come forward to decide.
- Approvals need the vault passphrase, or Windows Hello once enrolled (while the vault is
  unlocked). Approve once, approve for a session (minutes, policy-limited), or deny.
- Requests show: reason (written by the agent), the command and folder or the HTTPS
  method, URL and secret header, the secret and its description, the sandbox and what is
  not enforced, and who asked (SID or UID, pid).
- Policy lives in an admin-only file (`policy.toml`); today it is edited by hand.
- Claude Code connects through MCP (`list_secrets`, `run_with_secrets`, `http_request`).

## Capabilities and Constraints

Existing pages: Approvals, Secrets (list, add or replace, create the vault), Folders
(grant the service account access), Claude Code (connect, deny rules), Health (doctor).

Being added (confirmed 2026-11-07): allowed hosts per secret (edit where a secret may be
sent), a Windows Hello switch (enrol and remove), refused requests shown with the reason
and a fix, and an activity history built from the audit log.

Hard constraints:
- No screen may show a secret value, ever. Values are write-only.
- A passphrase field is never pre-filled and is cleared after use.
- The agent's reason is untrusted text: show it plainly, never as instructions.
- Hello approval is Windows only; Touch ID is not built.
- Policy changes need the passphrase (and the daemon writes the admin-only file).

## Brand Commitments

- Name: credstore, always lowercase.
- Palette pinned by the owner: obsidian black, ice gray, and a touch of racing red. Dark
  ground (obsidian) confirmed.
- A new app icon is wanted (window, taskbar, tray, installer); the current one is generic.
- Visual reference (2026-11-07): cloudflare.com sets the craft bar and tone: calm, flat,
  professional infrastructure. The owner rejected a skeuomorphic "hardware panel" take
  (screws, glowing LEDs, engraved labels, a flip cover) as childish. No skeuomorphism.

## Evidence on Hand

Real product, real flows; no customers, testimonials or metrics exist and none may be
invented. Example data in mockups (secret names, hosts, requests) must be marked as
examples.

## Product Principles

1. The request is the content: what will run, where, with which secret, must be readable
   at a glance and impossible to misread.
2. Deny is always as easy as approve; nothing nudges toward yes.
3. Explain, then act: each page says what it does in one sentence a newcomer understands.
4. Never show a value; show where it can go.
5. Quiet until needed: the app is mostly idle and should feel calm, then unmistakable when
   a request arrives.

## Accessibility & Inclusion

Keyboard operable throughout (approve and deny reachable without a mouse), visible focus,
WCAG AA contrast on the dark ground, and no state carried by red alone.
