# credstore: spec

A local secret broker that lets coding agents (Claude Code and similar) _use_ secrets
without ever _seeing_ them. The human approves each use, knowing what it is for.

Status: v0.2 spec. Written for an implementing agent. Read all of it before writing code.

Targets: Windows, Linux (including WSL2) and macOS, one codebase. Development and test
order: Windows first, then Linux through WSL2, then macOS. See section 4.1 for the platform layer.

---

## 1. Goal

Today secrets reach an agent by pasting them into chat or leaving them in `.env` files the
agent can read. Both leak the value into the model context.

credstore gives the agent a way to say: "run this command with `STRIPE_KEY` because I need
to test the webhook." The human sees exactly that, approves, and the command runs with the
secret injected. The agent receives only redacted output.

### Non-goals (v1)

- Not a general password manager (no browser autofill, no sync, no sharing).
- Not a defense against malware running as root, or against a fully compromised OS.
- Not a replacement for scoped, low-privilege keys (still recommended).
- No cloud service. Everything runs locally; remote use is over an SSH-forwarded socket (v2).

---

## 2. Threat model

| Actor                                | Capability                                                                      | Must be prevented                                                                 |
| ------------------------------------ | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| Prompt-injected or misbehaving agent | Runs as the user's UID, can run shell commands, read user files, call MCP tools | Reading secret values, reading the vault, self-approving, exfiltrating via output |
| Other local processes of the user    | Same as above                                                                   | Same                                                                              |
| Thief of the vault file              | Has the encrypted file only                                                     | Decrypting without the passphrase                                                 |
| Shoulder-surfer of logs/transcripts  | Reads audit log, MCP transcripts                                                | Finding secret values anywhere                                                    |

Key design consequences:

1. **Same-user is a weak boundary on every OS.** The daemon therefore runs as a **separate OS
   user** (`credstore` on Linux and Windows, `_credstore` on macOS). The vault file and the daemon's memory are not accessible to the
   agent's user. A "dev mode" that runs as the same user is allowed but must print a loud
   warning and must be documented as weaker.
2. **Approval must require something the agent does not have.** The agent runs as the same
   user and can invoke any CLI the user can. So approval is authenticated by proof the
   agent lacks: the vault **passphrase typed on a real terminal**, or (v2) a signed
   approval from the user's phone. A bare "y/n" prompt is not sufficient.
3. **Redaction is a safety net, not the control.** An approved command can encode or split
   a secret to beat redaction. The real controls are: the human reads the command,
   policy restricts commands, the sandbox restricts network egress.

---

## 3. Architecture

```
 Your user (untrusted)                         credstore user (trusted)
 ┌────────────────────────┐                   ┌───────────────────────────────────┐
 │ Agent (Claude Code)    │                   │ credstored                        │
 │   │ MCP (stdio)        │ socket / named    │  IPC server + peer identity check │
 │   ▼                    │ pipe (agent)      │  policy engine                    │
 │ credstore mcp  (shim)  ├──────────────────►│  approvals + session grants (RAM) │
 │ holds no secrets       │                   │  vault (age file)                 │
 └────────────────────────┘                   │  runner (sandboxed child)         │
                                              │  audit log (hash chained)         │
 ┌────────────────────────┐ approver endpoint │  [v2] auth proxy                  │
 │ credstore watch        ├──────────────────►│                                   │
 │ human TUI on real tty  │ passphrase auth   └───────────────────────────────────┘
 └────────────────────────┘
```

### 3.1 Processes

- **`credstored`**: long-running daemon. Owns vault, keys, policy, audit, runner.
- **`credstore`**: single binary CLI. Subcommands: `init`, `set`, `list`, `rm`, `run`,
  `watch`, `audit`, `mcp`, `doctor`. `credstore mcp` is the agent-facing MCP shim and is a
  thin client of the daemon.
- The shim and the CLI never decrypt anything themselves. They send requests to the daemon.

### 3.2 IPC endpoints (Unix sockets, or named pipes on Windows)

Endpoint locations per OS are in 5.4. Behavior is identical on every OS.

- **Agent endpoint** (`agent.sock`, or `\\.\pipe\credstore-agent` on Windows): only members of
  the `credstore-agents` group can connect (Unix: file mode and group; Windows: pipe ACL).
  Allowed requests: `list_secrets`, `run`. Every connection's peer identity is checked and
  logged: UID/PID via `SO_PEERCRED` (Linux) or `LOCAL_PEERCRED` (macOS), SID/PID from the
  pipe handle on Windows.
- **Approver endpoint** (`approver.sock`, or `\\.\pipe\credstore-approver` on Windows):
  restricted to group `credstore-approvers` (the human's user). Allowed requests: `subscribe_pending`, `approve`, `deny`, `unlock`,
  `admin_*`. Every approver request must carry proof of authentication (see 6.3). A
  connection alone grants nothing.
- Protocol: length-prefixed (u32 BE) JSON frames, versioned (`"v":1`). Max frame 1 MiB.

### 3.3 Dev mode (same user, no daemon install)

`credstored --dev` runs under the current user. Endpoints live under `$XDG_RUNTIME_DIR`
(Linux), `$TMPDIR` (macOS), or a per-user named pipe `\\.\pipe\credstore-dev-<username>`
(Windows). Dev mode is how every milestone is first built and tested on every OS.
Prints: `DEV MODE: the agent can read this process's memory and the vault file. Use the
installed mode for real secrets.` Required so development and tests work without sudo.

---

## 4. Tech stack

- Language: **Rust**, stable toolchain, edition 2021. One codebase for Windows, Linux and
  macOS. Platform-specific code lives only in the `credstore-os` crate behind `cfg` gates
  (section 4.1).
- Cargo workspace:
  ```
  credstore/
    Cargo.toml                 (workspace)
    crates/
      credstore-proto/         (request/response types, framing)
      credstore-core/          (vault, policy, redaction, audit; no I/O to sockets)
      credstore-os/            (platform layer: IPC, peer identity, sandbox, memory, paths)
      credstored/              (daemon binary)
      credstore/               (CLI + mcp shim binary)
    deploy/
      credstored.service       (Linux: systemd unit, hardened)
      sysusers.conf, tmpfiles.conf
      dev.credstore.daemon.plist (macOS: launchd)
      install.ps1              (Windows: service, groups, ACLs)
    tests/                     (integration + adversarial)
    docs/
  ```
- Crates (prefer these, justify any additions in the PR/commit message):
  `tokio` (rt, net, process, time), `interprocess` (Unix sockets and Windows named pipes
  behind one async API), `clap` (derive), `serde`, `serde_json`, `toml`,
  `age` (vault encryption, passphrase recipient), `zeroize` + `secrecy` (secret handling),
  `nix` (Unix only: peer creds, prctl, mlock), `landlock` (Linux only),
  `windows-sys` (Windows only: pipe ACLs, tokens, job objects, VirtualLock),
  `directories` (dev-mode paths), `sha2` (audit chain),
  `rpassword` (passphrase prompt), `rmcp` (official Rust MCP SDK; if unusable, implement
  minimal MCP stdio JSON-RPC by hand and say why), `tracing`, `thiserror`, `anyhow`
  (binaries only), `globset` (policy matching), `time`.
- Sandbox: per OS, see 4.1. Whatever is used, the mode actually applied (`bwrap`,
  `landlock`, `seatbelt`, `job-object`, `none`) is recorded in the audit log and shown in
  the approval prompt.
- Lints: `#![forbid(unsafe_code)]` everywhere except small, commented modules inside
  `credstore-os` for platform calls the safe crates do not cover.
- CI commands that must pass: `cargo fmt --check`, `cargo clippy -- -D warnings`,
  `cargo test --workspace`, `cargo deny check` (licenses/advisories). Run them in a CI
  matrix on `windows-latest`, `ubuntu-latest` and `macos-latest`.

### 4.1 Platform layer (`credstore-os`)

All OS-specific behavior sits behind traits in `credstore-os`: `Ipc`, `PeerIdentity`,
`Sandbox`, `MemoryGuard`, `Paths`, `ServiceInstall`, `Terminal`. Each method returns a
result that can be `Unavailable(reason)`. Callers must report an unavailable feature (audit
log, approval prompt) and honor policy (`sandbox = "require"` denies), never silently skip it.
Outside this crate there is no `cfg(unix)` / `cfg(windows)` and no hard-coded path separator.

| Capability                   | Linux (incl. WSL2)                          | macOS                                    | Windows                                                    |
| ---------------------------- | ------------------------------------------- | ---------------------------------------- | ---------------------------------------------------------- |
| IPC                          | Unix socket                                 | Unix socket                              | Named pipe                                                 |
| Peer identity                | `SO_PEERCRED`                               | `LOCAL_PEERCRED` / `getpeereid`          | Client PID + SID from pipe handle                          |
| Endpoint access control      | File mode + group                           | File mode + group                        | Pipe ACL (SDDL) built from group SIDs                      |
| Service account              | `credstore` (systemd)                       | `_credstore` (launchd)                   | `NT SERVICE\credstore` virtual account                     |
| Sandbox                      | bubblewrap, else landlock                   | Seatbelt profile via `sandbox-exec`      | Job Object + restricted token                              |
| Network restriction          | Yes (bwrap / landlock)                      | Yes (Seatbelt rules)                     | Not per process in v1                                      |
| Memory hardening             | `mlock`, `PR_SET_DUMPABLE 0`, no core dumps | `mlock`, `PT_DENY_ATTACH`, no core dumps | `VirtualLock`, process DACL denying VM read, WER dumps off |
| Passphrase terminal          | `/dev/tty`                                  | `/dev/tty`                               | Console                                                    |
| Run dir for `file` injection | tmpfs                                       | 0700 dir                                 | Private temp dir with child-only ACL                       |

Notes:

- **WSL2** is a real Linux kernel. The Linux build runs unchanged. Installed mode needs
  systemd enabled (`[boot] systemd=true` in `/etc/wsl.conf`). A Windows install and a WSL
  install are independent: separate daemons, vaults and policies, no bridging in v1.
- **macOS**: `sandbox-exec` is deprecated by Apple but still functional and has no CLI
  replacement. Keep it behind the `Sandbox` trait so it can be swapped. Code signing and
  notarization are out of scope for v1 (build locally).
- **Windows**: v1 sandbox is a Job Object (CPU, memory, process-count limits, kill the whole
  tree) plus a restricted token. It cannot restrict network access per process, so policy
  `network = "deny"` with `sandbox = "require"` is denied on Windows. AppContainer is v2.

---

## 5. Data formats

### 5.1 Vault file

Path: see 5.4 (installed) or `$CREDSTORE_HOME/vault.age` (dev). Unix: mode 0600 owned by
the service user. Windows: ACL granting access only to the service account and Administrators.

The file is a single `age` passphrase-encrypted blob (scrypt recipient) whose plaintext is
JSON:

```json
{
  "v": 1,
  "secrets": {
    "STRIPE_KEY": {
      "value": "sk_test_...",
      "description": "Stripe test key, billing API",
      "created": "2026-11-06T15:00:00Z",
      "updated": "2026-11-06T15:00:00Z"
    }
  }
}
```

A separate plaintext sidecar `index.json` holds names and descriptions only (so the agent
can list names without unlocking). It must never contain values. Writes are atomic
(write temp, fsync, rename). Names must match `^[A-Z_][A-Z0-9_]*$`.

### 5.2 Policy file

Path: see 5.4. Owned by root/Administrators, readable by the service user, **not writable
by the agent's user**. Reloaded on SIGHUP (Unix) or by `credstore reload` (all OSes).

```toml
[defaults]
require_approval = true
max_runtime_secs = 120
max_output_bytes = 20000
sandbox = "prefer"          # "require" | "prefer" | "off"
network = "inherit"         # "inherit" | "deny" | "allow-list"

[secret.STRIPE_KEY]
allow_commands = ["curl *api.stripe.com*", "stripe *", "pytest *"]
allow_dirs     = ["/home/ayman/projects/billing/**"]
network        = "allow-list"
allow_hosts    = ["api.stripe.com"]
grant_ttl_secs = 600        # max "approve for N minutes" allowed
injection      = ["env"]    # "env" | "file" | "stdin"

[secret.PROD_DB_URL]
require_approval = true
grant_ttl_secs   = 0        # never cache; approve every time
```

Rules:

- A secret with no `[secret.NAME]` block uses `[defaults]` and permits any command (still
  needs approval). Make this the documented default for easy start; add
  `strict = true` under `[defaults]` to deny anything not explicitly listed.
- A request that violates policy is denied **before** the human is asked, and the denial
  reason is returned to the agent and logged.
- Matching is on the resolved argv, using `globset`. Shell mode (`sh -c`) is denied unless
  the policy sets `allow_shell = true` for that secret.
- On Windows, paths are normalized to forward slashes and case-folded before matching, the
  executable is resolved to a full path and matched without its `.exe`/`.cmd` extension, and
  shell mode means `cmd /c` or `powershell -Command`. Use `C:/Users/...` style in `allow_dirs`.

### 5.3 Audit log

Path: see 5.4. Append-only where the OS supports it (`chattr +a` on Linux, `chflags sappnd`
on macOS; on Windows an ACL denying delete and overwrite to everyone but the service).
One JSON object per line:

```json
{
  "ts": "...",
  "id": "req_01...",
  "event": "request",
  "peer": { "uid": 1000, "pid": 4242, "exe": "/usr/bin/node" },
  "secrets": ["STRIPE_KEY"],
  "argv": ["curl", "-s", "https://api.stripe.com/v1/charges"],
  "cwd": "/home/ayman/projects/billing",
  "reason": "test webhook",
  "prev": "<sha256 hex>",
  "hash": "<sha256 hex>"
}
```

Events: `request`, `policy_denied`, `approved`, `denied`, `run_started`, `run_finished`
(exit code, duration, sandbox mode, bytes of output), `unlock`, `lock`, `vault_changed`,
`config_reloaded`. `hash = sha256(prev || canonical_json_without_hash)`.
`credstore audit verify` re-walks the chain and reports the first break.
**Never log secret values, even partially, and never log environment dumps.**

### 5.4 Installed-mode paths

| Item              | Linux / WSL2                     | macOS                              | Windows                               |
| ----------------- | -------------------------------- | ---------------------------------- | ------------------------------------- |
| Vault + index     | `/var/lib/credstore/`            | `/var/db/credstore/`               | `%ProgramData%\credstore\`            |
| Policy            | `/etc/credstore/policy.toml`     | `/etc/credstore/policy.toml`       | `%ProgramData%\credstore\policy.toml` |
| Audit log         | `/var/log/credstore/audit.jsonl` | `/var/log/credstore/audit.jsonl`   | `%ProgramData%\credstore\audit.jsonl` |
| Agent endpoint    | `/run/credstore/agent.sock`      | `/var/run/credstore/agent.sock`    | `\\.\pipe\credstore-agent`            |
| Approver endpoint | `/run/credstore/approver.sock`   | `/var/run/credstore/approver.sock` | `\\.\pipe\credstore-approver`         |

All paths come from the `Paths` trait. Never hard-code them elsewhere.

---

## 6. Behavior

### 6.1 Agent-facing MCP tools (served by `credstore mcp`)

`list_secrets`

- Input: none. Output: `[{name, description}]`. Never values.

`run_with_secrets`

- Input:
  ```json
  {
    "argv": ["pytest", "-q"],
    "secrets": ["STRIPE_KEY"],
    "reason": "Run billing tests against the Stripe test account",
    "cwd": "/abs/path",
    "timeout_secs": 60,
    "injection": "env"
  }
  ```
- `argv` is an array (preferred). A `shell` string field is accepted only when policy
  allows shell mode.
- `reason` is required, 10 to 300 chars, and is shown to the human verbatim. The tool
  description must tell the agent: explain what the command does with each secret.
- Output: `{exit_code, stdout, stderr, truncated, redactions}` (all redacted), or
  `{denied: "<reason>"}`.
- The call blocks while waiting for approval. Approval timeout default 120 s, then
  `{denied: "approval timed out"}`.

No tool may ever return a secret value. There is no `get_secret`.

### 6.2 Request lifecycle (daemon)

1. Accept on agent socket, record peer creds.
2. Validate input (schema, sizes, names exist, cwd is absolute and exists).
3. Policy check. On violation: log `policy_denied`, return denial.
4. If a valid **grant** covers (secrets, argv pattern, cwd, peer) and `now < expiry`,
   skip to 7. Log `approved` with `via: "grant"`.
5. Create a pending approval; notify all subscribed approvers (TUI, later phone).
6. Wait for approve/deny/timeout. On approve, the approver authenticated with the
   passphrase (6.3). Scope chosen by the human: `once`, `session` (until TTL, capped by
   policy `grant_ttl_secs`, default 10 min), or deny.
7. Decrypt (or use the cached unlocked vault, see 6.3), select only the requested
   secrets, run (6.4), redact, log, return.

### 6.3 Approval and unlock

- The daemon starts **locked**. The vault key is not on disk anywhere.
- `credstore watch` (human, real tty) connects to the approver socket, shows pending
  requests, and for each shows: reason, full argv, cwd, secret names + descriptions,
  sandbox mode, network policy, the requesting peer (uid, pid, exe path).
- To approve, the human types the **passphrase** into a no-echo prompt on `/dev/tty`. The
  daemon verifies it by decrypting the vault. Wrong passphrase: counts toward a rate
  limit (5 failures then 60 s lockout, doubling) and the request stays pending.
- After a successful approval the unlocked vault stays in daemon RAM until the **session
  idle TTL** (default 10 min, configurable, `0` = relock immediately after each run).
  `credstore lock` forces relock. Locking zeroizes memory.
- The agent cannot approve: it lacks the passphrase, and the daemon rejects any approver
  request that is not accompanied by a fresh passphrase proof. The `approve` request
  carries the passphrase (over the local socket) which the daemon checks; the daemon
  never stores it.
- Passphrase entry must happen in the `watch` process using `rpassword`, which reads the
  controlling terminal (`/dev/tty` on Unix, the console on Windows), not stdin, so a piped
  stdin cannot answer it.

### 6.4 Running the command

- Spawn child with `tokio::process`, **cleared environment** plus a minimal safe base
  (`PATH`, `HOME` if needed, `LANG`) plus only the approved secrets. Never inherit the
  daemon's environment. On Windows the base must also include `SystemRoot`, `ComSpec`,
  `TEMP`, `TMP` and `PATHEXT`, or most programs fail to start; environment variable names
  are case-insensitive there, so secret names are compared case-insensitively.
- Injection modes:
  - `env` (default): `NAME=value` in the child environment.
  - `file`: write the value to a file under a per-run directory on tmpfs, mode 0400,
    set `NAME_FILE=/path`, delete in all exit paths including panic/kill. Per-OS run
    directory as in 4.1 (Windows: private temp dir with an ACL for the child only).
  - `stdin`: pipe the value to the child's stdin (single secret only).
- Sandbox: the per-OS mechanism from 4.1. Where supported: read-only filesystem except
  `cwd` and a tmp dir, no access to the vault, policy or audit paths (5.4) or the daemon's
  process memory, network per policy. If `sandbox = "require"` and the OS cannot meet the
  policy (for example network deny on Windows), deny.
- Process hardening for the daemon (via `MemoryGuard`): Linux `prctl(PR_SET_DUMPABLE, 0)`,
  `mlock`, `RLIMIT_CORE = 0`; macOS `PT_DENY_ATTACH`, `mlock`, `RLIMIT_CORE = 0`; Windows
  `VirtualLock`, a process DACL denying `PROCESS_VM_READ`, `PROCESS_VM_WRITE` and
  `PROCESS_DUP_HANDLE` to non-service accounts, and Windows Error Reporting dumps disabled
  for the process. All best effort, and the result is logged at startup.
- Limits: wall-clock timeout (kill the process group, or the Job Object on Windows),
  stdout+stderr capped at
  `max_output_bytes` each, no TTY allocated.
- On exit, always zeroize the in-memory copies of values that are no longer needed.

### 6.5 Redaction

Applied to stdout, stderr, and any error text before returning or logging:

- Exact value, value + trailing newline, URL-encoded, base64 (all 3 alignments), hex
  (lower/upper), JSON-escaped, and each line of a multi-line value.
- Skip values shorter than 6 chars (document: too short to redact safely, warn at `set`).
- Replace with `[REDACTED:NAME]`.
- Return the count of redactions so the agent can tell something was masked.
- Be explicit in docs that this does not stop deliberate exfiltration (see threat model).

### 6.6 Auth proxy (v2, designed now)

For HTTP APIs: the agent calls `http_request {method, url, secret, header_template,
reason}`. The daemon makes the request itself, adds e.g. `Authorization: Bearer {value}`,
enforces `allow_hosts`, and returns the redacted response. The secret never enters any
agent-controlled process. Do not build in v1, but keep the proto crate extensible.

### 6.7 Phone approval (v2, designed now)

Daemon sends a push via ntfy (self-hosted or public) containing request details and two
links with single-use HMAC-signed tokens (key held only by the daemon). The topic name is a
secret kept in the vault config, so the agent cannot read it. Approving from the phone
still requires a second factor the agent lacks (biometric on the phone through a small
web page, or passphrase). Do not build in v1.

---

## 7. CLI

```
credstore init                      create vault + index, set passphrase (confirm twice)
credstore set NAME [-d DESC]        prompts for value (no echo); never accepts value in argv
credstore list                      names + descriptions
credstore rm NAME
credstore run -s NAME[,NAME] [--reason "..."] -- <argv...>   human-initiated run, same pipeline
credstore watch                     approval TUI (needs real tty)
credstore lock | status | reload
credstore audit [--follow] | verify
credstore mcp                       MCP stdio shim for agents
credstore doctor                    check install: user, perms, sockets, sandbox availability,
                                    policy file perms, whether agent user can read the vault
```

Rules: secret values are never accepted via argv or env of the CLI itself. `doctor` must
fail loudly if the vault or policy is writable/readable by the agent's user in installed
mode.

---

## 8. Deployment (Linux here; macOS and Windows in 8.1)

- `deploy/credstored.service` (systemd), run as `User=credstore`, with:
  `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`,
  `ReadWritePaths=/var/lib/credstore /var/log/credstore /run/credstore`,
  `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `CapabilityBoundingSet=`,
  `LimitCORE=0`, `MemoryDenyWriteExecute=yes`.
- `sysusers.conf` creates `credstore`, `credstore-agents`, `credstore-approvers`.
- An `install.sh` that does the above, adds the current user to both groups, writes a
  starter policy, and prints how to register the MCP server:
  `claude mcp add credstore -- credstore mcp`.
- Docs must tell the user to also add Claude Code **deny rules** for reading `.env*`,
  `/var/lib/credstore`, and `~/.credstore`, and to **not allowlist** the credstore MCP
  tool so Claude Code asks too.

### 8.1 macOS and Windows

- **macOS**: `deploy/dev.credstore.daemon.plist` installed to `/Library/LaunchDaemons/`,
  running as `_credstore` (created by the install script with `dscl`), groups
  `credstore-agents` and `credstore-approvers`, same file layout and permissions as Linux
  (5.4). Claude Code deny rules cover `/var/db/credstore`, `/etc/credstore` and
  `~/.credstore`.
- **Windows**: `deploy/install.ps1` (run elevated) creates the service with the virtual
  account (`sc.exe create credstore ... obj= "NT SERVICE\credstore"`), creates local groups
  `credstore-agents` and `credstore-approvers` (`New-LocalGroup`), adds the current user to
  both, sets ACLs on `%ProgramData%\credstore` (`icacls`), and builds the pipe ACLs from the
  group SIDs. Claude Code deny rules cover `%ProgramData%\credstore` and
  `%USERPROFILE%\.credstore`.
- Each installer prints the `claude mcp add credstore -- credstore mcp` line.

---

## 9. Milestones

Work in order. Commit after each milestone. Do not start the next until the acceptance
checks pass. Use fake secrets in all tests and fixtures.

Platform order: build and test each milestone first on Windows in dev mode, then on Linux
through WSL2, then on macOS. M7 (installed mode) is done per OS in that same order. A
milestone is not done until CI is green on all three OSes. Record what is stubbed per OS in
`docs/DESIGN.md`.

**M0: Skeleton**
Workspace, CI matrix (Windows, Linux, macOS), `credstore-proto` types + framing with
round-trip tests, `credstore-os` crate with the trait definitions and stub implementations
for all three OSes, `tracing`.
Accept: `cargo test` green on all three CI targets; framing rejects oversize and malformed
frames.

**M1: Vault + CLI**
`init`, `set`, `list`, `rm` against `credstore-core` vault (age, atomic writes, sidecar
index, mode 0600). In dev mode, no daemon yet.
Accept: vault file contains no plaintext value; wrong passphrase fails; index has no
values; killing the process mid-write never corrupts the vault.

**M2: Daemon, sockets, peercred, audit**
`credstored` with agent + approver endpoints through the `credstore-os` IPC trait (Unix
sockets, Windows named pipes), peer identity check, locked-by-default, hash-chained audit
log with `audit verify`. Dev mode only; no service install yet.
Accept: peer identity (uid/pid, or SID/pid on Windows) logged on every OS; tampering with a log line is detected by `verify`; frames over
limit rejected; approver requests without proof are refused.

**M3: Policy engine**
TOML parse, validation with clear errors, glob matching, `strict` mode, SIGHUP reload.
Accept: table-driven tests covering allow/deny by command, dir, shell mode, TTL cap.

**M4: Approvals + watch TUI**
Pending queue, `credstore watch` showing full request, passphrase proof on `/dev/tty`,
rate limit, `once` / `session` grants, idle relock.
Accept: request blocks until approved; wrong passphrase rate-limited; piping stdin to
`watch` cannot approve; grant expires on TTL; `lock` zeroizes (test with a debug hook
that scans a test buffer, not real secrets).

**M5: Runner + redaction + sandbox**
Cleared-env spawn, env/file/stdin injection, timeout + process-tree kill (process group on
Unix, Job Object on Windows), output caps, redaction (all encodings in 6.5), per-OS sandbox
from 4.1 with fallback and audit of the mode applied.
Accept: adversarial suite below passes.

**M6: MCP shim**
`credstore mcp` exposing `list_secrets` and `run_with_secrets` with strict schemas, clear
tool descriptions, blocking approval with timeout.
Accept: works end to end from Claude Code in dev mode; tool results never contain secret
values.

**M7: Install + doctor + docs**
Installers per OS (systemd unit + `install.sh`; launchd plist; `install.ps1`),
`credstore doctor` on every OS, README with threat model and "what this does not protect
against", sample policy.
Accept: on each OS (Windows, Linux via WSL2 with systemd enabled, macOS), install, add a
secret, run an approved command from Claude Code; `doctor` reports the agent user cannot
read the vault, and reports honestly which sandbox and hardening features are active.

(v2 backlog: auth proxy, phone approval, remote VPS via SSH-forwarded socket, hardware key
approval, stronger Windows sandbox via AppContainer, Windows/WSL bridging.)

---

## 10. Adversarial test suite (must exist and pass by M5)

Each test uses a fake secret `FAKE-SECRET-VALUE-12345` and asserts it never appears in the
returned output, audit log, tracing output, or any file under the agent-readable tree.

- Command `echo $KEY`, `printenv`, `env`, `set`, `cat /proc/self/environ`. On Windows also
  `cmd /c echo %KEY%`, `cmd /c set`, `powershell -Command Get-ChildItem Env:`.
- Command encodes the secret: base64 (3 alignments), hex, URL-encoding, reversed
  (document reversed/rot13 as a known bypass, mark the test `#[ignore]` with a comment).
- Command tries to read the vault, policy and audit paths (5.4) and the daemon's memory
  (`/proc/<daemon pid>/mem` on Linux, `task_for_pid` on macOS, `OpenProcess` with
  `PROCESS_VM_READ` on Windows).
- Command tries to open network connections when policy says `network = "deny"`.
- Command forks a background process that outlives the timeout (must be killed).
- Output flood (1 GB of stdout) is capped and the process killed.
- Agent socket client tries approver-only requests (must be rejected).
- Approver socket client sends `approve` without a valid passphrase (must be rejected).
- Request with unknown secret, relative cwd, empty reason, oversize argv, NUL bytes.
- Concurrent requests: approvals never cross-apply to a different request.
- Crash/kill the daemon mid-run: no temp secret files remain after restart (the daemon
  sweeps its run directory on startup).

---

## 11. Security requirements checklist

MUST:

- Hold secret values only in `secrecy::SecretBox`/`Zeroizing` types; `Debug` impls print
  `[REDACTED]`.
- Keep values out of argv, logs, panics, error messages, and `tracing` fields.
- Verify peer creds on every connection; treat PIDs as informational, UIDs as the check.
- Fail closed: any parse error, missing policy, missing sandbox under `require`, or
  unreachable approver means deny. A platform feature that is unavailable (no sandbox, no
  peer identity) is never silently skipped: it is reported in the audit log and the
  approval prompt, and the request is denied when policy requires it.
- Use constant-time comparison for any token/MAC comparison.

MUST NOT:

- Add a tool, CLI flag, or debug endpoint that returns a secret value to the agent side.
- Cache the passphrase or vault key on disk or in environment variables.
- Inherit the daemon environment into children.
- Trust the `reason` text for anything except display.

---

## 12. Decisions made (change only with the human's say-so) and open questions

Decided:

- Rust, one codebase for Windows, Linux and macOS (built and tested in that order, Linux
  through WSL2), single binary + daemon, separate OS user, passphrase-authenticated
  approval, age vault (scrypt KDF), env injection default, MCP via stdio shim.

Open (use the default, note it in the README, ask if it blocks you):

- Phone approval channel: defer to v2 (default: none in v1).
- Windows sandbox strength: v1 is Job Object + restricted token with no per-process network
  control; AppContainer is v2.
- Windows and WSL on the same machine: independent installs and vaults, no bridging in v1.
- Per-secret rate limits on how often a secret may be used: default none in v1.
- Whether approvals may be remembered "always for this exact command": default no in v1;
  only `once` and `session`.

---

## 13. Instructions to the implementing agent

- Work milestone by milestone; keep each commit focused and runnable.
- Write tests first for security-relevant behavior (policy, redaction, approval proof).
- Do not add dependencies beyond section 4 without a one-line justification in the commit.
- Never print, log, or echo real secrets. If you need a secret to test something, use the
  fake value from section 10.
- If a requirement here is ambiguous or conflicts with another, stop and ask; do not
  guess on anything in sections 2, 6.3, or 11.
- Keep a `docs/DESIGN.md` updated with any deviation from this spec and why.
- Keep platform code inside `credstore-os`. Do not claim a platform feature works until a
  test on that OS proves it; list anything stubbed per OS in `docs/DESIGN.md`.
- At the end of each milestone, summarize: what passes, what is stubbed, what you chose
  where the spec was silent.
