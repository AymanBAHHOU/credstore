# credstore

A local secret broker that lets coding agents (Claude Code and similar) **use** secrets
without **seeing** them.

The agent asks: "run `pytest tests/billing` with `STRIPE_KEY`, because I need to test
the webhook". You see exactly that request in `credstore watch` and approve it with your
vault passphrase. The command runs with the secret injected, and the agent gets back only
the output, with the value redacted. No tool, flag or endpoint returns a secret value.

Windows, Linux (including WSL2) and macOS, one Rust codebase. Everything runs locally.
The full design is in [SPEC.md](SPEC.md); where the code differs from it, and why, is in
[docs/DESIGN.md](docs/DESIGN.md).

```
 your user (untrusted)                        credstore user (trusted)
 ┌──────────────────────┐   agent endpoint   ┌──────────────────────────────┐
 │ Claude Code          │                    │ credstored                   │
 │   └ credstore mcp ───┼───────────────────►│  policy, approvals, vault,   │
 │     (holds nothing)  │                    │  sandboxed runner, redaction,│
 │ credstore watch  ────┼───────────────────►│  hash-chained audit log      │
 │   (your terminal)    │ approver endpoint  └──────────────────────────────┘
 └──────────────────────┘  (passphrase on every request)
```

## Install

**From a release** (Releases page of this repository):

| OS | Package | Install |
| --- | --- | --- |
| Windows | `credstore-VERSION-x64.msi` | double-click, or `msiexec /i credstore-VERSION-x64.msi` |
| macOS | `credstore-VERSION.pkg` | double-click, or `sudo installer -pkg credstore-VERSION.pkg -target /` |
| Debian, Ubuntu, WSL2 | `credstore_VERSION_amd64.deb` | `sudo apt install ./credstore_VERSION_amd64.deb` |
| Fedora, RHEL | `credstore-VERSION.x86_64.rpm` | `sudo dnf install ./credstore-VERSION.x86_64.rpm` |

The package installs the service and allows the user who installed it (no need to sign
out first). Then run, as yourself:

```bash
credstore setup
```

It creates the vault (you choose the passphrase) and, if you agree, registers credstore
with Claude Code for all folders and adds Claude Code deny rules for `.env` files and
credstore's own files. On Windows a Start menu entry, "credstore setup", runs the same
thing.

**Desktop app.** The Windows and macOS packages also install the credstore app (Start
menu "credstore", or `/Applications/credstore.app`); on Linux install
`credstore-app_VERSION_amd64.deb` (or the `.rpm`) too. It does the same as the commands
below without a terminal: approve requests (each one slides out of a small island at the top of the screen,
where you can decide without opening the window),
see the activity history and requests the policy refused, add and remove secrets and
choose the hosts and commands each one may be used with, grant folders, connect Claude
Code, run the health check, and turn Windows Hello approval on or off. Closing the
window keeps it in the tray. Every approval needs the passphrase, or Windows Hello.

On Windows the installer ends on a page that offers to open the app; no sign-out is
needed (the installer lets your account in directly, not only through the groups).

Builds are not code-signed yet, so Windows SmartScreen and macOS Gatekeeper warn before
installing (on macOS: right-click the package, then Open). The MSI also turns on page
file encryption (applies after a restart); pass `ENCRYPTPAGEFILE=0` to leave it alone.

**From source** (Rust stable):

```bash
cargo build --release
```

**Linux** (systemd; on WSL2 set `systemd=true` under `[boot]` in `/etc/wsl.conf` first)
and **macOS**:

```bash
sudo ./deploy/install.sh
```

**Windows**, from an elevated PowerShell:

```powershell
.\deploy\install.ps1
```

The installers create the service account (`credstore`, `_credstore` on macOS,
`NT SERVICE\credstore` on Windows) and the groups `credstore-agents` and
`credstore-approvers`, and add you to both. They also set up the directories with the
permissions below, write a starter policy, and start the service. They are safe to
re-run. `--uninstall` / `-Uninstall` removes the service and binaries but keeps the
vault, policy and audit log.

Then, as yourself:

```bash
credstore setup           # create the vault, connect Claude Code (asks first)
credstore set STRIPE_KEY  # the value is prompted for, never taken from argv
credstore grant ~/code/app  # let approved commands run in a project folder
credstore doctor          # check the install
```

| Item     | Linux / WSL2                     | macOS                             | Windows                               |
| -------- | -------------------------------- | --------------------------------- | ------------------------------------- |
| Vault    | `/var/lib/credstore/`            | `/var/db/credstore/`              | `%ProgramData%\credstore\`            |
| Policy   | `/etc/credstore/policy.toml`     | `/etc/credstore/policy.toml`      | `%ProgramData%\credstore\policy.toml` |
| Audit    | `/var/log/credstore/audit.jsonl` | `/var/log/credstore/audit.jsonl`  | `%ProgramData%\credstore\audit.jsonl` |
| Sockets  | `/run/credstore/*.sock`          | `/var/run/credstore/*.sock`       | `\\.\pipe\credstore-{agent,approver}` |

Your account cannot read any of these. Editing the policy and reading the audit log need
`sudo` (or an elevated shell on Windows). `credstore reload` applies policy edits.

### Dev mode (no install)

`credstored --dev` runs the daemon as you, with everything under `~/.credstore`. Use
`credstore --dev ...` with it. **Dev mode is weaker**: the agent runs as you too, so it
can read the (encrypted) vault file and the daemon's memory. It is for development and
trying credstore out, not for real secrets.

### Installed mode: where commands run

Approved commands run as the **service account**, not as you. They need access to the
project folders they run in. Give it with:

```bash
credstore grant /path/to/project    # default: the current folder
```

It shows the commands it will run (`icacls` on Windows, `setfacl` on Linux, `chmod +a`
on macOS), asks, and runs them as you: you own the folder, so no admin rights are
needed. If an agent asks to run somewhere the service cannot open, the request is denied
with the `credstore grant` command to run.

On Windows, `credstore grant` also opens the folder to the AppContainer that approved
commands run in, so run it for project folders in dev mode too. Without it, commands
there run with the weaker Job Object sandbox, and the approval screen says so.

The service account does not see your home directory's config (SSH keys, git
credentials) or tools installed only for you (a Python under `AppData`, global npm
packages, `~/.local/bin`). Install tools the agent should run machine-wide.

On Linux the unit also sets `MemoryDenyWriteExecute=yes`, which the commands inherit:
JIT runtimes (Node.js, Java, some Python builds) fail under it. To allow them, add a
drop-in with `sudo systemctl edit credstored`:

```ini
[Service]
MemoryDenyWriteExecute=no
```

On macOS, folders under `~/Desktop`, `~/Documents` and `~/Downloads` are also protected by
macOS privacy controls; keep projects elsewhere (for example `~/code`).

### Approve with Windows Hello

```bash
credstore hello enrol     # asks for the passphrase, then Windows Hello
```

After that, `credstore watch` and the desktop app confirm each approval with Windows
Hello (face, fingerprint or PIN) while the vault is unlocked. Unlocking, changing
secrets and `credstore run` still take the passphrase, and the passphrase always works
when Hello is cancelled. `credstore hello remove` undoes it; the app's Security page has
the same switch. Touch ID on macOS is not supported yet.

## Use with Claude Code

```bash
claude mcp add credstore -- credstore mcp
```

(`credstore --dev mcp` for dev mode.) This gives the agent three tools:

- `list_secrets`: names and descriptions only.
- `run_with_secrets`: argv (or a shell string, if policy allows it), the secret names, a
  reason of 10 to 300 characters, an optional cwd, timeout and injection mode (`env`,
  `file` or `stdin`). The call blocks until you decide in `credstore watch`.
- `http_request`: an HTTPS request that credstored sends itself, with one secret in one
  header (see [HTTPS APIs](#https-apis-http_request)). Also blocks until you decide.

Keep `credstore watch` open in a terminal. It shows the full request (command, folder,
secrets, reason, sandbox and anything **not** enforced) and asks for your passphrase to
approve once or for a session. Piped input cannot approve.

**Do not allowlist** credstore's tools in Claude Code, so Claude Code asks you too.
`doctor` warns if they are. **Add deny rules** so the agent cannot read secrets that are
still lying around, or credstore's files. For example, in `~/.claude/settings.json`:

```json
{
  "permissions": {
    "deny": [
      "Read(**/.env*)",
      "Read(//var/lib/credstore/**)",
      "Read(//etc/credstore/**)",
      "Read(~/.credstore/**)"
    ]
  }
}
```

In Claude Code rules `//` starts an absolute path and `~/` your home. On macOS use
`//var/db/credstore/**`; on Windows `//c/ProgramData/credstore/**` and `~/.credstore/**`.
Check Claude Code's permissions documentation if your version writes paths differently.

You can also run a command yourself: `credstore run -s STRIPE_KEY -- stripe listen`. The
passphrase you type is the approval, and policy still applies.

## Policy

[deploy/policy.toml](deploy/policy.toml) is the starter policy. Any secret without its
own block uses `[defaults]`, which allows any command but always asks you. The desktop
app edits a secret's hosts and commands and the vault and approval timers for you (with
the passphrase, keeping the file's comments); on Linux and macOS installs the file
belongs to root, so edit it with sudo there. A stricter
example:

```toml
[defaults]
require_approval = true
max_runtime_secs = 120
max_output_bytes = 20000
sandbox = "require"        # deny if the sandbox cannot enforce everything below
network = "deny"
strict = true              # deny secrets that have no [secret.NAME] block

[secret.STRIPE_KEY]
allow_commands = ["stripe *", "pytest *"]
allow_dirs     = ["/home/you/projects/billing/**"]
grant_ttl_secs = 600       # "approve for this session" lasts at most 10 minutes
injection      = ["env"]

[secret.PROD_DB_URL]
grant_ttl_secs = 0         # approve every single use
```

### HTTPS APIs: `http_request`

For an API that takes the key in a header, the agent can call the MCP tool
`http_request` instead of running `curl`: credstored sends the HTTPS request itself and
returns the redacted response, so no command ever holds the key. A secret can be used
this way only if its policy lists the hosts it may be sent to:

```toml
[secret.OILPRICEAPI_KEY]
network     = "allow-list"
allow_hosts = ["api.oilpriceapi.com"]   # also "*.example.com", "host:8443"
```

The approval shows the method, URL, the header with `{value}` where the key goes, the
other headers and the start of the body. Only `https://` URLs are allowed, redirects are
not followed, and the daemon ignores `HTTP(S)_PROXY`.

A request that breaks the policy is denied before you are asked. Shell mode (`sh -c`,
`cmd /c`, `powershell -Command`) is denied unless `allow_shell = true`. On Windows, write
`allow_dirs` as `C:/Users/...`.

## Threat model

| Actor                                | Can                                                       | credstore prevents                                                   |
| ------------------------------------ | --------------------------------------------------------- | -------------------------------------------------------------------- |
| Prompt-injected or misbehaving agent | run commands as your user, read your files, call MCP tools | reading values or the vault, approving its own requests, values in output |
| Other processes of your user         | the same                                                  | the same                                                             |
| Thief of the vault file              | has the encrypted file                                    | decrypting it without the passphrase (age, scrypt)                   |
| Reader of logs and transcripts       | reads the audit log and MCP transcripts                   | finding values anywhere                                              |

How:

- **A separate OS account.** The daemon, the vault and its memory belong to the service
  account, which your account (and so the agent) cannot read.
- **Approval needs something the agent does not have**: the vault passphrase, typed on a
  real terminal, checked by the daemon on every approver request. A connection alone
  grants nothing.
- **Policy, sandbox and a cleared environment** limit what an approved command can do;
  every gap is shown on the approval screen and in the audit log.
- **Redaction** of every output (exact value, line by line, URL, hex, JSON and base64
  forms) is a safety net, not the control.
- **A hash-chained audit log** of every request, decision and run;
  `credstore audit verify` finds a tampered or removed line.

## What this does not protect against

- **An approved command that leaks the secret on purpose.** It can encode it in a way
  redaction does not catch (reversed, split, compressed, encrypted), write it to a file
  the agent can read, or send it over the network. **You** are the control: read the
  command before approving. Restricting commands and folders in the policy, and
  `network = "deny"`, narrow it.
- **Network allow-lists are not enforced for commands.** `allow_hosts` limits where
  `http_request` sends a secret; a command run with that secret still has normal network
  access. With `sandbox = "require"` such runs are denied, with `prefer` they run and the
  approval screen says so. For HTTPS APIs, `http_request` closes this gap.
- **Windows: the AppContainer needs a granted folder and a machine-wide program.**
  Commands run in an AppContainer that sees only Windows, Program Files, folders opened
  with `credstore grant`, and its own temp folder, with no network unless allowed. A
  run in another folder, or of a program installed per user (for example under
  `%LOCALAPPDATA%`), falls back to a Job Object, which hides no files and cannot block
  the network; the approval screen says so, and `sandbox = "require"` denies it. On
  Windows Server, commands in the AppContainer cannot open `NUL` (`>NUL` fails with
  "Access is denied"); Windows 10 and 11 are fine.
- **Root, administrators, and anyone with debug privileges.** They can read any
  process's memory and any file. An agent running as an administrator (elevated, or with
  `SeDebugPrivilege` enabled) defeats the separate account. Run your agent as a normal
  user. `doctor` warns when it runs privileged.
- **A compromised OS or malware running as root** (spec non-goal).
- **Dev mode**, by design (see above).
- **Shoulder-surfing your passphrase**, or a keylogger in your session. On Windows,
  `credstore hello enrol` lets Windows Hello confirm approvals, so the passphrase is
  typed once per unlock instead of for every decision.
- **Over-broad secrets.** Use scoped, low-privilege keys where the provider has them.
- **Keys in memory are not locked.** The daemon disables core dumps and debugger attach
  where the OS allows it, but does not `mlock` / `VirtualLock` the vault, so it can reach
  swap. `doctor` lists what is active.
- **Commands that outlive the run** by leaving its process group (`setsid`) survive the
  kill under Landlock or no sandbox; bubblewrap and Windows Job Objects catch them.

## `credstore doctor`

Run it as the account your agent uses. It checks the service, your group membership,
that your account **cannot** read or write the vault, index or policy (it fails loudly
if it can), that both endpoints answer as the real daemon, and whether your account can
open the daemon's memory. With your passphrase, it shows the daemon's sandbox and each
memory hardening feature, active or not. It also warns if Claude Code allowlists
credstore's tools. It exits non-zero if anything failed.

## Status

All seven milestones in [SPEC.md](SPEC.md) are built. CI runs on Windows, Linux and
macOS: the unit and integration tests, the adversarial suite (spec 10) with each sandbox
and with none, an MCP session against the real binary, and the installers on fresh
runners, driving the installed service as a member of the groups (run, redaction,
`doctor`), then uninstalling.

Not verified:

- A session with Claude Code itself. The MCP shim is tested over stdio the way Claude
  Code drives it, but registering it changes Claude Code's configuration, which these
  sessions did not do.
- WSL2 with systemd, and macOS, on a real machine: CI covers Ubuntu and macOS runners,
  and WSL2 was used only in dev mode.
- `credstore watch` and the passphrase prompt on a real terminal (CI has none; piped
  input is tested to be refused).

Open questions use the spec's defaults (section 12): no phone approval in v1; Windows
sandbox is an AppContainer (no restricted token, see docs/DESIGN.md); Windows and WSL
installs are independent; no per-secret usage limits; only `once` and `session`
approvals, never "always".
