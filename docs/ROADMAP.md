# Roadmap after v0.1

v0.1 (M0–M7) works end to end, but setting it up takes about seven manual steps, several
of them in an admin terminal. The next milestones fix the everyday pain first (M8–M10),
then the two largest security gaps (M11–M13). Each milestone is one commit with CI green
on Windows, Linux and macOS, and every design change is recorded in `docs/DESIGN.md`.

| | Milestone | What changes for the user |
|---|---|---|
| M8 | Releases and installers | Download and double-click: `.msi`, `.pkg`, `.deb`, `.rpm`. Optional page-file encryption and "Connect Claude Code" |
| M9 | No sign-out, no manual folder grants | Works right after install; the first run in a new folder asks to grant it |
| M10 | Desktop app (Tauri) | Setup wizard, approval notifications, secrets manager, audit viewer, health page |
| M11 | Auth proxy | `http_request`: credstored calls HTTPS APIs itself with the key in a header; no command ever holds it |
| M12 | Windows AppContainer sandbox | Windows approved commands lose file and network access, like Linux and macOS |
| M13 | Biometric approval | Windows Hello / Touch ID instead of typing the passphrase (passphrase stays as fallback) |
| M14 | Backup, recovery, rotation | Encrypted backup and restore, optional recovery key, rotation reminders |

## M8: releases and installers

- A tag `vX.Y.Z` builds release binaries and installers on each OS and attaches them to a
  GitHub release (draft until a human publishes it).
- Windows `.msi` built with WiX. Linux `.deb` and `.rpm` built with nfpm. macOS `.pkg`
  built with `pkgbuild`/`productbuild`.
- Each installer does what `deploy/install.*` do today (service account, groups, ACLs,
  starter policy, service) and also adds credstore to PATH.
- `credstore setup` does the per-user part the installer cannot do as the system:
  register the MCP server with Claude Code at user scope and add deny rules (with
  consent), and on Windows offer page-file encryption.
- CI installs the real packages on fresh runners and runs the M7 smoke test against them.
- Builds are unsigned until code-signing certificates exist (needs the owner: an Apple
  Developer account and a Windows code-signing certificate).

## M9: no sign-out, no manual folder grants

- Windows: the installer adds the installing user's SID to the pipe DACLs, which applies
  without a new logon. Linux/macOS: the daemon also accepts peers whose UID is in an
  allowed-users list written by the installer. Groups stay for multi-user machines.
- Folder grants: the user owns their project folders, so granting the service access
  needs no admin rights. `credstore grant <dir>` does it, and `credstore run` /
  `credstore watch` / the app offer it when a run's folder is not yet granted.
- Open decision for the owner: tools installed only for the user (per-user Python, npm,
  git credentials) are not visible to the service account.

## M10: desktop app

Tauri app in the tray. First-run wizard (vault, passphrase, Claude Code, folders),
approval notifications with the passphrase entered in the app, secrets manager (values are
write-only), audit log viewer, and a health page running `doctor`. It uses the same
approver endpoint as the CLI, so the security model does not change.

Built: everything above except the audit viewer, which would need the audit log readable
by approvers (see `docs/DESIGN.md`, "Desktop app").

## M11: auth proxy

Built as spec 6.6 designs it: an `http_request` MCP tool. The daemon sends the HTTPS
request itself with the secret in one header, only to hosts in the secret's
`allow_hosts`, and returns the redacted response; the secret never enters a process the
agent controls. (The per-run local proxy first sketched here would need loopback access
from inside the network sandbox; see `docs/DESIGN.md`.)

## M12: Windows AppContainer

Run approved commands in an AppContainer with a capability set that allows only the
project folder and loopback to the proxy.

Built: commands run in the `credstore.run` AppContainer inside the Job Object, through a
small launcher (`credstore-sandbox.exe`). No loopback proxy is needed, since
`http_request` is sent by the daemon. Folders the container was not granted, and
programs it cannot execute (per-user installs), fall back to the Job Object with the
reason on the approval screen; `sandbox = "require"` denies them.

## M13: biometric approval

Windows Hello / Touch ID gates approvals, so the passphrase is not typed where a
same-user keylogger could capture it. The passphrase remains as the fallback.

## M14: backup, recovery, rotation

Encrypted vault backup and restore, an optional recovery key, and reminders for secrets
older than a configured age.
