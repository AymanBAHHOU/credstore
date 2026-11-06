# credstore design notes

Deviations from [SPEC.md](../SPEC.md), decisions where the spec was silent, and what is
stubbed per OS. Kept current at every milestone.

## Decisions made with the human (2026-11-06)

These settle gaps in the spec. They were confirmed by the human, not guessed.

1. **`credstore run` (human-initiated) is approved in place.** The CLI prompts for the
   passphrase on its own terminal and sends an `admin_run` request on the approver
   endpoint. No separate `watch` window is needed. Policy checks and audit logging are the
   same as for agent requests.
2. **Every approval needs the passphrase, even while the vault is unlocked.** The idle
   unlock window (6.3) only avoids decrypting the vault again. `session` grants are what
   skip prompts for repeat requests.
3. **`set` and `rm` go through the daemon** as passphrase-authenticated `admin_set` /
   `admin_rm` requests on the approver endpoint, so installed mode (where the human's user
   cannot write the vault) works through one code path. In M1, before the daemon exists,
   the CLI uses `credstore-core` directly in dev mode only.
4. **Dev mode checks the same user only.** Dev endpoints accept only the daemon's own
   UID (Unix) or SID (Windows), and log peer identity. They do not check
   `credstore-agents` / `credstore-approvers` membership, so development needs no admin
   setup. Installed mode enforces the groups.

## Protocol (`credstore-proto`)

- Envelope is `{"v": 1, "msg": <message>}`. The spec only requires `"v": 1`; `msg` keeps
  the version separate from message fields so the version is checked before the message
  is parsed.
- Messages are internally tagged (`"type": "list_secrets"`) and every struct uses
  `deny_unknown_fields`. An approver request cannot parse as an agent request, and an
  unknown type (for example a `get_secret`) is a parse error.
- **Every approver request carries a passphrase proof**, structurally: `ApproverRequest`
  is `{proof, op}`, so there is no way to build one without a proof. This follows 3.2
  literally, including `subscribe_pending`, `deny` and `lock`.
- Added `admin_run` for decision 1. Added `status` and `reload` as approver operations
  (the spec lists the CLI commands but not their wire operations).
- `SecretText` holds passphrases and `admin_set` values: zeroized on drop, `Debug` prints
  `[REDACTED]`, no `Display`. Frame buffers are `Zeroizing<Vec<u8>>`.
- **Parse errors never quote input.** serde_json's error messages can quote the bad value,
  which could be a secret. `FrameError::Malformed` keeps only the category and the
  line/column.
- Known gap: serde_json's internal buffer for strings with escapes is not zeroized. This
  matters only for approver frames, and only in daemon and CLI memory.

## Platform layer (`credstore-os`)

- Traits: `Paths`, `Ipc` (+ `IpcListener`, `IpcStream`), `PeerIdentity`, `Sandbox`,
  `MemoryGuard`, `ServiceInstall`, `Terminal`. One `Platform` struct implements all of
  them for the target OS. The trait shapes for `Sandbox` and `MemoryGuard` may change when
  M5 and M2 build the real implementations.
- `Ipc` uses `-> impl Future + Send` methods (no `async-trait` dependency); it is not
  object-safe, and callers are generic over it.
- The crate uses `unsafe_code = "deny"` instead of `forbid`, so a small commented module
  can opt in later. M0 has no unsafe code. Every other crate forbids it.
- **Dev endpoint names.** The spec gives one Windows dev pipe name
  (`\\.\pipe\credstore-dev-<username>`) but there are two endpoints, so they are
  `\\.\pipe\credstore-dev-<username>-agent` and `...-approver`.
- **Dev paths.** Home is `$CREDSTORE_HOME`, else `~/.credstore`; vault, index, policy and
  audit log live there. Sockets: Linux `$XDG_RUNTIME_DIR/credstore/`, macOS
  `$TMPDIR/credstore/`. If `CREDSTORE_HOME` is set (tests), or the runtime dir is
  missing, sockets go under `$CREDSTORE_HOME/run/`, and Windows pipe names get a short
  hash of the home path, so parallel test daemons don't collide.
- **Installed run dir** (not in spec 5.4): Linux `/run/credstore/run` (tmpfs), macOS
  `/var/run/credstore/run`, Windows `%ProgramData%\credstore\run`.

## Stubbed per OS

| Capability      | Linux                 | macOS                 | Windows               |
| --------------- | --------------------- | --------------------- | --------------------- |
| Paths           | done                  | done                  | done                  |
| Terminal prompt | done (`rpassword`)    | done (`rpassword`)    | done (`rpassword`)    |
| IPC             | stub, M2              | stub, M2              | stub, M2              |
| Peer identity   | stub, M2              | stub, M2              | stub, M2              |
| Memory guard    | stub, M2              | stub, M2              | stub, M2              |
| Sandbox         | stub, M5              | stub, M5              | stub, M5              |
| Service install | stub, M7              | stub, M7              | stub, M7              |

Stubs return `OsError::Unavailable("<mechanism> not built yet (Mx)")`; the daemon logs
each unavailable hardening feature at startup.

"Done" above means built and unit-tested for path resolution. The terminal prompt is not
yet exercised by an automated test (it needs a real tty; M4 adds the piped-stdin test).

## Dependencies added beyond spec section 4

- `tracing-subscriber`: needed to actually emit `tracing` output (stderr only) from the
  binaries.

## CI

`.github/workflows/ci.yml` runs fmt, clippy (`-D warnings`), tests and `cargo deny check`
on `windows-latest`, `ubuntu-latest` and `macos-latest`.
