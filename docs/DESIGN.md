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

## Vault (`credstore-core::vault`, M1)

- **Fixed scrypt cost.** New vaults use N = 2^18 (256 MiB, about 0.5-1 s). age's default
  picks the cost by timing the machine, so a debug build or a busy CPU would silently
  write a weaker vault; a fixed cost avoids that. Opening accepts up to 2^20 (1 GiB) to
  bound memory. Unit tests use a cheap cost through a `cfg(test)`-only constructor, so
  no release build can reach it.
- **Debug builds optimize the KDF crates** (`scrypt`, `salsa20`, `pbkdf2`, `sha2`,
  `hmac` at opt-level 3 in `[profile.dev]`) so tests and dev use stay fast. This affects
  speed only, since the cost is fixed.
- **Plaintext is zeroized.** Decryption uses age's `Decryptor` directly and reads into a
  `Zeroizing` buffer; age's `decrypt()` helper returns a plain `Vec`. Values are
  `SecretText`.
- **The passphrase is never kept.** `Vault` holds only paths. `unlock` and `save` take
  the passphrase each time, matching decision 2: every write carries a fresh proof.
- **Wrong passphrase vs. damage.** With a scrypt stanza, age reports a wrong passphrase
  as `DecryptionFailed` while unwrapping the file key; that maps to `WrongPassphrase`.
  A damaged header that still parses can't be told apart from a wrong passphrase. A
  damaged payload is reported as `Corrupt`.
- **Names are encrypted too.** The vault plaintext holds names, descriptions,
  timestamps and values. The index holds names and descriptions only.
- **Write order: vault, then index.** The index is rebuilt from the vault on every save,
  so after a crash between the two writes it lags by at most one operation and repairs
  itself on the next `set` or `rm`.
- **Atomic writes** live in `credstore-os::fs`: temp file in the same directory, fsync,
  rename, fsync the directory (Unix). Leftover temp files from a killed writer are
  removed on the next write. On Windows the rename is retried briefly if another process
  (an indexer, antivirus) holds the file.
- **Crash test.** `killing_a_writer_never_corrupts_the_vault` starts the test binary
  itself as a writer that saves in a loop, kills it at a different point in each of 12
  rounds, and checks the vault opens and the index parses every time.
- **No locking between writers.** Two `credstore set` runs at the same moment can lose
  one update. From M2 the daemon is the only writer.
- **Input rules (not in spec):** names at most 128 chars; descriptions at most 300 chars
  with no control characters (they are shown in the approval TUI, where escape sequences
  could disguise a request); values non-empty, at most 64 KiB, no NUL (an environment
  variable can't hold one). `list` also masks control characters, since the index is a
  plain file. Error messages never repeat the input, in case a value was typed into the
  wrong place.
- **Minimum passphrase length: 8** (not in spec).

## CLI (M1)

- `init`, `set`, `list`, `rm` work in dev mode (`--dev`) directly on the vault file.
  Without `--dev` they refuse: installed mode needs the daemon (M2).
- Passphrase and value prompts read the controlling terminal through `Terminal`, never
  stdin. Checked by hand on both OSes: with piped stdin on Windows, `init` keeps waiting
  for console input; on Linux with no controlling terminal, it refuses. Neither creates a
  vault. The automated version is M4's piped-stdin test.
- `set` asks for the value once (no confirmation) and warns when it is shorter than 6
  characters, since redaction skips such values.
- The command logic (`credstore/src/commands.rs`) takes the prompt as a parameter, so
  tests script the answers without a terminal.

## Stubbed per OS

| Capability      | Linux                 | macOS                 | Windows               |
| --------------- | --------------------- | --------------------- | --------------------- |
| Paths           | done                  | done                  | done                  |
| Private files   | done (0600/0700)      | done (0600/0700)      | stub, M7 (inherits folder ACL) |
| Atomic replace  | done                  | done                  | done                  |
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

## Dependency advisories

- **age stays on 0.11.5.** age 0.12 pulls in `crypto-bigint` 0.5, which has a timing
  vulnerability (RUSTSEC-2026-0387).
- age 0.11 brings two crates flagged "unmaintained" (not vulnerable): `basic-toml`
  (RUSTSEC-2026-0374) and `proc-macro-error2` (RUSTSEC-2026-0173). Both run only at
  build time, for age's translated error messages. They are allowed by ID in
  `deny.toml`, with reasons, so any new advisory still fails CI. Revisit when age
  releases a version without them.

## CI

`.github/workflows/ci.yml` runs fmt, clippy (`-D warnings`), tests and `cargo deny check`
on `windows-latest`, `ubuntu-latest` and `macos-latest`.
