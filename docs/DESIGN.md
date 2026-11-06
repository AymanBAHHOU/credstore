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

## Daemon, endpoints and audit (M2)

- **No `interprocess` crate.** tokio already provides Unix sockets with
  `UnixStream::peer_cred()` (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED`/`getpeereid` on
  macOS) and Windows named pipes. `interprocess` does not expose peer identity, which
  credstore needs on every connection.
- **The daemon is a library** (`credstored::start`) with a thin binary, so integration
  tests run real daemons in-process on temp homes, in parallel.
- **The CLI goes through the daemon** for every vault command, including `init` (new
  approver operation `admin_init`: the proof's passphrase becomes the vault passphrase,
  refused if a vault exists). So `credstored --dev` must be running for `credstore
  --dev ...`.
- **Peer check, Unix:** at accept time. Dev: peer UID must equal the daemon's. Installed:
  the peer's user must be in the endpoint's group (primary group or member list). The
  socket file is 0600 (dev) or 0660 with the group (installed), in a 0700 directory in
  dev mode.
- **Peer check, Windows:** the pipe ACL comes from SDDL: owner set to the daemon's SID;
  dev grants only the daemon's user; installed grants the group read/write/attributes
  but not `FILE_CREATE_PIPE_INSTANCE`, so a client can't create a rogue server instance.
  `first_pipe_instance` refuses to start if the name is already taken, and remote clients
  are refused. The client SID comes from briefly impersonating the client (Windows only
  knows it after the client has written, so the daemon authorizes after the first frame
  and before acting on it). Installed mode checks group membership with
  `CheckTokenMembership`. A failed `RevertToSelf` aborts the process.
- **Clients verify the daemon** before sending a passphrase: Unix checks the socket
  file's owner and the peer UID (the daemon's UID in dev, the `credstore`/`_credstore`
  user installed); Windows checks the pipe's owner SID (own SID in dev,
  `NT SERVICE\credstore` installed). This stops an impostor that creates the endpoint
  first from collecting passphrases.
- **Every approver request carries a proof**, checked by decrypting the vault (about
  0.5-1 s; scrypt runs on a blocking thread). Checks and vault writes are serialized,
  so the rate limit counts attempts one at a time and concurrent `set`s can't lose
  updates. Rate limit: 5 wrong passphrases, then 60 s lockout, doubling per lockout; a
  correct passphrase resets it. During a lockout even the right passphrase is refused.
- **Locked by default.** Admin operations (`set`, `rm`, `status`) do not unlock the vault;
  only `unlock` and (M4) approvals do. `lock` wipes every value (`VaultContents::wipe`
  zeroizes each one in place) and the audit `lock` record says how many were wiped, which
  is how the integration test checks zeroization without reading freed memory.
- **Audit log:** canonical JSON (keys sorted recursively, no whitespace) so the hash does
  not depend on serde_json map ordering. Each record is fsynced. On open, the chain
  continues from the last complete record; a partial last line (crash) is left in place
  and reported by `verify`. Trailing records removed from the end can't be detected by
  the chain alone; the append-only attribute (installed mode, M7) covers that.
- **Extra audit events** (not in spec 5.3): `auth_failed` (wrong passphrase, with
  peer), `daemon_started`, `daemon_stopped`. Connections are logged with `tracing`
  (uid/sid, pid, exe) rather than as audit records, to keep the audit log to decisions.
- **Memory hardening:** Linux `PR_SET_DUMPABLE=0` and `RLIMIT_CORE=0`; macOS
  `PT_DENY_ATTACH` and `RLIMIT_CORE=0`; Windows a protected process DACL. **mlock /
  VirtualLock are not applied** and are reported as unavailable: values are many small
  heap allocations, and `mlockall` would make the 256 MiB scrypt allocation fail under
  the default memlock limit. Mitigation: encrypted swap / page file.
- **Windows process DACL:** SYSTEM full; Owner Rights and the daemon's user get only
  query, query-limited, synchronize and terminate. No memory read/write, handle
  duplication or DACL change. Terminate is allowed so a user can always stop their dev
  daemon (`taskkill`, Task Manager, Ctrl-C). PowerShell's `Stop-Process` asks for full
  access and is refused; use `taskkill /PID <pid> /F`.
- **WER:** crash dialogs are turned off with `SetErrorMode`; a machine-wide LocalDumps
  policy could still write a dump, so this is reported as partial.

- **Dev socket paths on macOS:** a Unix socket path must fit in 104 bytes, and macOS temp
  dirs are long. When `<dir>/approver.sock` would be over 100 bytes, dev-mode sockets
  go in `/tmp/credstore-<uid>-<hash>`. `bind` refuses any socket directory that is not
  owned by the daemon's user or that others can write (in same-user mode, read either),
  so a directory someone else created in `/tmp` can't be used to swap the socket.

## Policy (`credstore-core::policy`, M3)

- **Format** as in spec 5.2, with these keys added under `[defaults]`: `strict`,
  `grant_ttl_secs`, `session_idle_secs`, `approval_timeout_secs`, `allow_shell`,
  `injection`, `allow_hosts`. Every per-secret key can also be set in `[defaults]`
  except `allow_commands` and `allow_dirs`. Unknown keys are errors, so a typo like
  `allow_dir` can't silently allow everything. An empty `allow_commands = []` is an
  error rather than "allow nothing" (remove the key, or the secret).
- **Validation:** numbers have ranges (runtime 1 s to 24 h, output 1 byte to 16 MiB, TTLs
  at most 24 h, approval timeout 1 to 3600 s); `allow-list` needs a non-empty
  `allow_hosts`, and `allow_hosts` without `allow-list` is an error; secret names follow
  the vault rules. Errors name the table and key.
- **Fail closed:** a missing, unreadable or invalid policy does not stop the daemon, but
  every run is denied with the reason until a reload succeeds. `credstore status` shows
  the policy error; `credstore reload` returns it. A failed reload replaces the old
  policy with "deny everything" rather than keeping it.
- **Starter policy:** in dev mode, `init` writes one (defaults only, plus a commented
  example) if none exists. Installed mode: the installer writes it (M7).
- **Reload:** `credstore reload` everywhere; SIGHUP on Linux and macOS. Each attempt is
  audited as `config_reloaded` with `trigger` (`startup`, `init`, `request`, `signal`),
  `ok` and `error`.
- **Multiple secrets:** the request must pass every secret's rules. Effective limits are
  the strictest: shortest runtime and output cap, smallest grant TTL, strictest sandbox
  and network, and the intersection of allow-lists (empty intersection is a denial).
  `timeout_secs` from the request can shorten the runtime, never lengthen it.
- **Command matching.** The daemon resolves `argv[0]` itself (`credstore-os::exec`):
  bare names through the daemon's `PATH` (absolute entries only, never the working
  directory, which Windows would otherwise search first), names with a path relative to
  the canonical `cwd`. The result is canonicalized (symlinks and `..` resolved), and that
  path is what runs. `allow_commands` patterns are matched against the command line
  `program + " " + args`, where `program` is the resolved full path, or, if `argv[0]`
  was a bare name, also that name. So `stripe *` allows `stripe listen` found on PATH
  but not `./stripe listen` or `/tmp/stripe listen`; to allow a path, write the path.
  In commands `*` matches anything including `/` (URLs). In `allow_dirs`, `*` stays in
  one path component and `**` crosses components; `dir/**` also matches `dir` itself.
- **Shell mode** (stricter than the spec's `sh -c` wording): a `shell` string, or argv
  whose program is a shell (`sh`, `bash`, `zsh`, `dash`, `ksh`, `fish`, `csh`, `tcsh`,
  `busybox`, `cmd`, `powershell`, `pwsh`, ...) with any arguments, or a wrapper (`env`,
  `xargs`, `nohup`, `timeout`, `sudo`, ...) whose arguments name a shell. Running a
  shell script by path is shell mode too. Each secret must set `allow_shell = true`.
- **Windows matching:** command lines and paths are case-folded, backslashes become `/`,
  the `\\?\` prefix is dropped, and `.exe`/`.cmd`/`.bat`/`.com` are dropped from the
  program.
- **Request checks before policy** (`credstore-core::request`, spec 6.2 step 2): exactly
  one of argv/shell; at most 256 args and 64 KiB; no NUL bytes; 1 to 16 distinct valid
  secret names that exist in the index; `reason` 10 to 300 characters with no control
  characters (it is shown on the approval screen, where escape codes could rewrite what
  the human sees); absolute, existing `cwd` (canonicalized); `stdin` injection with
  exactly one secret; the program must resolve. These errors never quote the input.
- **Audit:** `request` (peer, secrets, argv or shell, resolved program, cwd, reason,
  injection) for every well-formed request, then `policy_denied` with `denial` when
  policy refuses it. Malformed requests are refused without an audit record.
- **Until M4,** a request that passes policy is answered with a denial saying approvals
  are not built yet.

## Stubbed per OS

| Capability      | Linux                 | macOS                 | Windows               |
| --------------- | --------------------- | --------------------- | --------------------- |
| Paths           | done                  | done                  | done                  |
| Private files   | done (0600/0700)      | done (0600/0700)      | stub, M7 (inherits folder ACL) |
| Atomic replace  | done                  | done                  | done                  |
| Terminal prompt | done (`rpassword`)    | done (`rpassword`)    | done (`rpassword`)    |
| IPC             | done (Unix socket)    | done (Unix socket), CI only | done (named pipe) |
| Peer identity   | done (uid, pid, exe)  | done (uid, pid; no exe) | done (SID, pid, exe) |
| Group check     | done, untested (needs install) | done, untested | done, untested |
| Memory guard    | dumpable, core limit; no mlock | deny-attach, core limit; no mlock | DACL; WER partial; no VirtualLock |
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
