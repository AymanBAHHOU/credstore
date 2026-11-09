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
  them for the target OS. `Sandbox` only probes and plans (`sandbox_capabilities`,
  `sandbox_plan`); `credstore_os::run::run` applies the plan, because the runner and the
  sandbox wrap the same spawn.
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
  Clients therefore open the pipe with exactly those rights (`win::open_pipe_client`,
  identification-level QoS) rather than `GENERIC_WRITE`, which includes that right and
  is refused. `first_pipe_instance` refuses to start if the name is already taken, and remote clients
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
  the chain alone. In installed mode only root (or Administrators) and the service
  account can write the log. Not done: an append-only attribute (`chattr +a`,
  `chflags sappnd`); systemd's `LogsDirectory=` ownership fix-up cannot chown such a
  file, and Windows has no equivalent that also stops the directory's delete-child
  right. So truncating the tail needs root or the daemon's own account.
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
  example) if none exists. Installed mode: the installer writes the same text
  (`deploy/policy.toml`) and keeps an existing policy.
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
- **Canonical `allow_dirs`.** The cwd is matched in canonical form, so when the policy
  loads, each `allow_dirs` pattern's literal leading directory is canonicalized too (if
  it exists) and the pattern matches either form. Without this, `/var/folders/...` would
  never match on macOS (`/var` is a link to `/private/var`), nor would a Windows 8.3
  short name like `RUNNER~1`. Directories created after the policy loads need a reload
  for this.
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

## Approvals and `watch` (M4)

- **Pending queue** in the daemon, keyed by request id. Subscribers (`watch`) hold one
  approver connection open (`subscribe_pending`, with a passphrase proof); the daemon
  sends the full pending list at once and after every change. Sending anything on that
  connection, closing it, or daemon shutdown ends the subscription.
- **Every approve or deny is a separate approver request with a fresh passphrase
  proof** (decision 2), checked by decrypting the vault. A wrong passphrase counts
  toward the rate limit and the request stays pending. Approvals are by id, so they
  never apply to a different request; deciding an id twice fails.
- **Approval timeout** comes from `approval_timeout_secs` (default 120 s). On timeout
  the agent gets `approval timed out` and `denied` is audited with `via: "timeout"`.
- **Grants** (`session` scope) cover exactly the same request: same sorted secret set,
  same argv or shell string, same resolved program, same canonical cwd, same injection,
  same peer UID or SID (the PID is not part of it). The TTL is the smaller of what the
  approver asked for and the policy cap; a cap of 0 turns a session approval into
  `once`. Grants only help while the vault is unlocked: any lock (`credstore lock`, idle
  relock, shutdown) drops every grant, so after a lock the human is asked again.
- **`require_approval = false`** skips the human only while the vault is already
  unlocked (the daemon has no key otherwise). Audited as `approved` with
  `via: "policy"`.
- **Unlock after approval:** an approval leaves the vault unlocked in daemon memory until
  the idle TTL (`session_idle_secs`, default 600; 0 relocks right after each run,
  audited as a `lock` with reason `after-run`).
- **`watch` reads everything from the terminal.** The passphrase uses `rpassword`
  (`/dev/tty`, or the console on Windows); the o/s/d choice uses a plain line read from
  the same terminal, never stdin. With no terminal, `watch` exits with an error before
  connecting. `crates/credstore/tests/watch_stdin.rs` runs the real binary without a
  terminal (`setsid` on Linux, `DETACHED_PROCESS` on Windows; on macOS only when the
  test itself has no terminal, as in CI), pipes the passphrase and `o` into stdin, and
  checks that it refuses and the request stays pending.
- **What `watch` shows:** reason, argv (quoted for display), resolved program, cwd,
  secret names and descriptions, injection, sandbox mode, network policy and hosts, and
  the requester's uid/SID, pid and exe. Every agent-supplied string has control
  characters replaced, so an argv or path can't rewrite the screen.
- **New audit fields:** `approved` has `via` (`human`, `grant`, `policy`), `scope`
  (`"once"` or `{"session_secs": N}`) and the approver's peer; `denied` has `via`
  (`human`, `timeout`, `shutdown`, `disconnect`).
- **Zeroization check:** `lock` reports how many values it wiped, and the tests check
  that number. Values handed to an approved request are dropped (and zeroized) after
  use. Reading freed memory to prove it would need `unsafe` in tests, which the
  workspace forbids.

## Runner, sandbox and redaction (M5)

**Order of a run.** `prepare_run` validates, checks policy, refuses a cwd inside
credstore's own files, and plans the sandbox, all before the human is asked, so the
approval screen shows the sandbox mode and every gap (`sandbox_gaps` on
`PendingRequest`, shown as `NOT ENFORCED: ...` lines in `watch`). After approval the
runner (`credstored::runner`):

1. creates `<run_dir>/<request id>/` with `tmp/` and `files/` (0700; on Windows a
   protected DACL for this user and SYSTEM), removed by a drop guard on every exit path,
   panics included;
2. builds a cleared environment: `PATH` (the daemon's absolute `PATH` entries), `HOME`
   (`USERPROFILE` on Windows), `TMPDIR` (`TEMP`/`TMP`), `LANG` on Unix, and on Windows
   the standard system-defined variables (`SystemRoot`, `ComSpec`, `PATHEXT`, the
   `ProgramFiles`/`AppData` folders, `PSModulePath`, `PROCESSOR_*`, user and computer
   name), plus only the approved secrets (names compared case-insensitively on
   Windows). Deviation: spec 6.4 lists fewer Windows variables, but without
   `LOCALAPPDATA` Windows PowerShell rescans every installed module on each start
   (minutes on a CI image). None of these is user-defined or secret;
3. writes `run_started` to the audit log, and does not run if that write fails;
4. runs, kills the whole process tree whatever happened, redacts, writes `run_finished`
   (`exit_code`, `duration_ms`, `sandbox`, `stdout_bytes`, `stderr_bytes`, `truncated`,
   `timed_out`, `output_limit_hit`, `redactions`), and returns the result.

- **HOME.** Dev mode gives the child the human's real home (the daemon runs as the human,
  and tools need their config). Installed mode gives it the run's temp dir, since the
  daemon's home is the service account's.
- **Installed mode runs commands as the service user** (`credstore`), not as the human.
  Commands that need the human's files or credentials (ssh keys, git config) will not
  find them. Running as the requesting user needs a privileged helper; not in v1.
- **File injection**: `NAME_FILE=<run dir>/files/NAME`, mode 0400. In dev mode the run
  dir is not on tmpfs (it lives in the credstore home); installed Linux uses
  `/run/credstore/run`, which is tmpfs.
- **Timeout and caps.** The request's `timeout_secs` can only lower the policy maximum.
  Each of stdout and stderr is capped at `max_output_bytes`; going over kills the tree
  (a 1 GB flood is stopped as soon as it reaches the cap). Output pipes get 2 s to close after the
  kill. The agent sees `[credstore: ... was killed]` lines appended to stderr.
- **Process tree kill.** Unix: the child starts in a new session (`setsid` in
  `pre_exec`) and the whole process group gets `SIGKILL`. A descendant that calls
  `setsid` itself leaves the group and survives; under bubblewrap the PID namespace and
  `--die-with-parent` catch it, under Landlock or no sandbox they do not (known gap).
  Windows: the child starts suspended, is put in a Job Object, then resumed, so nothing
  runs outside the job; the job has kill-on-close, at most 512 processes and 4 GiB of
  committed memory, and is terminated at the end of every run.
- **`credstore run`** sends `admin_run` with the passphrase; that passphrase is the
  approval (audited as `approved` with `via: "admin"`). Policy still applies. The daemon
  releases its approver lock while the command runs.
- **Idle relock waits for running commands.** With `session_idle_secs = 0` the runner
  relocks right after each run (`lock` reason `after-run`); the background ticker
  gives a zero TTL 5 s of grace so it does not race an approval that is about to run.
- **Memory probe** (`credstore_os::probe::process_memory_access`): opens
  `/proc/<pid>/mem` or calls `OpenProcess(PROCESS_VM_READ)`, reads nothing. Used by the
  adversarial suite now and by `doctor` in M7.
- **Startup sweep**: the daemon empties its run dir at start and audits
  `run_dir_swept` if anything was left (a daemon killed mid-run).
- **Windows working directories** drop the `\\?\` prefix `canonicalize` adds (`cmd.exe`
  refuses it as a cwd); program paths are shown the same way.

**Sandbox per OS** (probed once; `credstored` logs the result at startup):

| OS      | Mode         | Files                                                   | Network deny | Notes |
| ------- | ------------ | ------------------------------------------------------- | ------------ | ----- |
| Linux   | `bwrap`      | read-only `/`, writable cwd and run tmp, credstore paths replaced by empty tmpfs or `/dev/null`; new PID/IPC/UTS namespaces | yes (`--unshare-net`) | needs unprivileged user namespaces (Ubuntu 24.04: AppArmor sysctl) |
| Linux   | `landlock`   | read anywhere except credstore paths, write only cwd and run tmp | kernel 6.7+ (Landlock ABI 4), else a gap | applied in `pre_exec`; also stops ptrace of the daemon |
| macOS   | `seatbelt`   | `sandbox-exec` profile: writes only cwd and run tmp, credstore paths unreadable | yes (`deny network*`) | `sandbox-exec` is deprecated by Apple but works |
| Windows | `appcontainer` | only what the `credstore.run` container was granted: the cwd (`credstore grant`), run tmp and secret files; system folders read-only | yes (no network capabilities); loopback always blocked | inside the Job Object; see below |
| Windows | `job-object` | **not hidden** (gap is reported)                         | **no** (`require` denies) | the fallback: folder or program the container cannot use |
| any     | `none`       | not restricted (gap is reported)                        | no           | `require` denies |

- `sandbox = "require"` denies a run whose plan has any gap (no sandbox, network deny not
  enforceable, `allow-list` network); `prefer` runs and lists the gaps; `off` runs with
  no sandbox. Process-tree kill, caps, cleared environment and redaction apply in every
  mode, sandbox or not.
- **`network = "allow-list"` is never enforced in v1.** `allow_hosts` needs the v2 auth
  proxy. With `require` it is denied; with `prefer` the command has normal network
  access and the gap says so.
- **Windows: AppContainer (M12)**, in place of the restricted token of spec 4.1 (an
  AppContainer hides files the user owns; a restricted token does not).
  - One container, `credstore.run`. Its SID comes from the name, so it is the same on
    every machine and `credstore grant` can compute it without the daemon.
    `credstored` registers the profile (`CreateAppContainerProfile`) and falls back to
    deriving the SID when it cannot (the service account has no profile to register in).
  - **Launcher.** `tokio::process` cannot pass `SECURITY_CAPABILITIES` (std's
    `raw_attribute` is unstable), so the daemon starts `credstore-sandbox.exe` (next to
    `credstored.exe`) suspended in the Job Object, with the pipes, as before. The
    launcher calls `CreateProcessW` with the container's security capabilities and a
    handle list of just its three std handles, waits, and exits with the child's code.
    The child is in the job too (job membership is inherited), so tree kill, process and
    memory caps are unchanged. Code 0x7EC5 means the launcher itself failed.
  - **Capabilities.** None, except `internetClient`, `internetClientServer` and
    `privateNetworkClientServer` when the run's network is not `deny`. Loopback is
    always blocked for AppContainers, which is fine: nothing a command needs listens
    there that it should reach.
  - **Files.** The container sees only what is granted to it or to ALL APPLICATION
    PACKAGES: Windows and Program Files (read and execute), its cwd once its owner ran
    `credstore grant` (which now adds `*S-1-15-2-…:(OI)(CI)M`, in dev mode too), and the
    run's tmp and secret-file folders, granted at start with protected DACLs. The vault,
    policy, audit log, the run directory and the human's other files are invisible.
  - **Per-run plan.** Before asking the human, the daemon checks the cwd's DACL
    (container or AC: read and write) and the program's (read and execute). If either
    fails the run falls back to the Job Object alone with the reason as the first gap
    ("Job Object only: …", naming `credstore grant` for a folder), or is denied under
    `sandbox = "require"`. Per-user installs (`%LOCALAPPDATA%\Programs`, scoop, cargo
    bin) are the usual reason for a program; spec 11 leaves that to the owner.
  - `CREDSTORE_FORCE_SANDBOX=job-object` forces the fallback (CI runs the adversarial
    suite both ways).
  - **Known gap: `NUL` on Windows Server.** Windows Server (the CI runners) refuses the
    `NUL` device to AppContainers, so `>NUL` and children started with null stdio fail
    with "Access is denied". Windows 10 and 11 allow it. Changing the device's DACL is a
    system security setting credstore does not touch; `tests/m12_appcontainer.rs`
    records what each CI run sees.
- `CREDSTORE_FORCE_SANDBOX=landlock|job-object|none` can only downgrade the sandbox. CI uses it to
  run the adversarial suite on each fallback.

**Redaction** (`credstore-core::redact`): exact value, value without a trailing newline,
each line of a multi-line value, URL-encoded (upper/lower hex, `+` or `%20`), hex
(upper/lower), JSON-escaped, base64 in all three alignments in the standard and URL-safe
alphabets. Values under 6 characters are skipped (`set` warns). When a stream was cut
(cap, timeout), a trailing partial match is masked too. Matching is longest pattern first.
Known bypasses (reversed, rot13, split, compressed) are documented and the reversed test
is `#[ignore]`d.

**Adversarial suite** (`tests/m5_adversarial.rs`, helper binary `credstore-adversary`):
environment dumps (`env`, `printenv`, `sh -c set`, `/proc/self/environ`; `cmd /c set`,
`cmd /c echo %KEY%`, PowerShell `Env:`), encodings, reading credstore's files and writing
outside cwd, reading daemon memory (Linux `/proc/<pid>/mem`, Windows `OpenProcess` with
`PROCESS_VM_READ`; skipped on macOS, where `task_for_pid` cannot even be attempted
without entitlements), network deny, a background process outliving the timeout, a 1 GB
flood, file and stdin injection cleanup, concurrent approvals, and the startup sweep.
Every test checks the value is absent from results, the audit log, every file under the
test tree, and all `tracing` output (captured in-process). Endpoint misuse and bad input
are in `m2_daemon.rs` and `m3_policy.rs`. The memory test is skipped when the test runs
with root or with Windows `SeDebugPrivilege` enabled and no isolating sandbox: those
read any process whatever its protection (GitHub's Windows runners are elevated with
the privilege on). `probe::bypasses_process_protection` reports it, and `doctor` will
warn about it: an agent running as an admin with debug privileges can read daemon
memory in dev mode.

## MCP shim (`credstore mcp`, M6)

- Built on **`rmcp` 3.9** (the official SDK, as the spec prefers), default features off:
  `server`, `macros`, `transport-io` only. No HTTP transport, no auth code. rmcp
  handles protocol version negotiation, which matters: the 2026-07-28 MCP revision
  dropped the `initialize` handshake, and a hand-rolled server would have to track that.
- Tools: `list_secrets` (no input), `run_with_secrets` and, since M11, `http_request`
  (see "`http_request`"). There is no tool that returns
  a value, and the shim could not offer one: it holds no secrets and only relays the
  agent endpoint, which never sends values.
- **Strict input schema** for `run_with_secrets` (generated with schemars from the
  argument struct): unknown fields rejected (`additionalProperties: false`), `reason`
  10 to 300 characters, `secrets` 1 to 16, `argv` 1 to 256, `timeout_secs` 1 to 86400,
  `injection` one of `env`, `file`, `stdin`. The daemon validates everything again.
- **`cwd` is optional** (deviation: the spec example always passes it). It defaults to
  the directory the shim runs in, which is the agent's project folder when Claude Code
  starts it.
- Results: the run result as JSON text (`exit_code`, `stdout`, `stderr`, `truncated`,
  `redactions`). Denials and daemon errors come back as tool errors (`isError: true`)
  with `{"denied": ...}` or `{"error": ...}`, so the agent sees the call did not run.
- The call blocks until the human decides or the policy approval timeout ends
  (`{"denied": "approval timed out"}`). If the MCP client cancels the call or exits,
  the shim's connection closes and the daemon drops the pending request (audited as
  `denied` with `via: "disconnect"`), so the human is not left approving a request
  nobody waits for. A command that has already started runs to completion.
- `init` and the installers print `claude mcp add credstore -- credstore mcp` and tell
  the user not to allowlist the tools.
- **Tested** by `crates/credstore/tests/mcp_stdio.rs`, which runs the real binary over
  stdio against a dev daemon: initialize, the tool list and schema, `list_secrets`, an
  approved run with redacted output, a denied run, unknown fields, a missing reason, an
  unknown tool, and that nothing the shim wrote contains the secret. **Not verified
  here:** a session with Claude Code itself (registering the server changes the user's
  Claude Code config, which these sessions do not do).

## Install, service and `doctor` (M7)

**Files** (`deploy/`): `credstored.service`, `sysusers.conf`, `install.sh` (Linux and
macOS), `dev.credstore.daemon.plist` and `dev.credstore.rundir.plist` (macOS),
`install.ps1` (Windows), and `policy.toml`, the starter policy. `STARTER_POLICY` in
`credstore-core` is `include_str!` of that file, so dev mode and the installers write the
same text.

**Accounts and permissions.**

- The service account is a **member of both groups** (`m` lines in `sysusers.conf`,
  `dseditgroup` on macOS). Without that it cannot `chgrp` its sockets to them. Membership
  grants it nothing else.
- Socket directory: 0755, owned by the service account (systemd `RuntimeDirectory`, the
  macOS rundir job). The sockets are 0660 with the group; the daemon refuses a socket
  directory it does not own or that others can write.
- Data and log directories: 0700, service account. Policy: `root:<service group>` 0640
  in a 0750 directory, so the daemon can read it and nobody else but root. Windows:
  `%ProgramData%\credstore` with inheritance cut and full control for SYSTEM,
  Administrators and `NT SERVICE\credstore` only.
- So in installed mode `credstore audit` needs `sudo` (or an elevated shell) to read the
  log. The CLI reads the file directly; routing the audit log through the daemon would
  mean an approver op that streams it, which can come later.

**Deviations from spec 8 / 8.1:**

- `RestrictAddressFamilies` adds **`AF_NETLINK`**: bubblewrap configures loopback in a
  run's new network namespace over netlink, so without it `network = "deny"` runs fail.
- **macOS needs a second launchd job**, `dev.credstore.rundir`, run as root at boot to
  create `/var/run/credstore`: macOS clears `/var/run` at boot and `_credstore` cannot
  create directories there. The daemon job has `KeepAlive`, so if it starts first it
  exits and is restarted 10 s later.
- **Windows service creation** uses `New-Service` and then
  `sc.exe config credstore obj= "NT SERVICE\credstore"` (plus `sidtype unrestricted`)
  instead of a single `sc.exe create ... obj=`: passing a quoted `binPath` with spaces to
  `sc.exe` is parsed differently by Windows PowerShell 5.1 and PowerShell 7. Same result.
- `credstored --service` (Windows only) runs the daemon under the Service Control
  Manager (`credstore-os::service`, `sys/windows/service.rs`) and logs to
  `credstored.log` in the data directory; a stop or shutdown request shuts it down
  cleanly. systemd and launchd run it as a plain process and stop it with SIGTERM.
- `install.sh` also takes `--uninstall` and `install.ps1` `-Uninstall`: they remove the
  service and binaries and keep the data, users and groups.

**Commands run under the unit's restrictions** (they are children of the daemon):
`ProtectHome=yes` hides `/home`, `ProtectSystem=strict` makes the rest read-only, and
`MemoryDenyWriteExecute=yes` breaks JIT runtimes. The README documents a drop-in to relax
these per machine rather than weakening the shipped unit.

**`credstore doctor`** (`crates/credstore/src/doctor.rs`), run as the agent's user:

- mode (dev is always a warning); service status (`systemctl`, `launchctl print`,
  `sc.exe query`); membership in both groups, active in this session (Linux
  `getgroups`, Windows `CheckTokenMembership`) or only listed (log out and back in);
- installed mode: tries to open the data dir, vault, index and policy for reading, and
  the files for appending (nothing is written). Any success is a **FAIL**; the audit log
  being readable is a warning, writable a failure. Dev mode instead checks the files are
  owner-only (Unix mode bits; Windows DACL read as SDDL, see `fs::is_owner_only`);
- both endpoints, each through the client's daemon identity check, and `list_secrets`;
- the daemon's memory: the client learns the daemon's PID from the connection (peer
  credentials on Unix, `GetNamedPipeServerProcessId` on Windows) and tries to open it
  for reading (`probe::process_memory_access`). Readable is a FAIL in installed mode;
- with the passphrase (only if there is a terminal): the daemon's own report from
  `status`: policy load error, sandbox mode and detail, and each hardening feature with
  whether it is active. Without it, doctor says so and shows this process's sandbox
  probe, labelled as such. A Job Object sandbox is a warning (no file or network
  isolation), `none` too;
- Claude Code settings (`~/.claude/settings.json`, `./.claude/settings*.json`): a
  warning if a `permissions.allow` rule names `mcp__credstore`;
- privileged accounts (root, elevated administrator, enabled `SeDebugPrivilege`) get a
  warning, and file and memory findings become warnings, since they show what that
  account can reach, not the agent.

Exit code 1 if anything failed.

**Tested** by `crates/credstore/tests/doctor_dev.rs` (dev daemon: with and without the
passphrase, wrong passphrase) and by the installed-mode smoke test
`tests/m7_installed.rs`, which CI runs after the real installers (see CI). It inits the
vault, adds the fake secret, runs an approved command through the agent endpoint as the
service, checks the redacted output, and requires `doctor` to report no failures: the
vault, index and policy unreadable by the test user, the service running, both groups
active, the memory closed (or not checkable on macOS), and a sandbox and hardening report
from the daemon.

## Packages and `credstore setup` (M8)

The roadmap is in [ROADMAP.md](ROADMAP.md).

**One install path.** Every package runs the same `deploy/install.ps1` / `install.sh`
that installs from source, with `-Package` / `--package`: the package manager already
put the binaries in place and owns them (and, for the MSI, the PATH entry), so the
script skips copying them and, on uninstall, skips deleting them. A bug fixed in the
script is fixed for every format.

| Format | Built with | Files | Runs the script from |
| --- | --- | --- | --- |
| `.msi` | WiX 5 (`packaging/wix/credstore.wxs`) | `%ProgramFiles%\credstore` | deferred custom action as SYSTEM (`WixQuietExec`, output in the MSI log); a rollback action uninstalls the service if a later step fails |
| `.deb`, `.rpm` | nfpm (`packaging/nfpm.yaml`) | `/usr/bin`, `/usr/lib/credstore` | `postinst` / `%post`; `prerm` / `%preun` on removal only, not upgrade |
| `.pkg` | `pkgbuild` (`packaging/macos/build-pkg.sh`) | `/usr/local/bin`, `/usr/local/share/credstore` | `postinstall` |

- **MSI pages.** Double-clicked, the MSI shows welcome, ready, progress and finish
  pages (a custom set of the WiX UI extension's dialogs, `CredstoreUI`: no licence page,
  no folder choice). The finish page says the service is running, that no sign-out is
  needed, and offers "Open credstore now" (`WixShellExec`, from the UI sequence, so as
  the user and not elevated). `/qn` skips the pages.
- **Which user is added to the groups.** MSI: `CREDSTOREUSER`, defaulting to
  `LogonUser` (the account that started the install, also when UAC elevated it).
  deb/rpm: `SUDO_USER`. pkg: the console user. If there is none (root, or a headless
  install) the script says how to add one later instead of failing.
- **Linux unit path.** The unit names `/usr/local/bin/credstored`; `install.sh --bin`
  rewrites it, so the packages run `/usr/bin/credstored`.
- **Page file encryption** (Windows): the MSI runs `fsutil behavior set
  encryptpagingfile 1` unless `ENCRYPTPAGEFILE=0`. This changes a system setting at
  install time; it is on by default because the daemon cannot `VirtualLock` its secrets
  (see M7). `doctor` now warns while it is off.
- **Removal keeps data.** Uninstalling any package keeps the vault, policy, audit log,
  service user and groups, as `-Uninstall` always did.
- **No macOS uninstaller.** A component `.pkg` cannot remove itself; `sudo
  /usr/local/share/credstore/install.sh --uninstall` removes the service and binaries
  and forgets the package receipt.
- **Unsigned.** Signing needs an Apple Developer ID Installer certificate and a Windows
  code-signing certificate, which the project does not have yet. `build-pkg.sh` signs if
  `SIGN_IDENTITY` is set; the MSI is unsigned.

**When CI runs (2026-11-07).** Pull requests run every job on Windows and Linux only;
pushes to `main` and `v*` tags run them on macOS too, so a macOS break shows up on `main`
after the merge, not on the PR. Pushes to other branches run nothing on their own (the
pull request runs them), which stops each PR push from running CI twice. The owner chose
this after the account ran out of Actions minutes; macOS minutes cost ten times Linux
ones on private repos. The repository was made public the same day.

**Releases.** CI's `packages` job builds and tests the packages on every run. A tag
`vX.Y.Z` also runs the `release` job, which attaches all packages and a `SHA256SUMS`
file to a **draft** GitHub release; a human publishes it.

**`credstore setup`** is the part the installer cannot do, because it runs as the system
and the vault passphrase and Claude Code settings belong to the human. It:

1. checks the daemon answers on the agent endpoint (and, if not, says to sign out and
   back in, the usual cause right after installing);
2. creates the vault if the daemon lists no secrets (if one already exists the daemon
   says so and nothing changes);
3. registers credstore with Claude Code at **user scope** through `claude mcp add
   --scope user` (the supported way; it does not edit `~/.claude.json` itself), unless
   `~/.claude.json` already has a user-scope `credstore` server;
4. adds the missing deny rules to `~/.claude/settings.json` (`.env*`, `~/.credstore`,
   and the OS's vault and policy directories), keeping every other setting. The old file
   is kept as `settings.json.before-credstore`. `serde_json` sorts keys when it writes,
   so the file's key order may change; its content does not.

It asks before steps 2 to 4, or takes `--yes`; without a terminal and without `--yes` it
refuses. `--no-claude` skips steps 3 and 4. **Tested** by
`crates/credstore/tests/setup_dev.rs` (dev daemon, throwaway home: vault created, deny
rules merged into existing settings, second run changes nothing, no terminal refuses)
and unit tests for the settings merge. Running `claude mcp add` itself is not tested in
CI (no Claude Code there).

## No sign-out, `credstore grant` (M9)

Two setup steps came from the design, not the installer: signing out so the new groups
apply, and granting the service account access to each project folder by hand.

**The users file.** The installer writes the user it adds to the groups into a *users
file* next to the policy (`/etc/credstore/users`, `%ProgramData%\credstore\users`; one
account name per line, `#` comments; root/SYSTEM-owned like the policy). At startup the
daemon reads it and allows those accounts on both endpoints in addition to the groups'
members. Changes need a service restart (the installer restarts it).

- **Windows.** Each listed account's SID gets its own entry in the pipe DACL (same
  rights as the group's), and `authorize` accepts the SID if the impersonation token is
  in the group *or* the SID is listed. A user entry applies at once; a group only reaches
  a token at the next logon. Unknown names are logged and skipped.
- **Linux, macOS.** `authorize` already checked the group in the account database
  (`getgrnam`), which changes immediately; what blocked a session that predates the
  group was the socket file's 0660 group permission. With listed users the sockets are
  **0666**, and the daemon's check (SO_PEERCRED, at accept, before anything is read) is
  the only gate. Without a users file they stay 0660. **Deviation from spec 8.1**, which
  relies on the socket's group permission as well: the daemon's own check was always
  the authoritative one, but there is no longer a kernel-level first filter, so any
  local user can open a connection that the daemon then closes.
- `doctor` reports "in the group, but this session predates it" as info, not a failure;
  the endpoint checks show whether the daemon let the user in.

**`credstore grant [DIR]`** (default: the current folder) gives the service account
read/write access to a folder the user owns, without admin rights. It prints the exact
commands, asks (or `--yes`), and runs them as the user (`credstore-os::grant`):

| OS | Commands |
| --- | --- |
| Windows | `icacls DIR /grant "NT SERVICE\credstore:(OI)(CI)M"`; services bypass traverse checks, so parents need nothing |
| Linux | `setfacl -R -m u:credstore:rwX DIR`, a default ACL on each directory in it (new files), and `u:credstore:x` (traverse only) on each parent the user owns, such as the 0750 home |
| macOS | `chmod -R +a "_credstore allow ...,file_inherit,directory_inherit" DIR`, and `_credstore allow search` on each parent the user owns |

The `.deb`/`.rpm` depend on `acl` for `setfacl`. In dev mode `grant` does nothing, since
commands run as the user.

**The daemon names the fix.** When a run's folder does not exist or the daemon cannot
open it, the denial (in installed mode) says so and gives the `credstore grant` command,
instead of the command failing later inside the sandbox.

**Linux unit.** `ProtectHome=yes` (spec 8) hid `/home` from the daemon and its commands
entirely, so no grant could work. The unit now has `ProtectHome=no` and
`ReadWritePaths=-/home -/mnt -/srv` (the `-` skips missing paths), keeping
`ProtectSystem=strict` for everything else. **Deviation from spec 8**: the credstore user
can now see whatever file permissions allow under `/home` (other users' world-readable
files, on systems with 0755 homes); its access to a user's projects comes only from the
ACLs `grant` adds. `MemoryDenyWriteExecute=yes` is unchanged (it still breaks Node and
Java; README).

**Not solved here: per-user tools.** Approved commands run as the service account, which
does not see tools installed only for the user (a Python under `AppData`, global npm
packages, `~/.local/bin`, git credentials, SSH keys). Install such tools machine-wide, or
give the service account access to them. Letting chosen commands run as the user would
remove this, but weakens the model (the agent, as the same user, could then read the
command's memory and environment); that is the owner's decision.

**Tested** in CI's `installed` job: right after installing, `credstore list` runs in the
CI shell, whose session predates the groups (Linux, macOS), and on Windows as the
runner's own account added after logon. On Linux and macOS the smoke test then runs its
approved commands in `~/credstore-smoke`, opened up with `credstore grant --yes` (no
sudo); on Windows `credstore grant` replaces the hand-written icacls. Unit tests cover the
users file and the grant plans.

## Desktop app (M10)

`app/` is a Tauri 2 app, `credstore-app`. It is its own Cargo workspace (the root one
excludes it), so building and testing the core does not need a webview toolkit.

**Same security model.** The app is a client like the CLI: it talks to the agent and
approver endpoints as the user, every approver operation sends the passphrase, and
nothing is cached in the app. The Rust side is thin commands that forward to
`credstore::api`, a library module the CLI's pieces were refactored into
(`create_vault`, `describe` for pending requests, `setup` for Claude Code, `grant`,
`doctor` with a given passphrase). `crates/credstore/tests/api_dev.rs` drives that module
against a dev daemon: vault, set, list, a pending request approved with the wrong and
then the right passphrase, remove, lock.

**What the page can do.** The page gets `core:default` only; the folder picker and
notifications are called from Rust. CSP allows only the app's own files and Tauri IPC,
and `freezePrototype` is on. Every string from an agent or the daemon is set with
`textContent`, so a request's reason or command cannot inject markup. Passphrases and
secret values go from the page to Rust as strings and are wrapped in `SecretText`
immediately; no command returns one. Input fields are cleared as they are read.

**Pages.** Approvals, Activity, Secrets, Folders, Claude Code, Health and Security; see
"App redesign" below for what each does since 2026-11-07.

**Tray.** Closing the window hides it; the tray icon reopens or quits. A new pending
request raises an OS notification and brings the window forward. On a desktop without a
tray the window just closes.

**Packages.** When the app was built, `build-msi.ps1` adds `credstore-app.exe` and a
"credstore" Start menu shortcut to the MSI, `build-pkg.sh` adds a minimal
`/Applications/credstore.app` bundle (removed by `install.sh --uninstall`), and
`build-linux.sh` builds a separate `credstore-app` `.deb`/`.rpm` that depends on
`credstore` and the WebKitGTK and appindicator libraries.

**Tested.** `CREDSTORE_APP_SMOKE=1` makes the app exit once the page has loaded and
called the backend (with a 90 s watchdog), printing what the page saw. CI's `packages`
job runs it from each installed package: on Linux under `xvfb-run` and on macOS it must
report the installed service as reachable; on Windows the runner account is not an
allowed user, so the check is that the page loads. The layout was checked in a browser
with a stubbed backend. Not tested: clicking through the pages in the real app, and
notifications and the tray on a real desktop.

## App redesign (2026-11-07)

The owner asked for the features the app lacked (allowed hosts, a Windows Hello switch,
refused requests with a fix, an activity history, security settings), for the window and
the Hello dialog to come to the front, for an app icon, and for a redesign. The visual
system is recorded in [VISUAL.md](VISUAL.md); `PRODUCT.md` holds the product brief.

**One live feed.** `ApproverOp::SubscribeFeed` streams a `Feed` (pending requests,
activity, the policy as it applies to each secret, whether the vault is locked) now and
after every audit record or pending change; bursts are sent once (50 ms). Like
`SubscribePending`, the proof is checked once, when the stream opens: the passphrase, or
an approval-key signature (Hello) while the vault is unlocked. The app opens it once
("Connect", or "Use Windows Hello") and keeps it open; it stores nothing. The CLI's
`SubscribePending` is unchanged.

**Activity (the audit viewer).** M10 left it out because reading the audit log over the
approver endpoint would widen what any member of `credstore-approvers` can see. The feed
answers that: only a connection that proved the passphrase (or an enrolled Hello key)
gets it. The daemon reads the last 1 MiB of `audit.jsonl` and groups records by request
id (`credstore_core::activity`): request, then `policy_denied` / `approved` / `denied`,
then `run_finished` / `http_finished`; plus vault and policy changes and failed proofs.
The newest 100 entries are sent. Audit records hold no values, so entries hold none.
The audit chain is not verified here (`credstore audit verify` does that).

**Refused requests and "Allow this host".** A request refused by policy never reaches the
human, so the agent used to be the only one who knew. The Approvals page now lists
refusals from the last hour with the reason in plain words, and for an HTTPS request,
a button that adds the host to that secret's `allow_hosts` (with the passphrase).

**Policy edits from the app.** `SetSecretRules {name, allow_hosts, allow_commands}` and
`SetDefaults {session_idle_secs, grant_ttl_secs, approval_timeout_secs}` change
`policy.toml` and reload it. Passphrase only: `key_allowed()` excludes them, so a Hello
key can watch and decide but not widen policy. The edit goes through `toml_edit`
(`credstore_core::policy_edit`), which keeps the file's comments and layout, then the
result is parsed with the full policy validator before it is written (atomically, with
the directory's ACL), so a bad edit changes nothing. Hosts set `network = "allow-list"`;
an empty list removes the rule (and `network` if it was `allow-list`), and an empty
block is removed, so the secret follows `[defaults]` again. Audited as
`policy_changed`.

On Linux and macOS installs the policy is root's (`/etc/credstore/policy.toml`, spec
5.4) and the service cannot write it; `PolicyInfo.editable` is false there and the app
says to edit the file with sudo. The installers were not changed to hand the file to
the service: that is a change to who may set policy, for the owner to decide.

**Windows: the policy is Administrators' too (2026-11-07, owner's decision).** Before,
`%ProgramData%\credstore\policy.toml` sat in the service's own folder with full control,
so a daemon that was taken over could widen its own rules; on Linux and macOS it cannot.
Now Windows matches:

- `install.ps1` gives the service full control of what it creates (vault, index, audit
  log, `run\`) but, on the folder itself, only list, read and create: no "delete child",
  so it cannot remove or replace a file it does not own. `policy.toml` and `users` get a
  protected DACL: SYSTEM and Administrators full control, the service read. (`users`
  says who may use the endpoints, the same kind of decision.)
- A change from the app still needs the passphrase. The daemon edits and validates the
  text as before but does not write it: it keeps it under a unique id for
  `POLICY_EDIT_TTL_SECS` (5 min) and answers `PolicyEditPending { id }`
  (`PolicyInfo.needs_admin` tells the app in advance).
- The app runs `credstore policy-apply ID` with ShellExecuteEx "runas", hidden; Windows
  asks the human (UAC). The helper connects to the daemon (the pipe owner check proves it
  is the service), takes the text with `Proof::PolicyEdit(id)`, checks the file still
  has the hash the change was made from, writes it (a new file created with the
  protected DACL, then renamed over the old one, so it never has broader access), and
  calls `FinishPolicyEdit`. The daemon checks the file holds exactly the text, audits
  `policy_changed` with the human's peer and the helper as `admin`, and reloads.
- The id is not a secret: the text comes from the daemon, never from the command line or
  a file the agent could change, so holding the id only lets someone apply the change the
  human made. It works only for `TakePolicyEdit` and `FinishPolicyEdit`.
- Exit codes the app turns into words: 0 done, 3 the file changed meanwhile, 4 the
  change expired or was replaced, 1 anything else (with the message in a report file).
  Declining UAC writes nothing.
- An administrator can still edit the file by hand, then `credstore reload`.

CI: the installed smoke test (non-admin) prepares a change and checks it cannot finish
it; the next step, as the elevated runner, runs `policy-apply` and checks the file, its
ACL, and that the change cannot be applied twice. Not tested in CI: the UAC prompt
itself (runners have none).

**Windows Hello switch.** Security has a switch that enrols (`hello::create`, then
`AddApprovalKey`, after checking the passphrase) or removes the key, the same steps as
`credstore hello enrol` / `remove`.

**Hello key from an older vault (2026-11-07, found by the owner).** The Hello key lives
in the user's Windows profile, the list of trusted keys in the vault. After a reinstall
with the data directory deleted, Windows still had the old key, so the switch showed
"on" and every Hello approval failed with "approval key rejected: unknown key". The
feed now carries `approval_keys`, the ids of the keys the vault trusts (`None` while the
vault is locked, because the list is inside it), and the overview carries
`hello_key_id`, the id of this user's Hello key. The switch is on only when the vault
trusts the key; for a key from an older vault it is off, with a note, and turning it on
replaces the key. Request boxes offer "leave empty for Windows Hello" only when Hello
can confirm (trusted key, vault open), and "unknown key" is explained in plain words in
the app and in `credstore watch`. Key ids are hashes of public keys and the feed needs
the passphrase or an enrolled key, so the list widens nothing.

**Window and dialog in front.** On a new request the app shows and unminimizes the
window, sets it topmost for a moment and back, asks for focus, and flashes the taskbar
button: Windows does not let a background app take the keyboard, but the window becomes
visible. Hello's dialog belongs to a system broker process and often opened behind the
app; `credstore-os` (`sys/windows/foreground.rs`, a small commented `unsafe` module)
now calls `AllowSetForegroundWindow(ASFW_ANY)` and, while a Hello request is open,
brings the window of class `Credential Dialog Xaml Host` forward. Not tested on CI (no
desktop): checked by hand only. Since the island (below), the window no longer comes
forward on a request; this is now the fallback when the island cannot be shown.

**The island (2026-11-07).** The owner did not want the whole window to pop up for
each request, and pointed at their F1 Island (a Dynamic Island style pill at the top of
the screen). On a new request the app now shows a second, small window, `island`
(`app/src/island.rs`, `app/ui/island.*`), at the top-centre of the screen the mouse is
on, instead of the OS notification and the window. The owner chose: only while a
request waits (nothing on screen otherwise); decide in the island; the main window
stays where it is.

- Collapsed it is a pill: "Agent wants NAME → host" (or the program), with a red count
  when more are waiting. Hovering or clicking opens it: the secret, the request (with
  its body) or command and folder, the agent's reason, anything not enforced, a
  passphrase field, and Deny / Approve for the policy's maximum / Approve once. "Open
  credstore" shows the full request on the Approvals page (headers, sandbox, who
  asked). Leaving with the mouse closes it again unless it was opened by a click, a
  decision is being sent, or the passphrase field has text.
- Deciding uses the same `decide` command as the Approvals page: an empty field means
  Windows Hello, offered only when the vault trusts the key and is open. Every
  approval still needs the passphrase or Hello, as before; the island adds no way
  around them.
- The window is borderless, transparent, always on top, out of the taskbar, and does
  not take the keyboard when it appears (clicking the field gives it the keyboard).
  The page measures itself and the window is resized to it (`island_size`, clamped),
  so nothing around the island blocks clicks. It hides itself after a short
  "Approved" / "Denied" once nothing is waiting, and when watching stops.
- It needs the feed, like the Approvals page: requests that arrive before "Connect"
  are not shown (that has not changed).
- If the island cannot be created, the app falls back to the notification and the
  window, as before.

The helpers both pages use moved to `app/ui/shared.js`. `top_centre` has a unit test;
the page was checked in a browser with a stubbed backend (pill, open, next, approve,
deny, hiding when empty, a key from an older vault, "Open credstore"). Not tested on
CI (no desktop) and not yet in the real app.

**First-run guide (2026-11-07).** The owner asked why `credstore setup` is a separate
step. The installer cannot do it: it runs elevated for the whole machine, while the
vault passphrase and the Claude Code settings belong to one user, and a passphrase
typed into an installer page could end up in Windows Installer's logs. The app runs
as the user, so it now does it: the first time it starts and reaches the service, if
there are no secrets or Claude Code is not connected, it opens a "Set up credstore"
page (`#m-welcome`) with three steps, using the commands the other pages already use:

1. Create the vault (`create_vault`; "already exists" is said plainly, as `credstore
   setup` does, because an empty list cannot tell an empty vault from none). The same
   passphrase then starts the feed, so requests reach the island at once.
2. Connect Claude Code (`connect_claude`), or say how to install it and check again.
3. Optional, when Windows Hello is set up for the account: turn it on (`set_hello`).

Steps 2 and 3 can be put off ("Later"); the vault is needed to finish. "Add your first
secret" ends on the Secrets page with the form open; "Finish later" ends on Approvals.
Either way the guide does not open by itself again (a flag in the page's local
storage); Health > "Open the setup guide" reopens it. An existing setup never sees it.

**Bug found on the first real run (2026-11-07):** "Connect Claude Code" in the app
registered the app itself (`credstore-app.exe mcp`), because registration used the
running program. Claude Code then started the app window, which never answers MCP, and
gave up after 30 s ("CONNECT_TIMEOUT"). Registration now always uses the credstore CLI
(`setup::cli_path`: the running program if it is the CLI, else the `credstore` beside it,
else the usual install places, else `credstore` on PATH). An entry that points at any
other program counts as not connected (`ClaudeState::wrong_command`, shown on the page),
and connecting removes it first (`claude mcp remove`) and adds the right one.

With the app installed, the MSI no longer adds the "credstore setup" Start menu entry,
and its finish page points to the app; without the app it is as before. `credstore
setup` itself is unchanged for the terminal and Linux. Checked in a browser with a
stubbed backend (fresh install, each step, a short passphrase, finishing, reopening
from Health, an existing setup); not yet in the real app.

**Icon.** `app/icons/make_icons.py` draws the mark (VISUAL.md) at 16 to 256 px into the
PNGs and a multi-size ICO; Tauri uses them for the window, taskbar and tray, and the MSI
now sets `ARPPRODUCTICON` and the Start menu shortcuts' icon.

**Fonts.** Geist and Geist Mono (SIL OFL 1.1, `app/ui/fonts/OFL.txt`) are bundled as
variable woff2 files, because the app's CSP allows only its own files.

**Tested.** `tests/app_feed.rs` drives the feed and the edits against a dev daemon: a
wrong passphrase gets no feed; activity shows a saved secret; an HTTPS request refused
for having no hosts shows up as refused, with its host; "allow" with a wrong passphrase
fails, with the right one the host lands in the file with the file's comments kept and
the feed shows it; an invalid timer changes nothing; no feed holds the fake value.
`m13_approval_keys.rs` checks a key opens the feed and cannot change policy.
`policy_edit` and `activity` have unit tests. The page was checked in a browser with a
stubbed backend (each page, the connect step, approve by keyboard, allow a host, edit
and save rules, change a timer, the narrow layout).

## `http_request`: the auth proxy (M11)

Built as spec 6.6 designs it, not as the per-run local proxy the roadmap first sketched:
the agent calls `http_request {method, url, secret, header_template, reason, headers?,
body?, timeout_secs?}` and **the daemon makes the HTTPS request itself**. The secret
never enters a process the agent controls, so even an approved request can only send it
to a host its policy names. (A per-run proxy would have had the same property for the
command, but needs loopback access from inside the sandbox, which bubblewrap's network
namespace removes, and a URL rewrite in every client.)

**Protocol.** `AgentRequest::Http(HttpRequest)` and `Response::HttpResult {status,
headers, body, truncated, redactions}`. `Injection` gains `header`, used only to label
these requests; a run asking for it is refused. `PendingRequest` gains `http: {method,
url, header_template, headers, body_bytes, body_preview}`; for HTTP requests `argv`,
`shell` and `program` are absent and `cwd` is empty.

**Policy.** A secret may be used this way only if its effective `network` is
`"allow-list"` and the URL's host is in its `allow_hosts` (`host`, `host:port`, or
`*.domain` for subdomains; no port means 443). Without that the request is denied before
the human is asked, so the default policy allows no HTTP use at all. `require_approval`,
`grant_ttl_secs`, `max_runtime_secs` (the request timeout) and `max_output_bytes` (the
body cap) apply; `allow_commands`, `allow_dirs`, `allow_shell`, `sandbox` and
`injection` are about commands and do not. Listing `header` in `injection` is a policy
error that says so. For commands, `allow-list` is still not enforced (the gap message
now points to `http_request`).

**Checks before policy** (`credstore-core::http`): method one of GET, HEAD, POST, PUT,
PATCH, DELETE; GET and HEAD without a body; the URL is ASCII `https://`, without user
info, backslashes, whitespace, control characters or a fragment, with a plain host name
(or IPv6 literal) and a port without leading zeros, so the host policy checks cannot be
read differently later; `header_template` is `Name: …{value}…` with `{value}` exactly
once and not a transport header; at most 32 extra headers, none of them `Host`,
`Content-Length`, `Transfer-Encoding`, `Connection` and similar, nor the secret's own
header; body at most 1 MiB. Errors never echo header values or the body.

**Sending** (`credstored::http`, blocking, on its own thread): the URL is parsed again
by the HTTP library and must give the same scheme, host and port, or nothing is sent.
HTTPS only, **no redirects followed** (a 3xx comes back to the agent, which may call
again: that is a new request), no proxy from the environment, a global timeout, and the
body read up to `max_output_bytes` (then cut and marked `truncated`). The secret header
is marked sensitive. Response headers and body are redacted like command output and the
result goes back as text (invalid UTF-8 replaced).

**Approval** reuses the M4 queue (`Job::Run` / `Job::Http`). `watch` and the app show
the method and URL, the secret header with `{value}` in place, the other headers, the
body size and its first 400 characters, and the allowed hosts. A session grant covers
exactly the same request (method, URL, secret header, headers and body) from the same
user.

**Audit.** `request` (with `kind: "http"`, method, URL, header names only, body size),
`policy_denied`, `approved`/`denied`, `http_sent` (written before anything is sent;
failing to write it means nothing is sent), `http_finished` (status, size, redactions,
or the redacted error).

**Dependency** beyond spec section 4: **`ureq` 3** with `rustls` (ring) and the Mozilla
root list (`webpki-roots`), no gzip, no cookies. Small and synchronous, which suits one
request per approval; `reqwest` would pull in hyper and a second async stack. The root
list is CDLA-Permissive-2.0, allowed for that crate only in `deny.toml`. Trust comes
from that list, not the OS store, so a corporate TLS-inspecting proxy is not trusted.

**Not covered:** query-string or body injection of the secret (header only), multipart
or binary bodies, responses as bytes. The header value sits in an ordinary buffer
inside the HTTP library until the request is written.

**Tested** in `tests/m11_http.rs`: policy denials (no allow-list, wrong host, wrong
port), malformed URLs, unknown secret, `header` refused for commands, the pending
request as `watch` prints it, denial, an approved request (to a closed local port, so no
network) with a session grant covering the identical request and not a different URL.
`live_the_response_is_redacted` (ignored by default, run by CI) sends a real request to
a public echo service, which returns the secret header in its body, and checks it comes
back as `[REDACTED:NAME]`; then a self-signed certificate is refused. The MCP test checks
the tool's schema and a policy denial over stdio. Core unit tests cover URL, header and
host matching.

## Approval keys: Windows Hello (M13)

**Goal.** Approve without typing the passphrase, so a same-user keylogger sees nothing
for most decisions. The daemon must not trust a client that only says "Hello said yes"
(any process of the human can say that), so the approval is a signature the daemon
verifies.

- **Enrolment** (`credstore hello enrol`, passphrase required). Windows Hello creates
  the RSA key `credstore-approver` (`KeyCredentialManager.RequestCreateAsync`); its
  private half stays in the TPM or the Hello container and is used only after Hello
  verifies the user. The CLI sends the DER SubjectPublicKeyInfo with
  `add_approval_key`; the daemon checks it imports as RSA and stores it **inside the
  encrypted vault** (`approval_keys`, id = first 16 bytes of its SHA-256), so nobody
  without the passphrase can add a key. At most 16 keys. `credstore hello remove`
  removes it from the vault and from Hello. `credstore status` lists the keys.
- **Proof.** `Proof` is now `{"passphrase": …}` (unchanged on the wire) or `{"key":
  {key_id, time, nonce, signature}}`. The signature (PKCS#1 v1.5, SHA-256, what Hello's
  `RequestSignAsync` makes) covers `credstore approval v1\n<key_id>\n<time>\n<nonce>\n`
  followed by the operation's JSON, so it cannot be reused for another operation.
- **What a key may do:** subscribe, approve, deny, status, lock (`key_allowed`). Not
  unlock, set/rm, `credstore run`, init, or add/remove keys: those need the passphrase.
- **Only while unlocked.** The keys live in the vault, so the daemon checks them
  against the unlocked copy; while locked, a key proof is refused ("unlock with the
  passphrase first"). Approving a request still needs the decrypted values, which only
  the passphrase gives after a relock. So the passphrase is typed once per unlock
  session (at most `session_idle_secs`), then Hello confirms each decision.
- **Freshness.** `time` within 60 s of the daemon's clock, and a nonce seen in the last
  two minutes is refused (replay). The nonce only needs to be unique (it is signed), so
  it is a hash of time, pid and a counter: no RNG dependency.
- **Failures** (unknown key, bad or stale signature, replay) are audited as
  `auth_failed` with `via: "approval_key"` and count towards the passphrase lockout.
- **Verification** uses CNG (`CryptImportPublicKeyInfoEx2`, `BCryptVerifySignature`) in
  `credstore-os` (`sys/windows/sig.rs`, the only new unsafe module). No RSA crate: the
  pure-Rust `rsa` crate carries an open advisory (Marvin), and Windows is the only
  platform with keys today.
- **Clients.** `credstore watch` uses Hello when this user has the key: it subscribes
  with Hello and confirms each decision with Hello, falling back to the passphrase
  prompt when Hello is cancelled or the daemon refuses (locked). The desktop app's
  passphrase box may be left empty to use Hello.
- **macOS (Touch ID): not built.** A Secure Enclave key needs a signed app with a
  keychain entitlement, which needs the owner's Apple Developer account (spec 11);
  `LAContext` alone is a yes/no the daemon cannot verify. **Linux:** no common biometric
  service; passphrase only.
- **Dependency** beyond spec section 4: the **`windows`** crate (Microsoft, same family
  as `windows-sys`) for the WinRT `KeyCredentialManager`, which `windows-sys` does not
  cover. Features: Foundation, Security_Credentials, Security_Cryptography(_Core),
  Storage_Streams.

**Tested** in `tests/m13_approval_keys.rs` (Windows) with an in-process CNG RSA key in
Hello's signature format (`SoftwareKey`; Hello itself needs a person): approve and deny
with a key; refused while locked; refused for unlock, rm and key changes; replay,
another operation's signature, an unknown key and a stale time refused; a removed key
stops working; malformed keys are not enrolled; keys survive a restart; `watch`
approves with no passphrase typed and falls back to it while locked.
`live_windows_hello_approves` (ignored) does the real enrol and sign, for a person at a
machine with Hello. Unit tests cover CNG sign/verify and the wire format.

## Uninstall and first run (2026-11-09)

Found by the owner reinstalling on Windows:

- **Removing keeps the data; deleting it is asked for explicitly.** A plain uninstall
  (and every upgrade) keeps the vault, policy, audit log, groups and service account,
  so an uninstall never costs the secrets. To delete them: `msiexec /x … DELETEDATA=1`
  (passes `-DeleteData` to install.ps1; ignored when `UPGRADINGPRODUCTCODE` is set),
  `apt purge` (the deb `postrm purge` deletes it itself, since install.sh is gone by
  then), or `install.sh --uninstall --delete-data` / `install.ps1 -Uninstall
  -DeleteData`. rpm has no purge, so the README gives the install.sh command to run
  before `dnf remove`. On Linux the sysusers file goes too, or systemd would recreate
  the account at boot. There is no checkbox in the MSI: Settings > Apps runs a removal
  with no dialogs, so a property reachable from every path was preferred.
- **Administrators are in the service's private directories on Windows.** They were
  SYSTEM and the service only, so an elevated `Remove-Item` failed on `run\` and the
  owner had to `takeown` it. Administrators can take any file anyway (spec non-goal), so
  listing them adds no access, only convenience. install.ps1 `-DeleteData` still takes
  over what it cannot open, for folders older versions made.
- **The app's setup guide opens whenever there is no vault.** It remembered "guide
  done" in its WebView storage (`%LOCALAPPDATA%\dev.credstore.app`), which survives an
  uninstall, so a reinstall after deleting the data skipped it. `ListSecrets` now says
  `no_vault` (no secret involved; the agent already sees the names), and the guide opens
  when it is set, whatever the app remembers.
- **The main window fits the screen.** 1180 x 780 is taller than the work area of a
  1366 x 768 laptop or 1080p at 150 %, so the bottom sat under the taskbar. At start it
  shrinks to the monitor's work area minus a 4 % margin each side and is centred
  (`app/src/fit.rs`).

## Stubbed per OS

| Capability      | Linux                 | macOS                 | Windows               |
| --------------- | --------------------- | --------------------- | --------------------- |
| Paths           | done                  | done                  | done                  |
| Private files   | done (0600/0700)      | done (0600/0700)      | done for dirs credstore creates (protected DACL); owner-only check reads the DACL |
| Atomic replace  | done                  | done                  | done                  |
| Terminal prompt | done (`rpassword`)    | done (`rpassword`)    | done (`rpassword`)    |
| IPC             | done (Unix socket)    | done (Unix socket), CI only | done (named pipe) |
| Peer identity   | done (uid, pid, exe)  | done (uid, pid; no exe) | done (SID, pid, exe) |
| Group check     | done (CI install job) | done (CI install job) | done (CI install job) |
| Memory guard    | dumpable, core limit; no mlock | deny-attach, core limit; no mlock | DACL; WER partial; no VirtualLock |
| Runner          | done (session + killpg) | done (session + killpg), CI only | done (suspended start + Job Object) |
| Sandbox         | done (bwrap, Landlock) | done (Seatbelt), CI only | done (AppContainer in a Job Object; Job Object alone for folders and programs the container cannot use) |
| Service install | systemd unit + `install.sh` (CI) | launchd + `install.sh` (CI) | SCM service + `install.ps1` (CI) |
| Package         | `.deb` (CI install), `.rpm` (built, inspected) | `.pkg`, unsigned (CI install) | `.msi`, unsigned (CI install) |
| `doctor`        | done                  | done (no memory probe) | done                  |
| Desktop app     | done (smoke under xvfb, CI) | done (smoke, CI) | done (smoke, CI) |
| Biometric approval | none (passphrase) | not built (needs a signed app) | done (Windows Hello key; CI tests use a software key) |

Stubs return `OsError::Unavailable("<mechanism> not built yet (Mx)")`; the daemon logs
each unavailable hardening feature at startup.

"Done" above means built and unit-tested for path resolution. The terminal prompt's
"no terminal" path is tested on every OS (piped stdin cannot answer it); reading from a
real terminal is not, since CI has none.

## Dependencies added beyond spec section 4

- `tracing-subscriber`: needed to actually emit `tracing` output (stderr only) from the
  binaries.
- `rmcp` (in the spec's list): see the MCP section.
- `ureq` 3 (rustls, webpki-roots): the HTTPS client for `http_request` (M11); see that
  section.
- The desktop app (`app/`, its own workspace) uses Tauri 2 and its dialog and
  notification plugins (M10).
- `windows` 0.62 (WinRT `KeyCredentialManager`): Windows Hello approval keys (M13); see
  that section.
- `toml_edit` 0.25: policy edits from the app that keep the file's comments. It is
  from the same project as `toml` and shares its parser crates (`toml_parser`,
  `toml_datetime`, `toml_writer`); `indexmap` and `winnow` were already in the tree.
- `windows-sys` feature `Win32_UI_WindowsAndMessaging`: bringing the Hello dialog
  forward.
- Fonts in the app: Geist and Geist Mono (OFL), bundled files, not a dependency.

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
on `windows-latest`, `ubuntu-latest` and `macos-latest`. On Ubuntu it installs
bubblewrap and allows unprivileged user namespaces, then runs the adversarial suite
twice more: with `CREDSTORE_FORCE_SANDBOX=landlock` (Linux) and `=none` (every OS).

The `installed` job (one per OS) builds release binaries, runs the real installer, and
runs `tests/m7_installed.rs` (`--ignored`) against the installed service, then
uninstalls. On Linux and macOS the test runs through `sudo -u $USER`, which picks up
the groups the installer just added. On Windows group membership only reaches a token
at logon, so the job creates a throwaway local user (random password, that runner
only), installs with `-User` set to it, and starts the test as that user with
`Start-Process -Credential`. Commands approved there run in `/opt/credstore-smoke`
(Linux; `ProtectHome` hides the checkout), `/usr/local/credstore-smoke` (macOS) or
`C:\credstore-smoke` (Windows, with an ACL for the service).

The `packages` job (one per OS, M8) builds the `.msi`, `.deb`/`.rpm` or `.pkg`,
installs it the way a user would (`msiexec /i /qn`, `apt-get install ./x.deb`,
`installer -pkg`), checks the service, PATH and group membership, runs the same smoke
test plus `credstore doctor`, then removes the package and checks the service and
binaries are gone and the vault is kept. The `.rpm` is only inspected (file list and
scripts), since the runner is Ubuntu.
