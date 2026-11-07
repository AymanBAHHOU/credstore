//! `credstore doctor` (spec 7): check the install and say, honestly, what protects the
//! secrets on this machine.
//!
//! Run it as the agent's user (the account Claude Code runs as). In installed mode it
//! fails loudly if that account can read or write the vault, its index or the policy,
//! or open the daemon's memory. The daemon's own sandbox and hardening report needs the
//! vault passphrase, so it is shown only when there is a terminal to ask on.

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use credstore_os::probe::{self, MemoryAccess};
use credstore_os::sandbox::mode_name;
use credstore_os::{
    EndpointKind, Mode, Paths, PeerIdentity, Sandbox, ServiceInstall, ServiceStatus, AGENTS_GROUP,
    APPROVERS_GROUP, OS_NAME, SERVICE_USER,
};
use credstore_proto::{AgentRequest, ApproverOp, Response};

use crate::client::{expect_status, response_error, Client};
use crate::commands::Prompt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Info,
    Warn,
    Fail,
}

impl Level {
    fn label(self) -> &'static str {
        match self {
            Level::Ok => "ok  ",
            Level::Info => "info",
            Level::Warn => "WARN",
            Level::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub level: Level,
    pub topic: &'static str,
    pub detail: String,
}

/// Every check doctor made, in order.
#[derive(Debug, Default)]
pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    pub fn failures(&self) -> usize {
        self.count(Level::Fail)
    }

    pub fn count(&self, level: Level) -> usize {
        self.checks.iter().filter(|c| c.level == level).count()
    }

    /// The checks about `topic`.
    pub fn about(&self, topic: &str) -> Vec<&Check> {
        self.checks.iter().filter(|c| c.topic == topic).collect()
    }
}

/// Prints each check as it is made and keeps it for the summary.
struct Doctor<'a> {
    out: &'a mut dyn Write,
    report: Report,
}

impl Doctor<'_> {
    fn check(&mut self, level: Level, topic: &'static str, detail: impl Into<String>) {
        let detail = detail.into();
        let _ = writeln!(self.out, "  {}  {topic:<10} {detail}", level.label());
        self.report.checks.push(Check {
            level,
            topic,
            detail,
        });
    }
}

/// What this account can do with a path. Nothing is created or changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Access {
    Missing,
    /// Neither readable nor writable (the OS refused).
    None(String),
    Some {
        read: bool,
        write: bool,
    },
    Unknown(String),
}

/// Try to open `path` for reading and (files only) for appending.
pub fn probe_access(path: &Path) -> Access {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::NotFound => return Access::Missing,
        Err(e) if e.kind() == ErrorKind::PermissionDenied => return Access::None(e.to_string()),
        Err(e) => return Access::Unknown(e.to_string()),
    };
    let read = if meta.is_dir() {
        std::fs::read_dir(path).map(drop)
    } else {
        File::open(path).map(drop)
    };
    // Opening for append writes nothing. Directories are judged by `read` alone.
    let write = !meta.is_dir() && OpenOptions::new().append(true).open(path).is_ok();
    match read {
        Ok(()) => Access::Some { read: true, write },
        Err(_) if write => Access::Some { read: false, write },
        Err(e) if e.kind() == ErrorKind::PermissionDenied => Access::None(e.to_string()),
        Err(e) => Access::Unknown(e.to_string()),
    }
}

/// Run every check. Returns the report; the caller exits non-zero if it has failures.
pub async fn doctor(
    client: &Client,
    p: &dyn Prompt,
    out: &mut dyn Write,
) -> anyhow::Result<Report> {
    let platform = client.platform();
    let mode = platform.mode();
    let user = probe::current_user();
    let privileged = probe::is_privileged();
    writeln!(
        out,
        "credstore doctor: {} mode, {OS_NAME}, credstore {}, running as {user}\n",
        match mode {
            Mode::Installed => "installed",
            Mode::Dev => "dev",
        },
        env!("CARGO_PKG_VERSION"),
    )?;
    let mut d = Doctor {
        out,
        report: Report::default(),
    };

    if privileged {
        d.check(
            Level::Warn,
            "account",
            format!(
                "{user} is privileged (root, an elevated administrator, or SeDebugPrivilege): \
                 it can read everything below. Run doctor as the agent's user to check what \
                 the agent can reach."
            ),
        );
    }
    if mode == Mode::Dev {
        d.check(
            Level::Warn,
            "mode",
            "dev mode: the daemon runs as you, so the agent (also you) can read the vault \
             file and the daemon's memory. Use the installed mode for real secrets.",
        );
    }

    service_checks(&mut d, client, mode);
    group_checks(&mut d, mode, &user);
    file_checks(&mut d, client, mode, &user, privileged);
    let daemon_pid = endpoint_checks(&mut d, client).await;
    memory_check(&mut d, mode, &user, privileged, daemon_pid);
    match probe::page_file_encrypted() {
        Some(true) => d.check(Level::Ok, "page file", "encrypted"),
        Some(false) => d.check(
            Level::Warn,
            "page file",
            "not encrypted: secrets paged out of memory can stay on disk. Fix (elevated, then restart): fsutil behavior set encryptpagingfile 1",
        ),
        None => {}
    }
    daemon_status(&mut d, client, p).await;
    claude_code_checks(&mut d);

    let report = d.report;
    let (fails, warns) = (report.failures(), report.count(Level::Warn));
    writeln!(
        out,
        "\n{}",
        match (fails, warns) {
            (0, 0) => "No problems found.".to_string(),
            (0, w) => format!("No failures; {w} warning(s)."),
            (f, w) => format!("{f} problem(s) and {w} warning(s) found."),
        }
    )?;
    Ok(report)
}

fn service_checks(d: &mut Doctor<'_>, client: &Client, mode: Mode) {
    if mode == Mode::Dev {
        d.check(
            Level::Info,
            "service",
            "dev mode: no service; credstored --dev runs as you",
        );
        return;
    }
    match client.platform().service_status() {
        Ok(ServiceStatus::Running) => d.check(Level::Ok, "service", "installed and running"),
        Ok(ServiceStatus::Stopped) => d.check(
            Level::Fail,
            "service",
            "installed but not running: start it (systemctl start credstored, \
             launchctl kickstart system/dev.credstore.daemon, or Start-Service credstore)",
        ),
        Ok(ServiceStatus::NotInstalled) => d.check(
            Level::Fail,
            "service",
            "not installed: run deploy/install.sh (Linux, macOS) or deploy/install.ps1 \
             (Windows), or use --dev",
        ),
        Err(e) => d.check(Level::Warn, "service", format!("could not check: {e}")),
    }
    d.check(
        Level::Info,
        "service",
        format!(
            "approved commands run as {SERVICE_USER}, which needs access to the project \
             folders they run in"
        ),
    );
}

fn group_checks(d: &mut Doctor<'_>, mode: Mode, user: &str) {
    if mode == Mode::Dev {
        d.check(
            Level::Info,
            "groups",
            "dev mode: the endpoints accept only your own account",
        );
        return;
    }
    for (group, role) in [(AGENTS_GROUP, "agent"), (APPROVERS_GROUP, "approver")] {
        match probe::group_membership(group) {
            Ok(m) if m.active => {
                d.check(Level::Ok, "groups", format!("{user} is in {group}"));
            }
            // The installer also lists the user in the daemon's users file, which lets
            // them in before the group reaches their session; the endpoint checks below
            // show whether that worked.
            Ok(m) if m.listed == Some(true) => d.check(
                Level::Info,
                "groups",
                format!(
                    "{user} is in {group}; this session predates it, so it applies at the \
                     next logon (the installer also lets you in directly)"
                ),
            ),
            Ok(_) => d.check(
                Level::Fail,
                "groups",
                format!(
                    "{user} is not in {group}, so it cannot use the {role} endpoint (if you \
                     were just added, log out and back in)"
                ),
            ),
            Err(e) => d.check(
                Level::Fail,
                "groups",
                format!("{group}: {e} (run the installer)"),
            ),
        }
    }
}

fn file_checks(d: &mut Doctor<'_>, client: &Client, mode: Mode, user: &str, privileged: bool) {
    let p = client.platform();
    // (topic, path, whether being readable is a failure; being writable always is)
    let items: [(&'static str, PathBuf, bool); 5] = [
        ("data dir", p.data_dir().to_path_buf(), true),
        ("vault", p.vault_file(), true),
        ("index", p.index_file(), true),
        ("policy", p.policy_file().to_path_buf(), true),
        ("audit log", p.audit_log().to_path_buf(), false),
    ];
    for (topic, path, read_fails) in items {
        let shown = path.display();
        if mode == Mode::Dev {
            match credstore_os::fs::is_owner_only(&path) {
                Ok(true) => d.check(
                    Level::Ok,
                    topic,
                    format!("{shown}: only you (and administrators) can open it"),
                ),
                Ok(false) => d.check(
                    Level::Fail,
                    topic,
                    format!("{shown}: other accounts can open it; fix its permissions"),
                ),
                Err(e) if is_not_found(&e) => {
                    d.check(Level::Info, topic, format!("{shown}: not created yet"))
                }
                Err(e) => d.check(Level::Info, topic, format!("{shown}: not checked ({e})")),
            }
            continue;
        }
        let as_who = if privileged {
            format!("{user} (privileged)")
        } else {
            user.to_string()
        };
        let exposed = if privileged { Level::Warn } else { Level::Fail };
        match probe_access(&path) {
            Access::None(why) => d.check(
                Level::Ok,
                topic,
                format!("{shown}: {as_who} cannot read or write it ({why})"),
            ),
            Access::Missing => d.check(
                if topic == "vault" || topic == "index" {
                    Level::Info
                } else {
                    Level::Warn
                },
                topic,
                format!("{shown}: {as_who} can see it does not exist yet"),
            ),
            Access::Some { read, write } => {
                let what = match (read, write) {
                    (true, true) => "read and write",
                    (true, false) => "read",
                    _ => "write",
                };
                let level = if write || read_fails {
                    exposed
                } else {
                    Level::Warn
                };
                d.check(
                    level,
                    topic,
                    format!(
                        "{shown}: {as_who} can {what} it, and so can an agent running as {user}"
                    ),
                );
            }
            Access::Unknown(e) => d.check(Level::Warn, topic, format!("{shown}: {e}")),
        }
    }
}

fn is_not_found(e: &credstore_os::OsError) -> bool {
    matches!(e, credstore_os::OsError::Io(io) if io.kind() == ErrorKind::NotFound)
}

/// Reach both endpoints (each connection checks the daemon's identity first). Returns the
/// daemon's PID when the OS reports it.
async fn endpoint_checks(d: &mut Doctor<'_>, client: &Client) -> Option<u32> {
    let p = client.platform();
    let mut pid = None;
    for (kind, topic) in [
        (EndpointKind::Agent, "agent"),
        (EndpointKind::Approver, "approver"),
    ] {
        let address = p.endpoint(kind).address;
        match client.connect(kind).await {
            Ok(stream) => {
                if let Ok(peer) = stream.peer_identity() {
                    pid = pid.or(peer.pid);
                }
                drop(stream);
                let detail = if kind == EndpointKind::Agent {
                    match client.agent(&AgentRequest::ListSecrets).await {
                        Ok(Response::Secrets { secrets }) => {
                            format!("{} secret(s) listed", secrets.len())
                        }
                        Ok(other) => {
                            d.check(
                                Level::Fail,
                                topic,
                                format!("{address}: {}", response_error(other)),
                            );
                            continue;
                        }
                        Err(e) => {
                            d.check(Level::Fail, topic, format!("{address}: {e:#}"));
                            continue;
                        }
                    }
                } else {
                    "every request still needs the passphrase".to_string()
                };
                d.check(
                    Level::Ok,
                    topic,
                    format!("{address}: reachable, daemon identity checked; {detail}"),
                );
            }
            Err(e) => d.check(Level::Fail, topic, format!("{e:#}")),
        }
    }
    pid
}

fn memory_check(d: &mut Doctor<'_>, mode: Mode, user: &str, privileged: bool, pid: Option<u32>) {
    let Some(pid) = pid else {
        d.check(
            Level::Info,
            "memory",
            "not checked: the daemon's PID is unknown (it is not reachable)",
        );
        return;
    };
    if pid == std::process::id() {
        d.check(
            Level::Info,
            "memory",
            "not checked: the daemon runs inside this process",
        );
        return;
    }
    match probe::process_memory_access(pid) {
        MemoryAccess::Denied(why) => d.check(
            Level::Ok,
            "memory",
            format!("{user} cannot open the daemon's memory (pid {pid}: {why})"),
        ),
        MemoryAccess::Readable => {
            let (level, why) = match (mode, privileged) {
                (Mode::Dev, _) => (Level::Warn, "expected in dev mode"),
                (_, true) => (Level::Warn, "this account is privileged"),
                _ => (Level::Fail, "so can an agent running as this user"),
            };
            d.check(
                level,
                "memory",
                format!("{user} can open the daemon's memory (pid {pid}): {why}"),
            );
        }
        MemoryAccess::Unsupported(why) => {
            d.check(Level::Info, "memory", format!("not checked: {why}"))
        }
    }
}

/// The daemon's own view (sandbox, hardening, policy). Needs the passphrase.
async fn daemon_status(d: &mut Doctor<'_>, client: &Client, p: &dyn Prompt) {
    let pass = if p.has_terminal() {
        match p.secret(
            "Vault passphrase, to show the daemon's sandbox and hardening (Enter to skip): ",
        ) {
            Ok(pass) if !pass.is_empty() => Some(pass),
            Ok(_) => None,
            Err(e) => {
                d.check(
                    Level::Warn,
                    "daemon",
                    format!("could not read the passphrase: {e}"),
                );
                None
            }
        }
    } else {
        None
    };
    let Some(pass) = pass else {
        d.check(
            Level::Info,
            "daemon",
            "skipped the daemon's sandbox and hardening report (it needs the passphrase \
             on a terminal); below is what this process can see",
        );
        let caps = client.platform().sandbox_capabilities();
        d.check(
            if caps.mode == credstore_proto::SandboxMode::None {
                Level::Warn
            } else {
                Level::Info
            },
            "sandbox",
            format!(
                "{}: {} (probed by this process; the daemon's may differ)",
                mode_name(caps.mode),
                caps.detail
            ),
        );
        return;
    };
    let status = match client.approver(ApproverOp::Status, pass).await {
        Ok(r) => expect_status(r),
        Err(e) => Err(e),
    };
    let s = match status {
        Ok(s) => s,
        Err(e) => {
            d.check(Level::Fail, "daemon", format!("status: {e:#}"));
            return;
        }
    };
    d.check(
        Level::Info,
        "daemon",
        format!(
            "credstored {} (pid {}), vault {}, {} pending request(s)",
            s.version.as_deref().unwrap_or("?"),
            s.pid.map_or("?".to_string(), |p| p.to_string()),
            if s.locked { "locked" } else { "unlocked" },
            s.pending
        ),
    );
    match &s.policy_error {
        None => d.check(Level::Ok, "policy", "loaded by the daemon"),
        Some(e) => d.check(
            Level::Fail,
            "policy",
            format!("not loaded, so every run is denied: {e}"),
        ),
    }
    match &s.sandbox {
        Some(sb) if sb.starts_with("none") => d.check(
            Level::Warn,
            "sandbox",
            format!("{sb} (commands can read and write anything the service account can)"),
        ),
        // A Job Object bounds the process tree but hides no files and blocks no network.
        Some(sb) if sb.starts_with("job-object") => d.check(Level::Warn, "sandbox", sb.clone()),
        Some(sb) => d.check(Level::Ok, "sandbox", sb.clone()),
        None => d.check(Level::Warn, "sandbox", "the daemon did not say"),
    }
    if s.hardening.is_empty() {
        d.check(Level::Warn, "hardening", "the daemon reported nothing");
    }
    for h in &s.hardening {
        match (&h.active, &h.detail) {
            (true, None) => d.check(Level::Ok, "hardening", format!("{}: active", h.name)),
            (true, Some(x)) => d.check(Level::Ok, "hardening", format!("{}: active ({x})", h.name)),
            (false, x) => d.check(
                Level::Warn,
                "hardening",
                format!(
                    "{}: not active{}",
                    h.name,
                    x.as_ref().map(|x| format!(" ({x})")).unwrap_or_default()
                ),
            ),
        }
    }
}

/// Claude Code settings: credstore's tools must not be allowlisted (spec 8).
fn claude_code_checks(d: &mut Doctor) {
    let mut files = Vec::new();
    if let Some(home) = credstore_os::run::user_home() {
        files.push(home.join(".claude").join("settings.json"));
    }
    if let Ok(cwd) = std::env::current_dir() {
        files.push(cwd.join(".claude").join("settings.json"));
        files.push(cwd.join(".claude").join("settings.local.json"));
    }
    let mut seen = false;
    for f in files {
        let Ok(text) = std::fs::read_to_string(&f) else {
            continue;
        };
        seen = true;
        let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
            d.check(
                Level::Warn,
                "claude",
                format!("{}: not valid JSON", f.display()),
            );
            continue;
        };
        let rules = |key: &str| -> Vec<String> {
            json["permissions"][key]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default()
        };
        let allowed: Vec<String> = rules("allow")
            .into_iter()
            .filter(|r| r.starts_with("mcp__credstore"))
            .collect();
        if !allowed.is_empty() {
            d.check(
                Level::Warn,
                "claude",
                format!(
                    "{} allowlists {}: remove it so Claude Code asks before each use too",
                    f.display(),
                    allowed.join(", ")
                ),
            );
        }
    }
    if !seen {
        d.check(
            Level::Info,
            "claude",
            "no Claude Code settings found; add the deny rules from the README",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "credstore-doctor-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn access_probe_reports_what_it_can_open() {
        let d = tempdir("access");
        assert_eq!(probe_access(&d.join("missing")), Access::Missing);
        let f = d.join("f");
        std::fs::write(&f, b"x").unwrap();
        assert_eq!(
            probe_access(&f),
            Access::Some {
                read: true,
                write: true
            }
        );
        assert_eq!(std::fs::read(&f).unwrap(), b"x", "the probe wrote nothing");
        assert!(matches!(probe_access(&d), Access::Some { read: true, .. }));
        std::fs::remove_dir_all(d).unwrap();
    }
}
