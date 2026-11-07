//! Checks for `doctor` and the adversarial tests: can this process read another
//! process's memory (spec 6.4 requires the daemon's memory to be closed to the agent),
//! is this account privileged, and is it in the credstore groups.

use crate::{OsError, OsResult};

/// Result of trying to open a process for memory reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryAccess {
    /// The process could be opened for reading. Its memory is exposed to this user.
    Readable,
    /// The OS refused. The string says how.
    Denied(String),
    /// This OS has no unprivileged way to try.
    Unsupported(String),
}

/// Try to open process `pid` for reading its memory: `/proc/<pid>/mem` on Linux,
/// `OpenProcess(PROCESS_VM_READ)` on Windows. Nothing is read.
pub fn process_memory_access(pid: u32) -> MemoryAccess {
    imp(pid)
}

/// Whether this process can read other processes' memory whatever their protection:
/// root on Unix, `SeDebugPrivilege` enabled on Windows. Hardening cannot stop such a
/// user; only a sandbox (or running the agent as another, unprivileged user) can.
pub fn bypasses_process_protection() -> bool {
    privileged()
}

/// Whether this account is root (Unix) or an elevated administrator or holds an enabled
/// `SeDebugPrivilege` (Windows). File checks run as such an account show what *it* can
/// read, not what the agent's user can.
pub fn is_privileged() -> bool {
    privileged() || elevated_admin()
}

/// Whether Windows encrypts its page file (`fsutil behavior query encryptpagingfile`).
/// Secrets the daemon holds can be paged out; this keeps them unreadable on disk after
/// shutdown. `None` where the question does not apply or the query failed.
pub fn page_file_encrypted() -> Option<bool> {
    #[cfg(windows)]
    {
        let fsutil = std::env::var_os("SystemRoot")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| r"C:\Windows".into())
            .join("System32")
            .join("fsutil.exe");
        let out = std::process::Command::new(fsutil)
            .args(["behavior", "query", "encryptpagingfile"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let line = text.lines().find(|l| l.contains("EncryptPagingFile"))?;
        let value = line.split('=').nth(1)?.trim();
        Some(value.starts_with('1'))
    }
    #[cfg(not(windows))]
    {
        None
    }
}

#[cfg(unix)]
fn elevated_admin() -> bool {
    false
}

/// Administrators (S-1-5-32-544) enabled in the token: an elevated session.
#[cfg(windows)]
fn elevated_admin() -> bool {
    crate::sys::current::win::token_has_sid("S-1-5-32-544").unwrap_or(false)
}

/// Name of the account running this process.
pub fn current_user() -> String {
    user_name()
}

#[cfg(unix)]
fn user_name() -> String {
    let uid = nix::unistd::geteuid();
    nix::unistd::User::from_uid(uid)
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_else(|| format!("uid {uid}"))
}

#[cfg(windows)]
fn user_name() -> String {
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "?".into());
    match std::env::var("USERDOMAIN") {
        Ok(d) if !d.is_empty() => format!(r"{d}\{user}"),
        _ => user,
    }
}

/// This account's membership in a local group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupMembership {
    /// The group applies to this process now (its credentials or token carry it).
    pub active: bool,
    /// The account is listed as a member (`/etc/group` or the directory). `None` where the
    /// OS gives no cheap answer (Windows).
    pub listed: Option<bool>,
}

/// Whether this account is in group `name`. Errors with `Unavailable` if there is no
/// such group. A member added after this session started is listed but not active until
/// the user logs in again.
pub fn group_membership(name: &str) -> OsResult<GroupMembership> {
    membership(name)
}

#[cfg(unix)]
fn membership(name: &str) -> OsResult<GroupMembership> {
    use nix::unistd::{getegid, geteuid, Group, User};
    let group = Group::from_name(name)
        .map_err(|e| OsError::Io(e.into()))?
        .ok_or_else(|| OsError::unavailable(format!("no group {name}")))?;
    let user = User::from_uid(geteuid()).map_err(|e| OsError::Io(e.into()))?;
    let listed = user
        .as_ref()
        .map(|u| u.gid == group.gid || group.mem.iter().any(|m| m == &u.name));
    Ok(GroupMembership {
        active: getegid() == group.gid || in_process_groups(group.gid, listed),
        listed,
    })
}

#[cfg(target_os = "linux")]
fn in_process_groups(gid: nix::unistd::Gid, _listed: Option<bool>) -> bool {
    nix::unistd::getgroups().is_ok_and(|g| g.contains(&gid))
}

/// macOS resolves supplementary groups through the directory service on each check, so
/// being listed is what counts.
#[cfg(not(target_os = "linux"))]
#[cfg(unix)]
fn in_process_groups(_gid: nix::unistd::Gid, listed: Option<bool>) -> bool {
    listed.unwrap_or(false)
}

#[cfg(windows)]
fn membership(name: &str) -> OsResult<GroupMembership> {
    use crate::sys::current::win;
    let sid = win::lookup_account_sid(name)
        .map_err(|e| OsError::unavailable(format!("no group {name} ({e})")))?;
    Ok(GroupMembership {
        active: win::token_has_sid(&sid)?,
        listed: None,
    })
}

#[cfg(unix)]
fn privileged() -> bool {
    nix::unistd::geteuid().is_root()
}

#[cfg(windows)]
fn privileged() -> bool {
    crate::sys::current::win::debug_privilege_enabled()
}

#[cfg(target_os = "linux")]
fn imp(pid: u32) -> MemoryAccess {
    match std::fs::File::open(format!("/proc/{pid}/mem")) {
        Ok(_) => MemoryAccess::Readable,
        Err(e) => MemoryAccess::Denied(e.to_string()),
    }
}

#[cfg(target_os = "macos")]
fn imp(_pid: u32) -> MemoryAccess {
    MemoryAccess::Unsupported(
        "task_for_pid needs the debugger entitlement or root; the daemon also sets \
         PT_DENY_ATTACH"
            .into(),
    )
}

#[cfg(windows)]
fn imp(pid: u32) -> MemoryAccess {
    crate::sys::current::win::open_for_memory_read(pid)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn imp(_pid: u32) -> MemoryAccess {
    MemoryAccess::Unsupported("not built for this OS".into())
}
