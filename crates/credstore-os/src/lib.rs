//! credstore platform layer.
//!
//! All OS-specific behavior lives here behind the traits below. Code outside this crate
//! must not use `cfg(unix)` / `cfg(windows)` or hard-code paths or separators.
//!
//! Every fallible method returns [`OsResult`]. A feature the OS (or this build) cannot
//! provide returns [`OsError::Unavailable`] with a reason. Callers must report that
//! reason (audit log, approval prompt) and apply policy; they must never skip it silently.

use std::future::Future;
use std::path::{Path, PathBuf};

use credstore_proto::{NetworkPolicy, PeerInfo, SecretText};
use tokio::io::{AsyncRead, AsyncWrite};

pub mod exec;
pub mod fs;
pub mod grant;
mod paths;
mod platform;
pub mod probe;
pub mod run;
pub mod sandbox;
pub mod service;
pub mod signals;
mod sys;

pub use paths::{PlatformPaths, CREDSTORE_HOME_ENV};
pub use platform::Platform;
pub use sandbox::{SandboxCapabilities, SandboxNeed, SandboxPlan, SandboxSpec};

/// Name of the OS this build targets: `"linux"`, `"macos"` or `"windows"`.
pub const OS_NAME: &str = std::env::consts::OS;

/// Account the installed daemon runs as.
#[cfg(target_os = "linux")]
pub const SERVICE_USER: &str = "credstore";
#[cfg(target_os = "macos")]
pub const SERVICE_USER: &str = "_credstore";
#[cfg(windows)]
pub const SERVICE_USER: &str = r"NT SERVICE\credstore";

/// Group allowed on the agent endpoint (installed mode).
pub const AGENTS_GROUP: &str = "credstore-agents";
/// Group allowed on the approver endpoint (installed mode).
pub const APPROVERS_GROUP: &str = "credstore-approvers";

#[derive(Debug, thiserror::Error)]
pub enum OsError {
    #[error("unavailable: {0}")]
    Unavailable(String),
    /// A peer or object failed an identity check.
    #[error("denied: {0}")]
    Denied(String),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

impl OsError {
    pub fn unavailable(reason: impl Into<String>) -> Self {
        OsError::Unavailable(reason.into())
    }

    pub fn is_unavailable(&self) -> bool {
        matches!(self, OsError::Unavailable(_))
    }
}

pub type OsResult<T> = Result<T, OsError>;

/// Whether the daemon runs as the separate service user (installed) or as the current
/// user (dev, weaker; see the spec's threat model).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Dev,
    Installed,
}

/// Warning `credstored --dev` must print.
pub const DEV_MODE_WARNING: &str = "DEV MODE: the agent can read this process's memory and \
the vault file. Use the installed mode for real secrets.";

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// Which daemon endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKind {
    Agent,
    Approver,
}

/// An IPC endpoint address: a socket path on Unix, a pipe name on Windows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub kind: EndpointKind,
    pub address: String,
}

/// Every location credstore uses. Nothing else may build these paths.
pub trait Paths {
    fn mode(&self) -> Mode;
    /// Directory holding the vault and its index.
    fn data_dir(&self) -> &Path;
    fn vault_file(&self) -> PathBuf {
        self.data_dir().join("vault.age")
    }
    fn index_file(&self) -> PathBuf {
        self.data_dir().join("index.json")
    }
    fn policy_file(&self) -> &Path;
    /// Accounts the installer allows on both endpoints directly (installed mode), next to
    /// the policy and protected like it.
    fn users_file(&self) -> PathBuf {
        self.policy_file().with_file_name("users")
    }
    fn audit_log(&self) -> &Path;
    /// Per-run directories for `file` injection live under here. Swept on startup.
    fn run_dir(&self) -> &Path;
    fn endpoint(&self, kind: EndpointKind) -> Endpoint;
}

// ---------------------------------------------------------------------------
// IPC and peer identity
// ---------------------------------------------------------------------------

/// Who may connect to an endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointAccess {
    /// Only the user running the daemon (dev mode).
    SameUser,
    /// Members of this local group (installed mode: `credstore-agents` /
    /// `credstore-approvers`), checked in the account database, plus `users` by name.
    ///
    /// `users` come from the installer's users file. They are let in without depending on
    /// the group reaching their logon session, which only happens at the next logon.
    Group { group: String, users: Vec<String> },
}

/// Accounts listed in the installer's users file (see [`Paths::users_file`]): one name
/// per line; blank lines and `#` comments are ignored. A missing file is an empty list.
pub fn read_users_file(path: &Path) -> OsResult<Vec<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(parse_users(&text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.into()),
    }
}

fn parse_users(text: &str) -> Vec<String> {
    let mut users: Vec<String> = Vec::new();
    for line in text.lines() {
        let name = line.split('#').next().unwrap_or("").trim();
        if !name.is_empty() && !users.iter().any(|u| u.eq_ignore_ascii_case(name)) {
            users.push(name.to_owned());
        }
    }
    users
}

#[cfg(test)]
mod users_file_tests {
    use super::*;

    #[test]
    fn users_file_lines_comments_and_duplicates() {
        let text = "# written by the installer\nalice\n\n  MYPC\\bob  # the approver\nALICE\n";
        assert_eq!(parse_users(text), ["alice", r"MYPC\bob"]);
    }

    #[test]
    fn missing_users_file_is_empty() {
        let p = std::env::temp_dir().join("credstore-no-such-users-file");
        assert!(read_users_file(&p).unwrap().is_empty());
    }
}

/// Identity of the process on the other end of a connection.
pub trait PeerIdentity {
    /// UID (Unix) or SID (Windows) is the access check; PID and exe are informational.
    fn peer_identity(&self) -> OsResult<PeerInfo>;
}

/// A connected IPC stream.
pub trait IpcStream: AsyncRead + AsyncWrite + PeerIdentity + Unpin + Send {
    /// Check the peer against the endpoint's access rule and return its identity.
    /// Errors with [`OsError::Denied`] if it is not allowed. Call it after reading the
    /// first frame and before acting on it: on Windows the client identity is only known
    /// once the client has written.
    fn authorize(&self) -> OsResult<PeerInfo>;
}

pub trait IpcListener: Send {
    type Stream: IpcStream;
    fn accept(&mut self) -> impl Future<Output = OsResult<Self::Stream>> + Send;
}

/// Unix sockets or Windows named pipes, with access control applied at bind time.
pub trait Ipc {
    type Listener: IpcListener<Stream = Self::Stream>;
    type Stream: IpcStream;
    fn bind(
        &self,
        endpoint: &Endpoint,
        access: &EndpointAccess,
    ) -> impl Future<Output = OsResult<Self::Listener>> + Send;
    fn connect(&self, endpoint: &Endpoint) -> impl Future<Output = OsResult<Self::Stream>> + Send;
}

// ---------------------------------------------------------------------------
// Sandbox
// ---------------------------------------------------------------------------

/// Sandbox capabilities and per-run planning. The runner (`run::run`) applies the plan.
pub trait Sandbox {
    /// What this machine can enforce (probed once per process).
    fn sandbox_capabilities(&self) -> &'static SandboxCapabilities;
    /// The sandbox a run will get, or why policy requires a denial.
    fn sandbox_plan(
        &self,
        need: SandboxNeed,
        network: NetworkPolicy,
    ) -> Result<SandboxPlan, String>;
    /// Like [`Sandbox::sandbox_plan`], also checking the run's folder and program where
    /// that matters (Windows AppContainer).
    fn sandbox_plan_for_run(
        &self,
        need: SandboxNeed,
        network: NetworkPolicy,
        cwd: &Path,
        program: Option<&Path>,
    ) -> Result<SandboxPlan, String>;
}

// ---------------------------------------------------------------------------
// Memory hardening
// ---------------------------------------------------------------------------

/// Whether one hardening feature is active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeatureStatus {
    Active,
    Unavailable(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardeningItem {
    pub name: &'static str,
    pub status: FeatureStatus,
}

pub trait MemoryGuard {
    /// Best effort: no core dumps, no debugger attach, no memory reads by other users.
    /// Returns one item per feature so the daemon can log what actually applied.
    fn harden_process(&self) -> Vec<HardeningItem>;
    /// Keep `buf` out of swap (`mlock` / `VirtualLock`).
    fn lock_memory(&self, buf: &mut [u8]) -> OsResult<()>;
}

// ---------------------------------------------------------------------------
// Service install
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStatus {
    NotInstalled,
    Stopped,
    Running,
}

pub trait ServiceInstall {
    fn service_status(&self) -> OsResult<ServiceStatus>;
}

// ---------------------------------------------------------------------------
// Terminal
// ---------------------------------------------------------------------------

pub trait Terminal {
    /// Whether a controlling terminal (`/dev/tty`, or the Windows console) can be opened.
    fn has_terminal(&self) -> bool;
    /// No-echo prompt read from the controlling terminal, never from stdin, so a piped
    /// stdin cannot answer it.
    fn read_passphrase(&self, prompt: &str) -> OsResult<SecretText>;
    /// One line of visible input from the controlling terminal (not stdin).
    fn read_line(&self, prompt: &str) -> OsResult<String>;
}
