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

use credstore_proto::{NetworkPolicy, PeerInfo, SandboxMode, SecretText};
use tokio::io::{AsyncRead, AsyncWrite};

pub mod fs;
mod paths;
mod platform;
mod stub;

pub use paths::PlatformPaths;
pub use platform::Platform;
pub use stub::{StubListener, StubStream};

/// Name of the OS this build targets: `"linux"`, `"macos"` or `"windows"`.
pub const OS_NAME: &str = std::env::consts::OS;

#[derive(Debug, thiserror::Error)]
pub enum OsError {
    #[error("unavailable: {0}")]
    Unavailable(String),
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
    /// `credstore-approvers`).
    Group(String),
}

/// Identity of the process on the other end of a connection.
pub trait PeerIdentity {
    /// UID (Unix) or SID (Windows) is the access check; PID and exe are informational.
    fn peer_identity(&self) -> OsResult<PeerInfo>;
}

/// A connected IPC stream.
pub trait IpcStream: AsyncRead + AsyncWrite + PeerIdentity + Unpin + Send {}

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

/// What a run is allowed to touch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxSpec {
    /// Writable paths (the run's cwd and its temp dir). Everything else is read-only.
    pub writable: Vec<PathBuf>,
    /// Paths the child must not see at all (vault, policy, audit).
    pub hidden: Vec<PathBuf>,
    pub network: NetworkPolicy,
    pub allow_hosts: Vec<String>,
}

/// What the sandbox can do on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxCapabilities {
    /// Best mechanism available.
    pub mode: SandboxMode,
    /// Whether network access can be restricted per process.
    pub network_restriction: bool,
}

/// A command rewritten to run inside the sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPlan {
    pub argv: Vec<String>,
    pub mode: SandboxMode,
}

pub trait Sandbox {
    fn capabilities(&self) -> OsResult<SandboxCapabilities>;
    /// Wrap `argv` so it runs confined by `spec`. Errors if `spec` cannot be met.
    fn plan(&self, argv: &[String], spec: &SandboxSpec) -> OsResult<SandboxPlan>;
    /// Called with the child's PID right after spawn (Windows: assign to the Job Object).
    fn attach(&self, pid: u32) -> OsResult<()>;
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
}
