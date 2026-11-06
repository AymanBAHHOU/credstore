//! The platform implementation for the OS this build targets.
//!
//! M0: every capability except paths and the passphrase terminal is a stub that returns
//! `Unavailable` with the milestone that will build it. `docs/DESIGN.md` lists them.

use credstore_proto::SecretText;

use crate::{
    Endpoint, EndpointAccess, EndpointKind, FeatureStatus, HardeningItem, Ipc, MemoryGuard, Mode,
    OsError, OsResult, Paths, PlatformPaths, Sandbox, SandboxCapabilities, SandboxPlan,
    SandboxSpec, ServiceInstall, ServiceStatus, StubListener, StubStream, Terminal,
};

/// Platform services for the current OS.
#[derive(Debug, Clone)]
pub struct Platform {
    paths: PlatformPaths,
}

impl Platform {
    pub fn new(mode: Mode) -> OsResult<Self> {
        Ok(Self {
            paths: PlatformPaths::new(mode)?,
        })
    }

    pub fn with_paths(paths: PlatformPaths) -> Self {
        Self { paths }
    }

    pub fn paths(&self) -> &PlatformPaths {
        &self.paths
    }
}

impl Paths for Platform {
    fn mode(&self) -> Mode {
        self.paths.mode()
    }
    fn data_dir(&self) -> &std::path::Path {
        self.paths.data_dir()
    }
    fn policy_file(&self) -> &std::path::Path {
        self.paths.policy_file()
    }
    fn audit_log(&self) -> &std::path::Path {
        self.paths.audit_log()
    }
    fn run_dir(&self) -> &std::path::Path {
        self.paths.run_dir()
    }
    fn endpoint(&self, kind: EndpointKind) -> Endpoint {
        self.paths.endpoint(kind)
    }
}

/// Mechanism name for this OS, used in "not built yet" messages.
#[cfg(target_os = "linux")]
const IPC_NAME: &str = "Unix sockets";
#[cfg(target_os = "macos")]
const IPC_NAME: &str = "Unix sockets";
#[cfg(windows)]
const IPC_NAME: &str = "named pipes";

#[cfg(target_os = "linux")]
const SANDBOX_NAME: &str = "bubblewrap / landlock";
#[cfg(target_os = "macos")]
const SANDBOX_NAME: &str = "Seatbelt (sandbox-exec)";
#[cfg(windows)]
const SANDBOX_NAME: &str = "Job Object + restricted token";

#[cfg(target_os = "linux")]
const HARDENING: &[&str] = &["PR_SET_DUMPABLE=0", "RLIMIT_CORE=0", "mlock"];
#[cfg(target_os = "macos")]
const HARDENING: &[&str] = &["PT_DENY_ATTACH", "RLIMIT_CORE=0", "mlock"];
#[cfg(windows)]
const HARDENING: &[&str] = &[
    "process DACL denying VM read/write/dup-handle",
    "WER dumps disabled",
    "VirtualLock",
];

impl Ipc for Platform {
    type Listener = StubListener;
    type Stream = StubStream;

    async fn bind(&self, _: &Endpoint, _: &EndpointAccess) -> OsResult<StubListener> {
        Err(OsError::unavailable(format!(
            "{IPC_NAME} not built yet (M2)"
        )))
    }

    async fn connect(&self, _: &Endpoint) -> OsResult<StubStream> {
        Err(OsError::unavailable(format!(
            "{IPC_NAME} not built yet (M2)"
        )))
    }
}

impl Sandbox for Platform {
    fn capabilities(&self) -> OsResult<SandboxCapabilities> {
        Err(OsError::unavailable(format!(
            "{SANDBOX_NAME} not built yet (M5)"
        )))
    }

    fn plan(&self, _: &[String], _: &SandboxSpec) -> OsResult<SandboxPlan> {
        Err(OsError::unavailable(format!(
            "{SANDBOX_NAME} not built yet (M5)"
        )))
    }

    fn attach(&self, _: u32) -> OsResult<()> {
        Err(OsError::unavailable(format!(
            "{SANDBOX_NAME} not built yet (M5)"
        )))
    }
}

impl MemoryGuard for Platform {
    fn harden_process(&self) -> Vec<HardeningItem> {
        HARDENING
            .iter()
            .map(|name| HardeningItem {
                name,
                status: FeatureStatus::Unavailable("not built yet (M2)".into()),
            })
            .collect()
    }

    fn lock_memory(&self, _: &mut [u8]) -> OsResult<()> {
        Err(OsError::unavailable("memory locking not built yet (M2)"))
    }
}

impl ServiceInstall for Platform {
    fn service_status(&self) -> OsResult<ServiceStatus> {
        Err(OsError::unavailable("service install not built yet (M7)"))
    }
}

impl Terminal for Platform {
    fn has_terminal(&self) -> bool {
        controlling_terminal_opens()
    }

    fn read_passphrase(&self, prompt: &str) -> OsResult<SecretText> {
        if !controlling_terminal_opens() {
            return Err(OsError::unavailable("no controlling terminal"));
        }
        // rpassword reads /dev/tty on Unix and the console (CONIN$) on Windows, not stdin.
        let value = rpassword::prompt_password(prompt)?;
        Ok(SecretText::new(value))
    }
}

#[cfg(unix)]
fn controlling_terminal_opens() -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .is_ok()
}

#[cfg(windows)]
fn controlling_terminal_opens() -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("CONIN$")
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn platform() -> Platform {
        Platform::with_paths(PlatformPaths::dev_with_home(
            std::env::temp_dir().join("credstore-os-test"),
        ))
    }

    #[tokio::test]
    async fn unbuilt_features_report_unavailable() {
        let p = platform();
        let ep = p.endpoint(EndpointKind::Agent);
        assert!(p
            .bind(&ep, &EndpointAccess::SameUser)
            .await
            .unwrap_err()
            .is_unavailable());
        assert!(p.connect(&ep).await.unwrap_err().is_unavailable());
        assert!(p.capabilities().unwrap_err().is_unavailable());
        assert!(p.attach(1).unwrap_err().is_unavailable());
        assert!(p.service_status().unwrap_err().is_unavailable());
        assert!(p.lock_memory(&mut [0u8; 4]).unwrap_err().is_unavailable());
    }

    #[test]
    fn hardening_reports_every_feature() {
        let items = platform().harden_process();
        assert_eq!(items.len(), HARDENING.len());
        assert!(items
            .iter()
            .all(|i| matches!(i.status, FeatureStatus::Unavailable(_))));
    }
}
