//! The platform implementation for the OS this build targets.

use std::io::{BufRead, Write};

use credstore_proto::{NetworkPolicy, SecretText};

use crate::sys::current as sys;
use crate::{
    Endpoint, EndpointAccess, EndpointKind, HardeningItem, Ipc, MemoryGuard, Mode, OsError,
    OsResult, Paths, PlatformPaths, Sandbox, SandboxCapabilities, SandboxNeed, SandboxPlan,
    ServiceInstall, ServiceStatus, Terminal,
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

#[cfg(unix)]
type SysListener = crate::sys::unix::ipc::UnixIpcListener;
#[cfg(unix)]
type SysStream = crate::sys::unix::ipc::UnixIpcStream;
#[cfg(windows)]
type SysListener = crate::sys::windows::ipc::PipeListener;
#[cfg(windows)]
type SysStream = crate::sys::windows::ipc::PipeStream;

impl Ipc for Platform {
    type Listener = SysListener;
    type Stream = SysStream;

    async fn bind(&self, endpoint: &Endpoint, access: &EndpointAccess) -> OsResult<SysListener> {
        sys::ipc::bind(endpoint, access).await
    }

    async fn connect(&self, endpoint: &Endpoint) -> OsResult<SysStream> {
        sys::ipc::connect(endpoint, self.mode()).await
    }
}

impl Sandbox for Platform {
    fn sandbox_capabilities(&self) -> &'static SandboxCapabilities {
        crate::sandbox::capabilities()
    }

    fn sandbox_plan(
        &self,
        need: SandboxNeed,
        network: NetworkPolicy,
    ) -> Result<SandboxPlan, String> {
        crate::sandbox::plan(self.sandbox_capabilities(), need, network)
    }
}

impl MemoryGuard for Platform {
    fn harden_process(&self) -> Vec<HardeningItem> {
        sys::harden_process()
    }

    fn lock_memory(&self, _: &mut [u8]) -> OsResult<()> {
        Err(OsError::unavailable(
            "per-buffer memory locking is not applied (see docs/DESIGN.md)",
        ))
    }
}

impl ServiceInstall for Platform {
    fn service_status(&self) -> OsResult<ServiceStatus> {
        Err(OsError::unavailable("service install not built yet (M7)"))
    }
}

impl Terminal for Platform {
    fn has_terminal(&self) -> bool {
        open_terminal().is_ok()
    }

    fn read_passphrase(&self, prompt: &str) -> OsResult<SecretText> {
        if !self.has_terminal() {
            return Err(OsError::unavailable("no controlling terminal"));
        }
        // rpassword reads /dev/tty on Unix and the console (CONIN$) on Windows, not stdin.
        let value = rpassword::prompt_password(prompt)?;
        Ok(SecretText::new(value))
    }

    fn read_line(&self, prompt: &str) -> OsResult<String> {
        let (input, mut output) = open_terminal()?;
        output.write_all(prompt.as_bytes())?;
        output.flush()?;
        let mut line = String::new();
        std::io::BufReader::new(input).read_line(&mut line)?;
        Ok(line.trim_end_matches(['\r', '\n']).to_owned())
    }
}

/// The controlling terminal as (input, output), never stdin/stdout.
#[cfg(unix)]
fn open_terminal() -> OsResult<(std::fs::File, std::fs::File)> {
    let open = || {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
    };
    Ok((open()?, open()?))
}

#[cfg(windows)]
fn open_terminal() -> OsResult<(std::fs::File, std::fs::File)> {
    let input = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("CONIN$")?;
    let output = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("CONOUT$")?;
    Ok((input, output))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn platform() -> Platform {
        Platform::with_paths(PlatformPaths::dev_with_home(
            std::env::temp_dir().join("credstore-os-test"),
        ))
    }

    #[test]
    fn unbuilt_features_report_unavailable() {
        let p = platform();
        // The sandbox is built; on every CI OS it finds a mechanism.
        let caps = p.sandbox_capabilities();
        assert!(!caps.detail.is_empty());
        assert!(p.service_status().unwrap_err().is_unavailable());
        assert!(p.lock_memory(&mut [0u8; 4]).unwrap_err().is_unavailable());
    }
}
