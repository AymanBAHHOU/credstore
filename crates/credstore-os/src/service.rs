//! The installed daemon as an OS service (spec 8).
//!
//! systemd (Linux) and launchd (macOS) run `credstored` as an ordinary process and stop
//! it with SIGTERM. Windows needs the process to talk to the Service Control Manager, so
//! `credstored --service` hands its body to [`run_as_service`] there.

#[cfg(not(windows))]
use crate::OsError;
use crate::{OsResult, ServiceStatus};

/// Windows service name.
pub const WINDOWS_SERVICE: &str = "credstore";
/// systemd unit.
pub const SYSTEMD_UNIT: &str = "credstored";
/// launchd label.
pub const LAUNCHD_LABEL: &str = "dev.credstore.daemon";

/// The daemon's body under a service manager. The receiver turns `true` when the
/// service manager asks it to stop.
pub type ServiceBody =
    Box<dyn FnOnce(tokio::sync::watch::Receiver<bool>) -> Result<(), String> + Send>;

/// Run `body` under the Windows Service Control Manager. Blocks until it returns.
pub fn run_as_service(body: ServiceBody) -> OsResult<()> {
    #[cfg(windows)]
    {
        crate::sys::current::service::run(WINDOWS_SERVICE, body)
    }
    #[cfg(not(windows))]
    {
        drop(body);
        Err(OsError::unavailable(
            "--service is for Windows; systemd and launchd run credstored directly",
        ))
    }
}

/// Whether the installed service exists and runs.
pub fn status() -> OsResult<ServiceStatus> {
    imp()
}

#[cfg(windows)]
fn imp() -> OsResult<ServiceStatus> {
    crate::sys::current::service::status(WINDOWS_SERVICE)
}

#[cfg(target_os = "linux")]
fn imp() -> OsResult<ServiceStatus> {
    let unit = format!("{SYSTEMD_UNIT}.service");
    let known = std::process::Command::new("systemctl")
        .args(["cat", &unit])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| OsError::unavailable(format!("systemctl: {e}")))?;
    if !known.success() {
        return Ok(ServiceStatus::NotInstalled);
    }
    let out = std::process::Command::new("systemctl")
        .args(["is-active", &unit])
        .output()?;
    Ok(if String::from_utf8_lossy(&out.stdout).trim() == "active" {
        ServiceStatus::Running
    } else {
        ServiceStatus::Stopped
    })
}

#[cfg(target_os = "macos")]
fn imp() -> OsResult<ServiceStatus> {
    let out = std::process::Command::new("launchctl")
        .args(["print", &format!("system/{LAUNCHD_LABEL}")])
        .output()?;
    if !out.status.success() {
        return Ok(ServiceStatus::NotInstalled);
    }
    Ok(
        if String::from_utf8_lossy(&out.stdout).contains("state = running") {
            ServiceStatus::Running
        } else {
            ServiceStatus::Stopped
        },
    )
}
