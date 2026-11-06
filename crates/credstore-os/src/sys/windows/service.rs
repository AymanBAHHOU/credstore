//! Running under the Windows Service Control Manager, and asking it about the service.
//!
//! `run` hands the calling thread to `StartServiceCtrlDispatcherW`, which calls
//! `service_main` on a new thread. That thread reports RUNNING, runs the daemon body, and
//! reports STOPPED when it returns. A stop or shutdown request from the SCM flips the
//! watch channel the body is given. Every `unsafe` block states why it is sound.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use tokio::sync::watch;
use windows_sys::core::PWSTR;
use windows_sys::Win32::Foundation::{ERROR_CALL_NOT_IMPLEMENTED, NO_ERROR};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
    SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_STATUS,
    SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};

use super::win::wide;
use crate::service::ServiceBody;
use crate::{OsError, OsResult, ServiceStatus};

static NAME: OnceLock<Vec<u16>> = OnceLock::new();
static BODY: Mutex<Option<ServiceBody>> = Mutex::new(None);
static RESULT: Mutex<Option<Result<(), String>>> = Mutex::new(None);
static STOP: OnceLock<watch::Sender<bool>> = OnceLock::new();
/// The SERVICE_STATUS_HANDLE, stored as an integer so it can live in a static.
static STATUS_HANDLE: AtomicUsize = AtomicUsize::new(0);

pub fn run(name: &str, body: ServiceBody) -> OsResult<()> {
    *BODY.lock().unwrap_or_else(|p| p.into_inner()) = Some(body);
    let name = NAME.get_or_init(|| wide(name));
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_ptr() as PWSTR,
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: `table` is a valid, null-terminated table that outlives the call, which
    // blocks until the service has stopped. The SCM does not write through the name.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(OsError::Io(std::io::Error::last_os_error()));
    }
    match RESULT.lock().unwrap_or_else(|p| p.into_inner()).take() {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(OsError::Io(std::io::Error::other(e))),
        None => Err(OsError::Io(std::io::Error::other(
            "the service stopped before it ran",
        ))),
    }
}

fn set_status(state: SERVICE_STATUS_CURRENT_STATE, exit_code: u32) {
    let handle = STATUS_HANDLE.load(Ordering::SeqCst) as SERVICE_STATUS_HANDLE;
    if handle.is_null() {
        return;
    }
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        },
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: if state == SERVICE_STOP_PENDING {
            15_000
        } else {
            0
        },
    };
    // SAFETY: `handle` came from RegisterServiceCtrlHandlerExW; `status` is valid.
    unsafe { SetServiceStatus(handle, &status) };
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
    let (tx, rx) = watch::channel(false);
    let _ = STOP.set(tx);
    let Some(name) = NAME.get() else { return };
    // SAFETY: `name` is NUL-terminated and static; `handler` has the required signature.
    let handle =
        unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(handler), std::ptr::null()) };
    if handle.is_null() {
        *RESULT.lock().unwrap_or_else(|p| p.into_inner()) = Some(Err(format!(
            "RegisterServiceCtrlHandlerExW failed: {}",
            std::io::Error::last_os_error()
        )));
        return;
    }
    STATUS_HANDLE.store(handle as usize, Ordering::SeqCst);
    set_status(SERVICE_RUNNING, NO_ERROR);

    let body = BODY.lock().unwrap_or_else(|p| p.into_inner()).take();
    let result = match body {
        Some(b) => b(rx),
        None => Err("no service body".into()),
    };
    set_status(SERVICE_STOPPED, if result.is_ok() { NO_ERROR } else { 1 });
    *RESULT.lock().unwrap_or_else(|p| p.into_inner()) = Some(result);
}

unsafe extern "system" fn handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            set_status(SERVICE_STOP_PENDING, NO_ERROR);
            if let Some(tx) = STOP.get() {
                let _ = tx.send(true);
            }
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

/// Service state from `sc.exe query`.
pub fn status(name: &str) -> OsResult<ServiceStatus> {
    let out = std::process::Command::new("sc.exe")
        .args(["query", name])
        .output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(if text.contains("RUNNING") {
        ServiceStatus::Running
    } else if text.contains("STATE") {
        ServiceStatus::Stopped
    } else {
        ServiceStatus::NotInstalled
    })
}
