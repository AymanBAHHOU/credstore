//! Linux and macOS.

pub mod ipc;
pub mod proc;
pub mod sandbox;

use crate::{FeatureStatus, HardeningItem};

/// Executable path of a process, best effort (informational only).
#[cfg(target_os = "linux")]
pub fn exe_of_pid(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// macOS: `proc_pidpath` needs an unsafe FFI call for an informational field; skipped.
#[cfg(target_os = "macos")]
pub fn exe_of_pid(_pid: u32) -> Option<String> {
    None
}

/// No core dumps, no debugger attach. Memory locking is reported, not applied: see
/// `docs/DESIGN.md` ("Memory hardening").
pub fn harden_process() -> Vec<HardeningItem> {
    let mut items = Vec::new();

    let core = nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0);
    items.push(HardeningItem {
        name: "RLIMIT_CORE=0",
        status: status(core.map_err(|e| e.to_string())),
    });

    #[cfg(target_os = "linux")]
    items.push(HardeningItem {
        name: "PR_SET_DUMPABLE=0",
        status: status(nix::sys::prctl::set_dumpable(false).map_err(|e| e.to_string())),
    });

    #[cfg(target_os = "macos")]
    items.push(HardeningItem {
        name: "PT_DENY_ATTACH",
        status: status(deny_attach()),
    });

    items.push(HardeningItem {
        name: "mlock",
        status: FeatureStatus::Unavailable(MLOCK_REASON.into()),
    });
    items
}

pub const MLOCK_REASON: &str = "not applied: secret values live in many small heap \
allocations, and locking all memory (mlockall) would make the 256 MiB scrypt allocation \
fail under the default RLIMIT_MEMLOCK; use encrypted swap";

fn status(r: Result<(), String>) -> FeatureStatus {
    match r {
        Ok(()) => FeatureStatus::Active,
        Err(e) => FeatureStatus::Unavailable(e),
    }
}

/// `ptrace(PT_DENY_ATTACH)`: stop debuggers (and `task_for_pid`-based readers) attaching.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn deny_attach() -> Result<(), String> {
    // SAFETY: PT_DENY_ATTACH takes no pointer argument; the other arguments are ignored.
    let rc = unsafe { nix::libc::ptrace(nix::libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().to_string())
    }
}
