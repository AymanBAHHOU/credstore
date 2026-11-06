//! Checks for `doctor` and the adversarial tests: can this process read another
//! process's memory? Spec 6.4 requires the daemon's memory to be closed to the agent.

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
