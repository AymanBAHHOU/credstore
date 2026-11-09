//! Job Objects for child processes, and private directories.
//!
//! Children start suspended, are put in a Job Object, then resumed, so no process of the
//! tree can start outside the job. The job kills every process in it when it is
//! terminated or its last handle closes. Every `unsafe` block states why it is sound.
#![allow(unsafe_code)]

use std::io;
use std::path::Path;

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};

use super::win::{current_user_sid, wide, OwnedHandle, SecurityDescriptor};

/// Most processes one run may have alive at once.
pub const MAX_PROCESSES: u32 = 512;
/// Most memory all processes of one run may commit together.
pub const MAX_JOB_MEMORY: usize = 4 << 30;

pub struct Job(OwnedHandle);

// SAFETY: a job handle can be used from any thread.
unsafe impl Send for Job {}
// SAFETY: the Win32 job functions used here are thread-safe.
unsafe impl Sync for Job {}

impl Job {
    /// A new anonymous job with kill-on-close and process/memory limits.
    pub fn new() -> io::Result<Self> {
        // SAFETY: null attributes and name create an unnamed job with default security.
        let h = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if h.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = Self(OwnedHandle::from_raw(h));
        // SAFETY: all-zero is a valid value for this plain C struct.
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_JOB_MEMORY;
        info.BasicLimitInformation.ActiveProcessLimit = MAX_PROCESSES;
        info.JobMemoryLimit = MAX_JOB_MEMORY;
        // SAFETY: `info` is a valid JOBOBJECT_EXTENDED_LIMIT_INFORMATION of the size given.
        let ok = unsafe {
            SetInformationJobObject(
                job.0.raw(),
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(job)
    }

    /// Put a (suspended) process in the job.
    pub fn assign(&self, process: HANDLE) -> io::Result<()> {
        // SAFETY: both handles are valid; `process` is owned by the caller's Child.
        if unsafe { AssignProcessToJobObject(self.0.raw(), process) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Kill every process in the job.
    pub fn terminate(&self) {
        // SAFETY: valid job handle. Failure (already empty) is harmless.
        unsafe { TerminateJobObject(self.0.raw(), 1) };
    }
}

/// Resume every thread of `pid` (started with `CREATE_SUSPENDED`). Returns how many.
pub fn resume_threads(pid: u32) -> io::Result<usize> {
    // SAFETY: plain snapshot call; the handle is owned below.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let snap = OwnedHandle::from_raw(snap);
    // SAFETY: all-zero is valid; dwSize is set as the API requires.
    let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
    let mut resumed = 0;
    // SAFETY: valid snapshot handle and a correctly sized entry.
    let mut more = unsafe { Thread32First(snap.raw(), &mut entry) } != 0;
    while more {
        if entry.th32OwnerProcessID == pid {
            // SAFETY: opening a thread by id; the handle is owned and closed below.
            let t = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
            if !t.is_null() {
                let t = OwnedHandle::from_raw(t);
                // SAFETY: valid thread handle with SUSPEND_RESUME access.
                if unsafe { ResumeThread(t.raw()) } != u32::MAX {
                    resumed += 1;
                }
            }
        }
        // SAFETY: same as Thread32First.
        more = unsafe { Thread32Next(snap.raw(), &mut entry) } != 0;
    }
    if resumed == 0 {
        return Err(io::Error::other("no thread of the child process to resume"));
    }
    Ok(resumed)
}

/// Create `dir` with a protected DACL: full control for this user, SYSTEM and
/// Administrators. Files created inside inherit it. Administrators can take any file
/// anyway; listing them lets an elevated shell delete the service's leftovers (the run
/// folder) without taking ownership first.
pub fn create_private_directory(dir: &Path) -> io::Result<()> {
    let me = current_user_sid()?;
    let sd = SecurityDescriptor::from_sddl(&format!(
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{me})"
    ))?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.ptr(),
        bInheritHandle: 0,
    };
    let w = wide(&dir.to_string_lossy());
    // SAFETY: `w` is NUL-terminated; `sa` and its descriptor live for the call.
    if unsafe { CreateDirectoryW(w.as_ptr(), &sa) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
