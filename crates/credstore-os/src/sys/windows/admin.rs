//! Administrator-only steps: start a program elevated (Windows asks the user with UAC)
//! and create a file the service may read but not change (the policy file).
#![allow(unsafe_code)]

use std::fs::File;
use std::io;
use std::os::windows::io::FromRawHandle;
use std::path::Path;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_CANCELLED, GENERIC_WRITE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL};
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
use windows_sys::Win32::UI::Shell::{
    ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

use super::win::{wide, SecurityDescriptor};

/// Start `exe` with `params` as administrator, hidden, and wait for it. `Ok(None)` when
/// the user declined the UAC prompt.
pub fn run_elevated(exe: &Path, params: &str) -> io::Result<Option<u32>> {
    let verb = wide("runas");
    let file = wide(&exe.to_string_lossy());
    let params = wide(params);
    // SAFETY: SHELLEXECUTEINFOW is a plain C struct; all-zero is its documented empty
    // state, and the fields used are set below.
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = params.as_ptr();
    info.nShow = SW_HIDE;
    // SAFETY: `info` is initialized and its strings are NUL-terminated and outlive the
    // call.
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(ERROR_CANCELLED as i32) {
            return Ok(None);
        }
        return Err(e);
    }
    let process = info.hProcess;
    if process.is_null() {
        return Err(io::Error::other("Windows started no process"));
    }
    let mut code = 0u32;
    // SAFETY: `process` is the handle SEE_MASK_NOCLOSEPROCESS returned; it is closed once,
    // below.
    let ok = unsafe {
        WaitForSingleObject(process, INFINITE);
        let ok = GetExitCodeProcess(process, &mut code);
        CloseHandle(process);
        ok
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Some(code))
}

/// Create `path` (which must not exist) with a protected DACL: SYSTEM and Administrators
/// full control, `reader_sid` read only. Nothing is inherited from the directory, so the
/// file never has a moment with the directory's broader access.
pub fn create_admin_file(path: &Path, reader_sid: &str) -> io::Result<File> {
    let sd = SecurityDescriptor::from_sddl(&format!(
        "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;{reader_sid})"
    ))?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.ptr(),
        bInheritHandle: 0,
    };
    let w = wide(&path.to_string_lossy());
    // SAFETY: `w` is NUL-terminated; `sa` and its descriptor live for the call.
    let h = unsafe {
        CreateFileW(
            w.as_ptr(),
            GENERIC_WRITE,
            0,
            &sa,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `h` is a new, valid file handle that nothing else owns.
    Ok(unsafe { File::from_raw_handle(h) })
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::sys::current::win;

    #[test]
    fn admin_files_are_read_only_for_the_reader_and_inherit_nothing() {
        let dir = std::env::temp_dir().join(format!("cs-admin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("policy.toml");
        let reader = win::current_user_sid().unwrap();
        let mut f = create_admin_file(&path, &reader).unwrap();
        f.write_all(b"[defaults]\n").unwrap();
        drop(f);
        let sddl = win::path_security_sddl(&path).unwrap();
        assert!(sddl.contains("D:P"), "protected DACL: {sddl}");
        assert!(sddl.contains(&format!(";FR;;;{reader})")), "{sddl}");
        assert!(!sddl.contains(&format!(";FA;;;{reader})")), "{sddl}");
        // The reader cannot write it.
        assert!(std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .is_err());
        // It already exists: never reused.
        assert!(create_admin_file(&path, &reader).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
