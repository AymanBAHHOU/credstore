//! Thin wrappers over the Win32 calls credstore needs that the safe crates do not cover:
//! SIDs and tokens, named-pipe security descriptors and client identity, and the
//! daemon's process DACL. Every `unsafe` block states why it is sound. Handles and
//! `LocalAlloc`ed buffers are owned by RAII guards so error paths cannot leak them.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::core::{BOOL, PWSTR};
use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_INSUFFICIENT_BUFFER, HANDLE, HLOCAL,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, GetSecurityInfo, SetSecurityInfo, SDDL_REVISION_1, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    CheckTokenMembership, GetSecurityDescriptorDacl, GetTokenInformation, LookupAccountNameW,
    RevertToSelf, TokenUser, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    SID_NAME_USE, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    SetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX,
};
use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, ImpersonateNamedPipeClient};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken,
    QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// Owned kernel handle, closed on drop.
pub struct OwnedHandle(HANDLE);

impl OwnedHandle {
    /// Take ownership of a valid handle.
    pub fn from_raw(h: HANDLE) -> Self {
        Self(h)
    }

    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: we own this handle and close it exactly once.
        unsafe { CloseHandle(self.0) };
    }
}

/// Memory returned by a Win32 API that must be released with `LocalFree`.
pub struct LocalBox(*mut c_void);

impl LocalBox {
    pub fn ptr(&self) -> *mut c_void {
        self.0
    }
}

impl Drop for LocalBox {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from a LocalAlloc-ing API and is freed once.
            unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }
}

fn check(ok: BOOL) -> io::Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// NUL-terminated UTF-16.
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Read a NUL-terminated UTF-16 string.
///
/// # Safety
/// `p` must point to a valid NUL-terminated UTF-16 string.
unsafe fn from_wide(p: PWSTR) -> String {
    let mut len = 0;
    // SAFETY: caller guarantees a terminating NUL within the allocation.
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` elements were just read from this valid allocation.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
}

/// String form (`S-1-5-...`) of a SID.
///
/// # Safety
/// `sid` must point to a valid SID.
unsafe fn sid_to_string(sid: PSID) -> io::Result<String> {
    let mut out: PWSTR = std::ptr::null_mut();
    // SAFETY: `sid` is valid (caller); `out` receives a LocalAlloc'd string.
    check(unsafe { ConvertSidToStringSidW(sid, &mut out) })?;
    let guard = LocalBox(out as *mut c_void);
    // SAFETY: ConvertSidToStringSidW returns a NUL-terminated string.
    let s = unsafe { from_wide(out) };
    drop(guard);
    Ok(s)
}

/// User SID of a token.
fn token_user_sid(token: HANDLE) -> io::Result<String> {
    let mut len = 0u32;
    // SAFETY: size query with a null buffer; expected to fail with INSUFFICIENT_BUFFER.
    let ok = unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len) };
    if ok == 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
            return Err(e);
        }
    }
    // u64 storage keeps TOKEN_USER (which holds a pointer) correctly aligned.
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` is at least `len` bytes and suitably aligned.
    check(unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr() as *mut c_void,
            len,
            &mut len,
        )
    })?;
    // SAFETY: the call filled `buf` with a TOKEN_USER whose SID points inside `buf`.
    unsafe {
        let tu = &*(buf.as_ptr() as *const TOKEN_USER);
        sid_to_string(tu.User.Sid)
    }
}

/// SID of the user running this process.
pub fn current_user_sid() -> io::Result<String> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess is a pseudo handle; `token` receives a new handle.
    check(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) })?;
    let token = OwnedHandle(token);
    token_user_sid(token.raw())
}

/// SID string of an account or group name (for example `credstore-agents` or
/// `NT SERVICE\credstore`).
pub fn lookup_account_sid(name: &str) -> io::Result<String> {
    let wname = wide(name);
    let mut sid_len = 0u32;
    let mut dom_len = 0u32;
    let mut use_: SID_NAME_USE = 0;
    // SAFETY: size query with null buffers.
    unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            wname.as_ptr(),
            std::ptr::null_mut(),
            &mut sid_len,
            std::ptr::null_mut(),
            &mut dom_len,
            &mut use_,
        )
    };
    if sid_len == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut sid = vec![0u32; (sid_len as usize).div_ceil(4)];
    let mut dom = vec![0u16; dom_len as usize + 1];
    // SAFETY: buffers are the sizes the first call asked for.
    check(unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            wname.as_ptr(),
            sid.as_mut_ptr() as PSID,
            &mut sid_len,
            dom.as_mut_ptr(),
            &mut dom_len,
            &mut use_,
        )
    })?;
    // SAFETY: `sid` now holds a valid SID.
    unsafe { sid_to_string(sid.as_mut_ptr() as PSID) }
}

/// Binary SID from its string form.
fn string_to_sid(s: &str) -> io::Result<LocalBox> {
    let ws = wide(s);
    let mut sid: PSID = std::ptr::null_mut();
    // SAFETY: `ws` is NUL-terminated; `sid` receives a LocalAlloc'd SID.
    check(unsafe { ConvertStringSidToSidW(ws.as_ptr(), &mut sid) })?;
    Ok(LocalBox(sid))
}

/// Security descriptor parsed from SDDL.
pub struct SecurityDescriptor(LocalBox);

impl SecurityDescriptor {
    pub fn from_sddl(sddl: &str) -> io::Result<Self> {
        let w = wide(sddl);
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `w` is NUL-terminated; `sd` receives a LocalAlloc'd descriptor.
        check(unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                w.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        })?;
        Ok(Self(LocalBox(sd)))
    }

    pub(crate) fn ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0.ptr()
    }
}

/// Create a named-pipe server instance protected by `sddl`, refusing remote clients.
pub fn create_pipe_server(name: &str, sddl: &str, first: bool) -> io::Result<NamedPipeServer> {
    let sd = SecurityDescriptor::from_sddl(sddl)?;
    let mut sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.ptr(),
        bInheritHandle: 0,
    };
    let mut opts = ServerOptions::new();
    opts.first_pipe_instance(first).reject_remote_clients(true);
    // SAFETY: `sa` and the descriptor it points to are valid for the whole call.
    unsafe { opts.create_with_security_attributes_raw(name, &mut sa as *mut _ as *mut c_void) }
}

/// Identity of the client on a server pipe handle, read by briefly impersonating it.
/// Returns the client's user SID and whether its token is a member of `group_sid`.
/// The client must already have written to the pipe (Windows takes the identity from the
/// last message read).
pub fn pipe_client_identity(pipe: HANDLE, group_sid: Option<&str>) -> io::Result<(String, bool)> {
    // SAFETY: `pipe` is a valid server pipe handle owned by the caller.
    check(unsafe { ImpersonateNamedPipeClient(pipe) })?;
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: query the impersonation token of this thread; OpenAsSelf so the check uses
    // the process's own security context.
    let opened = check(unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) });
    // SAFETY: always revert. Continuing to run as the client would be a privilege bug, so
    // a failed revert aborts the process.
    if unsafe { RevertToSelf() } == 0 {
        std::process::abort();
    }
    opened?;
    let token = OwnedHandle(token);
    let sid = token_user_sid(token.raw())?;
    let member = match group_sid {
        None => false,
        Some(g) => {
            let gsid = string_to_sid(g)?;
            let mut is_member: BOOL = 0;
            // SAFETY: `token` is an impersonation token; `gsid` is a valid SID.
            check(unsafe { CheckTokenMembership(token.raw(), gsid.ptr(), &mut is_member) })?;
            is_member != 0
        }
    };
    Ok((sid, member))
}

/// PID of the client on a server pipe handle (informational).
pub fn pipe_client_pid(pipe: HANDLE) -> io::Result<u32> {
    let mut pid = 0u32;
    // SAFETY: `pipe` is a valid server pipe handle.
    check(unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) })?;
    Ok(pid)
}

/// Owner SID of a kernel object handle (used to verify who created a pipe).
pub fn handle_owner_sid(handle: HANDLE) -> io::Result<String> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: valid handle; `sd` receives a LocalAlloc'd descriptor that `owner` points into.
    let rc = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    let _guard = LocalBox(sd);
    // SAFETY: `owner` points into `sd`, which is alive until `_guard` drops.
    unsafe { sid_to_string(owner) }
}

/// Executable path of a process, best effort (informational only).
pub fn exe_of_pid(pid: u32) -> Option<String> {
    // SAFETY: plain call; a null result means failure.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return None;
    }
    let h = OwnedHandle(h);
    let mut buf = vec![0u16; 1024];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` holds `len` u16s.
    let ok = unsafe { QueryFullProcessImageNameW(h.raw(), 0, buf.as_mut_ptr(), &mut len) };
    (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
}

/// Replace this process's DACL so other processes, including other processes of the
/// same user, can only query basic information, wait on it and terminate it: no memory
/// read/write, no handle duplication, no DACL change. `OW` (Owner Rights) overrides the
/// owner's implicit READ_CONTROL / WRITE_DAC. Accounts with SeDebugPrivilege bypass this.
/// Terminate is allowed so the user can always stop a dev daemon; it is not a
/// confidentiality risk.
pub fn protect_current_process() -> io::Result<()> {
    // SYSTEM: full. Owner rights and this account: PROCESS_QUERY_(LIMITED_)INFORMATION |
    // SYNCHRONIZE | PROCESS_TERMINATE. The explicit user ACE covers sessions where the
    // process owner is another SID (for example Administrators when elevated).
    let me = current_user_sid()?;
    let sd = SecurityDescriptor::from_sddl(&format!(
        "D:P(A;;GA;;;SY)(A;;0x101401;;;OW)(A;;0x101401;;;{me})"
    ))?;
    let mut present: BOOL = 0;
    let mut defaulted: BOOL = 0;
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: `sd` is a valid descriptor; `dacl` points into it.
    check(unsafe { GetSecurityDescriptorDacl(sd.ptr(), &mut present, &mut dacl, &mut defaulted) })?;
    // SAFETY: pseudo handle for this process; `dacl` stays valid while `sd` lives.
    let rc = unsafe {
        SetSecurityInfo(
            GetCurrentProcess(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    Ok(())
}

/// No crash dialogs (and so no interactive WER prompt) for this process.
pub fn disable_error_dialogs() {
    // SAFETY: plain flag-setting call.
    unsafe { SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX) };
}
