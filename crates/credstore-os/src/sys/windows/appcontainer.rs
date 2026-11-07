//! AppContainer sandbox for approved commands on Windows (M12).
//!
//! An AppContainer process can open only what is granted to its container SID (or to
//! "ALL APPLICATION PACKAGES", which covers System32 and Program Files), and has no
//! network unless the token carries a network capability. Loopback is always blocked.
//!
//! The daemon cannot add the needed process attribute through `std::process::Command`
//! on stable Rust, so it starts `credstore-sandbox.exe` (this module's [`launcher_main`])
//! the usual way: suspended, inside the run's Job Object, with the output pipes. The
//! launcher then creates the real command inside the AppContainer with
//! `CreateProcessW`; the command inherits the Job Object (so the tree is still killed as
//! one) and exactly the three standard handles.
//!
//! Every `unsafe` block states why it is sound.
#![allow(unsafe_code)]

use std::ffi::{c_void, OsString};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT};
use windows_sys::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W,
    GRANT_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{
    FreeSid, ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
    SUB_CONTAINERS_AND_OBJECTS_INHERIT,
};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, UpdateProcThreadAttribute, WaitForSingleObject,
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, INFINITE,
    PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTF_USESTDHANDLES, STARTUPINFOEXW,
};

use super::win::{self, LocalBox, OwnedHandle};

/// The one container every run uses. Its SID is derived from this name, so it is the
/// same on every machine, and `credstore grant` can name it without asking the daemon.
pub const CONTAINER_NAME: &str = "credstore.run";

/// SID string for "ALL APPLICATION PACKAGES" (SDDL alias `AC`).
const ALL_APP_PACKAGES: &str = "S-1-15-2-1";

/// Network capabilities given when the run may use the network: internetClient,
/// internetClientServer, privateNetworkClientServer.
const NETWORK_CAPABILITIES: [&str; 3] = ["S-1-15-3-1", "S-1-15-3-2", "S-1-15-3-3"];

/// `SE_GROUP_ENABLED` (in a windows-sys module credstore does not otherwise need).
const SE_GROUP_ENABLED: u32 = 4;

/// Exit code the launcher uses when it could not start the command.
pub const LAUNCH_FAILED: i32 = 0x7EC5;

/// Read, write, execute and delete, without changing permissions or owner ("Modify").
pub const MODIFY: u32 = 0x0013_01BF;
/// Read and execute.
pub const READ_EXECUTE: u32 = 0x0012_00A9;

const FILE_READ_DATA: u32 = 0x1;
const FILE_WRITE_DATA: u32 = 0x2;
const FILE_EXECUTE: u32 = 0x20;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_EXECUTE: u32 = 0x2000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_READ: u32 = 0x8000_0000;

/// Owned SID from an API that must be released with `FreeSid`.
struct FreeSidBox(PSID);

impl Drop for FreeSidBox {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the SID came from CreateAppContainerProfile or
            // DeriveAppContainerSidFromAppContainerName, which say to free it with FreeSid.
            unsafe { FreeSid(self.0) };
        }
    }
}

/// The container's SID (`S-1-15-2-...`). Registers the container profile for this
/// account if it is not registered yet; if that is not possible (no loaded profile),
/// the SID is derived from the name, which is all a launch needs.
pub fn container_sid() -> io::Result<String> {
    let name = win::wide(CONTAINER_NAME);
    let display = win::wide("credstore commands");
    let desc = win::wide("Approved commands run by credstore");
    let mut sid: PSID = std::ptr::null_mut();
    // SAFETY: all strings are NUL-terminated; no capabilities are passed; `sid`
    // receives a SID that FreeSidBox frees.
    let hr = unsafe {
        CreateAppContainerProfile(
            name.as_ptr(),
            display.as_ptr(),
            desc.as_ptr(),
            std::ptr::null(),
            0,
            &mut sid,
        )
    };
    if hr < 0 || sid.is_null() {
        sid = std::ptr::null_mut();
        // SAFETY: `name` is NUL-terminated; `sid` receives a SID freed by FreeSidBox.
        let hr = unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut sid) };
        if hr < 0 || sid.is_null() {
            return Err(io::Error::from_raw_os_error(hr));
        }
    }
    let sid = FreeSidBox(sid);
    // SAFETY: `sid.0` is a valid SID owned by `sid`.
    unsafe { win::sid_to_string(sid.0) }
}

/// The container's SID from its name alone, without registering anything (for
/// `credstore grant`, which runs as the human).
pub fn derived_sid() -> io::Result<String> {
    let name = win::wide(CONTAINER_NAME);
    let mut sid: PSID = std::ptr::null_mut();
    // SAFETY: `name` is NUL-terminated; `sid` receives a SID freed by FreeSidBox.
    let hr = unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut sid) };
    if hr < 0 || sid.is_null() {
        return Err(io::Error::from_raw_os_error(hr));
    }
    let sid = FreeSidBox(sid);
    // SAFETY: `sid.0` is a valid SID owned by `sid`.
    unsafe { win::sid_to_string(sid.0) }
}

fn wide_path(p: &Path) -> Vec<u16> {
    p.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Give `sid` `mask` on `dir` and (inherited) everything in it. For the run's own small
/// directories; a protected DACL stays protected.
pub fn allow_dir(dir: &Path, sid: &str, mask: u32, protected: bool) -> io::Result<()> {
    allow(
        dir,
        sid,
        mask,
        SUB_CONTAINERS_AND_OBJECTS_INHERIT,
        protected,
    )
}

/// Give `sid` `mask` on one file.
pub fn allow_file(file: &Path, sid: &str, mask: u32) -> io::Result<()> {
    allow(file, sid, mask, 0, false)
}

fn allow(target: &Path, sid: &str, mask: u32, inherit: u32, protected: bool) -> io::Result<()> {
    let path = wide_path(target);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `path` is NUL-terminated; `dacl` points into `sd`, which LocalBox frees.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    let _sd = LocalBox::from_raw(sd);
    let sid = win::string_to_sid(sid)?;
    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: mask,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: inherit,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid.ptr() as *mut u16,
        },
    };
    let mut new_dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: one valid entry whose SID outlives the call; `dacl` is valid (or null);
    // `new_dacl` receives a LocalAlloc'd ACL.
    let rc = unsafe { SetEntriesInAclW(1, &entry, dacl, &mut new_dacl) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    let new_dacl = LocalBox::from_raw(new_dacl as *mut c_void);
    let mut info = DACL_SECURITY_INFORMATION;
    if protected {
        info |= PROTECTED_DACL_SECURITY_INFORMATION;
    }
    // SAFETY: `path` is NUL-terminated and `new_dacl` is a valid ACL.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            info,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            new_dacl.ptr() as *const ACL,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    Ok(())
}

/// Whether the DACL of `path` lets the container (by its SID or as one of "ALL
/// APPLICATION PACKAGES") do everything in `need` (FILE_* bits).
pub fn container_allowed(path: &Path, sid: &str, need: u32) -> bool {
    match win::path_security_sddl(path) {
        Ok(sddl) => sddl_allows(&sddl, sid, need),
        Err(_) => false,
    }
}

/// Folder the command runs in: read and write.
pub fn can_work_in(dir: &Path, sid: &str) -> bool {
    container_allowed(dir, sid, FILE_READ_DATA | FILE_WRITE_DATA)
}

/// Program file: read and execute.
pub fn can_execute(program: &Path, sid: &str) -> bool {
    container_allowed(program, sid, FILE_READ_DATA | FILE_EXECUTE)
}

/// Rights an SDDL ACE gives, as file access bits (generic rights mapped).
fn ace_rights(text: &str) -> u32 {
    let raw = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).unwrap_or(0)
    } else {
        let mut m = 0;
        let mut i = 0;
        while i + 2 <= text.len() {
            m |= match &text[i..i + 2] {
                "FA" | "GA" => GENERIC_ALL,
                "FR" | "GR" => GENERIC_READ,
                "FW" | "GW" => GENERIC_WRITE,
                "FX" | "GX" => GENERIC_EXECUTE,
                _ => 0,
            };
            i += 2;
        }
        m
    };
    let mut m = raw & 0x0000_FFFF;
    if raw & GENERIC_ALL != 0 {
        m |= 0x1FF;
    }
    if raw & GENERIC_READ != 0 {
        m |= FILE_READ_DATA;
    }
    if raw & GENERIC_WRITE != 0 {
        m |= FILE_WRITE_DATA;
    }
    if raw & GENERIC_EXECUTE != 0 {
        m |= FILE_EXECUTE;
    }
    m
}

/// Allow ACEs in the DACL part of `sddl` that apply to the object itself (not
/// inherit-only) and name `sid` or ALL APPLICATION PACKAGES; true if together they give
/// every bit of `need` and no deny ACE for those SIDs takes any of it away.
pub(crate) fn sddl_allows(sddl: &str, sid: &str, need: u32) -> bool {
    let Some(start) = sddl.find("D:") else {
        return false;
    };
    let dacl = &sddl[start + 2..];
    let dacl = match dacl.find("S:") {
        Some(end) => &dacl[..end],
        None => dacl,
    };
    let (mut allowed, mut denied) = (0u32, 0u32);
    for ace in dacl.split('(').skip(1) {
        let ace = ace.trim_end_matches(')');
        let parts: Vec<&str> = ace.split(';').collect();
        if parts.len() < 6 {
            continue;
        }
        let (kind, flags, rights, who) = (parts[0], parts[1], parts[2], parts[5]);
        if flags.contains("IO") {
            continue;
        }
        let matches = who.eq_ignore_ascii_case(sid)
            || who == "AC"
            || who.eq_ignore_ascii_case(ALL_APP_PACKAGES);
        if !matches {
            continue;
        }
        match kind {
            "A" => allowed |= ace_rights(rights),
            "D" => denied |= ace_rights(rights),
            _ => {}
        }
    }
    allowed & !denied & need == need
}

// ---------------------------------------------------------------------------
// Launcher (credstore-sandbox.exe)
// ---------------------------------------------------------------------------

/// Quote one argument the way the C runtime (and Rust's `args`) splits it.
fn push_arg(out: &mut String, arg: &str) {
    if !out.is_empty() {
        out.push(' ');
    }
    if !arg.is_empty() && !arg.contains([' ', '\t', '\n', '\x0b', '"']) {
        out.push_str(arg);
        return;
    }
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
}

/// The command line for `program args... [raw tail]`.
pub(crate) fn command_line(program: &str, args: &[String], raw_tail: Option<&str>) -> String {
    // The program path cannot contain a quote, so plain quoting is exact.
    let mut line = format!("\"{program}\"");
    let mut rest = String::new();
    for a in args {
        push_arg(&mut rest, a);
    }
    if !rest.is_empty() {
        line.push(' ');
        line.push_str(&rest);
    }
    if let Some(tail) = raw_tail {
        line.push(' ');
        line.push_str(tail);
    }
    line
}

/// Arguments for the launcher: `--sid SID [--network] [--raw-tail TEXT] -- PROGRAM ARGS...`.
pub fn launcher_args(
    sid: &str,
    network: bool,
    raw_tail: Option<&str>,
    program: &Path,
    args: &[String],
) -> Vec<OsString> {
    let mut v: Vec<OsString> = vec!["--sid".into(), sid.into()];
    if network {
        v.push("--network".into());
    }
    if let Some(t) = raw_tail {
        v.push("--raw-tail".into());
        v.push(t.into());
    }
    v.push("--".into());
    v.push(program.as_os_str().to_owned());
    v.extend(args.iter().map(OsString::from));
    v
}

struct Parsed {
    sid: String,
    network: bool,
    raw_tail: Option<String>,
    program: String,
    args: Vec<String>,
}

fn parse(args: Vec<String>) -> Result<Parsed, String> {
    let mut it = args.into_iter();
    let (mut sid, mut network, mut raw_tail) = (None, false, None);
    loop {
        match it.next().as_deref() {
            Some("--sid") => sid = it.next(),
            Some("--network") => network = true,
            Some("--raw-tail") => raw_tail = it.next(),
            Some("--") => break,
            Some(other) => return Err(format!("unknown argument {other:?}")),
            None => return Err("missing -- PROGRAM".into()),
        }
    }
    let program = it.next().ok_or("missing PROGRAM")?;
    Ok(Parsed {
        sid: sid.ok_or("missing --sid")?,
        network,
        raw_tail,
        program,
        args: it.collect(),
    })
}

/// Attribute list for CreateProcessW, deleted on drop.
struct AttributeList(Vec<u8>);

impl AttributeList {
    fn new(count: u32) -> io::Result<Self> {
        let mut size = 0usize;
        // SAFETY: size query with a null list; fails with INSUFFICIENT_BUFFER by design.
        unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), count, 0, &mut size) };
        let mut buf = vec![0u8; size];
        // SAFETY: `buf` has the size the query returned.
        let ok = unsafe {
            InitializeProcThreadAttributeList(buf.as_mut_ptr() as *mut c_void, count, 0, &mut size)
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(buf))
    }

    fn ptr(&mut self) -> *mut c_void {
        self.0.as_mut_ptr() as *mut c_void
    }

    /// # Safety
    /// `value` must stay valid (and unmoved) until the list is dropped.
    unsafe fn set(&mut self, attribute: u32, value: *const c_void, size: usize) -> io::Result<()> {
        // SAFETY: the list is initialized; the caller keeps `value` alive.
        let ok = unsafe {
            UpdateProcThreadAttribute(
                self.ptr(),
                0,
                attribute as usize,
                value,
                size,
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: the list was initialized in `new` and is deleted once.
        unsafe { DeleteProcThreadAttributeList(self.ptr()) };
    }
}

fn launch(p: &Parsed) -> io::Result<i32> {
    let container = win::string_to_sid(&p.sid)?;
    let caps: Vec<LocalBox> = if p.network {
        NETWORK_CAPABILITIES
            .iter()
            .map(|s| win::string_to_sid(s))
            .collect::<io::Result<_>>()?
    } else {
        Vec::new()
    };
    let mut cap_attrs: Vec<SID_AND_ATTRIBUTES> = caps
        .iter()
        .map(|c| SID_AND_ATTRIBUTES {
            Sid: c.ptr(),
            Attributes: SE_GROUP_ENABLED,
        })
        .collect();
    let security = SECURITY_CAPABILITIES {
        AppContainerSid: container.ptr(),
        Capabilities: if cap_attrs.is_empty() {
            std::ptr::null_mut()
        } else {
            cap_attrs.as_mut_ptr()
        },
        CapabilityCount: cap_attrs.len() as u32,
        Reserved: 0,
    };

    // Pass on exactly our three standard handles (the daemon's pipes, or NUL).
    let mut handles: Vec<HANDLE> = Vec::new();
    let mut std_handles = [std::ptr::null_mut(); 3];
    for (i, which) in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE]
        .into_iter()
        .enumerate()
    {
        // SAFETY: plain query of this process's standard handle.
        let h = unsafe { GetStdHandle(which) };
        std_handles[i] = h;
        if !h.is_null() && h as isize != -1 && !handles.contains(&h) {
            // SAFETY: `h` is one of this process's open standard handles.
            unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) };
            handles.push(h);
        }
    }

    let mut attrs = AttributeList::new(2)?;
    // SAFETY: `security` (and the SIDs it points to) and `handles` live until after
    // CreateProcessW below, and `attrs` is dropped before them.
    unsafe {
        attrs.set(
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            &security as *const _ as *const c_void,
            std::mem::size_of::<SECURITY_CAPABILITIES>(),
        )?;
        if !handles.is_empty() {
            attrs.set(
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                handles.as_ptr() as *const c_void,
                handles.len() * std::mem::size_of::<HANDLE>(),
            )?;
        }
    }

    // SAFETY: STARTUPINFOEXW is plain data; zeroed is its documented initial state.
    let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = std_handles[0];
    si.StartupInfo.hStdOutput = std_handles[1];
    si.StartupInfo.hStdError = std_handles[2];
    si.lpAttributeList = attrs.ptr();

    let app = win::wide(&p.program);
    let mut line = win::wide(&command_line(&p.program, &p.args, p.raw_tail.as_deref()));
    // SAFETY: PROCESS_INFORMATION is plain data filled in by CreateProcessW.
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: `app` and `line` are NUL-terminated (`line` is mutable, as required);
    // a null environment and directory inherit ours; `si` and its attribute list are
    // valid; `pi` receives two handles we close below.
    let ok = unsafe {
        CreateProcessW(
            app.as_ptr(),
            line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            std::ptr::null(),
            std::ptr::null(),
            &si.StartupInfo,
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    drop(attrs);
    let process = OwnedHandle::from_raw(pi.hProcess);
    drop(OwnedHandle::from_raw(pi.hThread));
    // SAFETY: `process` is a valid process handle.
    unsafe { WaitForSingleObject(process.raw(), INFINITE) };
    let mut code = 0u32;
    // SAFETY: `process` is valid and has exited.
    if unsafe { GetExitCodeProcess(process.raw(), &mut code) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(code as i32)
}

/// `credstore-sandbox.exe`: run `PROGRAM ARGS...` in the AppContainer and exit with its
/// exit code. Errors go to stderr, which is the run's captured output.
pub fn launcher_main() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match parse(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("credstore-sandbox: {e}");
            return LAUNCH_FAILED;
        }
    };
    match launch(&parsed) {
        Ok(code) => code,
        Err(e) => {
            eprintln!(
                "credstore-sandbox: could not start {} in the AppContainer: {e}",
                parsed.program
            );
            LAUNCH_FAILED
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_arguments_like_the_c_runtime() {
        let line = command_line(
            r"C:\Windows\System32\cmd.exe",
            &[
                "plain".into(),
                "two words".into(),
                r#"say "hi""#.into(),
                r"C:\dir with space\".into(),
                String::new(),
            ],
            Some(r#""echo %X%""#),
        );
        assert_eq!(
            line,
            r#""C:\Windows\System32\cmd.exe" plain "two words" "say \"hi\"" "C:\dir with space\\" "" "echo %X%""#
        );
    }

    #[test]
    fn launcher_arguments_round_trip() {
        let args = launcher_args(
            "S-1-15-2-1",
            true,
            Some("\"x\""),
            Path::new(r"C:\a b\p.exe"),
            &["--flag".into()],
        );
        let p = parse(
            args.iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect(),
        )
        .unwrap();
        assert_eq!(p.sid, "S-1-15-2-1");
        assert!(p.network);
        assert_eq!(p.raw_tail.as_deref(), Some("\"x\""));
        assert_eq!(p.program, r"C:\a b\p.exe");
        assert_eq!(p.args, ["--flag"]);
        assert!(parse(vec!["--bogus".into()]).is_err());
    }

    #[test]
    fn reads_container_rights_from_sddl() {
        let me = "S-1-15-2-11-22";
        let rw = FILE_READ_DATA | FILE_WRITE_DATA;
        let rx = FILE_READ_DATA | FILE_EXECUTE;
        // System32-style: ALL APPLICATION PACKAGES read and execute, inherited.
        let sys = "O:S-1-5-80-1D:PAI(A;;FA;;;S-1-5-80-1)(A;ID;0x1200a9;;;AC)(A;ID;0x1200a9;;;BU)";
        assert!(sddl_allows(sys, me, rx));
        assert!(!sddl_allows(sys, me, rw));
        // A folder `credstore grant` opened up: Modify for the container, inheritable.
        let granted = format!("O:BAD:AI(A;OICI;0x1301bf;;;{me})(A;OICIID;FA;;;BA)");
        assert!(sddl_allows(&granted, me, rw));
        // Inherit-only does not apply to the folder itself.
        let io_only = format!("D:(A;OICIIO;FA;;;{me})");
        assert!(!sddl_allows(&io_only, me, rw));
        // Another container's grant does not count.
        assert!(!sddl_allows("D:(A;OICI;FA;;;S-1-15-2-99)", me, rw));
        // A deny wins.
        let denied = format!("D:(D;;FW;;;{me})(A;;FA;;;{me})");
        assert!(!sddl_allows(&denied, me, rw));
        assert!(sddl_allows(&denied, me, FILE_READ_DATA));
        // Generic rights.
        assert!(sddl_allows("D:(A;;GA;;;AC)", me, rw | rx));
        assert!(!sddl_allows("D:(A;;GR;;;AC)", me, rw));
    }
}
