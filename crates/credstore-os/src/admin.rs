//! Changes only an administrator may make. On Windows installs the policy file is
//! Administrators' and the service may only read it, so a daemon that was taken over
//! cannot widen its own rules (on Linux and macOS root owns it, spec 5.4). The app runs
//! `credstore policy-apply` elevated to write a change; Windows asks the user first.

use std::path::Path;

use crate::{OsError, OsResult};

/// How an elevated run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Elevated {
    /// It ran; its exit code.
    Exited(u32),
    /// The user said no to the admin prompt.
    Declined,
}

/// Run `exe args...` as administrator, hidden, and wait for it (Windows: UAC asks).
pub fn run_elevated(exe: &Path, args: &[String]) -> OsResult<Elevated> {
    #[cfg(windows)]
    {
        let params: Vec<String> = args.iter().map(|a| quote(a)).collect();
        match crate::sys::current::admin::run_elevated(exe, &params.join(" "))? {
            Some(code) => Ok(Elevated::Exited(code)),
            None => Ok(Elevated::Declined),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (exe, args);
        Err(OsError::unavailable(
            "on this system, edit the policy file with sudo",
        ))
    }
}

/// Atomically replace `path` with `data`, as a file the service may read but not change.
/// Needs administrator rights (Windows installs only).
pub fn write_admin_file(path: &Path, data: &[u8]) -> OsResult<()> {
    #[cfg(windows)]
    {
        use std::io::Write;
        let reader = crate::sys::current::win::lookup_account_sid(crate::SERVICE_USER)
            .map_err(|e| OsError::unavailable(format!("{}: {e}", crate::SERVICE_USER)))?;
        let dir = path
            .parent()
            .ok_or_else(|| OsError::unavailable("the policy file has no folder"))?;
        let name = path
            .file_name()
            .ok_or_else(|| OsError::unavailable("the policy file has no name"))?
            .to_string_lossy();
        let tmp = dir.join(format!(".{name}.admin-{}", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let result = (|| -> std::io::Result<()> {
            let mut f = crate::sys::current::admin::create_admin_file(&tmp, &reader)?;
            f.write_all(data)?;
            f.sync_all()?;
            drop(f);
            // A rename on the same volume keeps the file's own DACL.
            std::fs::rename(&tmp, path)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result.map_err(OsError::from)
    }
    #[cfg(not(windows))]
    {
        let _ = (path, data);
        Err(OsError::unavailable(
            "on this system, edit the policy file with sudo",
        ))
    }
}

/// One command-line argument as `CommandLineToArgvW` reads it back.
#[cfg_attr(not(windows), allow(dead_code))]
fn quote(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_owned();
    }
    let mut out = String::from('"');
    let mut slashes = 0;
    for c in arg.chars() {
        match c {
            '\\' => slashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(slashes * 2 + 1));
                out.push('"');
                slashes = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(slashes));
                out.push(c);
                slashes = 0;
            }
        }
    }
    out.push_str(&"\\".repeat(slashes * 2));
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::quote;

    #[test]
    fn arguments_are_quoted_for_windows() {
        assert_eq!(quote("policy-apply"), "policy-apply");
        assert_eq!(
            quote(r"C:\Users\me\AppData\Local\Temp\x.txt"),
            r"C:\Users\me\AppData\Local\Temp\x.txt"
        );
        assert_eq!(quote(r"C:\Program Files\x\"), r#""C:\Program Files\x\\""#);
        assert_eq!(quote(r#"a "b""#), r#""a \"b\"""#);
        assert_eq!(quote(""), r#""""#);
    }
}
