//! Child processes on Windows: started suspended, put in a Job Object, then resumed.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use windows_sys::Win32::System::Threading::{CREATE_NO_WINDOW, CREATE_SUSPENDED};

use super::job::{resume_threads, Job};
use crate::run::Launch;
use crate::OsResult;

fn system_root() -> PathBuf {
    std::env::var_os("SystemRoot")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
}

/// `cmd.exe /d /s /c "<script>"`: `/d` skips AutoRun, `/s` strips exactly the outer
/// quotes, so the script reaches cmd as written.
pub fn shell_command(script: &str) -> (PathBuf, Vec<String>, Option<String>) {
    (
        system_root().join("System32").join("cmd.exe"),
        vec!["/d".into(), "/s".into(), "/c".into()],
        Some(format!("\"{script}\"")),
    )
}

/// Spec 6.4: Windows programs need `SystemRoot`, `ComSpec`, `TEMP`, `TMP` and `PATHEXT`
/// to start. The standard system-defined variables (folders, machine and user names) are
/// passed too: they hold no secrets, and tools depend on them. Without `LOCALAPPDATA`,
/// for example, Windows PowerShell cannot find its module cache and rescans every
/// installed module on each start, which can take minutes. Nothing user-defined is
/// passed.
pub fn base_env(home: &Path, tmp: &Path, path: &OsString) -> Vec<(String, String)> {
    let mut v = vec![
        ("PATH".to_string(), path.to_string_lossy().into_owned()),
        ("TEMP".to_string(), tmp.to_string_lossy().into_owned()),
        ("TMP".to_string(), tmp.to_string_lossy().into_owned()),
        (
            "USERPROFILE".to_string(),
            home.to_string_lossy().into_owned(),
        ),
    ];
    for name in [
        "SystemRoot",
        "SystemDrive",
        "windir",
        "ComSpec",
        "PATHEXT",
        "OS",
        "PROCESSOR_ARCHITECTURE",
        "PROCESSOR_IDENTIFIER",
        "PROCESSOR_LEVEL",
        "PROCESSOR_REVISION",
        "NUMBER_OF_PROCESSORS",
        "APPDATA",
        "LOCALAPPDATA",
        "ProgramData",
        "ALLUSERSPROFILE",
        "PUBLIC",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramW6432",
        "CommonProgramFiles",
        "CommonProgramFiles(x86)",
        "CommonProgramW6432",
        "PSModulePath",
        "USERNAME",
        "USERDOMAIN",
        "COMPUTERNAME",
        "HOMEDRIVE",
        "HOMEPATH",
    ] {
        if let Ok(value) = std::env::var(name) {
            v.push((name.to_string(), value));
        }
    }
    if !v.iter().any(|(k, _)| k == "SystemRoot") {
        v.push((
            "SystemRoot".into(),
            system_root().to_string_lossy().into_owned(),
        ));
    }
    v
}

pub fn configure(cmd: &mut tokio::process::Command, launch: &Launch) -> OsResult<()> {
    cmd.creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW);
    if let Some(raw) = &launch.raw_tail {
        cmd.raw_arg(raw);
    }
    Ok(())
}

/// The run's Job Object. Dropping it kills anything still in it.
pub struct Tree {
    job: Job,
}

impl Tree {
    pub fn attach(child: &mut tokio::process::Child) -> OsResult<Self> {
        let job = Job::new()?;
        let handle = child
            .raw_handle()
            .ok_or_else(|| std::io::Error::other("child has no process handle"))?;
        job.assign(handle as _)?;
        let pid = child
            .id()
            .ok_or_else(|| std::io::Error::other("child has no pid"))?;
        resume_threads(pid)?;
        Ok(Self { job })
    }

    pub fn kill(&self) {
        self.job.terminate();
    }
}
