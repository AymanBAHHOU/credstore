//! Child processes on Unix: a new session (no controlling terminal, its own process
//! group, so the whole tree can be killed with one `killpg`), plus Landlock on Linux.
#![allow(unsafe_code)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use nix::sys::signal::{killpg, Signal};
use nix::unistd::Pid;

use crate::run::Launch;
use crate::OsResult;

pub fn shell_command(script: &str) -> (PathBuf, Vec<String>, Option<String>) {
    (
        PathBuf::from("/bin/sh"),
        vec!["-c".into(), script.into()],
        None,
    )
}

pub fn base_env(home: &Path, tmp: &Path, path: &OsString) -> Vec<(String, String)> {
    let lang = std::env::var("LANG")
        .ok()
        .filter(|l| !l.is_empty())
        .unwrap_or_else(|| "C.UTF-8".into());
    vec![
        ("PATH".into(), path.to_string_lossy().into_owned()),
        ("HOME".into(), home.to_string_lossy().into_owned()),
        ("TMPDIR".into(), tmp.to_string_lossy().into_owned()),
        ("LANG".into(), lang),
    ]
}

/// Set up the child to start in a new session and, on Linux with a Landlock plan, to
/// restrict itself before `exec`.
pub fn configure(cmd: &mut tokio::process::Command, launch: &Launch) -> OsResult<()> {
    #[cfg(target_os = "linux")]
    let mut ruleset = super::sandbox::landlock_ruleset(launch)?;
    #[cfg(not(target_os = "linux"))]
    let _ = launch;

    // SAFETY: the closure runs in the forked child before exec. It only makes
    // async-signal-safe calls (setsid, prctl, landlock_restrict_self) and does not
    // allocate: the ruleset was built, and its file descriptors opened, before fork.
    unsafe {
        cmd.pre_exec(move || {
            nix::unistd::setsid().map_err(std::io::Error::from)?;
            #[cfg(target_os = "linux")]
            if let Some(rs) = ruleset.take() {
                super::sandbox::restrict(rs)?;
            }
            Ok(())
        });
    }
    Ok(())
}

/// The child's process group (its PID, since it leads a new session).
pub struct Tree {
    pgid: Pid,
}

impl Tree {
    pub fn attach(child: &mut tokio::process::Child) -> OsResult<Self> {
        let pid = child
            .id()
            .ok_or_else(|| std::io::Error::other("child exited before it could be tracked"))?;
        Ok(Self {
            pgid: Pid::from_raw(pid as i32),
        })
    }

    /// Kill every process left in the group.
    pub fn kill(&self) {
        let _ = killpg(self.pgid, Signal::SIGKILL);
    }
}
