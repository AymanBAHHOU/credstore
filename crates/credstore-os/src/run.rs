//! Running a command for the daemon (spec 6.4): cleared environment, optional sandbox,
//! secret on stdin, output caps, wall-clock timeout, and the whole process tree killed
//! on every exit path (process group on Unix, Job Object on Windows).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use credstore_proto::SecretText;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use zeroize::Zeroizing;

use crate::sandbox::{SandboxPlan, SandboxSpec};
use crate::sys::current::{proc, sandbox};
use crate::OsResult;

/// How long to wait for output pipes to close after the process tree was killed.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

pub struct Launch {
    /// Resolved program. This exact file runs.
    pub program: PathBuf,
    pub args: Vec<String>,
    /// Windows only: text appended to the command line as is (the `cmd /c` string).
    pub raw_tail: Option<String>,
    pub cwd: PathBuf,
    /// The complete environment. Nothing is inherited.
    pub env: Vec<(String, SecretText)>,
    pub stdin: Option<SecretText>,
    pub timeout: Duration,
    /// Cap for stdout and for stderr, each.
    pub max_output: usize,
    pub sandbox: Option<(SandboxPlan, SandboxSpec)>,
}

impl std::fmt::Debug for Launch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Launch")
            .field("program", &self.program)
            .field("cwd", &self.cwd)
            .field(
                "env_names",
                &self.env.iter().map(|(k, _)| k).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct Outcome {
    /// `None` when killed by a signal (Unix).
    pub exit_code: Option<i32>,
    pub stdout: Zeroizing<Vec<u8>>,
    pub stderr: Zeroizing<Vec<u8>>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub timed_out: bool,
    /// Killed because output went over the cap.
    pub output_limit_hit: bool,
    pub duration: Duration,
}

/// The program and arguments for a shell string: `/bin/sh -c` on Unix, `cmd /d /s /c`
/// on Windows (where the string is passed verbatim).
pub fn shell_command(script: &str) -> (PathBuf, Vec<String>, Option<String>) {
    proc::shell_command(script)
}

/// Minimal safe environment (spec 6.4). `home` is the HOME/USERPROFILE to give the
/// child; `tmp` its private temp directory.
pub fn base_env(home: &Path, tmp: &Path, path: &OsString) -> Vec<(String, String)> {
    proc::base_env(home, tmp, path)
}

/// The current user's home directory (`HOME`, or `USERPROFILE` on Windows).
pub fn user_home() -> Option<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Name of the variable that carries a file-injected secret's path.
pub fn file_env_name(secret: &str) -> String {
    format!("{secret}_FILE")
}

/// Whether two environment variable names are the same variable (case-insensitive on
/// Windows).
pub fn same_env_name(a: &str, b: &str) -> bool {
    if cfg!(windows) {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

struct Capture {
    buf: Zeroizing<Vec<u8>>,
    truncated: bool,
}

async fn read_capped<R: AsyncRead + Unpin>(
    mut r: R,
    cap: usize,
    into: Arc<Mutex<Capture>>,
    over: Arc<Notify>,
) {
    let mut chunk = Zeroizing::new(vec![0u8; 16 * 1024]);
    loop {
        let n = match r.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        let mut c = into.lock().unwrap_or_else(|p| p.into_inner());
        let room = cap.saturating_sub(c.buf.len());
        let take = n.min(room);
        c.buf.extend_from_slice(&chunk[..take]);
        if take < n {
            c.truncated = true;
            drop(c);
            over.notify_one();
            return;
        }
    }
}

fn take(c: &Arc<Mutex<Capture>>) -> (Zeroizing<Vec<u8>>, bool) {
    let mut g = c.lock().unwrap_or_else(|p| p.into_inner());
    (std::mem::take(&mut g.buf), g.truncated)
}

/// Run `launch` to completion (or timeout / output cap), then kill whatever is left of
/// its process tree.
pub async fn run(launch: Launch) -> OsResult<Outcome> {
    let started = Instant::now();
    let (program, args) = match &launch.sandbox {
        Some((plan, spec)) => sandbox::wrap(plan, spec, &launch)?,
        None => (
            launch.program.clone().into_os_string(),
            launch.args.iter().map(OsString::from).collect(),
        ),
    };
    let mut cmd = tokio::process::Command::new(&program);
    cmd.args(&args)
        .current_dir(&launch.cwd)
        .env_clear()
        .stdin(if launch.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for (k, v) in &launch.env {
        cmd.env(k, v.expose());
    }
    proc::configure(&mut cmd, &launch)?;

    let mut child = cmd.spawn()?;
    let tree = match proc::Tree::attach(&mut child) {
        Ok(t) => t,
        Err(e) => {
            let _ = child.start_kill();
            return Err(e);
        }
    };

    if let (Some(value), Some(mut pipe)) = (launch.stdin.clone(), child.stdin.take()) {
        tokio::spawn(async move {
            let _ = pipe.write_all(value.expose().as_bytes()).await;
            let _ = pipe.shutdown().await;
        });
    }

    let over = Arc::new(Notify::new());
    let new_capture = || {
        Arc::new(Mutex::new(Capture {
            buf: Zeroizing::new(Vec::new()),
            truncated: false,
        }))
    };
    let (out, err) = (new_capture(), new_capture());
    let mut readers = Vec::new();
    if let Some(p) = child.stdout.take() {
        readers.push(tokio::spawn(read_capped(
            p,
            launch.max_output,
            out.clone(),
            over.clone(),
        )));
    }
    if let Some(p) = child.stderr.take() {
        readers.push(tokio::spawn(read_capped(
            p,
            launch.max_output,
            err.clone(),
            over.clone(),
        )));
    }

    let mut timed_out = false;
    let mut output_limit_hit = false;
    let status = tokio::select! {
        s = child.wait() => s.ok(),
        _ = tokio::time::sleep(launch.timeout) => { timed_out = true; None }
        _ = over.notified() => { output_limit_hit = true; None }
    };
    // Always: kills the timed-out or flooding process, and anything it left running.
    tree.kill();
    let status = match status {
        Some(s) => Some(s),
        None => child.wait().await.ok(),
    };
    for r in readers {
        let abort = r.abort_handle();
        if tokio::time::timeout(DRAIN_GRACE, r).await.is_err() {
            abort.abort();
        }
    }

    let (stdout, stdout_truncated) = take(&out);
    let (stderr, stderr_truncated) = take(&err);
    Ok(Outcome {
        exit_code: if timed_out || output_limit_hit {
            None
        } else {
            status.and_then(|s| s.code())
        },
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        timed_out,
        output_limit_hit,
        duration: started.elapsed(),
    })
}
