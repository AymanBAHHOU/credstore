//! Windows sandbox (M12): an AppContainer inside a Job Object.
//!
//! The Job Object kills the process tree and caps processes and memory. The AppContainer
//! hides everything not granted to the `credstore.run` container (the vault, policy,
//! audit log, other users' and the human's files) and has no network unless the run may
//! use it. A run gets the AppContainer when the container can work in its folder and
//! execute its program; otherwise it falls back to the Job Object alone, with the reason
//! on the approval screen (or is denied, with `sandbox = "require"`).
//!
//! `CREDSTORE_FORCE_SANDBOX=job-object` or `=none` force the weaker modes (tests).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use credstore_proto::{NetworkPolicy, SandboxMode};

use super::appcontainer::{self, MODIFY, READ_EXECUTE};
use super::job::Job;
use crate::run::Launch;
use crate::sandbox::{SandboxCapabilities, SandboxNeed, SandboxPlan, SandboxSpec};
use crate::OsResult;

const LAUNCHER: &str = "credstore-sandbox.exe";

/// The launcher and the container SID, if the AppContainer can be used.
struct Container {
    launcher: PathBuf,
    sid: String,
}

fn container() -> &'static Result<Container, String> {
    static C: OnceLock<Result<Container, String>> = OnceLock::new();
    C.get_or_init(|| {
        let launcher = find_launcher()
            .ok_or_else(|| format!("{LAUNCHER} was not found next to the daemon"))?;
        let sid = appcontainer::container_sid()
            .map_err(|e| format!("cannot get the AppContainer SID: {e}"))?;
        Ok(Container { launcher, sid })
    })
}

/// Next to this executable, or one folder up (test binaries live in `target/*/deps`).
fn find_launcher() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    [dir.join(LAUNCHER), dir.parent()?.join(LAUNCHER)]
        .into_iter()
        .find(|p| p.is_file())
}

/// The container's SID, if this machine can use it.
pub fn container_sid() -> Option<&'static str> {
    container().as_ref().ok().map(|c| c.sid.as_str())
}

fn job_caps(detail: String) -> SandboxCapabilities {
    SandboxCapabilities {
        mode: SandboxMode::JobObject,
        network_restriction: false,
        hides_paths: false,
        detail,
    }
}

pub fn probe() -> SandboxCapabilities {
    let forced = std::env::var("CREDSTORE_FORCE_SANDBOX").ok();
    if forced.as_deref() == Some("none") {
        return SandboxCapabilities {
            mode: SandboxMode::None,
            network_restriction: false,
            hides_paths: false,
            detail: "CREDSTORE_FORCE_SANDBOX=none".into(),
        };
    }
    if let Err(e) = Job::new() {
        return SandboxCapabilities {
            mode: SandboxMode::None,
            network_restriction: false,
            hides_paths: false,
            detail: format!("cannot create a Job Object: {e}"),
        };
    }
    if forced.as_deref() == Some("job-object") {
        return job_caps("Job Object only (CREDSTORE_FORCE_SANDBOX=job-object)".into());
    }
    match container() {
        Ok(c) => SandboxCapabilities {
            mode: SandboxMode::AppContainer,
            network_restriction: true,
            hides_paths: true,
            detail: format!(
                "AppContainer {} ({}) inside a Job Object: only granted folders, no \
                 network unless allowed",
                appcontainer::CONTAINER_NAME,
                c.sid
            ),
        },
        Err(why) => job_caps(format!(
            "Job Object only (kills the process tree; process and memory limits); no \
             AppContainer: {why}"
        )),
    }
}

/// The AppContainer if the run's folder and program allow it, else the Job Object with
/// the reason as a gap.
pub fn plan_for_run(
    caps: &SandboxCapabilities,
    need: SandboxNeed,
    network: NetworkPolicy,
    cwd: &Path,
    program: Option<&Path>,
) -> Result<SandboxPlan, String> {
    let plan = crate::sandbox::plan(caps, need, network)?;
    if plan.mode != SandboxMode::AppContainer {
        return Ok(plan);
    }
    let Ok(c) = container() else {
        return Ok(plan);
    };
    let why = if !appcontainer::can_work_in(cwd, &c.sid) {
        Some(format!(
            "the AppContainer cannot use {} (its owner can run `credstore grant \"{}\"`)",
            cwd.display(),
            cwd.display()
        ))
    } else {
        program
            .filter(|p| !appcontainer::can_execute(p, &c.sid))
            .map(|p| {
                format!(
                    "{} cannot run inside the AppContainer (it can run programs under \
                     Windows and Program Files, not per-user installs)",
                    p.display()
                )
            })
    };
    let Some(why) = why else {
        return Ok(plan);
    };
    if need == SandboxNeed::Require {
        return Err(why);
    }
    let mut fallback = crate::sandbox::plan(&job_caps(caps.detail.clone()), need, network)?;
    fallback.gaps.insert(0, format!("Job Object only: {why}"));
    Ok(fallback)
}

/// The program to start: the command itself (Job Object), or the launcher that starts
/// it in the AppContainer. The run's temp and secret-file folders are granted to the
/// container first.
pub fn wrap(
    plan: &SandboxPlan,
    spec: &SandboxSpec,
    launch: &Launch,
) -> OsResult<(OsString, Vec<OsString>)> {
    if plan.mode != SandboxMode::AppContainer {
        return Ok((
            launch.program.clone().into_os_string(),
            launch.args.iter().map(OsString::from).collect(),
        ));
    }
    let c = container()
        .as_ref()
        .map_err(|e| std::io::Error::other(e.clone()))?;
    // The run's own folders under the run directory (protected DACLs). The cwd was
    // granted by its owner and checked when the run was planned.
    for dir in spec.writable.iter().filter(|d| **d != launch.cwd) {
        appcontainer::allow_dir(dir, &c.sid, MODIFY, true)?;
    }
    for dir in &spec.readable {
        appcontainer::allow_dir(dir, &c.sid, READ_EXECUTE, true)?;
    }
    let network = spec.network != Some(NetworkPolicy::Deny);
    Ok((
        c.launcher.clone().into_os_string(),
        appcontainer::launcher_args(
            &c.sid,
            network,
            launch.raw_tail.as_deref(),
            &launch.program,
            &launch.args,
        ),
    ))
}

/// Whether `launch` goes through the launcher (then the raw command-line tail is passed
/// to it as an argument, not appended).
pub fn uses_launcher(launch: &Launch) -> bool {
    matches!(&launch.sandbox, Some((p, _)) if p.mode == SandboxMode::AppContainer)
}

/// Let the container run `program` (tests).
pub fn allow_program(program: &Path) -> OsResult<()> {
    let c = container()
        .as_ref()
        .map_err(|e| std::io::Error::other(e.clone()))?;
    appcontainer::allow_file(program, &c.sid, READ_EXECUTE)?;
    Ok(())
}

/// Give the container read/write access to `dir` (tests, and dev mode setups).
pub fn grant_container(dir: &Path) -> OsResult<()> {
    let c = container()
        .as_ref()
        .map_err(|e| std::io::Error::other(e.clone()))?;
    appcontainer::allow_dir(dir, &c.sid, MODIFY, false)?;
    Ok(())
}
