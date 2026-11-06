//! Windows v1 sandbox: a Job Object (process tree kill, process-count and memory
//! limits). No restricted token yet, so it neither hides files nor restricts the
//! network; `plan` lists those gaps and `sandbox = "require"` with `network = "deny"`
//! is refused. AppContainer is v2.

use std::ffi::OsString;

use credstore_proto::SandboxMode;

use super::job::Job;
use crate::run::Launch;
use crate::sandbox::{SandboxCapabilities, SandboxPlan, SandboxSpec};
use crate::OsResult;

pub fn probe() -> SandboxCapabilities {
    if std::env::var("CREDSTORE_FORCE_SANDBOX").as_deref() == Ok("none") {
        return SandboxCapabilities {
            mode: SandboxMode::None,
            network_restriction: false,
            hides_paths: false,
            detail: "CREDSTORE_FORCE_SANDBOX=none".into(),
        };
    }
    match Job::new() {
        Ok(_) => SandboxCapabilities {
            mode: SandboxMode::JobObject,
            network_restriction: false,
            hides_paths: false,
            detail: "Job Object (kills the process tree; process and memory limits); no \
                     restricted token, file or network restriction in v1"
                .into(),
        },
        Err(e) => SandboxCapabilities {
            mode: SandboxMode::None,
            network_restriction: false,
            hides_paths: false,
            detail: format!("cannot create a Job Object: {e}"),
        },
    }
}

/// Nothing to wrap: the Job Object is applied after spawn.
pub fn wrap(
    _plan: &SandboxPlan,
    _spec: &SandboxSpec,
    launch: &Launch,
) -> OsResult<(OsString, Vec<OsString>)> {
    Ok((
        launch.program.clone().into_os_string(),
        launch.args.iter().map(OsString::from).collect(),
    ))
}
