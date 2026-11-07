//! Sandbox capabilities and planning (spec 4.1, 6.4).
//!
//! The daemon plans the sandbox before asking the human, so the approval screen shows
//! the mode that will apply. Anything the OS cannot enforce is either a denial (policy
//! `sandbox = "require"`) or a listed gap (`"prefer"`); it is never skipped silently.

use std::path::PathBuf;
use std::sync::OnceLock;

use credstore_proto::{NetworkPolicy, SandboxMode};

/// How much sandboxing policy asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxNeed {
    Require,
    Prefer,
    Off,
}

/// What a run may touch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SandboxSpec {
    /// Writable: the run's cwd and its private temp dir. Everything else is read-only.
    pub writable: Vec<PathBuf>,
    /// Read-only even if inside a hidden path (the run's own secret files).
    pub readable: Vec<PathBuf>,
    /// Not visible at all: vault, index, policy, audit log, the run directory root.
    pub hidden: Vec<PathBuf>,
    pub network: Option<NetworkPolicy>,
}

/// What this machine can do, probed once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxCapabilities {
    /// Best mechanism available (`None` if there is none).
    pub mode: SandboxMode,
    /// Can deny network access per run.
    pub network_restriction: bool,
    /// Can hide paths (vault, policy, audit) from the run.
    pub hides_paths: bool,
    /// Human-readable summary, for `doctor` and the startup log.
    pub detail: String,
}

/// The sandbox a run will get.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPlan {
    pub mode: SandboxMode,
    pub network_enforced: bool,
    /// What policy asked for but this run will not get.
    pub gaps: Vec<String>,
}

pub fn mode_name(m: SandboxMode) -> &'static str {
    match m {
        SandboxMode::Bwrap => "bwrap",
        SandboxMode::Landlock => "landlock",
        SandboxMode::Seatbelt => "seatbelt",
        SandboxMode::JobObject => "job-object",
        SandboxMode::None => "none",
    }
}

/// Probed once per process.
pub fn capabilities() -> &'static SandboxCapabilities {
    static CAPS: OnceLock<SandboxCapabilities> = OnceLock::new();
    CAPS.get_or_init(crate::sys::current::sandbox::probe)
}

/// Decide the sandbox for a run, or why it must be denied.
pub fn plan(
    caps: &SandboxCapabilities,
    need: SandboxNeed,
    network: NetworkPolicy,
) -> Result<SandboxPlan, String> {
    let mut gaps = Vec::new();
    if need == SandboxNeed::Off {
        if network != NetworkPolicy::Inherit {
            gaps.push("sandbox is off, so the network policy is not enforced".into());
        }
        gaps.push("sandbox is off by policy".into());
        return Ok(SandboxPlan {
            mode: SandboxMode::None,
            network_enforced: false,
            gaps,
        });
    }
    if caps.mode == SandboxMode::None {
        let why = format!("no sandbox is available here ({})", caps.detail);
        if need == SandboxNeed::Require {
            return Err(why);
        }
        gaps.push(why);
        if network != NetworkPolicy::Inherit {
            gaps.push("network policy not enforced (no sandbox)".into());
        }
        return Ok(SandboxPlan {
            mode: SandboxMode::None,
            network_enforced: false,
            gaps,
        });
    }

    let network_enforced = match network {
        NetworkPolicy::Inherit => true,
        NetworkPolicy::Deny if caps.network_restriction => true,
        NetworkPolicy::Deny => {
            let why = format!(
                "network = \"deny\" cannot be enforced with {} on this OS",
                mode_name(caps.mode)
            );
            if need == SandboxNeed::Require {
                return Err(why);
            }
            gaps.push(why);
            false
        }
        NetworkPolicy::AllowList => {
            let why = "network = \"allow-list\" is not enforced for commands (allow_hosts \
                       limits http_request only); the command has normal network access"
                .to_string();
            if need == SandboxNeed::Require {
                return Err(why);
            }
            gaps.push(why);
            false
        }
    };
    if !caps.hides_paths {
        gaps.push(format!(
            "{} does not hide files: the command can read the vault, policy and audit \
             files like any process of this user",
            mode_name(caps.mode)
        ));
    }
    Ok(SandboxPlan {
        mode: caps.mode,
        network_enforced,
        gaps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(mode: SandboxMode, net: bool, hides: bool) -> SandboxCapabilities {
        SandboxCapabilities {
            mode,
            network_restriction: net,
            hides_paths: hides,
            detail: "test".into(),
        }
    }

    #[test]
    fn require_denies_what_cannot_be_enforced() {
        let none = caps(SandboxMode::None, false, false);
        let job = caps(SandboxMode::JobObject, false, false);
        let bwrap = caps(SandboxMode::Bwrap, true, true);
        use NetworkPolicy::*;
        use SandboxNeed::*;
        assert!(plan(&none, Require, Inherit).is_err());
        assert!(plan(&job, Require, Deny)
            .unwrap_err()
            .contains("cannot be enforced"));
        assert!(plan(&bwrap, Require, AllowList)
            .unwrap_err()
            .contains("http_request"));
        let p = plan(&bwrap, Require, Deny).unwrap();
        assert!(p.network_enforced && p.gaps.is_empty());
        let p = plan(&job, Require, Inherit).unwrap();
        assert_eq!(p.mode, SandboxMode::JobObject);
        assert!(p.gaps[0].contains("does not hide files"));
    }

    #[test]
    fn prefer_runs_with_listed_gaps() {
        use NetworkPolicy::*;
        use SandboxNeed::*;
        let none = caps(SandboxMode::None, false, false);
        let p = plan(&none, Prefer, Deny).unwrap();
        assert_eq!(p.mode, SandboxMode::None);
        assert_eq!(p.gaps.len(), 2);
        let job = caps(SandboxMode::JobObject, false, false);
        let p = plan(&job, Prefer, Deny).unwrap();
        assert!(!p.network_enforced);
        let p = plan(&caps(SandboxMode::Bwrap, true, true), Off, Inherit).unwrap();
        assert_eq!(p.mode, SandboxMode::None);
    }
}
