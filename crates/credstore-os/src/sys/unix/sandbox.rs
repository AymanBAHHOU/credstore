//! Sandboxes on Unix: bubblewrap, else Landlock, on Linux; Seatbelt (`sandbox-exec`) on
//! macOS. `CREDSTORE_FORCE_SANDBOX` (`landlock` or `none`) can only pick a weaker mode
//! than the best one available; it exists so CI can test every mode on one machine.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use credstore_proto::{NetworkPolicy, SandboxMode};

use crate::run::Launch;
use crate::sandbox::{SandboxCapabilities, SandboxPlan, SandboxSpec};
use crate::OsResult;

const FORCE_ENV: &str = "CREDSTORE_FORCE_SANDBOX";

fn forced() -> Option<String> {
    std::env::var(FORCE_ENV).ok().filter(|v| !v.is_empty())
}

fn none(detail: impl Into<String>) -> SandboxCapabilities {
    SandboxCapabilities {
        mode: SandboxMode::None,
        network_restriction: false,
        hides_paths: false,
        detail: detail.into(),
    }
}

/// Nothing per run to check on Linux and macOS.
pub fn plan_for_run(
    caps: &SandboxCapabilities,
    need: crate::sandbox::SandboxNeed,
    network: NetworkPolicy,
    _cwd: &std::path::Path,
    _program: Option<&std::path::Path>,
) -> Result<SandboxPlan, String> {
    crate::sandbox::plan(caps, need, network)
}

fn denies_network(spec: &SandboxSpec, plan: &SandboxPlan) -> bool {
    plan.network_enforced && spec.network == Some(NetworkPolicy::Deny)
}

/// Paths under `root` that a run may access, leaving out every path in `hidden` (and
/// anything below them). Directories on the way to a hidden path are expanded into their
/// entries; symlinks are skipped (access is checked at their target).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn allowed_beneath(root: &Path, hidden: &[PathBuf]) -> Vec<PathBuf> {
    fn walk(dir: &Path, hidden: &[PathBuf], out: &mut Vec<PathBuf>) {
        if hidden.iter().any(|h| dir.starts_with(h)) {
            return;
        }
        if !hidden.iter().any(|h| h.starts_with(dir)) {
            out.push(dir.to_owned());
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            let Ok(meta) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                walk(&p, hidden, out);
            } else if !hidden.iter().any(|h| p.starts_with(h)) {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, hidden, &mut out);
    out
}

// ----------------------------------------------------------------------------
// Linux
// ----------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use landlock::{
        path_beneath_rules, Access, AccessFs, AccessNet, CompatLevel, Compatible, Ruleset,
        RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus, ABI,
    };

    const LANDLOCK_ABI: ABI = ABI::V5;

    fn bwrap_path() -> Option<PathBuf> {
        ["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"]
            .iter()
            .map(PathBuf::from)
            .find(|p| p.is_file())
    }

    /// bwrap is only usable if unprivileged user namespaces work (Ubuntu's AppArmor
    /// restriction and some containers turn them off).
    fn bwrap_works(bwrap: &Path) -> bool {
        std::process::Command::new(bwrap)
            .args([
                "--ro-bind",
                "/",
                "/",
                "--dev",
                "/dev",
                "--proc",
                "/proc",
                "--unshare-pid",
                "--unshare-net",
                "--die-with-parent",
                "--",
                "/bin/true",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    fn landlock_fs() -> bool {
        Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(ABI::V1))
            .and_then(|r| r.create())
            .is_ok()
    }

    fn landlock_net() -> bool {
        Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessNet::from_all(ABI::V4))
            .and_then(|r| r.create())
            .is_ok()
    }

    pub fn probe() -> SandboxCapabilities {
        let force = forced();
        if force.as_deref() == Some("none") {
            return none(format!("{FORCE_ENV}=none"));
        }
        if force.is_none() {
            if let Some(b) = bwrap_path() {
                if bwrap_works(&b) {
                    return SandboxCapabilities {
                        mode: SandboxMode::Bwrap,
                        network_restriction: true,
                        hides_paths: true,
                        detail: format!("bubblewrap at {}", b.display()),
                    };
                }
            }
        }
        if landlock_fs() {
            let net = landlock_net();
            return SandboxCapabilities {
                mode: SandboxMode::Landlock,
                network_restriction: net,
                hides_paths: true,
                detail: if net {
                    "Landlock (files and TCP)".into()
                } else {
                    "Landlock (files only; this kernel cannot restrict network, needs 6.7+)".into()
                },
            };
        }
        none("no usable bubblewrap and no Landlock in this kernel")
    }

    pub fn wrap(
        plan: &SandboxPlan,
        spec: &SandboxSpec,
        launch: &Launch,
    ) -> OsResult<(OsString, Vec<OsString>)> {
        let direct = || {
            (
                launch.program.clone().into_os_string(),
                launch.args.iter().map(OsString::from).collect(),
            )
        };
        if plan.mode != SandboxMode::Bwrap {
            return Ok(direct());
        }
        let bwrap = bwrap_path()
            .ok_or_else(|| crate::OsError::unavailable("bubblewrap disappeared since startup"))?;
        let mut a: Vec<OsString> = Vec::new();
        let mut push = |xs: &[&std::ffi::OsStr]| a.extend(xs.iter().map(|x| x.to_os_string()));
        push(&[
            "--die-with-parent".as_ref(),
            "--new-session".as_ref(),
            "--unshare-pid".as_ref(),
            "--unshare-ipc".as_ref(),
            "--unshare-uts".as_ref(),
            "--unshare-cgroup-try".as_ref(),
        ]);
        if denies_network(spec, plan) {
            push(&["--unshare-net".as_ref()]);
        }
        push(&[
            "--ro-bind".as_ref(),
            "/".as_ref(),
            "/".as_ref(),
            "--dev".as_ref(),
            "/dev".as_ref(),
            "--proc".as_ref(),
            "/proc".as_ref(),
            "--tmpfs".as_ref(),
            "/tmp".as_ref(),
        ]);
        let inside_hidden = |p: &Path| spec.hidden.iter().any(|h| p.starts_with(h));
        // Order matters: later mounts cover earlier ones. Writable dirs outside hidden
        // paths, then the hidden paths over them, then the run's own dirs on top.
        for w in spec.writable.iter().filter(|w| !inside_hidden(w)) {
            push(&["--bind".as_ref(), w.as_os_str(), w.as_os_str()]);
        }
        for h in &spec.hidden {
            match std::fs::metadata(h) {
                Ok(m) if m.is_dir() => push(&["--tmpfs".as_ref(), h.as_os_str()]),
                Ok(_) => push(&["--ro-bind".as_ref(), "/dev/null".as_ref(), h.as_os_str()]),
                Err(_) => {}
            }
        }
        for w in spec.writable.iter().filter(|w| inside_hidden(w)) {
            push(&["--bind".as_ref(), w.as_os_str(), w.as_os_str()]);
        }
        for r in &spec.readable {
            push(&["--ro-bind".as_ref(), r.as_os_str(), r.as_os_str()]);
        }
        push(&[
            "--chdir".as_ref(),
            launch.cwd.as_os_str(),
            "--".as_ref(),
            launch.program.as_os_str(),
        ]);
        a.extend(launch.args.iter().map(OsString::from));
        Ok((bwrap.into_os_string(), a))
    }

    /// Built before fork; applied in the child by [`restrict`].
    pub fn landlock_ruleset(launch: &Launch) -> OsResult<Option<RulesetCreated>> {
        let Some((plan, spec)) = &launch.sandbox else {
            return Ok(None);
        };
        if plan.mode != SandboxMode::Landlock {
            return Ok(None);
        }
        let e = |e: landlock::RulesetError| crate::OsError::unavailable(e.to_string());
        let mut rs = Ruleset::default()
            .handle_access(AccessFs::from_all(LANDLOCK_ABI))
            .map_err(e)?;
        if denies_network(spec, plan) {
            rs = rs.handle_access(AccessNet::from_all(ABI::V4)).map_err(e)?;
        }
        let read = AccessFs::from_read(LANDLOCK_ABI);
        let all = AccessFs::from_all(LANDLOCK_ABI);
        let mut writable = Vec::new();
        for w in &spec.writable {
            // A writable dir that contains a hidden path gets everything but that path.
            let others: Vec<PathBuf> = spec
                .hidden
                .iter()
                .filter(|h| !w.starts_with(h))
                .cloned()
                .collect();
            writable.extend(allowed_beneath(w, &others));
        }
        let created = rs
            .create()
            .map_err(e)?
            .add_rules(path_beneath_rules(
                allowed_beneath(Path::new("/"), &spec.hidden),
                read,
            ))
            .map_err(e)?
            .add_rules(path_beneath_rules(&spec.readable, read))
            .map_err(e)?
            .add_rules(path_beneath_rules(&writable, all))
            .map_err(e)?
            .add_rules(path_beneath_rules(["/dev"], all))
            .map_err(e)?;
        Ok(Some(created))
    }

    /// In the child, before exec. Fails (and so the spawn fails) if nothing is enforced.
    pub fn restrict(rs: RulesetCreated) -> std::io::Result<()> {
        match rs.restrict_self() {
            Ok(s) if s.ruleset != RulesetStatus::NotEnforced => Ok(()),
            Ok(_) => Err(std::io::Error::other("landlock not enforced")),
            Err(_) => Err(std::io::Error::other("landlock restrict_self failed")),
        }
    }
}

// ----------------------------------------------------------------------------
// macOS
// ----------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod imp {
    use super::*;

    const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

    pub fn probe() -> SandboxCapabilities {
        if forced().as_deref() == Some("none") {
            return none(format!("{FORCE_ENV}=none"));
        }
        let ok = std::process::Command::new(SANDBOX_EXEC)
            .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            return none("sandbox-exec is missing or not working");
        }
        SandboxCapabilities {
            mode: SandboxMode::Seatbelt,
            network_restriction: true,
            hides_paths: true,
            detail: "Seatbelt profile via sandbox-exec (deprecated by Apple, still works)".into(),
        }
    }

    /// A Seatbelt string literal.
    fn lit(p: &Path) -> String {
        let s = p.to_string_lossy();
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    }

    /// Later rules win over earlier ones.
    pub fn profile(spec: &SandboxSpec, deny_net: bool) -> String {
        let mut p = String::from("(version 1)\n(allow default)\n(deny file-write*)\n");
        p.push_str(
            "(allow file-write* (literal \"/dev/null\") (literal \"/dev/zero\") \
             (literal \"/dev/dtracehelper\") (regex #\"^/dev/fd/\") (regex #\"^/dev/tty\"))\n",
        );
        for w in &spec.writable {
            p.push_str(&format!("(allow file-write* (subpath {}))\n", lit(w)));
        }
        for h in &spec.hidden {
            p.push_str(&format!(
                "(deny file-read* file-write* (subpath {}))\n",
                lit(h)
            ));
        }
        for w in spec
            .writable
            .iter()
            .filter(|w| spec.hidden.iter().any(|h| w.starts_with(h)))
        {
            p.push_str(&format!(
                "(allow file-read* file-write* (subpath {}))\n",
                lit(w)
            ));
        }
        for r in &spec.readable {
            p.push_str(&format!("(allow file-read* (subpath {}))\n", lit(r)));
        }
        if deny_net {
            p.push_str("(deny network*)\n");
        }
        p
    }

    pub fn wrap(
        plan: &SandboxPlan,
        spec: &SandboxSpec,
        launch: &Launch,
    ) -> OsResult<(OsString, Vec<OsString>)> {
        if plan.mode != SandboxMode::Seatbelt {
            return Ok((
                launch.program.clone().into_os_string(),
                launch.args.iter().map(OsString::from).collect(),
            ));
        }
        let mut a: Vec<OsString> = vec![
            "-p".into(),
            profile(spec, denies_network(spec, plan)).into(),
            launch.program.clone().into_os_string(),
        ];
        a.extend(launch.args.iter().map(OsString::from));
        Ok((SANDBOX_EXEC.into(), a))
    }
}

pub use imp::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_beneath_leaves_out_hidden_paths() {
        let root = std::env::temp_dir().join(format!("cs-beneath-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for d in ["a/b/secret", "a/b/open", "a/c", "z"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(root.join("a/b/file"), "x").unwrap();
        std::fs::write(root.join("a/b/secret/vault"), "x").unwrap();
        let hidden = vec![root.join("a/b/secret")];
        let mut got = allowed_beneath(&root, &hidden);
        got.sort();
        let mut want = vec![
            root.join("a/b/file"),
            root.join("a/b/open"),
            root.join("a/c"),
            root.join("z"),
        ];
        want.sort();
        assert_eq!(got, want);
        assert!(allowed_beneath(&root.join("a/b/secret"), &hidden).is_empty());
        assert_eq!(
            allowed_beneath(&root.join("z"), &hidden),
            vec![root.join("z")]
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
