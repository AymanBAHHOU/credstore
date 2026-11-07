//! Give the service account access to a project folder (M9, `credstore grant`).
//!
//! Approved commands run as the service account, so it needs to read and write the
//! folders they run in. The folder's owner can grant that without admin rights. This
//! builds the OS commands that do it; `credstore grant` shows them, asks, and runs them
//! as the user.
//!
//! - Windows: `icacls DIR /grant "NT SERVICE\credstore:(OI)(CI)M"`. Services hold
//!   "bypass traverse checking", so parent folders need nothing.
//! - Linux: `setfacl` gives `credstore` rwX on DIR and everything in it, a default ACL
//!   on its directories (new files), and `x` (traverse only) on each parent the user
//!   owns, such as the 0750 home directory.
//! - macOS: `chmod +a` the same way, for `_credstore`.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{OsError, OsResult, SERVICE_USER};

/// One command `grant` will run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub program: String,
    pub args: Vec<String>,
}

impl Step {
    fn new(program: &str, args: &[&str]) -> Self {
        Self {
            program: program.to_owned(),
            args: args.iter().map(|a| (*a).to_owned()).collect(),
        }
    }

    /// For showing to the human.
    pub fn display(&self) -> String {
        let mut s = self.program.clone();
        for a in &self.args {
            if a.contains(' ') {
                s.push_str(&format!(" \"{a}\""));
            } else {
                s.push(' ');
                s.push_str(a);
            }
        }
        s
    }
}

/// The commands that give the service account access to `dir` (absolute, existing).
pub fn plan(dir: &Path) -> OsResult<Vec<Step>> {
    let dir = dir.canonicalize().map_err(|e| {
        OsError::Io(std::io::Error::new(
            e.kind(),
            format!("{}: {e}", dir.display()),
        ))
    })?;
    if !dir.is_dir() {
        return Err(OsError::Denied(format!(
            "{} is not a folder",
            dir.display()
        )));
    }
    Ok(imp::plan(&strip_verbatim(dir)))
}

/// Run the steps from [`plan`], stopping at the first failure.
pub fn apply(steps: &[Step]) -> OsResult<()> {
    for step in steps {
        let out = Command::new(&step.program).args(&step.args).output()?;
        if !out.status.success() {
            return Err(OsError::Io(std::io::Error::other(format!(
                "{} failed: {}",
                step.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            ))));
        }
    }
    Ok(())
}

fn strip_verbatim(p: PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    match s.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
        _ => p,
    }
}

#[cfg(windows)]
mod imp {
    use super::*;

    pub fn plan(dir: &Path) -> Vec<Step> {
        let d = dir.to_string_lossy();
        let grant = format!("{SERVICE_USER}:(OI)(CI)M");
        vec![Step::new("icacls.exe", &[&d, "/grant", &grant])]
    }
}

#[cfg(unix)]
mod imp {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    /// Parents of `dir` owned by this user (stopping at the first one that is not),
    /// which need traverse rights for the service account to reach `dir`.
    pub(super) fn owned_parents(dir: &Path) -> Vec<PathBuf> {
        let me = nix::unistd::geteuid().as_raw();
        dir.ancestors()
            .skip(1)
            .take_while(|p| p.parent().is_some())
            .take_while(|p| std::fs::metadata(p).map(|m| m.uid() == me).unwrap_or(false))
            .map(Path::to_path_buf)
            .collect()
    }

    #[cfg(target_os = "linux")]
    pub fn plan(dir: &Path) -> Vec<Step> {
        let d = dir.to_string_lossy();
        let rw = format!("u:{SERVICE_USER}:rwX");
        let mut steps = vec![
            Step::new("setfacl", &["-R", "-m", &rw, &d]),
            // Default ACLs (for new files) go on directories only.
            Step::new(
                "find",
                &[
                    &d, "-type", "d", "-exec", "setfacl", "-d", "-m", &rw, "{}", "+",
                ],
            ),
        ];
        let x = format!("u:{SERVICE_USER}:x");
        for p in owned_parents(dir) {
            steps.push(Step::new("setfacl", &["-m", &x, &p.to_string_lossy()]));
        }
        steps
    }

    #[cfg(target_os = "macos")]
    pub fn plan(dir: &Path) -> Vec<Step> {
        let d = dir.to_string_lossy();
        let rights = "list,search,add_file,add_subdirectory,delete_child,readattr,writeattr,\
                      readextattr,writeextattr,readsecurity,read,write,append,execute,delete";
        let inherit = format!("{SERVICE_USER} allow {rights},file_inherit,directory_inherit");
        let mut steps = vec![Step::new("chmod", &["-R", "+a", &inherit, &d])];
        let search = format!("{SERVICE_USER} allow search");
        for p in owned_parents(dir) {
            steps.push(Step::new("chmod", &["+a", &search, &p.to_string_lossy()]));
        }
        steps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_names_the_service_account_and_the_folder() {
        let dir = std::env::temp_dir();
        let steps = plan(&dir).unwrap();
        assert!(!steps.is_empty());
        let first = steps[0].display();
        assert!(first.contains(SERVICE_USER), "{first}");
        let shown = strip_verbatim(dir.canonicalize().unwrap());
        assert!(
            steps[0].args.iter().any(|a| Path::new(a) == shown),
            "{first}"
        );
    }

    #[test]
    fn missing_folders_are_refused() {
        let dir = std::env::temp_dir().join("credstore-grant-no-such-dir");
        assert!(plan(&dir).is_err());
    }
}
