//! Program lookup for child processes (spec 5.2: matching is on the resolved argv).
//!
//! The daemon resolves `argv[0]` itself and runs the resolved path, so the program that
//! policy approved is the program that runs. Lookup never searches the working directory
//! (Windows `CreateProcess` would), and ignores relative `PATH` entries such as `.`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::{OsError, OsResult};

/// Canonical form of an existing directory, or `None`. On Windows the `\\?\C:\` prefix
/// that `canonicalize` adds is dropped: `cmd.exe` and many tools cannot use it as a
/// working directory.
pub fn canonical_dir(path: &Path) -> Option<PathBuf> {
    let c = std::fs::canonicalize(path).ok().filter(|p| p.is_dir())?;
    Some(simplify(c))
}

/// Canonical form of an existing path (file or directory), simplified as above.
pub fn canonical_path(path: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(path).ok().map(simplify)
}

fn simplify(p: PathBuf) -> PathBuf {
    if cfg!(windows) {
        let s = p.to_string_lossy();
        let b = s.as_bytes();
        if b.len() >= 7 && s.starts_with(r"\\?\") && b[5] == b':' && b[6] == b'\\' {
            return PathBuf::from(&s[4..]);
        }
    }
    p
}

/// Directories searched for bare program names: the daemon's own `PATH`, absolute
/// entries only.
pub fn search_path() -> Vec<PathBuf> {
    std::env::var_os("PATH")
        .map(|p| {
            std::env::split_paths(&p)
                .filter(|d| d.is_absolute())
                .collect()
        })
        .unwrap_or_default()
}

/// The `PATH` value given to children: the same directories as [`search_path`].
pub fn child_path(dirs: &[PathBuf]) -> OsString {
    std::env::join_paths(dirs).unwrap_or_default()
}

/// Resolve `program` to a canonical full path. A name with a path separator is taken
/// relative to `cwd`; a bare name is looked up in `dirs`.
pub fn resolve_program(program: &str, cwd: &Path, dirs: &[PathBuf]) -> OsResult<PathBuf> {
    if program.is_empty() {
        return Err(not_found("an empty program name"));
    }
    let has_sep = program.contains('/') || (cfg!(windows) && program.contains('\\'));
    if has_sep || Path::new(program).is_absolute() {
        let p = cwd.join(program);
        return candidates(&p)
            .into_iter()
            .find(|c| is_runnable(c))
            .map(canonical)
            .transpose()?
            .ok_or_else(|| not_found(program));
    }
    for dir in dirs {
        if let Some(found) = candidates(&dir.join(program))
            .into_iter()
            .find(|c| is_runnable(c))
        {
            return canonical(found);
        }
    }
    Err(not_found(program))
}

fn canonical(p: PathBuf) -> OsResult<PathBuf> {
    Ok(simplify(std::fs::canonicalize(p)?))
}

fn not_found(program: &str) -> OsError {
    OsError::Io(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("program {program:?} not found"),
    ))
}

#[cfg(unix)]
fn candidates(p: &Path) -> Vec<PathBuf> {
    vec![p.to_owned()]
}

#[cfg(unix)]
fn is_runnable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// `name` as is when it already has a `PATHEXT` extension, else `name` + each extension.
#[cfg(windows)]
fn candidates(p: &Path) -> Vec<PathBuf> {
    let exts: Vec<String> = std::env::var("PATHEXT")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".into())
        .split(';')
        .filter(|e| e.starts_with('.') && e.len() > 1)
        .map(|e| e.to_ascii_lowercase())
        .collect();
    let has_ext = p
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_ascii_lowercase()))
        .is_some_and(|e| exts.contains(&e));
    if has_ext {
        return vec![p.to_owned()];
    }
    exts.iter()
        .map(|e| {
            let mut s = p.as_os_str().to_owned();
            s.push(e);
            PathBuf::from(s)
        })
        .collect()
}

#[cfg(windows)]
fn is_runnable(p: &Path) -> bool {
    std::fs::metadata(p).is_ok_and(|m| m.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_programs_on_path_but_not_in_cwd() {
        let dirs = search_path();
        let cwd = std::env::temp_dir();
        #[cfg(unix)]
        let prog = "sh";
        #[cfg(windows)]
        let prog = "cmd";
        let p = resolve_program(prog, &cwd, &dirs).unwrap();
        assert!(p.is_absolute(), "{}", p.display());

        // A program that only exists in the working directory is not found by bare name.
        let dir = std::env::temp_dir().join(format!("cs-exec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        let local = {
            use std::os::unix::fs::PermissionsExt;
            let f = dir.join("only-here");
            std::fs::write(&f, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
            "only-here"
        };
        #[cfg(windows)]
        let local = {
            std::fs::write(dir.join("only-here.cmd"), "@echo off\r\n").unwrap();
            "only-here"
        };
        assert!(resolve_program(local, &dir, &dirs).is_err());
        let explicit = format!("./{local}");
        let found = resolve_program(&explicit, &dir, &dirs).unwrap();
        assert!(found.starts_with(canonical_dir(&dir).unwrap()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn relative_path_entries_are_ignored() {
        assert!(search_path().iter().all(|d| d.is_absolute()));
        assert!(resolve_program("", Path::new("/"), &[]).is_err());
    }
}
