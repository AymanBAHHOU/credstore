//! Private files and atomic replacement.
//!
//! `write_private_atomic` writes to a temp file in the same directory, fsyncs it, then
//! renames it over the target, so a reader (or a crash) only ever sees the old file or the
//! new one, never a partial write.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::{FeatureStatus, OsError, OsResult};

/// Create `dir` and its parents. On Unix the leaf is mode 0700.
pub fn create_private_dir(dir: &Path) -> OsResult<()> {
    if let Some(parent) = dir.parent() {
        fs::create_dir_all(parent)?;
    }
    match create_dir_private(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Whether files written here are restricted to their owner.
pub fn private_file_protection() -> FeatureStatus {
    protection_status()
}

/// Atomically replace `path` with `data`. New files are owner-only (Unix mode 0600).
/// Leftover temp files from an earlier interrupted write are removed first.
pub fn write_private_atomic(path: &Path, data: &[u8]) -> OsResult<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| {
            OsError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path has no parent directory",
            ))
        })?;
    let name = path
        .file_name()
        .ok_or_else(|| {
            OsError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path has no file name",
            ))
        })?
        .to_string_lossy()
        .into_owned();

    sweep_temp_files(dir, &name);

    let tmp = temp_path(dir, &name);
    let result = (|| -> std::io::Result<()> {
        let mut f = open_private_new(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        rename_replace(&tmp, path)?;
        sync_dir(dir)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.map_err(OsError::from)
}

fn temp_prefix(name: &str) -> String {
    format!(".{name}.tmp-")
}

fn temp_path(dir: &Path, name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    dir.join(format!(
        "{}{}-{nanos:09}",
        temp_prefix(name),
        std::process::id()
    ))
}

/// Remove temp files a killed writer left behind. They are never read.
fn sweep_temp_files(dir: &Path, name: &str) {
    let prefix = temp_prefix(name);
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_name().to_string_lossy().starts_with(&prefix) {
            let _ = fs::remove_file(entry.path());
        }
    }
}

// ---------------------------------- Unix ----------------------------------

#[cfg(unix)]
fn create_dir_private(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(dir)
}

#[cfg(unix)]
fn open_private_new(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(unix)]
fn rename_replace(from: &Path, to: &Path) -> std::io::Result<()> {
    fs::rename(from, to)
}

/// Make the rename itself durable.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(unix)]
fn protection_status() -> FeatureStatus {
    FeatureStatus::Active
}

/// Whether `path` is readable or writable by anyone but its owner.
#[cfg(unix)]
pub fn is_owner_only(path: &Path) -> OsResult<bool> {
    use std::os::unix::fs::PermissionsExt;
    Ok(fs::metadata(path)?.permissions().mode() & 0o077 == 0)
}

// -------------------------------- Windows ---------------------------------

#[cfg(windows)]
fn create_dir_private(dir: &Path) -> std::io::Result<()> {
    fs::create_dir(dir)
}

#[cfg(windows)]
fn open_private_new(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

/// `fs::rename` replaces the target on Windows (MoveFileEx with REPLACE_EXISTING). It can
/// fail briefly while another process (an indexer, antivirus) has the target open, so
/// retry a few times.
#[cfg(windows)]
fn rename_replace(from: &Path, to: &Path) -> std::io::Result<()> {
    let mut last = None;
    for attempt in 0..10u64 {
        match fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                last = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(20 * (attempt + 1)));
            }
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("rename failed")))
}

/// Windows has no directory fsync; NTFS journals the rename.
#[cfg(windows)]
fn sync_dir(_: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn protection_status() -> FeatureStatus {
    FeatureStatus::Unavailable(
        "explicit file ACLs are not built yet (M7); files inherit the folder's ACL \
         (your user profile in dev mode)"
            .into(),
    )
}

/// Windows: ACL inspection is not built yet (M7).
#[cfg(windows)]
pub fn is_owner_only(_: &Path) -> OsResult<bool> {
    Err(OsError::unavailable(
        "file ACL inspection not built yet (M7)",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "credstore-fs-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        create_private_dir(&d).unwrap();
        d
    }

    #[test]
    fn writes_and_replaces() {
        let d = tempdir("replace");
        let p = d.join("f.json");
        write_private_atomic(&p, b"one").unwrap();
        write_private_atomic(&p, b"two").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        let names: Vec<_> = fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "no temp files left: {names:?}");
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn sweeps_leftover_temp_files() {
        let d = tempdir("sweep");
        let p = d.join("vault.age");
        fs::write(d.join(".vault.age.tmp-1-000000001"), b"partial").unwrap();
        fs::write(d.join("unrelated"), b"keep").unwrap();
        write_private_atomic(&p, b"data").unwrap();
        assert!(!d.join(".vault.age.tmp-1-000000001").exists());
        assert!(d.join("unrelated").exists());
        fs::remove_dir_all(d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn files_are_owner_only() {
        let d = tempdir("mode");
        let p = d.join("secret");
        write_private_atomic(&p, b"x").unwrap();
        assert!(is_owner_only(&p).unwrap());
        assert!(is_owner_only(&d).unwrap());
        fs::remove_dir_all(d).unwrap();
    }
}
