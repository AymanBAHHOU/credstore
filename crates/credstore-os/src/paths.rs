//! Per-OS file and endpoint locations (spec 3.3 and 5.4).

use std::path::{Path, PathBuf};

use crate::{Endpoint, EndpointKind, Mode, OsError, OsResult, Paths};

/// Environment variable that overrides the dev-mode home directory.
pub const CREDSTORE_HOME_ENV: &str = "CREDSTORE_HOME";

/// Resolved locations for one mode. Built once; getters never fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformPaths {
    mode: Mode,
    data_dir: PathBuf,
    policy_file: PathBuf,
    audit_log: PathBuf,
    run_dir: PathBuf,
    agent: String,
    approver: String,
}

impl PlatformPaths {
    /// Resolve paths for `mode`. Dev mode uses `$CREDSTORE_HOME`, else `~/.credstore`.
    pub fn new(mode: Mode) -> OsResult<Self> {
        match mode {
            Mode::Installed => Ok(installed()),
            Mode::Dev => match std::env::var_os(CREDSTORE_HOME_ENV) {
                Some(home) if !home.is_empty() => Ok(dev(PathBuf::from(home), true)),
                _ => {
                    let base = directories::BaseDirs::new().ok_or_else(|| {
                        OsError::unavailable("cannot determine the home directory")
                    })?;
                    Ok(dev(base.home_dir().join(".credstore"), false))
                }
            },
        }
    }

    /// Dev-mode paths rooted at an explicit home (tests run isolated daemons this way).
    pub fn dev_with_home(home: impl Into<PathBuf>) -> Self {
        dev(home.into(), true)
    }
}

impl Paths for PlatformPaths {
    fn mode(&self) -> Mode {
        self.mode
    }
    fn data_dir(&self) -> &Path {
        &self.data_dir
    }
    fn policy_file(&self) -> &Path {
        &self.policy_file
    }
    fn audit_log(&self) -> &Path {
        &self.audit_log
    }
    fn run_dir(&self) -> &Path {
        &self.run_dir
    }
    fn endpoint(&self, kind: EndpointKind) -> Endpoint {
        let address = match kind {
            EndpointKind::Agent => self.agent.clone(),
            EndpointKind::Approver => self.approver.clone(),
        };
        Endpoint { kind, address }
    }
}

fn dev(home: PathBuf, explicit_home: bool) -> PlatformPaths {
    let (agent, approver, run_dir) = dev_endpoints(&home, explicit_home);
    PlatformPaths {
        mode: Mode::Dev,
        policy_file: home.join("policy.toml"),
        audit_log: home.join("audit.jsonl"),
        data_dir: home,
        run_dir,
        agent,
        approver,
    }
}

/// FNV-1a, used only to give each dev home its own endpoint names.
fn short_hash(p: &Path) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in p.to_string_lossy().as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{:08x}", h as u32)
}

// --------------------------------- Linux ----------------------------------

#[cfg(target_os = "linux")]
fn installed() -> PlatformPaths {
    PlatformPaths {
        mode: Mode::Installed,
        data_dir: "/var/lib/credstore".into(),
        policy_file: "/etc/credstore/policy.toml".into(),
        audit_log: "/var/log/credstore/audit.jsonl".into(),
        run_dir: "/run/credstore/run".into(),
        agent: "/run/credstore/agent.sock".into(),
        approver: "/run/credstore/approver.sock".into(),
    }
}

/// Linux dev: sockets and run dir under `$XDG_RUNTIME_DIR/credstore` (tmpfs). With an
/// explicit home, or without `XDG_RUNTIME_DIR`, they go under the home directory.
#[cfg(target_os = "linux")]
fn dev_endpoints(home: &Path, explicit_home: bool) -> (String, String, PathBuf) {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|v| !v.is_empty() && !explicit_home)
        .map(|v| PathBuf::from(v).join("credstore"));
    unix_dev_endpoints(runtime.unwrap_or_else(|| home.join("run")))
}

// --------------------------------- macOS ----------------------------------

#[cfg(target_os = "macos")]
fn installed() -> PlatformPaths {
    PlatformPaths {
        mode: Mode::Installed,
        data_dir: "/var/db/credstore".into(),
        policy_file: "/etc/credstore/policy.toml".into(),
        audit_log: "/var/log/credstore/audit.jsonl".into(),
        run_dir: "/var/run/credstore/run".into(),
        agent: "/var/run/credstore/agent.sock".into(),
        approver: "/var/run/credstore/approver.sock".into(),
    }
}

/// macOS dev: sockets under `$TMPDIR/credstore` (per-user on macOS).
#[cfg(target_os = "macos")]
fn dev_endpoints(home: &Path, explicit_home: bool) -> (String, String, PathBuf) {
    let tmp = std::env::var_os("TMPDIR")
        .filter(|v| !v.is_empty() && !explicit_home)
        .map(|v| PathBuf::from(v).join("credstore"));
    unix_dev_endpoints(tmp.unwrap_or_else(|| home.join("run")))
}

/// Longest socket path we use. `sun_path` is 104 bytes on macOS and 108 on Linux,
/// including the terminating NUL.
#[cfg(unix)]
const MAX_SOCKET_PATH: usize = 100;

/// Sockets go in `dir` unless the path would be too long for a Unix socket (macOS temp
/// dirs often are). Then they go in `/tmp/credstore-<uid>-<hash of dir>`, which `bind`
/// creates 0700 and refuses to use if someone else owns it.
#[cfg(unix)]
fn unix_dev_endpoints(dir: PathBuf) -> (String, String, PathBuf) {
    let run_dir = dir.join("run");
    let sock_dir = if dir.join("approver.sock").as_os_str().len() > MAX_SOCKET_PATH {
        PathBuf::from(format!(
            "/tmp/credstore-{}-{}",
            nix::unistd::geteuid(),
            short_hash(&dir)
        ))
    } else {
        dir
    };
    let s = |name: &str| sock_dir.join(name).to_string_lossy().into_owned();
    (s("agent.sock"), s("approver.sock"), run_dir)
}

// -------------------------------- Windows ---------------------------------

#[cfg(windows)]
fn installed() -> PlatformPaths {
    let program_data = std::env::var_os("ProgramData")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    let base = program_data.join("credstore");
    PlatformPaths {
        mode: Mode::Installed,
        policy_file: base.join("policy.toml"),
        audit_log: base.join("audit.jsonl"),
        run_dir: base.join("run"),
        data_dir: base,
        agent: r"\\.\pipe\credstore-agent".into(),
        approver: r"\\.\pipe\credstore-approver".into(),
    }
}

/// Windows dev: per-user pipes `\\.\pipe\credstore-dev-<user>-{agent,approver}`. With an
/// explicit home, a short hash of the home path is added so test daemons don't collide.
#[cfg(windows)]
fn dev_endpoints(home: &Path, explicit_home: bool) -> (String, String, PathBuf) {
    let user: String = std::env::var("USERNAME")
        .unwrap_or_else(|_| "user".into())
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let mut stem = format!(r"\\.\pipe\credstore-dev-{user}");
    if explicit_home {
        stem.push('-');
        stem.push_str(&short_hash(home));
    }
    (
        format!("{stem}-agent"),
        format!("{stem}-approver"),
        home.join("run"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_paths_live_under_home() {
        let home = std::env::temp_dir().join("credstore-test-home");
        let p = PlatformPaths::dev_with_home(&home);
        assert_eq!(p.mode(), Mode::Dev);
        assert_eq!(p.vault_file(), home.join("vault.age"));
        assert_eq!(p.index_file(), home.join("index.json"));
        assert_eq!(p.policy_file(), home.join("policy.toml"));
        assert_eq!(p.audit_log(), home.join("audit.jsonl"));
        assert!(p.run_dir().starts_with(&home));
    }

    #[test]
    fn endpoints_differ_and_are_per_home() {
        let a = PlatformPaths::dev_with_home(std::env::temp_dir().join("cs-a"));
        let b = PlatformPaths::dev_with_home(std::env::temp_dir().join("cs-b"));
        let (aa, ap) = (
            a.endpoint(EndpointKind::Agent),
            a.endpoint(EndpointKind::Approver),
        );
        assert_ne!(aa.address, ap.address);
        assert_ne!(aa.address, b.endpoint(EndpointKind::Agent).address);
    }

    #[cfg(unix)]
    #[test]
    fn long_homes_get_short_socket_paths() {
        let home = std::env::temp_dir().join("x".repeat(120));
        let p = PlatformPaths::dev_with_home(&home);
        for kind in [EndpointKind::Agent, EndpointKind::Approver] {
            let a = p.endpoint(kind).address;
            assert!(a.len() <= MAX_SOCKET_PATH, "{a}");
            assert!(a.starts_with("/tmp/credstore-"), "{a}");
        }
        assert!(p.run_dir().starts_with(&home));
    }

    #[test]
    fn installed_paths_match_spec() {
        let p = installed();
        assert_eq!(p.mode(), Mode::Installed);
        #[cfg(target_os = "linux")]
        {
            assert_eq!(p.vault_file(), Path::new("/var/lib/credstore/vault.age"));
            assert_eq!(
                p.endpoint(EndpointKind::Agent).address,
                "/run/credstore/agent.sock"
            );
        }
        #[cfg(target_os = "macos")]
        {
            assert_eq!(p.vault_file(), Path::new("/var/db/credstore/vault.age"));
            assert_eq!(
                p.endpoint(EndpointKind::Approver).address,
                "/var/run/credstore/approver.sock"
            );
        }
        #[cfg(windows)]
        {
            assert!(p.data_dir().ends_with("credstore"));
            assert_eq!(
                p.endpoint(EndpointKind::Agent).address,
                r"\\.\pipe\credstore-agent"
            );
            assert_eq!(
                p.endpoint(EndpointKind::Approver).address,
                r"\\.\pipe\credstore-approver"
            );
        }
    }
}
