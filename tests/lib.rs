//! Shared helpers for the integration and adversarial tests.
//!
//! Each test runs its own dev-mode daemon in-process on a fresh temp home, so tests run
//! in parallel without sharing a vault, policy, audit log or endpoint.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use credstore::client::Client;
use credstore::commands::Prompt;
use credstore_os::{EndpointKind, Ipc, Paths, Platform, PlatformPaths};
use credstore_proto::{SecretText, MAX_FRAME_LEN};
use credstored::{DaemonConfig, RunningDaemon};

/// The fake secret every adversarial test uses (spec section 10).
pub const FAKE: &str = "FAKE-SECRET-VALUE-12345";
/// Test passphrase.
pub const PASS: &str = "correct horse battery";

pub fn pass() -> SecretText {
    SecretText::new(PASS.into())
}

/// A daemon on a temp home, plus a client for it.
pub struct TestDaemon {
    pub home: PathBuf,
    pub platform: Platform,
    daemon: Option<RunningDaemon>,
}

impl TestDaemon {
    pub async fn start(tag: &str) -> Self {
        let home = std::env::temp_dir().join(format!(
            "cs-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
                % 1_000_000_000
        ));
        Self::start_at(home).await
    }

    pub async fn start_at(home: PathBuf) -> Self {
        let paths = PlatformPaths::dev_with_home(&home);
        let daemon = credstored::start(DaemonConfig {
            paths: paths.clone(),
        })
        .await
        .expect("daemon starts");
        Self {
            home,
            platform: Platform::with_paths(paths),
            daemon: Some(daemon),
        }
    }

    pub fn client(&self) -> Client {
        Client::new(self.platform.clone())
    }

    pub fn daemon(&self) -> &RunningDaemon {
        self.daemon.as_ref().expect("running")
    }

    pub async fn stop(mut self) {
        if let Some(d) = self.daemon.take() {
            d.shutdown().await;
        }
    }

    /// Stop the daemon but keep the home for a restart.
    pub async fn stop_keep(mut self) -> PathBuf {
        if let Some(d) = self.daemon.take() {
            d.shutdown().await;
        }
        let home = self.home.clone();
        std::mem::forget(self);
        home
    }

    pub fn audit_log(&self) -> PathBuf {
        self.platform.audit_log().to_owned()
    }

    /// All audit records, parsed.
    pub fn audit_records(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(self.audit_log())
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    pub fn records(&self, event: &str) -> Vec<serde_json::Value> {
        self.audit_records()
            .into_iter()
            .filter(|r| r["event"] == event)
            .collect()
    }

    /// Create the vault with [`PASS`].
    pub async fn init_vault(&self) {
        let mut msg = Vec::new();
        credstore::commands::init(&self.client(), &Scripted::new(&[PASS, PASS]), &mut msg)
            .await
            .unwrap();
    }

    /// Add a secret.
    pub async fn set_secret(&self, name: &str, value: &str) {
        let mut msg = Vec::new();
        credstore::commands::set(
            &self.client(),
            name,
            Some(format!("test secret {name}")),
            &Scripted::new(&[PASS, value]),
            &mut msg,
        )
        .await
        .unwrap();
    }

    /// Raw connection to an endpoint.
    pub async fn connect(&self, kind: EndpointKind) -> <Platform as Ipc>::Stream {
        self.platform
            .connect(&self.platform.endpoint(kind))
            .await
            .unwrap()
    }

    /// Every file under the home, for "the value never hits disk" checks.
    pub fn all_files(&self) -> Vec<PathBuf> {
        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            if let Ok(rd) = std::fs::read_dir(dir) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        walk(&p, out);
                    } else {
                        out.push(p);
                    }
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.home, &mut out);
        out
    }

    /// Assert no file under the home contains `needle`.
    pub fn assert_not_on_disk(&self, needle: &str) {
        for f in self.all_files() {
            if let Ok(bytes) = std::fs::read(&f) {
                assert!(
                    !contains(&bytes, needle.as_bytes()),
                    "{} contains the secret",
                    f.display()
                );
            }
        }
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        if self.daemon.is_some() {
            // Not shut down cleanly (test panicked); best effort cleanup.
            let _ = std::fs::remove_dir_all(&self.home);
        }
    }
}

pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Scripted hidden input for the CLI commands.
pub struct Scripted(RefCell<VecDeque<String>>);

impl Scripted {
    pub fn new(answers: &[&str]) -> Self {
        Self(RefCell::new(
            answers.iter().map(|s| s.to_string()).collect(),
        ))
    }
    pub fn remaining(&self) -> usize {
        self.0.borrow().len()
    }
}

impl Prompt for Scripted {
    fn secret(&self, _: &str) -> anyhow::Result<SecretText> {
        self.0
            .borrow_mut()
            .pop_front()
            .map(SecretText::new)
            .ok_or_else(|| anyhow::anyhow!("unexpected prompt"))
    }
}

/// Just over the frame limit.
pub const OVERSIZE: u32 = MAX_FRAME_LEN + 1;
