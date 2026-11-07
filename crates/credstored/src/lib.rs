//! credstored: the credstore daemon, as a library so tests can run it in-process.
//! The `credstored` binary is a thin wrapper around [`start`].

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use credstore_core::audit::AuditLog;
use credstore_os::{fs as osfs, Mode, Paths, Platform, PlatformPaths};
use serde_json::json;
use tokio::sync::watch;
use tokio::task::JoinHandle;

mod approvals;
mod http;
mod run;
mod runner;
mod server;
mod state;

pub use state::{FIRST_LOCKOUT, MAX_FAILURES};

/// What to run.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub paths: PlatformPaths,
}

/// A started daemon. Call [`RunningDaemon::shutdown`] to stop it.
pub struct RunningDaemon {
    shutdown: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
    state: Arc<state::State>,
}

/// Bind both endpoints and start serving. The vault starts locked.
pub async fn start(config: DaemonConfig) -> anyhow::Result<RunningDaemon> {
    let platform = Platform::with_paths(config.paths);
    osfs::create_private_dir(platform.data_dir()).context("creating the data directory")?;
    let audit = AuditLog::open(platform.audit_log()).context("opening the audit log")?;
    let state = Arc::new(state::State::new(platform, audit));
    // A missing or invalid policy does not stop the daemon: runs are denied until
    // `credstore reload` (or SIGHUP) loads a valid one.
    let _ = state.load_policy("startup");
    state.sweep_run_dir();
    let caps = credstore_os::sandbox::capabilities();
    tracing::info!(
        sandbox = credstore_os::sandbox::mode_name(caps.mode),
        detail = %caps.detail,
        "sandbox probed"
    );

    let (agent, approver) = server::bind_all(&state)
        .await
        .context("binding the daemon endpoints")?;

    let _ = state.audit(
        "daemon_started",
        None,
        json!({
            "mode": match state.mode() { Mode::Dev => "dev", Mode::Installed => "installed" },
            "os": credstore_os::OS_NAME,
            "version": env!("CARGO_PKG_VERSION"),
        }),
    );

    let (tx, rx) = watch::channel(false);
    let mut tasks = vec![
        tokio::spawn(server::accept_loop(
            state.clone(),
            agent,
            server::Endpoint::Agent,
            rx.clone(),
        )),
        tokio::spawn(server::accept_loop(
            state.clone(),
            approver,
            server::Endpoint::Approver,
            rx.clone(),
        )),
    ];

    // Idle relock.
    let relock_state = state.clone();
    let mut relock_rx = rx.clone();
    tasks.push(tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        loop {
            tokio::select! {
                _ = relock_rx.changed() => return,
                _ = tick.tick() => relock_state.relock_if_idle(),
            }
        }
    }));

    // Reload on SIGHUP (Unix; on Windows only `credstore reload` triggers it).
    match credstore_os::signals::ReloadSignal::new() {
        Ok(mut sig) => {
            let reload_state = state.clone();
            let mut reload_rx = rx.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = reload_rx.changed() => return,
                        _ = sig.recv() => { let _ = reload_state.load_policy("signal"); }
                    }
                }
            }));
        }
        Err(e) => tracing::warn!(%e, "no reload signal; use `credstore reload`"),
    }

    Ok(RunningDaemon {
        shutdown: tx,
        tasks,
        state,
    })
}

impl RunningDaemon {
    /// Stop accepting, wipe the unlocked vault, and wait for the background tasks.
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        for t in self.tasks {
            let _ = t.await;
        }
        self.state.cancel_pending();
        self.state.relock("shutdown");
        let _ = self.state.audit("daemon_stopped", None, json!({}));
    }

    /// Record what process hardening applied, for `credstore status` and `doctor`.
    pub fn report_hardening(&self, items: &[credstore_os::HardeningItem]) {
        let reports = items
            .iter()
            .map(|i| credstore_proto::HardeningReport {
                name: i.name.to_string(),
                active: i.status == credstore_os::FeatureStatus::Active,
                detail: match &i.status {
                    credstore_os::FeatureStatus::Active => None,
                    credstore_os::FeatureStatus::Unavailable(why) => Some(why.clone()),
                },
            })
            .collect();
        *self
            .state
            .hardening
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = reports;
    }

    /// Whether the vault is currently unlocked in memory.
    pub fn is_unlocked(&self) -> bool {
        self.state.is_unlocked()
    }

    /// Requests waiting for the human.
    pub fn pending_count(&self) -> usize {
        self.state.pending_count()
    }

    /// Set the idle relock time (normally from policy).
    pub fn set_idle_ttl(&self, ttl: Duration) {
        *self
            .state
            .idle_ttl
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = ttl;
    }
}
