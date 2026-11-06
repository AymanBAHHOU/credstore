//! credstored: the credstore daemon. Owns the vault, policy, audit log and runner.

use anyhow::Context;
use clap::Parser;
use credstore_os::{FeatureStatus, MemoryGuard, Mode, Paths, Platform, DEV_MODE_WARNING};
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "credstored", version, about = "credstore daemon")]
struct Args {
    /// Run as the current user, without the service install. Weaker: see the threat model.
    #[arg(long)]
    dev: bool,
    /// Windows: run under the Service Control Manager (the installed service uses this).
    /// Logs go to credstored.log in the data directory.
    #[arg(long, conflicts_with = "dev")]
    service: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if args.service {
        let platform = Platform::new(Mode::Installed).context("resolving credstore paths")?;
        init_tracing_file(&platform)?;
        credstore_os::service::run_as_service(Box::new(move |stop| {
            run(platform, Some(stop)).map_err(|e| {
                tracing::error!("{e:#}");
                format!("{e:#}")
            })
        }))?;
        return Ok(());
    }

    init_tracing_stderr();
    let mode = if args.dev { Mode::Dev } else { Mode::Installed };
    if mode == Mode::Dev {
        eprintln!("{DEV_MODE_WARNING}");
        tracing::warn!("{DEV_MODE_WARNING}");
    }
    let platform = Platform::new(mode).context("resolving credstore paths")?;
    run(platform, None)
}

/// Harden, start the daemon, and serve until a signal (or the service manager) stops it.
fn run(platform: Platform, stop: Option<watch::Receiver<bool>>) -> anyhow::Result<()> {
    let hardening = platform.harden_process();
    for item in &hardening {
        match &item.status {
            FeatureStatus::Active => tracing::info!(feature = item.name, "hardening active"),
            FeatureStatus::Unavailable(reason) => {
                tracing::warn!(feature = item.name, %reason, "hardening unavailable")
            }
        }
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")?;
    rt.block_on(async move {
        let daemon = credstored::start(credstored::DaemonConfig {
            paths: platform.paths().clone(),
        })
        .await?;
        daemon.report_hardening(&hardening);
        tracing::info!(
            os = credstore_os::OS_NAME,
            mode = ?platform.mode(),
            "credstored ready (vault locked)"
        );

        match stop {
            Some(mut stop) => {
                tokio::select! {
                    _ = credstore_os::signals::terminate() => {}
                    _ = stop.wait_for(|s| *s) => {}
                }
            }
            None => credstore_os::signals::terminate().await,
        }
        tracing::info!("shutting down");
        daemon.shutdown().await;
        anyhow::Ok(())
    })
}

fn filter() -> EnvFilter {
    EnvFilter::try_from_env("CREDSTORE_LOG").unwrap_or_else(|_| EnvFilter::new("info"))
}

fn init_tracing_stderr() {
    // Logs go to stderr (journald / launchd capture it). Never log secret values or
    // environment dumps.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter())
        .init();
}

/// A Windows service has no console: log to `<data dir>/credstored.log` (no secrets are
/// ever logged).
fn init_tracing_file(platform: &Platform) -> anyhow::Result<()> {
    credstore_os::fs::create_private_dir(platform.data_dir())
        .context("creating the data directory")?;
    let file = credstore_os::fs::open_append_private(&platform.data_dir().join("credstored.log"))
        .context("opening credstored.log")?;
    tracing_subscriber::fmt()
        .with_writer(std::sync::Mutex::new(file))
        .with_ansi(false)
        .with_env_filter(filter())
        .init();
    Ok(())
}
