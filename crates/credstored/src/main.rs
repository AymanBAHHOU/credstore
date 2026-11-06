//! credstored: the credstore daemon. Owns the vault, policy, audit log and runner.

use anyhow::Context;
use clap::Parser;
use credstore_os::{
    EndpointAccess, EndpointKind, FeatureStatus, Ipc, MemoryGuard, Mode, Paths, Platform,
    DEV_MODE_WARNING,
};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "credstored", version, about = "credstore daemon")]
struct Args {
    /// Run as the current user, without the service install. Weaker: see the threat model.
    #[arg(long)]
    dev: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let args = Args::parse();

    let mode = if args.dev { Mode::Dev } else { Mode::Installed };
    if mode == Mode::Dev {
        eprintln!("{DEV_MODE_WARNING}");
        tracing::warn!("{DEV_MODE_WARNING}");
    }

    let platform = Platform::new(mode).context("resolving credstore paths")?;
    tracing::info!(
        os = credstore_os::OS_NAME,
        ?mode,
        data_dir = %platform.data_dir().display(),
        "starting credstored"
    );

    for item in platform.harden_process() {
        match &item.status {
            FeatureStatus::Active => tracing::info!(feature = item.name, "hardening active"),
            FeatureStatus::Unavailable(reason) => {
                tracing::warn!(feature = item.name, %reason, "hardening unavailable")
            }
        }
    }

    let access = match mode {
        Mode::Dev => EndpointAccess::SameUser,
        Mode::Installed => EndpointAccess::Group("credstore-agents".into()),
    };
    let endpoint = platform.endpoint(EndpointKind::Agent);
    platform
        .bind(&endpoint, &access)
        .await
        .with_context(|| format!("binding agent endpoint {}", endpoint.address))?;
    Ok(())
}

fn init_tracing() {
    // Logs go to stderr. Never log secret values or environment dumps.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_env("CREDSTORE_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}
