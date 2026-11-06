//! credstore: CLI for humans, plus `credstore mcp`, the stdio MCP shim for agents.
//!
//! Neither decrypts anything; both talk to `credstored`. Secret values are never accepted
//! on argv or from the CLI's own environment.

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use credstore_core::vault::Vault;
use credstore_os::{Mode, Paths, Platform, Terminal};
use credstore_proto::SecretText;
use tracing_subscriber::EnvFilter;

mod commands;

#[derive(Debug, Parser)]
#[command(
    name = "credstore",
    version,
    about = "Let agents use secrets without seeing them"
)]
struct Cli {
    /// Talk to a dev-mode daemon (`credstored --dev`) instead of the installed one.
    #[arg(long, global = true)]
    dev: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create the vault and index, and set the passphrase.
    Init,
    /// Add or replace a secret. The value is prompted for, never taken from argv.
    Set {
        name: String,
        #[arg(short = 'd', long = "description")]
        description: Option<String>,
    },
    /// List secret names and descriptions.
    List,
    /// Remove a secret.
    Rm { name: String },
    /// Run a command with secrets, approved in place with the passphrase.
    Run {
        #[arg(short = 's', long = "secrets", value_delimiter = ',', required = true)]
        secrets: Vec<String>,
        #[arg(long)]
        reason: Option<String>,
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },
    /// Approval TUI. Needs a real terminal.
    Watch,
    /// Relock the vault now and zeroize it in daemon memory.
    Lock,
    /// Show daemon status.
    Status,
    /// Reload the policy file.
    Reload,
    /// Show the audit log, or verify its hash chain.
    Audit {
        #[arg(long)]
        follow: bool,
        #[command(subcommand)]
        action: Option<AuditAction>,
    },
    /// MCP stdio server for agents (stdout carries only MCP traffic).
    Mcp,
    /// Check the install: users, permissions, endpoints, sandbox, hardening.
    Doctor,
}

#[derive(Debug, Subcommand)]
enum AuditAction {
    /// Re-walk the hash chain and report the first break.
    Verify,
}

fn main() -> ExitCode {
    init_tracing();
    let cli = Cli::parse();
    tracing::debug!(dev = cli.dev, "credstore starting");

    let milestone = match &cli.command {
        Command::Init | Command::Set { .. } | Command::List | Command::Rm { .. } => {
            return match vault_command(&cli) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("credstore: error: {e:#}");
                    ExitCode::FAILURE
                }
            };
        }
        Command::Audit { .. } | Command::Status | Command::Lock => "M2",
        Command::Reload => "M3",
        Command::Watch => "M4",
        Command::Run { .. } => "M5",
        Command::Mcp => "M6",
        Command::Doctor => "M7",
    };
    eprintln!("credstore: this command is not built yet ({milestone}).");
    ExitCode::from(2)
}

/// `init`, `set`, `list`, `rm` against the dev-mode vault (M1: no daemon yet).
fn vault_command(cli: &Cli) -> anyhow::Result<()> {
    if !cli.dev {
        anyhow::bail!(
            "installed mode needs the daemon, which is not built yet (M2). \
             Use --dev to work on the dev-mode vault."
        );
    }
    let platform = Platform::new(Mode::Dev)?;
    let vault = Vault::new(platform.vault_file(), platform.index_file());
    let prompt = TerminalPrompt(&platform);
    let mut msg = std::io::stderr();
    match &cli.command {
        Command::Init => commands::init(&vault, &prompt, &mut msg),
        Command::Set { name, description } => {
            commands::set(&vault, name, description.clone(), &prompt, &mut msg)
        }
        Command::List => commands::list(&vault, &mut std::io::stdout(), &mut msg),
        Command::Rm { name } => commands::rm(&vault, name, &prompt, &mut msg),
        _ => unreachable!("not a vault command"),
    }
}

/// Reads hidden input from the controlling terminal, never from stdin.
struct TerminalPrompt<'a>(&'a Platform);

impl commands::Prompt for TerminalPrompt<'_> {
    fn secret(&self, prompt: &str) -> anyhow::Result<SecretText> {
        if !self.0.has_terminal() {
            anyhow::bail!("this command needs a terminal to read hidden input");
        }
        Ok(self.0.read_passphrase(prompt)?)
    }
}

fn init_tracing() {
    // stderr only: stdout belongs to command output and, for `mcp`, the MCP protocol.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_env("CREDSTORE_LOG").unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn set_has_no_value_argument() {
        // `credstore set NAME VALUE` must be rejected: values never come from argv.
        assert!(Cli::try_parse_from(["credstore", "set", "KEY", "sk_test_value"]).is_err());
        assert!(Cli::try_parse_from(["credstore", "set", "KEY", "-d", "desc"]).is_ok());
    }

    #[test]
    fn run_parses_secrets_and_argv() {
        let cli = Cli::try_parse_from([
            "credstore",
            "run",
            "-s",
            "A,B",
            "--reason",
            "why",
            "--",
            "curl",
            "-s",
            "x",
        ])
        .unwrap();
        match cli.command {
            Command::Run {
                secrets,
                reason,
                argv,
            } => {
                assert_eq!(secrets, ["A", "B"]);
                assert_eq!(reason.as_deref(), Some("why"));
                assert_eq!(argv, ["curl", "-s", "x"]);
            }
            other => panic!("parsed as {other:?}"),
        }
    }
}
