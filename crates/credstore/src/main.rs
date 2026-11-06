//! credstore: CLI for humans, plus `credstore mcp`, the stdio MCP shim for agents.
//!
//! Neither decrypts anything; both talk to `credstored`. Secret values are never accepted
//! on argv or from the CLI's own environment.

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use credstore::client::Client;
use credstore::commands::{self, Prompt};
use credstore_os::{Mode, Paths, Platform, Terminal};
use credstore_proto::SecretText;
use tracing_subscriber::EnvFilter;

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
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("credstore: error: {e}");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(run(cli)) {
        Ok(0) => ExitCode::SUCCESS,
        Ok(code) => ExitCode::from(u8::try_from(code).ok().filter(|c| *c != 0).unwrap_or(1)),
        Err(e) => {
            eprintln!("credstore: error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// Returns the process exit code (the child's, for `credstore run`).
async fn run(cli: Cli) -> anyhow::Result<i32> {
    let mode = if cli.dev { Mode::Dev } else { Mode::Installed };
    let platform = Platform::new(mode)?;
    let client = Client::new(platform.clone());
    let prompt = TerminalPrompt(&platform);
    let mut msg = std::io::stderr();
    let mut out = std::io::stdout();
    let done = match cli.command {
        Command::Run {
            secrets,
            reason,
            argv,
        } => {
            return commands::run(&client, secrets, reason, argv, &prompt, &mut out, &mut msg).await
        }
        Command::Init => commands::init(&client, &prompt, &mut msg).await,
        Command::Set { name, description } => {
            commands::set(&client, &name, description, &prompt, &mut msg).await
        }
        Command::List => commands::list(&client, &mut out, &mut msg).await,
        Command::Rm { name } => commands::rm(&client, &name, &prompt, &mut msg).await,
        Command::Lock => commands::lock(&client, &prompt, &mut msg).await,
        Command::Status => commands::status(&client, &prompt, &mut out).await,
        Command::Reload => commands::reload(&client, &prompt, &mut msg).await,
        Command::Audit { follow, action } => match (action, follow) {
            (Some(AuditAction::Verify), _) => {
                commands::audit_verify(platform.audit_log(), &mut out)
            }
            (None, true) => commands::audit_follow(platform.audit_log(), &mut out),
            (None, false) => commands::audit_show(platform.audit_log(), &mut out),
        },
        Command::Watch => credstore::watch::watch(&client, &prompt, &mut out).await,
        Command::Mcp => credstore::mcp::serve(client).await,
        Command::Doctor => {
            let report = credstore::doctor::doctor(&client, &prompt, &mut out).await?;
            return Ok(i32::from(report.failures() > 0));
        }
    };
    done.map(|()| 0)
}

/// Reads hidden input from the controlling terminal, never from stdin.
struct TerminalPrompt<'a>(&'a Platform);

impl Prompt for TerminalPrompt<'_> {
    fn secret(&self, prompt: &str) -> anyhow::Result<SecretText> {
        if !self.0.has_terminal() {
            anyhow::bail!("this command needs a terminal to read hidden input");
        }
        Ok(self.0.read_passphrase(prompt)?)
    }

    fn line(&self, prompt: &str) -> anyhow::Result<String> {
        Ok(self.0.read_line(prompt)?)
    }

    fn has_terminal(&self) -> bool {
        self.0.has_terminal()
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
