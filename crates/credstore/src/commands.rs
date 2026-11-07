//! CLI commands. Everything that touches the vault goes through the daemon; the CLI
//! never decrypts anything (decision 3 in docs/DESIGN.md).
//!
//! `msg` gets human-facing messages (stderr in the binary); `out` gets command output.

use std::io::{BufRead, Write};
use std::path::Path;

use anyhow::{bail, Context};
use credstore_core::names;
use credstore_core::vault::{MIN_PASSPHRASE_LEN, MIN_REDACTABLE_LEN};
use credstore_proto::{AgentRequest, ApproverOp, Response, SecretText};

use crate::client::{expect_ok, expect_status, response_error, Client};

/// Source of input. The binary reads the controlling terminal (never stdin); tests
/// script it.
pub trait Prompt {
    /// Hidden input.
    fn secret(&self, prompt: &str) -> anyhow::Result<SecretText>;
    /// Visible input.
    fn line(&self, prompt: &str) -> anyhow::Result<String> {
        let _ = prompt;
        bail!("no terminal input available")
    }
    /// Whether there is a terminal to read from.
    fn has_terminal(&self) -> bool {
        true
    }
}

pub async fn init(client: &Client, p: &dyn Prompt, msg: &mut dyn Write) -> anyhow::Result<()> {
    if !create_vault(client, p).await? {
        bail!("a vault already exists");
    }
    writeln!(msg, "Created the vault.")?;
    writeln!(
        msg,
        "There is no way to recover the vault without this passphrase."
    )?;
    writeln!(msg, "{MCP_HINT}")?;
    Ok(())
}

/// Ask for a new passphrase (twice) and create the vault. `Ok(false)` if a vault
/// already exists.
pub async fn create_vault(client: &Client, p: &dyn Prompt) -> anyhow::Result<bool> {
    let first = p.secret("New vault passphrase: ")?;
    if first.expose().chars().count() < MIN_PASSPHRASE_LEN {
        bail!("the passphrase must be at least {MIN_PASSPHRASE_LEN} characters");
    }
    let second = p.secret("Repeat the passphrase: ")?;
    if first != second {
        bail!("the passphrases do not match");
    }
    match client.approver(ApproverOp::AdminInit, first).await? {
        Response::Ok => Ok(true),
        Response::Error { message, .. } if message.contains("already exists") => Ok(false),
        other => Err(crate::client::response_error(other)),
    }
}

/// `credstore grant DIR`: let the service account (which runs approved commands) read
/// and write `dir`. Shows the OS commands, asks, then runs them as the user.
pub fn grant(
    dir: &Path,
    yes: bool,
    dev: bool,
    p: &dyn Prompt,
    msg: &mut dyn Write,
) -> anyhow::Result<()> {
    if dev {
        writeln!(
            msg,
            "dev mode: approved commands run as you, so there is nothing to grant."
        )?;
        return Ok(());
    }
    let steps = credstore_os::grant::plan(dir)?;
    writeln!(
        msg,
        "To let approved commands read and write {}, credstore will run (as you):",
        dir.display()
    )?;
    for s in &steps {
        writeln!(msg, "  {}", s.display())?;
    }
    if !yes {
        if !p.has_terminal() {
            bail!("`credstore grant` asks first and needs a terminal; or pass --yes");
        }
        let answer = p.line("Go ahead? [Y/n] ")?;
        if !matches!(
            answer.trim().to_ascii_lowercase().as_str(),
            "" | "y" | "yes"
        ) {
            writeln!(msg, "Nothing changed.")?;
            return Ok(());
        }
    }
    credstore_os::grant::apply(&steps)?;
    writeln!(msg, "Done.")?;
    Ok(())
}

/// How to connect an agent, printed by `init` and the installers.
pub const MCP_HINT: &str = "Register the MCP server with Claude Code:
  claude mcp add credstore -- credstore mcp            (installed)
  claude mcp add credstore -- credstore --dev mcp      (dev mode)
Do not allowlist its tools, so Claude Code asks you too.";

pub async fn set(
    client: &Client,
    name: &str,
    description: Option<String>,
    p: &dyn Prompt,
    msg: &mut dyn Write,
) -> anyhow::Result<()> {
    names::validate_name(name)?;
    if let Some(d) = &description {
        names::validate_description(d)?;
    }
    let pass = p.secret("Vault passphrase: ")?;
    // Check the passphrase before asking for the value.
    expect_status(client.approver(ApproverOp::Status, pass.clone()).await?)?;
    let value = p.secret(&format!("Value for {name} (input hidden): "))?;
    names::validate_value(value.expose())?;
    let short = value.expose().chars().count() < MIN_REDACTABLE_LEN;
    expect_ok(
        client
            .approver(
                ApproverOp::AdminSet {
                    name: name.to_owned(),
                    description,
                    value,
                },
                pass,
            )
            .await?,
    )?;
    writeln!(msg, "Saved {name}.")?;
    if short {
        writeln!(
            msg,
            "warning: values shorter than {MIN_REDACTABLE_LEN} characters are too short to \
             redact safely, so {name} will not be masked in command output."
        )?;
    }
    Ok(())
}

pub async fn list(client: &Client, out: &mut dyn Write, msg: &mut dyn Write) -> anyhow::Result<()> {
    let infos = match client.agent(&AgentRequest::ListSecrets).await? {
        Response::Secrets { secrets } => secrets,
        other => return Err(response_error(other)),
    };
    if infos.is_empty() {
        writeln!(msg, "No secrets yet. Add one with `credstore set NAME`.")?;
        return Ok(());
    }
    let width = infos.iter().map(|i| i.name.len()).max().unwrap_or(0);
    for i in infos {
        // Never print control characters (the index is a plain file).
        writeln!(
            out,
            "{:width$}  {}",
            printable(&i.name),
            printable(&i.description)
        )?;
    }
    Ok(())
}

pub async fn rm(
    client: &Client,
    name: &str,
    p: &dyn Prompt,
    msg: &mut dyn Write,
) -> anyhow::Result<()> {
    names::validate_name(name)?;
    let pass = p.secret("Vault passphrase: ")?;
    expect_ok(
        client
            .approver(
                ApproverOp::AdminRm {
                    name: name.to_owned(),
                },
                pass,
            )
            .await?,
    )?;
    writeln!(msg, "Removed {name}.")?;
    Ok(())
}

pub async fn lock(client: &Client, p: &dyn Prompt, msg: &mut dyn Write) -> anyhow::Result<()> {
    let pass = p.secret("Vault passphrase: ")?;
    expect_ok(client.approver(ApproverOp::Lock, pass).await?)?;
    writeln!(msg, "Locked. The vault is no longer in daemon memory.")?;
    Ok(())
}

pub async fn status(client: &Client, p: &dyn Prompt, out: &mut dyn Write) -> anyhow::Result<()> {
    let pass = p.secret("Vault passphrase: ")?;
    let s = expect_status(client.approver(ApproverOp::Status, pass).await?)?;
    writeln!(
        out,
        "vault:   {}\nmode:    {}\npending: {}",
        if s.locked { "locked" } else { "unlocked" },
        if s.dev_mode {
            "dev (weaker)"
        } else {
            "installed"
        },
        s.pending
    )?;
    match &s.policy_error {
        None => writeln!(out, "policy:  ok")?,
        Some(e) => writeln!(out, "policy:  NOT LOADED, every run is denied: {e}")?,
    }
    Ok(())
}

/// Reason sent with `credstore run` when the human gives none.
pub const DEFAULT_RUN_REASON: &str = "Run by the human from a terminal with credstore run";

/// `credstore run`: the passphrase typed here is the approval. Prints the (redacted)
/// output and returns the command's exit code.
pub async fn run(
    client: &Client,
    secrets: Vec<String>,
    reason: Option<String>,
    argv: Vec<String>,
    p: &dyn Prompt,
    out: &mut dyn Write,
    msg: &mut dyn Write,
) -> anyhow::Result<i32> {
    let cwd = std::env::current_dir()?;
    let req = credstore_proto::RunRequest {
        argv: Some(argv),
        shell: None,
        secrets,
        reason: reason.unwrap_or_else(|| DEFAULT_RUN_REASON.to_owned()),
        cwd: cwd.to_string_lossy().into_owned(),
        timeout_secs: None,
        injection: None,
    };
    let pass = p.secret("Vault passphrase to run this command: ")?;
    match client.approver(ApproverOp::AdminRun(req), pass).await? {
        Response::RunResult(r) => {
            out.write_all(r.stdout.as_bytes())?;
            out.flush()?;
            msg.write_all(r.stderr.as_bytes())?;
            if r.truncated {
                writeln!(msg, "credstore: output was truncated")?;
            }
            if r.redactions > 0 {
                writeln!(
                    msg,
                    "credstore: {} secret value(s) were redacted from the output",
                    r.redactions
                )?;
            }
            Ok(r.exit_code.unwrap_or(1))
        }
        Response::Denied { reason } => anyhow::bail!("denied: {reason}"),
        other => {
            expect_ok(other)?;
            anyhow::bail!("unexpected reply from the daemon")
        }
    }
}

pub async fn reload(client: &Client, p: &dyn Prompt, msg: &mut dyn Write) -> anyhow::Result<()> {
    let pass = p.secret("Vault passphrase: ")?;
    expect_ok(client.approver(ApproverOp::Reload, pass).await?)?;
    writeln!(msg, "Policy reloaded.")?;
    Ok(())
}

/// Print the audit log.
pub fn audit_show(path: &Path, out: &mut dyn Write) -> anyhow::Result<()> {
    let f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    for line in std::io::BufReader::new(f).lines() {
        writeln!(out, "{}", printable(&line?))?;
    }
    Ok(())
}

/// Print the audit log, then keep printing new lines.
pub fn audit_follow(path: &Path, out: &mut dyn Write) -> anyhow::Result<()> {
    use std::io::{Seek, SeekFrom};
    let mut f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut pos = 0u64;
    let mut pending = String::new();
    loop {
        let len = f.metadata()?.len();
        if len < pos {
            pos = 0; // rotated or truncated
        }
        if len > pos {
            f.seek(SeekFrom::Start(pos))?;
            let mut chunk = String::new();
            std::io::Read::read_to_string(&mut f, &mut chunk)?;
            pos = len;
            pending.push_str(&chunk);
            while let Some(i) = pending.find('\n') {
                let line: String = pending.drain(..=i).collect();
                writeln!(out, "{}", printable(line.trim_end()))?;
            }
            out.flush()?;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

/// Re-walk the chain. Errors (non-zero exit) on a break.
pub fn audit_verify(path: &Path, out: &mut dyn Write) -> anyhow::Result<()> {
    let f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let report = credstore_core::audit::verify(std::io::BufReader::new(f))?;
    match report.first_break {
        None => {
            writeln!(out, "ok: {} records, chain intact", report.entries)?;
            Ok(())
        }
        Some(b) => {
            writeln!(
                out,
                "BROKEN at line {}: {} ({} valid records before it)",
                b.line, b.reason, report.entries
            )?;
            bail!("the audit log failed verification")
        }
    }
}

pub fn printable(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}
