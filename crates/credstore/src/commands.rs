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
    let first = p.secret("New vault passphrase: ")?;
    if first.expose().chars().count() < MIN_PASSPHRASE_LEN {
        bail!("the passphrase must be at least {MIN_PASSPHRASE_LEN} characters");
    }
    let second = p.secret("Repeat the passphrase: ")?;
    if first != second {
        bail!("the passphrases do not match");
    }
    expect_ok(client.approver(ApproverOp::AdminInit, first).await?)?;
    writeln!(msg, "Created the vault.")?;
    writeln!(
        msg,
        "There is no way to recover the vault without this passphrase."
    )?;
    Ok(())
}

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

pub(crate) fn printable(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}
