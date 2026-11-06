//! `credstore watch`: the approval screen (spec 6.3).
//!
//! Every answer is typed on the controlling terminal (`Prompt` reads `/dev/tty` or the
//! Windows console, never stdin), and every approval or denial sends a fresh passphrase
//! proof, so an agent that can write to this process's stdin cannot approve anything.

use std::collections::HashSet;
use std::io::Write;

use anyhow::{bail, Context};
use credstore_os::EndpointKind;
use credstore_proto::{
    read_message, write_message, ApproverOp, ApproverRequest, ErrorCode, GrantScope,
    PendingRequest, Proof, Response,
};

use crate::client::{response_error, Client};
use crate::commands::{printable, Prompt};

pub const NO_TERMINAL: &str = "credstore watch needs a terminal: approvals are typed on the \
terminal, never read from stdin";

/// Show pending requests as they arrive and ask the human about each one. Runs until the
/// connection drops or input fails (Ctrl-C ends the process).
pub async fn watch(client: &Client, p: &dyn Prompt, out: &mut dyn Write) -> anyhow::Result<()> {
    if !p.has_terminal() {
        bail!(NO_TERMINAL);
    }
    let passphrase = p.secret("Vault passphrase: ")?;
    let mut stream = client.connect(EndpointKind::Approver).await?;
    write_message(
        &mut stream,
        &ApproverRequest {
            proof: Proof { passphrase },
            op: ApproverOp::SubscribePending,
        },
    )
    .await
    .context("subscribing to pending requests")?;

    let mut first = true;
    let mut handled: HashSet<String> = HashSet::new();
    loop {
        let resp: Response = read_message(&mut stream)
            .await
            .context("lost the connection to credstored")?;
        let requests = match resp {
            Response::Pending { requests } => requests,
            other => return Err(response_error(other)),
        };
        if first {
            writeln!(out, "Watching for requests. Press Ctrl-C to stop.")?;
            first = false;
        }
        handled.retain(|id| requests.iter().any(|r| &r.id.0 == id));
        for req in requests {
            if handled.insert(req.id.0.clone()) {
                show(&req, out)?;
                decide(client, p, &req, out).await?;
            }
        }
    }
}

/// Print everything the human needs to decide. All agent-supplied text goes through
/// `printable`, so control characters can't redraw the screen.
pub fn show(r: &PendingRequest, out: &mut dyn Write) -> anyhow::Result<()> {
    writeln!(out)?;
    writeln!(out, "=== Request {} ===", printable(&r.id.0))?;
    writeln!(out, "reason:   {}", printable(&r.reason))?;
    match (&r.argv, &r.shell) {
        (Some(argv), _) => {
            let line: Vec<String> = argv.iter().map(|a| quote(a)).collect();
            writeln!(out, "command:  {}", line.join(" "))?;
        }
        (None, Some(shell)) => writeln!(out, "shell:    {}", printable(shell))?,
        (None, None) => {}
    }
    if let Some(prog) = &r.program {
        writeln!(out, "program:  {}", printable(prog))?;
    }
    writeln!(out, "cwd:      {}", printable(&r.cwd))?;
    let secrets: Vec<String> = r
        .secrets
        .iter()
        .map(|s| {
            if s.description.is_empty() {
                s.name.clone()
            } else {
                format!("{} ({})", s.name, printable(&s.description))
            }
        })
        .collect();
    writeln!(out, "secrets:  {}", secrets.join(", "))?;
    writeln!(
        out,
        "inject:   {}",
        credstore_core::policy::injection_name(r.injection)
    )?;
    let sandbox = serde_json::to_value(r.sandbox)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    let network = serde_json::to_value(r.network)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    let hosts = if r.allow_hosts.is_empty() {
        String::new()
    } else {
        format!(" ({})", printable(&r.allow_hosts.join(", ")))
    };
    writeln!(out, "sandbox:  {sandbox}    network: {network}{hosts}")?;
    for gap in &r.sandbox_gaps {
        writeln!(out, "  NOT ENFORCED: {}", printable(gap))?;
    }
    let mut from = Vec::new();
    if let Some(uid) = r.peer.uid {
        from.push(format!("uid {uid}"));
    }
    if let Some(sid) = &r.peer.sid {
        from.push(format!("sid {}", printable(sid)));
    }
    if let Some(pid) = r.peer.pid {
        from.push(format!("pid {pid}"));
    }
    if let Some(exe) = &r.peer.exe {
        from.push(format!("exe {}", printable(exe)));
    }
    writeln!(out, "from:     {}", from.join(", "))?;
    Ok(())
}

async fn decide(
    client: &Client,
    p: &dyn Prompt,
    r: &PendingRequest,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    let session = r.max_grant_secs > 0;
    let question = if session {
        format!(
            "Approve [o]nce, for this [s]ession ({}), or [d]eny? ",
            duration(r.max_grant_secs)
        )
    } else {
        "Approve [o]nce or [d]eny? ".to_string()
    };
    loop {
        let answer = p.line(&question)?.trim().to_ascii_lowercase();
        let (op, done) = match answer.as_str() {
            "o" | "once" => (
                ApproverOp::Approve {
                    request_id: r.id.clone(),
                    scope: GrantScope::Once,
                },
                "Approved once.",
            ),
            "s" | "session" if session => (
                ApproverOp::Approve {
                    request_id: r.id.clone(),
                    scope: GrantScope::Session {
                        ttl_secs: r.max_grant_secs,
                    },
                },
                "Approved for this session.",
            ),
            "d" | "deny" => (
                ApproverOp::Deny {
                    request_id: r.id.clone(),
                },
                "Denied.",
            ),
            _ => {
                writeln!(out, "Type o, {}or d.", if session { "s " } else { "" })?;
                continue;
            }
        };
        let passphrase = p.secret("Passphrase to confirm: ")?;
        match client.approver(op, passphrase).await? {
            Response::Ok => {
                writeln!(out, "{done}")?;
                return Ok(());
            }
            Response::Error {
                code: ErrorCode::Unauthorized,
                ..
            } => writeln!(out, "Wrong passphrase. The request is still pending.")?,
            Response::Error {
                code: ErrorCode::RateLimited,
                message,
            } => writeln!(out, "{message}. The request is still pending.")?,
            Response::Error { message, .. } => {
                writeln!(out, "Could not decide: {}", printable(&message))?;
                return Ok(());
            }
            other => return Err(response_error(other)),
        }
    }
}

/// Display form of one argument: quoted when it has spaces, quotes or nothing in it.
fn quote(a: &str) -> String {
    let a = printable(a);
    if !a.is_empty() && !a.contains([' ', '\t', '"', '\'']) {
        a
    } else {
        format!("\"{}\"", a.replace('"', "\\\""))
    }
}

fn duration(secs: u64) -> String {
    match secs {
        s if s % 3600 == 0 => format!("{} h", s / 3600),
        s if s % 60 == 0 => format!("{} min", s / 60),
        s => format!("{s} s"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_and_durations() {
        assert_eq!(quote("plain"), "plain");
        assert_eq!(quote("two words"), "\"two words\"");
        assert_eq!(quote(""), "\"\"");
        assert_eq!(quote("a\x1b[2Jb"), "a?[2Jb");
        assert_eq!(duration(600), "10 min");
        assert_eq!(duration(7200), "2 h");
        assert_eq!(duration(90), "90 s");
    }
}
