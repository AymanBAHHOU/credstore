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

/// Everything the human needs to decide, as display text. All agent-supplied text goes
/// through `printable`, so control characters cannot redraw a terminal; the desktop app
/// shows these strings as plain text, never as markup.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RequestView {
    pub id: String,
    pub reason: String,
    /// The argv, quoted, or the shell string.
    pub command: String,
    pub is_shell: bool,
    pub program: Option<String>,
    pub cwd: String,
    /// `NAME` or `NAME (description)`.
    pub secrets: Vec<String>,
    pub injection: String,
    pub sandbox: String,
    /// The network rule, with allowed hosts if any.
    pub network: String,
    /// What policy asked for that this run will not get.
    pub not_enforced: Vec<String>,
    /// Who asked: uid or SID, pid, executable.
    pub from: String,
    /// Longest "approve for this session"; 0 means once only.
    pub max_grant_secs: u64,
    pub max_grant: String,
    /// Set for an HTTP request the daemon would send (then `command` is "METHOD URL").
    pub http: Option<HttpView>,
}

/// An HTTP request the daemon would send with the secret in one header.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct HttpView {
    pub method: String,
    pub url: String,
    /// The header that carries the secret, with `{value}` in its place.
    pub secret_header: String,
    /// Other headers, as `Name: value`.
    pub headers: Vec<String>,
    /// `N bytes: <start of the body>`, if there is a body.
    pub body: Option<String>,
}

pub fn describe(r: &PendingRequest) -> RequestView {
    let http = r.http.as_ref().map(|h| HttpView {
        method: printable(&h.method),
        url: printable(&h.url),
        secret_header: printable(&h.header_template),
        headers: h
            .headers
            .iter()
            .map(|x| printable(&format!("{}: {}", x.name, x.value)))
            .collect(),
        body: h.body_bytes.map(|n| {
            format!(
                "{n} bytes: {}",
                printable(h.body_preview.as_deref().unwrap_or(""))
            )
        }),
    });
    let (command, is_shell) = match (&r.argv, &r.shell) {
        _ if http.is_some() => {
            let h = http.as_ref().map(|h| format!("{} {}", h.method, h.url));
            (h.unwrap_or_default(), false)
        }
        (Some(argv), _) => (
            argv.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" "),
            false,
        ),
        (None, Some(shell)) => (printable(shell), true),
        (None, None) => (String::new(), false),
    };
    let secrets = r
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
    let label = |v: serde_json::Result<serde_json::Value>| {
        v.ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default()
    };
    let mut network = label(serde_json::to_value(r.network));
    if !r.allow_hosts.is_empty() {
        network.push_str(&format!(" ({})", printable(&r.allow_hosts.join(", "))));
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
    RequestView {
        id: printable(&r.id.0),
        reason: printable(&r.reason),
        command,
        is_shell,
        program: r.program.as_deref().map(printable),
        cwd: printable(&r.cwd),
        secrets,
        injection: credstore_core::policy::injection_name(r.injection).to_owned(),
        sandbox: label(serde_json::to_value(r.sandbox)),
        network,
        not_enforced: r.sandbox_gaps.iter().map(|g| printable(g)).collect(),
        from: from.join(", "),
        max_grant_secs: r.max_grant_secs,
        max_grant: if r.max_grant_secs > 0 {
            duration(r.max_grant_secs)
        } else {
            String::new()
        },
        http,
    }
}

/// Print everything the human needs to decide.
pub fn show(r: &PendingRequest, out: &mut dyn Write) -> anyhow::Result<()> {
    let v = describe(r);
    writeln!(out)?;
    writeln!(out, "=== Request {} ===", v.id)?;
    writeln!(out, "reason:   {}", v.reason)?;
    if let Some(h) = &v.http {
        writeln!(out, "http:     {} {}", h.method, h.url)?;
        writeln!(
            out,
            "secret:   {}  (credstored sends it; the agent never sees it)",
            v.secrets.join(", ")
        )?;
        writeln!(out, "header:   {}", h.secret_header)?;
        for line in &h.headers {
            writeln!(out, "  also:   {line}")?;
        }
        if let Some(body) = &h.body {
            writeln!(out, "body:     {body}")?;
        }
        writeln!(out, "hosts:    {}", v.network)?;
        writeln!(out, "from:     {}", v.from)?;
        return Ok(());
    }
    if !v.command.is_empty() {
        let label = if v.is_shell { "shell:   " } else { "command: " };
        writeln!(out, "{label} {}", v.command)?;
    }
    if let Some(prog) = &v.program {
        writeln!(out, "program:  {prog}")?;
    }
    writeln!(out, "cwd:      {}", v.cwd)?;
    writeln!(out, "secrets:  {}", v.secrets.join(", "))?;
    writeln!(out, "inject:   {}", v.injection)?;
    writeln!(out, "sandbox:  {}    network: {}", v.sandbox, v.network)?;
    for gap in &v.not_enforced {
        writeln!(out, "  NOT ENFORCED: {gap}")?;
    }
    writeln!(out, "from:     {}", v.from)?;
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
pub(crate) fn quote(a: &str) -> String {
    let a = printable(a);
    if !a.is_empty() && !a.contains([' ', '\t', '"', '\'']) {
        a
    } else {
        format!("\"{}\"", a.replace('"', "\\\""))
    }
}

pub(crate) fn duration(secs: u64) -> String {
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
