//! `credstore policy-apply ID`: the administrator's step of a policy change made in the
//! app on a Windows install. The human entered the passphrase in the app (the daemon
//! checked the change and keeps it under ID), then Windows asked them to allow this
//! program to run as administrator. It writes the file the service may only read.
//!
//! The text comes from the daemon, which the pipe check proves is the credstore service,
//! never from the command line or a file the agent could change.

use std::path::Path;

use anyhow::{bail, Context};
use credstore_os::Paths;
use credstore_proto::{ApproverOp, Proof, Response};
use sha2::{Digest, Sha256};

use crate::client::{expect_ok, response_error, Client};

/// Exit codes the app turns into words.
pub const OK: i32 = 0;
pub const FAILED: i32 = 1;
/// The policy file changed after the change was made in the app.
pub const CHANGED_MEANWHILE: i32 = 3;
/// The change is gone (it timed out or a newer one replaced it).
pub const EXPIRED: i32 = 4;

/// Apply change `id`. Errors are written to `report` (a file the app reads) as well as
/// stderr, since the app runs this hidden.
pub async fn policy_apply(client: &Client, id: &str, report: Option<&Path>) -> i32 {
    let (code, message) = match apply(client, id).await {
        Ok(code) => (code, None),
        Err(e) => (FAILED, Some(format!("{e:#}"))),
    };
    if let Some(m) = &message {
        eprintln!("credstore: error: {m}");
    }
    if let Some(path) = report {
        let _ = std::fs::write(path, message.unwrap_or_default());
    }
    code
}

async fn apply(client: &Client, id: &str) -> anyhow::Result<i32> {
    let proof = || Proof::PolicyEdit(id.to_owned());
    let (text, base) = match client
        .approver_with(ApproverOp::TakePolicyEdit, proof())
        .await?
    {
        Response::PolicyEdit { text, base_sha256 } => (text, base_sha256),
        Response::Error { message, .. } if message.contains("expired") => return Ok(EXPIRED),
        other => return Err(response_error(other)),
    };
    let path = client.platform().policy_file();
    let current = match std::fs::read(path) {
        Ok(b) => credstore_proto::hex(&Sha256::digest(&b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => bail!("cannot read {}: {e}", path.display()),
    };
    if current != base {
        return Ok(CHANGED_MEANWHILE);
    }
    credstore_os::admin::write_admin_file(path, text.as_bytes()).with_context(|| {
        format!(
            "cannot write {} (this step needs administrator rights)",
            path.display()
        )
    })?;
    expect_ok(
        client
            .approver_with(ApproverOp::FinishPolicyEdit, proof())
            .await?,
    )?;
    Ok(OK)
}
