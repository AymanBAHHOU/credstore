//! What the desktop app does (M10), as plain data in and out.
//!
//! The app's UI layer only forwards calls here, so its behaviour is tested with the rest
//! of credstore (`tests/api_dev.rs`) against a real daemon. It talks to the daemon
//! exactly like the CLI: the same endpoints, a passphrase proof on every approver
//! operation, nothing cached. Passphrases and secret values come in as [`SecretText`]
//! and are never returned; every string that came from an agent goes through
//! `printable` (see [`crate::watch::describe`]) and must be shown as plain text.

use std::path::Path;

use anyhow::{bail, Context, Result};
use credstore_core::names;
use credstore_core::vault::{MIN_PASSPHRASE_LEN, MIN_REDACTABLE_LEN};
use credstore_os::{EndpointKind, Mode, Paths, OS_NAME};
use credstore_proto::{
    read_message, write_message, ActivityEntry, AgentRequest, ApproverOp, ApproverRequest,
    ErrorCode, Feed, GrantScope, PolicyInfo, Proof, RequestId, Response, SecretInfo, SecretText,
};
use serde::{Deserialize, Serialize};

use crate::client::{expect_ok, expect_status, response_error, Client};
use crate::commands::{printable, Prompt};
use crate::doctor::Report;
use crate::setup::{ClaudeCode, ClaudeState};
use crate::watch::{describe, RequestView};

/// The app's handle on credstore.
#[derive(Clone)]
pub struct Api {
    client: Client,
}

/// The first screen: is the daemon there, and what does it hold.
#[derive(Debug, Clone, Serialize)]
pub struct Overview {
    pub mode: &'static str,
    pub os: &'static str,
    pub version: &'static str,
    pub reachable: bool,
    /// Why the daemon could not be reached, with what to do.
    pub error: Option<String>,
    pub secrets: Vec<SecretInfo>,
    /// This user has a credstore key in Windows Hello (M13). The vault may not trust it
    /// (a key left from an older vault): compare `hello_key_id` with
    /// `Feed::approval_keys`.
    pub hello: bool,
    /// The id of that key, as the daemon names enrolled keys.
    pub hello_key_id: Option<String>,
    /// Windows Hello can be set up here (Windows, with Hello configured for this user).
    pub hello_available: bool,
}

/// How the app proves who it is when it starts watching.
pub enum Auth {
    Passphrase(SecretText),
    /// Windows shows its Hello dialog once; needs the vault unlocked.
    Hello,
}

/// The app's live view (see [`Api::feed`]). Every string that came from an agent or the
/// policy file went through `printable`.
#[derive(Debug, Clone, Serialize)]
pub struct FeedView {
    pub pending: Vec<RequestView>,
    pub activity: Vec<ActivityEntry>,
    pub policy: Option<PolicyInfo>,
    pub policy_error: Option<String>,
    pub locked: bool,
}

fn printable_all(v: &mut [String]) {
    for s in v {
        *s = printable(s);
    }
}

impl FeedView {
    fn new(f: Feed) -> Self {
        let mut activity = f.activity;
        for a in &mut activity {
            a.summary = printable(&a.summary);
            printable_all(&mut a.secrets);
            for s in [&mut a.detail, &mut a.host, &mut a.cwd, &mut a.via]
                .into_iter()
                .flatten()
            {
                *s = printable(s);
            }
        }
        let mut policy = f.policy;
        if let Some(p) = &mut policy {
            p.path = printable(&p.path);
            for r in &mut p.secrets {
                r.name = printable(&r.name);
                printable_all(&mut r.allow_hosts);
                for l in [&mut r.allow_commands, &mut r.allow_dirs]
                    .into_iter()
                    .flatten()
                {
                    printable_all(l);
                }
            }
        }
        Self {
            pending: f.pending.iter().map(describe).collect(),
            activity,
            policy,
            policy_error: f.policy_error.map(|e| printable(&e)),
            locked: f.locked,
        }
    }
}

/// What the human decided about a pending request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Decision {
    Once,
    Session { ttl_secs: u64 },
    Deny,
}

/// How a decision went. A wrong passphrase leaves the request pending.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Decided {
    Done,
    WrongPassphrase,
    RateLimited { message: String },
    Failed { message: String },
}

/// Result of saving a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Saved {
    /// Values this short are not redacted from output (too likely to match by chance).
    pub too_short_to_redact: bool,
}

impl Api {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    pub fn mode(&self) -> Mode {
        self.client.platform().mode()
    }

    pub async fn overview(&self) -> Overview {
        let mode = match self.mode() {
            Mode::Installed => "installed",
            Mode::Dev => "dev",
        };
        let (reachable, error, secrets) = match self.client.agent(&AgentRequest::ListSecrets).await
        {
            Ok(Response::Secrets { secrets }) => (true, None, secrets),
            Ok(other) => (false, Some(response_error(other).to_string()), Vec::new()),
            Err(e) => (
                false,
                Some(format!(
                    "{e:#}. If credstore was just installed, sign out and back in, or \
                     reinstall; the Health page shows what is wrong."
                )),
                Vec::new(),
            ),
        };
        let hello_key_id = credstore_os::approval_key::hello::public_key()
            .ok()
            .map(|k| credstore_os::approval_key::key_id(&k));
        Overview {
            mode,
            os: OS_NAME,
            version: env!("CARGO_PKG_VERSION"),
            reachable,
            error,
            secrets: secrets
                .into_iter()
                .map(|s| SecretInfo {
                    name: printable(&s.name),
                    description: printable(&s.description),
                })
                .collect(),
            hello: hello_key_id.is_some(),
            hello_key_id,
            hello_available: credstore_os::approval_key::supported()
                && credstore_os::approval_key::hello::available(),
        }
    }

    /// Change where a secret may be used (see [`ApproverOp::SetSecretRules`]).
    pub async fn set_secret_rules(
        &self,
        name: &str,
        allow_hosts: Option<Vec<String>>,
        allow_commands: Option<Vec<String>>,
        pass: SecretText,
    ) -> Result<()> {
        names::validate_name(name)?;
        expect_ok(
            self.client
                .approver(
                    ApproverOp::SetSecretRules {
                        name: name.to_owned(),
                        allow_hosts,
                        allow_commands,
                    },
                    pass,
                )
                .await?,
        )
    }

    /// Change the `[defaults]` timers.
    pub async fn set_defaults(
        &self,
        session_idle_secs: Option<u64>,
        grant_ttl_secs: Option<u64>,
        approval_timeout_secs: Option<u64>,
        pass: SecretText,
    ) -> Result<()> {
        expect_ok(
            self.client
                .approver(
                    ApproverOp::SetDefaults {
                        session_idle_secs,
                        grant_ttl_secs,
                        approval_timeout_secs,
                    },
                    pass,
                )
                .await?,
        )
    }

    /// Create a Windows Hello key (Windows asks the user) and enrol it in the vault.
    pub async fn hello_enrol(&self, pass: SecretText) -> Result<()> {
        if !credstore_os::approval_key::supported() {
            bail!("approval keys need Windows Hello; on this system approvals use the passphrase");
        }
        self.check_passphrase(pass.clone()).await?;
        let spki = tokio::task::spawn_blocking(credstore_os::approval_key::hello::create)
            .await
            .map_err(|e| anyhow::anyhow!("Windows Hello: {e}"))?
            .context("Windows Hello did not create the key")?;
        crate::approval::enrol(&self.client, &spki, &crate::approval::default_label(), pass)
            .await
            .map(drop)
    }

    /// Remove this user's Hello key from the vault and from Windows Hello.
    pub async fn hello_remove(&self, pass: SecretText) -> Result<()> {
        let spki = credstore_os::approval_key::hello::public_key()
            .context("no credstore key in Windows Hello")?;
        let id = credstore_os::approval_key::key_id(&spki);
        match crate::approval::remove(&self.client, &id, pass).await {
            Ok(()) => {}
            // Enrolled in another vault, or already removed: still delete it from Hello.
            Err(e) if e.to_string().contains("no approval key") => {}
            Err(e) => return Err(e),
        }
        tokio::task::spawn_blocking(credstore_os::approval_key::hello::delete)
            .await
            .map_err(|e| anyhow::anyhow!("Windows Hello: {e}"))??;
        Ok(())
    }

    /// Create the vault. `Ok(false)` if one already exists.
    pub async fn create_vault(&self, pass: SecretText, repeat: SecretText) -> Result<bool> {
        if pass.expose().chars().count() < MIN_PASSPHRASE_LEN {
            bail!("the passphrase must be at least {MIN_PASSPHRASE_LEN} characters");
        }
        if pass != repeat {
            bail!("the passphrases do not match");
        }
        match self.client.approver(ApproverOp::AdminInit, pass).await? {
            Response::Ok => Ok(true),
            Response::Error { message, .. } if message.contains("already exists") => Ok(false),
            other => Err(response_error(other)),
        }
    }

    /// Add or replace a secret.
    pub async fn set_secret(
        &self,
        name: &str,
        description: Option<String>,
        value: SecretText,
        pass: SecretText,
    ) -> Result<Saved> {
        names::validate_name(name)?;
        let description = description.filter(|d| !d.trim().is_empty());
        if let Some(d) = &description {
            names::validate_description(d)?;
        }
        names::validate_value(value.expose())?;
        let too_short_to_redact = value.expose().chars().count() < MIN_REDACTABLE_LEN;
        expect_ok(
            self.client
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
        Ok(Saved {
            too_short_to_redact,
        })
    }

    pub async fn remove_secret(&self, name: &str, pass: SecretText) -> Result<()> {
        names::validate_name(name)?;
        expect_ok(
            self.client
                .approver(
                    ApproverOp::AdminRm {
                        name: name.to_owned(),
                    },
                    pass,
                )
                .await?,
        )
    }

    /// Check a passphrase without changing anything.
    pub async fn check_passphrase(&self, pass: SecretText) -> Result<()> {
        expect_status(self.client.approver(ApproverOp::Status, pass).await?).map(drop)
    }

    pub async fn lock(&self, pass: SecretText) -> Result<()> {
        expect_ok(self.client.approver(ApproverOp::Lock, pass).await?)
    }

    /// Approve or deny one pending request.
    pub async fn decide(&self, id: &str, decision: Decision, pass: SecretText) -> Result<Decided> {
        let op = decision_op(id, decision);
        decided(self.client.approver(op, pass).await?)
    }

    /// Like [`Api::decide`], confirmed with Windows Hello (Windows shows its own dialog).
    /// The daemon refuses it while the vault is locked; the human then uses the
    /// passphrase.
    pub async fn decide_with_hello(&self, id: &str, decision: Decision) -> Result<Decided> {
        let op = decision_op(id, decision);
        let signed = op.clone();
        let proof = tokio::task::spawn_blocking(move || {
            crate::approval::key_proof(&crate::approval::Hello, &signed)
        })
        .await
        .map_err(|e| anyhow::anyhow!("Windows Hello: {e}"))?;
        let proof = match proof {
            Ok(p) => p,
            Err(e) => {
                return Ok(Decided::Failed {
                    message: printable(&format!("{e:#}")),
                })
            }
        };
        Ok(match self.client.approver_with(op, proof).await? {
            Response::Error {
                code: ErrorCode::Unauthorized,
                message,
            } => Decided::Failed {
                message: printable(&message),
            },
            other => decided(other)?,
        })
    }
}

fn decision_op(id: &str, decision: Decision) -> ApproverOp {
    let request_id = RequestId(id.to_owned());
    match decision {
        Decision::Once => ApproverOp::Approve {
            request_id,
            scope: GrantScope::Once,
        },
        Decision::Session { ttl_secs } => ApproverOp::Approve {
            request_id,
            scope: GrantScope::Session { ttl_secs },
        },
        Decision::Deny => ApproverOp::Deny { request_id },
    }
}

fn decided(resp: Response) -> Result<Decided> {
    Ok(match resp {
        Response::Ok => Decided::Done,
        Response::Error {
            code: ErrorCode::Unauthorized,
            ..
        } => Decided::WrongPassphrase,
        Response::Error {
            code: ErrorCode::RateLimited,
            message,
        } => Decided::RateLimited {
            message: printable(&message),
        },
        Response::Error { message, .. } => Decided::Failed {
            message: printable(&message),
        },
        other => return Err(response_error(other)),
    })
}

impl Api {
    /// Subscribe to pending requests and call `on_update` with the full list each time it
    /// changes. Returns when the connection ends (an error says why).
    pub async fn watch(
        &self,
        pass: SecretText,
        mut on_update: impl FnMut(Vec<RequestView>) + Send,
    ) -> Result<()> {
        let mut stream = self.client.connect(EndpointKind::Approver).await?;
        write_message(
            &mut stream,
            &ApproverRequest {
                proof: Proof::Passphrase(pass),
                op: ApproverOp::SubscribePending,
            },
        )
        .await
        .context("subscribing to pending requests")?;
        loop {
            let resp: Response = read_message(&mut stream)
                .await
                .context("lost the connection to credstored")?;
            match resp {
                Response::Pending { requests } => {
                    on_update(requests.iter().map(describe).collect());
                }
                other => return Err(response_error(other)),
            }
        }
    }

    /// Subscribe to the app's feed (pending requests, activity, policy) and call
    /// `on_update` each time it changes. Returns when the connection ends.
    pub async fn feed(&self, auth: Auth, mut on_update: impl FnMut(FeedView) + Send) -> Result<()> {
        let op = ApproverOp::SubscribeFeed;
        let proof = match auth {
            Auth::Passphrase(p) => Proof::Passphrase(p),
            Auth::Hello => {
                let signed = op.clone();
                tokio::task::spawn_blocking(move || {
                    crate::approval::key_proof(&crate::approval::Hello, &signed)
                })
                .await
                .map_err(|e| anyhow::anyhow!("Windows Hello: {e}"))??
            }
        };
        let mut stream = self.client.connect(EndpointKind::Approver).await?;
        write_message(&mut stream, &ApproverRequest { proof, op })
            .await
            .context("subscribing to credstored")?;
        loop {
            let resp: Response = read_message(&mut stream)
                .await
                .context("lost the connection to credstored")?;
            match resp {
                Response::Feed(f) => on_update(FeedView::new(*f)),
                other => return Err(response_error(other)),
            }
        }
    }

    /// The commands `grant` would run for `dir`, for showing before asking.
    pub fn grant_plan(&self, dir: &Path) -> Result<Vec<String>> {
        Ok(credstore_os::grant::plan(dir, self.mode())?
            .iter()
            .map(|s| s.display())
            .collect())
    }

    /// Let approved commands use `dir` (often nothing to do in dev mode).
    pub fn grant(&self, dir: &Path) -> Result<()> {
        credstore_os::grant::apply(&credstore_os::grant::plan(dir, self.mode())?)?;
        Ok(())
    }

    /// Run `doctor`. With a passphrase it includes the daemon's own sandbox and
    /// hardening report.
    pub async fn doctor(&self, pass: Option<SecretText>) -> Result<Report> {
        let prompt = Given(pass);
        crate::doctor::doctor(&self.client, &prompt, &mut std::io::sink()).await
    }

    /// Claude Code's state for this user, or `None` without a home directory.
    pub fn claude(&self) -> Result<Option<ClaudeState>> {
        ClaudeCode::detect().map(|c| c.state()).transpose()
    }

    /// Register credstore with Claude Code (if `claude` is on PATH and it is not
    /// registered yet) and add the missing deny rules.
    pub fn connect_claude(&self) -> Result<ClaudeState> {
        let c = ClaudeCode::detect().context("no home directory")?;
        let state = c.state()?;
        if !state.registered && state.found {
            c.register(self.mode() == Mode::Dev)?;
        }
        c.add_deny_rules()?;
        c.state()
    }
}

/// A prompt that answers with a passphrase given up front (or has no terminal).
struct Given(Option<SecretText>);

impl Prompt for Given {
    fn secret(&self, _: &str) -> Result<SecretText> {
        self.0.clone().context("no passphrase given")
    }
    fn has_terminal(&self) -> bool {
        self.0.is_some()
    }
}
