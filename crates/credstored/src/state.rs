//! Daemon state and request handling (everything except socket plumbing).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use credstore_core::audit::AuditLog;
use credstore_core::policy::Policy;

use crate::approvals::{Approvals, Job};
use credstore_core::vault::{Vault, VaultContents, VaultError};
use credstore_os::{exec, Mode, Paths, Platform};
use credstore_proto::{
    AgentRequest, ApproverOp, ApproverRequest, ErrorCode, KeyProof, PeerInfo, Proof, Response,
    SecretText, StatusInfo,
};
use serde_json::{json, Map, Value};

/// Failed passphrase attempts allowed before a lockout.
pub const MAX_FAILURES: u32 = 5;
/// First lockout; doubles after each further lockout until a correct passphrase.
pub const FIRST_LOCKOUT: Duration = Duration::from_secs(60);
/// How far an approval-key signature's time may be from the daemon's clock.
pub const KEY_PROOF_WINDOW_SECS: u64 = 60;

pub(crate) struct State {
    pub platform: Platform,
    pub vault: Vault,
    audit: Mutex<AuditLog>,
    /// Serializes passphrase checks and vault writes (no lost updates, and the rate
    /// limit counts attempts one at a time).
    vault_ops: tokio::sync::Mutex<()>,
    pub(crate) unlocked: Mutex<Option<Unlocked>>,
    limiter: Mutex<RateLimiter>,
    /// Nonces of approval-key proofs seen in the last two windows (no replays).
    key_nonces: Mutex<HashMap<String, Instant>>,
    pub idle_ttl: Mutex<Duration>,
    /// Loaded policy, or why it could not be loaded (then every run is denied).
    pub(crate) policy: Mutex<Result<Arc<Policy>, String>>,
    /// Where bare program names are looked up.
    pub(crate) search_path: Vec<PathBuf>,
    pub(crate) approvals: Mutex<Approvals>,
    /// Bumped whenever the pending list changes; `watch` subscribers wait on it.
    pub(crate) pending_version: tokio::sync::watch::Sender<u64>,
    /// Bumped on every audit record and pending change; the app's feed waits on it.
    pub(crate) feed_version: tokio::sync::watch::Sender<u64>,
    /// Commands running now. The idle relock waits for them.
    pub(crate) active_runs: std::sync::atomic::AtomicUsize,
    /// What `harden_process` applied (set by the binary; empty in tests).
    pub(crate) hardening: Mutex<Vec<credstore_proto::HardeningReport>>,
    /// A policy change waiting for the admin helper to write it (Windows installs).
    pub(crate) policy_edit: Mutex<Option<crate::feed::PendingPolicyEdit>>,
}

/// With `session_idle_secs = 0` the runner relocks right after each run; the background
/// ticker only catches a vault left unlocked with no run (for example after `unlock`).
const ZERO_TTL_GRACE: Duration = Duration::from_secs(5);

pub(crate) struct Unlocked {
    pub contents: VaultContents,
    pub last_used: Instant,
}

impl Drop for Unlocked {
    fn drop(&mut self) {
        self.contents.wipe();
    }
}

/// 5 failures, then 60 s lockout, doubling.
#[derive(Debug)]
pub(crate) struct RateLimiter {
    failures: u32,
    locked_until: Option<Instant>,
    next_lockout: Duration,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            failures: 0,
            locked_until: None,
            next_lockout: FIRST_LOCKOUT,
        }
    }

    /// Seconds left in a lockout, if any.
    pub fn locked_out(&self, now: Instant) -> Option<u64> {
        self.locked_until
            .filter(|t| *t > now)
            .map(|t| (t - now).as_secs().max(1))
    }

    pub fn failure(&mut self, now: Instant) {
        self.failures += 1;
        if self.failures >= MAX_FAILURES {
            self.locked_until = Some(now + self.next_lockout);
            self.next_lockout *= 2;
            self.failures = 0;
        }
    }

    pub fn success(&mut self) {
        *self = Self::new();
    }
}

pub(crate) fn error(code: ErrorCode, message: impl Into<String>) -> Response {
    Response::Error {
        code,
        message: message.into(),
    }
}

pub(crate) fn peer_json(peer: &PeerInfo) -> Value {
    serde_json::to_value(peer).unwrap_or(Value::Null)
}

fn fields(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

impl State {
    pub fn new(platform: Platform, audit: AuditLog) -> Self {
        let vault = Vault::new(platform.vault_file(), platform.index_file());
        Self {
            platform,
            vault,
            audit: Mutex::new(audit),
            vault_ops: tokio::sync::Mutex::new(()),
            unlocked: Mutex::new(None),
            limiter: Mutex::new(RateLimiter::new()),
            key_nonces: Mutex::new(HashMap::new()),
            idle_ttl: Mutex::new(Duration::from_secs(600)),
            policy: Mutex::new(Err("not loaded yet".into())),
            search_path: exec::search_path(),
            approvals: Mutex::new(Approvals::default()),
            pending_version: tokio::sync::watch::channel(0).0,
            feed_version: tokio::sync::watch::channel(0).0,
            active_runs: std::sync::atomic::AtomicUsize::new(0),
            hardening: Mutex::new(Vec::new()),
            policy_edit: Mutex::new(None),
        }
    }

    pub fn mode(&self) -> Mode {
        self.platform.mode()
    }

    /// Append an audit record. Errors are returned so callers on the run path can fail
    /// closed; elsewhere they are logged.
    pub fn audit(&self, event: &str, id: Option<&str>, f: Value) -> Result<(), String> {
        let mut log = self.audit.lock().unwrap_or_else(|p| p.into_inner());
        let r = log.append(event, id, fields(f)).map_err(|e| {
            tracing::error!(%e, event, "audit write failed");
            e.to_string()
        });
        drop(log);
        self.feed_version.send_modify(|v| *v = v.wrapping_add(1));
        r
    }

    /// Where the audit log is (the app's activity history reads it).
    pub(crate) fn audit_path(&self) -> PathBuf {
        self.audit
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .path()
            .to_path_buf()
    }

    pub fn is_unlocked(&self) -> bool {
        self.unlocked
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_some()
    }

    /// Ids of the enrolled approval keys, or `None` while locked. Does not count as use
    /// of the vault (the idle timer is not reset).
    pub(crate) fn approval_key_ids(&self) -> Option<Vec<String>> {
        self.unlocked
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(|u| {
                u.contents
                    .approval_keys()
                    .into_iter()
                    .map(|k| k.id)
                    .collect()
            })
    }

    /// Keep `contents` in memory until the idle TTL (or `lock`).
    pub fn set_unlocked(&self, contents: VaultContents) {
        *self.unlocked.lock().unwrap_or_else(|p| p.into_inner()) = Some(Unlocked {
            contents,
            last_used: Instant::now(),
        });
    }

    /// Replace the cached contents if (and only if) the vault is unlocked.
    fn refresh_unlocked(&self, contents: &VaultContents) {
        let mut g = self.unlocked.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(u) = g.as_mut() {
            u.contents = contents.clone();
        }
    }

    /// Wipe the in-memory vault. Returns how many values were zeroized, if it was
    /// unlocked.
    pub fn relock(&self, reason: &str) -> Option<usize> {
        self.clear_grants();
        let taken = self
            .unlocked
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        let mut u = taken?;
        let wiped = u.contents.wipe();
        let _ = self.audit(
            "lock",
            None,
            json!({"reason": reason, "wiped_secrets": wiped}),
        );
        tracing::info!(reason, wiped, "vault locked");
        Some(wiped)
    }

    /// Relock if idle for longer than the TTL. Never while a command runs.
    pub fn relock_if_idle(&self) {
        if self.active_runs.load(std::sync::atomic::Ordering::SeqCst) > 0 {
            return;
        }
        let mut ttl = *self.idle_ttl.lock().unwrap_or_else(|p| p.into_inner());
        if ttl.is_zero() {
            ttl = ZERO_TTL_GRACE;
        }
        let idle = self
            .unlocked
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .is_some_and(|u| u.last_used.elapsed() >= ttl);
        if idle {
            self.relock("idle");
        }
    }

    /// Check a proof for `op`. The caller must hold `vault_ops`.
    async fn verify_proof(
        &self,
        proof: &Proof,
        op: &ApproverOp,
        peer: &PeerInfo,
    ) -> Result<VaultContents, Response> {
        match proof {
            Proof::Passphrase(pass) => self.verify_passphrase(pass, peer).await,
            Proof::Key(k) => self.verify_key(k, op, peer),
            Proof::PolicyEdit(_) => Err(error(
                ErrorCode::Unauthorized,
                "a policy change id only applies that change",
            )),
        }
    }

    /// Check an approval-key signature (M13). Only for [`ApproverOp::key_allowed`]
    /// operations, only while the vault is unlocked (the key is in it), within the time
    /// window, once per nonce. Failures count towards the passphrase lockout.
    fn verify_key(
        &self,
        k: &KeyProof,
        op: &ApproverOp,
        peer: &PeerInfo,
    ) -> Result<VaultContents, Response> {
        let unauthorized = |msg: &str| error(ErrorCode::Unauthorized, msg);
        if let Some(wait) = self
            .limiter
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .locked_out(Instant::now())
        {
            return Err(error(
                ErrorCode::RateLimited,
                format!("too many failed approvals; try again in {wait} s"),
            ));
        }
        if !op.key_allowed() {
            return Err(unauthorized("this operation needs the passphrase"));
        }
        let Some(contents) = self
            .unlocked
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(|u| u.contents.clone())
        else {
            return Err(unauthorized(
                "the vault is locked; unlock it with the passphrase first",
            ));
        };
        let fail = |why: &str| {
            self.limiter
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .failure(Instant::now());
            let _ = self.audit(
                "auth_failed",
                None,
                json!({"peer": peer_json(peer), "via": "approval_key", "key_id": k.key_id, "why": why}),
            );
            unauthorized(&format!("approval key rejected: {why}"))
        };
        let Some(key) = contents.approval_key(&k.key_id) else {
            return Err(fail("unknown key"));
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now.abs_diff(k.time) > KEY_PROOF_WINDOW_SECS {
            return Err(fail("signed too long ago, or the clock is off"));
        }
        if k.nonce.len() != 32 || credstore_proto::unhex(&k.nonce).is_none() {
            return Err(fail("bad nonce"));
        }
        let (Some(spki), Some(sig)) = (
            credstore_proto::unhex(&key.public_key),
            credstore_proto::unhex(&k.signature),
        ) else {
            return Err(fail("bad signature encoding"));
        };
        {
            let mut seen = self.key_nonces.lock().unwrap_or_else(|p| p.into_inner());
            let keep = Duration::from_secs(KEY_PROOF_WINDOW_SECS * 2 + 5);
            seen.retain(|_, t| t.elapsed() < keep);
            if seen.contains_key(&k.nonce) {
                return Err(fail("replayed"));
            }
            let msg = credstore_proto::signed_message(&k.key_id, k.time, &k.nonce, op);
            if !credstore_os::approval_key::verify(&spki, &msg, &sig) {
                return Err(fail("bad signature"));
            }
            seen.insert(k.nonce.clone(), Instant::now());
        }
        self.limiter
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .success();
        Ok(contents)
    }

    /// Check a passphrase by decrypting the vault. Rate limited.
    async fn verify_passphrase(
        &self,
        pass: &SecretText,
        peer: &PeerInfo,
    ) -> Result<VaultContents, Response> {
        if let Some(wait) = self
            .limiter
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .locked_out(Instant::now())
        {
            return Err(error(
                ErrorCode::RateLimited,
                format!("too many wrong passphrases; try again in {wait} s"),
            ));
        }
        let vault = self.vault.clone();
        let pass = pass.clone();
        let result = tokio::task::spawn_blocking(move || vault.unlock(&pass)).await;
        match result {
            Ok(Ok(contents)) => {
                self.limiter
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .success();
                Ok(contents)
            }
            Ok(Err(VaultError::WrongPassphrase)) => {
                self.limiter
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .failure(Instant::now());
                let _ = self.audit("auth_failed", None, json!({"peer": peer_json(peer)}));
                Err(error(ErrorCode::Unauthorized, "wrong passphrase"))
            }
            Ok(Err(VaultError::Missing(_))) => Err(error(
                ErrorCode::BadRequest,
                "no vault yet; run `credstore init`",
            )),
            Ok(Err(e)) => Err(error(ErrorCode::Internal, e.to_string())),
            Err(_) => Err(error(ErrorCode::Internal, "passphrase check failed")),
        }
    }

    // ------------------------------------------------------------------
    // Agent endpoint
    // ------------------------------------------------------------------

    /// `closed` resolves if the agent hangs up. A request still waiting for the human is
    /// then cancelled; a command that is already running is left to finish.
    pub async fn agent(
        self: &Arc<Self>,
        req: AgentRequest,
        peer: &PeerInfo,
        closed: impl std::future::Future<Output = ()>,
    ) -> Response {
        match req {
            AgentRequest::ListSecrets => match self.vault.list() {
                Ok(secrets) => Response::Secrets { secrets },
                Err(VaultError::Missing(_)) => Response::Secrets { secrets: vec![] },
                Err(e) => error(ErrorCode::Internal, e.to_string()),
            },
            AgentRequest::Run(req) => match self.prepare_run(req, peer).await {
                Ok(p) => self.authorize_and_do(Job::Run(p), peer, closed).await,
                Err(resp) => resp,
            },
            AgentRequest::Http(req) => match self.prepare_http(req, peer).await {
                Ok(p) => self.authorize_and_do(Job::Http(p), peer, closed).await,
                Err(resp) => resp,
            },
        }
    }

    /// Wait for approval (or a grant), then run the command or send the request.
    async fn authorize_and_do(
        self: &Arc<Self>,
        job: Job,
        peer: &PeerInfo,
        closed: impl std::future::Future<Output = ()>,
    ) -> Response {
        let decision = tokio::select! {
            d = self.authorize(&job, peer) => d,
            () = closed => {
                self.cancel_request(job.id(), "disconnect");
                return Response::Denied { reason: "the agent disconnected".into() };
            }
        };
        match (decision, job) {
            (Ok(values), Job::Run(p)) => self.execute(p, values).await,
            (Ok(values), Job::Http(p)) => self.execute_http(p, values).await,
            (Err(resp), _) => resp,
        }
    }

    // ------------------------------------------------------------------
    // Approver endpoint
    // ------------------------------------------------------------------

    pub async fn approver(self: &Arc<Self>, req: ApproverRequest, peer: &PeerInfo) -> Response {
        let _ops = self.vault_ops.lock().await;

        if let ApproverOp::AdminInit = req.op {
            return self.admin_init(&req.proof, peer).await;
        }
        if let Proof::PolicyEdit(id) = &req.proof {
            return self.policy_edit_step(id, &req.op, peer);
        }

        let contents = match self.verify_proof(&req.proof, &req.op, peer).await {
            Ok(c) => c,
            Err(resp) => return resp,
        };

        match req.op {
            ApproverOp::AdminInit => unreachable!("handled above"),
            ApproverOp::Unlock => {
                self.set_unlocked(contents);
                let _ = self.audit("unlock", None, json!({"peer": peer_json(peer)}));
                Response::Ok
            }
            ApproverOp::Lock => {
                drop(contents);
                self.relock("requested");
                Response::Ok
            }
            ApproverOp::Status => Response::Status(Box::new(StatusInfo {
                locked: !self.is_unlocked(),
                dev_mode: self.mode() == Mode::Dev,
                pending: u32::try_from(self.pending_count()).unwrap_or(u32::MAX),
                policy_error: self.policy().err(),
                pid: Some(std::process::id()),
                version: Some(env!("CARGO_PKG_VERSION").into()),
                sandbox: Some({
                    let c = credstore_os::sandbox::capabilities();
                    format!("{}: {}", credstore_os::sandbox::mode_name(c.mode), c.detail)
                }),
                hardening: self
                    .hardening
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .clone(),
                approval_keys: contents.approval_keys(),
            })),
            ApproverOp::AddApprovalKey { label, public_key } => {
                let Some(spki) = credstore_proto::unhex(&public_key) else {
                    return error(ErrorCode::BadRequest, "public_key is not hex");
                };
                if let Err(e) = credstore_os::approval_key::check_public_key(&spki) {
                    return error(ErrorCode::BadRequest, format!("unusable public key: {e}"));
                }
                let id = credstore_os::approval_key::key_id(&spki);
                let mut contents = contents;
                if let Err(e) = contents.add_approval_key(&id, &label, &public_key) {
                    return error(ErrorCode::BadRequest, e.to_string());
                }
                self.save(contents, &req.proof, peer, "approval_key_added", &id)
                    .await
            }
            ApproverOp::SetSecretRules {
                name,
                allow_hosts,
                allow_commands,
            } => {
                drop(contents);
                self.edit_policy(&req.proof, peer, Some(&name), |text| {
                    credstore_core::policy_edit::set_secret_rules(
                        text,
                        &name,
                        allow_hosts.as_deref(),
                        allow_commands.as_deref(),
                    )
                })
            }
            ApproverOp::SetDefaults {
                session_idle_secs,
                grant_ttl_secs,
                approval_timeout_secs,
            } => {
                drop(contents);
                self.edit_policy(&req.proof, peer, None, |text| {
                    credstore_core::policy_edit::set_defaults(
                        text,
                        session_idle_secs,
                        grant_ttl_secs,
                        approval_timeout_secs,
                    )
                })
            }
            ApproverOp::RemoveApprovalKey { id } => {
                let mut contents = contents;
                if let Err(e) = contents.remove_approval_key(&id) {
                    return error(ErrorCode::BadRequest, e.to_string());
                }
                self.save(contents, &req.proof, peer, "approval_key_removed", &id)
                    .await
            }
            ApproverOp::AdminSet {
                name,
                description,
                value,
            } => {
                let mut contents = contents;
                if let Err(e) = contents.set(&name, value, description) {
                    return error(ErrorCode::BadRequest, e.to_string());
                }
                self.save(contents, &req.proof, peer, "set", &name).await
            }
            ApproverOp::AdminRm { name } => {
                let mut contents = contents;
                if let Err(e) = contents.remove(&name) {
                    return error(ErrorCode::BadRequest, e.to_string());
                }
                self.save(contents, &req.proof, peer, "rm", &name).await
            }
            ApproverOp::Reload => match self.load_policy("request") {
                Ok(()) => Response::Ok,
                Err(e) => error(
                    ErrorCode::BadRequest,
                    format!("policy not loaded, so every run is denied until it is fixed: {e}"),
                ),
            },
            ApproverOp::Approve { request_id, scope } => {
                self.approve(&request_id, scope, contents, peer)
            }
            ApproverOp::Deny { request_id } => {
                drop(contents);
                self.deny(&request_id, peer)
            }
            ApproverOp::TakePolicyEdit | ApproverOp::FinishPolicyEdit => error(
                ErrorCode::Unauthorized,
                "this step needs a policy change id",
            ),
            // Streamed by the server after `verify`.
            ApproverOp::SubscribePending | ApproverOp::SubscribeFeed => {
                error(ErrorCode::BadRequest, "subscribe is streamed")
            }
            ApproverOp::AdminRun(run) => {
                // The run can take minutes; other approver requests must not wait on it.
                drop(_ops);
                self.admin_run(run, contents, peer).await
            }
        }
    }

    /// Check a proof on its own (for streaming operations).
    pub async fn verify(
        &self,
        proof: &Proof,
        op: &ApproverOp,
        peer: &PeerInfo,
    ) -> Result<(), Response> {
        let _ops = self.vault_ops.lock().await;
        self.verify_proof(proof, op, peer).await.map(drop)
    }

    async fn admin_init(&self, proof: &Proof, peer: &PeerInfo) -> Response {
        if self.vault.exists() {
            return error(ErrorCode::BadRequest, "a vault already exists");
        }
        let Proof::Passphrase(pass) = proof else {
            return error(
                ErrorCode::Unauthorized,
                "creating a vault needs a passphrase",
            );
        };
        let vault = self.vault.clone();
        let pass = pass.clone();
        match tokio::task::spawn_blocking(move || vault.create(&pass)).await {
            Ok(Ok(())) => {
                let _ = self.audit(
                    "vault_changed",
                    None,
                    json!({"action": "init", "peer": peer_json(peer)}),
                );
                self.write_starter_policy();
                Response::Ok
            }
            Ok(Err(e)) => error(ErrorCode::BadRequest, e.to_string()),
            Err(_) => error(ErrorCode::Internal, "creating the vault failed"),
        }
    }

    async fn save(
        &self,
        contents: VaultContents,
        proof: &Proof,
        peer: &PeerInfo,
        action: &str,
        name: &str,
    ) -> Response {
        // Only passphrase-proved operations change the vault (key_allowed has none).
        let Proof::Passphrase(pass) = proof else {
            return error(
                ErrorCode::Unauthorized,
                "this operation needs the passphrase",
            );
        };
        let vault = self.vault.clone();
        let pass = pass.clone();
        let saved = tokio::task::spawn_blocking(move || {
            let r = vault.save(&contents, &pass);
            (contents, r)
        })
        .await;
        match saved {
            Ok((contents, Ok(()))) => {
                self.refresh_unlocked(&contents);
                let _ = self.audit(
                    "vault_changed",
                    None,
                    json!({"action": action, "secret": name, "peer": peer_json(peer)}),
                );
                Response::Ok
            }
            Ok((_, Err(e))) => error(ErrorCode::Internal, e.to_string()),
            Err(_) => error(ErrorCode::Internal, "saving the vault failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_locks_out_after_five_and_doubles() {
        let t0 = Instant::now();
        let mut l = RateLimiter::new();
        for _ in 0..4 {
            l.failure(t0);
            assert_eq!(l.locked_out(t0), None);
        }
        l.failure(t0);
        assert_eq!(l.locked_out(t0), Some(60));
        assert_eq!(l.locked_out(t0 + Duration::from_secs(61)), None);

        let t1 = t0 + Duration::from_secs(61);
        for _ in 0..5 {
            l.failure(t1);
        }
        assert_eq!(l.locked_out(t1), Some(120), "second lockout doubles");

        l.success();
        assert_eq!(l.locked_out(t1), None);
        for _ in 0..5 {
            l.failure(t1);
        }
        assert_eq!(l.locked_out(t1), Some(60), "success resets the doubling");
    }
}
