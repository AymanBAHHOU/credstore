//! Daemon state and request handling (everything except socket plumbing).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use credstore_core::audit::AuditLog;
use credstore_core::vault::{Vault, VaultContents, VaultError};
use credstore_os::{Mode, Paths, Platform};
use credstore_proto::{
    AgentRequest, ApproverOp, ApproverRequest, ErrorCode, PeerInfo, Proof, Response, StatusInfo,
};
use serde_json::{json, Map, Value};

/// Failed passphrase attempts allowed before a lockout.
pub const MAX_FAILURES: u32 = 5;
/// First lockout; doubles after each further lockout until a correct passphrase.
pub const FIRST_LOCKOUT: Duration = Duration::from_secs(60);

pub(crate) struct State {
    pub platform: Platform,
    pub vault: Vault,
    audit: Mutex<AuditLog>,
    /// Serializes passphrase checks and vault writes (no lost updates, and the rate
    /// limit counts attempts one at a time).
    vault_ops: tokio::sync::Mutex<()>,
    unlocked: Mutex<Option<Unlocked>>,
    limiter: Mutex<RateLimiter>,
    pub idle_ttl: Mutex<Duration>,
}

struct Unlocked {
    contents: VaultContents,
    last_used: Instant,
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
            idle_ttl: Mutex::new(Duration::from_secs(600)),
        }
    }

    pub fn mode(&self) -> Mode {
        self.platform.mode()
    }

    /// Append an audit record. Errors are returned so callers on the run path can fail
    /// closed; elsewhere they are logged.
    pub fn audit(&self, event: &str, id: Option<&str>, f: Value) -> Result<(), String> {
        let mut log = self.audit.lock().unwrap_or_else(|p| p.into_inner());
        log.append(event, id, fields(f)).map_err(|e| {
            tracing::error!(%e, event, "audit write failed");
            e.to_string()
        })
    }

    pub fn is_unlocked(&self) -> bool {
        self.unlocked
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_some()
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

    /// Relock if idle for longer than the TTL.
    pub fn relock_if_idle(&self) {
        let ttl = *self.idle_ttl.lock().unwrap_or_else(|p| p.into_inner());
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

    /// Check a passphrase proof by decrypting the vault. Rate limited; the caller must
    /// hold `vault_ops`.
    async fn verify_proof(
        &self,
        proof: &Proof,
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
        let pass = proof.passphrase.clone();
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

    pub async fn agent(self: &Arc<Self>, req: AgentRequest, peer: &PeerInfo) -> Response {
        match req {
            AgentRequest::ListSecrets => match self.vault.list() {
                Ok(secrets) => Response::Secrets { secrets },
                Err(VaultError::Missing(_)) => Response::Secrets { secrets: vec![] },
                Err(e) => error(ErrorCode::Internal, e.to_string()),
            },
            AgentRequest::Run(_) => {
                let _ = peer;
                Response::Denied {
                    reason: "running commands is not built yet".into(),
                }
            }
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

        let contents = match self.verify_proof(&req.proof, peer).await {
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
            ApproverOp::Status => Response::Status(StatusInfo {
                locked: !self.is_unlocked(),
                dev_mode: self.mode() == Mode::Dev,
                pending: 0,
            }),
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
            ApproverOp::Reload
            | ApproverOp::SubscribePending
            | ApproverOp::Approve { .. }
            | ApproverOp::Deny { .. }
            | ApproverOp::AdminRun(_) => error(ErrorCode::Unsupported, "not built yet"),
        }
    }

    async fn admin_init(&self, proof: &Proof, peer: &PeerInfo) -> Response {
        if self.vault.exists() {
            return error(ErrorCode::BadRequest, "a vault already exists");
        }
        let vault = self.vault.clone();
        let pass = proof.passphrase.clone();
        match tokio::task::spawn_blocking(move || vault.create(&pass)).await {
            Ok(Ok(())) => {
                let _ = self.audit(
                    "vault_changed",
                    None,
                    json!({"action": "init", "peer": peer_json(peer)}),
                );
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
        let vault = self.vault.clone();
        let pass = proof.passphrase.clone();
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
