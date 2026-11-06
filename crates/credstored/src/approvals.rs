//! Pending approvals and session grants (spec 6.2 steps 4 to 6, 6.3).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use credstore_core::policy::injection_name;
use credstore_core::vault::VaultContents;
use credstore_proto::{
    ErrorCode, GrantScope, Injection, PeerInfo, PendingRequest, RequestId, Response, SecretText,
};
use serde_json::json;
use tokio::sync::oneshot;

use crate::run::Prepared;
use crate::state::{error, peer_json, State};

/// Values handed to the runner, in request order.
pub(crate) type Values = Vec<(String, SecretText)>;

pub(crate) enum Decision {
    Approved(Values),
    Denied(String),
}

pub(crate) struct Entry {
    pub info: PendingRequest,
    pub prepared: Prepared,
    pub requester: PeerInfo,
    pub tx: oneshot::Sender<Decision>,
}

/// What a session grant covers: exactly the same request from the same user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GrantKey {
    secrets: Vec<String>,
    argv: Option<Vec<String>>,
    shell: Option<String>,
    program: Option<PathBuf>,
    cwd: PathBuf,
    injection: Injection,
    uid: Option<u32>,
    sid: Option<String>,
}

impl GrantKey {
    pub fn new(p: &Prepared, peer: &PeerInfo) -> Self {
        let mut secrets = p.req.secrets.clone();
        secrets.sort();
        Self {
            secrets,
            argv: p.req.argv.clone(),
            shell: p.req.shell.clone(),
            program: p.program.clone(),
            cwd: p.cwd.clone(),
            injection: p.injection,
            uid: peer.uid,
            sid: peer.sid.clone(),
        }
    }
}

pub(crate) struct Grant {
    key: GrantKey,
    expires: Instant,
}

#[derive(Default)]
pub(crate) struct Approvals {
    pending: BTreeMap<String, Entry>,
    grants: Vec<Grant>,
}

pub(crate) fn select(contents: &VaultContents, names: &[String]) -> Result<Values, String> {
    names
        .iter()
        .map(|n| {
            contents
                .get(n)
                .map(|e| (n.clone(), e.value.clone()))
                .ok_or_else(|| format!("secret {n} was removed from the vault"))
        })
        .collect()
}

fn scope_json(scope: &GrantScope) -> serde_json::Value {
    match scope {
        GrantScope::Once => json!("once"),
        GrantScope::Session { ttl_secs } => json!({"session_secs": ttl_secs}),
    }
}

impl State {
    fn approvals(&self) -> std::sync::MutexGuard<'_, Approvals> {
        self.approvals.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn notify(&self) {
        self.pending_version.send_modify(|v| *v = v.wrapping_add(1));
    }

    pub fn pending_list(&self) -> Vec<PendingRequest> {
        self.approvals()
            .pending
            .values()
            .map(|e| e.info.clone())
            .collect()
    }

    pub fn pending_count(&self) -> usize {
        self.approvals().pending.len()
    }

    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.pending_version.subscribe()
    }

    /// Drop every grant (on lock: a locked vault must ask the human again).
    pub fn clear_grants(&self) {
        self.approvals().grants.clear();
    }

    /// Cancel every waiting request (shutdown).
    pub fn cancel_pending(&self) {
        let drained = std::mem::take(&mut self.approvals().pending);
        drop(drained);
        self.notify();
    }

    /// Values for a request covered by a live grant, if the vault is still unlocked.
    fn granted_values(&self, key: &GrantKey, names: &[String]) -> Option<Values> {
        let now = Instant::now();
        {
            let mut a = self.approvals();
            a.grants.retain(|g| g.expires > now);
            if !a.grants.iter().any(|g| &g.key == key) {
                return None;
            }
        }
        self.unlocked_values(names)
    }

    /// Values from the unlocked vault (refreshing its idle timer), if unlocked.
    fn unlocked_values(&self, names: &[String]) -> Option<Values> {
        let mut g = self.unlocked.lock().unwrap_or_else(|p| p.into_inner());
        let u = g.as_mut()?;
        u.last_used = Instant::now();
        select(&u.contents, names).ok()
    }

    /// Steps 4 to 6: use a grant, or wait for the human. Returns the approved values or
    /// the response to send back.
    pub async fn authorize_run(
        self: &Arc<Self>,
        prepared: &Prepared,
        peer: &PeerInfo,
    ) -> Result<Values, Response> {
        let id = prepared.id.clone();
        let key = GrantKey::new(prepared, peer);
        if let Some(values) = self.granted_values(&key, &prepared.req.secrets) {
            let _ = self.audit("approved", Some(&id), json!({"via": "grant"}));
            return Ok(values);
        }
        if !prepared.effective.require_approval {
            if let Some(values) = self.unlocked_values(&prepared.req.secrets) {
                let _ = self.audit("approved", Some(&id), json!({"via": "policy"}));
                return Ok(values);
            }
        }

        let info = PendingRequest {
            id: RequestId(id.clone()),
            reason: prepared.req.reason.clone(),
            argv: prepared.req.argv.clone(),
            shell: prepared.req.shell.clone(),
            program: prepared
                .program
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
            cwd: prepared.cwd.to_string_lossy().into_owned(),
            secrets: prepared.secrets.clone(),
            injection: prepared.injection,
            sandbox: prepared.sandbox.mode,
            sandbox_gaps: prepared.sandbox.gaps.clone(),
            network: prepared.effective.network,
            allow_hosts: prepared.effective.allow_hosts.clone(),
            max_grant_secs: prepared.effective.grant_ttl_cap_secs,
            peer: peer.clone(),
        };
        let (tx, rx) = oneshot::channel();
        self.approvals().pending.insert(
            id.clone(),
            Entry {
                info,
                prepared: prepared.clone(),
                requester: peer.clone(),
                tx,
            },
        );
        self.notify();
        tracing::info!(id, "waiting for approval");

        let wait = Duration::from_secs(prepared.effective.approval_timeout_secs);
        let decision = tokio::time::timeout(wait, rx).await;
        if self.approvals().pending.remove(&id).is_some() {
            self.notify();
        }
        match decision {
            Ok(Ok(Decision::Approved(values))) => Ok(values),
            Ok(Ok(Decision::Denied(why))) => Err(Response::Denied { reason: why }),
            Ok(Err(_)) => {
                let _ = self.audit("denied", Some(&id), json!({"via": "shutdown"}));
                Err(Response::Denied {
                    reason: "the daemon is shutting down".into(),
                })
            }
            Err(_) => {
                let _ = self.audit("denied", Some(&id), json!({"via": "timeout"}));
                Err(Response::Denied {
                    reason: "approval timed out".into(),
                })
            }
        }
    }

    /// The human approved `id` (the caller verified the passphrase into `contents`).
    pub fn approve(
        &self,
        id: &RequestId,
        scope: GrantScope,
        contents: VaultContents,
        approver: &PeerInfo,
    ) -> Response {
        let Some(entry) = self.approvals().pending.remove(&id.0) else {
            return error(
                ErrorCode::BadRequest,
                format!("no pending request {} (it may have timed out)", id.0),
            );
        };
        self.notify();

        let values = match select(&contents, &entry.prepared.req.secrets) {
            Ok(v) => v,
            Err(why) => {
                let _ = entry.tx.send(Decision::Denied(why.clone()));
                return error(ErrorCode::BadRequest, why);
            }
        };

        // Session grants are capped by policy; a cap of 0 means approve once only.
        let cap = entry.prepared.effective.grant_ttl_cap_secs;
        let scope = match scope {
            GrantScope::Session { ttl_secs } if cap > 0 && ttl_secs > 0 => GrantScope::Session {
                ttl_secs: ttl_secs.min(cap),
            },
            _ => GrantScope::Once,
        };

        // The vault stays unlocked until the idle TTL (6.3).
        self.set_unlocked(contents);
        let _ = self.audit(
            "approved",
            Some(&id.0),
            json!({
                "via": "human",
                "scope": scope_json(&scope),
                "approver": peer_json(approver),
                "injection": injection_name(entry.prepared.injection),
            }),
        );
        if let GrantScope::Session { ttl_secs } = scope {
            self.approvals().grants.push(Grant {
                key: GrantKey::new(&entry.prepared, &entry.requester),
                expires: Instant::now() + Duration::from_secs(ttl_secs),
            });
        }
        match entry.tx.send(Decision::Approved(values)) {
            Ok(()) => Response::Ok,
            Err(_) => error(ErrorCode::BadRequest, "the request is no longer waiting"),
        }
    }

    pub fn deny(&self, id: &RequestId, approver: &PeerInfo) -> Response {
        let Some(entry) = self.approvals().pending.remove(&id.0) else {
            return error(
                ErrorCode::BadRequest,
                format!("no pending request {} (it may have timed out)", id.0),
            );
        };
        self.notify();
        let _ = self.audit(
            "denied",
            Some(&id.0),
            json!({"via": "human", "approver": peer_json(approver)}),
        );
        let _ = entry
            .tx
            .send(Decision::Denied("denied by the human".into()));
        Response::Ok
    }
}
