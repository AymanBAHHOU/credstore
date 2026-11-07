//! What the desktop app sees and changes besides approvals: the activity history (from
//! the audit log), the policy as it applies to each secret, and policy edits.

use std::io::{Read, Seek, SeekFrom};
use std::time::{Duration, Instant};

use credstore_core::policy::PolicyError;
use credstore_core::policy::{Policy, STARTER_POLICY};
use credstore_os::{exec, fs as osfs, Mode, Paths};
use credstore_proto::{
    ApproverOp, ErrorCode, Feed, PeerInfo, PolicyInfo, Proof, Response, POLICY_EDIT_TTL_SECS,
};
use serde_json::json;

use crate::run::match_style;
use crate::state::{error, peer_json, State};

/// Entries in the app's activity list.
const ACTIVITY_LIMIT: usize = 100;
/// How much of the end of the audit log is read for it.
const ACTIVITY_TAIL_BYTES: u64 = 1024 * 1024;

impl State {
    pub(crate) fn feed(&self) -> Feed {
        let policy = self.policy();
        Feed {
            pending: self.pending_list(),
            activity: self.activity(),
            policy: policy.as_ref().ok().map(|p| self.policy_info(p)),
            policy_error: policy.err(),
            locked: !self.is_unlocked(),
            approval_keys: self.approval_key_ids(),
        }
    }

    fn activity(&self) -> Vec<credstore_proto::ActivityEntry> {
        let text = match read_tail(&self.audit_path(), ACTIVITY_TAIL_BYTES) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(%e, "cannot read the audit log for the activity list");
                return Vec::new();
            }
        };
        credstore_core::activity::from_audit(text.lines(), ACTIVITY_LIMIT)
    }

    fn policy_info(&self, policy: &Policy) -> PolicyInfo {
        let mut names: Vec<String> = self
            .vault
            .list()
            .map(|l| l.into_iter().map(|s| s.name).collect())
            .unwrap_or_default();
        for n in policy.configured_secrets() {
            if !names.iter().any(|m| m == n) {
                names.push(n.to_owned());
            }
        }
        names.sort();
        let d = &policy.defaults;
        PolicyInfo {
            path: self.platform.policy_file().display().to_string(),
            editable: policy_writer(self.mode()) != Writer::ByHand,
            needs_admin: policy_writer(self.mode()) == Writer::Admin,
            strict: d.strict,
            session_idle_secs: d.session_idle_secs,
            grant_ttl_secs: d.grant_ttl_secs,
            approval_timeout_secs: d.approval_timeout_secs,
            secrets: names.iter().map(|n| policy.rules_info(n)).collect(),
        }
    }

    /// Change the policy file with `edit`, check the result, write it and reload. The
    /// caller has verified `proof`; only a passphrase may change policy.
    pub(crate) fn edit_policy(
        &self,
        proof: &Proof,
        peer: &PeerInfo,
        secret: Option<&str>,
        edit: impl FnOnce(&str) -> Result<String, PolicyError>,
    ) -> Response {
        if !matches!(proof, Proof::Passphrase(_)) {
            return error(
                ErrorCode::Unauthorized,
                "changing the policy needs the passphrase",
            );
        }
        let path = self.platform.policy_file();
        let writer = policy_writer(self.mode());
        if writer == Writer::ByHand {
            return error(
                ErrorCode::Unsupported,
                format!(
                    "{} belongs to root on this system; edit it with sudo, then run \
                     `credstore reload`",
                    path.display()
                ),
            );
        }
        let (text, base) = match std::fs::read(path) {
            Ok(b) => (String::from_utf8_lossy(&b).into_owned(), sha256_hex(&b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                (STARTER_POLICY.to_owned(), String::new())
            }
            Err(e) => {
                return error(
                    ErrorCode::Internal,
                    format!("cannot read {}: {e}", path.display()),
                )
            }
        };
        let new = match edit(&text) {
            Ok(n) => n,
            Err(e) => return error(ErrorCode::BadRequest, e.0),
        };
        if let Err(e) = Policy::parse_with(&new, match_style(), &|d| {
            exec::canonical_path(std::path::Path::new(d)).map(|c| c.to_string_lossy().into_owned())
        }) {
            return error(ErrorCode::BadRequest, e.0);
        }
        if writer == Writer::Admin {
            // The service may only read the file: hand the checked text to the admin
            // helper, which writes it after Windows asks the human (UAC).
            let id = edit_id();
            *self.policy_edit.lock().unwrap_or_else(|p| p.into_inner()) = Some(PendingPolicyEdit {
                id: id.clone(),
                text: new,
                base_sha256: base,
                secret: secret.map(str::to_owned),
                peer: peer.clone(),
                created: Instant::now(),
            });
            return Response::PolicyEditPending { id };
        }
        if let Err(e) = osfs::write_private_atomic(path, new.as_bytes()) {
            return error(
                ErrorCode::Internal,
                format!("cannot write {}: {e}", path.display()),
            );
        }
        self.policy_written(peer, secret, None)
    }

    /// Audit a policy change and reload the file.
    fn policy_written(
        &self,
        peer: &PeerInfo,
        secret: Option<&str>,
        admin: Option<&PeerInfo>,
    ) -> Response {
        let mut f = json!({"peer": peer_json(peer)});
        if let Some(s) = secret {
            f["secret"] = json!(s);
        }
        if let Some(a) = admin {
            f["admin"] = peer_json(a);
        }
        let _ = self.audit("policy_changed", None, f);
        match self.load_policy("app") {
            Ok(()) => Response::Ok,
            Err(e) => error(ErrorCode::Internal, e),
        }
    }

    /// The admin helper's two steps, authorized by the change's id: take the prepared
    /// text, then (after writing it) finish. Finishing checks the file really holds the
    /// text, so nobody can claim a write that did not happen.
    pub(crate) fn policy_edit_step(
        &self,
        id: &str,
        op: &ApproverOp,
        helper: &PeerInfo,
    ) -> Response {
        let mut slot = self.policy_edit.lock().unwrap_or_else(|p| p.into_inner());
        let live = slot.as_ref().filter(|e| {
            e.id == id && e.created.elapsed() < Duration::from_secs(POLICY_EDIT_TTL_SECS)
        });
        let Some(edit) = live else {
            return error(
                ErrorCode::BadRequest,
                "this policy change expired or was replaced; make it again",
            );
        };
        match op {
            ApproverOp::TakePolicyEdit => Response::PolicyEdit {
                text: edit.text.clone(),
                base_sha256: edit.base_sha256.clone(),
            },
            ApproverOp::FinishPolicyEdit => {
                let path = self.platform.policy_file();
                match std::fs::read(path) {
                    Ok(b) if b == edit.text.as_bytes() => {}
                    _ => {
                        return error(
                            ErrorCode::BadRequest,
                            format!("{} does not hold the change", path.display()),
                        )
                    }
                }
                let Some(edit) = slot.take() else {
                    unreachable!("checked above")
                };
                drop(slot);
                self.policy_written(&edit.peer, edit.secret.as_deref(), Some(helper))
            }
            _ => error(
                ErrorCode::Unauthorized,
                "a policy change id only applies that change",
            ),
        }
    }
}

/// A checked policy change waiting for the admin helper.
pub(crate) struct PendingPolicyEdit {
    id: String,
    text: String,
    base_sha256: String,
    secret: Option<String>,
    /// Who made the change (with the passphrase).
    peer: PeerInfo,
    created: Instant,
}

/// Who writes the policy file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Writer {
    /// The daemon (dev mode: the file is the user's).
    Daemon,
    /// An administrator (Windows installs): the service may only read it, so a daemon
    /// that was taken over cannot widen its own rules. The app runs the admin helper.
    Admin,
    /// root, by hand (Linux and macOS installs, spec 5.4).
    ByHand,
}

fn policy_writer(mode: Mode) -> Writer {
    match mode {
        Mode::Dev => Writer::Daemon,
        Mode::Installed if cfg!(windows) => Writer::Admin,
        Mode::Installed => Writer::ByHand,
    }
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    credstore_proto::hex(&Sha256::digest(b))
}

/// A unique id for a prepared change. It needs to be unique, not secret: holding it
/// only lets someone apply the change the human made.
fn edit_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    sha256_hex(format!("{nanos}-{}-{n}", std::process::id()).as_bytes())[..32].to_owned()
}

/// The last `max` bytes of a file, from the first whole line.
fn read_tail(path: &std::path::Path, max: u64) -> std::io::Result<String> {
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(e) => return Err(e),
    };
    let len = f.metadata()?.len();
    let start = len.saturating_sub(max);
    f.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    f.take(max).read_to_end(&mut buf)?;
    let text = String::from_utf8_lossy(&buf).into_owned();
    Ok(if start > 0 {
        text.split_once('\n')
            .map(|(_, rest)| rest.to_owned())
            .unwrap_or_default()
    } else {
        text
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn who_writes_the_policy() {
        assert_eq!(policy_writer(Mode::Dev), Writer::Daemon);
        let installed = policy_writer(Mode::Installed);
        if cfg!(windows) {
            assert_eq!(installed, Writer::Admin);
        } else {
            assert_eq!(installed, Writer::ByHand);
        }
    }

    #[test]
    fn edit_ids_are_unique() {
        let (a, b) = (edit_id(), edit_id());
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
    }
}
