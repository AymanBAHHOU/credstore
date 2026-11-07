//! What the desktop app sees and changes besides approvals: the activity history (from
//! the audit log), the policy as it applies to each secret, and policy edits.

use std::io::{Read, Seek, SeekFrom};

use credstore_core::policy::PolicyError;
use credstore_core::policy::{Policy, STARTER_POLICY};
use credstore_os::{exec, fs as osfs, Mode, Paths};
use credstore_proto::{ErrorCode, Feed, PeerInfo, PolicyInfo, Proof, Response};
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
            editable: policy_editable(self.mode()),
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
        if !policy_editable(self.mode()) {
            return error(
                ErrorCode::Unsupported,
                format!(
                    "{} belongs to root on this system; edit it with sudo, then run \
                     `credstore reload`",
                    path.display()
                ),
            );
        }
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => STARTER_POLICY.to_owned(),
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
        if let Err(e) = osfs::write_private_atomic(path, new.as_bytes()) {
            return error(
                ErrorCode::Internal,
                format!("cannot write {}: {e}", path.display()),
            );
        }
        let mut f = json!({"peer": peer_json(peer)});
        if let Some(s) = secret {
            f["secret"] = json!(s);
        }
        let _ = self.audit("policy_changed", None, f);
        match self.load_policy("app") {
            Ok(()) => Response::Ok,
            Err(e) => error(ErrorCode::Internal, e),
        }
    }
}

/// On Linux and macOS installs the policy is root's (`/etc/credstore`, spec 5.4) and the
/// service cannot write it. Elsewhere it sits in the service's own data directory.
fn policy_editable(mode: Mode) -> bool {
    mode == Mode::Dev || cfg!(windows)
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
