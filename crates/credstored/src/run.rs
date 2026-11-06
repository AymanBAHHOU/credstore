//! Run requests up to the policy and sandbox decision (spec 6.2 steps 1 to 3).

use std::path::PathBuf;
use std::sync::Arc;

use credstore_core::policy::{self, Command, Effective, MatchStyle, Policy, SandboxRequirement};
use credstore_core::request;
use credstore_core::util::new_id;
use credstore_core::vault::VaultError;
use credstore_os::{exec, fs as osfs, Mode, Paths, Sandbox, SandboxNeed, SandboxPlan};
use credstore_proto::{ErrorCode, Injection, PeerInfo, Response, RunRequest, SecretInfo};
use serde_json::json;

use crate::state::{error, peer_json, State};

/// A request that passed validation and policy, ready for approval.
#[derive(Debug, Clone)]
pub(crate) struct Prepared {
    pub id: String,
    pub req: RunRequest,
    pub injection: Injection,
    /// Canonical working directory.
    pub cwd: PathBuf,
    /// Resolved program (argv form only). This path is what runs.
    pub program: Option<PathBuf>,
    pub secrets: Vec<SecretInfo>,
    pub effective: Effective,
    /// Sandbox this run will get (planned before the human is asked).
    pub sandbox: SandboxPlan,
}

pub(crate) fn match_style() -> MatchStyle {
    if cfg!(windows) {
        MatchStyle::Windows
    } else {
        MatchStyle::Unix
    }
}

impl State {
    /// Current policy, or why there is none. Callers deny when there is none.
    pub fn policy(&self) -> Result<Arc<Policy>, String> {
        self.policy
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// (Re)load the policy file. On any error the daemon fails closed: every run is
    /// denied until a later reload succeeds.
    pub fn load_policy(&self, trigger: &str) -> Result<(), String> {
        let path = self.platform.policy_file();
        let loaded = match std::fs::read_to_string(path) {
            Ok(text) => Policy::parse_with(&text, match_style(), &|d| {
                exec::canonical_path(std::path::Path::new(d))
                    .map(|c| c.to_string_lossy().into_owned())
            })
            .map_err(|e| e.to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(format!(
                "no policy file at {}{}",
                path.display(),
                if self.mode() == Mode::Dev {
                    " (`credstore init` writes a starter policy)"
                } else {
                    ""
                }
            )),
            Err(e) => Err(format!("cannot read {}: {e}", path.display())),
        };
        let result = loaded.as_ref().map(|_| ()).map_err(Clone::clone);
        if let Ok(p) = &loaded {
            *self.idle_ttl.lock().unwrap_or_else(|p| p.into_inner()) =
                std::time::Duration::from_secs(p.defaults.session_idle_secs);
        }
        *self.policy.lock().unwrap_or_else(|p| p.into_inner()) = loaded.map(Arc::new);
        match &result {
            Ok(()) => tracing::info!(trigger, "policy loaded"),
            Err(e) => tracing::warn!(trigger, error = %e, "policy not loaded; runs are denied"),
        }
        let _ = self.audit(
            "config_reloaded",
            None,
            json!({"trigger": trigger, "ok": result.is_ok(), "error": result.as_ref().err()}),
        );
        result
    }

    /// Dev mode: write the starter policy if there is none yet, then load it.
    pub fn write_starter_policy(&self) {
        if self.mode() != Mode::Dev || self.platform.policy_file().exists() {
            return;
        }
        match osfs::write_private_atomic(
            self.platform.policy_file(),
            policy::STARTER_POLICY.as_bytes(),
        ) {
            Ok(()) => {
                let _ = self.load_policy("init");
            }
            Err(e) => tracing::warn!(%e, "could not write the starter policy"),
        }
    }

    /// Validate a run request and check it against policy. Denials are audited and
    /// returned as `Response::Denied`; malformed requests as `Response::Error`.
    pub async fn prepare_run(
        &self,
        req: RunRequest,
        peer: &PeerInfo,
    ) -> Result<Prepared, Response> {
        let injection =
            request::check(&req).map_err(|e| error(ErrorCode::BadRequest, e.to_string()))?;

        let known = match self.vault.list() {
            Ok(k) => k,
            Err(VaultError::Missing(_)) => {
                return Err(error(
                    ErrorCode::BadRequest,
                    "no vault yet; the human must run `credstore init`",
                ))
            }
            Err(e) => return Err(error(ErrorCode::Internal, e.to_string())),
        };
        let mut secrets = Vec::with_capacity(req.secrets.len());
        for name in &req.secrets {
            match known.iter().find(|s| &s.name == name) {
                Some(s) => secrets.push(s.clone()),
                None => {
                    return Err(error(
                        ErrorCode::BadRequest,
                        format!("unknown secret {name} (see list_secrets)"),
                    ))
                }
            }
        }

        let cwd = exec::canonical_dir(std::path::Path::new(&req.cwd)).ok_or_else(|| {
            error(
                ErrorCode::BadRequest,
                "cwd does not exist or is not a directory",
            )
        })?;

        let program = match &req.argv {
            Some(argv) => Some(
                exec::resolve_program(&argv[0], &cwd, &self.search_path)
                    .map_err(|e| error(ErrorCode::BadRequest, e.to_string()))?,
            ),
            None => None,
        };

        let id = new_id("req");
        let _ = self.audit(
            "request",
            Some(&id),
            json!({
                "peer": peer_json(peer),
                "secrets": req.secrets,
                "argv": req.argv,
                "shell": req.shell,
                "program": program.as_ref().map(|p| p.to_string_lossy()),
                "cwd": cwd.to_string_lossy(),
                "reason": req.reason,
                "injection": policy::injection_name(injection),
            }),
        );

        let deny = |why: String| {
            let _ = self.audit(
                "policy_denied",
                Some(&id),
                json!({"peer": peer_json(peer), "denial": why}),
            );
            Response::Denied {
                reason: format!("denied by policy: {why}"),
            }
        };

        let pol = self
            .policy()
            .map_err(|e| deny(format!("no valid policy is loaded ({e})")))?;
        let command = match (&req.argv, &program) {
            (Some(argv), Some(resolved)) => Command::Argv { argv, resolved },
            _ => Command::Shell(req.shell.as_deref().unwrap_or_default()),
        };
        let effective = pol
            .evaluate(&policy::Request {
                secrets: &req.secrets,
                command,
                cwd: &cwd,
                injection,
                timeout_secs: req.timeout_secs,
            })
            .map_err(|d| deny(d.0))?;

        // The run may write its cwd, so it must not be one of credstore's own paths.
        if let Some(h) = self.hidden_paths().iter().find(|h| cwd.starts_with(h)) {
            return Err(deny(format!(
                "cwd is inside credstore's own files ({})",
                h.display()
            )));
        }

        let need = match effective.sandbox {
            SandboxRequirement::Require => SandboxNeed::Require,
            SandboxRequirement::Prefer => SandboxNeed::Prefer,
            SandboxRequirement::Off => SandboxNeed::Off,
        };
        let sandbox = self
            .platform
            .sandbox_plan(need, effective.network)
            .map_err(|why| deny(format!("sandbox = \"require\", but {why}")))?;

        Ok(Prepared {
            id,
            req,
            injection,
            cwd,
            program,
            secrets,
            effective,
            sandbox,
        })
    }

    /// Paths a run must not see (spec 6.4): vault and index, policy, audit log, and the
    /// run directories. Canonical where they exist.
    pub fn hidden_paths(&self) -> Vec<PathBuf> {
        let p = &self.platform;
        [
            p.data_dir().to_path_buf(),
            p.policy_file().to_path_buf(),
            p.audit_log().to_path_buf(),
            p.run_dir().to_path_buf(),
        ]
        .into_iter()
        .map(|x| exec::canonical_path(&x).unwrap_or(x))
        .collect()
    }
}
