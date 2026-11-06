//! Step 7: run an approved request (spec 6.4) and redact what comes back (6.5).
//!
//! Every run gets a private directory `<run_dir>/<request id>/` holding its temp dir and,
//! for `file` injection, one read-only file per secret. The directory is removed when the
//! run ends, including on panic; a daemon that was killed mid-run sweeps leftovers at the
//! next start.

use std::path::{Path, PathBuf};
use std::time::Duration;

use credstore_core::policy::injection_name;
use credstore_core::redact::Redactor;
use credstore_core::vault::VaultContents;
use credstore_os::run::{self as osrun, Launch, Outcome};
use credstore_os::sandbox::mode_name;
use credstore_os::{exec, fs as osfs, Mode, Paths, SandboxSpec};
use credstore_proto::{
    ErrorCode, Injection, PeerInfo, Response, RunRequest, RunResult, SandboxMode, SecretText,
};
use serde_json::json;

use crate::approvals::{select, Values};
use crate::run::Prepared;
use crate::state::{error, peer_json, State};

/// One run's private directory. Removed on drop.
struct RunDir {
    root: PathBuf,
}

impl RunDir {
    fn create(base: &Path, id: &str) -> Result<Self, String> {
        let root = base.join(id);
        osfs::create_private_dir(&root).map_err(|e| e.to_string())?;
        let dir = Self { root };
        for sub in [dir.tmp(), dir.files()] {
            osfs::create_private_dir(&sub).map_err(|e| e.to_string())?;
        }
        Ok(dir)
    }

    /// Canonical, so sandbox rules match the real path (macOS `/var` is `/private/var`).
    fn tmp(&self) -> PathBuf {
        canonical(self.root.join("tmp"))
    }

    fn files(&self) -> PathBuf {
        canonical(self.root.join("files"))
    }
}

impl Drop for RunDir {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.root) {
            tracing::warn!(%e, dir = %self.root.display(), "could not remove a run directory; it is swept at the next start");
        }
    }
}

fn canonical(p: PathBuf) -> PathBuf {
    exec::canonical_dir(&p).unwrap_or(p)
}

/// Set `name` in `env`, replacing any variable of the same name.
fn set_env(env: &mut Vec<(String, SecretText)>, name: String, value: SecretText) {
    env.retain(|(k, _)| !osrun::same_env_name(k, &name));
    env.push((name, value));
}

impl State {
    /// Remove run directories a killed daemon left behind (spec 10). Called at startup.
    pub fn sweep_run_dir(&self) {
        let dir = self.platform.run_dir();
        if let Err(e) = osfs::create_private_dir(dir) {
            tracing::warn!(%e, "could not create the run directory");
            return;
        }
        match osfs::clear_dir(dir) {
            Ok(0) => {}
            Ok(n) => {
                tracing::warn!(entries = n, "removed leftover run directories");
                let _ = self.audit("run_dir_swept", None, json!({"entries": n}));
            }
            Err(e) => tracing::error!(%e, "could not sweep the run directory"),
        }
    }

    /// Run an approved request, then relock if the idle TTL is zero.
    pub async fn execute(&self, prepared: Prepared, values: Values) -> Response {
        struct Active<'a>(&'a std::sync::atomic::AtomicUsize);
        impl Drop for Active<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
        self.active_runs
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let active = Active(&self.active_runs);
        let resp = self.execute_inner(&prepared, values).await;
        drop(active);
        let idle = *self.idle_ttl.lock().unwrap_or_else(|p| p.into_inner());
        if idle.is_zero() {
            self.relock("after-run");
        }
        resp
    }

    /// Human-initiated `credstore run`: the passphrase on the request is the approval.
    /// Policy still applies.
    pub async fn admin_run(
        &self,
        req: RunRequest,
        contents: VaultContents,
        peer: &PeerInfo,
    ) -> Response {
        let prepared = match self.prepare_run(req, peer).await {
            Ok(p) => p,
            Err(resp) => return resp,
        };
        let values = match select(&contents, &prepared.req.secrets) {
            Ok(v) => v,
            Err(why) => return error(ErrorCode::BadRequest, why),
        };
        self.set_unlocked(contents);
        let _ = self.audit(
            "approved",
            Some(&prepared.id),
            json!({
                "via": "admin",
                "scope": "once",
                "approver": peer_json(peer),
                "injection": injection_name(prepared.injection),
            }),
        );
        self.execute(prepared, values).await
    }

    async fn execute_inner(&self, p: &Prepared, values: Values) -> Response {
        let id = p.id.as_str();
        let redactor = Redactor::new(values.iter().map(|(n, v)| (n.as_str(), v)));
        let failed = |what: &str, why: String| {
            let (why, _) = redactor.redact_str(&why);
            let _ = self.audit(
                "run_finished",
                Some(id),
                json!({"ok": false, "error": format!("{what}: {why}")}),
            );
            error(ErrorCode::Internal, format!("{what}: {why}"))
        };

        let dir = match RunDir::create(self.platform.run_dir(), id) {
            Ok(d) => d,
            Err(e) => return failed("could not create the run directory", e),
        };
        let launch = match self.launch(p, values, &dir) {
            Ok(l) => l,
            Err(e) => return failed("could not prepare the run", e),
        };

        // Fail closed: no audit record, no run.
        if let Err(e) = self.audit(
            "run_started",
            Some(id),
            json!({
                "sandbox": mode_name(p.sandbox.mode),
                "network_enforced": p.sandbox.network_enforced,
                "sandbox_gaps": p.sandbox.gaps,
                "injection": injection_name(p.injection),
                "timeout_secs": p.effective.timeout_secs,
            }),
        ) {
            return error(
                ErrorCode::Internal,
                format!("the audit log cannot be written, so the command was not run: {e}"),
            );
        }
        tracing::info!(id, sandbox = mode_name(p.sandbox.mode), "run started");

        let outcome = osrun::run(launch).await;
        drop(dir);
        match outcome {
            Ok(o) => self.finish(p, &redactor, o),
            Err(e) => failed("could not run the command", e.to_string()),
        }
    }

    /// Build the child's launch: cleared environment plus the approved secrets.
    fn launch(&self, p: &Prepared, values: Values, dir: &RunDir) -> Result<Launch, String> {
        let tmp = dir.tmp();
        // Installed mode runs as the service user, whose home is not the human's: give
        // the child its temp dir. Dev mode runs as the human, so tools find their config.
        let home = match self.mode() {
            Mode::Dev => osrun::user_home().unwrap_or_else(|| tmp.clone()),
            Mode::Installed => tmp.clone(),
        };
        let path = exec::child_path(&self.search_path);
        let mut env: Vec<(String, SecretText)> = osrun::base_env(&home, &tmp, &path)
            .into_iter()
            .map(|(k, v)| (k, SecretText::new(v)))
            .collect();

        let mut stdin = None;
        let mut readable = Vec::new();
        for (name, value) in values {
            match p.injection {
                Injection::Env => set_env(&mut env, name, value),
                Injection::File => {
                    let file = dir.files().join(&name);
                    osfs::write_secret_file(&file, value.expose().as_bytes())
                        .map_err(|e| format!("writing the file for {name}: {e}"))?;
                    drop(value);
                    let var = osrun::file_env_name(&name);
                    set_env(
                        &mut env,
                        var,
                        SecretText::new(file.to_string_lossy().into_owned()),
                    );
                }
                Injection::Stdin => stdin = Some(value),
            }
        }
        if p.injection == Injection::File {
            readable.push(dir.files());
        }

        let (program, args, raw_tail) = match (&p.program, &p.req.argv, &p.req.shell) {
            (Some(program), Some(argv), _) => (program.clone(), argv[1..].to_vec(), None),
            (_, _, Some(script)) => osrun::shell_command(script),
            _ => return Err("the request has neither argv nor shell".into()),
        };

        let sandbox = (p.sandbox.mode != SandboxMode::None).then(|| {
            (
                p.sandbox.clone(),
                SandboxSpec {
                    writable: vec![p.cwd.clone(), tmp.clone()],
                    readable,
                    hidden: self.hidden_paths(),
                    network: Some(p.effective.network),
                },
            )
        });

        Ok(Launch {
            program,
            args,
            raw_tail,
            cwd: p.cwd.clone(),
            env,
            stdin,
            timeout: Duration::from_secs(p.effective.timeout_secs),
            max_output: usize::try_from(p.effective.max_output_bytes).unwrap_or(usize::MAX),
            sandbox,
        })
    }

    /// Redact the output, audit the result, and build the reply.
    fn finish(&self, p: &Prepared, redactor: &Redactor, o: Outcome) -> Response {
        // A stream that was cut (cap, timeout, kill) may end in the middle of a value.
        let cut = o.timed_out || o.output_limit_hit;
        let red = |bytes: &[u8], truncated: bool| {
            if truncated || cut {
                redactor.redact_truncated(bytes)
            } else {
                redactor.redact(bytes)
            }
        };
        let (out, n_out) = red(&o.stdout, o.stdout_truncated);
        let (err, n_err) = red(&o.stderr, o.stderr_truncated);
        let stdout = String::from_utf8_lossy(&out).into_owned();
        let mut stderr = String::from_utf8_lossy(&err).into_owned();
        if o.timed_out {
            stderr.push_str(&format!(
                "\n[credstore: the command ran past its {} s timeout and was killed]\n",
                p.effective.timeout_secs
            ));
        }
        if o.output_limit_hit {
            stderr.push_str(&format!(
                "\n[credstore: output went over {} bytes, so the command was killed]\n",
                p.effective.max_output_bytes
            ));
        }
        let truncated = o.stdout_truncated || o.stderr_truncated;
        let redactions = n_out + n_err;

        let _ = self.audit(
            "run_finished",
            Some(&p.id),
            json!({
                "ok": true,
                "exit_code": o.exit_code,
                "duration_ms": u64::try_from(o.duration.as_millis()).unwrap_or(u64::MAX),
                "sandbox": mode_name(p.sandbox.mode),
                "stdout_bytes": o.stdout.len(),
                "stderr_bytes": o.stderr.len(),
                "truncated": truncated,
                "timed_out": o.timed_out,
                "output_limit_hit": o.output_limit_hit,
                "redactions": redactions,
            }),
        );
        tracing::info!(id = %p.id, exit_code = ?o.exit_code, redactions, "run finished");

        Response::RunResult(RunResult {
            exit_code: o.exit_code,
            stdout,
            stderr,
            truncated,
            redactions,
        })
    }
}
