//! Shared helpers for the integration and adversarial tests.
//!
//! Each test runs its own dev-mode daemon in-process on a fresh temp home, so tests run
//! in parallel without sharing a vault, policy, audit log or endpoint.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use credstore::client::Client;
use credstore::commands::Prompt;
use credstore_os::{EndpointKind, Ipc, Paths, Platform, PlatformPaths};
use credstore_proto::{
    read_message, write_message, AgentRequest, ApproverOp, ApproverRequest, GrantScope,
    PendingRequest, Proof, Response, RunRequest, SecretText, MAX_FRAME_LEN,
};
use credstored::{DaemonConfig, RunningDaemon};

/// The fake secret every adversarial test uses (spec section 10).
pub const FAKE: &str = "FAKE-SECRET-VALUE-12345";
/// Test passphrase.
pub const PASS: &str = "correct horse battery";

pub fn pass() -> SecretText {
    SecretText::new(PASS.into())
}

/// A daemon on a temp home, plus a client for it.
///
/// Layout: `<root>/home` is the credstore home (vault, policy, audit log; a run may not
/// use it as its cwd) and `<root>/work` is a project folder for commands.
pub struct TestDaemon {
    pub root: PathBuf,
    pub home: PathBuf,
    pub platform: Platform,
    daemon: Option<RunningDaemon>,
}

impl TestDaemon {
    pub async fn start(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "cs-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
                % 1_000_000_000
        ));
        Self::start_at(root.join("home")).await
    }

    /// Start on `home` (`<root>/home`; see [`TestDaemon`]).
    pub async fn start_at(home: PathBuf) -> Self {
        let root = home.parent().expect("home has a parent").to_path_buf();
        let paths = PlatformPaths::dev_with_home(&home);
        let daemon = credstored::start(DaemonConfig {
            paths: paths.clone(),
        })
        .await
        .expect("daemon starts");
        Self {
            root,
            home,
            platform: Platform::with_paths(paths),
            daemon: Some(daemon),
        }
    }

    /// A project folder outside the credstore home (created on first use).
    pub fn work(&self) -> PathBuf {
        let w = self.root.join("work");
        std::fs::create_dir_all(&w).unwrap();
        // Canonical, so it matches what the daemon reports and what policy sees.
        credstore_os::exec::canonical_dir(&w).unwrap()
    }

    pub fn client(&self) -> Client {
        Client::new(self.platform.clone())
    }

    pub fn daemon(&self) -> &RunningDaemon {
        self.daemon.as_ref().expect("running")
    }

    pub async fn stop(mut self) {
        if let Some(d) = self.daemon.take() {
            d.shutdown().await;
        }
    }

    /// Stop the daemon but keep the home for a restart.
    pub async fn stop_keep(mut self) -> PathBuf {
        if let Some(d) = self.daemon.take() {
            d.shutdown().await;
        }
        let home = self.home.clone();
        std::mem::forget(self);
        home
    }

    pub fn audit_log(&self) -> PathBuf {
        self.platform.audit_log().to_owned()
    }

    /// All audit records, parsed.
    pub fn audit_records(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(self.audit_log())
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    pub fn records(&self, event: &str) -> Vec<serde_json::Value> {
        self.audit_records()
            .into_iter()
            .filter(|r| r["event"] == event)
            .collect()
    }

    /// Create the vault with [`PASS`].
    pub async fn init_vault(&self) {
        let mut msg = Vec::new();
        credstore::commands::init(&self.client(), &Scripted::new(&[PASS, PASS]), &mut msg)
            .await
            .unwrap();
    }

    /// Add a secret.
    pub async fn set_secret(&self, name: &str, value: &str) {
        let mut msg = Vec::new();
        credstore::commands::set(
            &self.client(),
            name,
            Some(format!("test secret {name}")),
            &Scripted::new(&[PASS, value]),
            &mut msg,
        )
        .await
        .unwrap();
    }

    /// Replace the policy file (takes effect on reload).
    pub fn write_policy(&self, text: &str) {
        std::fs::write(self.platform.policy_file(), text).unwrap();
    }

    /// Ask the daemon to reload its policy.
    pub async fn reload(&self) -> Response {
        self.client()
            .approver(ApproverOp::Reload, pass())
            .await
            .unwrap()
    }

    /// Send a run request on the agent endpoint.
    pub async fn run(&self, req: RunRequest) -> Response {
        self.client().agent(&AgentRequest::Run(req)).await.unwrap()
    }

    /// Current pending requests (one subscription round trip).
    pub async fn pending(&self) -> Vec<PendingRequest> {
        let mut s = self.connect(EndpointKind::Approver).await;
        write_message(
            &mut s,
            &ApproverRequest {
                proof: Proof { passphrase: pass() },
                op: ApproverOp::SubscribePending,
            },
        )
        .await
        .unwrap();
        match read_message::<Response, _>(&mut s).await.unwrap() {
            Response::Pending { requests } => requests,
            other => panic!("{other:?}"),
        }
    }

    /// Wait until exactly `n` requests are pending.
    pub async fn wait_pending(&self, n: usize) {
        for _ in 0..200 {
            if self.daemon().pending_count() == n {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!(
            "expected {n} pending requests, have {}",
            self.daemon().pending_count()
        );
    }

    /// Send `op` for the only pending request once it shows up.
    pub async fn decide_only(
        &self,
        op: impl FnOnce(credstore_proto::RequestId) -> ApproverOp,
    ) -> Response {
        self.wait_pending(1).await;
        let id = self.pending().await.pop().unwrap().id;
        self.client().approver(op(id), pass()).await.unwrap()
    }

    /// Run `req`, deny it when it reaches the human, and return what the agent got.
    pub async fn run_and_deny(&self, req: RunRequest) -> Response {
        let (r, d) = tokio::join!(
            self.run(req),
            self.decide_only(|request_id| ApproverOp::Deny { request_id })
        );
        assert!(matches!(d, Response::Ok), "{d:?}");
        r
    }

    /// Run `req`, approve it with `scope`, and return what the agent got.
    pub async fn run_and_approve(&self, req: RunRequest, scope: GrantScope) -> Response {
        let (r, d) = tokio::join!(
            self.run(req),
            self.decide_only(|request_id| ApproverOp::Approve { request_id, scope })
        );
        assert!(matches!(d, Response::Ok), "{d:?}");
        r
    }

    /// Raw connection to an endpoint.
    pub async fn connect(&self, kind: EndpointKind) -> <Platform as Ipc>::Stream {
        self.platform
            .connect(&self.platform.endpoint(kind))
            .await
            .unwrap()
    }

    /// Every file under the home, for "the value never hits disk" checks.
    pub fn all_files(&self) -> Vec<PathBuf> {
        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            if let Ok(rd) = std::fs::read_dir(dir) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        walk(&p, out);
                    } else {
                        out.push(p);
                    }
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.root, &mut out);
        out
    }

    /// Assert no file under the test root (home and work folder) contains `needle`.
    pub fn assert_not_on_disk(&self, needle: &str) {
        for f in self.all_files() {
            if let Ok(bytes) = std::fs::read(&f) {
                assert!(
                    !contains(&bytes, needle.as_bytes()),
                    "{} contains the secret",
                    f.display()
                );
            }
        }
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        if self.daemon.is_some() {
            // Not shut down cleanly (test panicked); best effort cleanup.
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}

pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Scripted hidden input for the CLI commands.
pub struct Scripted(RefCell<VecDeque<String>>);

impl Scripted {
    pub fn new(answers: &[&str]) -> Self {
        Self(RefCell::new(
            answers.iter().map(|s| s.to_string()).collect(),
        ))
    }
    pub fn remaining(&self) -> usize {
        self.0.borrow().len()
    }
}

impl Prompt for Scripted {
    fn secret(&self, _: &str) -> anyhow::Result<SecretText> {
        self.0
            .borrow_mut()
            .pop_front()
            .map(SecretText::new)
            .ok_or_else(|| anyhow::anyhow!("unexpected prompt"))
    }

    fn line(&self, _: &str) -> anyhow::Result<String> {
        self.0
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| anyhow::anyhow!("unexpected prompt"))
    }
}

/// Just over the frame limit.
pub const OVERSIZE: u32 = MAX_FRAME_LEN + 1;

/// A program that exists on every CI machine and is not a shell.
pub fn harmless_program() -> &'static str {
    if cfg!(windows) {
        "hostname"
    } else {
        "echo"
    }
}

/// A run request with a valid reason.
pub fn run_request(argv: &[&str], secrets: &[&str], cwd: &Path) -> RunRequest {
    RunRequest {
        argv: Some(argv.iter().map(|s| s.to_string()).collect()),
        shell: None,
        secrets: secrets.iter().map(|s| s.to_string()).collect(),
        reason: "Integration test: print something harmless".into(),
        cwd: cwd.to_string_lossy().into_owned(),
        timeout_secs: None,
        injection: None,
    }
}

/// True if the request was approved and run (whatever the command's exit code).
pub fn approved(r: &Response) -> bool {
    matches!(r, Response::RunResult(_))
}

/// The denial text, or panic.
pub fn denial(r: &Response) -> &str {
    match r {
        Response::Denied { reason } => reason,
        other => panic!("expected a denial, got {other:?}"),
    }
}

/// The encodings the redactor must catch (spec 6.5), as a command would print them.
pub mod enc {
    pub const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    pub const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    pub fn base64(data: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                chunk.get(1).copied().unwrap_or(0),
                chunk.get(2).copied().unwrap_or(0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(alphabet[((n >> (18 - 6 * i)) & 63) as usize] as char);
                } else if pad {
                    out.push('=');
                }
            }
        }
        out
    }

    pub fn hex(data: &[u8], upper: bool) -> String {
        data.iter()
            .map(|b| {
                if upper {
                    format!("{b:02X}")
                } else {
                    format!("{b:02x}")
                }
            })
            .collect()
    }

    pub fn url(data: &[u8], plus_for_space: bool) -> String {
        let mut out = String::new();
        for &b in data {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    out.push(b as char)
                }
                b' ' if plus_for_space => out.push('+'),
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }

    /// Each form on its own: base64 (3 alignments, both alphabets), hex, URL, JSON.
    pub fn known_forms(v: &[u8]) -> Vec<String> {
        let mut forms = Vec::new();
        for prefix in [&b""[..], b"a", b"ab"] {
            let data = [prefix, v].concat();
            forms.push(base64(&data, STD, true));
            forms.push(base64(&data, URL, false));
        }
        forms.push(hex(v, false));
        forms.push(hex(v, true));
        forms.push(url(v, true));
        forms.push(url(v, false));
        let json = serde_json::to_string(&String::from_utf8_lossy(v)).unwrap_or_default();
        forms.push(json.trim_matches('"').to_owned());
        forms
    }
}

/// Everything `tracing` logs in this test process, for the "never in tracing output"
/// checks. Installed once per test binary by [`capture_tracing`].
pub fn captured_tracing() -> String {
    String::from_utf8_lossy(&TRACE_BUF.lock().unwrap()).into_owned()
}

static TRACE_BUF: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());

struct TraceWriter;

impl std::io::Write for TraceWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        TRACE_BUF.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Route all `tracing` output (every level) of this test binary into a buffer.
pub fn capture_tracing() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let sub = tracing_subscriber::fmt()
            .with_writer(|| TraceWriter)
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish();
        let _ = tracing::subscriber::set_global_default(sub);
    });
}
