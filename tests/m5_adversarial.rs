//! M5 adversarial suite (spec section 10).
//!
//! Every test injects `FAKE-SECRET-VALUE-12345` and checks that it never shows up in what
//! the agent gets back, the audit log, any file under the test tree, or tracing output.
//! Items of section 10 covered elsewhere: agent-endpoint misuse and approver requests
//! without a valid passphrase in `m2_daemon.rs`; unknown secret, relative cwd, empty
//! reason, oversize argv and NUL bytes in `m3_policy.rs`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use credstore_os::sandbox::capabilities;
use credstore_os::{MemoryGuard, Paths};
use credstore_proto::{ApproverOp, GrantScope, Injection, Response, RunResult};
use credstore_tests::*;

const BASE_POLICY: &str = "[defaults]
require_approval = false
allow_shell = true
max_runtime_secs = 60
";

fn adversary() -> &'static str {
    env!("CARGO_BIN_EXE_credstore-adversary")
}

/// A daemon with `API_KEY = FAKE`, policy `BASE_POLICY + extra`, vault unlocked.
async fn ready(tag: &str, extra: &str) -> (TestDaemon, PathBuf) {
    capture_tracing();
    let d = TestDaemon::start(tag).await;
    d.init_vault().await;
    d.set_secret("API_KEY", FAKE).await;
    let base = if extra.contains("require_approval") {
        BASE_POLICY.replace("require_approval = false\n", "")
    } else {
        BASE_POLICY.to_owned()
    };
    d.write_policy(&format!("{base}{extra}"));
    assert!(matches!(d.reload().await, Response::Ok));
    let r = d
        .client()
        .approver(ApproverOp::Unlock, pass())
        .await
        .unwrap();
    assert!(matches!(r, Response::Ok), "{r:?}");
    let work = d.work();
    (d, work)
}

fn request(argv: &[&str], dir: &Path) -> credstore_proto::RunRequest {
    let mut r = run_request(argv, &["API_KEY"], dir);
    r.reason = "Adversarial test: try to leak the injected secret".into();
    r
}

fn result(r: Response) -> RunResult {
    match r {
        Response::RunResult(r) => r,
        other => panic!("expected a run result, got {other:?}"),
    }
}

async fn run_adv(d: &TestDaemon, dir: &Path, args: &[&str]) -> RunResult {
    let mut argv = vec![adversary()];
    argv.extend_from_slice(args);
    result(d.run(request(&argv, dir)).await)
}

/// The value is nowhere: not in results, audit log, files, or tracing.
fn assert_clean(d: &TestDaemon, results: &[&RunResult]) {
    for r in results {
        assert!(!r.stdout.contains(FAKE), "stdout leaked: {}", r.stdout);
        assert!(!r.stderr.contains(FAKE), "stderr leaked: {}", r.stderr);
    }
    let audit = std::fs::read_to_string(d.audit_log()).unwrap();
    assert!(!audit.contains(FAKE), "audit log contains the secret");
    d.assert_not_on_disk(FAKE);
    assert!(
        !captured_tracing().contains(FAKE),
        "tracing output contains the secret"
    );
}

fn last_record(d: &TestDaemon, event: &str) -> serde_json::Value {
    d.records(event)
        .pop()
        .unwrap_or_else(|| panic!("no {event} record"))
}

#[tokio::test(flavor = "multi_thread")]
async fn environment_dumps_are_redacted() {
    let (d, dir) = ready("m5env", "").await;
    let mut commands: Vec<Vec<&str>> = vec![vec![adversary(), "env"]];
    if cfg!(windows) {
        commands.push(vec!["cmd", "/c", "echo %API_KEY%"]);
        commands.push(vec!["cmd", "/c", "set"]);
        commands.push(vec![
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-ChildItem Env: | Format-Table -AutoSize -Wrap | Out-String -Width 500",
        ]);
    } else {
        commands.push(vec!["printenv"]);
        commands.push(vec!["env"]);
        commands.push(vec!["sh", "-c", "echo $API_KEY"]);
        commands.push(vec!["sh", "-c", "set"]);
        if cfg!(target_os = "linux") {
            commands.push(vec!["cat", "/proc/self/environ"]);
        }
    }
    let mut results = Vec::new();
    for argv in &commands {
        let r = result(d.run(request(argv, &dir)).await);
        assert!(
            r.redactions >= 1,
            "{argv:?} printed no secret? stdout: {} stderr: {}",
            r.stdout,
            r.stderr
        );
        assert!(
            r.stdout.contains("[REDACTED:API_KEY]"),
            "{argv:?}: {}",
            r.stdout
        );
        results.push(r);
    }
    // The cleared environment: none of this test process's variables got through.
    let env = &results[0].stdout;
    assert!(!env.contains("CARGO_"), "daemon environment leaked: {env}");
    assert_clean(&d, &results.iter().collect::<Vec<_>>());
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn encoded_values_are_redacted() {
    let (d, dir) = ready("m5enc", "").await;
    let r = run_adv(&d, &dir, &["encode", "API_KEY"]).await;
    let forms = enc::known_forms(FAKE.as_bytes());
    for f in &forms {
        assert!(
            !r.stdout.contains(f.as_str()),
            "{f} not redacted:\n{}",
            r.stdout
        );
    }
    assert!(r.redactions >= forms.len() as u64, "{r:?}");
    assert_clean(&d, &[&r]);
    d.stop().await;
}

/// Known bypass, documented in the threat model: redaction matches known encodings
/// only, so a command that reverses (or rot13s, splits, compresses...) the value gets it
/// out. The controls are the human reading the command, policy and the sandbox.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "known bypass: reversed values are not redacted (see threat model)"]
async fn reversed_value_is_a_known_bypass() {
    let (d, dir) = ready("m5rev", "").await;
    let r = run_adv(&d, &dir, &["reverse", "API_KEY"]).await;
    let reversed: String = FAKE.chars().rev().collect();
    assert!(!r.stdout.contains(&reversed));
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn credstore_files_are_hidden_or_the_gap_is_reported() {
    let (d, dir) = ready("m5files", "").await;
    let p = &d.platform;
    let targets: Vec<String> = [
        p.vault_file(),
        p.index_file(),
        p.policy_file().to_path_buf(),
        p.audit_log().to_path_buf(),
        p.run_dir().to_path_buf(),
    ]
    .iter()
    .map(|x| x.to_string_lossy().into_owned())
    .collect();
    let mut args = vec!["read"];
    args.extend(targets.iter().map(String::as_str));
    let r = run_adv(&d, &dir, &args).await;

    // Writing outside cwd and the run's temp dir.
    let outside = d.root.join("outside.txt");
    let w = run_adv(&d, &dir, &["write", &outside.to_string_lossy()]).await;
    // Writing inside cwd is allowed.
    let inside = dir.join("inside.txt");
    let w2 = run_adv(&d, &dir, &["write", &inside.to_string_lossy()]).await;
    assert!(w2.stdout.contains("WROTE"), "{w2:?}");

    let caps = capabilities();
    if caps.hides_paths {
        assert!(
            !r.stdout.contains("READ "),
            "{} let the command read credstore files:\n{}",
            caps.detail,
            r.stdout
        );
        // Checked on the host: under bubblewrap /tmp is a private tmpfs, so the write
        // "succeeds" inside the sandbox and never reaches the real file.
        assert!(
            !outside.exists(),
            "{} let the command write outside cwd ({})",
            caps.detail,
            w.stdout
        );
    } else {
        let started = last_record(&d, "run_started");
        let gaps = started["sandbox_gaps"].to_string();
        assert!(
            gaps.contains("does not hide files") || gaps.contains("no sandbox"),
            "{started}"
        );
        eprintln!("note: {} does not hide files; gap reported", caps.detail);
    }
    assert_clean(&d, &[&r, &w, &w2]);
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn daemon_memory_cannot_be_read() {
    let (d, dir) = ready("m5mem", "").await;
    // The daemon runs inside this test process: harden it as `credstored` does.
    for item in d.platform.harden_process() {
        eprintln!("hardening: {} = {:?}", item.name, item.status);
    }
    // Root (CAP_SYS_PTRACE) and Windows SeDebugPrivilege read any process whatever its
    // protection; only a sandbox that isolates the daemon (or another user) stops them.
    use credstore_proto::SandboxMode;
    let isolated = matches!(
        capabilities().mode,
        SandboxMode::Bwrap | SandboxMode::Landlock | SandboxMode::Seatbelt
    );
    if credstore_os::probe::bypasses_process_protection() && !isolated {
        eprintln!("skipped: this test runs with root or debug privileges and no sandbox");
        d.stop().await;
        return;
    }
    let pid = std::process::id().to_string();
    let r = if cfg!(any(target_os = "linux", windows)) {
        run_adv(&d, &dir, &["readmem", &pid, "API_KEY"]).await
    } else {
        // macOS: task_for_pid needs the debugger entitlement or root, and the daemon sets
        // PT_DENY_ATTACH; there is no unprivileged way to even attempt it from a test.
        eprintln!("skipped on macOS: task_for_pid cannot be attempted without entitlements");
        d.stop().await;
        return;
    };
    assert!(
        r.stdout.contains("denied"),
        "daemon memory was readable: stdout {} stderr {}",
        r.stdout,
        r.stderr
    );
    assert_clean(&d, &[&r]);
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn network_deny_is_enforced_or_the_run_is_denied() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let caps = capabilities();

    let (d, dir) = ready("m5net", "network = \"deny\"\nsandbox = \"require\"\n").await;
    if caps.network_restriction {
        let r = run_adv(&d, &dir, &["connect", &addr]).await;
        assert!(
            r.stdout.contains("connect failed"),
            "{}: {r:?}",
            caps.detail
        );
        assert_clean(&d, &[&r]);
    } else {
        let r = d.run(request(&[adversary(), "connect", &addr], &dir)).await;
        let why = denial(&r);
        assert!(
            why.contains("cannot be enforced") || why.contains("no sandbox"),
            "{why}"
        );
        // With "prefer" it runs, and the gap is on record.
        d.write_policy(&format!(
            "{BASE_POLICY}network = \"deny\"\nsandbox = \"prefer\"\n"
        ));
        assert!(matches!(d.reload().await, Response::Ok));
        let r = run_adv(&d, &dir, &["connect", &addr]).await;
        let started = last_record(&d, "run_started");
        assert!(started["network_enforced"] == false, "{started}");
        assert!(
            started["sandbox_gaps"].to_string().contains("network"),
            "{started}"
        );
        assert_clean(&d, &[&r]);
    }
    drop(listener);
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn background_processes_die_with_the_run() {
    let (d, dir) = ready("m5bg", "").await;
    let marker = dir.join("survivor.txt");
    let mut req = request(
        &[adversary(), "spawn-sleeper", &marker.to_string_lossy(), "4"],
        &dir,
    );
    req.timeout_secs = Some(2);
    let started = std::time::Instant::now();
    let r = result(d.run(req).await);
    assert!(started.elapsed() < Duration::from_secs(15), "{r:?}");
    assert_eq!(r.exit_code, None, "{r:?}");
    assert!(r.stderr.contains("timeout"), "{r:?}");
    assert!(r.stdout.contains("spawned"), "{r:?}");
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert!(
        !marker.exists(),
        "a background process outlived the run (sandbox: {})",
        capabilities().detail
    );
    assert_eq!(last_record(&d, "run_finished")["timed_out"], true);
    assert_clean(&d, &[&r]);
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn output_floods_are_capped_and_killed() {
    let (d, dir) = ready("m5flood", "max_output_bytes = 20000\n").await;
    let started = std::time::Instant::now();
    let r = run_adv(&d, &dir, &["flood", "1073741824"]).await;
    assert!(started.elapsed() < Duration::from_secs(30), "took too long");
    assert!(r.truncated, "{}", r.stderr);
    assert!(r.stdout.len() <= 20000, "{}", r.stdout.len());
    assert!(r.stderr.contains("output went over"), "{}", r.stderr);
    let fin = last_record(&d, "run_finished");
    assert_eq!(fin["output_limit_hit"], true, "{fin}");
    assert_clean(&d, &[&r]);
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn file_injection_files_are_removed_after_the_run() {
    let (d, dir) = ready("m5file", "").await;
    let mut req = request(&[adversary(), "cat-env-file", "API_KEY_FILE"], &dir);
    req.injection = Some(Injection::File);
    let r = result(d.run(req).await);
    let path = r
        .stdout
        .lines()
        .find_map(|l| l.strip_prefix("path="))
        .expect("path printed")
        .to_owned();
    assert!(!path.is_empty(), "{r:?}");
    assert!(r.redactions >= 1, "{r:?}");
    assert!(!Path::new(&path).exists(), "{path} still exists");
    let run_dir = d.platform.run_dir();
    assert_eq!(std::fs::read_dir(run_dir).unwrap().count(), 0);
    assert_clean(&d, &[&r]);
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn stdin_injection_is_redacted() {
    let (d, dir) = ready("m5stdin", "").await;
    let mut req = request(&[adversary(), "stdin"], &dir);
    req.injection = Some(Injection::Stdin);
    let r = result(d.run(req).await);
    assert!(r.stdout.contains("[REDACTED:API_KEY]"), "{r:?}");
    assert_clean(&d, &[&r]);
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_approvals_never_cross_apply() {
    let (d, dir) = ready("m5conc", "require_approval = true\n").await;
    let one = request(&[adversary(), "echo", "one"], &dir);
    let two = request(&[adversary(), "echo", "two"], &dir);
    let decide = async {
        d.wait_pending(2).await;
        let pending = d.pending().await;
        let id_of = |word: &str| {
            pending
                .iter()
                .find(|p| p.argv.as_ref().is_some_and(|a| a.iter().any(|x| x == word)))
                .unwrap()
                .id
                .clone()
        };
        let (id_one, id_two) = (id_of("one"), id_of("two"));
        let ok = d
            .client()
            .approver(
                ApproverOp::Approve {
                    request_id: id_two,
                    scope: GrantScope::Once,
                },
                pass(),
            )
            .await
            .unwrap();
        assert!(matches!(ok, Response::Ok), "{ok:?}");
        // The other request is still waiting for its own decision.
        d.wait_pending(1).await;
        let ok = d
            .client()
            .approver(ApproverOp::Deny { request_id: id_one }, pass())
            .await
            .unwrap();
        assert!(matches!(ok, Response::Ok), "{ok:?}");
    };
    let (r1, r2, ()) = tokio::join!(d.run(one), d.run(two), decide);
    assert!(denial(&r1).contains("denied by the human"), "{r1:?}");
    let r2 = result(r2);
    assert_eq!(r2.stdout.trim(), "two");
    assert_clean(&d, &[&r2]);
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn leftover_run_directories_are_swept_at_start() {
    let (d, _dir) = ready("m5sweep", "").await;
    // What a daemon killed mid-run leaves: a run dir with a secret file.
    let dead = d.platform.run_dir().join("req_killed");
    std::fs::create_dir_all(dead.join("files")).unwrap();
    std::fs::write(dead.join("files").join("API_KEY"), FAKE).unwrap();

    let home = d.stop_keep().await;
    let d = TestDaemon::start_at(home).await;
    assert!(!dead.exists(), "leftover run dir survived a restart");
    assert_eq!(d.records("run_dir_swept").len(), 1);
    d.assert_not_on_disk(FAKE);
    d.stop().await;
}
