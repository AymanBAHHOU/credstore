//! M12: the Windows AppContainer. Commands run inside `credstore.run` when the container
//! can use their folder and program; otherwise they fall back to the Job Object alone,
//! with the reason shown, or are denied under `sandbox = "require"`.
//!
//! The adversarial suite (`m5_adversarial.rs`) covers what a run can see and do. These
//! tests cover the choice of sandbox. They also pass with
//! `CREDSTORE_FORCE_SANDBOX=job-object` (CI runs both), and do nothing off Windows.

#![cfg(windows)]

use std::path::Path;

use credstore_os::sandbox::{capabilities, mode_name};
use credstore_proto::{ApproverOp, Response, SandboxMode};
use credstore_tests::*;

const POLICY: &str = "[defaults]
require_approval = false
allow_shell = true
max_runtime_secs = 60
";

fn appcontainer() -> bool {
    capabilities().mode == SandboxMode::AppContainer
}

async fn ready(tag: &str, extra: &str) -> TestDaemon {
    let d = TestDaemon::start(tag).await;
    d.init_vault().await;
    d.set_secret("API_KEY", FAKE).await;
    d.write_policy(&format!("{POLICY}{extra}"));
    assert!(matches!(d.reload().await, Response::Ok));
    let r = d
        .client()
        .approver(ApproverOp::Unlock, pass())
        .await
        .unwrap();
    assert!(matches!(r, Response::Ok), "{r:?}");
    d
}

/// A folder the container was never given (next to the work folder, not inside it).
fn closed_folder(d: &TestDaemon) -> std::path::PathBuf {
    let dir = d.root.join("closed");
    std::fs::create_dir_all(&dir).unwrap();
    credstore_os::exec::canonical_dir(&dir).unwrap()
}

fn last_start(d: &TestDaemon) -> serde_json::Value {
    d.records("run_started")
        .pop()
        .expect("a run_started record")
}

#[tokio::test]
async fn a_granted_folder_runs_in_the_appcontainer() {
    let d = ready("m12-granted", "").await;
    let r = d
        .run(run_request(&[harmless_program()], &["API_KEY"], &d.work()))
        .await;
    assert!(approved(&r), "{r:?}");
    let start = last_start(&d);
    assert_eq!(start["sandbox"], mode_name(capabilities().mode), "{start}");
    if appcontainer() {
        assert_eq!(start["sandbox"], "appcontainer", "{start}");
    }
    d.stop().await;
}

#[tokio::test]
async fn a_folder_the_container_cannot_use_falls_back_with_the_reason() {
    let d = ready("m12-closed", "").await;
    let closed = closed_folder(&d);
    let r = d
        .run(run_request(&[harmless_program()], &["API_KEY"], &closed))
        .await;
    assert!(approved(&r), "{r:?}");
    let start = last_start(&d);
    assert_eq!(start["sandbox"], "job-object", "{start}");
    if appcontainer() {
        let gaps = start["sandbox_gaps"].to_string();
        assert!(gaps.contains("Job Object only"), "{gaps}");
        assert!(gaps.contains("credstore grant"), "{gaps}");
    }
    d.stop().await;
}

#[tokio::test]
async fn require_denies_what_the_container_cannot_run() {
    if !appcontainer() {
        return; // Without the container, "require" is covered by m5.
    }
    let d = ready("m12-require", "sandbox = \"require\"\n").await;
    let closed = closed_folder(&d);
    let r = d
        .run(run_request(&[harmless_program()], &["API_KEY"], &closed))
        .await;
    let why = denial(&r);
    assert!(why.contains("sandbox = \"require\""), "{why}");
    assert!(why.contains("credstore grant"), "{why}");
    // In a granted folder the same policy runs.
    let r = d
        .run(run_request(&[harmless_program()], &["API_KEY"], &d.work()))
        .await;
    assert!(approved(&r), "{r:?}");
    d.stop().await;
}

#[tokio::test]
async fn the_container_cannot_read_the_humans_files() {
    let d = ready("m12-read", "").await;
    let closed = closed_folder(&d);
    let file = closed.join("private.txt");
    std::fs::write(&file, "only for the human").unwrap();
    let path = file.to_string_lossy().into_owned();
    let r = d
        .run(run_request(
            &["cmd.exe", "/d", "/c", "type", &path],
            &["API_KEY"],
            &d.work(),
        ))
        .await;
    let Response::RunResult(r) = r else {
        panic!("expected a run result, got {r:?}");
    };
    if appcontainer() {
        assert_ne!(r.exit_code, Some(0), "{r:?}");
        assert!(!r.stdout.contains("only for the human"), "{}", r.stdout);
    } else {
        // The documented gap of the Job Object: it hides nothing.
        assert!(r.stdout.contains("only for the human"), "{r:?}");
    }
    assert!(Path::new(&path).exists());
    d.stop().await;
}
