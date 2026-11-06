//! M3 acceptance: policy loaded by the daemon, denials before the human is asked, clear
//! errors, fail closed, reload (request and SIGHUP).

use credstore::client::expect_status;
use credstore_os::Paths;
use credstore_proto::{ApproverOp, ErrorCode, Response};
use credstore_tests::*;

const PENDING_M4: &str = "approvals are not built yet";

async fn ready(tag: &str) -> TestDaemon {
    let d = TestDaemon::start(tag).await;
    d.init_vault().await;
    d.set_secret("API_KEY", FAKE).await;
    d.set_secret("OTHER_KEY", "other-fake-value").await;
    d
}

fn cwd(d: &TestDaemon) -> std::path::PathBuf {
    let p = d.home.join("project");
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[tokio::test(flavor = "multi_thread")]
async fn init_writes_a_starter_policy_that_allows_with_approval() {
    let d = ready("m3start").await;
    let text = std::fs::read_to_string(d.platform.policy_file()).unwrap();
    assert!(text.contains("[defaults]"));
    let status = expect_status(
        d.client()
            .approver(ApproverOp::Status, pass())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(status.policy_error, None);

    let r = d
        .run(run_request(
            &[harmless_program(), "hi"],
            &["API_KEY"],
            &cwd(&d),
        ))
        .await;
    assert!(denial(&r).contains(PENDING_M4), "{r:?}");
    assert!(d.records("policy_denied").is_empty());
    let req = d.records("request").pop().expect("request audited");
    assert_eq!(req["secrets"][0], "API_KEY");
    assert!(req["program"].as_str().unwrap().len() > 3, "{req}");
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_denials_are_returned_and_audited() {
    let d = ready("m3deny").await;
    let dir = cwd(&d);
    let allowed_dir = format!("{}/**", dir.to_string_lossy().replace('\\', "/"));
    d.write_policy(&format!(
        r#"
[secret.API_KEY]
allow_commands = ["{prog} *"]
allow_dirs = ["{allowed_dir}"]
"#,
        prog = harmless_program()
    ));
    assert!(matches!(d.reload().await, Response::Ok));

    // Allowed: right program, right dir.
    let r = d
        .run(run_request(&[harmless_program(), "x"], &["API_KEY"], &dir))
        .await;
    assert!(denial(&r).contains(PENDING_M4), "{r:?}");

    // Wrong command.
    let other = if cfg!(windows) { "whoami" } else { "ls" };
    let r = d.run(run_request(&[other], &["API_KEY"], &dir)).await;
    assert!(
        denial(&r).contains("command not allowed for API_KEY"),
        "{r:?}"
    );

    // Wrong directory.
    let r = d
        .run(run_request(
            &[harmless_program(), "x"],
            &["API_KEY"],
            &d.home,
        ))
        .await;
    assert!(
        denial(&r).contains("working directory not allowed"),
        "{r:?}"
    );

    // Shell mode.
    let mut shell = run_request(&[], &["API_KEY"], &dir);
    shell.argv = None;
    shell.shell = Some("echo hi".into());
    let r = d.run(shell).await;
    assert!(
        denial(&r).contains("shell commands are not allowed"),
        "{r:?}"
    );

    // A shell program in argv form is shell mode too.
    let sh: &[&str] = if cfg!(windows) {
        &["cmd", "/c", "echo hi"]
    } else {
        &["sh", "-c", "echo hi"]
    };
    let r = d.run(run_request(sh, &["OTHER_KEY"], &dir)).await;
    assert!(
        denial(&r).contains("shell commands are not allowed"),
        "{r:?}"
    );

    let denied = d.records("policy_denied");
    assert_eq!(denied.len(), 4, "{denied:?}");
    assert!(denied[0]["denial"]
        .as_str()
        .unwrap()
        .contains("command not allowed"));
    assert!(denied.iter().all(|r| r["id"].as_str().is_some()));
    d.assert_not_on_disk(FAKE);
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn strict_mode_denies_secrets_without_a_block() {
    let d = ready("m3strict").await;
    d.write_policy("[defaults]\nstrict = true\n[secret.API_KEY]\n");
    assert!(matches!(d.reload().await, Response::Ok));
    let dir = cwd(&d);
    let r = d
        .run(run_request(&[harmless_program()], &["OTHER_KEY"], &dir))
        .await;
    assert!(denial(&r).contains("policy is strict"), "{r:?}");
    let r = d
        .run(run_request(&[harmless_program()], &["API_KEY"], &dir))
        .await;
    assert!(denial(&r).contains(PENDING_M4), "{r:?}");
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_or_broken_policy_fails_closed() {
    let d = ready("m3closed").await;
    let dir = cwd(&d);

    d.write_policy("[defaults]\nsandbox = \"sometimes\"\n");
    match d.reload().await {
        Response::Error { code, message } => {
            assert_eq!(code, ErrorCode::BadRequest);
            assert!(message.contains("unknown variant `sometimes`"), "{message}");
            assert!(message.contains("every run is denied"), "{message}");
        }
        other => panic!("{other:?}"),
    }
    let r = d
        .run(run_request(&[harmless_program()], &["API_KEY"], &dir))
        .await;
    assert!(denial(&r).contains("no valid policy is loaded"), "{r:?}");
    let status = expect_status(
        d.client()
            .approver(ApproverOp::Status, pass())
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(status.policy_error.unwrap().contains("sometimes"));

    std::fs::remove_file(d.platform.policy_file()).unwrap();
    assert!(matches!(d.reload().await, Response::Error { .. }));
    let r = d
        .run(run_request(&[harmless_program()], &["API_KEY"], &dir))
        .await;
    assert!(denial(&r).contains("no policy file"), "{r:?}");

    // Fixing it and reloading restores service.
    d.write_policy("");
    assert!(matches!(d.reload().await, Response::Ok));
    let r = d
        .run(run_request(&[harmless_program()], &["API_KEY"], &dir))
        .await;
    assert!(denial(&r).contains(PENDING_M4), "{r:?}");

    let reloads = d.records("config_reloaded");
    assert!(reloads.iter().any(|r| r["ok"] == false));
    assert_eq!(reloads.last().unwrap()["ok"], true);
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_without_a_policy_starts_but_denies() {
    let d = TestDaemon::start("m3nopol").await;
    let r = d
        .run(run_request(&[harmless_program()], &["API_KEY"], &d.home))
        .await;
    // No vault yet either: that is reported first.
    assert!(matches!(r, Response::Error { .. }), "{r:?}");
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_requests_are_rejected_before_policy() {
    let d = ready("m3bad").await;
    let dir = cwd(&d);
    let cases: Vec<(&str, credstore_proto::RunRequest, &str)> = vec![
        (
            "unknown secret",
            run_request(&[harmless_program()], &["NOPE_KEY"], &dir),
            "unknown secret NOPE_KEY",
        ),
        (
            "relative cwd",
            {
                let mut r = run_request(&[harmless_program()], &["API_KEY"], &dir);
                r.cwd = "project".into();
                r
            },
            "absolute",
        ),
        (
            "missing cwd",
            run_request(&[harmless_program()], &["API_KEY"], &dir.join("gone")),
            "cwd does not exist",
        ),
        (
            "empty reason",
            {
                let mut r = run_request(&[harmless_program()], &["API_KEY"], &dir);
                r.reason.clear();
                r
            },
            "reason must be",
        ),
        (
            "program not on PATH",
            run_request(&["credstore-no-such-program"], &["API_KEY"], &dir),
            "not found",
        ),
        (
            "NUL byte",
            run_request(&[harmless_program(), "a\0b"], &["API_KEY"], &dir),
            "NUL",
        ),
        (
            "oversize argv",
            {
                let big = "a".repeat(70 * 1024);
                run_request(&[harmless_program(), &big], &["API_KEY"], &dir)
            },
            "longer than",
        ),
    ];
    for (name, req, want) in cases {
        match d.run(req).await {
            Response::Error { code, message } => {
                assert_eq!(code, ErrorCode::BadRequest, "{name}");
                assert!(message.contains(want), "{name}: {message:?}");
            }
            other => panic!("{name}: {other:?}"),
        }
    }
    assert!(
        d.records("request").is_empty(),
        "invalid requests never reach policy"
    );
    d.stop().await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn sighup_reloads_the_policy() {
    let d = ready("m3hup").await;
    let dir = cwd(&d);
    d.write_policy("[defaults]\nstrict = true\n");
    let before = d.records("config_reloaded").len();
    let status = std::process::Command::new("kill")
        .args(["-HUP", &std::process::id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let mut reloaded = false;
    for _ in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if d.records("config_reloaded")
            .iter()
            .skip(before)
            .any(|r| r["trigger"] == "signal")
        {
            reloaded = true;
            break;
        }
    }
    assert!(reloaded, "SIGHUP did not reload the policy");
    let r = d
        .run(run_request(&[harmless_program()], &["API_KEY"], &dir))
        .await;
    assert!(denial(&r).contains("policy is strict"), "{r:?}");
    d.stop().await;
}
