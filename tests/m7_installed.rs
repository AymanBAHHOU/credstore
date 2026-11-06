//! M7 smoke test against a real installed-mode daemon (the service the installers set
//! up). Ignored by default: CI runs it after `deploy/install.sh` or `deploy/install.ps1`,
//! as a user that is in both credstore groups, with:
//!
//!   CREDSTORE_SMOKE_DIR  a folder the service account can read, holding a copy of the
//!                        `credstore-adversary` binary; approved commands run there
//!                        (default: the working directory).
//!
//! It initializes the vault, adds the fake secret, runs an approved command through the
//! agent endpoint, and checks `doctor`: the agent's user must not be able to read the
//! vault, and the sandbox and hardening report must come from the daemon.

use std::path::PathBuf;
use std::time::Duration;

use credstore::client::{expect_ok, Client};
use credstore::commands;
use credstore::doctor::{doctor, Level};
use credstore_os::{Mode, Platform};
use credstore_proto::{AgentRequest, ApproverOp, GrantScope, Response};
use credstore_tests::{pass, run_request, Scripted, FAKE, PASS};

/// `CREDSTORE_SMOKE_DIR`, else the working directory.
fn smoke_dir() -> PathBuf {
    std::env::var_os("CREDSTORE_SMOKE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs an installed credstore service (CI smoke job)"]
async fn installed_daemon_end_to_end() {
    let platform = Platform::new(Mode::Installed).unwrap();
    let client = Client::new(platform);
    let mut msg = Vec::new();

    commands::init(&client, &Scripted::new(&[PASS, PASS]), &mut msg)
        .await
        .expect("init");
    commands::set(
        &client,
        "API_KEY",
        Some("Smoke test key".into()),
        &Scripted::new(&[PASS, FAKE]),
        &mut msg,
    )
    .await
    .expect("set");

    // An agent request, approved by the human through the approver endpoint.
    let dir = smoke_dir();
    let adversary = dir.join(format!(
        "credstore-adversary{}",
        std::env::consts::EXE_SUFFIX
    ));
    assert!(adversary.exists(), "{} is missing", adversary.display());
    let req = run_request(&[adversary.to_str().unwrap(), "env"], &["API_KEY"], &dir);
    let approve = async {
        let id = loop {
            match client
                .approver(ApproverOp::SubscribePending, pass())
                .await
                .unwrap()
            {
                Response::Pending { requests } if !requests.is_empty() => {
                    break requests[0].id.clone()
                }
                _ => tokio::time::sleep(Duration::from_millis(200)).await,
            }
        };
        expect_ok(
            client
                .approver(
                    ApproverOp::Approve {
                        request_id: id,
                        scope: GrantScope::Once,
                    },
                    pass(),
                )
                .await
                .unwrap(),
        )
        .unwrap();
    };
    let req = AgentRequest::Run(req);
    let (resp, ()) = tokio::join!(client.agent(&req), approve);
    let result = match resp.unwrap() {
        Response::RunResult(r) => r,
        other => panic!("expected a run result, got {other:?}"),
    };
    println!(
        "run: exit {:?}
{}
{}",
        result.exit_code, result.stdout, result.stderr
    );
    assert_eq!(result.exit_code, Some(0));
    assert!(
        result.stdout.contains("API_KEY=[REDACTED:API_KEY]"),
        "{}",
        result.stdout
    );
    assert!(!result.stdout.contains(FAKE) && !result.stderr.contains(FAKE));

    // doctor, as the agent's user.
    let mut out = Vec::new();
    let report = doctor(&client, &Scripted::new(&[PASS]), &mut out)
        .await
        .unwrap();
    let text = String::from_utf8(out).unwrap();
    println!("{text}");
    assert!(!text.contains(FAKE));
    assert_eq!(report.failures(), 0, "{text}");
    for topic in ["vault", "index", "policy"] {
        let c = report.about(topic);
        assert_eq!(c[0].level, Level::Ok, "{topic}: {text}");
        assert!(c[0].detail.contains("cannot read or write"), "{text}");
    }
    assert_eq!(report.about("service")[0].level, Level::Ok, "{text}");
    for group in report.about("groups") {
        assert_eq!(group.level, Level::Ok, "{text}");
    }
    let memory = report.about("memory");
    assert!(
        matches!(memory[0].level, Level::Ok | Level::Info),
        "memory: {text}"
    );
    assert!(!report.about("hardening").is_empty(), "{text}");
    assert!(!report.about("sandbox").is_empty(), "{text}");
}
