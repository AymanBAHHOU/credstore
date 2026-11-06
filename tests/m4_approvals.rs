//! M4 acceptance: pending queue, `watch`, passphrase proof per approval, rate limit,
//! once/session grants, grant expiry, idle relock, lock wipes.

use std::time::{Duration, Instant};

use credstore::client::expect_status;
use credstore_proto::{ApproverOp, ErrorCode, GrantScope, RequestId, Response, SecretText};
use credstore_tests::*;

async fn ready(tag: &str, policy: &str) -> (TestDaemon, std::path::PathBuf) {
    let d = TestDaemon::start(tag).await;
    d.init_vault().await;
    d.set_secret("API_KEY", FAKE).await;
    d.set_secret("OTHER_KEY", "other-fake-value").await;
    d.write_policy(policy);
    assert!(matches!(d.reload().await, Response::Ok));
    let dir = d.work();
    (d, dir)
}

fn req(dir: &std::path::Path, secret: &str) -> credstore_proto::RunRequest {
    run_request(&[harmless_program(), "x"], &[secret], dir)
}

#[tokio::test(flavor = "multi_thread")]
async fn request_blocks_until_approved() {
    let (d, dir) = ready("m4block", "").await;
    let mut approved_at = None;
    let ((r, finished_at), ()) = tokio::join!(
        async {
            let r = d.run(req(&dir, "API_KEY")).await;
            (r, Instant::now())
        },
        async {
            d.wait_pending(1).await;
            let status = expect_status(
                d.client()
                    .approver(ApproverOp::Status, pass())
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(status.pending, 1);
            tokio::time::sleep(Duration::from_millis(500)).await;
            let id = d.pending().await.pop().unwrap().id;
            approved_at = Some(Instant::now());
            let resp = d
                .client()
                .approver(
                    ApproverOp::Approve {
                        request_id: id,
                        scope: GrantScope::Once,
                    },
                    pass(),
                )
                .await
                .unwrap();
            assert!(matches!(resp, Response::Ok), "{resp:?}");
        }
    );
    assert!(approved(&r), "{r:?}");
    assert!(
        finished_at >= approved_at.unwrap(),
        "answered before approval"
    );
    let rec = d.records("approved").pop().unwrap();
    assert_eq!(rec["via"], "human");
    assert_eq!(rec["scope"], "once");
    assert_eq!(d.daemon().pending_count(), 0);
    d.assert_not_on_disk(FAKE);
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn watch_shows_the_full_request_and_needs_the_passphrase() {
    let (d, dir) = ready("m4watch", "").await;
    let client = d.client();
    // Subscribe, choose once, wrong passphrase, choose once again, right passphrase.
    let script = Scripted::new(&[PASS, "o", "wrong passphrase", "x", "o", PASS]);
    let mut out = Vec::new();
    let mut request = req(&dir, "API_KEY");
    request.reason = "Check the API key works against the test account".into();
    let r = tokio::select! {
        w = credstore::watch::watch(&client, &script, &mut out) => panic!("watch ended: {w:?}"),
        r = d.run(request) => r,
    };
    assert!(approved(&r), "{r:?}");
    let shown = String::from_utf8_lossy(&out).into_owned();
    for want in [
        "reason:   Check the API key works against the test account",
        &format!("command:  {} x", harmless_program()),
        "program:  ",
        &format!("cwd:      {}", dir.display()),
        "secrets:  API_KEY (test secret API_KEY)",
        "inject:   env",
        &format!(
            "sandbox:  {}    network: inherit",
            credstore_os::sandbox::mode_name(credstore_os::sandbox::capabilities().mode)
        ),
        &format!("pid {}", std::process::id()),
        "Wrong passphrase. The request is still pending.",
        "Type o, s or d.",
        "Approved once.",
    ] {
        assert!(shown.contains(want), "missing {want:?} in:\n{shown}");
    }
    assert!(!shown.contains(FAKE) && !shown.contains(PASS));
    assert_eq!(d.records("auth_failed").len(), 1);
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_passphrases_are_rate_limited_and_the_request_stays_pending() {
    let (d, dir) = ready("m4rate", "[defaults]\napproval_timeout_secs = 12\n").await;
    let (r, ()) = tokio::join!(d.run(req(&dir, "API_KEY")), async {
        d.wait_pending(1).await;
        let id = d.pending().await.pop().unwrap().id;
        let c = d.client();
        let approve = |p: &str| {
            c.approver(
                ApproverOp::Approve {
                    request_id: id.clone(),
                    scope: GrantScope::Once,
                },
                SecretText::new(p.into()),
            )
        };
        for _ in 0..credstored::MAX_FAILURES {
            match approve("wrong passphrase").await.unwrap() {
                Response::Error { code, .. } => assert_eq!(code, ErrorCode::Unauthorized),
                other => panic!("{other:?}"),
            }
            assert_eq!(d.daemon().pending_count(), 1, "still pending");
        }
        match approve(PASS).await.unwrap() {
            Response::Error { code, .. } => assert_eq!(code, ErrorCode::RateLimited),
            other => panic!("{other:?}"),
        }
        assert_eq!(d.daemon().pending_count(), 1);
    });
    assert_eq!(denial(&r), "approval timed out");
    assert_eq!(d.records("denied").pop().unwrap()["via"], "timeout");
    assert!(!d.daemon().is_unlocked());
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn session_grant_covers_the_same_request_until_its_ttl() {
    let (d, dir) = ready("m4grant", "[defaults]\ngrant_ttl_secs = 2\n").await;
    let r = d
        .run_and_approve(req(&dir, "API_KEY"), GrantScope::Session { ttl_secs: 600 })
        .await;
    assert!(approved(&r), "{r:?}");
    let rec = d.records("approved").pop().unwrap();
    assert_eq!(rec["scope"]["session_secs"], 2, "capped by policy: {rec}");

    // Same request again: no human needed.
    let r = d.run(req(&dir, "API_KEY")).await;
    assert!(approved(&r), "{r:?}");
    assert_eq!(d.records("approved").pop().unwrap()["via"], "grant");

    // A different command is not covered.
    let other = run_request(&[harmless_program(), "y"], &["API_KEY"], &dir);
    assert_eq!(denial(&d.run_and_deny(other).await), "denied by the human");
    // Nor a different secret.
    assert_eq!(
        denial(&d.run_and_deny(req(&dir, "OTHER_KEY")).await),
        "denied by the human"
    );

    // After the TTL the human is asked again.
    tokio::time::sleep(Duration::from_millis(2300)).await;
    assert_eq!(
        denial(&d.run_and_deny(req(&dir, "API_KEY")).await),
        "denied by the human"
    );
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn grant_ttl_zero_means_approve_every_time() {
    let (d, dir) = ready("m4ttl0", "[secret.API_KEY]\ngrant_ttl_secs = 0\n").await;
    let pending = {
        let (r, list) = tokio::join!(d.run(req(&dir, "API_KEY")), async {
            d.wait_pending(1).await;
            let list = d.pending().await;
            let id = list[0].id.clone();
            d.client()
                .approver(
                    ApproverOp::Approve {
                        request_id: id,
                        scope: GrantScope::Session { ttl_secs: 600 },
                    },
                    pass(),
                )
                .await
                .unwrap();
            list
        });
        assert!(approved(&r), "{r:?}");
        list
    };
    assert_eq!(pending[0].max_grant_secs, 0);
    assert_eq!(d.records("approved").pop().unwrap()["scope"], "once");
    assert_eq!(
        denial(&d.run_and_deny(req(&dir, "API_KEY")).await),
        "denied by the human"
    );
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn lock_wipes_values_and_revokes_grants() {
    let (d, dir) = ready("m4lock", "").await;
    let r = d
        .run_and_approve(req(&dir, "API_KEY"), GrantScope::Session { ttl_secs: 600 })
        .await;
    assert!(approved(&r));
    assert!(
        d.daemon().is_unlocked(),
        "approval leaves the vault unlocked"
    );

    let mut msg = Vec::new();
    credstore::commands::lock(&d.client(), &Scripted::new(&[PASS]), &mut msg)
        .await
        .unwrap();
    assert!(!d.daemon().is_unlocked());
    let lock = d.records("lock").pop().unwrap();
    assert_eq!(lock["wiped_secrets"], 2, "{lock}");

    assert_eq!(
        denial(&d.run_and_deny(req(&dir, "API_KEY")).await),
        "denied by the human",
        "the grant did not survive the lock"
    );
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn approvals_never_cross_apply() {
    let (d, dir) = ready("m4cross", "").await;
    let (a, b, ()) = tokio::join!(
        d.run(req(&dir, "API_KEY")),
        d.run(req(&dir, "OTHER_KEY")),
        async {
            d.wait_pending(2).await;
            let list = d.pending().await;
            let id_of = |name: &str| {
                list.iter()
                    .find(|p| p.secrets[0].name == name)
                    .unwrap()
                    .id
                    .clone()
            };
            let c = d.client();
            let r = c
                .approver(
                    ApproverOp::Approve {
                        request_id: id_of("OTHER_KEY"),
                        scope: GrantScope::Once,
                    },
                    pass(),
                )
                .await
                .unwrap();
            assert!(matches!(r, Response::Ok));
            d.wait_pending(1).await;
            assert_eq!(d.pending().await[0].secrets[0].name, "API_KEY");
            let r = c
                .approver(
                    ApproverOp::Deny {
                        request_id: id_of("API_KEY"),
                    },
                    pass(),
                )
                .await
                .unwrap();
            assert!(matches!(r, Response::Ok));
            // Deciding the same id twice fails.
            let r = c
                .approver(
                    ApproverOp::Deny {
                        request_id: id_of("API_KEY"),
                    },
                    pass(),
                )
                .await
                .unwrap();
            assert!(matches!(r, Response::Error { .. }), "{r:?}");
        }
    );
    assert_eq!(denial(&a), "denied by the human");
    assert!(approved(&b), "{b:?}");

    let r = d
        .client()
        .approver(
            ApproverOp::Approve {
                request_id: RequestId("req_unknown".into()),
                scope: GrantScope::Once,
            },
            pass(),
        )
        .await
        .unwrap();
    match r {
        Response::Error { code, message } => {
            assert_eq!(code, ErrorCode::BadRequest);
            assert!(message.contains("no pending request"), "{message}");
        }
        other => panic!("{other:?}"),
    }
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn idle_relock_follows_the_policy() {
    let (d, dir) = ready("m4idle", "[defaults]\nsession_idle_secs = 1\n").await;
    let r = d
        .run_and_approve(req(&dir, "API_KEY"), GrantScope::Once)
        .await;
    assert!(approved(&r));
    assert!(d.daemon().is_unlocked());
    tokio::time::sleep(Duration::from_millis(2000)).await;
    assert!(!d.daemon().is_unlocked());
    assert_eq!(d.records("lock").pop().unwrap()["reason"], "idle");

    // 0 = relock right after each run.
    d.write_policy("[defaults]\nsession_idle_secs = 0\n");
    assert!(matches!(d.reload().await, Response::Ok));
    let r = d
        .run_and_approve(req(&dir, "API_KEY"), GrantScope::Once)
        .await;
    assert!(approved(&r));
    assert!(!d.daemon().is_unlocked());
    assert_eq!(d.records("lock").pop().unwrap()["reason"], "after-run");
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_endpoint_cannot_subscribe_or_approve() {
    // Long enough that the scrypt-backed approver calls below fit under a loaded test run.
    let (d, dir) = ready("m4agent", "[defaults]\napproval_timeout_secs = 10\n").await;
    let (r, ()) = tokio::join!(d.run(req(&dir, "API_KEY")), async {
        d.wait_pending(1).await;
        let id = d.pending().await.pop().unwrap().id;
        for op in [
            ApproverOp::SubscribePending,
            ApproverOp::Approve {
                request_id: id,
                scope: GrantScope::Once,
            },
        ] {
            let mut s = d.connect(credstore_os::EndpointKind::Agent).await;
            credstore_proto::write_message(
                &mut s,
                &credstore_proto::ApproverRequest {
                    proof: credstore_proto::Proof { passphrase: pass() },
                    op,
                },
            )
            .await
            .unwrap();
            let resp: Response = credstore_proto::read_message(&mut s).await.unwrap();
            assert!(
                matches!(
                    resp,
                    Response::Error {
                        code: ErrorCode::BadRequest,
                        ..
                    }
                ),
                "{resp:?}"
            );
        }
        assert_eq!(d.daemon().pending_count(), 1);
    });
    assert_eq!(denial(&r), "approval timed out");
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_is_cancelled_when_its_agent_disconnects() {
    let (d, dir) = ready("m4gone", "[defaults]\napproval_timeout_secs = 60\n").await;
    let client = d.client();
    let request = req(&dir, "API_KEY");
    let task = tokio::spawn(async move {
        client
            .agent(&credstore_proto::AgentRequest::Run(request))
            .await
    });
    d.wait_pending(1).await;
    task.abort();
    let _ = task.await;
    // The human no longer sees it, and the audit log says why.
    d.wait_pending(0).await;
    let denied = d.records("denied");
    assert_eq!(denied.last().unwrap()["via"], "disconnect", "{denied:?}");
    assert!(d.records("run_started").is_empty());
    d.stop().await;
}
