//! M2 acceptance: daemon, endpoints, peer identity, locked by default, audit chain.

use credstore::client::expect_ok;
use credstore::commands;
use credstore_os::EndpointKind;
use credstore_proto::{
    read_message, write_message, AgentRequest, ApproverOp, ApproverRequest, ErrorCode, Proof,
    Response, SecretText,
};
use credstore_tests::*;
use tokio::io::AsyncWriteExt;

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn vault_commands_go_through_the_daemon() {
    let d = TestDaemon::start("m2flow").await;
    let c = d.client();
    let (mut msg, mut out) = (Vec::new(), Vec::new());

    d.init_vault().await;
    commands::set(
        &c,
        "STRIPE_KEY",
        Some("Stripe test key".into()),
        &Scripted::new(&[PASS, FAKE]),
        &mut msg,
    )
    .await
    .unwrap();
    commands::list(&c, &mut out, &mut msg).await.unwrap();
    assert_eq!(text(&out), "STRIPE_KEY  Stripe test key\n");

    commands::rm(&c, "STRIPE_KEY", &Scripted::new(&[PASS]), &mut msg)
        .await
        .unwrap();
    out.clear();
    commands::list(&c, &mut out, &mut msg).await.unwrap();
    assert!(out.is_empty());

    // Re-init is refused.
    assert!(commands::init(&c, &Scripted::new(&[PASS, PASS]), &mut msg)
        .await
        .is_err());

    let shown = text(&msg);
    assert!(!shown.contains(FAKE) && !shown.contains(PASS), "{shown}");
    d.assert_not_on_disk(FAKE);
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_identity_is_logged() {
    let d = TestDaemon::start("m2peer").await;
    d.init_vault().await;
    d.set_secret("K_ONE", FAKE).await;
    let rec = d
        .records("vault_changed")
        .into_iter()
        .find(|r| r["action"] == "set")
        .expect("set recorded");
    let peer = &rec["peer"];
    assert_eq!(peer["pid"], std::process::id(), "{peer}");
    assert!(peer["uid"].is_u64() || peer["sid"].is_string(), "{peer}");
    #[cfg(windows)]
    assert!(peer["sid"].as_str().unwrap().starts_with("S-1-"));
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn daemon_starts_locked_and_lock_wipes() {
    let d = TestDaemon::start("m2lock").await;
    d.init_vault().await;
    d.set_secret("A_KEY", FAKE).await;
    d.set_secret("B_KEY", "another-fake-value").await;
    assert!(
        !d.daemon().is_unlocked(),
        "locked by default, even after set"
    );

    let c = d.client();
    expect_ok(c.approver(ApproverOp::Unlock, pass()).await.unwrap()).unwrap();
    assert!(d.daemon().is_unlocked());

    let mut msg = Vec::new();
    commands::lock(&c, &Scripted::new(&[PASS]), &mut msg)
        .await
        .unwrap();
    assert!(!d.daemon().is_unlocked());
    let lock = d.records("lock").pop().expect("lock recorded");
    assert_eq!(lock["reason"], "requested");
    assert_eq!(lock["wiped_secrets"], 2, "both values zeroized: {lock}");
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn idle_vault_relocks() {
    let d = TestDaemon::start("m2idle").await;
    d.init_vault().await;
    // Long enough that a loaded runner still sees it unlocked right after the unlock.
    d.daemon().set_idle_ttl(std::time::Duration::from_secs(2));
    expect_ok(
        d.client()
            .approver(ApproverOp::Unlock, pass())
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(d.daemon().is_unlocked());
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    assert!(!d.daemon().is_unlocked());
    assert_eq!(d.records("lock").pop().unwrap()["reason"], "idle");
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn approver_requests_without_valid_proof_are_refused() {
    let d = TestDaemon::start("m2proof").await;
    d.init_vault().await;

    // No proof at all: does not parse as an approver request.
    let mut s = d.connect(EndpointKind::Approver).await;
    s.write_all(&{
        let body = br#"{"v":1,"msg":{"op":{"type":"lock"}}}"#;
        let mut f = (body.len() as u32).to_be_bytes().to_vec();
        f.extend_from_slice(body);
        f
    })
    .await
    .unwrap();
    match read_message::<Response, _>(&mut s).await.unwrap() {
        Response::Error { code, .. } => assert_eq!(code, ErrorCode::Unauthorized),
        other => panic!("{other:?}"),
    }

    // Wrong passphrase.
    let r = d
        .client()
        .approver(
            ApproverOp::Unlock,
            SecretText::new("wrong passphrase".into()),
        )
        .await
        .unwrap();
    assert!(
        matches!(
            r,
            Response::Error {
                code: ErrorCode::Unauthorized,
                ..
            }
        ),
        "{r:?}"
    );
    assert!(!d.daemon().is_unlocked());
    assert_eq!(d.records("auth_failed").len(), 1);
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_passphrases_are_rate_limited() {
    let d = TestDaemon::start("m2rate").await;
    d.init_vault().await;
    let c = d.client();
    for _ in 0..credstored::MAX_FAILURES {
        let r = c
            .approver(
                ApproverOp::Status,
                SecretText::new("wrong passphrase".into()),
            )
            .await
            .unwrap();
        assert!(matches!(
            r,
            Response::Error {
                code: ErrorCode::Unauthorized,
                ..
            }
        ));
    }
    // Now even the right passphrase is refused until the lockout ends.
    let r = c.approver(ApproverOp::Status, pass()).await.unwrap();
    match r {
        Response::Error { code, message } => {
            assert_eq!(code, ErrorCode::RateLimited);
            assert!(message.contains("try again"), "{message}");
        }
        other => panic!("{other:?}"),
    }
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_endpoint_rejects_approver_requests() {
    let d = TestDaemon::start("m2agent").await;
    d.init_vault().await;
    let mut s = d.connect(EndpointKind::Agent).await;
    write_message(
        &mut s,
        &ApproverRequest {
            proof: Proof { passphrase: pass() },
            op: ApproverOp::Unlock,
        },
    )
    .await
    .unwrap();
    match read_message::<Response, _>(&mut s).await.unwrap() {
        Response::Error { code, .. } => assert_eq!(code, ErrorCode::BadRequest),
        other => panic!("{other:?}"),
    }
    assert!(!d.daemon().is_unlocked());
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn oversize_and_malformed_frames_are_rejected() {
    let d = TestDaemon::start("m2frame").await;
    for kind in [EndpointKind::Agent, EndpointKind::Approver] {
        let mut s = d.connect(kind).await;
        s.write_all(&OVERSIZE.to_be_bytes()).await.unwrap();
        match read_message::<Response, _>(&mut s).await.unwrap() {
            Response::Error { code, message } => {
                assert_eq!(code, ErrorCode::BadRequest);
                assert!(message.contains("exceeds"), "{message}");
            }
            other => panic!("{other:?}"),
        }

        let mut s = d.connect(kind).await;
        s.write_all(&[0, 0, 0, 3, b'{', b'{', b'{']).await.unwrap();
        assert!(matches!(
            read_message::<Response, _>(&mut s).await.unwrap(),
            Response::Error { .. }
        ));
    }
    // The daemon still serves after bad clients.
    let r = d.client().agent(&AgentRequest::ListSecrets).await.unwrap();
    assert!(matches!(r, Response::Secrets { .. }));
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn audit_chain_verifies_and_detects_tampering() {
    let d = TestDaemon::start("m2audit").await;
    d.init_vault().await;
    d.set_secret("K_A", FAKE).await;
    d.set_secret("K_B", FAKE).await;
    let path = d.audit_log();
    let mut out = Vec::new();
    commands::audit_verify(&path, &mut out).unwrap();
    assert!(text(&out).starts_with("ok:"), "{}", text(&out));
    d.assert_not_on_disk(FAKE);
    d.stop().await;

    // Tamper with one line: verify reports it.
    let content = std::fs::read_to_string(&path).unwrap();
    let tampered = content.replacen("\"K_A\"", "\"K_Z\"", 1);
    assert_ne!(content, tampered);
    std::fs::write(&path, tampered).unwrap();
    out.clear();
    assert!(commands::audit_verify(&path, &mut out).is_err());
    assert!(text(&out).contains("BROKEN at line"), "{}", text(&out));
}

#[tokio::test(flavor = "multi_thread")]
async fn second_daemon_on_the_same_home_fails() {
    let d = TestDaemon::start("m2dup").await;
    let paths = credstore_os::PlatformPaths::dev_with_home(&d.home);
    let second = credstored::start(credstored::DaemonConfig { paths }).await;
    assert!(second.is_err());
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_passphrase_on_set_never_asks_for_the_value() {
    let d = TestDaemon::start("m2setpw").await;
    d.init_vault().await;
    let p = Scripted::new(&["wrong passphrase", FAKE]);
    let mut msg = Vec::new();
    let err = commands::set(&d.client(), "K", None, &p, &mut msg)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("wrong passphrase"), "{err}");
    assert_eq!(p.remaining(), 1);
    d.stop().await;
}
