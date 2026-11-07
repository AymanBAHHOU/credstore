//! M13: approval keys. A key enrolled with the passphrase signs approvals afterwards.
//!
//! Windows Hello itself cannot run on CI (no user to verify), so these tests use an
//! in-process RSA key with Hello's signature format; the daemon cannot tell them apart.
//! Windows only: other platforms do not accept approval keys yet.

#![cfg(windows)]

use credstore::approval::{self, KeySigner};
use credstore_os::approval_key::SoftwareKey;
use credstore_proto::{ApproverOp, ErrorCode, GrantScope, Proof, RequestId, Response};
use credstore_tests::*;

const POLICY: &str = "[defaults]
max_runtime_secs = 60
";

async fn ready(tag: &str) -> (TestDaemon, SoftwareKey, String) {
    let d = TestDaemon::start(tag).await;
    d.init_vault().await;
    d.set_secret("API_KEY", FAKE).await;
    d.write_policy(POLICY);
    assert!(matches!(d.reload().await, Response::Ok));
    let key = SoftwareKey::generate().unwrap();
    let id = approval::enrol(
        &d.client(),
        &KeySigner::public_key(&key).unwrap(),
        "test key",
        pass(),
    )
    .await
    .unwrap();
    (d, key, id)
}

async fn unlock(d: &TestDaemon) {
    let r = d
        .client()
        .approver(ApproverOp::Unlock, pass())
        .await
        .unwrap();
    assert!(matches!(r, Response::Ok), "{r:?}");
}

fn unauthorized(r: &Response) -> &str {
    match r {
        Response::Error {
            code: ErrorCode::Unauthorized,
            message,
        } => message,
        other => panic!("expected unauthorized, got {other:?}"),
    }
}

async fn pending_id(d: &TestDaemon) -> RequestId {
    d.wait_pending(1).await;
    d.pending().await.pop().unwrap().id
}

fn approve(request_id: RequestId) -> ApproverOp {
    ApproverOp::Approve {
        request_id,
        scope: GrantScope::Once,
    }
}

#[tokio::test]
async fn an_enrolled_key_approves_while_the_vault_is_unlocked() {
    let (d, key, id) = ready("m13-approve").await;
    let status = d
        .client()
        .approver(ApproverOp::Status, pass())
        .await
        .unwrap();
    let Response::Status(s) = status else {
        panic!("{status:?}")
    };
    assert_eq!(s.approval_keys.len(), 1);
    assert_eq!(s.approval_keys[0].id, id);
    assert_eq!(s.approval_keys[0].label, "test key");

    unlock(&d).await;
    let req = run_request(&[harmless_program()], &["API_KEY"], &d.work());
    let client = d.client();
    let (r, decided) = tokio::join!(d.run(req), async {
        let rid = pending_id(&d).await;
        approval::send(&client, &key, approve(rid)).await.unwrap()
    });
    assert!(matches!(decided, Response::Ok), "{decided:?}");
    assert!(approved(&r), "{r:?}");
    // The key also watches and denies.
    let req = run_request(&[harmless_program()], &["API_KEY"], &d.work());
    let (r, decided) = tokio::join!(d.run(req), async {
        let rid = pending_id(&d).await;
        approval::send(&client, &key, ApproverOp::Deny { request_id: rid })
            .await
            .unwrap()
    });
    assert!(matches!(decided, Response::Ok), "{decided:?}");
    denial(&r);
    assert!(!d
        .audit_records()
        .iter()
        .any(|r| r.to_string().contains(FAKE)));
    d.stop().await;
}

#[tokio::test]
async fn a_locked_vault_needs_the_passphrase() {
    let (d, key, _) = ready("m13-locked").await;
    let r = approval::send(&d.client(), &key, ApproverOp::Status)
        .await
        .unwrap();
    assert!(unauthorized(&r).contains("locked"), "{r:?}");
    d.stop().await;
}

#[tokio::test]
async fn keys_cannot_unlock_change_secrets_keys_or_policy() {
    let (d, key, id) = ready("m13-scope").await;
    unlock(&d).await;
    for op in [
        ApproverOp::Unlock,
        ApproverOp::AdminRm {
            name: "API_KEY".into(),
        },
        ApproverOp::RemoveApprovalKey { id: id.clone() },
        ApproverOp::AddApprovalKey {
            label: "x".into(),
            public_key: "00".into(),
        },
        ApproverOp::SetSecretRules {
            name: "API_KEY".into(),
            allow_hosts: Some(vec!["evil.example".into()]),
            allow_commands: None,
        },
        ApproverOp::SetDefaults {
            session_idle_secs: Some(3600),
            grant_ttl_secs: None,
            approval_timeout_secs: None,
        },
    ] {
        let r = approval::send(&d.client(), &key, op).await.unwrap();
        assert!(unauthorized(&r).contains("passphrase"), "{r:?}");
    }
    d.stop().await;
}

#[tokio::test]
async fn a_key_opens_the_apps_feed() {
    use credstore_os::EndpointKind;
    use credstore_proto::{read_message, write_message, ApproverRequest};
    let (d, key, _) = ready("m13-feed").await;
    unlock(&d).await;
    let op = ApproverOp::SubscribeFeed;
    let proof = approval::key_proof(&key, &op).unwrap();
    let mut stream = d.connect(EndpointKind::Approver).await;
    write_message(&mut stream, &ApproverRequest { proof, op })
        .await
        .unwrap();
    let r: Response = read_message(&mut stream).await.unwrap();
    let Response::Feed(f) = r else {
        panic!("{r:?}")
    };
    assert!(!f.locked);
    assert!(f.policy.is_some());
    d.stop().await;
}

#[tokio::test]
async fn forged_replayed_and_stale_proofs_are_refused() {
    let (d, key, id) = ready("m13-forged").await;
    unlock(&d).await;
    let client = d.client();

    // Replayed: the same signed proof twice.
    let proof = approval::key_proof(&key, &ApproverOp::Status).unwrap();
    let first = client
        .approver_with(ApproverOp::Status, proof.clone())
        .await
        .unwrap();
    assert!(matches!(first, Response::Status(_)), "{first:?}");
    let again = client
        .approver_with(ApproverOp::Status, proof)
        .await
        .unwrap();
    assert!(unauthorized(&again).contains("replayed"), "{again:?}");

    // Signed for another operation.
    let proof = approval::key_proof(&key, &ApproverOp::Status).unwrap();
    let r = client.approver_with(ApproverOp::Lock, proof).await.unwrap();
    assert!(unauthorized(&r).contains("bad signature"), "{r:?}");

    // A key nobody enrolled.
    let stranger = SoftwareKey::generate().unwrap();
    let r = approval::send(&client, &stranger, ApproverOp::Status)
        .await
        .unwrap();
    assert!(unauthorized(&r).contains("unknown key"), "{r:?}");

    // Signed long ago (a fresh signature over an old time).
    let Proof::Key(mut old) = approval::key_proof(&key, &ApproverOp::Status).unwrap() else {
        unreachable!()
    };
    old.time -= 600;
    let msg = credstore_proto::signed_message(&id, old.time, &old.nonce, &ApproverOp::Status);
    old.signature = credstore_proto::hex(&KeySigner::sign(&key, &msg).unwrap());
    let r = client
        .approver_with(ApproverOp::Status, Proof::Key(old))
        .await
        .unwrap();
    assert!(unauthorized(&r).contains("too long ago"), "{r:?}");

    assert!(d.records("auth_failed").len() >= 4);
    assert!(d.daemon().is_unlocked(), "failures do not lock the vault");
    d.stop().await;
}

#[tokio::test]
async fn removed_keys_stop_working_and_bad_keys_are_not_enrolled() {
    let (d, key, id) = ready("m13-remove").await;
    unlock(&d).await;
    approval::remove(&d.client(), &id, pass()).await.unwrap();
    let r = approval::send(&d.client(), &key, ApproverOp::Status)
        .await
        .unwrap();
    assert!(unauthorized(&r).contains("unknown key"), "{r:?}");

    for public_key in ["zz", "", "3003020100"] {
        let r = d
            .client()
            .approver(
                ApproverOp::AddApprovalKey {
                    label: "bad".into(),
                    public_key: public_key.into(),
                },
                pass(),
            )
            .await
            .unwrap();
        assert!(
            matches!(
                &r,
                Response::Error {
                    code: ErrorCode::BadRequest,
                    ..
                }
            ),
            "{public_key}: {r:?}"
        );
    }
    // A key survives a daemon restart (it is in the vault).
    let key2 = SoftwareKey::generate().unwrap();
    let id2 = approval::enrol(
        &d.client(),
        &KeySigner::public_key(&key2).unwrap(),
        "k2",
        pass(),
    )
    .await
    .unwrap();
    let home = d.stop_keep().await;
    let d = TestDaemon::start_at(home).await;
    unlock(&d).await;
    let r = approval::send(&d.client(), &key2, ApproverOp::Status)
        .await
        .unwrap();
    let Response::Status(s) = r else {
        panic!("{r:?}")
    };
    assert_eq!(s.approval_keys.len(), 1);
    assert_eq!(s.approval_keys[0].id, id2);
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn watch_approves_with_the_key_and_no_passphrase() {
    let (d, key, _) = ready("m13-watch").await;
    unlock(&d).await;
    let client = d.client();
    // Only the decision: no passphrase is asked for.
    let script = Scripted::new(&["o"]);
    let mut out = Vec::new();
    let r = tokio::select! {
        w = credstore::watch::watch_with(&client, &script, &mut out, Some(&key)) => {
            panic!("watch ended: {w:?}")
        }
        r = d.run(run_request(&[harmless_program()], &["API_KEY"], &d.work())) => r,
    };
    assert!(approved(&r), "{r:?}");
    let shown = String::from_utf8_lossy(&out).into_owned();
    assert!(shown.contains("Confirm with test key"), "{shown}");
    assert!(shown.contains("Approved once."), "{shown}");
    assert_eq!(script.remaining(), 0);
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn watch_falls_back_to_the_passphrase_while_locked() {
    let (d, key, _) = ready("m13-watch-locked").await;
    let client = d.client();
    // Locked: the key cannot subscribe or approve, so the passphrase is asked for both.
    let script = Scripted::new(&[PASS, "o", PASS]);
    let mut out = Vec::new();
    let r = tokio::select! {
        w = credstore::watch::watch_with(&client, &script, &mut out, Some(&key)) => {
            panic!("watch ended: {w:?}")
        }
        r = d.run(run_request(&[harmless_program()], &["API_KEY"], &d.work())) => r,
    };
    assert!(approved(&r), "{r:?}");
    let shown = String::from_utf8_lossy(&out).into_owned();
    assert!(shown.contains("locked"), "{shown}");
    assert!(shown.contains("Approved once."), "{shown}");
    assert_eq!(script.remaining(), 0);
    d.stop().await;
}

/// The real thing, for a human at a Windows machine with Hello set up:
/// `cargo test -p credstore-tests --test m13_approval_keys -- --ignored --nocapture`.
/// Windows asks to verify twice (create the key, then sign). Deletes the key after.
#[tokio::test]
#[ignore = "needs a person and Windows Hello"]
async fn live_windows_hello_approves() {
    use credstore_os::approval_key::hello;
    if !hello::available() {
        eprintln!("Windows Hello is not set up for this user; nothing to test.");
        return;
    }
    let d = TestDaemon::start("m13-live").await;
    d.init_vault().await;
    let spki = hello::create().unwrap();
    approval::enrol(&d.client(), &spki, "live", pass())
        .await
        .unwrap();
    unlock(&d).await;
    let r = approval::send(&d.client(), &approval::Hello, ApproverOp::Status)
        .await
        .unwrap();
    hello::delete().unwrap();
    assert!(matches!(r, Response::Status(_)), "{r:?}");
    eprintln!("Windows Hello signed an approval and the daemon verified it.");
    d.stop().await;
}
