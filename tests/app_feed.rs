//! The desktop app's feed and policy edits against a real dev-mode daemon: activity from
//! the audit log, refused requests with their host, allowed hosts and security settings
//! written to the policy file (comments kept), and no secret value anywhere.

use std::time::Duration;

use credstore::api::{Api, Auth, FeedView};
use credstore_os::Paths;
use credstore_proto::{
    ActivityKind, ActivityOutcome, AgentRequest, ApproverOp, ErrorCode, HttpRequest, NetworkPolicy,
    Response, SecretText,
};
use credstore_tests::*;
use tokio::sync::mpsc;

const POLICY: &str = "# my notes stay\n[defaults]\nsession_idle_secs = 600 # keep me\n";

/// Start the feed and return a receiver of its updates.
fn feed(api: &Api, auth: Auth) -> mpsc::UnboundedReceiver<FeedView> {
    let (tx, rx) = mpsc::unbounded_channel();
    let api = api.clone();
    tokio::spawn(async move {
        let _ = api
            .feed(auth, move |v| {
                let _ = tx.send(v);
            })
            .await;
    });
    rx
}

/// Wait for an update that satisfies `ok`.
async fn until(
    rx: &mut mpsc::UnboundedReceiver<FeedView>,
    ok: impl Fn(&FeedView) -> bool,
) -> FeedView {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let v = rx.recv().await.expect("the feed ended");
            assert!(!format!("{v:?}").contains(FAKE), "a value reached the feed");
            if ok(&v) {
                return v;
            }
        }
    })
    .await
    .expect("the feed never showed it")
}

fn http(url: &str) -> HttpRequest {
    HttpRequest {
        method: "GET".into(),
        url: url.into(),
        secret: "API_KEY".into(),
        header_template: "Authorization: Bearer {value}".into(),
        reason: "Check the account".into(),
        headers: vec![],
        body: None,
        timeout_secs: Some(5),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_feed_shows_activity_and_the_app_edits_the_policy() {
    let d = TestDaemon::start("app-feed").await;
    d.init_vault().await;
    d.set_secret("API_KEY", FAKE).await;
    d.write_policy(POLICY);
    assert!(matches!(d.reload().await, Response::Ok));
    let api = Api::new(d.client());

    // A wrong passphrase gets no feed.
    let wrong = api
        .feed(
            Auth::Passphrase(SecretText::new("wrong passphrase".into())),
            |_| {},
        )
        .await;
    assert!(wrong.is_err());

    let mut rx = feed(&api, Auth::Passphrase(pass()));
    let first = until(&mut rx, |v| v.policy.is_some()).await;
    let p = first.policy.as_ref().unwrap();
    assert!(p.editable, "dev mode can edit the policy");
    // The app's view carries the trusted key list (empty here) whenever the vault is
    // open, so the page can tell whether Windows Hello can confirm.
    assert_eq!(
        first.approval_keys.is_none(),
        first.locked,
        "{:?}",
        first.approval_keys
    );
    assert_eq!(p.session_idle_secs, 600);
    let rules = p.secrets.iter().find(|r| r.name == "API_KEY").unwrap();
    assert!(!rules.configured);
    assert_eq!(rules.network, NetworkPolicy::Inherit);
    assert!(first
        .activity
        .iter()
        .any(|a| a.kind == ActivityKind::Vault && a.summary == "Saved API_KEY"));

    // Refused by policy: no host list yet. The feed shows why and which host.
    let r = d
        .client()
        .agent(&AgentRequest::Http(http("https://api.example.com/v1/me")))
        .await
        .unwrap();
    assert!(matches!(r, Response::Denied { .. }), "{r:?}");
    let v = until(&mut rx, |v| {
        v.activity
            .iter()
            .any(|a| a.outcome == ActivityOutcome::Refused)
    })
    .await;
    let refused = v
        .activity
        .iter()
        .find(|a| a.outcome == ActivityOutcome::Refused)
        .unwrap();
    assert_eq!(refused.kind, ActivityKind::Http);
    assert_eq!(refused.host.as_deref(), Some("api.example.com"));
    assert_eq!(refused.secrets, vec!["API_KEY".to_owned()]);
    assert!(refused.detail.as_deref().unwrap().contains("allow_hosts"));

    // "Allow this host": needs the passphrase, then lands in the file with notes kept.
    assert!(api
        .set_secret_rules(
            "API_KEY",
            Some(vec!["api.example.com".into()]),
            None,
            SecretText::new("wrong passphrase".into())
        )
        .await
        .is_err());
    api.set_secret_rules(
        "API_KEY",
        Some(vec!["API.example.com".into()]),
        None,
        pass(),
    )
    .await
    .unwrap();
    let v = until(&mut rx, |v| {
        v.policy.as_ref().is_some_and(|p| {
            p.secrets
                .iter()
                .any(|r| r.name == "API_KEY" && r.configured)
        })
    })
    .await;
    let rules = v
        .policy
        .as_ref()
        .unwrap()
        .secrets
        .iter()
        .find(|r| r.name == "API_KEY")
        .unwrap()
        .clone();
    assert_eq!(rules.allow_hosts, vec!["api.example.com".to_owned()]);
    assert_eq!(rules.network, NetworkPolicy::AllowList);
    let file = std::fs::read_to_string(d.platform.policy_file()).unwrap();
    assert!(
        file.contains("# my notes stay") && file.contains("# keep me"),
        "{file}"
    );
    assert_eq!(d.records("policy_changed").len(), 1);

    // Security settings. An invalid value changes nothing.
    let bad = api.set_defaults(None, None, Some(0), pass()).await;
    assert!(bad.is_err());
    api.set_defaults(Some(300), Some(120), Some(90), pass())
        .await
        .unwrap();
    let v = until(&mut rx, |v| {
        v.policy
            .as_ref()
            .is_some_and(|p| p.session_idle_secs == 300)
    })
    .await;
    let p = v.policy.unwrap();
    assert_eq!((p.grant_ttl_secs, p.approval_timeout_secs), (120, 90));
    assert!(v
        .activity
        .iter()
        .any(|a| a.summary == "Changed the security settings"));

    // An approval key may watch but never change policy.
    let r = d
        .client()
        .approver(
            ApproverOp::SetDefaults {
                session_idle_secs: Some(1),
                grant_ttl_secs: None,
                approval_timeout_secs: None,
            },
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
    assert!(!ApproverOp::SetDefaults {
        session_idle_secs: None,
        grant_ttl_secs: None,
        approval_timeout_secs: None
    }
    .key_allowed());
    assert!(ApproverOp::SubscribeFeed.key_allowed());

    d.assert_not_on_disk(FAKE);
    d.stop().await;
}
