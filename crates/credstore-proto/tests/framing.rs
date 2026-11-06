use credstore_proto::*;
use tokio::io::AsyncWriteExt;

const FAKE: &str = "FAKE-SECRET-VALUE-12345";

fn proof() -> Proof {
    Proof {
        passphrase: SecretText::new("fake passphrase".into()),
    }
}

fn run_request() -> RunRequest {
    RunRequest {
        argv: Some(vec!["pytest".into(), "-q".into()]),
        shell: None,
        secrets: vec!["STRIPE_KEY".into()],
        reason: "Run billing tests against the Stripe test account".into(),
        cwd: "/abs/path".into(),
        timeout_secs: Some(60),
        injection: Some(Injection::Env),
    }
}

fn payload_of(frame: &[u8]) -> &[u8] {
    let len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
    assert_eq!(len, frame.len() - 4, "length prefix matches payload");
    &frame[4..]
}

fn round_trip<T>(msg: T)
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let frame = encode(&msg).unwrap();
    let back: T = decode(payload_of(&frame)).unwrap();
    assert_eq!(back, msg);
}

#[test]
fn agent_requests_round_trip() {
    round_trip(AgentRequest::ListSecrets);
    round_trip(AgentRequest::Run(run_request()));
    round_trip(AgentRequest::Run(RunRequest {
        argv: None,
        shell: Some("echo hi".into()),
        timeout_secs: None,
        injection: None,
        ..run_request()
    }));
}

#[test]
fn approver_requests_round_trip() {
    let ops = vec![
        ApproverOp::SubscribePending,
        ApproverOp::Approve {
            request_id: RequestId("req_01".into()),
            scope: GrantScope::Once,
        },
        ApproverOp::Approve {
            request_id: RequestId("req_02".into()),
            scope: GrantScope::Session { ttl_secs: 600 },
        },
        ApproverOp::Deny {
            request_id: RequestId("req_03".into()),
        },
        ApproverOp::Unlock,
        ApproverOp::Lock,
        ApproverOp::Status,
        ApproverOp::Reload,
        ApproverOp::AdminSet {
            name: "STRIPE_KEY".into(),
            description: Some("Stripe test key".into()),
            value: SecretText::new(FAKE.into()),
        },
        ApproverOp::AdminRm {
            name: "STRIPE_KEY".into(),
        },
        ApproverOp::AdminRun(run_request()),
    ];
    for op in ops {
        round_trip(ApproverRequest { proof: proof(), op });
    }
}

#[test]
fn responses_round_trip() {
    let responses = vec![
        Response::Secrets {
            secrets: vec![SecretInfo {
                name: "STRIPE_KEY".into(),
                description: "Stripe test key".into(),
            }],
        },
        Response::RunResult(RunResult {
            exit_code: Some(0),
            stdout: "ok [REDACTED:STRIPE_KEY]".into(),
            stderr: String::new(),
            truncated: false,
            redactions: 1,
        }),
        Response::Denied {
            reason: "approval timed out".into(),
        },
        Response::Pending {
            requests: vec![PendingRequest {
                id: RequestId("req_01".into()),
                reason: "test webhook".into(),
                argv: Some(vec!["curl".into()]),
                shell: None,
                program: Some("C:/Windows/System32/curl.exe".into()),
                cwd: "/abs".into(),
                secrets: vec![],
                injection: Injection::File,
                sandbox: SandboxMode::JobObject,
                network: NetworkPolicy::AllowList,
                allow_hosts: vec!["api.example.com".into()],
                max_grant_secs: 600,
                peer: PeerInfo {
                    uid: None,
                    sid: Some("S-1-5-21-1".into()),
                    pid: Some(4242),
                    exe: Some("C:/node.exe".into()),
                },
            }],
        },
        Response::Status(StatusInfo {
            locked: true,
            dev_mode: true,
            pending: 0,
            policy_error: Some("bad policy".into()),
        }),
        Response::Ok,
        Response::Error {
            code: ErrorCode::Unauthorized,
            message: "bad proof".into(),
        },
    ];
    for r in responses {
        round_trip(r);
    }
}

#[test]
fn wire_format_is_versioned_snake_case() {
    let frame = encode(&AgentRequest::ListSecrets).unwrap();
    let json = std::str::from_utf8(payload_of(&frame)).unwrap();
    assert_eq!(json, r#"{"v":1,"msg":{"type":"list_secrets"}}"#);

    let frame = encode(&SandboxMode::JobObject).unwrap();
    assert_eq!(payload_of(&frame), br#"{"v":1,"msg":"job-object"}"#);
}

#[test]
fn rejects_wrong_version() {
    let err = decode::<AgentRequest>(br#"{"v":2,"msg":{"type":"list_secrets"}}"#).unwrap_err();
    assert!(matches!(err, FrameError::UnsupportedVersion(2)), "{err:?}");
}

#[test]
fn rejects_malformed_payloads() {
    let cases: &[&[u8]] = &[
        b"",
        b"not json",
        b"{",
        br#"{"msg":{"type":"list_secrets"}}"#,
        br#"{"v":1}"#,
        br#"{"v":"1","msg":{"type":"list_secrets"}}"#,
        br#"{"v":1,"msg":{"type":"get_secret","name":"X"}}"#,
        br#"{"v":1,"msg":{"type":"list_secrets"},"extra":true}"#,
        br#"{"v":1,"msg":{"type":"run","secrets":[],"reason":"r","cwd":"/","evil":1}}"#,
        b"\xff\xfe\x00",
    ];
    for c in cases {
        let err = decode::<AgentRequest>(c).unwrap_err();
        assert!(
            matches!(err, FrameError::Malformed { .. }),
            "{:?} -> {err:?}",
            String::from_utf8_lossy(c)
        );
    }
}

#[test]
fn agent_endpoint_cannot_parse_approver_requests() {
    let frame = encode(&ApproverRequest {
        proof: proof(),
        op: ApproverOp::Lock,
    })
    .unwrap();
    assert!(decode::<AgentRequest>(payload_of(&frame)).is_err());

    // And an approve sent without a proof does not parse on the approver side.
    let no_proof =
        br#"{"v":1,"msg":{"op":{"type":"approve","request_id":"r","scope":{"kind":"once"}}}}"#;
    assert!(decode::<ApproverRequest>(no_proof).is_err());
}

#[test]
fn parse_errors_never_quote_input() {
    // serde_json's own message would quote this string; ours must not.
    let payload = format!(r#"{{"v":1,"msg":{{"type":"run","secrets":"{FAKE}"}}}}"#);
    let err = decode::<AgentRequest>(payload.as_bytes()).unwrap_err();
    let shown = format!("{err} {err:?}");
    assert!(!shown.contains(FAKE), "{shown}");
}

#[test]
fn debug_of_requests_hides_secrets() {
    let req = ApproverRequest {
        proof: proof(),
        op: ApproverOp::AdminSet {
            name: "K".into(),
            description: None,
            value: SecretText::new(FAKE.into()),
        },
    };
    let shown = format!("{req:?}");
    assert!(
        !shown.contains(FAKE) && !shown.contains("fake passphrase"),
        "{shown}"
    );
}

#[test]
fn encode_rejects_oversize() {
    let big = Response::Denied {
        reason: "x".repeat(MAX_FRAME_LEN as usize),
    };
    assert!(matches!(encode(&big), Err(FrameError::TooLarge { .. })));
}

#[tokio::test]
async fn stream_round_trip() {
    let (mut a, mut b) = tokio::io::duplex(64);
    let writer = tokio::spawn(async move {
        write_message(&mut a, &AgentRequest::Run(run_request()))
            .await
            .unwrap();
        write_message(&mut a, &AgentRequest::ListSecrets)
            .await
            .unwrap();
    });
    let first: AgentRequest = read_message(&mut b).await.unwrap();
    let second: AgentRequest = read_message(&mut b).await.unwrap();
    writer.await.unwrap();
    assert_eq!(first, AgentRequest::Run(run_request()));
    assert_eq!(second, AgentRequest::ListSecrets);
    assert!(matches!(
        read_message::<AgentRequest, _>(&mut b).await,
        Err(FrameError::Closed)
    ));
}

#[tokio::test]
async fn read_rejects_oversize_length_without_reading_payload() {
    let (mut a, mut b) = tokio::io::duplex(16);
    // Claim 4 GiB - 1; send no payload. Must fail on the header alone.
    a.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
    let err = read_frame(&mut b).await.unwrap_err();
    assert!(matches!(err, FrameError::TooLarge { len } if len == u64::from(u32::MAX)));

    let (mut a, mut b) = tokio::io::duplex(16);
    a.write_all(&(MAX_FRAME_LEN + 1).to_be_bytes())
        .await
        .unwrap();
    assert!(matches!(
        read_frame(&mut b).await,
        Err(FrameError::TooLarge { .. })
    ));
}

#[tokio::test]
async fn read_accepts_exactly_max_len() {
    let (mut a, mut b) = tokio::io::duplex(1 << 16);
    let writer = tokio::spawn(async move {
        a.write_all(&MAX_FRAME_LEN.to_be_bytes()).await.unwrap();
        a.write_all(&vec![b' '; MAX_FRAME_LEN as usize])
            .await
            .unwrap();
    });
    let payload = read_frame(&mut b).await.unwrap();
    writer.await.unwrap();
    assert_eq!(payload.len(), MAX_FRAME_LEN as usize);
}

#[tokio::test]
async fn read_detects_truncated_frames() {
    let (mut a, mut b) = tokio::io::duplex(64);
    a.write_all(&[0, 0]).await.unwrap();
    drop(a);
    assert!(matches!(
        read_frame(&mut b).await,
        Err(FrameError::Truncated)
    ));

    let (mut a, mut b) = tokio::io::duplex(64);
    a.write_all(&10u32.to_be_bytes()).await.unwrap();
    a.write_all(b"{\"v\"").await.unwrap();
    drop(a);
    assert!(matches!(
        read_frame(&mut b).await,
        Err(FrameError::Truncated)
    ));
}
