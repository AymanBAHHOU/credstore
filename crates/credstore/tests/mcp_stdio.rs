//! M6: drive the real `credstore mcp` binary over stdio as an agent would, against an
//! in-process dev daemon, and check that no tool result ever contains a secret value.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use credstore::client::Client;
use credstore::commands::{self, Prompt};
use credstore_os::{Paths, Platform, PlatformPaths, CREDSTORE_HOME_ENV};
use credstore_proto::{ApproverOp, GrantScope, Response, SecretText};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout};

const PASS: &str = "correct horse battery";
const FAKE: &str = "FAKE-SECRET-VALUE-12345";

struct Script(RefCell<VecDeque<String>>);

impl Prompt for Script {
    fn secret(&self, _: &str) -> anyhow::Result<SecretText> {
        Ok(SecretText::new(self.0.borrow_mut().pop_front().unwrap()))
    }
}

fn script(a: &[&str]) -> Script {
    Script(RefCell::new(a.iter().map(|s| s.to_string()).collect()))
}

fn pass() -> SecretText {
    SecretText::new(PASS.into())
}

/// An MCP client speaking newline-delimited JSON-RPC to the shim.
struct Mcp {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    /// Everything the shim wrote, to check for leaks at the end.
    transcript: String,
}

impl Mcp {
    fn start(home: &std::path::Path) -> Self {
        let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_credstore"))
            .args(["--dev", "mcp"])
            .env(CREDSTORE_HOME_ENV, home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .expect("start credstore mcp");
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            stdin,
            stdout,
            transcript: String::new(),
        }
    }

    async fn send(&mut self, msg: Value) {
        let mut line = msg.to_string();
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).await.unwrap();
        self.stdin.flush().await.unwrap();
    }

    /// Send a request and wait for the response with the same id.
    async fn call(&mut self, id: u64, method: &str, params: Value) -> Value {
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await;
        loop {
            let mut line = String::new();
            let n =
                tokio::time::timeout(Duration::from_secs(120), self.stdout.read_line(&mut line))
                    .await
                    .expect("shim answered in time")
                    .unwrap();
            assert!(n > 0, "shim closed stdout");
            self.transcript.push_str(&line);
            let v: Value = serde_json::from_str(&line).expect("stdout carries only JSON-RPC");
            if v["id"] == json!(id) {
                return v;
            }
        }
    }

    async fn tool(&mut self, id: u64, name: &str, arguments: Value) -> Value {
        self.call(
            id,
            "tools/call",
            json!({"name": name, "arguments": arguments}),
        )
        .await
    }
}

/// The text content of a tool result, and whether it is an error.
fn tool_text(resp: &Value) -> (String, bool) {
    let r = &resp["result"];
    let text = r["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    (text, r["isError"].as_bool().unwrap_or(false))
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_tools_work_end_to_end_and_never_return_values() {
    let root = std::env::temp_dir().join(format!(
        "cs-mcp-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            % 1_000_000_000
    ));
    let home = root.join("home");
    let work = root.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let work: PathBuf = credstore_os::exec::canonical_dir(&work).unwrap();

    let paths = PlatformPaths::dev_with_home(&home);
    let daemon = credstored::start(credstored::DaemonConfig {
        paths: paths.clone(),
    })
    .await
    .unwrap();
    let platform = Platform::with_paths(paths);
    let client = Client::new(platform.clone());
    let mut msg = Vec::new();
    commands::init(&client, &script(&[PASS, PASS]), &mut msg)
        .await
        .unwrap();
    commands::set(
        &client,
        "API_KEY",
        Some("Test account key".into()),
        &script(&[PASS, FAKE]),
        &mut msg,
    )
    .await
    .unwrap();
    std::fs::write(
        platform.policy_file(),
        "[defaults]\nallow_shell = true\napproval_timeout_secs = 60\n",
    )
    .unwrap();
    commands::reload(&client, &script(&[PASS]), &mut msg)
        .await
        .unwrap();

    let mut mcp = Mcp::start(&home);
    let init = mcp
        .call(
            1,
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "credstore-test", "version": "0"}
            }),
        )
        .await;
    assert_eq!(init["result"]["serverInfo"]["name"], "credstore", "{init}");
    mcp.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await;

    // Exactly the three tools, with strict input schemas.
    let tools = mcp.call(2, "tools/list", json!({})).await;
    let list = tools["result"]["tools"].as_array().expect("tools").clone();
    let mut names: Vec<&str> = list.iter().map(|t| t["name"].as_str().unwrap()).collect();
    names.sort();
    assert_eq!(
        names,
        ["http_request", "list_secrets", "run_with_secrets"],
        "{tools}"
    );
    let http_tool = list.iter().find(|t| t["name"] == "http_request").unwrap();
    let http_schema = &http_tool["inputSchema"];
    assert_eq!(http_schema["additionalProperties"], false, "{http_schema}");
    for field in ["method", "url", "secret", "header_template", "reason"] {
        assert!(
            http_schema["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == field),
            "{field} should be required: {http_schema}"
        );
    }
    let run_tool = list
        .iter()
        .find(|t| t["name"] == "run_with_secrets")
        .unwrap();
    let schema = &run_tool["inputSchema"];
    assert_eq!(schema["additionalProperties"], false, "{schema}");
    assert_eq!(schema["properties"]["reason"]["minLength"], 10, "{schema}");
    assert_eq!(schema["properties"]["reason"]["maxLength"], 300, "{schema}");
    let required: Vec<&str> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(required.contains(&"reason") && required.contains(&"secrets"));
    assert!(run_tool["description"]
        .as_str()
        .unwrap()
        .contains("explain what the command does with each secret"));

    // list_secrets: names and descriptions only.
    let r = mcp.tool(3, "list_secrets", json!({})).await;
    let (text, is_error) = tool_text(&r);
    assert!(!is_error, "{r}");
    assert!(
        text.contains("API_KEY") && text.contains("Test account key"),
        "{text}"
    );

    // http_request: the starter policy lists no hosts for the secret, so it is denied
    // before anyone is asked.
    let r = mcp
        .tool(
            40,
            "http_request",
            json!({
                "method": "GET",
                "url": "https://api.example.com/v1/me",
                "secret": "API_KEY",
                "header_template": "Authorization: Bearer {value}",
                "reason": "Check which account the key belongs to",
            }),
        )
        .await;
    let (text, is_error) = tool_text(&r);
    assert!(is_error, "{r}");
    assert!(
        text.contains("denied") && text.contains("allow-list"),
        "{text}"
    );

    // run_with_secrets: blocks until the human approves, output is redacted.
    let argv: Vec<&str> = if cfg!(windows) {
        vec!["cmd", "/c", "echo %API_KEY%"]
    } else {
        vec!["sh", "-c", "echo $API_KEY"]
    };
    let approve = async {
        for _ in 0..400 {
            if daemon.pending_count() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let id = match client
            .approver(ApproverOp::SubscribePending, pass())
            .await
            .unwrap()
        {
            Response::Pending { requests } => requests[0].id.clone(),
            other => panic!("{other:?}"),
        };
        client
            .approver(
                ApproverOp::Approve {
                    request_id: id,
                    scope: GrantScope::Once,
                },
                pass(),
            )
            .await
            .unwrap()
    };
    let run_args = json!({
        "argv": argv,
        "secrets": ["API_KEY"],
        "reason": "Print the key to check that MCP output is redacted",
        "cwd": work.to_string_lossy(),
        "timeout_secs": 30
    });
    let (r, ok) = tokio::join!(mcp.tool(4, "run_with_secrets", run_args.clone()), approve);
    assert!(matches!(ok, Response::Ok), "{ok:?}");
    let (text, is_error) = tool_text(&r);
    assert!(!is_error, "{r}");
    let out: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(out["exit_code"], 0, "{out}");
    assert!(
        out["stdout"]
            .as_str()
            .unwrap()
            .contains("[REDACTED:API_KEY]"),
        "{out}"
    );
    assert!(out["redactions"].as_u64().unwrap() >= 1, "{out}");

    // A denied request comes back as {denied: ...}.
    let deny = async {
        for _ in 0..400 {
            if daemon.pending_count() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let id = match client
            .approver(ApproverOp::SubscribePending, pass())
            .await
            .unwrap()
        {
            Response::Pending { requests } => requests[0].id.clone(),
            other => panic!("{other:?}"),
        };
        client
            .approver(ApproverOp::Deny { request_id: id }, pass())
            .await
            .unwrap()
    };
    let (r, ok) = tokio::join!(mcp.tool(5, "run_with_secrets", run_args), deny);
    assert!(matches!(ok, Response::Ok), "{ok:?}");
    let (text, is_error) = tool_text(&r);
    assert!(is_error, "{r}");
    assert_eq!(
        serde_json::from_str::<Value>(&text).unwrap()["denied"],
        "denied by the human"
    );

    // Unknown fields and a missing reason are rejected (no request reaches the human).
    let r = mcp
        .tool(
            6,
            "run_with_secrets",
            json!({"argv": ["x"], "secrets": ["API_KEY"], "reason": "long enough reason", "get_value": true}),
        )
        .await;
    assert!(
        r.get("error").is_some() || tool_text(&r).1,
        "unknown field accepted: {r}"
    );
    let r = mcp
        .tool(
            7,
            "run_with_secrets",
            json!({"argv": ["x"], "secrets": ["API_KEY"]}),
        )
        .await;
    assert!(
        r.get("error").is_some() || tool_text(&r).1,
        "missing reason accepted: {r}"
    );
    // No such tool.
    let r = mcp.tool(8, "get_secret", json!({"name": "API_KEY"})).await;
    assert!(r.get("error").is_some() || tool_text(&r).1, "{r}");
    assert_eq!(daemon.pending_count(), 0);

    assert!(
        !mcp.transcript.contains(FAKE),
        "a secret value reached the agent"
    );
    drop(mcp.stdin);
    let _ = tokio::time::timeout(Duration::from_secs(10), mcp.child.wait()).await;
    daemon.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
}
