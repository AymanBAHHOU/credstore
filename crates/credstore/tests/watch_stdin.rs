//! Piping answers into `credstore watch` must not approve anything (spec 6.3, M4).
//!
//! The real binary runs without a controlling terminal (a new session on Linux, a
//! detached process on Windows) with the passphrase and "o" on stdin. It must refuse to
//! run, and the pending request must stay pending.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use credstore::client::Client;
use credstore::commands::{self, Prompt};
use credstore_os::{Paths, Platform, PlatformPaths};
use credstore_proto::{AgentRequest, ApproverOp, Response, RunRequest, SecretText};

const PASS: &str = "correct horse battery";

struct Script(RefCell<VecDeque<String>>);

impl Prompt for Script {
    fn secret(&self, _: &str) -> anyhow::Result<SecretText> {
        Ok(SecretText::new(self.0.borrow_mut().pop_front().unwrap()))
    }
}

fn script(a: &[&str]) -> Script {
    Script(RefCell::new(a.iter().map(|s| s.to_string()).collect()))
}

/// A command for `bin` that runs without a controlling terminal, or `None` if this
/// machine has no way to do that.
fn without_terminal(bin: &Path) -> Option<Command> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        let mut c = Command::new(bin);
        c.creation_flags(DETACHED_PROCESS);
        Some(c)
    }
    #[cfg(unix)]
    {
        for setsid in ["/usr/bin/setsid", "/bin/setsid"] {
            if Path::new(setsid).exists() {
                let mut c = Command::new(setsid);
                c.arg("-w").arg(bin);
                return Some(c);
            }
        }
        // No setsid (macOS): fine only if this process has no terminal either.
        if std::fs::File::open("/dev/tty").is_err() {
            return Some(Command::new(bin));
        }
        None
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn piped_stdin_cannot_approve() {
    let home = std::env::temp_dir().join(format!("cs-watchstdin-{}", std::process::id()));
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
        None,
        &script(&[PASS, "FAKE-SECRET-VALUE-12345"]),
        &mut msg,
    )
    .await
    .unwrap();
    std::fs::write(
        platform.policy_file(),
        "[defaults]\napproval_timeout_secs = 60\n",
    )
    .unwrap();
    commands::reload(&client, &script(&[PASS]), &mut msg)
        .await
        .unwrap();

    let agent = client.clone();
    let cwd = home.to_string_lossy().into_owned();
    let request = tokio::spawn(async move {
        agent
            .agent(&AgentRequest::Run(RunRequest {
                argv: Some(vec![if cfg!(windows) { "hostname" } else { "echo" }.into()]),
                shell: None,
                secrets: vec!["API_KEY".into()],
                reason: "Check that piped stdin cannot approve".into(),
                cwd,
                timeout_secs: None,
                injection: None,
            }))
            .await
            .unwrap()
    });
    for _ in 0..200 {
        if daemon.pending_count() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(daemon.pending_count(), 1);

    let bin = Path::new(env!("CARGO_BIN_EXE_credstore"));
    match without_terminal(bin) {
        None => eprintln!("skipped the binary check: no way to drop this terminal here"),
        Some(mut cmd) => {
            let home2 = home.clone();
            let out = tokio::task::spawn_blocking(move || {
                let mut child = cmd
                    .args(["--dev", "watch"])
                    .env("CREDSTORE_HOME", &home2)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap();
                let mut stdin = child.stdin.take().unwrap();
                let _ = stdin.write_all(format!("{PASS}\no\n{PASS}\no\n{PASS}\n").as_bytes());
                drop(stdin);
                child.wait_with_output().unwrap()
            })
            .await
            .unwrap();
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(!out.status.success(), "watch must refuse: {stderr}");
            assert!(stderr.contains("needs a terminal"), "{stderr}");
        }
    }

    // Nothing was approved, nothing unlocked.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(daemon.pending_count(), 1, "the request is still pending");
    assert!(!daemon.is_unlocked());
    let log = std::fs::read_to_string(platform.audit_log()).unwrap();
    assert!(!log.contains("\"approved\""), "{log}");

    // Clean up: deny it.
    let id = {
        use credstore_proto::{read_message, write_message, ApproverRequest, Proof};
        let mut s = client
            .connect(credstore_os::EndpointKind::Approver)
            .await
            .unwrap();
        write_message(
            &mut s,
            &ApproverRequest {
                proof: Proof {
                    passphrase: SecretText::new(PASS.into()),
                },
                op: ApproverOp::SubscribePending,
            },
        )
        .await
        .unwrap();
        match read_message::<Response, _>(&mut s).await.unwrap() {
            Response::Pending { mut requests } => requests.pop().unwrap().id,
            other => panic!("{other:?}"),
        }
    };
    let r = client
        .approver(
            ApproverOp::Deny { request_id: id },
            SecretText::new(PASS.into()),
        )
        .await
        .unwrap();
    assert!(matches!(r, Response::Ok));
    assert!(matches!(request.await.unwrap(), Response::Denied { .. }));
    daemon.shutdown().await;
    let _ = std::fs::remove_dir_all(&home);
}
