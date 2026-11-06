//! M7: `credstore doctor` against a real dev-mode daemon.

use std::cell::RefCell;
use std::collections::VecDeque;

use credstore::client::Client;
use credstore::commands::{self, Prompt};
use credstore::doctor::{doctor, Level};
use credstore_os::{FeatureStatus, HardeningItem, Platform, PlatformPaths};
use credstore_proto::SecretText;

const PASS: &str = "correct horse battery";
const FAKE: &str = "FAKE-SECRET-VALUE-12345";

struct Script {
    answers: RefCell<VecDeque<String>>,
    terminal: bool,
}

impl Prompt for Script {
    fn secret(&self, _: &str) -> anyhow::Result<SecretText> {
        Ok(SecretText::new(
            self.answers
                .borrow_mut()
                .pop_front()
                .expect("scripted answer"),
        ))
    }
    fn has_terminal(&self) -> bool {
        self.terminal
    }
}

fn script(a: &[&str]) -> Script {
    Script {
        answers: RefCell::new(a.iter().map(|s| s.to_string()).collect()),
        terminal: true,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn doctor_reports_a_healthy_dev_install() {
    let home = std::env::temp_dir().join(format!(
        "cs-doctor-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            % 1_000_000_000
    ));
    let paths = PlatformPaths::dev_with_home(&home);
    let daemon = credstored::start(credstored::DaemonConfig {
        paths: paths.clone(),
    })
    .await
    .unwrap();
    daemon.report_hardening(&[
        HardeningItem {
            name: "no core dumps",
            status: FeatureStatus::Active,
        },
        HardeningItem {
            name: "memory locking",
            status: FeatureStatus::Unavailable("test: not attempted".into()),
        },
    ]);
    let client = Client::new(Platform::with_paths(paths));
    let mut msg = Vec::new();
    commands::init(&client, &script(&[PASS, PASS]), &mut msg)
        .await
        .unwrap();
    commands::set(
        &client,
        "API_KEY",
        Some("Test key".into()),
        &script(&[PASS, FAKE]),
        &mut msg,
    )
    .await
    .unwrap();

    // With the passphrase: the daemon's own sandbox and hardening report.
    let mut out = Vec::new();
    let report = doctor(&client, &script(&[PASS]), &mut out).await.unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(!text.contains(FAKE), "{text}");
    assert_eq!(report.failures(), 0, "{text}");
    for topic in ["vault", "index", "policy", "audit log"] {
        let c = report.about(topic);
        assert_eq!(c[0].level, Level::Ok, "{topic}: {text}");
    }
    let agent = report.about("agent");
    assert_eq!(agent[0].level, Level::Ok, "{text}");
    assert!(agent[0].detail.contains("1 secret(s)"), "{text}");
    assert_eq!(report.about("approver")[0].level, Level::Ok, "{text}");
    assert_eq!(report.about("policy").len(), 2, "file and daemon: {text}");
    let sandbox = report.about("sandbox");
    assert_eq!(sandbox.len(), 1, "{text}");
    let expected = credstore_os::sandbox::mode_name(credstore_os::sandbox::capabilities().mode);
    assert!(sandbox[0].detail.starts_with(expected), "{text}");
    let hardening = report.about("hardening");
    assert_eq!(hardening.len(), 2, "{text}");
    assert_eq!(hardening[0].level, Level::Ok);
    assert_eq!(hardening[1].level, Level::Warn);
    assert!(hardening[1].detail.contains("not attempted"), "{text}");
    // Dev mode is always called out.
    assert_eq!(report.about("mode")[0].level, Level::Warn);

    // Without a terminal: no passphrase prompt, and this process's probe instead.
    let no_tty = Script {
        answers: RefCell::new(VecDeque::new()),
        terminal: false,
    };
    let mut out = Vec::new();
    let report = doctor(&client, &no_tty, &mut out).await.unwrap();
    let text = String::from_utf8(out).unwrap();
    assert_eq!(report.failures(), 0, "{text}");
    assert!(report.about("hardening").is_empty(), "{text}");
    assert!(
        report.about("sandbox")[0]
            .detail
            .contains("probed by this process"),
        "{text}"
    );

    // A wrong passphrase is a failure, not a crash.
    let mut out = Vec::new();
    let report = doctor(&client, &script(&["not the passphrase"]), &mut out)
        .await
        .unwrap();
    assert_eq!(report.failures(), 1, "{}", String::from_utf8_lossy(&out));
    assert_eq!(report.about("daemon")[0].level, Level::Fail);

    daemon.shutdown().await;
    let _ = std::fs::remove_dir_all(&home);
}
