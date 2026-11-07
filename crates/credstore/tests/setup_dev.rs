//! M8: `credstore setup` against a real dev-mode daemon, with a throwaway home.

use std::cell::RefCell;
use std::collections::VecDeque;

use credstore::client::Client;
use credstore::commands::Prompt;
use credstore::setup::{deny_rules, setup, ClaudeCode, Options};
use credstore_os::{Platform, PlatformPaths};
use credstore_proto::{AgentRequest, Response, SecretText};

const PASS: &str = "correct horse battery";

struct Script {
    secrets: RefCell<VecDeque<String>>,
    lines: RefCell<VecDeque<String>>,
    terminal: bool,
}

impl Prompt for Script {
    fn secret(&self, _: &str) -> anyhow::Result<SecretText> {
        Ok(SecretText::new(
            self.secrets
                .borrow_mut()
                .pop_front()
                .expect("scripted secret"),
        ))
    }
    fn line(&self, _: &str) -> anyhow::Result<String> {
        Ok(self
            .lines
            .borrow_mut()
            .pop_front()
            .expect("scripted answer"))
    }
    fn has_terminal(&self) -> bool {
        self.terminal
    }
}

fn script(secrets: &[&str], lines: &[&str]) -> Script {
    Script {
        secrets: RefCell::new(secrets.iter().map(|s| s.to_string()).collect()),
        lines: RefCell::new(lines.iter().map(|s| s.to_string()).collect()),
        terminal: true,
    }
}

fn tempdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "cs-setup-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            % 1_000_000_000
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[tokio::test(flavor = "multi_thread")]
async fn setup_creates_the_vault_and_adds_deny_rules() {
    let home = tempdir("daemon");
    let user_home = tempdir("user");
    let paths = PlatformPaths::dev_with_home(&home);
    let daemon = credstored::start(credstored::DaemonConfig {
        paths: paths.clone(),
    })
    .await
    .unwrap();
    let client = Client::new(Platform::with_paths(paths));
    let claude = ClaudeCode {
        home: user_home.clone(),
        exe: None, // `claude` missing: registration is skipped with a hint
        credstore: "credstore".into(),
    };
    // Existing settings must survive.
    let settings = user_home.join(".claude").join("settings.json");
    std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
    std::fs::write(
        &settings,
        r#"{"model":"opus","permissions":{"allow":["Bash(ls)"]}}"#,
    )
    .unwrap();

    // Answer yes to the vault and to the deny rules.
    let mut msg = Vec::new();
    setup(
        &client,
        &script(&[PASS, PASS], &["y", ""]),
        &Options {
            yes: false,
            dev: true,
        },
        Some(&claude),
        &mut msg,
    )
    .await
    .unwrap();
    let text = String::from_utf8(msg).unwrap();
    assert!(text.contains("created the vault"), "{text}");
    assert!(text.contains("`claude` is not on PATH"), "{text}");
    assert!(text.contains("deny rule(s)"), "{text}");

    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    assert_eq!(json["model"], "opus");
    assert_eq!(
        json["permissions"]["allow"],
        serde_json::json!(["Bash(ls)"])
    );
    let deny = json["permissions"]["deny"].as_array().unwrap();
    for r in deny_rules() {
        assert!(deny.iter().any(|v| v.as_str() == Some(&r)), "{r} missing");
    }
    assert!(settings.with_extension("json.before-credstore").exists());

    // The vault is real: the daemon has one and accepts the passphrase.
    assert!(matches!(
        client.agent(&AgentRequest::ListSecrets).await.unwrap(),
        Response::Secrets { .. }
    ));

    // Run again with --yes: nothing to add; the existing vault is detected.
    let mut msg = Vec::new();
    setup(
        &client,
        &script(&[PASS, PASS], &[]),
        &Options {
            yes: true,
            dev: true,
        },
        Some(&claude),
        &mut msg,
    )
    .await
    .unwrap();
    let text = String::from_utf8(msg).unwrap();
    assert!(text.contains("a vault already exists"), "{text}");
    assert!(text.contains("deny rules are in place"), "{text}");

    // Without a terminal and without --yes it refuses instead of guessing.
    let no_tty = Script {
        secrets: RefCell::new(VecDeque::new()),
        lines: RefCell::new(VecDeque::new()),
        terminal: false,
    };
    let mut msg = Vec::new();
    let err = setup(
        &client,
        &no_tty,
        &Options {
            yes: false,
            dev: true,
        },
        Some(&claude),
        &mut msg,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("--yes"), "{err}");

    daemon.shutdown().await;
    let _ = std::fs::remove_dir_all(&home);
    let _ = std::fs::remove_dir_all(&user_home);
}
