//! M10: the desktop app's API layer (`credstore::api`) against a real dev-mode daemon.

use std::time::Duration;

use credstore::api::{Api, Decided, Decision};
use credstore::client::Client;
use credstore::doctor::Level;
use credstore_os::{Paths, Platform, PlatformPaths};
use credstore_proto::{AgentRequest, Response, RunRequest, SecretText};

const PASS: &str = "correct horse battery";
const FAKE: &str = "FAKE-SECRET-VALUE-12345";

fn pass() -> SecretText {
    SecretText::new(PASS.to_string())
}

#[tokio::test(flavor = "multi_thread")]
async fn the_app_api_covers_setup_secrets_and_approvals() {
    let home = std::env::temp_dir().join(format!(
        "cs-api-{}-{}",
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
    let platform = Platform::with_paths(paths);
    let client = Client::new(platform.clone());
    let api = Api::new(client.clone());

    // First screen: reachable, dev mode, no secrets.
    let o = api.overview().await;
    assert!(o.reachable, "{o:?}");
    assert_eq!(o.mode, "dev");
    assert!(o.secrets.is_empty());

    // Vault: the passphrases must match; a second create says it exists.
    assert!(api
        .create_vault(pass(), SecretText::new("something else!".into()))
        .await
        .is_err());
    assert!(api.create_vault(pass(), pass()).await.unwrap());
    assert!(!api.create_vault(pass(), pass()).await.unwrap());

    // Secrets: the value goes in, only the name and description come out.
    let saved = api
        .set_secret(
            "API_KEY",
            Some("Test key".into()),
            SecretText::new(FAKE.into()),
            pass(),
        )
        .await
        .unwrap();
    assert!(!saved.too_short_to_redact);
    assert!(api
        .set_secret("BAD NAME", None, SecretText::new(FAKE.into()), pass())
        .await
        .is_err());
    assert!(api
        .set_secret(
            "OTHER",
            None,
            SecretText::new(FAKE.into()),
            SecretText::new("wrong passphrase".into())
        )
        .await
        .is_err());
    let o = api.overview().await;
    assert_eq!(o.secrets.len(), 1);
    assert_eq!(o.secrets[0].name, "API_KEY");
    assert!(!format!("{o:?}").contains(FAKE));

    // Approvals: watch sees the agent's request; a wrong passphrase leaves it pending;
    // approving runs it and the agent gets redacted output.
    std::fs::write(
        platform.policy_file(),
        "[defaults]\nallow_shell = true\napproval_timeout_secs = 60\n",
    )
    .unwrap();
    credstore::commands::reload(&client, &Fixed, &mut Vec::new())
        .await
        .unwrap();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let watcher = {
        let api = api.clone();
        tokio::spawn(async move {
            let _ = api
                .watch(pass(), move |list| {
                    let _ = tx.send(list);
                })
                .await;
        })
    };
    let argv: Vec<String> = if cfg!(windows) {
        vec!["cmd".into(), "/c".into(), "echo %API_KEY%".into()]
    } else {
        vec!["sh".into(), "-c".into(), "echo $API_KEY".into()]
    };
    let agent = {
        let client = client.clone();
        let project = home.with_extension("project");
        std::fs::create_dir_all(&project).unwrap();
        let cwd = project.to_string_lossy().into_owned();
        tokio::spawn(async move {
            client
                .agent(&AgentRequest::Run(RunRequest {
                    argv: Some(argv),
                    shell: None,
                    secrets: vec!["API_KEY".into()],
                    reason: "Print the key to check redaction".into(),
                    cwd,
                    timeout_secs: None,
                    injection: None,
                }))
                .await
        })
    };
    let mut agent = agent;
    let view = loop {
        tokio::select! {
            list = rx.recv() => {
                if let Some(v) = list.expect("watch running").into_iter().next() {
                    break v;
                }
            }
            done = &mut agent => panic!("the agent's request ended before approval: {done:?}"),
            _ = tokio::time::sleep(Duration::from_secs(20)) => panic!("no pending request"),
        }
    };
    assert_eq!(view.reason, "Print the key to check redaction");
    assert!(view.command.contains("API_KEY"), "{view:?}");
    assert_eq!(view.secrets, ["API_KEY (Test key)"]);
    assert!(!format!("{view:?}").contains(FAKE));

    let wrong = api
        .decide(
            &view.id,
            Decision::Once,
            SecretText::new("not the passphrase".into()),
        )
        .await
        .unwrap();
    assert_eq!(wrong, Decided::WrongPassphrase);
    assert_eq!(daemon.pending_count(), 1);
    assert_eq!(
        api.decide(&view.id, Decision::Once, pass()).await.unwrap(),
        Decided::Done
    );
    let result = tokio::time::timeout(Duration::from_secs(30), agent)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    match result {
        Response::RunResult(r) => {
            assert_eq!(r.exit_code, Some(0), "{r:?}");
            assert!(r.stdout.contains("[REDACTED:API_KEY]"), "{r:?}");
            assert!(!r.stdout.contains(FAKE));
        }
        other => panic!("{other:?}"),
    }
    // The list empties once it is decided.
    let emptied = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(list) = rx.recv().await {
            if list.is_empty() {
                return true;
            }
        }
        false
    })
    .await
    .unwrap_or(false);
    assert!(emptied);
    watcher.abort();

    // Deny works the same way.
    assert!(matches!(
        api.decide("req-no-such", Decision::Deny, pass())
            .await
            .unwrap(),
        Decided::Failed { .. }
    ));

    // Health: doctor without a passphrase and with one; no failures in dev mode.
    let report = api.doctor(None).await.unwrap();
    assert_eq!(report.failures(), 0, "{report:?}");
    let report = api.doctor(Some(pass())).await.unwrap();
    assert_eq!(report.failures(), 0, "{report:?}");
    assert_eq!(report.about("mode")[0].level, Level::Warn);
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("\"level\":\"warn\""), "{json}");

    // Dev mode: grant has nothing to do.
    assert!(api.grant_plan(&home).unwrap().is_empty());

    // Remove, then lock.
    api.remove_secret("API_KEY", pass()).await.unwrap();
    assert!(api.overview().await.secrets.is_empty());
    api.lock(pass()).await.unwrap();

    daemon.shutdown().await;
    let _ = std::fs::remove_dir_all(&home);
    let _ = std::fs::remove_dir_all(home.with_extension("project"));
}

/// Answers every passphrase prompt with PASS.
struct Fixed;

impl credstore::commands::Prompt for Fixed {
    fn secret(&self, _: &str) -> anyhow::Result<SecretText> {
        Ok(pass())
    }
}
