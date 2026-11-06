use std::path::PathBuf;
use std::time::Duration;

use super::*;

const FAKE: &str = "FAKE-SECRET-VALUE-12345";

fn pass() -> SecretText {
    SecretText::new("correct horse battery".into())
}

struct TempHome(PathBuf);

impl TempHome {
    fn new(tag: &str) -> Self {
        let d = std::env::temp_dir().join(format!(
            "credstore-vault-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        Self(d)
    }

    fn vault(&self) -> Vault {
        Vault::new(self.0.join("vault.age"), self.0.join("index.json")).with_test_kdf()
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn create_set_unlock_round_trip() {
    let home = TempHome::new("roundtrip");
    let v = home.vault();
    v.create(&pass()).unwrap();
    assert!(v.unlock(&pass()).unwrap().is_empty());

    let mut c = v.unlock(&pass()).unwrap();
    let out = c
        .set(
            "STRIPE_KEY",
            SecretText::new(FAKE.into()),
            Some("Stripe test key".into()),
        )
        .unwrap();
    assert_eq!(
        out,
        SetOutcome {
            replaced: false,
            too_short_to_redact: false
        }
    );
    v.save(&c, &pass()).unwrap();

    let c = v.unlock(&pass()).unwrap();
    let e = c.get("STRIPE_KEY").unwrap();
    assert_eq!(e.value.expose(), FAKE);
    assert_eq!(e.description, "Stripe test key");
    assert!(e.created.ends_with('Z') && e.created == e.updated);
}

#[test]
fn create_refuses_existing_vault_and_weak_passphrase() {
    let home = TempHome::new("create");
    let v = home.vault();
    assert!(matches!(
        v.create(&SecretText::new("short".into())),
        Err(VaultError::WeakPassphrase)
    ));
    assert!(!v.exists());
    v.create(&pass()).unwrap();
    assert!(matches!(
        v.create(&pass()),
        Err(VaultError::AlreadyExists(_))
    ));
}

#[test]
fn wrong_passphrase_fails() {
    let home = TempHome::new("wrongpass");
    let v = home.vault();
    v.create(&pass()).unwrap();
    let err = v
        .unlock(&SecretText::new("not the passphrase".into()))
        .unwrap_err();
    assert!(matches!(err, VaultError::WrongPassphrase), "{err:?}");
}

#[test]
fn missing_vault_is_reported() {
    let home = TempHome::new("missing");
    let v = home.vault();
    assert!(matches!(v.unlock(&pass()), Err(VaultError::Missing(_))));
    assert!(matches!(v.list(), Err(VaultError::Missing(_))));
}

#[test]
fn vault_and_index_contain_no_plaintext_value() {
    let home = TempHome::new("plaintext");
    let v = home.vault();
    v.create(&pass()).unwrap();
    let mut c = v.unlock(&pass()).unwrap();
    c.set("STRIPE_KEY", SecretText::new(FAKE.into()), None)
        .unwrap();
    c.set(
        "MULTI",
        SecretText::new(format!("line-one-{FAKE}\nline-two")),
        Some("multi-line".into()),
    )
    .unwrap();
    v.save(&c, &pass()).unwrap();

    let raw = std::fs::read(v.vault_file()).unwrap();
    assert!(raw.starts_with(b"age-encryption.org/v1"));
    assert!(!contains(&raw, FAKE.as_bytes()));
    assert!(
        !contains(&raw, b"STRIPE_KEY"),
        "names are inside the encryption too"
    );

    let index = std::fs::read(v.index_file()).unwrap();
    assert!(!contains(&index, FAKE.as_bytes()));
    assert!(!contains(&index, b"line-two"));
    assert!(!contains(&index, b"value"));
    assert!(contains(&index, b"STRIPE_KEY"));

    // No other file in the home holds the value either.
    for entry in std::fs::read_dir(&home.0).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        assert!(!contains(&bytes, FAKE.as_bytes()));
    }
}

#[test]
fn list_reads_index_without_passphrase() {
    let home = TempHome::new("list");
    let v = home.vault();
    v.create(&pass()).unwrap();
    assert!(v.list().unwrap().is_empty());
    let mut c = v.unlock(&pass()).unwrap();
    c.set("B_KEY", SecretText::new(FAKE.into()), Some("b".into()))
        .unwrap();
    c.set("A_KEY", SecretText::new(FAKE.into()), Some("a".into()))
        .unwrap();
    v.save(&c, &pass()).unwrap();
    let names: Vec<_> = v.list().unwrap().into_iter().map(|i| i.name).collect();
    assert_eq!(names, ["A_KEY", "B_KEY"]);
}

#[test]
fn replace_keeps_description_unless_given() {
    let mut c = VaultContents::default();
    c.set(
        "K",
        SecretText::new("value-one".into()),
        Some("first".into()),
    )
    .unwrap();
    let out = c
        .set("K", SecretText::new("value-two".into()), None)
        .unwrap();
    assert!(out.replaced);
    assert_eq!(c.get("K").unwrap().description, "first");
    assert_eq!(c.get("K").unwrap().value.expose(), "value-two");
    c.set(
        "K",
        SecretText::new("value-3".into()),
        Some("second".into()),
    )
    .unwrap();
    assert_eq!(c.get("K").unwrap().description, "second");
}

#[test]
fn short_values_are_flagged() {
    let mut c = VaultContents::default();
    let out = c.set("PIN", SecretText::new("12345".into()), None).unwrap();
    assert!(out.too_short_to_redact);
    let out = c
        .set("PIN", SecretText::new("123456".into()), None)
        .unwrap();
    assert!(!out.too_short_to_redact);
}

#[test]
fn set_and_remove_validate_input() {
    let mut c = VaultContents::default();
    assert!(matches!(
        c.set("lower", SecretText::new(FAKE.into()), None),
        Err(VaultError::Input(InputError::BadName))
    ));
    assert!(matches!(
        c.set("K", SecretText::new(String::new()), None),
        Err(VaultError::Input(InputError::EmptyValue))
    ));
    assert!(matches!(
        c.set("K", SecretText::new(FAKE.into()), Some("\x1b[31m".into())),
        Err(VaultError::Input(InputError::DescriptionControlChars))
    ));
    assert!(matches!(c.remove("NOPE"), Err(VaultError::NoSuchSecret(_))));
    c.set("K", SecretText::new(FAKE.into()), None).unwrap();
    c.remove("K").unwrap();
    assert!(c.is_empty());
}

#[test]
fn tampered_vault_is_rejected() {
    let home = TempHome::new("tamper");
    let v = home.vault();
    v.create(&pass()).unwrap();
    let mut c = v.unlock(&pass()).unwrap();
    c.set("K", SecretText::new(FAKE.into()), None).unwrap();
    v.save(&c, &pass()).unwrap();

    let good = std::fs::read(v.vault_file()).unwrap();
    // Flip one byte near the end (payload) and one in the header.
    for pos in [good.len() - 5, 30] {
        let mut bad = good.clone();
        bad[pos] ^= 0x01;
        std::fs::write(v.vault_file(), &bad).unwrap();
        let err = v.unlock(&pass()).unwrap_err();
        assert!(
            matches!(err, VaultError::Corrupt(_) | VaultError::WrongPassphrase),
            "byte {pos}: {err:?}"
        );
    }
    std::fs::write(v.vault_file(), b"not a vault").unwrap();
    assert!(matches!(v.unlock(&pass()), Err(VaultError::Corrupt(_))));
}

#[test]
fn excessive_kdf_cost_is_refused() {
    let home = TempHome::new("cost");
    let mut v = home.vault();
    v.kdf.work_factor = 6;
    v.create(&pass()).unwrap();
    v.kdf.max_work_factor = 5;
    assert!(matches!(v.unlock(&pass()), Err(VaultError::ExcessiveWork)));
}

#[test]
fn debug_output_hides_values() {
    let mut c = VaultContents::default();
    c.set("K", SecretText::new(FAKE.into()), None).unwrap();
    let shown = format!("{c:?}");
    assert!(!shown.contains(FAKE), "{shown}");
    assert!(shown.contains("[REDACTED]"));
}

#[test]
fn production_kdf_cost_is_fixed() {
    let v = Vault::new("v.age", "i.json");
    assert_eq!(v.kdf.work_factor, 18);
    assert!(v.kdf.max_work_factor >= v.kdf.work_factor);
}

// ---------------------------------------------------------------------------
// Crash safety: kill a writer at many points, the vault must always open.
// ---------------------------------------------------------------------------

const WRITER_ENV: &str = "CREDSTORE_TEST_WRITER_HOME";

/// Child process body for `killing_a_writer_never_corrupts_the_vault`. Ignored in normal
/// runs; the parent starts it with `--ignored --exact`.
#[test]
#[ignore = "helper process for the crash-safety test"]
fn writer_child() {
    let Some(home) = std::env::var_os(WRITER_ENV) else {
        return;
    };
    let home = PathBuf::from(home);
    let v = Vault::new(home.join("vault.age"), home.join("index.json")).with_test_kdf();
    let mut i: u64 = 0;
    loop {
        let mut c = v.unlock(&pass()).expect("child unlock");
        let value = format!("{FAKE}-{i}-{}", "x".repeat((i % 7) as usize * 1000));
        c.set(
            &format!("KEY_{}", i % 5),
            SecretText::new(value),
            Some(format!("n{i}")),
        )
        .unwrap();
        v.save(&c, &pass()).expect("child save");
        i += 1;
    }
}

#[test]
fn killing_a_writer_never_corrupts_the_vault() {
    let home = TempHome::new("crash");
    let v = home.vault();
    v.create(&pass()).unwrap();
    let exe = std::env::current_exe().unwrap();

    let log = home.0.with_extension("child.log");
    for round in 0..12u64 {
        let before = std::fs::read(v.vault_file()).unwrap();
        let mut child = std::process::Command::new(&exe)
            .args([
                "--ignored",
                "--exact",
                "vault::tests::writer_child",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(WRITER_ENV, &home.0)
            .stdout(std::process::Stdio::null())
            .stderr(std::fs::File::create(&log).unwrap())
            .spawn()
            .unwrap();

        // Wait until the child has saved at least once (process start-up can be slow,
        // for example while antivirus scans a fresh test binary).
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            if std::fs::read(v.vault_file()).is_ok_and(|now| now != before) {
                break;
            }
            if let Some(status) = child.try_wait().unwrap() {
                panic!(
                    "round {round}: writer exited early ({status}): {}",
                    std::fs::read_to_string(&log).unwrap_or_default()
                );
            }
            assert!(std::time::Instant::now() < deadline, "writer never saved");
            std::thread::sleep(Duration::from_millis(2));
        }
        // Then kill it at a different point in its write loop each round.
        std::thread::sleep(Duration::from_millis(round * 3));
        child.kill().unwrap();
        child.wait().unwrap();

        let c = v
            .unlock(&pass())
            .unwrap_or_else(|e| panic!("round {round}: vault unreadable after kill: {e:?}"));
        // Index is always valid JSON and lags the vault by at most one write.
        let listed = v.list().unwrap();
        assert!(listed.len().abs_diff(c.len()) <= 1, "round {round}");
    }

    let c = v.unlock(&pass()).unwrap();
    assert!(!c.is_empty(), "the child made progress");
    let _ = std::fs::remove_file(log);
}
