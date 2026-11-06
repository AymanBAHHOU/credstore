//! Vault commands (`init`, `set`, `list`, `rm`). M1: dev mode, working on the vault file
//! directly. From M2 these go through the daemon (`admin_*` on the approver endpoint).
//!
//! `msg` gets human-facing messages (stderr in the binary); `out` gets command output.

use std::io::Write;

use anyhow::{bail, Context};
use credstore_core::names;
use credstore_core::vault::{Vault, MIN_PASSPHRASE_LEN, MIN_REDACTABLE_LEN};
use credstore_os::{fs as osfs, FeatureStatus};
use credstore_proto::SecretText;

/// Source of hidden input. The binary reads the controlling terminal; tests script it.
pub trait Prompt {
    fn secret(&self, prompt: &str) -> anyhow::Result<SecretText>;
}

pub fn init(vault: &Vault, p: &dyn Prompt, msg: &mut dyn Write) -> anyhow::Result<()> {
    if vault.exists() {
        bail!("a vault already exists at {}", vault.vault_file().display());
    }
    let first = p.secret("New vault passphrase: ")?;
    if first.expose().chars().count() < MIN_PASSPHRASE_LEN {
        bail!("the passphrase must be at least {MIN_PASSPHRASE_LEN} characters");
    }
    let second = p.secret("Repeat the passphrase: ")?;
    if first != second {
        bail!("the passphrases do not match");
    }
    vault.create(&first)?;
    writeln!(msg, "Created vault at {}", vault.vault_file().display())?;
    writeln!(
        msg,
        "There is no way to recover the vault without this passphrase."
    )?;
    if let FeatureStatus::Unavailable(reason) = osfs::private_file_protection() {
        writeln!(msg, "warning: vault file permissions: {reason}")?;
    }
    Ok(())
}

pub fn set(
    vault: &Vault,
    name: &str,
    description: Option<String>,
    p: &dyn Prompt,
    msg: &mut dyn Write,
) -> anyhow::Result<()> {
    // Check what we can before asking for anything.
    names::validate_name(name)?;
    if let Some(d) = &description {
        names::validate_description(d)?;
    }
    if !vault.exists() {
        bail!("no vault yet; run `credstore init` first");
    }
    let pass = p.secret("Vault passphrase: ")?;
    let mut contents = vault.unlock(&pass)?;
    let value = p.secret(&format!("Value for {name} (input hidden): "))?;
    let outcome = contents.set(name, value, description)?;
    vault.save(&contents, &pass).context("saving the vault")?;

    let verb = if outcome.replaced {
        "Replaced"
    } else {
        "Saved"
    };
    writeln!(msg, "{verb} {name}.")?;
    if outcome.too_short_to_redact {
        writeln!(
            msg,
            "warning: values shorter than {MIN_REDACTABLE_LEN} characters are too short to \
             redact safely, so {name} will not be masked in command output."
        )?;
    }
    Ok(())
}

pub fn list(vault: &Vault, out: &mut dyn Write, msg: &mut dyn Write) -> anyhow::Result<()> {
    let infos = vault.list()?;
    if infos.is_empty() {
        writeln!(msg, "No secrets yet. Add one with `credstore set NAME`.")?;
        return Ok(());
    }
    let width = infos.iter().map(|i| i.name.len()).max().unwrap_or(0);
    for i in infos {
        // The index is plain text another process could edit; never print control chars.
        let name = printable(&i.name);
        let desc = printable(&i.description);
        writeln!(out, "{name:width$}  {desc}")?;
    }
    Ok(())
}

pub fn rm(vault: &Vault, name: &str, p: &dyn Prompt, msg: &mut dyn Write) -> anyhow::Result<()> {
    names::validate_name(name)?;
    if !vault.exists() {
        bail!("no vault yet; run `credstore init` first");
    }
    let pass = p.secret("Vault passphrase: ")?;
    let mut contents = vault.unlock(&pass)?;
    contents.remove(name)?;
    vault.save(&contents, &pass).context("saving the vault")?;
    writeln!(msg, "Removed {name}.")?;
    Ok(())
}

fn printable(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::path::PathBuf;

    use super::*;

    const FAKE: &str = "FAKE-SECRET-VALUE-12345";
    const PASS: &str = "correct horse battery";

    /// Scripted answers; panics-free error if asked more than scripted.
    struct Scripted(RefCell<VecDeque<String>>);

    impl Scripted {
        fn new(answers: &[&str]) -> Self {
            Self(RefCell::new(
                answers.iter().map(|s| s.to_string()).collect(),
            ))
        }
        fn remaining(&self) -> usize {
            self.0.borrow().len()
        }
    }

    impl Prompt for Scripted {
        fn secret(&self, _: &str) -> anyhow::Result<SecretText> {
            self.0
                .borrow_mut()
                .pop_front()
                .map(SecretText::new)
                .ok_or_else(|| anyhow::anyhow!("unexpected prompt"))
        }
    }

    struct Home(PathBuf);
    impl Home {
        fn new(tag: &str) -> Self {
            Self(std::env::temp_dir().join(format!(
                "credstore-cli-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )))
        }
        fn vault(&self) -> Vault {
            Vault::new(self.0.join("vault.age"), self.0.join("index.json"))
        }
    }
    impl Drop for Home {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn text(buf: &[u8]) -> String {
        String::from_utf8_lossy(buf).into_owned()
    }

    #[test]
    fn full_flow() {
        let home = Home::new("flow");
        let v = home.vault();
        let mut msg = Vec::new();
        let mut out = Vec::new();

        init(&v, &Scripted::new(&[PASS, PASS]), &mut msg).unwrap();

        let p = Scripted::new(&[PASS, FAKE]);
        set(
            &v,
            "STRIPE_KEY",
            Some("Stripe test key".into()),
            &p,
            &mut msg,
        )
        .unwrap();
        assert_eq!(p.remaining(), 0);

        list(&v, &mut out, &mut msg).unwrap();
        assert_eq!(text(&out), "STRIPE_KEY  Stripe test key\n");

        rm(&v, "STRIPE_KEY", &Scripted::new(&[PASS]), &mut msg).unwrap();
        out.clear();
        list(&v, &mut out, &mut msg).unwrap();
        assert!(out.is_empty());

        let all = text(&msg);
        assert!(all.contains("Saved STRIPE_KEY.") && all.contains("Removed STRIPE_KEY."));
        assert!(!all.contains(FAKE) && !all.contains(PASS), "{all}");
    }

    #[test]
    fn init_rejects_mismatch_short_and_existing() {
        let home = Home::new("init");
        let v = home.vault();
        let mut msg = Vec::new();
        assert!(init(
            &v,
            &Scripted::new(&[PASS, "different passphrase"]),
            &mut msg
        )
        .is_err());
        assert!(init(&v, &Scripted::new(&["short"]), &mut msg).is_err());
        assert!(!v.exists());
        init(&v, &Scripted::new(&[PASS, PASS]), &mut msg).unwrap();
        // Existing vault: refused before any prompt.
        assert!(init(&v, &Scripted::new(&[]), &mut msg).is_err());
    }

    #[test]
    fn set_with_wrong_passphrase_changes_nothing() {
        let home = Home::new("wrong");
        let v = home.vault();
        let mut msg = Vec::new();
        init(&v, &Scripted::new(&[PASS, PASS]), &mut msg).unwrap();
        let before = std::fs::read(v.vault_file()).unwrap();
        let p = Scripted::new(&["wrong passphrase", FAKE]);
        let err = set(&v, "K_1", None, &p, &mut msg).unwrap_err();
        assert!(err.to_string().contains("wrong passphrase"), "{err}");
        assert_eq!(p.remaining(), 1, "value was never asked for");
        assert_eq!(std::fs::read(v.vault_file()).unwrap(), before);
    }

    #[test]
    fn bad_input_is_refused_before_prompting() {
        let home = Home::new("bad");
        let v = home.vault();
        let mut msg = Vec::new();
        let none = Scripted::new(&[]);
        assert!(set(&v, "lower_case", None, &none, &mut msg).is_err());
        assert!(set(&v, "K", Some("a\x1b[2Jb".into()), &none, &mut msg).is_err());
        assert!(rm(&v, "not valid", &none, &mut msg).is_err());
        assert!(set(&v, "K", None, &none, &mut msg)
            .unwrap_err()
            .to_string()
            .contains("credstore init"));
    }

    #[test]
    fn short_value_warns() {
        let home = Home::new("short");
        let v = home.vault();
        let mut msg = Vec::new();
        init(&v, &Scripted::new(&[PASS, PASS]), &mut msg).unwrap();
        set(&v, "PIN", None, &Scripted::new(&[PASS, "1234"]), &mut msg).unwrap();
        assert!(text(&msg).contains("too short to redact"));
    }

    #[test]
    fn list_masks_control_characters_from_a_tampered_index() {
        let home = Home::new("tampered");
        let v = home.vault();
        let mut msg = Vec::new();
        init(&v, &Scripted::new(&[PASS, PASS]), &mut msg).unwrap();
        std::fs::write(
            v.index_file(),
            r#"{"v":1,"secrets":[{"name":"K","description":"\u001b[2Jhi"}]}"#,
        )
        .unwrap();
        let mut out = Vec::new();
        list(&v, &mut out, &mut msg).unwrap();
        assert_eq!(text(&out), "K  ?[2Jhi\n");
    }
}
