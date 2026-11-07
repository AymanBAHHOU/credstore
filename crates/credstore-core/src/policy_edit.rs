//! Changes to the policy file made from the desktop app, keeping the file's comments and
//! layout (`toml_edit`). These only produce the new text: the daemon validates it with
//! [`Policy::parse`](crate::policy::Policy::parse) before writing it.

use toml_edit::{Array, DocumentMut, Item, Table};

use crate::names;
use crate::policy::PolicyError;

fn bad(msg: impl Into<String>) -> PolicyError {
    PolicyError(msg.into())
}

fn parse(text: &str) -> Result<DocumentMut, PolicyError> {
    text.parse::<DocumentMut>().map_err(|e| bad(e.to_string()))
}

fn array(items: &[String]) -> Item {
    let mut a = Array::new();
    for i in items {
        a.push(i.as_str());
    }
    toml_edit::value(a)
}

/// A table under `doc`, created if missing. Fails if the key holds something else.
fn table<'a>(
    parent: &'a mut Table,
    key: &str,
    implicit: bool,
) -> Result<&'a mut Table, PolicyError> {
    let item = parent.entry(key).or_insert_with(|| {
        let mut t = Table::new();
        t.set_implicit(implicit);
        Item::Table(t)
    });
    item.as_table_mut()
        .ok_or_else(|| bad(format!("`{key}` in the policy is not a table")))
}

/// Trim, lowercase and drop duplicates. Validation is left to the policy parser.
pub fn clean_hosts(hosts: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for h in hosts {
        let h = h.trim().to_ascii_lowercase();
        if !h.is_empty() && !out.contains(&h) {
            out.push(h);
        }
    }
    out
}

/// Set or clear `allow_hosts` (with `network = "allow-list"`) and `allow_commands` in
/// `[secret.NAME]`. `None` leaves a rule alone; an empty list removes it. A block left
/// empty is removed, so the secret follows `[defaults]` again.
pub fn set_secret_rules(
    text: &str,
    name: &str,
    allow_hosts: Option<&[String]>,
    allow_commands: Option<&[String]>,
) -> Result<String, PolicyError> {
    names::validate_name(name).map_err(|e| bad(e.to_string()))?;
    let mut doc = parse(text)?;
    let secrets = table(doc.as_table_mut(), "secret", true)?;
    let block = table(secrets, name, false)?;
    if let Some(hosts) = allow_hosts {
        let hosts = clean_hosts(hosts);
        if hosts.is_empty() {
            block.remove("allow_hosts");
            if block.get("network").and_then(Item::as_str) == Some("allow-list") {
                block.remove("network");
            }
        } else {
            block.insert("network", toml_edit::value("allow-list"));
            block.insert("allow_hosts", array(&hosts));
        }
    }
    if let Some(cmds) = allow_commands {
        let cmds: Vec<String> = cmds
            .iter()
            .map(|c| c.trim().to_owned())
            .filter(|c| !c.is_empty())
            .collect();
        if cmds.is_empty() {
            block.remove("allow_commands");
        } else {
            block.insert("allow_commands", array(&cmds));
        }
    }
    if block.is_empty() {
        secrets.remove(name);
    }
    Ok(doc.to_string())
}

/// Set `[defaults]` timers. `None` leaves a setting alone.
pub fn set_defaults(
    text: &str,
    session_idle_secs: Option<u64>,
    grant_ttl_secs: Option<u64>,
    approval_timeout_secs: Option<u64>,
) -> Result<String, PolicyError> {
    let mut doc = parse(text)?;
    let defaults = table(doc.as_table_mut(), "defaults", false)?;
    for (key, v) in [
        ("session_idle_secs", session_idle_secs),
        ("grant_ttl_secs", grant_ttl_secs),
        ("approval_timeout_secs", approval_timeout_secs),
    ] {
        if let Some(v) = v {
            let v = i64::try_from(v).map_err(|_| bad(format!("{key} is too large")))?;
            match defaults.get_mut(key).and_then(Item::as_value_mut) {
                // Keep the comment after the value.
                Some(old) => {
                    let decor = old.decor().clone();
                    *old = toml_edit::Value::from(v);
                    *old.decor_mut() = decor;
                }
                None => {
                    defaults.insert(key, toml_edit::value(v));
                }
            }
        }
    }
    Ok(doc.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{MatchStyle, Policy, STARTER_POLICY};

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn adds_hosts_and_keeps_comments() {
        let out = set_secret_rules(
            STARTER_POLICY,
            "STRIPE_KEY",
            Some(&s(&[" API.stripe.com "])),
            None,
        )
        .unwrap();
        assert!(out.contains("# credstore policy. See SPEC.md section 5.2."));
        assert!(out.contains("# longest \"approve for this session\" allowed"));
        let p = Policy::parse(&out, MatchStyle::Unix).unwrap();
        let r = p.rules_info("STRIPE_KEY");
        assert!(r.configured);
        assert_eq!(r.allow_hosts, s(&["api.stripe.com"]));
        assert_eq!(r.network, credstore_proto::NetworkPolicy::AllowList);
        assert!(p
            .evaluate_http("STRIPE_KEY", "api.stripe.com", 443, None)
            .is_ok());
    }

    #[test]
    fn empty_lists_remove_the_rules_and_the_block() {
        let with = set_secret_rules(
            STARTER_POLICY,
            "K",
            Some(&s(&["a.example"])),
            Some(&s(&["curl *"])),
        )
        .unwrap();
        assert!(Policy::parse(&with, MatchStyle::Unix)
            .unwrap()
            .rules_info("K")
            .allow_commands
            .is_some());
        let only_cmds = set_secret_rules(&with, "K", Some(&[]), None).unwrap();
        let r = Policy::parse(&only_cmds, MatchStyle::Unix)
            .unwrap()
            .rules_info("K");
        assert!(r.configured && r.allow_hosts.is_empty());
        assert_eq!(r.network, credstore_proto::NetworkPolicy::Inherit);
        let none = set_secret_rules(&only_cmds, "K", None, Some(&[])).unwrap();
        assert!(!none.contains("[secret.K]"), "{none}");
        assert!(
            !Policy::parse(&none, MatchStyle::Unix)
                .unwrap()
                .rules_info("K")
                .configured
        );
    }

    #[test]
    fn other_rules_in_the_block_stay() {
        let text = "[secret.K]\nallow_dirs = [\"/p/**\"] # mine\n";
        let out = set_secret_rules(text, "K", Some(&s(&["x.example"])), None).unwrap();
        assert!(out.contains("allow_dirs = [\"/p/**\"] # mine"), "{out}");
        let back = set_secret_rules(&out, "K", Some(&[]), None).unwrap();
        assert!(back.contains("[secret.K]") && back.contains("allow_dirs"));
    }

    #[test]
    fn bad_names_and_bad_hosts() {
        assert!(set_secret_rules(STARTER_POLICY, "bad name", Some(&s(&["x"])), None).is_err());
        let out = set_secret_rules(STARTER_POLICY, "K", Some(&s(&["a b"])), None).unwrap();
        assert!(
            Policy::parse(&out, MatchStyle::Unix).is_err(),
            "the parser rejects it"
        );
    }

    #[test]
    fn sets_defaults_and_keeps_their_comments() {
        let out = set_defaults(STARTER_POLICY, Some(300), None, Some(60)).unwrap();
        assert!(out.contains("session_idle_secs = 300"), "{out}");
        assert!(out.contains("# relock the vault after this long unused"));
        let p = Policy::parse(&out, MatchStyle::Unix).unwrap();
        assert_eq!(p.defaults.session_idle_secs, 300);
        assert_eq!(p.defaults.approval_timeout_secs, 60);
        assert_eq!(p.defaults.grant_ttl_secs, 600);
        let added = set_defaults("", None, Some(120), None).unwrap();
        assert_eq!(
            Policy::parse(&added, MatchStyle::Unix)
                .unwrap()
                .defaults
                .grant_ttl_secs,
            120
        );
    }
}
