use std::path::Path;

use super::*;

const STRIPE: &str = r#"
[defaults]
sandbox = "prefer"

[secret.STRIPE_KEY]
allow_commands = ["curl *api.stripe.com*", "stripe *", "pytest *"]
allow_dirs     = ["/home/me/projects/billing/**"]
network        = "allow-list"
allow_hosts    = ["api.stripe.com"]
grant_ttl_secs = 600
injection      = ["env"]

[secret.PROD_DB_URL]
grant_ttl_secs = 0

[secret.SHELL_OK]
allow_shell = true
"#;

fn unix(text: &str) -> Policy {
    Policy::parse(text, MatchStyle::Unix).expect("policy parses")
}

fn win(text: &str) -> Policy {
    Policy::parse(text, MatchStyle::Windows).expect("policy parses")
}

fn args(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// One evaluation case. `cmd` is either argv (with its resolved path) or a shell string.
struct Case {
    name: &'static str,
    secrets: &'static [&'static str],
    argv: &'static [&'static str],
    resolved: &'static str,
    shell: Option<&'static str>,
    cwd: &'static str,
    injection: Injection,
    /// `None` = allowed; `Some(text)` = denied with a reason containing `text`.
    deny: Option<&'static str>,
}

const BASE: Case = Case {
    name: "",
    secrets: &["STRIPE_KEY"],
    argv: &["stripe", "listen"],
    resolved: "/usr/bin/stripe",
    shell: None,
    cwd: "/home/me/projects/billing",
    injection: Injection::Env,
    deny: None,
};

fn run(policy: &Policy, cases: &[Case]) {
    for c in cases {
        let argv = args(c.argv);
        let secrets = args(c.secrets);
        let command = match c.shell {
            Some(s) => Command::Shell(s),
            None => Command::Argv {
                argv: &argv,
                resolved: Path::new(c.resolved),
            },
        };
        let got = policy.evaluate(&Request {
            secrets: &secrets,
            command,
            cwd: Path::new(c.cwd),
            injection: c.injection,
            timeout_secs: None,
        });
        match (c.deny, got) {
            (None, Ok(_)) => {}
            (Some(want), Err(Denial(reason))) => assert!(
                reason.contains(want),
                "{}: denial {reason:?} should mention {want:?}",
                c.name
            ),
            (None, Err(d)) => panic!("{}: expected allow, got denial {d}", c.name),
            (Some(want), Ok(e)) => panic!("{}: expected denial ({want}), got {e:?}", c.name),
        }
    }
}

#[test]
fn commands_dirs_shell_and_injection() {
    let p = unix(STRIPE);
    run(
        &p,
        &[
            Case {
                name: "allowed command in allowed dir",
                ..BASE
            },
            Case {
                name: "subdirectory",
                cwd: "/home/me/projects/billing/api/tests",
                ..BASE
            },
            Case {
                name: "curl with url",
                argv: &["curl", "-s", "https://api.stripe.com/v1/charges"],
                resolved: "/usr/bin/curl",
                ..BASE
            },
            Case {
                name: "full path to an allowed program",
                argv: &["/usr/bin/stripe", "listen"],
                resolved: "/usr/bin/stripe",
                deny: Some("command not allowed"),
                ..BASE
            },
            Case {
                name: "same basename at a different path",
                argv: &["./stripe", "listen"],
                resolved: "/home/me/projects/billing/stripe",
                deny: Some("command not allowed for STRIPE_KEY"),
                ..BASE
            },
            Case {
                name: "command not listed",
                argv: &["printenv"],
                resolved: "/usr/bin/printenv",
                deny: Some("command not allowed for STRIPE_KEY (allowed: curl"),
                ..BASE
            },
            Case {
                name: "curl to another host",
                argv: &["curl", "https://evil.example/"],
                resolved: "/usr/bin/curl",
                deny: Some("command not allowed"),
                ..BASE
            },
            Case {
                name: "dir outside",
                cwd: "/home/me",
                deny: Some("working directory not allowed"),
                ..BASE
            },
            Case {
                name: "sibling with the same prefix",
                cwd: "/home/me/projects/billing2",
                deny: Some("working directory not allowed"),
                ..BASE
            },
            Case {
                name: "shell string without allow_shell",
                shell: Some("stripe listen"),
                deny: Some("shell commands are not allowed with STRIPE_KEY"),
                ..BASE
            },
            Case {
                name: "sh -c in argv form",
                argv: &["sh", "-c", "stripe listen"],
                resolved: "/bin/sh",
                deny: Some("shell commands are not allowed"),
                ..BASE
            },
            Case {
                name: "shell behind a wrapper",
                argv: &["env", "/bin/bash", "-c", "stripe listen"],
                resolved: "/usr/bin/env",
                deny: Some("shell commands are not allowed"),
                ..BASE
            },
            Case {
                name: "file injection not allowed",
                injection: Injection::File,
                deny: Some("injection mode file not allowed"),
                ..BASE
            },
            Case {
                name: "unlisted secret, not strict: any command",
                secrets: &["OTHER_KEY"],
                argv: &["printenv"],
                resolved: "/usr/bin/printenv",
                cwd: "/tmp",
                ..BASE
            },
            Case {
                name: "unlisted secret still cannot use a shell",
                secrets: &["OTHER_KEY"],
                shell: Some("echo $OTHER_KEY"),
                deny: Some("shell commands are not allowed with OTHER_KEY"),
                ..BASE
            },
            Case {
                name: "shell allowed for SHELL_OK",
                secrets: &["SHELL_OK"],
                shell: Some("echo hi | wc -c"),
                cwd: "/tmp",
                ..BASE
            },
            Case {
                name: "every secret must allow the shell",
                secrets: &["SHELL_OK", "OTHER_KEY"],
                shell: Some("echo hi"),
                deny: Some("OTHER_KEY"),
                ..BASE
            },
            Case {
                name: "every secret must allow the command",
                secrets: &["OTHER_KEY", "STRIPE_KEY"],
                argv: &["printenv"],
                resolved: "/usr/bin/printenv",
                deny: Some("command not allowed for STRIPE_KEY"),
                ..BASE
            },
            Case {
                name: "no secrets",
                secrets: &[],
                deny: Some("no secrets requested"),
                ..BASE
            },
        ],
    );
}

#[test]
fn star_in_allow_dirs_stays_in_one_component() {
    let p = unix(
        r#"
[secret.K]
allow_dirs = ["/srv/*/app"]
"#,
    );
    run(
        &p,
        &[
            Case {
                name: "one component",
                secrets: &["K"],
                cwd: "/srv/blue/app",
                ..BASE
            },
            Case {
                name: "two components",
                secrets: &["K"],
                cwd: "/srv/blue/green/app",
                deny: Some("working directory not allowed"),
                ..BASE
            },
        ],
    );
}

#[test]
fn strict_mode_denies_unlisted_secrets() {
    let p = unix("[defaults]\nstrict = true\n[secret.LISTED]\n");
    run(
        &p,
        &[
            Case {
                name: "listed",
                secrets: &["LISTED"],
                ..BASE
            },
            Case {
                name: "unlisted",
                secrets: &["LISTED", "NOT_LISTED"],
                deny: Some("NOT_LISTED has no [secret.NOT_LISTED] block and the policy is strict"),
                ..BASE
            },
        ],
    );
}

fn eff(p: &Policy, secrets: &[&str], timeout: Option<u64>) -> Effective {
    let argv = args(&["true"]);
    let secrets = args(secrets);
    p.evaluate(&Request {
        secrets: &secrets,
        command: Command::Argv {
            argv: &argv,
            resolved: Path::new("/usr/bin/true"),
        },
        cwd: Path::new("/tmp"),
        injection: Injection::Env,
        timeout_secs: timeout,
    })
    .unwrap()
}

#[test]
fn ttl_cap_is_the_smallest_across_secrets() {
    let p = unix(
        r#"
[defaults]
grant_ttl_secs = 900
[secret.A]
grant_ttl_secs = 300
[secret.NEVER]
grant_ttl_secs = 0
"#,
    );
    for (secrets, cap) in [
        (&["UNLISTED"][..], 900),
        (&["A"][..], 300),
        (&["A", "UNLISTED"][..], 300),
        (&["NEVER"][..], 0),
        (&["A", "NEVER"][..], 0),
    ] {
        assert_eq!(
            eff(&p, secrets, None).grant_ttl_cap_secs,
            cap,
            "{secrets:?}"
        );
    }
}

#[test]
fn effective_settings_take_the_strictest() {
    let p = unix(
        r#"
[defaults]
max_runtime_secs = 100
max_output_bytes = 5000
require_approval = false
[secret.A]
network = "allow-list"
allow_hosts = ["a.example", "b.example"]
sandbox = "require"
max_runtime_secs = 30
[secret.B]
network = "allow-list"
allow_hosts = ["b.example", "c.example"]
require_approval = true
max_output_bytes = 100
[secret.C]
network = "allow-list"
allow_hosts = ["c.example"]
[secret.OFF]
sandbox = "off"
network = "deny"
"#,
    );
    let e = eff(&p, &["UNLISTED"], None);
    assert!(!e.require_approval);
    assert_eq!(
        (e.timeout_secs, e.max_output_bytes, e.network),
        (100, 5000, NetworkPolicy::Inherit)
    );

    let e = eff(&p, &["A", "B"], Some(60));
    assert!(e.require_approval, "any secret requiring approval wins");
    assert_eq!(e.timeout_secs, 30, "policy cap beats a longer request");
    assert_eq!(e.max_output_bytes, 100);
    assert_eq!(e.sandbox, SandboxRequirement::Require);
    assert_eq!(e.network, NetworkPolicy::AllowList);
    assert_eq!(e.allow_hosts, vec!["b.example".to_string()]);

    assert_eq!(eff(&p, &["UNLISTED"], Some(5)).timeout_secs, 5);
    assert_eq!(eff(&p, &["A", "OFF"], None).network, NetworkPolicy::Deny);
    assert_eq!(
        eff(&p, &["A", "OFF"], None).sandbox,
        SandboxRequirement::Require
    );

    let argv = args(&["true"]);
    let both = args(&["A", "C"]);
    let d = p
        .evaluate(&Request {
            secrets: &both,
            command: Command::Argv {
                argv: &argv,
                resolved: Path::new("/usr/bin/true"),
            },
            cwd: Path::new("/tmp"),
            injection: Injection::Env,
            timeout_secs: None,
        })
        .unwrap_err();
    assert!(d.0.contains("no host in common"), "{d}");
}

#[test]
fn windows_matching_is_case_folded_and_ignores_extensions() {
    let p = win(r#"
[secret.STRIPE_KEY]
allow_commands = ["stripe *", "C:/Tools/deploy *"]
allow_dirs = ["C:/Users/Me/Projects/Billing/**"]
"#);
    let w = Case {
        argv: &["stripe", "listen"],
        resolved: r"C:\Program Files\Stripe\stripe.exe",
        cwd: r"\\?\C:\Users\me\projects\billing\api",
        ..BASE
    };
    run(
        &p,
        &[
            Case {
                name: "bare name, any case, with .exe",
                argv: &["STRIPE.EXE", "listen"],
                ..w
            },
            Case {
                name: "resolved path matched without extension",
                argv: &[r"C:\tools\Deploy.cmd", "prod"],
                resolved: r"C:\Tools\Deploy.cmd",
                ..w
            },
            Case {
                name: "dir root, backslashes, case",
                cwd: r"C:\USERS\ME\PROJECTS\BILLING",
                ..w
            },
            Case {
                name: "dir outside",
                cwd: r"C:\Users\me",
                deny: Some("working directory not allowed"),
                ..w
            },
            Case {
                name: "cmd /c is shell mode",
                argv: &["cmd.exe", "/c", "stripe listen"],
                resolved: r"C:\Windows\System32\cmd.exe",
                deny: Some("shell commands are not allowed"),
                ..w
            },
            Case {
                name: "powershell -Command is shell mode",
                argv: &["powershell", "-Command", "stripe listen"],
                resolved: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                deny: Some("shell commands are not allowed"),
                ..w
            },
            Case {
                name: "pwsh by full path is shell mode",
                argv: &[r"C:\Program Files\PowerShell\7\pwsh.exe", "-c", "x"],
                resolved: r"C:\Program Files\PowerShell\7\pwsh.exe",
                deny: Some("shell commands are not allowed"),
                ..w
            },
        ],
    );
}

#[test]
fn unix_matching_is_case_sensitive() {
    let p = unix("[secret.K]\nallow_commands = [\"stripe *\"]\n");
    run(
        &p,
        &[Case {
            name: "different case",
            secrets: &["K"],
            argv: &["Stripe", "listen"],
            resolved: "/usr/bin/Stripe",
            deny: Some("command not allowed"),
            ..BASE
        }],
    );
}

#[test]
fn starter_policy_parses() {
    let p = unix(STARTER_POLICY);
    assert_eq!(p.defaults, Defaults::default());
    win(STARTER_POLICY);
}

#[test]
fn invalid_policies_are_rejected_with_clear_errors() {
    for (text, want) in [
        ("[defaults]\nbogus = 1\n", "unknown field `bogus`"),
        (
            "[defaults]\nsandbox = \"maybe\"\n",
            "unknown variant `maybe`",
        ),
        (
            "[defaults]\nnetwork = \"allow-list\"\n",
            "needs a non-empty allow_hosts",
        ),
        (
            "[defaults]\nallow_hosts = [\"a.example\"]\n",
            "allow_hosts only applies with network = \"allow-list\"",
        ),
        (
            "[defaults]\nmax_runtime_secs = 0\n",
            "max_runtime_secs must be between",
        ),
        (
            "[defaults]\nmax_output_bytes = 0\n",
            "max_output_bytes must be between",
        ),
        (
            "[defaults]\ngrant_ttl_secs = 999999\n",
            "grant_ttl_secs must be at most",
        ),
        (
            "[defaults]\napproval_timeout_secs = 0\n",
            "approval_timeout_secs",
        ),
        (
            "[defaults]\ninjection = []\n",
            "injection must list at least one mode",
        ),
        (
            "[defaults]\ninjection = [\"pipe\"]\n",
            "unknown variant `pipe`",
        ),
        ("[secret.lower_case]\n", "[secret.lower_case]"),
        (
            "[secret.K]\nallow_commands = []\n",
            "allow_commands is empty",
        ),
        (
            "[secret.K]\nallow_commands = [\"a[\"]\n",
            "bad pattern \"a[\"",
        ),
        (
            "[secret.K]\nallow_dir = [\"/x\"]\n",
            "unknown field `allow_dir`",
        ),
        (
            "[secret.K]\nnetwork = \"allow-list\"\nallow_hosts = [\"a b\"]\n",
            "is not a host name",
        ),
        (
            "[secret.K]\nmax_runtime_secs = 0\n",
            "[secret.K] max_runtime_secs",
        ),
        ("[defaults\n", "policy error"),
        ("[default]\n", "unknown field `default`"),
    ] {
        let err = Policy::parse(text, MatchStyle::Unix)
            .expect_err(text)
            .to_string();
        assert!(
            err.contains(want),
            "{text:?}: {err:?} should mention {want:?}"
        );
    }
}

#[test]
fn empty_policy_uses_defaults() {
    let p = unix("");
    assert_eq!(p.defaults, Defaults::default());
    let e = eff(&p, &["ANY"], None);
    assert!(e.require_approval);
    assert_eq!(e.grant_ttl_cap_secs, 600);
}
