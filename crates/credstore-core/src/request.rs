//! Input checks for run requests (spec 6.2 step 2), before policy is consulted.
//!
//! Errors describe what is wrong without echoing the input: argv and shell strings may
//! contain a secret the agent pasted by mistake.

use credstore_proto::{Injection, RunRequest};

use crate::names;

pub const MAX_ARGS: usize = 256;
pub const MAX_COMMAND_BYTES: usize = 64 * 1024;
pub const MAX_SECRETS: usize = 16;
pub const REASON_MIN_CHARS: usize = 10;
pub const REASON_MAX_CHARS: usize = 300;
pub const MAX_CWD_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid request: {0}")]
pub struct RequestError(pub String);

fn bad(m: impl Into<String>) -> RequestError {
    RequestError(m.into())
}

/// Check sizes, names and shape. Returns the injection mode (default `env`).
pub fn check(req: &RunRequest) -> Result<Injection, RequestError> {
    match (&req.argv, &req.shell) {
        (Some(_), Some(_)) => return Err(bad("give either argv or shell, not both")),
        (None, None) => return Err(bad("argv is required")),
        (Some(argv), None) => {
            if argv.is_empty() || argv[0].is_empty() {
                return Err(bad("argv must start with a program name"));
            }
            if argv.len() > MAX_ARGS {
                return Err(bad(format!("argv has more than {MAX_ARGS} entries")));
            }
            let total: usize = argv.iter().map(|a| a.len() + 1).sum();
            if total > MAX_COMMAND_BYTES {
                return Err(bad(format!(
                    "argv is longer than {MAX_COMMAND_BYTES} bytes"
                )));
            }
            if let Some(i) = argv.iter().position(|a| a.contains('\0')) {
                return Err(bad(format!("argv[{i}] contains a NUL byte")));
            }
        }
        (None, Some(shell)) => {
            if shell.trim().is_empty() {
                return Err(bad("shell command is empty"));
            }
            if shell.len() > MAX_COMMAND_BYTES {
                return Err(bad(format!(
                    "shell command is longer than {MAX_COMMAND_BYTES} bytes"
                )));
            }
            if shell.contains('\0') {
                return Err(bad("shell command contains a NUL byte"));
            }
        }
    }

    if req.secrets.is_empty() {
        return Err(bad("secrets must name at least one secret"));
    }
    if req.secrets.len() > MAX_SECRETS {
        return Err(bad(format!("at most {MAX_SECRETS} secrets per request")));
    }
    for (i, s) in req.secrets.iter().enumerate() {
        names::validate_name(s).map_err(|e| bad(format!("secrets[{i}]: {e}")))?;
        if req.secrets[..i].contains(s) {
            return Err(bad(format!("secret {s} is listed twice")));
        }
    }

    check_reason(&req.reason)?;

    if req.cwd.is_empty() || req.cwd.len() > MAX_CWD_BYTES || req.cwd.contains('\0') {
        return Err(bad("cwd must be an absolute path"));
    }
    if !std::path::Path::new(&req.cwd).is_absolute() {
        return Err(bad("cwd must be an absolute path"));
    }
    if req.timeout_secs == Some(0) {
        return Err(bad("timeout_secs must be at least 1"));
    }

    let injection = req.injection.unwrap_or(Injection::Env);
    if injection == Injection::Header {
        return Err(bad(
            "header injection is only for http_request, not for commands",
        ));
    }
    if injection == Injection::Stdin && req.secrets.len() != 1 {
        return Err(bad("stdin injection takes exactly one secret"));
    }
    Ok(injection)
}

/// `reason` is shown to the human verbatim, so it must be readable: 10 to 300 characters,
/// no control characters (which could rewrite the approval screen).
pub fn check_reason(reason: &str) -> Result<(), RequestError> {
    let n = reason.trim().chars().count();
    if !(REASON_MIN_CHARS..=REASON_MAX_CHARS).contains(&n) {
        return Err(bad(format!(
            "reason must be {REASON_MIN_CHARS} to {REASON_MAX_CHARS} characters \
             (explain what the command does with each secret)"
        )));
    }
    if reason.chars().any(char::is_control) {
        return Err(bad("reason must not contain control characters"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok() -> RunRequest {
        RunRequest {
            argv: Some(vec!["pytest".into(), "-q".into()]),
            shell: None,
            secrets: vec!["STRIPE_KEY".into()],
            reason: "Run billing tests against the Stripe test account".into(),
            cwd: if cfg!(windows) {
                r"C:\work".into()
            } else {
                "/work".into()
            },
            timeout_secs: None,
            injection: None,
        }
    }

    #[test]
    fn accepts_a_normal_request() {
        assert_eq!(check(&ok()), Ok(Injection::Env));
    }

    #[test]
    fn rejects_bad_input_without_echoing_it() {
        let secret = "FAKE-SECRET-VALUE-12345";
        type Edit = Box<dyn Fn(&mut RunRequest)>;
        let cases: Vec<(&str, Edit, &str)> = vec![
            ("no argv", Box::new(|r| r.argv = None), "argv is required"),
            (
                "empty argv",
                Box::new(|r| r.argv = Some(vec![])),
                "program name",
            ),
            (
                "both forms",
                Box::new(|r| r.shell = Some("x".into())),
                "not both",
            ),
            (
                "too many args",
                Box::new(|r| r.argv = Some(vec!["a".into(); MAX_ARGS + 1])),
                "more than",
            ),
            (
                "oversize argv",
                Box::new(|r| r.argv = Some(vec!["a".repeat(MAX_COMMAND_BYTES)])),
                "longer than",
            ),
            (
                "NUL in argv",
                Box::new(move |r| r.argv = Some(vec!["echo".into(), format!("{secret}\0")])),
                "argv[1] contains a NUL byte",
            ),
            (
                "NUL in shell",
                Box::new(move |r| {
                    r.argv = None;
                    r.shell = Some(format!("echo {secret}\0"));
                }),
                "NUL",
            ),
            (
                "no secrets",
                Box::new(|r| r.secrets.clear()),
                "at least one",
            ),
            (
                "unknown-format secret name",
                Box::new(|r| r.secrets = vec!["lower".into()]),
                "secrets[0]",
            ),
            (
                "duplicate secret",
                Box::new(|r| r.secrets = vec!["A".into(), "A".into()]),
                "listed twice",
            ),
            (
                "empty reason",
                Box::new(|r| r.reason.clear()),
                "reason must be",
            ),
            (
                "short reason",
                Box::new(|r| r.reason = "  test  ".into()),
                "reason must be",
            ),
            (
                "long reason",
                Box::new(|r| r.reason = "x".repeat(301)),
                "reason must be",
            ),
            (
                "escape codes in reason",
                Box::new(|r| r.reason = "approve me \x1b[2J\x1b[H all good".into()),
                "control characters",
            ),
            (
                "relative cwd",
                Box::new(|r| r.cwd = "projects/billing".into()),
                "absolute",
            ),
            ("empty cwd", Box::new(|r| r.cwd.clear()), "absolute"),
            (
                "zero timeout",
                Box::new(|r| r.timeout_secs = Some(0)),
                "timeout_secs",
            ),
            (
                "stdin with two secrets",
                Box::new(|r| {
                    r.secrets = vec!["A".into(), "B".into()];
                    r.injection = Some(Injection::Stdin);
                }),
                "exactly one secret",
            ),
        ];
        for (name, edit, want) in cases {
            let mut r = ok();
            edit(&mut r);
            let err = check(&r).expect_err(name).to_string();
            assert!(
                err.contains(want),
                "{name}: {err:?} should mention {want:?}"
            );
            assert!(!err.contains(secret), "{name}: error echoes input");
        }
    }

    #[test]
    fn reason_length_counts_characters_not_bytes() {
        assert!(check_reason(&"é".repeat(300)).is_ok());
        assert!(check_reason(&"é".repeat(301)).is_err());
    }
}
