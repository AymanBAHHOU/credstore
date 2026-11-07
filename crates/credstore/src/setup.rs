//! `credstore setup`: the per-user half of an install (M8).
//!
//! The package installs the service as the system. This runs as the human, after it:
//! it creates the vault if there is none, registers credstore with Claude Code for every
//! folder, and adds Claude Code deny rules for credstore's files and `.env` files. It asks
//! before each change (or takes `--yes`), and never touches a secret value.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use credstore_proto::{AgentRequest, Response};
use serde_json::Value;

use crate::client::Client;
use crate::commands::{self, Prompt};

/// What `setup` may do.
pub struct Options {
    /// Make every change without asking.
    pub yes: bool,
    /// Register `credstore --dev mcp` instead of `credstore mcp`.
    pub dev: bool,
}

/// Where Claude Code lives for this user. `None` from [`ClaudeCode::detect`] when there
/// is no home directory.
pub struct ClaudeCode {
    /// The user's home: `~/.claude.json` and `~/.claude/settings.json` live here.
    pub home: PathBuf,
    /// The `claude` executable, if it is on `PATH`.
    pub exe: Option<PathBuf>,
    /// The credstore binary to register (normally this one).
    pub credstore: PathBuf,
}

impl ClaudeCode {
    pub fn detect() -> Option<Self> {
        let home = credstore_os::run::user_home()?;
        let cwd = std::env::current_dir().unwrap_or_else(|_| home.clone());
        let exe =
            credstore_os::exec::resolve_program("claude", &cwd, &credstore_os::exec::search_path())
                .ok();
        let credstore = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("credstore"));
        Some(Self {
            home,
            exe,
            credstore,
        })
    }

    fn settings(&self) -> PathBuf {
        self.home.join(".claude").join("settings.json")
    }
}

pub async fn setup(
    client: &Client,
    p: &dyn Prompt,
    opts: &Options,
    claude: Option<&ClaudeCode>,
    msg: &mut dyn Write,
) -> Result<()> {
    // 1. The daemon must answer, or nothing else can work.
    let secrets = match client.agent(&AgentRequest::ListSecrets).await {
        Ok(Response::Secrets { secrets }) => secrets,
        Ok(other) => return Err(crate::client::response_error(other)),
        Err(e) => bail!(
            "cannot reach credstored: {e:#}\n\
             If you just installed credstore, sign out and back in (the credstore groups \
             apply at logon), then run `credstore setup` again. `credstore doctor` shows \
             what is wrong."
        ),
    };
    writeln!(msg, "ok    credstored answers")?;

    // 2. The vault. An empty list may still be a vault with no secrets; the daemon says.
    if secrets.is_empty() {
        if confirm(p, opts.yes, "Create the vault now?")? {
            if commands::create_vault(client, p).await? {
                writeln!(msg, "done  created the vault (there is no way to recover it without the passphrase)")?;
            } else {
                writeln!(msg, "ok    a vault already exists")?;
            }
        } else {
            writeln!(msg, "skip  vault: run `credstore init` later")?;
        }
    } else {
        writeln!(msg, "ok    the vault exists ({} secret(s))", secrets.len())?;
    }

    // 3. Claude Code.
    match claude {
        None => writeln!(msg, "skip  Claude Code")?,
        Some(c) => claude_code(c, p, opts, msg)?,
    }

    writeln!(msg)?;
    writeln!(msg, "Next:")?;
    writeln!(
        msg,
        "  credstore set NAME     add a secret (the value is prompted for)"
    )?;
    if !opts.dev {
        writeln!(
            msg,
            "  credstore grant DIR    let approved commands run in a project folder"
        )?;
    }
    writeln!(
        msg,
        "  credstore watch        keep open to approve agents' requests"
    )?;
    writeln!(msg, "  credstore doctor       check everything")?;
    Ok(())
}

/// Where Claude Code stands for this user (shown by the desktop app).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ClaudeState {
    /// `claude` is on PATH.
    pub found: bool,
    /// credstore is registered at user scope.
    pub registered: bool,
    /// Deny rules that are not in `~/.claude/settings.json` yet.
    pub missing_rules: Vec<String>,
    pub settings_file: String,
}

impl ClaudeCode {
    pub fn state(&self) -> Result<ClaudeState> {
        let settings = read_json(&self.settings())?;
        Ok(ClaudeState {
            found: self.exe.is_some(),
            registered: user_scope_registered(&self.home),
            missing_rules: deny_rules()
                .into_iter()
                .filter(|r| !has_deny_rule(&settings, r))
                .collect(),
            settings_file: self.settings().display().to_string(),
        })
    }

    /// `claude mcp add --scope user credstore -- <credstore> [--dev] mcp`.
    pub fn register(&self, dev: bool) -> Result<()> {
        let exe = self.exe.as_ref().context("`claude` is not on PATH")?;
        let mut cmd = Command::new(exe);
        cmd.args(["mcp", "add", "--scope", "user", "credstore", "--"])
            .arg(&self.credstore);
        if dev {
            cmd.arg("--dev");
        }
        cmd.arg("mcp");
        let out = cmd
            .output()
            .with_context(|| format!("running {}", exe.display()))?;
        if !out.status.success() {
            bail!(
                "claude mcp add failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    /// Add the missing deny rules to `~/.claude/settings.json`, keeping the old file as
    /// a backup. Returns the rules added.
    pub fn add_deny_rules(&self) -> Result<Vec<String>> {
        let path = self.settings();
        let mut settings = read_json(&path)?;
        let added = add_deny_rules(&mut settings, &deny_rules())?;
        if !added.is_empty() {
            write_json(&path, &settings)?;
        }
        Ok(added)
    }
}

fn claude_code(c: &ClaudeCode, p: &dyn Prompt, opts: &Options, msg: &mut dyn Write) -> Result<()> {
    let state = c.state()?;
    // Registration, at user scope so every folder sees it.
    if state.registered {
        writeln!(
            msg,
            "ok    Claude Code: credstore is registered for all folders"
        )?;
    } else if state.found {
        if confirm(
            p,
            opts.yes,
            "Register credstore with Claude Code for all folders (claude mcp add --scope user)?",
        )? {
            c.register(opts.dev)?;
            writeln!(
                msg,
                "done  Claude Code: registered credstore for all folders"
            )?;
        } else {
            writeln!(msg, "skip  Claude Code registration")?;
        }
    } else {
        writeln!(
            msg,
            "skip  Claude Code: `claude` is not on PATH. Later: claude mcp add --scope user credstore -- credstore mcp"
        )?;
    }

    // Deny rules in ~/.claude/settings.json.
    if state.missing_rules.is_empty() {
        writeln!(msg, "ok    Claude Code: deny rules are in place")?;
        return Ok(());
    }
    writeln!(msg, "      These Claude Code deny rules stop the agent reading .env files and credstore's files:")?;
    for r in &state.missing_rules {
        writeln!(msg, "        {r}")?;
    }
    if !confirm(
        p,
        opts.yes,
        &format!("Add them to {}?", state.settings_file),
    )? {
        writeln!(msg, "skip  Claude Code deny rules")?;
        return Ok(());
    }
    let added = c.add_deny_rules()?;
    writeln!(
        msg,
        "done  Claude Code: added {} deny rule(s) to {} (the old file is kept as {})",
        added.len(),
        state.settings_file,
        backup_path(&c.settings()).display()
    )?;
    Ok(())
}

fn confirm(p: &dyn Prompt, yes: bool, question: &str) -> Result<bool> {
    if yes {
        return Ok(true);
    }
    if !p.has_terminal() {
        bail!("`credstore setup` asks before each change and needs a terminal; or pass --yes");
    }
    let answer = p.line(&format!("{question} [Y/n] "))?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "" | "y" | "yes"
    ))
}

/// Whether `~/.claude.json` registers a `credstore` MCP server at user scope.
pub fn user_scope_registered(home: &Path) -> bool {
    std::fs::read_to_string(home.join(".claude.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .is_some_and(|j| j["mcpServers"]["credstore"].is_object())
}

/// The deny rules for this OS, in Claude Code's syntax (`//` = absolute, `~/` = home).
pub fn deny_rules() -> Vec<String> {
    let mut rules = vec![
        "Read(**/.env*)".to_owned(),
        "Read(~/.credstore/**)".to_owned(),
    ];
    if cfg!(windows) {
        let data = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
        rules.push(format!("Read({}/credstore/**)", claude_abs(&data)));
    } else if cfg!(target_os = "macos") {
        rules.push("Read(//var/db/credstore/**)".into());
        rules.push("Read(//etc/credstore/**)".into());
    } else {
        rules.push("Read(//var/lib/credstore/**)".into());
        rules.push("Read(//etc/credstore/**)".into());
    }
    rules
}

/// `C:\ProgramData` -> `//c/ProgramData` (Claude Code's absolute-path form).
fn claude_abs(windows_path: &str) -> String {
    let p = windows_path.replace('\\', "/");
    match p.split_once(':') {
        Some((drive, rest)) if drive.len() == 1 => {
            format!("//{}{}", drive.to_ascii_lowercase(), rest)
        }
        _ => p,
    }
}

fn has_deny_rule(settings: &Value, rule: &str) -> bool {
    settings["permissions"]["deny"]
        .as_array()
        .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(rule)))
}

/// Add the rules that are missing to `permissions.deny`. Returns the ones added.
pub fn add_deny_rules(settings: &mut Value, rules: &[String]) -> Result<Vec<String>> {
    if settings.is_null() {
        *settings = Value::Object(Default::default());
    }
    let obj = settings
        .as_object_mut()
        .context("Claude Code settings: the top level is not an object")?;
    let perms = obj
        .entry("permissions")
        .or_insert_with(|| Value::Object(Default::default()))
        .as_object_mut()
        .context("Claude Code settings: `permissions` is not an object")?;
    let deny = perms
        .entry("deny")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .context("Claude Code settings: `permissions.deny` is not a list")?;
    let mut added = Vec::new();
    for r in rules {
        if !deny.iter().any(|v| v.as_str() == Some(r)) {
            deny.push(Value::String(r.clone()));
            added.push(r.clone());
        }
    }
    Ok(added)
}

fn read_json(path: &Path) -> Result<Value> {
    match std::fs::read_to_string(path) {
        Ok(t) if t.trim().is_empty() => Ok(Value::Null),
        Ok(t) => serde_json::from_str(&t).with_context(|| {
            format!(
                "{} is not valid JSON; fix it or skip this step",
                path.display()
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Value::Null),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

fn backup_path(path: &Path) -> PathBuf {
    path.with_extension("json.before-credstore")
}

/// Write `value` to `path` through a temporary file, keeping the old file as a backup.
fn write_json(path: &Path, value: &Value) -> Result<()> {
    let dir = path.parent().context("settings path has no parent")?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    if path.exists() {
        std::fs::copy(path, backup_path(path))
            .with_context(|| format!("backing up {}", path.display()))?;
    }
    let tmp = path.with_extension("json.credstore-tmp");
    let mut text = serde_json::to_string_pretty(value)?;
    text.push('\n');
    std::fs::write(&tmp, text).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn deny_rules_are_added_once_and_others_kept() {
        let mut s = json!({"model": "x", "permissions": {"deny": ["Read(//secret)"], "allow": ["Bash(ls)"]}});
        let rules = vec!["Read(**/.env*)".to_owned(), "Read(//secret)".to_owned()];
        let added = add_deny_rules(&mut s, &rules).unwrap();
        assert_eq!(added, ["Read(**/.env*)"]);
        assert_eq!(s["model"], "x");
        assert_eq!(s["permissions"]["allow"], json!(["Bash(ls)"]));
        assert_eq!(
            s["permissions"]["deny"],
            json!(["Read(//secret)", "Read(**/.env*)"])
        );
        assert!(add_deny_rules(&mut s, &rules).unwrap().is_empty());
    }

    #[test]
    fn deny_rules_start_from_nothing() {
        let mut s = Value::Null;
        add_deny_rules(&mut s, &["Read(a)".to_owned()]).unwrap();
        assert_eq!(s, json!({"permissions": {"deny": ["Read(a)"]}}));
    }

    #[test]
    fn odd_settings_are_refused_not_overwritten() {
        let mut s = json!({"permissions": {"deny": "Read(a)"}});
        assert!(add_deny_rules(&mut s, &["Read(b)".to_owned()]).is_err());
        let mut s = json!([1, 2]);
        assert!(add_deny_rules(&mut s, &["Read(b)".to_owned()]).is_err());
    }

    #[test]
    fn windows_paths_become_claude_absolute_paths() {
        assert_eq!(claude_abs(r"C:\ProgramData"), "//c/ProgramData");
        assert_eq!(claude_abs(r"D:\x\y"), "//d/x/y");
    }

    #[test]
    fn user_scope_registration_is_read_from_claude_json() {
        let home = std::env::temp_dir().join(format!("cs-setup-{}", std::process::id()));
        std::fs::create_dir_all(&home).unwrap();
        assert!(!user_scope_registered(&home));
        std::fs::write(
            home.join(".claude.json"),
            r#"{"projects":{"/x":{"mcpServers":{"credstore":{}}}}}"#,
        )
        .unwrap();
        assert!(
            !user_scope_registered(&home),
            "project scope is not user scope"
        );
        std::fs::write(
            home.join(".claude.json"),
            r#"{"mcpServers":{"credstore":{"type":"stdio","command":"credstore"}}}"#,
        )
        .unwrap();
        assert!(user_scope_registered(&home));
        let _ = std::fs::remove_dir_all(&home);
    }
}
