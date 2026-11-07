//! Policy file (spec 5.2): parsing, validation and evaluation.
//!
//! A request is checked here *before* the human is asked. Anything that does not pass is
//! denied with a reason that goes back to the agent and into the audit log.

use std::collections::BTreeMap;
use std::path::Path;

use credstore_proto::{Injection, NetworkPolicy};
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use serde::Deserialize;

use crate::names;

/// Starter policy written for a new dev-mode vault and by the installers.
pub const STARTER_POLICY: &str = include_str!("../../../deploy/policy.toml");

/// Upper bounds on numeric settings.
const MAX_RUNTIME_CAP: u64 = 24 * 3600;
const MAX_OUTPUT_CAP: u64 = 16 * 1024 * 1024;
const MAX_TTL_CAP: u64 = 24 * 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SandboxRequirement {
    Require,
    #[default]
    Prefer,
    Off,
}

impl SandboxRequirement {
    fn strictness(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::Prefer => 1,
            Self::Require => 2,
        }
    }
}

fn network_strictness(n: NetworkPolicy) -> u8 {
    match n {
        NetworkPolicy::Inherit => 0,
        NetworkPolicy::AllowList => 1,
        NetworkPolicy::Deny => 2,
    }
}

// ---------------------------------------------------------------------------
// File format
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    #[serde(default)]
    defaults: DefaultsFile,
    #[serde(default)]
    secret: BTreeMap<String, SecretFile>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DefaultsFile {
    require_approval: Option<bool>,
    max_runtime_secs: Option<u64>,
    max_output_bytes: Option<u64>,
    sandbox: Option<SandboxRequirement>,
    network: Option<NetworkPolicy>,
    allow_hosts: Option<Vec<String>>,
    strict: Option<bool>,
    grant_ttl_secs: Option<u64>,
    session_idle_secs: Option<u64>,
    approval_timeout_secs: Option<u64>,
    allow_shell: Option<bool>,
    injection: Option<Vec<Injection>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretFile {
    allow_commands: Option<Vec<String>>,
    allow_dirs: Option<Vec<String>>,
    network: Option<NetworkPolicy>,
    allow_hosts: Option<Vec<String>>,
    grant_ttl_secs: Option<u64>,
    injection: Option<Vec<Injection>>,
    allow_shell: Option<bool>,
    require_approval: Option<bool>,
    sandbox: Option<SandboxRequirement>,
    max_runtime_secs: Option<u64>,
    max_output_bytes: Option<u64>,
}

// ---------------------------------------------------------------------------
// Validated policy
// ---------------------------------------------------------------------------

/// How paths and commands are normalized before matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchStyle {
    /// Exact, case-sensitive.
    Unix,
    /// Forward slashes, case-folded, `.exe`/`.cmd`/`.bat`/`.com` dropped from the program.
    Windows,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Defaults {
    pub require_approval: bool,
    pub max_runtime_secs: u64,
    pub max_output_bytes: u64,
    pub sandbox: SandboxRequirement,
    pub network: NetworkPolicy,
    pub allow_hosts: Vec<String>,
    pub strict: bool,
    pub grant_ttl_secs: u64,
    pub session_idle_secs: u64,
    pub approval_timeout_secs: u64,
    pub allow_shell: bool,
    pub injection: Vec<Injection>,
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            require_approval: true,
            max_runtime_secs: 120,
            max_output_bytes: 20_000,
            sandbox: SandboxRequirement::Prefer,
            network: NetworkPolicy::Inherit,
            allow_hosts: vec![],
            strict: false,
            grant_ttl_secs: 600,
            session_idle_secs: 600,
            approval_timeout_secs: 120,
            allow_shell: false,
            injection: vec![Injection::Env, Injection::File, Injection::Stdin],
        }
    }
}

#[derive(Debug, Clone)]
struct Patterns {
    raw: Vec<String>,
    set: GlobSet,
}

/// Rules for one secret, with defaults already applied.
#[derive(Debug, Clone)]
struct SecretRules {
    commands: Option<Patterns>,
    dirs: Option<Patterns>,
    network: NetworkPolicy,
    allow_hosts: Vec<String>,
    grant_ttl_secs: u64,
    injection: Vec<Injection>,
    allow_shell: bool,
    require_approval: bool,
    sandbox: SandboxRequirement,
    max_runtime_secs: u64,
    max_output_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub defaults: Defaults,
    secrets: BTreeMap<String, SecretRules>,
    style: MatchStyle,
}

/// Maps a directory to its canonical form, if it exists.
pub type DirResolver<'a> = &'a dyn Fn(&str) -> Option<String>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("policy error: {0}")]
pub struct PolicyError(pub String);

/// Why a request was refused before reaching the human.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Denial(pub String);

fn bad(msg: impl Into<String>) -> PolicyError {
    PolicyError(msg.into())
}

impl Policy {
    /// Parse and validate a policy file.
    pub fn parse(text: &str, style: MatchStyle) -> Result<Self, PolicyError> {
        Self::parse_with(text, style, &|_| None)
    }

    /// Like [`Policy::parse`], with `resolve` mapping a directory to its canonical form
    /// (the daemon passes `fs::canonicalize`). Each `allow_dirs` pattern then also matches
    /// with its literal leading directory canonicalized, because the request's cwd is
    /// canonical: `/var/x/**` also allows `/private/var/x` on macOS, and a Windows
    /// 8.3 short name also allows the long name.
    pub fn parse_with(
        text: &str,
        style: MatchStyle,
        resolve: DirResolver<'_>,
    ) -> Result<Self, PolicyError> {
        let file: PolicyFile = toml::from_str(text).map_err(|e| bad(e.to_string()))?;
        let d = file.defaults;
        let base = Defaults::default();
        let defaults = Defaults {
            require_approval: d.require_approval.unwrap_or(base.require_approval),
            max_runtime_secs: d.max_runtime_secs.unwrap_or(base.max_runtime_secs),
            max_output_bytes: d.max_output_bytes.unwrap_or(base.max_output_bytes),
            sandbox: d.sandbox.unwrap_or(base.sandbox),
            network: d.network.unwrap_or(base.network),
            allow_hosts: d.allow_hosts.unwrap_or_default(),
            strict: d.strict.unwrap_or(false),
            grant_ttl_secs: d.grant_ttl_secs.unwrap_or(base.grant_ttl_secs),
            session_idle_secs: d.session_idle_secs.unwrap_or(base.session_idle_secs),
            approval_timeout_secs: d
                .approval_timeout_secs
                .unwrap_or(base.approval_timeout_secs),
            allow_shell: d.allow_shell.unwrap_or(false),
            injection: d.injection.unwrap_or(base.injection),
        };
        check_limits(
            "[defaults]",
            defaults.max_runtime_secs,
            defaults.max_output_bytes,
        )?;
        check_ttl("[defaults] grant_ttl_secs", defaults.grant_ttl_secs)?;
        check_ttl("[defaults] session_idle_secs", defaults.session_idle_secs)?;
        if !(1..=3600).contains(&defaults.approval_timeout_secs) {
            return Err(bad(
                "[defaults] approval_timeout_secs must be between 1 and 3600",
            ));
        }
        check_network("[defaults]", defaults.network, &defaults.allow_hosts)?;
        if defaults.injection.is_empty() {
            return Err(bad("[defaults] injection must list at least one mode"));
        }
        check_injection("[defaults]", &defaults.injection)?;

        let mut secrets = BTreeMap::new();
        for (name, s) in file.secret {
            let where_ = format!("[secret.{name}]");
            names::validate_name(&name).map_err(|e| bad(format!("{where_}: {e}")))?;
            let network = s.network.unwrap_or(defaults.network);
            let allow_hosts = s
                .allow_hosts
                .unwrap_or_else(|| defaults.allow_hosts.clone());
            check_network(&where_, network, &allow_hosts)?;
            let rules = SecretRules {
                commands: s
                    .allow_commands
                    .map(|p| compile(&where_, "allow_commands", p, style, None))
                    .transpose()?,
                dirs: s
                    .allow_dirs
                    .map(|p| compile(&where_, "allow_dirs", p, style, Some(resolve)))
                    .transpose()?,
                network,
                allow_hosts,
                grant_ttl_secs: s.grant_ttl_secs.unwrap_or(defaults.grant_ttl_secs),
                injection: s.injection.unwrap_or_else(|| defaults.injection.clone()),
                allow_shell: s.allow_shell.unwrap_or(defaults.allow_shell),
                require_approval: s.require_approval.unwrap_or(defaults.require_approval),
                sandbox: s.sandbox.unwrap_or(defaults.sandbox),
                max_runtime_secs: s.max_runtime_secs.unwrap_or(defaults.max_runtime_secs),
                max_output_bytes: s.max_output_bytes.unwrap_or(defaults.max_output_bytes),
            };
            check_limits(&where_, rules.max_runtime_secs, rules.max_output_bytes)?;
            check_ttl(&format!("{where_} grant_ttl_secs"), rules.grant_ttl_secs)?;
            if rules.injection.is_empty() {
                return Err(bad(format!(
                    "{where_} injection must list at least one mode"
                )));
            }
            check_injection(&where_, &rules.injection)?;
            secrets.insert(name, rules);
        }
        Ok(Self {
            defaults,
            secrets,
            style,
        })
    }

    pub fn style(&self) -> MatchStyle {
        self.style
    }
}

fn check_limits(where_: &str, runtime: u64, output: u64) -> Result<(), PolicyError> {
    if !(1..=MAX_RUNTIME_CAP).contains(&runtime) {
        return Err(bad(format!(
            "{where_} max_runtime_secs must be between 1 and {MAX_RUNTIME_CAP}"
        )));
    }
    if !(1..=MAX_OUTPUT_CAP).contains(&output) {
        return Err(bad(format!(
            "{where_} max_output_bytes must be between 1 and {MAX_OUTPUT_CAP}"
        )));
    }
    Ok(())
}

/// `injection` lists how commands get secrets; HTTP requests are allowed by `allow_hosts`.
fn check_injection(where_: &str, modes: &[Injection]) -> Result<(), PolicyError> {
    if modes.contains(&Injection::Header) {
        return Err(bad(format!(
            "{where_} injection: \"header\" is not a command injection mode; http_request \
             is allowed by network = \"allow-list\" and allow_hosts"
        )));
    }
    Ok(())
}

fn check_ttl(what: &str, ttl: u64) -> Result<(), PolicyError> {
    if ttl > MAX_TTL_CAP {
        return Err(bad(format!("{what} must be at most {MAX_TTL_CAP}")));
    }
    Ok(())
}

fn check_network(where_: &str, n: NetworkPolicy, hosts: &[String]) -> Result<(), PolicyError> {
    match n {
        NetworkPolicy::AllowList if hosts.is_empty() => Err(bad(format!(
            "{where_} network = \"allow-list\" needs a non-empty allow_hosts"
        ))),
        NetworkPolicy::AllowList => {
            for h in hosts {
                if h.is_empty()
                    || !h
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '*' | ':'))
                {
                    return Err(bad(format!(
                        "{where_} allow_hosts entry {h:?} is not a host name"
                    )));
                }
            }
            Ok(())
        }
        _ if !hosts.is_empty() => Err(bad(format!(
            "{where_} allow_hosts only applies with network = \"allow-list\""
        ))),
        _ => Ok(()),
    }
}

fn compile(
    where_: &str,
    key: &str,
    patterns: Vec<String>,
    style: MatchStyle,
    dirs: Option<DirResolver<'_>>,
) -> Result<Patterns, PolicyError> {
    let path_like = dirs.is_some();
    if patterns.is_empty() {
        return Err(bad(format!(
            "{where_} {key} is empty, which would allow nothing; remove it to allow anything"
        )));
    }
    let norm = |p: &str| match style {
        MatchStyle::Unix => p.to_owned(),
        MatchStyle::Windows => p.trim_start_matches(r"\\?\").replace('\\', "/"),
    };
    let mut all: Vec<String> = patterns.iter().map(|p| norm(p)).collect();
    if let Some(resolve) = dirs {
        for p in all.clone() {
            let lit = p.find(['*', '?', '[', '{']).unwrap_or(p.len());
            let dir = match p[..lit].rfind('/') {
                Some(i) if lit < p.len() => &p[..i.max(1)],
                _ => &p[..lit],
            };
            if let Some(canon) = resolve(dir).map(|c| norm(&c)) {
                if canon != dir && !canon.is_empty() {
                    all.push(format!("{}{}", globset::escape(&canon), &p[dir.len()..]));
                }
            }
        }
    }
    let mut b = GlobSetBuilder::new();
    for (i, norm) in all.iter().enumerate() {
        let p = patterns.get(i).unwrap_or(norm);
        let g = GlobBuilder::new(norm)
            .case_insensitive(style == MatchStyle::Windows)
            // In directories `*` stays inside one component and `**` crosses them; in
            // commands `*` matches anything (URLs have slashes).
            .literal_separator(path_like)
            .backslash_escape(style == MatchStyle::Unix)
            .build()
            .map_err(|e| bad(format!("{where_} {key}: bad pattern {p:?}: {e}")))?;
        b.add(g);
    }
    let set = b.build().map_err(|e| bad(format!("{where_} {key}: {e}")))?;
    Ok(Patterns { raw: patterns, set })
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

/// The command, as the daemon will run it.
#[derive(Debug, Clone, Copy)]
pub enum Command<'a> {
    /// `argv[0]` as requested, plus the full path it resolved to.
    Argv {
        argv: &'a [String],
        resolved: &'a Path,
    },
    /// A shell string (`sh -c` / `cmd /c`).
    Shell(&'a str),
}

/// Everything policy needs about a validated request.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    pub secrets: &'a [String],
    pub command: Command<'a>,
    /// Canonical working directory.
    pub cwd: &'a Path,
    pub injection: Injection,
    pub timeout_secs: Option<u64>,
}

/// Settings for an allowed request: the most restrictive across its secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effective {
    pub require_approval: bool,
    pub timeout_secs: u64,
    pub max_output_bytes: u64,
    pub sandbox: SandboxRequirement,
    pub network: NetworkPolicy,
    /// Hosts allowed by every secret (only with `allow-list`).
    pub allow_hosts: Vec<String>,
    /// Longest session grant the human may choose.
    pub grant_ttl_cap_secs: u64,
    pub approval_timeout_secs: u64,
    /// Whether the command runs a shell (argv form included).
    pub shell: bool,
}

/// Programs that interpret a command string.
const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "mksh",
    "fish",
    "csh",
    "tcsh",
    "ash",
    "busybox",
    "cmd",
    "powershell",
    "pwsh",
];
/// Programs that run another program given as an argument.
const WRAPPERS: &[&str] = &[
    "env", "nohup", "nice", "timeout", "xargs", "sudo", "doas", "stdbuf", "time", "command",
    "exec", "setsid", "script", "chroot", "unshare", "start", "runas", "wsl", "flock", "ionice",
    "taskset", "watch", "strace", "ltrace",
];

impl Policy {
    /// Allow (with effective settings) or deny, without asking anyone.
    pub fn evaluate(&self, req: &Request<'_>) -> Result<Effective, Denial> {
        if req.secrets.is_empty() {
            return Err(Denial("no secrets requested".into()));
        }
        let shell = match req.command {
            Command::Shell(_) => true,
            Command::Argv { argv, .. } => self.argv_is_shell(argv),
        };
        let candidates = self.command_candidates(&req.command);
        let cwd = self.norm_path(&req.cwd.to_string_lossy());

        let mut eff = Effective {
            require_approval: false,
            timeout_secs: u64::MAX,
            max_output_bytes: u64::MAX,
            sandbox: SandboxRequirement::Off,
            network: NetworkPolicy::Inherit,
            allow_hosts: vec![],
            grant_ttl_cap_secs: u64::MAX,
            approval_timeout_secs: self.defaults.approval_timeout_secs,
            shell,
        };
        let mut hosts: Option<Vec<String>> = None;

        for name in req.secrets {
            let fallback;
            let rules = match self.secrets.get(name) {
                Some(r) => r,
                None if self.defaults.strict => {
                    return Err(Denial(format!(
                        "{name} has no [secret.{name}] block and the policy is strict"
                    )));
                }
                None => {
                    fallback = self.default_rules();
                    &fallback
                }
            };

            if shell && !rules.allow_shell {
                return Err(Denial(format!(
                    "shell commands are not allowed with {name} (set allow_shell = true in \
                     [secret.{name}] to allow them)"
                )));
            }
            if let Some(p) = &rules.commands {
                if !candidates.iter().any(|c| p.set.is_match(c)) {
                    return Err(Denial(format!(
                        "command not allowed for {name} (allowed: {})",
                        p.raw.join(", ")
                    )));
                }
            }
            if let Some(p) = &rules.dirs {
                let inside = format!("{}/", cwd.trim_end_matches('/'));
                if !(p.set.is_match(&cwd) || p.set.is_match(&inside)) {
                    return Err(Denial(format!(
                        "working directory not allowed for {name} (allowed: {})",
                        p.raw.join(", ")
                    )));
                }
            }
            if !rules.injection.contains(&req.injection) {
                return Err(Denial(format!(
                    "injection mode {} not allowed for {name}",
                    injection_name(req.injection)
                )));
            }

            eff.require_approval |= rules.require_approval;
            eff.timeout_secs = eff.timeout_secs.min(rules.max_runtime_secs);
            eff.max_output_bytes = eff.max_output_bytes.min(rules.max_output_bytes);
            eff.grant_ttl_cap_secs = eff.grant_ttl_cap_secs.min(rules.grant_ttl_secs);
            if rules.sandbox.strictness() > eff.sandbox.strictness() {
                eff.sandbox = rules.sandbox;
            }
            if network_strictness(rules.network) > network_strictness(eff.network) {
                eff.network = rules.network;
            }
            if rules.network == NetworkPolicy::AllowList {
                hosts = Some(match hosts {
                    None => rules.allow_hosts.clone(),
                    Some(h) => h
                        .into_iter()
                        .filter(|x| rules.allow_hosts.contains(x))
                        .collect(),
                });
            }
        }

        if eff.network == NetworkPolicy::AllowList {
            eff.allow_hosts = hosts.unwrap_or_default();
            if eff.allow_hosts.is_empty() {
                return Err(Denial(
                    "the requested secrets' allow_hosts lists have no host in common".into(),
                ));
            }
        }
        if let Some(t) = req.timeout_secs {
            eff.timeout_secs = eff.timeout_secs.min(t.max(1));
        }
        Ok(eff)
    }

    /// Allow (with effective settings) or deny an HTTP request (spec 6.6). The secret
    /// must have `network = "allow-list"`, and the URL's host must be in its
    /// `allow_hosts`. `allow_commands`, `allow_dirs`, `injection`, `allow_shell` and
    /// `sandbox` are about commands and do not apply.
    pub fn evaluate_http(
        &self,
        secret: &str,
        host: &str,
        port: u16,
        timeout_secs: Option<u64>,
    ) -> Result<Effective, Denial> {
        let fallback;
        let rules = match self.secrets.get(secret) {
            Some(r) => r,
            None if self.defaults.strict => {
                return Err(Denial(format!(
                    "{secret} has no [secret.{secret}] block and the policy is strict"
                )));
            }
            None => {
                fallback = self.default_rules();
                &fallback
            }
        };
        if rules.network != NetworkPolicy::AllowList {
            return Err(Denial(format!(
                "http_request needs the hosts {secret} may be sent to: set \
                 network = \"allow-list\" and allow_hosts in [secret.{secret}]"
            )));
        }
        if !crate::http::host_allowed(&rules.allow_hosts, host, port) {
            return Err(Denial(format!(
                "{secret} may not be sent to {host}:{port} (allowed: {})",
                rules.allow_hosts.join(", ")
            )));
        }
        Ok(Effective {
            require_approval: rules.require_approval,
            timeout_secs: timeout_secs.map_or(rules.max_runtime_secs, |t| {
                t.clamp(1, rules.max_runtime_secs)
            }),
            max_output_bytes: rules.max_output_bytes,
            sandbox: SandboxRequirement::Off,
            network: NetworkPolicy::AllowList,
            allow_hosts: rules.allow_hosts.clone(),
            grant_ttl_cap_secs: rules.grant_ttl_secs,
            approval_timeout_secs: self.defaults.approval_timeout_secs,
            shell: false,
        })
    }

    fn default_rules(&self) -> SecretRules {
        let d = &self.defaults;
        SecretRules {
            commands: None,
            dirs: None,
            network: d.network,
            allow_hosts: d.allow_hosts.clone(),
            grant_ttl_secs: d.grant_ttl_secs,
            injection: d.injection.clone(),
            allow_shell: d.allow_shell,
            require_approval: d.require_approval,
            sandbox: d.sandbox,
            max_runtime_secs: d.max_runtime_secs,
            max_output_bytes: d.max_output_bytes,
        }
    }

    fn norm_path(&self, p: &str) -> String {
        match self.style {
            MatchStyle::Unix => p.to_owned(),
            MatchStyle::Windows => p
                .trim_start_matches(r"\\?\")
                .replace('\\', "/")
                .to_lowercase(),
        }
    }

    /// Program name used for shell/wrapper detection: basename, normalized.
    fn program_name(&self, p: &str) -> String {
        let p = self.norm_path(p);
        let base = p.rsplit(['/', '\\']).next().unwrap_or(&p).to_owned();
        match self.style {
            MatchStyle::Unix => base,
            MatchStyle::Windows => strip_ext(&base).to_owned(),
        }
    }

    fn argv_is_shell(&self, argv: &[String]) -> bool {
        let Some(first) = argv.first() else {
            return false;
        };
        let prog = self.program_name(first);
        if SHELLS.contains(&prog.as_str()) {
            return true;
        }
        // `env sh -c ...`, `xargs bash`, `timeout 5 sh -c ...`
        WRAPPERS.contains(&prog.as_str())
            && argv[1..]
                .iter()
                .any(|a| SHELLS.contains(&self.program_name(a).as_str()))
    }

    /// The strings `allow_commands` is matched against: the command line with the program
    /// as its resolved full path, and, when `argv[0]` was a bare name looked up on PATH,
    /// as that name. So `stripe *` matches `stripe login` found on PATH but not
    /// `./stripe login`, which needs a pattern naming its path.
    fn command_candidates(&self, cmd: &Command<'_>) -> Vec<String> {
        match cmd {
            Command::Shell(s) => vec![self.norm_cmd(s)],
            Command::Argv { argv, resolved } => {
                let rest = argv[1..].join(" ");
                let bare = !argv[0].contains(['/', '\\']);
                let mut progs = vec![resolved.to_string_lossy().into_owned()];
                if bare {
                    progs.push(argv[0].clone());
                }
                if self.style == MatchStyle::Windows {
                    progs = progs
                        .into_iter()
                        .map(|p| strip_ext(&self.norm_path(&p)).to_owned())
                        .collect();
                }
                progs.dedup();
                progs
                    .into_iter()
                    .map(|p| {
                        let line = if rest.is_empty() {
                            p
                        } else {
                            format!("{p} {rest}")
                        };
                        self.norm_cmd(&line)
                    })
                    .collect()
            }
        }
    }

    fn norm_cmd(&self, s: &str) -> String {
        match self.style {
            MatchStyle::Unix => s.to_owned(),
            MatchStyle::Windows => s.replace('\\', "/").to_lowercase(),
        }
    }
}

pub fn injection_name(i: Injection) -> &'static str {
    match i {
        Injection::Env => "env",
        Injection::File => "file",
        Injection::Stdin => "stdin",
        Injection::Header => "header",
    }
}

fn strip_ext(p: &str) -> &str {
    for ext in [".exe", ".cmd", ".bat", ".com"] {
        if p.len() > ext.len() && p.to_ascii_lowercase().ends_with(ext) {
            return &p[..p.len() - ext.len()];
        }
    }
    p
}

#[cfg(test)]
mod tests;
