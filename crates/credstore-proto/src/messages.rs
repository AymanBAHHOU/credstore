//! Request and response types for both endpoints.
//!
//! The agent endpoint accepts only [`AgentRequest`]. The approver endpoint accepts only
//! [`ApproverRequest`], and every one of those carries a passphrase [`Proof`]: a
//! connection alone grants nothing. Unknown fields and unknown message types are
//! rejected, so a request meant for one endpoint cannot be parsed by the other.

use serde::{Deserialize, Serialize};

use crate::SecretText;

/// Wire envelope: protocol version plus the message.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope<T> {
    pub v: u32,
    pub msg: T,
}

/// Opaque request id, e.g. `req_01J...`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestId(pub String);

// ---------------------------------------------------------------------------
// Agent endpoint
// ---------------------------------------------------------------------------

/// Requests allowed on the agent endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentRequest {
    ListSecrets,
    Run(RunRequest),
}

/// A request to run a command with secrets injected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunRequest {
    /// Preferred form: the exact argv.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argv: Option<Vec<String>>,
    /// Shell string. Accepted only when policy sets `allow_shell` for every secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    pub secrets: Vec<String>,
    /// Shown to the human verbatim. Never trusted for anything else.
    pub reason: String,
    /// Absolute working directory.
    pub cwd: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub injection: Option<Injection>,
}

/// How a secret reaches the child process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Injection {
    Env,
    File,
    Stdin,
}

// ---------------------------------------------------------------------------
// Approver endpoint
// ---------------------------------------------------------------------------

/// Proof that the sender knows the vault passphrase. Checked on every approver request;
/// the daemon verifies it by decrypting the vault and never stores it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub passphrase: SecretText,
}

/// A request on the approver endpoint. The proof is mandatory by construction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproverRequest {
    pub proof: Proof,
    pub op: ApproverOp,
}

/// Operations allowed on the approver endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApproverOp {
    SubscribePending,
    Approve {
        request_id: RequestId,
        scope: GrantScope,
    },
    Deny {
        request_id: RequestId,
    },
    /// Create the vault; the proof's passphrase becomes the vault passphrase. Refused
    /// if a vault already exists.
    AdminInit,
    Unlock,
    Lock,
    Status,
    Reload,
    AdminSet {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        value: SecretText,
    },
    AdminRm {
        name: String,
    },
    /// Human-initiated `credstore run`: approved in place by the proof on this request.
    AdminRun(RunRequest),
}

/// What the human approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GrantScope {
    /// This request only.
    Once,
    /// Matching requests until the TTL ends (capped by policy `grant_ttl_secs`).
    Session { ttl_secs: u64 },
}

// ---------------------------------------------------------------------------
// Responses (both endpoints)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Secrets { secrets: Vec<SecretInfo> },
    RunResult(RunResult),
    Denied { reason: String },
    Pending { requests: Vec<PendingRequest> },
    Status(StatusInfo),
    Ok,
    Error { code: ErrorCode, message: String },
}

/// Name and description of a secret. Never the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretInfo {
    pub name: String,
    pub description: String,
}

/// Result of an approved run. All text is already redacted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunResult {
    /// `None` when the process was killed by a signal or by the timeout.
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub redactions: u64,
}

/// Everything the human needs to decide on a request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingRequest {
    pub id: RequestId,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argv: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    /// Full path of the program that will run (argv form).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    pub cwd: String,
    pub secrets: Vec<SecretInfo>,
    pub injection: Injection,
    pub sandbox: SandboxMode,
    pub network: NetworkPolicy,
    /// Hosts allowed when `network` is `allow-list`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_hosts: Vec<String>,
    /// Longest "approve for this session" policy allows; 0 = once only.
    pub max_grant_secs: u64,
    pub peer: PeerInfo,
}

/// Identity of the process on the other end of a connection.
/// UID (Unix) or SID (Windows) is the access check; PID and exe are informational.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
}

/// Sandbox actually applied to a run. Recorded in the audit log and shown to the human.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxMode {
    Bwrap,
    Landlock,
    Seatbelt,
    JobObject,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkPolicy {
    Inherit,
    Deny,
    AllowList,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusInfo {
    pub locked: bool,
    pub dev_mode: bool,
    pub pending: u32,
    /// Why the policy could not be loaded. While set, every run request is denied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    Unauthorized,
    RateLimited,
    Unsupported,
    Internal,
}
