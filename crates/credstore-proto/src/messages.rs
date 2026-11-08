//! Request and response types for both endpoints.
//!
//! The agent endpoint accepts only [`AgentRequest`]. The approver endpoint accepts only
//! [`ApproverRequest`], and every one of those carries a [`Proof`] (the passphrase, or a
//! signature by an enrolled approval key): a connection alone grants nothing. Unknown fields and unknown message types are
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
    /// The daemon makes an HTTPS request with one secret in a header (spec 6.6).
    Http(HttpRequest),
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

/// How a secret reaches the child process, or (`Header`) the HTTP request the daemon
/// makes for an [`HttpRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Injection {
    Env,
    File,
    Stdin,
    Header,
}

/// An HTTPS request the daemon makes itself, adding one secret to one header (spec 6.6).
/// The secret never enters a process the agent controls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRequest {
    /// `GET`, `POST`, `PUT`, `PATCH`, `DELETE` or `HEAD`.
    pub method: String,
    /// Absolute `https://` URL. Its host must be in the secret's `allow_hosts`.
    pub url: String,
    pub secret: String,
    /// One header line with `{value}` where the secret goes, e.g.
    /// `Authorization: Bearer {value}`.
    pub header_template: String,
    /// Shown to the human verbatim. Never trusted for anything else.
    pub reason: String,
    /// Extra request headers (not the secret's header, not hop-by-hop ones).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<HttpHeader>,
    /// Request body, as text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

// ---------------------------------------------------------------------------
// Approver endpoint
// ---------------------------------------------------------------------------

/// Proof that the sender is the human. Checked on every approver request.
///
/// - `passphrase`: the daemon verifies it by decrypting the vault and never stores it.
///   Every operation accepts it.
/// - `key` (M13): a signature by an approval key enrolled in the vault (Windows Hello),
///   over [`signed_message`]. Accepted only for [`ApproverOp::key_allowed`] operations
///   while the vault is unlocked.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Proof {
    Passphrase(SecretText),
    Key(KeyProof),
    /// Names a policy change the daemon prepared after a passphrase
    /// ([`Response::PolicyEditPending`]). Accepted only for [`ApproverOp::TakePolicyEdit`]
    /// and [`ApproverOp::FinishPolicyEdit`], by the admin helper that writes the file.
    /// Not a secret: it only lets its holder apply the change the human made.
    PolicyEdit(String),
}

/// A signature by an approval key. Hex throughout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyProof {
    /// [`approval_key_id`] of the key.
    pub key_id: String,
    /// Unix seconds when it was signed; the daemon accepts a minute either way.
    pub time: u64,
    /// 16 random bytes; the daemon refuses a nonce it has seen.
    pub nonce: String,
    pub signature: String,
}

/// What an approval key signs: a fixed label, the key, time, nonce and the operation.
/// The operation is the same JSON the request carries, so a signature for one operation
/// cannot be reused for another.
pub fn signed_message(key_id: &str, time: u64, nonce: &str, op: &ApproverOp) -> Vec<u8> {
    let mut m = format!("credstore approval v1\n{key_id}\n{time}\n{nonce}\n").into_bytes();
    // Serializing these types cannot fail (no maps with non-string keys).
    m.extend(serde_json::to_vec(op).unwrap_or_default());
    m
}

/// The id of an approval key: the first 16 bytes of the SHA-256 of its public key, hex.
/// Computed by the daemon; the client computes the same to name its key.
pub fn approval_key_id(sha256_of_public_key: &[u8]) -> String {
    hex(&sha256_of_public_key[..16.min(sha256_of_public_key.len())])
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Inverse of [`hex`]; `None` for odd length or a non-hex character.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// An approval key enrolled in the vault, as `status` lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalKeyInfo {
    pub id: String,
    pub label: String,
    pub created: String,
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
    /// Enrol an approval key (M13): a DER SubjectPublicKeyInfo of an RSA key that signs
    /// with PKCS#1 v1.5 and SHA-256 (what Windows Hello makes), hex. Passphrase only.
    AddApprovalKey {
        label: String,
        public_key: String,
    },
    /// Remove an enrolled approval key. Passphrase only.
    RemoveApprovalKey {
        id: String,
    },
    /// The desktop app's live view: a [`Feed`] now and after every change, until the
    /// client hangs up. Streamed like `SubscribePending`.
    SubscribeFeed,
    /// Change one secret's rules in the policy file, then reload it. `None` leaves a
    /// rule as it is; an empty list removes it (the secret then follows `[defaults]`).
    /// Hosts set `network = "allow-list"`. Passphrase only.
    SetSecretRules {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allow_hosts: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allow_commands: Option<Vec<String>>,
    },
    /// Change `[defaults]` timers in the policy file, then reload it. `None` leaves a
    /// setting as it is. Passphrase only.
    SetDefaults {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_idle_secs: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grant_ttl_secs: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        approval_timeout_secs: Option<u64>,
    },
    /// Where only administrators may write the policy file (Windows installs): get the
    /// prepared change ([`Response::PolicyEdit`]) to write it. Proof:
    /// [`Proof::PolicyEdit`].
    TakePolicyEdit,
    /// The admin helper wrote the prepared change: check the file, reload, audit.
    /// Proof: [`Proof::PolicyEdit`].
    FinishPolicyEdit,
}

impl ApproverOp {
    /// Operations an approval key may authorize: watching, deciding, status and lock.
    /// Unlocking, changing secrets, keys or policy, and `credstore run` need the
    /// passphrase.
    pub fn key_allowed(&self) -> bool {
        matches!(
            self,
            Self::SubscribePending
                | Self::SubscribeFeed
                | Self::Approve { .. }
                | Self::Deny { .. }
                | Self::Status
                | Self::Lock
        )
    }
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
    Secrets {
        secrets: Vec<SecretInfo>,
    },
    RunResult(RunResult),
    HttpResult(HttpResult),
    Denied {
        reason: String,
    },
    Pending {
        requests: Vec<PendingRequest>,
    },
    Status(Box<StatusInfo>),
    Feed(Box<Feed>),
    /// A policy change was checked but only an administrator may write the file: run
    /// `credstore policy-apply ID` elevated within [`POLICY_EDIT_TTL_SECS`].
    PolicyEditPending {
        id: String,
    },
    /// The prepared change for the admin helper: the whole new file, and the SHA-256 (hex)
    /// of the file it was made from ("" if there was none), so a change made meanwhile is
    /// not overwritten.
    PolicyEdit {
        text: String,
        base_sha256: String,
    },
    Ok,
    Error {
        code: ErrorCode,
        message: String,
    },
}

/// How long a prepared policy change waits for the admin helper.
pub const POLICY_EDIT_TTL_SECS: u64 = 300;

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

/// Response to an approved [`HttpRequest`]. Headers and body are already redacted.
/// Redirects are not followed: a 3xx comes back as is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpResult {
    pub status: u16,
    pub headers: Vec<HttpHeader>,
    /// Body as text (invalid UTF-8 replaced), cut at the policy's `max_output_bytes`.
    pub body: String,
    pub truncated: bool,
    pub redactions: u64,
}

/// The HTTP request a pending approval would make.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingHttp {
    pub method: String,
    pub url: String,
    /// The header line with `{value}` still in place of the secret.
    pub header_template: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<HttpHeader>,
    /// Size of the request body in bytes, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_bytes: Option<u64>,
    /// The start of the body, for the human to read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_preview: Option<String>,
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
    /// What policy asked for that this run will not get (shown to the human).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sandbox_gaps: Vec<String>,
    pub network: NetworkPolicy,
    /// Hosts allowed when `network` is `allow-list`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_hosts: Vec<String>,
    /// Longest "approve for this session" policy allows; 0 = once only.
    pub max_grant_secs: u64,
    pub peer: PeerInfo,
    /// Set for an HTTP request (then there is no argv, shell or program, and `cwd` is
    /// empty).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<PendingHttp>,
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
    /// Windows AppContainer (M12), inside a Job Object. One word, as Windows spells it.
    #[serde(rename = "appcontainer")]
    AppContainer,
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
    /// Daemon process id (for `doctor`'s memory check).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Sandbox the daemon found: mode and a human-readable summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<String>,
    /// Memory hardening the daemon applied at startup.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hardening: Vec<HardeningReport>,
    /// Approval keys enrolled in the vault (M13).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approval_keys: Vec<ApprovalKeyInfo>,
}

/// What the desktop app shows, streamed by `SubscribeFeed`. Never holds a secret value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Feed {
    pub pending: Vec<PendingRequest>,
    /// Most recent first.
    pub activity: Vec<ActivityEntry>,
    /// `None` while the policy cannot be loaded (`policy_error` says why).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_error: Option<String>,
    pub locked: bool,
    /// Ids of the approval keys the vault trusts (`AddApprovalKey`). `None` while the
    /// vault is locked, because the list is inside it. The app compares its own Hello key
    /// with this list, so a key left from an older vault does not show as "on".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_keys: Option<Vec<String>>,
}

/// The policy as the app shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyInfo {
    /// Where the policy file is.
    pub path: String,
    /// Whether the app can change the file (`SetSecretRules`, `SetDefaults`). On Linux
    /// and macOS installs it belongs to root and is edited by hand.
    pub editable: bool,
    /// Changes need an administrator (Windows installs): Windows asks before writing.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub needs_admin: bool,
    pub strict: bool,
    pub session_idle_secs: u64,
    pub grant_ttl_secs: u64,
    pub approval_timeout_secs: u64,
    /// Every secret in the vault, and every `[secret.NAME]` block, by name.
    pub secrets: Vec<SecretRules>,
}

/// One secret's rules with `[defaults]` applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRules {
    pub name: String,
    /// The policy has a `[secret.NAME]` block for it.
    pub configured: bool,
    pub network: NetworkPolicy,
    /// Hosts it may be sent to (with `network = "allow-list"`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_hosts: Vec<String>,
    /// Command patterns; `None` allows any command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_commands: Option<Vec<String>>,
    /// Folder patterns; `None` allows any folder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_dirs: Option<Vec<String>>,
    pub require_approval: bool,
    pub grant_ttl_secs: u64,
}

/// One line of the app's activity history, built from the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivityEntry {
    /// Request id, or empty for vault and policy changes.
    pub id: String,
    /// When it started (RFC 3339).
    pub ts: String,
    pub kind: ActivityKind,
    pub outcome: ActivityOutcome,
    /// The command line, `METHOD URL`, or what changed.
    pub summary: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<String>,
    /// Why it was refused or denied, or how it ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// The host of an HTTP request (`host` or `host:port`), for an "allow this host" fix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Who or what approved it: `human`, `grant`, `policy` or `admin`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityKind {
    Run,
    Http,
    Vault,
    Policy,
    /// A wrong passphrase or a rejected key proof.
    Auth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityOutcome {
    /// Waiting for the human.
    Waiting,
    /// Approved, not finished yet.
    Running,
    /// Refused by policy before the human was asked.
    Refused,
    /// Denied by the human, or timed out.
    Denied,
    Ok,
    Failed,
    /// A vault or policy change.
    Changed,
}

/// One memory hardening feature and whether it is active in the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardeningReport {
    pub name: String,
    pub active: bool,
    /// Why it is not (fully) active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
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
