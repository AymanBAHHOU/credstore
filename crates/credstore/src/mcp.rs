//! `credstore mcp`: the agent-facing MCP server on stdio (spec 6.1).
//!
//! Three tools, `list_secrets`, `run_with_secrets` and `http_request`, each a thin wrapper over the
//! daemon's agent endpoint. The shim holds no secrets and decrypts nothing; it can only
//! return what the daemon returns, which is names, descriptions and redacted output.
//! There is deliberately no tool that returns a secret value. stdout carries only MCP
//! traffic; logs go to stderr.

use credstore_proto::{AgentRequest, HttpHeader, HttpRequest, Injection, Response, RunRequest};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig};
use rmcp::{schemars, tool, tool_handler, tool_router, ErrorData, ServerHandler, ServiceExt};
use serde::Deserialize;
use serde_json::json;

use crate::client::Client;

/// Sent to the agent when it connects.
pub const INSTRUCTIONS: &str = "credstore runs commands with secrets the agent never sees. \
Call list_secrets to see which secrets exist (names and descriptions only). Call \
run_with_secrets with the exact command and the secret names it needs; a human approves \
each request in a terminal with their passphrase, so the call can block for up to a few \
minutes. Output comes back with secret values replaced by [REDACTED:NAME]. Do not try to \
print, encode or exfiltrate secret values: the human reads every command before approving. \
For an HTTPS API call that needs one secret in a header, prefer http_request: credstored \
sends the request itself, so no command ever holds the secret (the secret's policy must \
list the API's host in allow_hosts).";

/// Arguments of `http_request`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HttpRequestArgs {
    /// GET, HEAD, POST, PUT, PATCH or DELETE.
    pub method: String,
    /// Absolute https:// URL, query string included. Its host must be in the secret's
    /// allow_hosts. Redirects are not followed.
    #[schemars(length(min = 9, max = 8192))]
    pub url: String,
    /// Name of the secret (from list_secrets).
    pub secret: String,
    /// The header that carries the secret, with {value} where it goes, for example
    /// "Authorization: Bearer {value}" or "X-Api-Key: {value}".
    pub header_template: String,
    /// Shown to the human verbatim when they decide. Say what the request does.
    #[schemars(length(min = 10, max = 300))]
    pub reason: String,
    /// Other request headers as {"Name": "value"}.
    #[serde(default)]
    pub headers: Option<std::collections::BTreeMap<String, String>>,
    /// Request body as text (for example JSON). Not allowed with GET or HEAD.
    #[serde(default)]
    pub body: Option<String>,
    /// Limit in seconds. Policy sets the maximum; this can only lower it.
    #[serde(default)]
    #[schemars(range(min = 1, max = 86400))]
    pub timeout_secs: Option<u64>,
}

/// Arguments of `run_with_secrets`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunWithSecrets {
    /// The exact command as an argument array, for example ["pytest", "-q"]. Preferred
    /// over `shell`. The program is looked up on the daemon's PATH, never in cwd.
    #[serde(default)]
    #[schemars(length(min = 1, max = 256))]
    pub argv: Option<Vec<String>>,
    /// A shell command string. Accepted only when policy allows shell mode for every
    /// requested secret. Give exactly one of `argv` and `shell`.
    #[serde(default)]
    #[schemars(length(min = 1, max = 65536))]
    pub shell: Option<String>,
    /// Names of the secrets the command needs (from list_secrets).
    #[schemars(length(min = 1, max = 16))]
    pub secrets: Vec<String>,
    /// Shown to the human verbatim when they decide. Explain what the command does with
    /// each secret, for example "Run the billing tests; STRIPE_KEY authenticates to the
    /// Stripe test account".
    #[schemars(length(min = 10, max = 300))]
    pub reason: String,
    /// Absolute working directory. Defaults to the directory this MCP server runs in.
    #[serde(default)]
    pub cwd: Option<String>,
    /// Wall-clock limit in seconds. Policy sets the maximum; this can only lower it.
    #[serde(default)]
    #[schemars(range(min = 1, max = 86400))]
    pub timeout_secs: Option<u64>,
    /// How the secrets reach the command: "env" (default) sets NAME=value; "file"
    /// writes the value to a private file and sets NAME_FILE=path; "stdin" pipes the
    /// value to stdin (one secret only).
    #[serde(default)]
    pub injection: Option<InjectionArg>,
}

#[derive(Debug, Clone, Copy, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InjectionArg {
    Env,
    File,
    Stdin,
}

impl From<InjectionArg> for Injection {
    fn from(i: InjectionArg) -> Self {
        match i {
            InjectionArg::Env => Injection::Env,
            InjectionArg::File => Injection::File,
            InjectionArg::Stdin => Injection::Stdin,
        }
    }
}

/// The MCP server.
#[derive(Clone)]
pub struct McpServer {
    client: Client,
    tool_router: ToolRouter<Self>,
}

fn ok_json(v: serde_json::Value) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(v.to_string())])
}

fn err_json(v: serde_json::Value) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(v.to_string())])
}

/// What the agent gets for a daemon reply. Never contains a secret value: the daemon
/// sends names, descriptions and redacted output only.
pub fn tool_result(resp: Response) -> CallToolResult {
    match resp {
        Response::Secrets { secrets, .. } => ok_json(json!(secrets)),
        Response::RunResult(r) => ok_json(json!({
            "exit_code": r.exit_code,
            "stdout": r.stdout,
            "stderr": r.stderr,
            "truncated": r.truncated,
            "redactions": r.redactions,
        })),
        Response::HttpResult(r) => ok_json(json!({
            "status": r.status,
            "headers": r.headers.iter().map(|h| (h.name.clone(), h.value.clone())).collect::<Vec<_>>(),
            "body": r.body,
            "truncated": r.truncated,
            "redactions": r.redactions,
        })),
        Response::Denied { reason } => err_json(json!({ "denied": reason })),
        Response::Error { message, .. } => err_json(json!({ "error": message })),
        _ => err_json(json!({ "error": "unexpected reply from the credstore daemon" })),
    }
}

#[tool_router]
impl McpServer {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            tool_router: Self::tool_router(),
        }
    }

    async fn ask(&self, req: AgentRequest) -> CallToolResult {
        match self.client.agent(&req).await {
            Ok(resp) => tool_result(resp),
            Err(e) => err_json(json!({
                "error": format!("the credstore daemon is not reachable: {e:#}")
            })),
        }
    }

    #[tool(
        name = "list_secrets",
        description = "List the secrets credstore holds: names and descriptions, never \
                       values. Use the names with run_with_secrets."
    )]
    async fn list_secrets(&self) -> Result<CallToolResult, ErrorData> {
        Ok(self.ask(AgentRequest::ListSecrets).await)
    }

    #[tool(
        name = "run_with_secrets",
        description = "Run a command with secrets injected, without ever seeing them. A \
                       human approves each request with their passphrase, so this call \
                       blocks until they decide (or the approval times out). In `reason`, \
                       explain what the command does with each secret: the human reads it \
                       next to the exact command. Returns {exit_code, stdout, stderr, \
                       truncated, redactions} with every secret value replaced by \
                       [REDACTED:NAME], or {denied: why}."
    )]
    async fn run_with_secrets(
        &self,
        Parameters(args): Parameters<RunWithSecrets>,
    ) -> Result<CallToolResult, ErrorData> {
        let cwd = match args.cwd {
            Some(c) => c,
            None => match std::env::current_dir() {
                Ok(d) => d.to_string_lossy().into_owned(),
                Err(e) => {
                    return Ok(err_json(json!({
                        "error": format!("no cwd given and the current directory is unknown: {e}")
                    })))
                }
            },
        };
        let req = RunRequest {
            argv: args.argv,
            shell: args.shell,
            secrets: args.secrets,
            reason: args.reason,
            cwd,
            timeout_secs: args.timeout_secs,
            injection: args.injection.map(Into::into),
        };
        Ok(self.ask(AgentRequest::Run(req)).await)
    }

    #[tool(
        name = "http_request",
        description = "Send an HTTPS request with one secret in one header, without ever \
                       seeing it: credstored makes the request itself. A human approves \
                       each request with their passphrase, so this call blocks until they \
                       decide. The URL's host must be in the secret's allow_hosts policy. \
                       Returns {status, headers, body, truncated, redactions} with the \
                       secret replaced by [REDACTED:NAME] wherever it appears, or \
                       {denied: why}."
    )]
    async fn http_request(
        &self,
        Parameters(args): Parameters<HttpRequestArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let req = HttpRequest {
            method: args.method,
            url: args.url,
            secret: args.secret,
            header_template: args.header_template,
            reason: args.reason,
            headers: args
                .headers
                .unwrap_or_default()
                .into_iter()
                .map(|(name, value)| HttpHeader { name, value })
                .collect(),
            body: args.body,
            timeout_secs: args.timeout_secs,
        };
        Ok(self.ask(AgentRequest::Http(req)).await)
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for McpServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("credstore", env!("CARGO_PKG_VERSION")))
            .with_instructions(INSTRUCTIONS)
    }
}

/// Serve MCP on stdin/stdout until the client disconnects.
pub async fn serve(client: Client) -> anyhow::Result<()> {
    let running = McpServer::new(client)
        .serve(rmcp::transport::stdio())
        .await?;
    running.waiting().await?;
    Ok(())
}
