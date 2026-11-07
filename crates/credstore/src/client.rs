//! Client for the daemon's endpoints. One connection per request.

use anyhow::{anyhow, bail, Context};
use credstore_os::{EndpointKind, Ipc, Paths, Platform};
use credstore_proto::{
    read_message, write_message, AgentRequest, ApproverOp, ApproverRequest, Proof, Response,
    SecretText,
};
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct Client {
    platform: Platform,
}

impl Client {
    pub fn new(platform: Platform) -> Self {
        Self { platform }
    }

    pub fn platform(&self) -> &Platform {
        &self.platform
    }

    pub async fn agent(&self, req: &AgentRequest) -> anyhow::Result<Response> {
        self.call(EndpointKind::Agent, req).await
    }

    /// Send an approver operation with a passphrase proof.
    pub async fn approver(
        &self,
        op: ApproverOp,
        passphrase: SecretText,
    ) -> anyhow::Result<Response> {
        let req = ApproverRequest {
            proof: Proof::Passphrase(passphrase),
            op,
        };
        self.call(EndpointKind::Approver, &req).await
    }

    /// Send an approver operation with any proof (an approval-key signature).
    pub async fn approver_with(&self, op: ApproverOp, proof: Proof) -> anyhow::Result<Response> {
        self.call(EndpointKind::Approver, &ApproverRequest { proof, op })
            .await
    }

    /// Open a connection to an endpoint (for streaming requests).
    pub async fn connect(&self, kind: EndpointKind) -> anyhow::Result<<Platform as Ipc>::Stream> {
        let ep = self.platform.endpoint(kind);
        self.platform
            .connect(&ep)
            .await
            .with_context(|| format!("connecting to credstored at {}", ep.address))
    }

    async fn call<T: Serialize>(&self, kind: EndpointKind, msg: &T) -> anyhow::Result<Response> {
        let mut stream = self.connect(kind).await?;
        write_message(&mut stream, msg)
            .await
            .context("sending the request")?;
        read_message(&mut stream)
            .await
            .context("reading the daemon's answer")
    }
}

/// Turn anything but `Ok` into an error.
pub fn expect_ok(resp: Response) -> anyhow::Result<()> {
    match resp {
        Response::Ok => Ok(()),
        other => Err(response_error(other)),
    }
}

/// Error for an unexpected or failure response.
pub fn response_error(resp: Response) -> anyhow::Error {
    match resp {
        Response::Error { message, .. } => anyhow!("{message}"),
        Response::Denied { reason } => anyhow!("denied: {reason}"),
        other => anyhow!("unexpected answer from credstored: {}", kind_of(&other)),
    }
}

fn kind_of(r: &Response) -> &'static str {
    match r {
        Response::Secrets { .. } => "secrets",
        Response::RunResult(_) => "run_result",
        Response::HttpResult(_) => "http_result",
        Response::Denied { .. } => "denied",
        Response::Pending { .. } => "pending",
        Response::Status(_) => "status",
        Response::Ok => "ok",
        Response::Error { .. } => "error",
    }
}

/// Bail unless `resp` is a status.
pub fn expect_status(resp: Response) -> anyhow::Result<credstore_proto::StatusInfo> {
    match resp {
        Response::Status(s) => Ok(*s),
        other => bail!(response_error(other)),
    }
}
