//! Endpoint listeners and per-connection framing.

use std::sync::Arc;
use std::time::Duration;

use credstore_os::{Ipc, IpcListener, IpcStream, OsError};
use credstore_proto::{
    decode, read_frame, write_message, AgentRequest, ApproverOp, ApproverRequest, ErrorCode,
    FrameError, PeerInfo, Response,
};
use tokio::io::AsyncReadExt;
use tokio::sync::watch;

use crate::state::{error, State};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Endpoint {
    Agent,
    Approver,
}

/// Accept connections until shutdown.
pub(crate) async fn accept_loop<L>(
    state: Arc<State>,
    mut listener: L,
    which: Endpoint,
    mut shutdown: watch::Receiver<bool>,
) where
    L: IpcListener,
    L::Stream: 'static,
{
    loop {
        let accepted = tokio::select! {
            _ = shutdown.changed() => return,
            a = listener.accept() => a,
        };
        match accepted {
            Ok(stream) => {
                let state = state.clone();
                let shutdown = shutdown.clone();
                tokio::spawn(async move { serve(state, stream, which, shutdown).await });
            }
            Err(OsError::Denied(reason)) => {
                tracing::warn!(endpoint = ?which, %reason, "connection refused");
            }
            Err(e) => {
                tracing::warn!(endpoint = ?which, %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

/// One connection: read frames, authorize the peer after the first frame, answer.
async fn serve<S: IpcStream>(
    state: Arc<State>,
    mut stream: S,
    which: Endpoint,
    shutdown: watch::Receiver<bool>,
) {
    let mut peer: Option<PeerInfo> = None;
    loop {
        let payload = match read_frame(&mut stream).await {
            Ok(p) => p,
            Err(FrameError::Closed) => return,
            Err(e) => {
                let _ =
                    write_message(&mut stream, &error(ErrorCode::BadRequest, e.to_string())).await;
                return;
            }
        };
        let who = match &peer {
            Some(p) => p.clone(),
            None => match stream.authorize() {
                Ok(p) => {
                    tracing::info!(endpoint = ?which, uid = ?p.uid, sid = ?p.sid, pid = ?p.pid,
                        exe = ?p.exe, "connection");
                    peer = Some(p.clone());
                    p
                }
                Err(e) => {
                    tracing::warn!(endpoint = ?which, %e, "connection refused");
                    let _ = write_message(
                        &mut stream,
                        &error(ErrorCode::Unauthorized, "not allowed on this endpoint"),
                    )
                    .await;
                    return;
                }
            },
        };
        let response = match which {
            Endpoint::Agent => match decode::<AgentRequest>(&payload) {
                Ok(req) => state.agent(req, &who, closed(&mut stream)).await,
                Err(e) => error(ErrorCode::BadRequest, e.to_string()),
            },
            Endpoint::Approver => match decode::<ApproverRequest>(&payload) {
                Ok(req) if matches!(req.op, ApproverOp::SubscribePending) => {
                    drop(payload);
                    match state.verify(&req.proof, &who).await {
                        Ok(()) => subscription(&state, &mut stream, shutdown).await,
                        Err(resp) => {
                            let _ = write_message(&mut stream, &resp).await;
                        }
                    }
                    return;
                }
                Ok(req) => state.approver(req, &who).await,
                // Includes requests without a proof, which cannot parse.
                Err(e) => error(ErrorCode::Unauthorized, format!("rejected: {e}")),
            },
        };
        drop(payload);
        if write_message(&mut stream, &response).await.is_err() {
            return;
        }
    }
}

/// Resolves when the client closes the connection (or sends anything, which it must not
/// do while waiting for a reply).
async fn closed<S: IpcStream>(stream: &mut S) {
    let mut b = [0u8; 1];
    let _ = stream.read(&mut b).await;
}

/// Send the pending list now and after every change, until the client closes the
/// connection (or sends anything) or the daemon shuts down.
async fn subscription<S: IpcStream>(
    state: &State,
    stream: &mut S,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut changes = state.subscribe();
    loop {
        changes.mark_unchanged();
        let list = Response::Pending {
            requests: state.pending_list(),
        };
        if write_message(stream, &list).await.is_err() {
            return;
        }
        let mut b = [0u8; 1];
        tokio::select! {
            _ = stream.read(&mut b) => return,
            _ = shutdown.changed() => return,
            r = changes.changed() => if r.is_err() { return },
        }
    }
}

/// Bind both endpoints with the mode's access rules.
pub(crate) async fn bind_all(
    state: &State,
) -> Result<
    (
        <credstore_os::Platform as Ipc>::Listener,
        <credstore_os::Platform as Ipc>::Listener,
    ),
    OsError,
> {
    use credstore_os::{EndpointAccess, EndpointKind, Mode, Paths, AGENTS_GROUP, APPROVERS_GROUP};
    let (agent_access, approver_access) = match state.mode() {
        Mode::Dev => (EndpointAccess::SameUser, EndpointAccess::SameUser),
        Mode::Installed => (
            EndpointAccess::Group(AGENTS_GROUP.into()),
            EndpointAccess::Group(APPROVERS_GROUP.into()),
        ),
    };
    let p = &state.platform;
    let agent = p
        .bind(&p.endpoint(EndpointKind::Agent), &agent_access)
        .await?;
    let approver = p
        .bind(&p.endpoint(EndpointKind::Approver), &approver_access)
        .await?;
    Ok((agent, approver))
}
