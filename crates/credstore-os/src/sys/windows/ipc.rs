//! Named pipes with an SDDL ACL, client SID from impersonation, and owner verification
//! on the client side.

use std::os::windows::io::AsRawHandle;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use credstore_proto::PeerInfo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer};
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, HANDLE};

use super::win;
use crate::{
    Endpoint, EndpointAccess, IpcListener, IpcStream, Mode, OsError, OsResult, PeerIdentity,
    SERVICE_USER,
};

/// Rights for clients: read/write data and attributes, sync. Deliberately *not*
/// FILE_CREATE_PIPE_INSTANCE (0x4, part of GENERIC_WRITE), so a client cannot create a
/// rogue server instance of the pipe.
const CLIENT_RIGHTS: &str = "0x120183";

pub struct PipeListener {
    name: String,
    sddl: String,
    next: Option<NamedPipeServer>,
    access: EndpointAccess,
    own_sid: String,
    group_sid: Option<String>,
}

enum Conn {
    Server(NamedPipeServer),
    Client(NamedPipeClient),
}

pub struct PipeStream {
    conn: Conn,
    access: EndpointAccess,
    own_sid: String,
    group_sid: Option<String>,
    /// Client side only: who the server is.
    server_peer: Option<PeerInfo>,
}

pub async fn bind(endpoint: &Endpoint, access: &EndpointAccess) -> OsResult<PipeListener> {
    let own_sid = win::current_user_sid()?;
    let (sddl, group_sid) = match access {
        // Owner is set explicitly so clients can verify it.
        EndpointAccess::SameUser => (format!("O:{own_sid}D:P(A;;GA;;;{own_sid})"), None),
        EndpointAccess::Group(g) => {
            let gsid = win::lookup_account_sid(g)
                .map_err(|e| OsError::unavailable(format!("group {g}: {e}")))?;
            (
                format!("O:{own_sid}D:P(A;;GA;;;{own_sid})(A;;{CLIENT_RIGHTS};;;{gsid})"),
                Some(gsid),
            )
        }
    };
    // first_pipe_instance: fail if anyone (an impostor, or another daemon) already owns
    // this pipe name.
    let first = win::create_pipe_server(&endpoint.address, &sddl, true).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            OsError::Io(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!(
                    "pipe {} already exists (another credstored, or an impostor)",
                    endpoint.address
                ),
            ))
        } else {
            OsError::Io(e)
        }
    })?;
    Ok(PipeListener {
        name: endpoint.address.clone(),
        sddl,
        next: Some(first),
        access: access.clone(),
        own_sid,
        group_sid,
    })
}

impl IpcListener for PipeListener {
    type Stream = PipeStream;

    async fn accept(&mut self) -> OsResult<PipeStream> {
        let server = match self.next.take() {
            Some(s) => s,
            None => win::create_pipe_server(&self.name, &self.sddl, false)?,
        };
        let connected = server.connect().await;
        // Always have the next instance ready before handing this one out.
        self.next = Some(win::create_pipe_server(&self.name, &self.sddl, false)?);
        connected?;
        Ok(PipeStream {
            conn: Conn::Server(server),
            access: self.access.clone(),
            own_sid: self.own_sid.clone(),
            group_sid: self.group_sid.clone(),
            server_peer: None,
        })
    }
}

/// Connect, then verify the pipe's owner is the daemon's account, so a passphrase is
/// never sent to an impostor that created the pipe first.
pub async fn connect(endpoint: &Endpoint, mode: Mode) -> OsResult<PipeStream> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let client = loop {
        match ClientOptions::new().open(&endpoint.address) {
            Ok(c) => break c,
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                if Instant::now() > deadline {
                    return Err(e.into());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) => {
                return Err(OsError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("credstored is not running (no pipe {})", endpoint.address),
                )));
            }
            Err(e) => return Err(e.into()),
        }
    };
    let owner = win::handle_owner_sid(client.as_raw_handle() as HANDLE)?;
    let expected = match mode {
        Mode::Dev => win::current_user_sid()?,
        Mode::Installed => win::lookup_account_sid(SERVICE_USER)
            .map_err(|e| OsError::unavailable(format!("{SERVICE_USER}: {e}")))?,
    };
    if owner != expected {
        return Err(OsError::Denied(format!(
            "pipe {} is owned by {owner}, expected {expected}",
            endpoint.address
        )));
    }
    Ok(PipeStream {
        conn: Conn::Client(client),
        access: EndpointAccess::SameUser,
        own_sid: String::new(),
        group_sid: None,
        server_peer: Some(PeerInfo {
            sid: Some(owner),
            ..PeerInfo::default()
        }),
    })
}

impl PipeStream {
    fn client_peer(&self, server: &NamedPipeServer) -> OsResult<(PeerInfo, bool)> {
        let h = server.as_raw_handle() as HANDLE;
        let (sid, member) = win::pipe_client_identity(h, self.group_sid.as_deref())?;
        let pid = win::pipe_client_pid(h).ok();
        let peer = PeerInfo {
            uid: None,
            sid: Some(sid),
            pid,
            exe: pid.and_then(win::exe_of_pid),
        };
        Ok((peer, member))
    }
}

impl PeerIdentity for PipeStream {
    fn peer_identity(&self) -> OsResult<PeerInfo> {
        match &self.conn {
            Conn::Server(s) => Ok(self.client_peer(s)?.0),
            Conn::Client(_) => Ok(self.server_peer.clone().unwrap_or_default()),
        }
    }
}

impl IpcStream for PipeStream {
    /// SID is the check. Dev: the daemon's own user. Installed: a member of the group.
    /// Call after reading the first frame (see `pipe_client_identity`).
    fn authorize(&self) -> OsResult<PeerInfo> {
        let Conn::Server(s) = &self.conn else {
            return self.peer_identity();
        };
        let (peer, member) = self.client_peer(s)?;
        let sid = peer.sid.clone().unwrap_or_default();
        let ok = match &self.access {
            EndpointAccess::SameUser => sid == self.own_sid,
            EndpointAccess::Group(_) => member,
        };
        if ok {
            Ok(peer)
        } else {
            Err(OsError::Denied(format!(
                "peer {sid} (pid {:?}) is not allowed on this endpoint",
                peer.pid
            )))
        }
    }
}

impl AsyncRead for PipeStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut self.conn {
            Conn::Server(s) => Pin::new(s).poll_read(cx, buf),
            Conn::Client(c) => Pin::new(c).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for PipeStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut self.conn {
            Conn::Server(s) => Pin::new(s).poll_write(cx, buf),
            Conn::Client(c) => Pin::new(c).poll_write(cx, buf),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.conn {
            Conn::Server(s) => Pin::new(s).poll_flush(cx),
            Conn::Client(c) => Pin::new(c).poll_flush(cx),
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.conn {
            Conn::Server(s) => Pin::new(s).poll_shutdown(cx),
            Conn::Client(c) => Pin::new(c).poll_shutdown(cx),
        }
    }
}
