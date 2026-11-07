//! Unix sockets with peer credentials (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` /
//! `getpeereid` on macOS, both through tokio's `peer_cred`).

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use credstore_proto::PeerInfo;
use nix::unistd::{Group, Uid, User};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{UnixListener, UnixStream};

use crate::{
    fs as osfs, Endpoint, EndpointAccess, IpcListener, IpcStream, Mode, OsError, OsResult,
    PeerIdentity, SERVICE_USER,
};

pub struct UnixIpcListener {
    listener: UnixListener,
    path: PathBuf,
    access: EndpointAccess,
}

pub struct UnixIpcStream {
    stream: UnixStream,
    peer: PeerInfo,
}

pub async fn bind(endpoint: &Endpoint, access: &EndpointAccess) -> OsResult<UnixIpcListener> {
    let path = PathBuf::from(&endpoint.address);
    if let Some(dir) = path.parent() {
        osfs::create_private_dir(dir)?;
        check_socket_dir(dir, access)?;
    }
    if path.exists() {
        if UnixStream::connect(&path).await.is_ok() {
            return Err(OsError::Io(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!(
                    "another credstored is already listening on {}",
                    path.display()
                ),
            )));
        }
        std::fs::remove_file(&path)?;
    }
    let listener = UnixListener::bind(&path)?;
    match access {
        EndpointAccess::SameUser => {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        EndpointAccess::Group { group, users } => {
            let group = lookup_group(group)?;
            nix::unistd::chown(&path, None, Some(group.gid)).map_err(errno)?;
            // With listed users the socket must be connectable without the group in the
            // peer's credentials (new members only get it at their next login), so it is
            // 0666 and `authorize` (SO_PEERCRED, before anything is read) is the check.
            let mode = if users.is_empty() { 0o660 } else { 0o666 };
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
        }
    }
    Ok(UnixIpcListener {
        listener,
        path,
        access: access.clone(),
    })
}

/// The socket directory must be ours and not writable by others, or someone could swap
/// the socket. In same-user mode it must not be readable by others either.
fn check_socket_dir(dir: &Path, access: &EndpointAccess) -> OsResult<()> {
    let meta = std::fs::symlink_metadata(dir)?;
    let mode = meta.mode() & 0o777;
    let open_bits = match access {
        EndpointAccess::SameUser => 0o077,
        EndpointAccess::Group { .. } => 0o002,
    };
    if !meta.is_dir() || meta.uid() != Uid::effective().as_raw() || mode & open_bits != 0 {
        return Err(OsError::Denied(format!(
            "refusing to use socket directory {}: it must be a directory owned by this user with mode 0700 (found owner uid {}, mode {:o})",
            dir.display(),
            meta.uid(),
            mode
        )));
    }
    Ok(())
}

impl Drop for UnixIpcListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl IpcListener for UnixIpcListener {
    type Stream = UnixIpcStream;

    async fn accept(&mut self) -> OsResult<UnixIpcStream> {
        let (stream, _) = self.listener.accept().await?;
        let peer = peer_of(&stream)?;
        authorize(&peer, &self.access)?;
        Ok(UnixIpcStream { stream, peer })
    }
}

/// Connect, then check the daemon really is who it should be (the socket's owner and the
/// peer UID), so a passphrase is never sent to an impostor.
pub async fn connect(endpoint: &Endpoint, mode: Mode) -> OsResult<UnixIpcStream> {
    let path = Path::new(&endpoint.address);
    let expected = expected_daemon_uid(mode)?;
    let owner = std::fs::metadata(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                OsError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!(
                        "credstored is not running (no socket at {})",
                        path.display()
                    ),
                ))
            } else {
                OsError::Io(e)
            }
        })?
        .uid();
    if owner != expected {
        return Err(OsError::Denied(format!(
            "socket {} is owned by uid {owner}, expected {expected}",
            path.display()
        )));
    }
    let stream = UnixStream::connect(path).await?;
    let peer = peer_of(&stream)?;
    if peer.uid != Some(expected) {
        return Err(OsError::Denied(format!(
            "daemon peer uid {:?} is not the expected uid {expected}",
            peer.uid
        )));
    }
    Ok(UnixIpcStream { stream, peer })
}

fn expected_daemon_uid(mode: Mode) -> OsResult<u32> {
    match mode {
        Mode::Dev => Ok(Uid::effective().as_raw()),
        Mode::Installed => User::from_name(SERVICE_USER)
            .map_err(errno)?
            .map(|u| u.uid.as_raw())
            .ok_or_else(|| OsError::unavailable(format!("no user {SERVICE_USER}"))),
    }
}

fn peer_of(stream: &UnixStream) -> OsResult<PeerInfo> {
    let cred = stream.peer_cred()?;
    let pid = cred.pid().and_then(|p| u32::try_from(p).ok());
    Ok(PeerInfo {
        uid: Some(cred.uid()),
        sid: None,
        pid,
        exe: pid.and_then(super::exe_of_pid),
    })
}

/// UID is the check. Dev: the daemon's own user. Installed: a member of the group in
/// the account database (not the peer's own group list, which only changes at login), or
/// a listed user.
fn authorize(peer: &PeerInfo, access: &EndpointAccess) -> OsResult<()> {
    let uid = peer
        .uid
        .ok_or_else(|| OsError::Denied("peer has no uid".into()))?;
    match access {
        EndpointAccess::SameUser => {
            let me = Uid::effective().as_raw();
            if uid == me {
                Ok(())
            } else {
                Err(OsError::Denied(format!(
                    "peer uid {uid} (pid {:?}) is not the daemon's user {me}",
                    peer.pid
                )))
            }
        }
        EndpointAccess::Group { group: name, users } => {
            let group = lookup_group(name)?;
            let user = User::from_uid(Uid::from_raw(uid))
                .map_err(errno)?
                .ok_or_else(|| OsError::Denied(format!("peer uid {uid} has no user entry")))?;
            if user.gid == group.gid
                || group.mem.iter().any(|m| m == &user.name)
                || users.iter().any(|u| u == &user.name)
            {
                Ok(())
            } else {
                Err(OsError::Denied(format!(
                    "peer {} (uid {uid}, pid {:?}) is not in group {name}",
                    user.name, peer.pid
                )))
            }
        }
    }
}

fn lookup_group(name: &str) -> OsResult<Group> {
    Group::from_name(name)
        .map_err(errno)?
        .ok_or_else(|| OsError::unavailable(format!("no group {name}")))
}

fn errno(e: nix::errno::Errno) -> OsError {
    OsError::Io(std::io::Error::from(e))
}

impl PeerIdentity for UnixIpcStream {
    fn peer_identity(&self) -> OsResult<PeerInfo> {
        Ok(self.peer.clone())
    }
}

impl IpcStream for UnixIpcStream {
    /// Already checked at accept time.
    fn authorize(&self) -> OsResult<PeerInfo> {
        Ok(self.peer.clone())
    }
}

impl AsyncRead for UnixIpcStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for UnixIpcStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
