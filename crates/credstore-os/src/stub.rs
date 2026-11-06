//! Placeholder IPC types for features not built yet. They can never be constructed, so
//! any code path that would use one has already returned `Unavailable`.

use std::pin::Pin;
use std::task::{Context, Poll};

use credstore_proto::PeerInfo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{IpcListener, IpcStream, OsResult, PeerIdentity};

/// Uninhabited stream.
#[derive(Debug)]
pub enum StubStream {}

/// Uninhabited listener.
#[derive(Debug)]
pub enum StubListener {}

impl AsyncRead for StubStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match *self {}
    }
}

impl AsyncWrite for StubStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match *self {}
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match *self {}
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match *self {}
    }
}

impl PeerIdentity for StubStream {
    fn peer_identity(&self) -> OsResult<PeerInfo> {
        match *self {}
    }
}

impl IpcStream for StubStream {}

impl IpcListener for StubListener {
    type Stream = StubStream;
    async fn accept(&mut self) -> OsResult<StubStream> {
        match *self {}
    }
}
