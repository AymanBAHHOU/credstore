//! Length-prefixed JSON framing: `u32` big-endian length, then a JSON [`Envelope`].
//!
//! Frame buffers are wrapped in `Zeroizing` because approver frames carry passphrases.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::{Envelope, PROTOCOL_VERSION};

/// Largest payload accepted or produced: 1 MiB.
pub const MAX_FRAME_LEN: u32 = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame of {len} bytes exceeds the {MAX_FRAME_LEN} byte limit")]
    TooLarge { len: u64 },
    #[error("connection closed")]
    Closed,
    #[error("connection closed mid-frame")]
    Truncated,
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u32),
    /// Malformed JSON or wrong shape. Holds only the error category and position, never
    /// serde_json's own message: that message can quote input, and input may be a secret.
    #[error("malformed frame: {kind} at line {line}, column {column}")]
    Malformed {
        kind: &'static str,
        line: usize,
        column: usize,
    },
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

impl FrameError {
    fn from_json(e: &serde_json::Error) -> Self {
        let kind = match e.classify() {
            serde_json::error::Category::Io => "i/o",
            serde_json::error::Category::Syntax => "syntax error",
            serde_json::error::Category::Data => "invalid message",
            serde_json::error::Category::Eof => "unexpected end of input",
        };
        FrameError::Malformed {
            kind,
            line: e.line(),
            column: e.column(),
        }
    }
}

/// Serialize `msg` into a complete frame (length prefix + envelope JSON).
pub fn encode<T: Serialize>(msg: &T) -> Result<Zeroizing<Vec<u8>>, FrameError> {
    let env = Envelope {
        v: PROTOCOL_VERSION,
        msg,
    };
    let mut buf = Zeroizing::new(vec![0u8; 4]);
    serde_json::to_writer(&mut *buf, &env).map_err(|e| FrameError::from_json(&e))?;
    let len = buf.len() - 4;
    if len as u64 > u64::from(MAX_FRAME_LEN) {
        return Err(FrameError::TooLarge { len: len as u64 });
    }
    buf[..4].copy_from_slice(&(len as u32).to_be_bytes());
    Ok(buf)
}

/// Parse a frame payload (without the length prefix), checking the version first.
pub fn decode<T: DeserializeOwned>(payload: &[u8]) -> Result<T, FrameError> {
    #[derive(Deserialize)]
    struct VersionProbe {
        v: u32,
    }
    let probe: VersionProbe =
        serde_json::from_slice(payload).map_err(|e| FrameError::from_json(&e))?;
    if probe.v != PROTOCOL_VERSION {
        return Err(FrameError::UnsupportedVersion(probe.v));
    }
    let env: Envelope<T> =
        serde_json::from_slice(payload).map_err(|e| FrameError::from_json(&e))?;
    Ok(env.msg)
}

/// Read one frame's payload. Rejects oversize frames before allocating or reading them.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Zeroizing<Vec<u8>>, FrameError> {
    let mut len_buf = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        let n = r.read(&mut len_buf[got..]).await?;
        if n == 0 {
            return Err(if got == 0 {
                FrameError::Closed
            } else {
                FrameError::Truncated
            });
        }
        got += n;
    }
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge {
            len: u64::from(len),
        });
    }
    let mut payload = Zeroizing::new(vec![0u8; len as usize]);
    r.read_exact(&mut payload).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            FrameError::Truncated
        } else {
            FrameError::Io(e)
        }
    })?;
    Ok(payload)
}

/// Read and decode one message.
pub async fn read_message<T, R>(r: &mut R) -> Result<T, FrameError>
where
    T: DeserializeOwned,
    R: AsyncRead + Unpin,
{
    let payload = read_frame(r).await?;
    decode(&payload)
}

/// Encode and write one message, then flush.
pub async fn write_message<T, W>(w: &mut W, msg: &T) -> Result<(), FrameError>
where
    T: Serialize,
    W: AsyncWrite + Unpin,
{
    let frame = encode(msg)?;
    w.write_all(&frame).await?;
    w.flush().await?;
    Ok(())
}
