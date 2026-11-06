//! credstore wire protocol.
//!
//! Every message is a frame: a big-endian `u32` length followed by that many bytes of
//! JSON. The JSON is an [`Envelope`] carrying the protocol version (`"v": 1`) and the
//! message. Frames over [`MAX_FRAME_LEN`] are rejected before any payload is read.

pub mod frame;
pub mod messages;
pub mod secret;

pub use frame::{
    decode, encode, read_frame, read_message, write_message, FrameError, MAX_FRAME_LEN,
};
pub use messages::*;
pub use secret::SecretText;

/// Protocol version carried in every envelope.
pub const PROTOCOL_VERSION: u32 = 1;
