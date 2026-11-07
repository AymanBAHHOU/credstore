//! credstore core logic: vault (M1), audit (M2), policy and request checks (M3),
//! redaction (M5), HTTP request checks (M11).
//!
//! This crate does no socket I/O and contains no platform-specific code; file operations
//! that differ per OS go through `credstore-os`.

pub mod audit;
pub mod http;
pub mod names;
pub mod policy;
pub mod redact;
pub mod request;
pub mod util;
pub mod vault;

pub use credstore_proto as proto;
