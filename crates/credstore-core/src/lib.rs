//! credstore core logic: vault (M1), policy (M3), redaction and audit (M2, M5).
//!
//! This crate does no socket I/O and contains no platform-specific code; file operations
//! that differ per OS go through `credstore-os`.

pub mod names;
pub mod vault;

pub use credstore_proto as proto;
