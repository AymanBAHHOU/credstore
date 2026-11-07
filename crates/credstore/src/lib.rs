//! credstore CLI and MCP shim, as a library so tests can drive the commands.
//!
//! Neither the CLI nor the shim decrypts anything; both talk to `credstored`. Secret
//! values are never accepted on argv or from the CLI's own environment.

pub mod api;
pub mod approval;
pub mod client;
pub mod commands;
pub mod doctor;
pub mod mcp;
pub mod policy_apply;
pub mod setup;
pub mod watch;
