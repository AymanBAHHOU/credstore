//! Per-OS implementations. Only `credstore-os` may contain `cfg(unix)` / `cfg(windows)`.

#[cfg(unix)]
pub mod unix;
#[cfg(unix)]
pub use unix as current;

#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
pub use windows as current;
