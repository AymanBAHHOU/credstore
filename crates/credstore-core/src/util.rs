//! Small helpers: timestamps and ids.

use std::sync::atomic::{AtomicU64, Ordering};

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// UTC now, RFC 3339, whole seconds.
pub fn now_rfc3339() -> String {
    let now = OffsetDateTime::now_utc();
    let now = now.replace_nanosecond(0).unwrap_or(now);
    now.format(&Rfc3339).unwrap_or_default()
}

/// UTC now, RFC 3339, milliseconds.
pub fn now_rfc3339_millis() -> String {
    let now = OffsetDateTime::now_utc();
    let ms = now.nanosecond() / 1_000_000 * 1_000_000;
    let now = now.replace_nanosecond(ms).unwrap_or(now);
    now.format(&Rfc3339).unwrap_or_default()
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Unique, time-ordered id like `req_0195f3a2b4c1000001`. Not secret and not a
/// capability: acting on a request also needs the passphrase.
pub fn new_id(prefix: &str) -> String {
    let millis = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}_{millis:012x}{:06x}", n & 0xff_ffff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_prefixed() {
        let a = new_id("req");
        let b = new_id("req");
        assert_ne!(a, b);
        assert!(a.starts_with("req_") && a.len() == 4 + 18);
    }

    #[test]
    fn timestamps_are_utc() {
        assert!(now_rfc3339().ends_with('Z'));
        let ms = now_rfc3339_millis();
        assert!(ms.ends_with('Z'), "{ms}");
    }
}
