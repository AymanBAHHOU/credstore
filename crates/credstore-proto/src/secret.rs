//! A string that holds sensitive data (a passphrase or a secret value) on the wire.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, Zeroizing};

/// Sensitive text. Zeroized on drop, never shown by `Debug`, has no `Display`.
///
/// Only the approver endpoint ever carries one (passphrase proofs, `admin_set` values).
/// Nothing sent to the agent endpoint's clients may contain a `SecretText`.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretText(Zeroizing<String>);

impl SecretText {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Borrow the plaintext. Keep the borrow short and never log it.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Overwrite the contents with zeros now (also happens on drop). Returns the number
    /// of bytes wiped.
    pub fn wipe(&mut self) -> usize {
        let n = self.0.len();
        self.0.zeroize();
        n
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for SecretText {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl Serialize for SecretText {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(Self::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let s = SecretText::new("FAKE-SECRET-VALUE-12345".into());
        assert_eq!(format!("{s:?}"), "[REDACTED]");
        assert_eq!(format!("{:?}", Some(&s)), "Some([REDACTED])");
    }

    #[test]
    fn wipe_clears_contents() {
        let mut s = SecretText::new("FAKE-SECRET-VALUE-12345".into());
        assert_eq!(s.wipe(), 23);
        assert!(s.is_empty());
        assert_eq!(s.expose(), "");
    }
}
