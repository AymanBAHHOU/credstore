//! Approval keys (M13): a key the human enrols once (with the passphrase) and that
//! signs approvals afterwards, so the passphrase is not typed for every decision.
//!
//! The only kind today is a Windows Hello key: RSA, PKCS#1 v1.5 with SHA-256, private
//! half in the TPM or the Hello container, used only after Hello verifies the user. The
//! daemon verifies signatures with the public key stored in the encrypted vault, so a
//! process that merely claims "the user said yes" gets nothing.
//!
//! macOS (Touch ID) needs a signed app to hold a Secure Enclave key, and Linux has no
//! common biometric service; both keep the passphrase.

use sha2::{Digest, Sha256};

/// Id of a public key (DER SubjectPublicKeyInfo): see `credstore_proto::approval_key_id`.
pub fn key_id(spki: &[u8]) -> String {
    credstore_proto::approval_key_id(&Sha256::digest(spki))
}

/// Whether this platform can verify approval-key signatures.
pub fn supported() -> bool {
    cfg!(windows)
}

/// Check that `spki` is a key the daemon can verify signatures with.
pub fn check_public_key(spki: &[u8]) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::sys::windows::sig::check_public_key(spki).map_err(|e| e.to_string())
    }
    #[cfg(not(windows))]
    {
        let _ = spki;
        Err("approval keys are only supported on Windows (Windows Hello) for now".into())
    }
}

/// Whether `signature` is a valid signature of `message` by the key `spki`.
pub fn verify(spki: &[u8], message: &[u8], signature: &[u8]) -> bool {
    #[cfg(windows)]
    {
        let digest: [u8; 32] = Sha256::digest(message).into();
        crate::sys::windows::sig::verify(spki, &digest, signature).unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        let _ = (spki, message, signature);
        false
    }
}

/// Windows Hello, from the human's side (the CLI and the app).
pub mod hello {
    use std::io;

    #[cfg(not(windows))]
    fn unsupported() -> io::Error {
        io::Error::other("Windows Hello is only available on Windows")
    }

    /// Whether Hello is set up for this user.
    pub fn available() -> bool {
        #[cfg(windows)]
        {
            crate::sys::windows::hello::available()
        }
        #[cfg(not(windows))]
        {
            false
        }
    }

    /// Create (or replace) the credstore key; Windows asks the user. Returns the public
    /// key (DER SubjectPublicKeyInfo).
    pub fn create() -> io::Result<Vec<u8>> {
        #[cfg(windows)]
        {
            crate::sys::windows::hello::create()
        }
        #[cfg(not(windows))]
        {
            Err(unsupported())
        }
    }

    /// The existing key's public key, without asking the user.
    pub fn public_key() -> io::Result<Vec<u8>> {
        #[cfg(windows)]
        {
            crate::sys::windows::hello::existing_public_key()
        }
        #[cfg(not(windows))]
        {
            Err(unsupported())
        }
    }

    /// Sign `message`; Windows asks the user.
    pub fn sign(message: &[u8]) -> io::Result<Vec<u8>> {
        #[cfg(windows)]
        {
            crate::sys::windows::hello::sign(message)
        }
        #[cfg(not(windows))]
        {
            let _ = message;
            Err(unsupported())
        }
    }

    /// Delete the credstore key from Hello.
    pub fn delete() -> io::Result<()> {
        #[cfg(windows)]
        {
            crate::sys::windows::hello::delete()
        }
        #[cfg(not(windows))]
        {
            Err(unsupported())
        }
    }
}

/// An in-process key with the same signature format as a Hello key (tests).
#[cfg(windows)]
pub struct SoftwareKey(crate::sys::windows::sig::SoftwareKey);

#[cfg(windows)]
impl SoftwareKey {
    pub fn generate() -> std::io::Result<Self> {
        crate::sys::windows::sig::SoftwareKey::generate().map(Self)
    }

    pub fn public_key(&self) -> std::io::Result<Vec<u8>> {
        self.0.public_key()
    }

    /// Sign `message` as Hello would (SHA-256, PKCS#1 v1.5).
    pub fn sign(&self, message: &[u8]) -> std::io::Result<Vec<u8>> {
        self.0.sign(&Sha256::digest(message).into())
    }
}
