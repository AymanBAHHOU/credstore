//! Approval keys from the human's side (M13): enrol a Windows Hello key once with the
//! passphrase, then sign approvals with it instead of typing the passphrase.
//!
//! The daemon accepts a key signature only for watching, approving, denying, status and
//! lock, and only while the vault is unlocked; everything else, and the first unlock,
//! still needs the passphrase.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Context;
use credstore_os::approval_key;
use credstore_proto::{hex, ApproverOp, KeyProof, Proof, Response, SecretText};

use crate::client::{expect_ok, Client};

/// Something that holds an approval key's private half.
pub trait KeySigner: Send + Sync {
    /// DER SubjectPublicKeyInfo. Must not ask the user.
    fn public_key(&self) -> io::Result<Vec<u8>>;
    /// RSA PKCS#1 v1.5 / SHA-256 signature of `message`. May ask the user.
    fn sign(&self, message: &[u8]) -> io::Result<Vec<u8>>;
    /// Shown to the human ("Windows Hello").
    fn name(&self) -> &'static str;
}

/// The Windows Hello key `credstore-approver`.
pub struct Hello;

impl KeySigner for Hello {
    fn public_key(&self) -> io::Result<Vec<u8>> {
        approval_key::hello::public_key()
    }

    fn sign(&self, message: &[u8]) -> io::Result<Vec<u8>> {
        approval_key::hello::sign(message)
    }

    fn name(&self) -> &'static str {
        "Windows Hello"
    }
}

impl Hello {
    /// The Hello signer, if this user has a credstore key in Hello (asks nothing).
    pub fn if_present() -> Option<Self> {
        approval_key::hello::public_key().ok().map(|_| Self)
    }
}

/// An in-process key (tests, Windows only).
#[cfg(windows)]
impl KeySigner for approval_key::SoftwareKey {
    fn public_key(&self) -> io::Result<Vec<u8>> {
        approval_key::SoftwareKey::public_key(self)
    }

    fn sign(&self, message: &[u8]) -> io::Result<Vec<u8>> {
        approval_key::SoftwareKey::sign(self, message)
    }

    fn name(&self) -> &'static str {
        "test key"
    }
}

/// Unique per call: time, process and a counter, hashed. Replay protection needs a
/// nonce the daemon has not seen, not a secret one (the signature covers it).
fn nonce() -> String {
    use sha2::{Digest, Sha256};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seed = format!(
        "{nanos}:{}:{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    hex(&Sha256::digest(seed.as_bytes())[..16])
}

/// A signed proof for `op`. Asks the user (Hello) once.
pub fn key_proof(signer: &dyn KeySigner, op: &ApproverOp) -> anyhow::Result<Proof> {
    let spki = signer
        .public_key()
        .with_context(|| format!("reading the {} key", signer.name()))?;
    let key_id = approval_key::key_id(&spki);
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let nonce = nonce();
    let message = credstore_proto::signed_message(&key_id, time, &nonce, op);
    let signature = signer.sign(&message)?;
    Ok(Proof::Key(KeyProof {
        key_id,
        time,
        nonce,
        signature: hex(&signature),
    }))
}

/// Send `op` signed by `signer`.
pub async fn send(
    client: &Client,
    signer: &dyn KeySigner,
    op: ApproverOp,
) -> anyhow::Result<Response> {
    let proof = key_proof(signer, &op)?;
    client.approver_with(op, proof).await
}

/// Enrol a public key in the vault. Returns its id.
pub async fn enrol(
    client: &Client,
    public_key: &[u8],
    label: &str,
    passphrase: SecretText,
) -> anyhow::Result<String> {
    let op = ApproverOp::AddApprovalKey {
        label: label.to_owned(),
        public_key: hex(public_key),
    };
    expect_ok(client.approver(op, passphrase).await?)?;
    Ok(approval_key::key_id(public_key))
}

/// Remove an enrolled key from the vault.
pub async fn remove(client: &Client, id: &str, passphrase: SecretText) -> anyhow::Result<()> {
    let op = ApproverOp::RemoveApprovalKey { id: id.to_owned() };
    expect_ok(client.approver(op, passphrase).await?)
}

/// Default label: this computer's name.
pub fn default_label() -> String {
    let host = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "this computer".into());
    format!("Windows Hello on {host}")
}
