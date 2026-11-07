//! Windows Hello approval key (M13): an RSA key in the Hello key store, used only after
//! Hello verifies the user (face, fingerprint or PIN). Its private half never leaves the
//! TPM or the Hello container; credstore keeps only the public key, in the vault.

use std::io;

use windows::core::HSTRING;
use windows::Security::Credentials::{
    KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
};
use windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType;
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Storage::Streams::IBuffer;

/// Name of the key in the user's Hello key store.
pub const KEY_NAME: &str = "credstore-approver";

fn err(e: windows::core::Error) -> io::Error {
    io::Error::other(e.message())
}

fn status(s: KeyCredentialStatus, what: &str) -> io::Result<()> {
    if s == KeyCredentialStatus::Success {
        return Ok(());
    }
    let why = if s == KeyCredentialStatus::UserCanceled {
        "cancelled"
    } else if s == KeyCredentialStatus::NotFound {
        "no credstore key in Windows Hello (run `credstore hello enrol`)"
    } else if s == KeyCredentialStatus::UserPrefersPassword {
        "the user chose the passphrase"
    } else if s == KeyCredentialStatus::SecurityDeviceLocked {
        "the security device is locked"
    } else {
        "Windows Hello failed"
    };
    Err(io::Error::other(format!("{what}: {why}")))
}

fn bytes(buf: &IBuffer) -> io::Result<Vec<u8>> {
    let mut out = windows::core::Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(buf, &mut out).map_err(err)?;
    Ok(out.to_vec())
}

fn public_key(k: &KeyCredential) -> io::Result<Vec<u8>> {
    let buf = k
        .RetrievePublicKeyWithBlobType(CryptographicPublicKeyBlobType::X509SubjectPublicKeyInfo)
        .map_err(err)?;
    bytes(&buf)
}

/// Whether Windows Hello is set up for this user.
pub fn available() -> bool {
    KeyCredentialManager::IsSupportedAsync()
        .and_then(|op| op.join())
        .unwrap_or(false)
}

/// Create (or replace) the key; Windows asks the user to verify. Returns the public key
/// as a DER SubjectPublicKeyInfo.
pub fn create() -> io::Result<Vec<u8>> {
    let _front = super::foreground::HelloInFront::start();
    let r = KeyCredentialManager::RequestCreateAsync(
        &HSTRING::from(KEY_NAME),
        KeyCredentialCreationOption::ReplaceExisting,
    )
    .and_then(|op| op.join())
    .map_err(err)?;
    status(r.Status().map_err(err)?, "creating the Hello key")?;
    public_key(&r.Credential().map_err(err)?)
}

/// The public key of the existing key, without asking the user.
pub fn existing_public_key() -> io::Result<Vec<u8>> {
    let r = KeyCredentialManager::OpenAsync(&HSTRING::from(KEY_NAME))
        .and_then(|op| op.join())
        .map_err(err)?;
    status(r.Status().map_err(err)?, "opening the Hello key")?;
    public_key(&r.Credential().map_err(err)?)
}

/// Sign `message` (Hello hashes it with SHA-256 and signs with PKCS#1 v1.5). Windows
/// asks the user to verify.
pub fn sign(message: &[u8]) -> io::Result<Vec<u8>> {
    let r = KeyCredentialManager::OpenAsync(&HSTRING::from(KEY_NAME))
        .and_then(|op| op.join())
        .map_err(err)?;
    status(r.Status().map_err(err)?, "opening the Hello key")?;
    let key = r.Credential().map_err(err)?;
    let data = CryptographicBuffer::CreateFromByteArray(message).map_err(err)?;
    let _front = super::foreground::HelloInFront::start();
    let s = key
        .RequestSignAsync(&data)
        .and_then(|op| op.join())
        .map_err(err)?;
    status(s.Status().map_err(err)?, "Windows Hello")?;
    bytes(&s.Result().map_err(err)?)
}

/// Delete the key from the Hello key store.
pub fn delete() -> io::Result<()> {
    KeyCredentialManager::DeleteAsync(&HSTRING::from(KEY_NAME))
        .and_then(|op| op.join())
        .map_err(err)
}
