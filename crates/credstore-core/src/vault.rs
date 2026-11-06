//! The vault: one age passphrase-encrypted (scrypt) file whose plaintext is JSON, plus a
//! plaintext `index.json` sidecar holding names and descriptions only.
//!
//! - The passphrase is never stored. Every operation that reads or writes values takes it.
//! - Plaintext lives only in `Zeroizing` buffers and `SecretText` values.
//! - Writes are atomic (temp file, fsync, rename): a crash leaves the old or new vault.
//! - The vault is written before the index. The index is rebuilt from the vault on every
//!   save, so after a crash between the two writes it lags by at most one operation.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use age::secrecy::SecretString;
use credstore_os::{fs as osfs, OsError};
use credstore_proto::{SecretInfo, SecretText};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::names::{self, InputError};

/// Plaintext format version inside the vault and the index.
pub const VAULT_VERSION: u32 = 1;
/// Shortest passphrase accepted by `init`.
pub const MIN_PASSPHRASE_LEN: usize = 8;
/// Values shorter than this are not redacted from output (spec 6.5); `set` warns.
pub const MIN_REDACTABLE_LEN: usize = 6;

/// scrypt cost for new vaults: N = 2^18 (256 MiB, roughly 0.5-1 s). Fixed rather than
/// age's timing-based default, so a slow or debug build never writes a weaker vault.
const WORK_FACTOR: u8 = 18;
/// Highest cost accepted when opening a vault (2^20, 1 GiB), to bound memory use.
const MAX_WORK_FACTOR: u8 = 20;
/// Largest vault file read.
const MAX_VAULT_BYTES: u64 = 32 * 1024 * 1024;
/// Largest index file read.
const MAX_INDEX_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("no vault at {0}; run `credstore init` first")]
    Missing(PathBuf),
    #[error("a vault already exists at {0}")]
    AlreadyExists(PathBuf),
    #[error("wrong passphrase")]
    WrongPassphrase,
    #[error("the vault file is damaged or is not a credstore vault ({0})")]
    Corrupt(&'static str),
    #[error("the vault's key-derivation cost is above the allowed maximum")]
    ExcessiveWork,
    #[error("unsupported vault format version {0}")]
    UnsupportedVersion(u32),
    #[error("the index file is damaged ({0}); it is rebuilt on the next `set` or `rm`")]
    IndexCorrupt(&'static str),
    #[error("the passphrase must be at least {MIN_PASSPHRASE_LEN} characters")]
    WeakPassphrase,
    #[error("no secret named {0}")]
    NoSuchSecret(String),
    #[error(transparent)]
    Input(#[from] InputError),
    #[error("encrypting the vault failed")]
    Encrypt,
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Os(#[from] OsError),
}

/// One stored secret. `Debug` shows the value as `[REDACTED]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub value: SecretText,
    pub description: String,
    pub created: String,
    pub updated: String,
}

/// What `set` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetOutcome {
    /// An existing secret was replaced.
    pub replaced: bool,
    /// The value is shorter than [`MIN_REDACTABLE_LEN`] and will not be redacted.
    pub too_short_to_redact: bool,
}

/// Decrypted vault contents.
#[derive(Debug, Clone, Default)]
pub struct VaultContents {
    secrets: BTreeMap<String, Entry>,
}

impl VaultContents {
    pub fn get(&self, name: &str) -> Option<&Entry> {
        self.secrets.get(name)
    }

    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    /// Names and descriptions, sorted by name.
    pub fn infos(&self) -> Vec<SecretInfo> {
        self.secrets
            .iter()
            .map(|(name, e)| SecretInfo {
                name: name.clone(),
                description: e.description.clone(),
            })
            .collect()
    }

    /// Add or replace a secret. With `description: None`, a replaced secret keeps its
    /// description.
    pub fn set(
        &mut self,
        name: &str,
        value: SecretText,
        description: Option<String>,
    ) -> Result<SetOutcome, VaultError> {
        names::validate_name(name)?;
        names::validate_value(value.expose())?;
        if let Some(d) = &description {
            names::validate_description(d)?;
        }
        let too_short_to_redact = value.expose().chars().count() < MIN_REDACTABLE_LEN;
        let now = now_rfc3339();
        let replaced = match self.secrets.get_mut(name) {
            Some(e) => {
                e.value = value;
                if let Some(d) = description {
                    e.description = d;
                }
                e.updated = now;
                true
            }
            None => {
                self.secrets.insert(
                    name.to_owned(),
                    Entry {
                        value,
                        description: description.unwrap_or_default(),
                        created: now.clone(),
                        updated: now,
                    },
                );
                false
            }
        };
        Ok(SetOutcome {
            replaced,
            too_short_to_redact,
        })
    }

    pub fn remove(&mut self, name: &str) -> Result<(), VaultError> {
        names::validate_name(name)?;
        self.secrets
            .remove(name)
            .map(drop)
            .ok_or_else(|| VaultError::NoSuchSecret(name.to_owned()))
    }
}

#[derive(Serialize)]
struct VaultFileRef<'a> {
    v: u32,
    secrets: &'a BTreeMap<String, Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultFile {
    v: u32,
    secrets: BTreeMap<String, Entry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexFile {
    v: u32,
    secrets: Vec<SecretInfo>,
}

#[derive(Debug, Clone, Copy)]
struct Kdf {
    work_factor: u8,
    max_work_factor: u8,
}

/// Handle to a vault on disk. Holds paths only, never the passphrase or contents.
#[derive(Debug, Clone)]
pub struct Vault {
    vault_file: PathBuf,
    index_file: PathBuf,
    kdf: Kdf,
}

impl Vault {
    pub fn new(vault_file: impl Into<PathBuf>, index_file: impl Into<PathBuf>) -> Self {
        Self {
            vault_file: vault_file.into(),
            index_file: index_file.into(),
            kdf: Kdf {
                work_factor: WORK_FACTOR,
                max_work_factor: MAX_WORK_FACTOR,
            },
        }
    }

    /// Cheap scrypt cost for unit tests only. Not reachable outside `cfg(test)`.
    #[cfg(test)]
    fn with_test_kdf(mut self) -> Self {
        self.kdf = Kdf {
            work_factor: 4,
            max_work_factor: 20,
        };
        self
    }

    pub fn vault_file(&self) -> &Path {
        &self.vault_file
    }

    pub fn index_file(&self) -> &Path {
        &self.index_file
    }

    pub fn exists(&self) -> bool {
        self.vault_file.exists()
    }

    /// Create an empty vault and index. Fails if a vault already exists.
    pub fn create(&self, passphrase: &SecretText) -> Result<(), VaultError> {
        if passphrase.expose().chars().count() < MIN_PASSPHRASE_LEN {
            return Err(VaultError::WeakPassphrase);
        }
        if self.exists() {
            return Err(VaultError::AlreadyExists(self.vault_file.clone()));
        }
        if let Some(dir) = self.vault_file.parent() {
            osfs::create_private_dir(dir)?;
        }
        self.save(&VaultContents::default(), passphrase)
    }

    /// Decrypt the vault. A wrong passphrase gives [`VaultError::WrongPassphrase`].
    pub fn unlock(&self, passphrase: &SecretText) -> Result<VaultContents, VaultError> {
        let ciphertext = read_bounded(&self.vault_file, MAX_VAULT_BYTES)
            .map_err(|e| missing_or(e, &self.vault_file))?
            .ok_or(VaultError::Corrupt("file too large"))?;

        let mut identity = age::scrypt::Identity::new(secret_string(passphrase));
        identity.set_max_work_factor(self.kdf.max_work_factor);

        let decryptor = age::Decryptor::new_buffered(&ciphertext[..]).map_err(map_header)?;
        let mut reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .map_err(map_unwrap)?;
        let mut plaintext = Zeroizing::new(Vec::new());
        reader
            .read_to_end(&mut plaintext)
            .map_err(|_| VaultError::Corrupt("payload failed authentication"))?;

        let file: VaultFile =
            serde_json::from_slice(&plaintext).map_err(|_| VaultError::Corrupt("contents"))?;
        if file.v != VAULT_VERSION {
            return Err(VaultError::UnsupportedVersion(file.v));
        }
        if file
            .secrets
            .keys()
            .any(|n| names::validate_name(n).is_err())
        {
            return Err(VaultError::Corrupt("invalid secret name"));
        }
        Ok(VaultContents {
            secrets: file.secrets,
        })
    }

    /// Encrypt `contents` with `passphrase` and atomically replace the vault, then the
    /// index. Callers must have unlocked the vault with the same passphrase.
    pub fn save(
        &self,
        contents: &VaultContents,
        passphrase: &SecretText,
    ) -> Result<(), VaultError> {
        let mut plaintext = Zeroizing::new(Vec::new());
        serde_json::to_writer(
            &mut *plaintext,
            &VaultFileRef {
                v: VAULT_VERSION,
                secrets: &contents.secrets,
            },
        )
        .map_err(|_| VaultError::Encrypt)?;

        let mut recipient = age::scrypt::Recipient::new(secret_string(passphrase));
        recipient.set_work_factor(self.kdf.work_factor);
        let ciphertext = age::encrypt(&recipient, &plaintext).map_err(|_| VaultError::Encrypt)?;

        osfs::write_private_atomic(&self.vault_file, &ciphertext)?;
        self.write_index(contents)
    }

    /// Names and descriptions from the index. Needs no passphrase.
    pub fn list(&self) -> Result<Vec<SecretInfo>, VaultError> {
        let bytes = match read_bounded(&self.index_file, MAX_INDEX_BYTES) {
            Ok(Some(b)) => b,
            Ok(None) => return Err(VaultError::IndexCorrupt("file too large")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(if self.exists() {
                    VaultError::IndexCorrupt("file missing")
                } else {
                    VaultError::Missing(self.vault_file.clone())
                });
            }
            Err(e) => return Err(e.into()),
        };
        let index: IndexFile =
            serde_json::from_slice(&bytes).map_err(|_| VaultError::IndexCorrupt("contents"))?;
        if index.v != VAULT_VERSION {
            return Err(VaultError::UnsupportedVersion(index.v));
        }
        Ok(index.secrets)
    }

    fn write_index(&self, contents: &VaultContents) -> Result<(), VaultError> {
        let index = IndexFile {
            v: VAULT_VERSION,
            secrets: contents.infos(),
        };
        let mut bytes = serde_json::to_vec_pretty(&index).map_err(|_| VaultError::Encrypt)?;
        bytes.push(b'\n');
        osfs::write_private_atomic(&self.index_file, &bytes)?;
        Ok(())
    }
}

fn secret_string(p: &SecretText) -> SecretString {
    SecretString::from(p.expose().to_owned())
}

/// Errors from parsing the age header.
fn map_header(_: age::DecryptError) -> VaultError {
    VaultError::Corrupt("not an age file")
}

/// Errors from unwrapping the file key with the passphrase. For a scrypt stanza, a wrong
/// passphrase surfaces as `DecryptionFailed` (the wrapped key fails to authenticate).
/// Payload damage is reported later, while reading.
fn map_unwrap(e: age::DecryptError) -> VaultError {
    match e {
        age::DecryptError::NoMatchingKeys | age::DecryptError::DecryptionFailed => {
            VaultError::WrongPassphrase
        }
        age::DecryptError::ExcessiveWork { .. } => VaultError::ExcessiveWork,
        age::DecryptError::InvalidMac => VaultError::Corrupt("header failed authentication"),
        _ => VaultError::Corrupt("unreadable header"),
    }
}

fn missing_or(e: std::io::Error, path: &Path) -> VaultError {
    if e.kind() == std::io::ErrorKind::NotFound {
        VaultError::Missing(path.to_owned())
    } else {
        VaultError::Io(e)
    }
}

/// Read a whole file, or `None` if it is larger than `max`.
fn read_bounded(path: &Path, max: u64) -> std::io::Result<Option<Vec<u8>>> {
    let f = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    f.take(max + 1).read_to_end(&mut buf)?;
    Ok((buf.len() as u64 <= max).then_some(buf))
}

fn now_rfc3339() -> String {
    let now = time::OffsetDateTime::now_utc();
    let now = now.replace_nanosecond(0).unwrap_or(now);
    now.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
