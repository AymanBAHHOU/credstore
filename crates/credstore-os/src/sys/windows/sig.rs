//! RSA PKCS#1 v1.5 / SHA-256 signatures with CNG (M13): what Windows Hello keys sign
//! with. The daemon verifies approval signatures here; [`SoftwareKey`] is an ordinary
//! CNG key with the same format, for tests and machines without Hello.
//!
//! Unsafe: CNG and crypt32 calls. Each block says what it relies on; every handle and
//! every crypt32 allocation is owned by a guard that frees it.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;

use windows_sys::Win32::Security::Cryptography::{
    BCryptCloseAlgorithmProvider, BCryptDestroyKey, BCryptFinalizeKeyPair, BCryptGenerateKeyPair,
    BCryptOpenAlgorithmProvider, BCryptSignHash, BCryptVerifySignature, CryptDecodeObjectEx,
    CryptEncodeObjectEx, CryptExportPublicKeyInfoFromBCryptKeyHandle, CryptImportPublicKeyInfoEx2,
    BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE, BCRYPT_PAD_PKCS1, BCRYPT_PKCS1_PADDING_INFO,
    BCRYPT_RSA_ALGORITHM, BCRYPT_SHA256_ALGORITHM, CERT_PUBLIC_KEY_INFO, CRYPT_DECODE_ALLOC_FLAG,
    CRYPT_ENCODE_ALLOC_FLAG, X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
};

use super::win::LocalBox;

/// Largest public key accepted (a 4096-bit RSA SubjectPublicKeyInfo is about 550 bytes).
const MAX_SPKI: usize = 4096;
const RSA_OID: &[u8] = b"1.2.840.113549.1.1.1\0";

struct Key(BCRYPT_KEY_HANDLE);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the handle came from CNG and is destroyed once, here.
        unsafe { BCryptDestroyKey(self.0) };
    }
}

struct Alg(BCRYPT_ALG_HANDLE);

impl Drop for Alg {
    fn drop(&mut self) {
        // SAFETY: the handle came from BCryptOpenAlgorithmProvider and is closed once.
        unsafe { BCryptCloseAlgorithmProvider(self.0, 0) };
    }
}

fn nt(status: i32, what: &str) -> io::Result<()> {
    if status < 0 {
        Err(io::Error::other(format!("{what} failed (0x{status:08x})")))
    } else {
        Ok(())
    }
}

fn padding() -> BCRYPT_PKCS1_PADDING_INFO {
    BCRYPT_PKCS1_PADDING_INFO {
        pszAlgId: BCRYPT_SHA256_ALGORITHM,
    }
}

/// Import a DER SubjectPublicKeyInfo holding an RSA key.
fn import(spki: &[u8]) -> io::Result<Key> {
    if spki.is_empty() || spki.len() > MAX_SPKI {
        return Err(io::Error::other("public key has a bad size"));
    }
    let mut info: *mut c_void = std::ptr::null_mut();
    let mut len = 0u32;
    // SAFETY: `spki` is valid for its length; with CRYPT_DECODE_ALLOC_FLAG crypt32
    // writes a LocalAlloc'd CERT_PUBLIC_KEY_INFO pointer into `info`.
    let ok = unsafe {
        CryptDecodeObjectEx(
            X509_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO,
            spki.as_ptr(),
            spki.len() as u32,
            CRYPT_DECODE_ALLOC_FLAG,
            std::ptr::null(),
            (&mut info as *mut *mut c_void).cast(),
            &mut len,
        )
    };
    if ok == 0 || info.is_null() {
        return Err(io::Error::other("not a SubjectPublicKeyInfo"));
    }
    let info = LocalBox::from_raw(info);
    // Only RSA: the signature check below assumes PKCS#1 padding.
    // SAFETY: `info` points to the CERT_PUBLIC_KEY_INFO crypt32 decoded; the OID is a
    // NUL-terminated string inside the same allocation.
    let oid = unsafe {
        let pki = &*(info.ptr() as *const CERT_PUBLIC_KEY_INFO);
        std::ffi::CStr::from_ptr(pki.Algorithm.pszObjId as *const std::ffi::c_char)
    };
    if oid.to_bytes_with_nul() != RSA_OID {
        return Err(io::Error::other("not an RSA public key"));
    }
    let mut key: BCRYPT_KEY_HANDLE = std::ptr::null_mut();
    // SAFETY: `info` is a valid CERT_PUBLIC_KEY_INFO; `key` receives a CNG key handle.
    let ok = unsafe {
        CryptImportPublicKeyInfoEx2(
            X509_ASN_ENCODING,
            info.ptr() as *const CERT_PUBLIC_KEY_INFO,
            0,
            std::ptr::null(),
            &mut key,
        )
    };
    if ok == 0 || key.is_null() {
        return Err(io::Error::other("cannot import the public key"));
    }
    Ok(Key(key))
}

/// Check that the public key can be used to verify signatures.
pub fn check_public_key(spki: &[u8]) -> io::Result<()> {
    import(spki).map(drop)
}

/// Whether `signature` is a valid PKCS#1 v1.5 signature of the SHA-256 `digest` by the
/// RSA key in `spki`.
pub fn verify(spki: &[u8], digest: &[u8; 32], signature: &[u8]) -> io::Result<bool> {
    let key = import(spki)?;
    let pad = padding();
    // SAFETY: `key` is a valid public key; padding, digest and signature buffers are
    // valid for the lengths given.
    let status = unsafe {
        BCryptVerifySignature(
            key.0,
            (&pad as *const BCRYPT_PKCS1_PADDING_INFO).cast(),
            digest.as_ptr(),
            32,
            signature.as_ptr(),
            u32::try_from(signature.len()).unwrap_or(u32::MAX),
            BCRYPT_PAD_PKCS1,
        )
    };
    Ok(status >= 0)
}

/// An RSA-2048 key held in this process: the same signature format as a Hello key.
pub struct SoftwareKey {
    key: Key,
    _alg: Alg,
}

// SAFETY: CNG key and provider handles are process-wide and may be used from any
// thread; signing and exporting do not change the key, and the handles are freed only
// on drop, when no other reference exists.
unsafe impl Send for SoftwareKey {}
// SAFETY: see above; BCryptSignHash on one key from several threads is allowed.
unsafe impl Sync for SoftwareKey {}

impl SoftwareKey {
    pub fn generate() -> io::Result<Self> {
        let mut alg: BCRYPT_ALG_HANDLE = std::ptr::null_mut();
        // SAFETY: `alg` receives a provider handle, closed by `Alg`.
        nt(
            unsafe {
                BCryptOpenAlgorithmProvider(&mut alg, BCRYPT_RSA_ALGORITHM, std::ptr::null(), 0)
            },
            "opening the RSA provider",
        )?;
        let alg = Alg(alg);
        let mut key: BCRYPT_KEY_HANDLE = std::ptr::null_mut();
        // SAFETY: `alg.0` is an open RSA provider; `key` receives a key handle.
        nt(
            unsafe { BCryptGenerateKeyPair(alg.0, &mut key, 2048, 0) },
            "generating a key",
        )?;
        let key = Key(key);
        // SAFETY: `key.0` is a key pair not finalized yet.
        nt(
            unsafe { BCryptFinalizeKeyPair(key.0, 0) },
            "finalizing the key",
        )?;
        Ok(Self { key, _alg: alg })
    }

    /// The public key as a DER SubjectPublicKeyInfo.
    pub fn public_key(&self) -> io::Result<Vec<u8>> {
        let mut len = 0u32;
        // SAFETY: first call with a null buffer asks for the size.
        let ok = unsafe {
            CryptExportPublicKeyInfoFromBCryptKeyHandle(
                self.key.0,
                X509_ASN_ENCODING,
                RSA_OID.as_ptr(),
                0,
                std::ptr::null(),
                std::ptr::null_mut(),
                &mut len,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // u64 backing keeps the CERT_PUBLIC_KEY_INFO aligned.
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        // SAFETY: `buf` holds at least `len` bytes, suitably aligned.
        let ok = unsafe {
            CryptExportPublicKeyInfoFromBCryptKeyHandle(
                self.key.0,
                X509_ASN_ENCODING,
                RSA_OID.as_ptr(),
                0,
                std::ptr::null(),
                buf.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len = 0u32;
        // SAFETY: `buf` holds the CERT_PUBLIC_KEY_INFO just written; with
        // CRYPT_ENCODE_ALLOC_FLAG crypt32 writes a LocalAlloc'd buffer into `out`.
        let ok = unsafe {
            CryptEncodeObjectEx(
                X509_ASN_ENCODING,
                X509_PUBLIC_KEY_INFO,
                buf.as_ptr().cast(),
                CRYPT_ENCODE_ALLOC_FLAG,
                std::ptr::null(),
                (&mut out as *mut *mut u8).cast(),
                &mut out_len,
            )
        };
        if ok == 0 || out.is_null() {
            return Err(io::Error::last_os_error());
        }
        let owned = LocalBox::from_raw(out.cast());
        // SAFETY: crypt32 wrote `out_len` bytes at `out`, owned by `owned`.
        let der = unsafe { std::slice::from_raw_parts(owned.ptr() as *const u8, out_len as usize) };
        Ok(der.to_vec())
    }

    /// Sign a SHA-256 digest.
    pub fn sign(&self, digest: &[u8; 32]) -> io::Result<Vec<u8>> {
        let pad = padding();
        let mut sig = vec![0u8; 512];
        let mut len = 0u32;
        // SAFETY: `self.key.0` is a private key; buffers are valid for their lengths.
        nt(
            unsafe {
                BCryptSignHash(
                    self.key.0,
                    (&pad as *const BCRYPT_PKCS1_PADDING_INFO).cast(),
                    digest.as_ptr(),
                    32,
                    sig.as_mut_ptr(),
                    sig.len() as u32,
                    &mut len,
                    BCRYPT_PAD_PKCS1,
                )
            },
            "signing",
        )?;
        sig.truncate(len as usize);
        Ok(sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signature_verifies_and_a_changed_one_does_not() {
        let k = SoftwareKey::generate().unwrap();
        let spki = k.public_key().unwrap();
        check_public_key(&spki).unwrap();
        let digest = [7u8; 32];
        let mut sig = k.sign(&digest).unwrap();
        assert!(verify(&spki, &digest, &sig).unwrap());
        assert!(!verify(&spki, &[8u8; 32], &sig).unwrap());
        sig[10] ^= 1;
        assert!(!verify(&spki, &digest, &sig).unwrap());
        let other = SoftwareKey::generate().unwrap().public_key().unwrap();
        assert!(!verify(&other, &digest, &k.sign(&digest).unwrap()).unwrap());
    }

    #[test]
    fn garbage_is_not_a_key() {
        assert!(check_public_key(b"").is_err());
        assert!(check_public_key(&[0x30, 0x03, 0x02, 0x01, 0x00]).is_err());
        assert!(check_public_key(&vec![0u8; MAX_SPKI + 1]).is_err());
    }
}
