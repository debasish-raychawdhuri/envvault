//! Password-based encryption for the vault file.
//!
//! Key derivation: Argon2id (password + per-file random salt) -> 32-byte key.
//! Encryption: ChaCha20-Poly1305 AEAD with a fresh random nonce per save.
//!
//! On-disk format (UTF-8 text, git/copy-paste friendly):
//! ```text
//! ENVVAULT v1
//! <base64( salt[16] || nonce[12] || ciphertext+tag )>
//! ```

use anyhow::{anyhow, bail, Context, Result};
use argon2::Argon2;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use std::path::Path;
use zeroize::Zeroizing;

const MAGIC: &str = "ENVVAULT v1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

/// Fill an array with cryptographically secure random bytes.
fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).map_err(|e| anyhow!("failed to gather randomness: {e}"))?;
    Ok(buf)
}

/// Derive a 32-byte key from a password and salt using Argon2id.
fn derive_key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::default()
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|e| anyhow!("key derivation failed: {e}"))?;
    Ok(key)
}

/// An open crypto session for a single vault file: the salt is fixed for the
/// life of the file, the derived key is held in memory (zeroized on drop), and
/// a fresh nonce is generated on each save.
pub struct Session {
    salt: [u8; SALT_LEN],
    key: Zeroizing<[u8; KEY_LEN]>,
}

impl Session {
    /// Create a brand-new vault session with a freshly generated salt.
    pub fn create(password: &[u8]) -> Result<Self> {
        let salt = random_array::<SALT_LEN>()?;
        let key = derive_key(password, &salt)?;
        Ok(Self { salt, key })
    }

    /// Encrypt `plaintext` and return the full armored file body as a String.
    pub fn armor(&self, plaintext: &[u8]) -> Result<String> {
        let nonce_bytes = random_array::<NONCE_LEN>()?;
        let cipher = ChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|e| anyhow!("invalid key length: {e}"))?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
            .map_err(|_| anyhow!("encryption failed"))?;

        let mut blob = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
        blob.extend_from_slice(&self.salt);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext);

        Ok(format!("{MAGIC}\n{}\n", B64.encode(&blob)))
    }

    /// Encrypt and atomically write the vault to `path` with 0600 permissions.
    pub fn save(&self, path: &Path, plaintext: &[u8]) -> Result<()> {
        let armored = self.armor(plaintext)?;
        write_private(path, armored.as_bytes())
    }
}

/// Open an existing vault: parse the file, derive the key from `password`,
/// decrypt, and return the session (for later re-saving) plus the plaintext.
pub fn open(path: &Path, password: &[u8]) -> Result<(Session, Zeroizing<Vec<u8>>)> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read vault at {}", path.display()))?;

    let mut lines = text.lines();
    let header = lines.next().unwrap_or("").trim();
    if header != MAGIC {
        bail!("{} is not an envvault file (bad header)", path.display());
    }
    let b64: String = lines.collect::<Vec<_>>().join("");
    let blob = B64
        .decode(b64.trim())
        .context("vault body is not valid base64 (file corrupted?)")?;

    if blob.len() < SALT_LEN + NONCE_LEN {
        bail!("vault file is truncated or corrupted");
    }
    let salt: [u8; SALT_LEN] = blob[..SALT_LEN].try_into().unwrap();
    let nonce = &blob[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &blob[SALT_LEN + NONCE_LEN..];

    let key = derive_key(password, &salt)?;
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|e| anyhow!("invalid key length: {e}"))?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| anyhow!("decryption failed — wrong password or corrupted file"))?;

    Ok((Session { salt, key }, Zeroizing::new(plaintext)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn armor_then_open_round_trips() {
        let dir = std::env::temp_dir().join("envvault-test-rt");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rt.vault");

        let session = Session::create(b"correct horse").unwrap();
        session.save(&path, b"SECRET=hunter2\n").unwrap();

        let (_s, pt) = open(&path, b"correct horse").unwrap();
        assert_eq!(&pt[..], b"SECRET=hunter2\n");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn wrong_password_fails() {
        let dir = std::env::temp_dir().join("envvault-test-wp");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wp.vault");

        let session = Session::create(b"right").unwrap();
        session.save(&path, b"K=v\n").unwrap();

        assert!(open(&path, b"wrong").is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let session = Session::create(b"pw").unwrap();
        let armored = session.armor(b"K=v\n").unwrap();
        // Flip a character in the base64 body to simulate corruption/tampering.
        let mut lines: Vec<String> = armored.lines().map(str::to_string).collect();
        let body = &mut lines[1];
        let flipped = if body.starts_with('A') { 'B' } else { 'A' };
        body.replace_range(0..1, &flipped.to_string());
        let tampered = format!("{}\n{}\n", lines[0], lines[1]);

        let dir = std::env::temp_dir().join("envvault-test-tp");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tp.vault");
        std::fs::write(&path, tampered).unwrap();
        assert!(open(&path, b"pw").is_err());
        std::fs::remove_file(&path).ok();
    }
}

/// Write bytes to `path`, creating it with owner-only (0600) permissions on
/// unix, via a temp file + rename so we never leave a partial file behind.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let tmp = match dir {
        Some(d) => d.join(format!(
            ".{}.tmp",
            path.file_name().and_then(|n| n.to_str()).unwrap_or("vault")
        )),
        None => std::path::PathBuf::from(format!(
            ".{}.tmp",
            path.file_name().and_then(|n| n.to_str()).unwrap_or("vault")
        )),
    };

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&tmp)
        .with_context(|| format!("failed to create temp file {}", tmp.display()))?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    drop(f);

    std::fs::rename(&tmp, path)
        .with_context(|| format!("failed to move temp file into place at {}", path.display()))?;
    Ok(())
}
