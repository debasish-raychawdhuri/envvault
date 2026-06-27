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

    /// Encrypt and durably write the vault to `path` with 0600 permissions.
    ///
    /// This is a journaling write: the ciphertext is written to a temp file,
    /// fsynced, **decrypted and compared back against `plaintext`**, and only
    /// then atomically renamed over `path` (with the directory fsynced so the
    /// rename survives power loss). If anything fails before the rename, the
    /// previous vault file is left completely untouched and the temp file is
    /// removed — so a torn write, a storage fault, or an encryption bug can
    /// never destroy the only good copy of your secrets.
    pub fn save(&self, path: &Path, plaintext: &[u8]) -> Result<()> {
        let armored = self.armor(plaintext)?;
        write_private(path, armored.as_bytes(), |tmp| {
            let got = self.decrypt_file(tmp).context(
                "post-write verification: could not decrypt the file just written",
            )?;
            if got.as_slice() != plaintext {
                bail!(
                    "post-write verification failed: the decrypted contents of the \
                     newly written file differ from what was encrypted"
                );
            }
            Ok(())
        })
    }

    /// Decrypt a vault file using *this* session's key (no password re-prompt).
    /// Used to verify a freshly written file before committing it. The salt
    /// stored in the file must match the session's, or the file isn't ours.
    fn decrypt_file(&self, path: &Path) -> Result<Zeroizing<Vec<u8>>> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to re-read {} for verification", path.display()))?;
        let (salt, nonce, ciphertext) = parse_armored(&text, &path.display().to_string())?;
        if salt != self.salt {
            bail!("verification: the file just written has an unexpected salt");
        }
        let cipher = ChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|e| anyhow!("invalid key length: {e}"))?;
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
            .map_err(|_| anyhow!("verification: could not decrypt the file just written"))?;
        Ok(Zeroizing::new(plaintext))
    }
}

/// Open an existing vault: parse the file, derive the key from `password`,
/// decrypt, and return the session (for later re-saving) plus the plaintext.
pub fn open(path: &Path, password: &[u8]) -> Result<(Session, Zeroizing<Vec<u8>>)> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read vault at {}", path.display()))?;
    let (salt, nonce, ciphertext) = parse_armored(&text, &path.display().to_string())?;

    let key = derive_key(password, &salt)?;
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|e| anyhow!("invalid key length: {e}"))?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| anyhow!("decryption failed — wrong password or corrupted file"))?;

    Ok((Session { salt, key }, Zeroizing::new(plaintext)))
}

/// Parse an armored vault body into its `(salt, nonce, ciphertext)` parts.
/// `src` names the source (a path) for error messages.
fn parse_armored(text: &str, src: &str) -> Result<([u8; SALT_LEN], [u8; NONCE_LEN], Vec<u8>)> {
    let mut lines = text.lines();
    let header = lines.next().unwrap_or("").trim();
    if header != MAGIC {
        bail!("{src} is not an envvault file (bad header)");
    }
    let b64: String = lines.collect::<Vec<_>>().join("");
    let blob = B64
        .decode(b64.trim())
        .context("vault body is not valid base64 (file corrupted?)")?;

    if blob.len() < SALT_LEN + NONCE_LEN {
        bail!("vault file is truncated or corrupted");
    }
    let salt: [u8; SALT_LEN] = blob[..SALT_LEN].try_into().unwrap();
    let nonce: [u8; NONCE_LEN] = blob[SALT_LEN..SALT_LEN + NONCE_LEN].try_into().unwrap();
    let ciphertext = blob[SALT_LEN + NONCE_LEN..].to_vec();
    Ok((salt, nonce, ciphertext))
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
    fn change_password_reencrypts() {
        let dir = std::env::temp_dir().join("envvault-test-cp");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cp.vault");

        let session = Session::create(b"oldpw").unwrap();
        session.save(&path, b"SECRET=v\n").unwrap();

        // Re-key: open with the old password, re-encrypt under a new one
        // (this is exactly what `cmd_passwd` does).
        let (_old, plaintext) = open(&path, b"oldpw").unwrap();
        let new_session = Session::create(b"newpw").unwrap();
        new_session.save(&path, &plaintext).unwrap();

        // The new password decrypts the same contents; the old one no longer does.
        let (_s, pt) = open(&path, b"newpw").unwrap();
        assert_eq!(&pt[..], b"SECRET=v\n");
        assert!(open(&path, b"oldpw").is_err());
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
    fn save_leaves_no_temp_litter_and_overwrites_atomically() {
        let dir = std::env::temp_dir().join("envvault-test-litter");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v.vault");

        let session = Session::create(b"pw").unwrap();
        session.save(&path, b"K=1\n").unwrap();
        // Re-save over the existing vault (the autosave / re-encrypt case).
        session.save(&path, b"K=2\n").unwrap();

        // The new contents are present...
        let (_s, pt) = open(&path, b"pw").unwrap();
        assert_eq!(&pt[..], b"K=2\n");

        // ...and no temp file was left behind in the directory.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "stray temp files: {leftovers:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_verifies_before_commit() {
        // A save must round-trip under this session's own key; decrypt_file is
        // the verification gate write_private runs before renaming into place.
        let dir = std::env::temp_dir().join("envvault-test-verify");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v.vault");

        let session = Session::create(b"pw").unwrap();
        session.save(&path, b"SECRET=v\n").unwrap();
        let got = session.decrypt_file(&path).unwrap();
        assert_eq!(&got[..], b"SECRET=v\n");

        // A file written under a *different* session's key must not verify as
        // this session's, guarding the "is this file really ours" check.
        let other = Session::create(b"pw").unwrap(); // fresh salt => different key
        assert!(other.decrypt_file(&path).is_err());

        let _ = std::fs::remove_dir_all(&dir);
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

/// Removes a temp file on drop unless disarmed — so a failed write or a failed
/// verification never leaves a stray partial file behind.
struct TmpGuard {
    path: std::path::PathBuf,
    armed: bool,
}

impl TmpGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TmpGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Durably write `bytes` to `path` with owner-only (0600) permissions, as a
/// journaling write:
///
/// 1. write the bytes to a per-process temp file in the same directory,
/// 2. `fsync` the temp file's data,
/// 3. call `verify(tmp)` — a chance to confirm the bytes round-trip *before*
///    we touch the existing file (we never destroy the only good copy),
/// 4. atomically `rename` the temp over `path`, then
/// 5. `fsync` the directory so the rename itself survives a power loss.
///
/// On any failure before step 4 the previous file is untouched and the temp is
/// removed. Same-directory temp guarantees the rename is atomic (same fs).
fn write_private(
    path: &Path,
    bytes: &[u8],
    verify: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    use std::io::Write;

    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let stem = path.file_name().and_then(|n| n.to_str()).unwrap_or("vault");
    // Per-process temp name so two writers (or a stale crash leftover) can't
    // clobber each other's in-flight file.
    let tmp_name = format!(".{stem}.{}.tmp", std::process::id());
    let tmp = match parent {
        Some(d) => d.join(&tmp_name),
        None => std::path::PathBuf::from(&tmp_name),
    };
    let mut guard = TmpGuard {
        path: tmp.clone(),
        armed: true,
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

    // Confirm the new file is good *before* replacing the old one.
    verify(&tmp).context("refusing to commit: the newly written vault file did not verify")?;

    std::fs::rename(&tmp, path)
        .with_context(|| format!("failed to move temp file into place at {}", path.display()))?;
    guard.disarm(); // the temp no longer exists under its old name

    // Make the rename durable: without fsyncing the directory, a crash right
    // after the rename can lose the new directory entry. Best-effort — the data
    // is already safely in place, so a dir-fsync failure shouldn't fail the save.
    if let Some(dir) = parent
        && let Ok(df) = std::fs::File::open(dir)
    {
        let _ = df.sync_all();
    }
    Ok(())
}
