//! Directory vaults: keep a whole directory (e.g. a tool's config dir that
//! stores API keys) encrypted at rest, exposing its plaintext only in memory.
//!
//! The plaintext is a small container — magic, the embedded canonical target
//! path, then a tar archive of the directory tree — encrypted with the same
//! [`crate::crypto`] primitives used for env-var vaults (Argon2id +
//! ChaCha20-Poly1305). Embedding the path inside the *encrypted* plaintext
//! keeps it off disk in cleartext while letting `dir run` re-mount at the
//! original location.

use crate::crypto::{self, Session};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Container magic (4 bytes) prefixing the embedded path + tar archive.
const CONTAINER_MAGIC: &[u8; 4] = b"EVD1";

/// Refuse archives larger than this, to bound the tmpfs a `dir run` mounts and
/// to reject absurd inputs. 256 MiB is far more than any credential directory.
const MAX_ARCHIVE: usize = 256 * 1024 * 1024;

/// An opened directory vault: the crypto session (held so we can re-encrypt
/// under the same salt/key without re-prompting), the embedded target path,
/// and the decrypted container bytes (wiped on drop).
pub struct DirVault {
    session: Session,
    target: PathBuf,
    plaintext: Zeroizing<Vec<u8>>,
}

/// Tar `archive_dir`'s contents and wrap them with the magic + `embed_path`
/// header into a single plaintext container (wiped on drop).
fn pack(embed_path: &Path, archive_dir: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let path_str = embed_path
        .to_str()
        .context("target path is not valid UTF-8")?;
    let path_bytes = path_str.as_bytes();
    if path_bytes.len() > u16::MAX as usize {
        bail!("target path is too long");
    }

    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(CONTAINER_MAGIC);
    blob.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
    blob.extend_from_slice(path_bytes);
    {
        let mut builder = tar::Builder::new(&mut blob);
        builder.follow_symlinks(false); // store symlinks as links, don't chase them
        builder
            .append_dir_all(".", archive_dir)
            .with_context(|| format!("failed to archive {}", archive_dir.display()))?;
        builder.finish().context("failed to finalize archive")?;
    }
    if blob.len() > MAX_ARCHIVE {
        bail!("directory is too large to vault (> {} bytes)", MAX_ARCHIVE);
    }
    Ok(Zeroizing::new(blob))
}

/// Parse a plaintext container into (embedded target path, tar-archive slice).
fn unpack(blob: &[u8]) -> Result<(PathBuf, &[u8])> {
    if blob.len() < CONTAINER_MAGIC.len() + 2 || &blob[..4] != CONTAINER_MAGIC {
        bail!("not a valid directory vault (bad header)");
    }
    let path_len = u16::from_le_bytes([blob[4], blob[5]]) as usize;
    let rest = &blob[6..];
    if rest.len() < path_len {
        bail!("directory vault is truncated");
    }
    let path_str =
        std::str::from_utf8(&rest[..path_len]).context("embedded target path is invalid UTF-8")?;
    let tar_bytes = &rest[path_len..];
    Ok((PathBuf::from(path_str), tar_bytes))
}

/// Create a new directory vault at `path`: archive `canonical_target`'s
/// contents (embedding its path), encrypt under `password`, and write the file.
pub fn create(path: &Path, password: &[u8], canonical_target: &Path) -> Result<()> {
    let blob = pack(canonical_target, canonical_target)?;
    let session = Session::create(password)?;
    session.save(path, &blob)?;
    Ok(())
}

/// Open an existing directory vault: decrypt and parse out the target path.
pub fn open(path: &Path, password: &[u8]) -> Result<DirVault> {
    let (session, plaintext) = crypto::open(path, password)?;
    let (target, _tar) = unpack(&plaintext)?;
    Ok(DirVault {
        session,
        target,
        plaintext,
    })
}

impl DirVault {
    /// The original directory this vault was created from (where `dir run`
    /// exposes the decrypted contents).
    pub fn target(&self) -> &Path {
        &self.target
    }

    /// Extract the archived contents into `dest` (which should already exist,
    /// e.g. the freshly mounted tmpfs), preserving modes and symlinks. The
    /// `tar` crate rejects absolute paths and `..` traversal during `unpack`.
    pub fn extract_into(&self, dest: &Path) -> Result<()> {
        let (_t, tar_bytes) = unpack(&self.plaintext)?;
        let mut archive = tar::Archive::new(tar_bytes);
        archive.set_preserve_permissions(true);
        archive.set_preserve_mtime(true);
        archive.set_overwrite(true);
        archive
            .unpack(dest)
            .with_context(|| format!("failed to extract into {}", dest.display()))?;
        Ok(())
    }

    /// Re-archive `dir`'s current contents and re-encrypt to `path` under the
    /// original session (same salt/key, fresh nonce). Used after a `dir run`
    /// child exits to persist whatever it changed.
    pub fn save_from(&self, path: &Path, dir: &Path) -> Result<()> {
        let blob = pack(&self.target, dir)?;
        self.session.save(path, &blob)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_contents_modes_and_symlink() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;

        let base = std::env::temp_dir().join("envvault-dv-rt");
        let src = base.join("src");
        let out = base.join("out");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&src).unwrap();

        // A secret file with 0600 mode, a nested dir, and an internal symlink.
        let secret = src.join("creds.json");
        std::fs::write(&secret, b"{\"key\":\"sk-123\"}").unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("sub/inner"), b"inner").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("creds.json", src.join("link")).unwrap();

        let path = base.join("v.dirvault");
        let canonical = src.canonicalize().unwrap();
        create(&path, b"pw", &canonical).unwrap();

        let dv = open(&path, b"pw").unwrap();
        assert_eq!(dv.target(), canonical.as_path());

        std::fs::create_dir_all(&out).unwrap();
        dv.extract_into(&out).unwrap();

        assert_eq!(
            std::fs::read(out.join("creds.json")).unwrap(),
            b"{\"key\":\"sk-123\"}"
        );
        assert_eq!(std::fs::read(out.join("sub/inner")).unwrap(), b"inner");
        #[cfg(unix)]
        {
            let mode = std::fs::metadata(out.join("creds.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "file mode should be preserved");
            let link = std::fs::symlink_metadata(out.join("link")).unwrap();
            assert!(link.file_type().is_symlink(), "symlink should be preserved");
        }

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn wrong_password_fails_to_open() {
        let base = std::env::temp_dir().join("envvault-dv-wp");
        let src = base.join("src");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("f"), b"x").unwrap();

        let path = base.join("v.dirvault");
        create(&path, b"right", &src.canonicalize().unwrap()).unwrap();
        assert!(open(&path, b"wrong").is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn rejects_non_dirvault_bytes() {
        assert!(unpack(b"nope").is_err());
        assert!(unpack(b"EVD1").is_err()); // header but no length
    }
}
