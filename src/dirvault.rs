//! Directory and single-file vaults: keep a directory — or one file marooned in
//! a large directory (e.g. a tool's `auth.json` next to a multi-GB database) —
//! encrypted at rest, exposing its plaintext only in memory.
//!
//! The plaintext is a small container — magic, a kind byte (dir vs file), the
//! embedded canonical target path, then a tar archive — encrypted with the same
//! [`crate::crypto`] primitives used for env-var vaults (Argon2id +
//! ChaCha20-Poly1305). Embedding the path inside the *encrypted* plaintext keeps
//! it off disk in cleartext while letting `dir run` re-mount at the original
//! location.

use crate::crypto::{self, Session};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Container magic (4 bytes), followed by a kind byte, path length, path, tar.
const CONTAINER_MAGIC: &[u8; 4] = b"EVD1";

/// Refuse archives larger than this, to bound the tmpfs a `dir run` mounts and
/// to reject absurd inputs. 256 MiB is far more than any credential directory.
const MAX_ARCHIVE: usize = 256 * 1024 * 1024;

/// What a vault holds: a whole directory, or a single file.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Dir,
    File,
}

impl Kind {
    fn to_byte(self) -> u8 {
        match self {
            Kind::Dir => 0,
            Kind::File => 1,
        }
    }

    fn from_byte(b: u8) -> Result<Self> {
        match b {
            0 => Ok(Kind::Dir),
            1 => Ok(Kind::File),
            other => bail!("unknown vault kind byte {other}"),
        }
    }
}

/// An opened vault: the crypto session (held so we can re-encrypt under the same
/// salt/key without re-prompting), the kind, the embedded target path, and the
/// decrypted container bytes (wiped on drop).
pub struct DirVault {
    session: Session,
    kind: Kind,
    target: PathBuf,
    plaintext: Zeroizing<Vec<u8>>,
}

/// Archive `source` (a dir or a single file, per `kind`) and wrap it with the
/// magic + kind + `embed_path` header into one plaintext container.
fn pack(kind: Kind, embed_path: &Path, source: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let path_str = embed_path
        .to_str()
        .context("target path is not valid UTF-8")?;
    let path_bytes = path_str.as_bytes();
    if path_bytes.len() > u16::MAX as usize {
        bail!("target path is too long");
    }

    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(CONTAINER_MAGIC);
    blob.push(kind.to_byte());
    blob.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
    blob.extend_from_slice(path_bytes);
    {
        let mut builder = tar::Builder::new(&mut blob);
        builder.follow_symlinks(false); // store symlinks as links, don't chase them
        match kind {
            Kind::Dir => builder
                .append_dir_all(".", source)
                .with_context(|| format!("failed to archive {}", source.display()))?,
            Kind::File => {
                let name = source
                    .file_name()
                    .context("vaulted file has no file name")?;
                builder
                    .append_path_with_name(source, name)
                    .with_context(|| format!("failed to archive {}", source.display()))?;
            }
        }
        builder.finish().context("failed to finalize archive")?;
    }
    if blob.len() > MAX_ARCHIVE {
        bail!("target is too large to vault (> {} bytes)", MAX_ARCHIVE);
    }
    Ok(Zeroizing::new(blob))
}

/// Parse a plaintext container into (kind, embedded target path, tar slice).
fn unpack(blob: &[u8]) -> Result<(Kind, PathBuf, &[u8])> {
    // magic[4] + kind[1] + path_len[2]
    if blob.len() < 7 || &blob[..4] != CONTAINER_MAGIC {
        bail!("not a valid vault (bad header)");
    }
    let kind = Kind::from_byte(blob[4])?;
    let path_len = u16::from_le_bytes([blob[5], blob[6]]) as usize;
    let rest = &blob[7..];
    if rest.len() < path_len {
        bail!("vault is truncated");
    }
    let path_str =
        std::str::from_utf8(&rest[..path_len]).context("embedded target path is invalid UTF-8")?;
    let tar_bytes = &rest[path_len..];
    Ok((kind, PathBuf::from(path_str), tar_bytes))
}

/// Create a new vault at `path`: archive `canonical_target` (a directory or a
/// single file, auto-detected), encrypt under `password`, and write the file.
pub fn create(path: &Path, password: &[u8], canonical_target: &Path) -> Result<()> {
    let kind = if canonical_target.is_dir() {
        Kind::Dir
    } else {
        Kind::File
    };
    let blob = pack(kind, canonical_target, canonical_target)?;
    let session = Session::create(password)?;
    session.save(path, &blob)?;
    Ok(())
}

/// Open an existing vault: decrypt and parse out the kind and target path.
///
/// Opportunistically upgrades a legacy (v1) vault to the current (v2) Argon2id
/// parameters while the password is in hand. Best-effort: if the re-save fails
/// (e.g. a read-only vault directory) we keep using the legacy session so opens
/// never break — `dir upgrade` can retry when writable.
pub fn open(path: &Path, password: &[u8]) -> Result<DirVault> {
    let (mut session, plaintext) = crypto::open(path, password)?;
    let (kind, target, _tar) = unpack(&plaintext)?;
    if !session.is_current() {
        match Session::create(password).and_then(|v2| v2.save(path, &plaintext).map(|()| v2)) {
            Ok(v2) => {
                eprintln!(
                    "note: upgraded directory vault to v2 (Argon2id m=64 MiB, t=3); \
                     password unchanged"
                );
                session = v2;
            }
            Err(e) => eprintln!(
                "warning: could not upgrade directory vault to v2 ({e:#}); continuing with \
                 legacy parameters"
            ),
        }
    }
    Ok(DirVault {
        session,
        kind,
        target,
        plaintext,
    })
}

impl DirVault {
    /// The original path this vault was created from.
    pub fn target(&self) -> &Path {
        &self.target
    }

    /// Whether this vault holds a directory or a single file.
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// Whether the underlying crypto session uses the current (v2) Argon2id
    /// parameters. A `false` result means the vault was created under the
    /// legacy v1 defaults and can be re-keyed with `dir upgrade`.
    pub fn is_current(&self) -> bool {
        self.session.is_current()
    }

    /// The decrypted container plaintext (magic + kind + path + tar), wiped on
    /// drop. Used by `dir upgrade` to re-encrypt under a fresh v2 session.
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    /// Extract the archived contents into `dest`, preserving modes and symlinks.
    /// For a directory vault the tree lands directly under `dest`; for a file
    /// vault the single file lands at `dest/<basename>`. The `tar` crate rejects
    /// absolute paths and `..` traversal during `unpack`.
    pub fn extract_into(&self, dest: &Path) -> Result<()> {
        let (_kind, _t, tar_bytes) = unpack(&self.plaintext)?;
        let mut archive = tar::Archive::new(tar_bytes);
        archive.set_preserve_permissions(true);
        archive.set_preserve_mtime(true);
        archive.set_overwrite(true);
        archive
            .unpack(dest)
            .with_context(|| format!("failed to extract into {}", dest.display()))?;
        Ok(())
    }

    /// Re-archive `source` (the live directory or file) and re-encrypt to `path`
    /// under the original session (same salt/key, fresh nonce). Used after a
    /// `dir run` child exits, and by the debounced autosaver.
    pub fn save_from(&self, path: &Path, source: &Path) -> Result<()> {
        let blob = pack(self.kind, &self.target, source)?;
        self.session.save(path, &blob)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_dir_contents_modes_and_symlink() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;

        let base = std::env::temp_dir().join("envvault-dv-rt");
        let src = base.join("src");
        let out = base.join("out");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&src).unwrap();

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
        assert_eq!(dv.kind(), Kind::Dir);
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
    fn round_trips_single_file() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;

        let base = std::env::temp_dir().join("envvault-dv-file");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let secret = base.join("auth.json");
        std::fs::write(&secret, b"{\"token\":\"abc\"}").unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();

        let path = base.join("v.dirvault");
        let canonical = secret.canonicalize().unwrap();
        create(&path, b"pw", &canonical).unwrap();

        let dv = open(&path, b"pw").unwrap();
        assert_eq!(dv.kind(), Kind::File);
        assert_eq!(dv.target(), canonical.as_path());

        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        dv.extract_into(&out).unwrap();
        assert_eq!(
            std::fs::read(out.join("auth.json")).unwrap(),
            b"{\"token\":\"abc\"}"
        );
        #[cfg(unix)]
        {
            let mode = std::fs::metadata(out.join("auth.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "file mode should be preserved");
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
    fn rejects_non_vault_bytes() {
        assert!(unpack(b"nope").is_err());
        assert!(unpack(b"EVD1").is_err()); // header but no kind/length
    }
}
