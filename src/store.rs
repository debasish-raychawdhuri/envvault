//! Where vaults live: a fixed per-user directory holding one encrypted file
//! per named vault (`<name>.vault`). Resolves names to paths, lists vaults,
//! and creates the directory with owner-only permissions on first use.

use anyhow::{bail, Context, Result};
use std::path::PathBuf;

const VAULT_EXT: &str = "vault";

/// The directory that holds all vaults. Overridable with `$ENVVAULT_DIR`;
/// otherwise `<config-dir>/envvault` (e.g. `~/.config/envvault` on Linux).
pub fn vault_dir() -> Result<PathBuf> {
    if let Some(custom) = std::env::var_os("ENVVAULT_DIR") {
        return Ok(PathBuf::from(custom));
    }
    let base = dirs::config_dir()
        .context("could not determine your config directory; set $ENVVAULT_DIR")?;
    Ok(base.join("envvault"))
}

/// Like [`vault_dir`], but creates the directory (0700 on unix) if missing.
pub fn ensure_vault_dir() -> Result<PathBuf> {
    let dir = vault_dir()?;
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create vault directory {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(dir)
}

/// Resolve a vault name to its file path inside the vault directory.
pub fn vault_path(name: &str) -> Result<PathBuf> {
    validate_name(name)?;
    Ok(ensure_vault_dir()?.join(format!("{name}.{VAULT_EXT}")))
}

/// Names of all vaults present in the vault directory, sorted.
pub fn list_vaults() -> Result<Vec<String>> {
    let dir = vault_dir()?;
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for entry in std::fs::read_dir(&dir)
        .with_context(|| format!("failed to read vault directory {}", dir.display()))?
    {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) == Some(VAULT_EXT)
            && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
        {
            names.push(stem.to_string());
        }
    }
    names.sort();
    Ok(names)
}

/// A vault name must be a single safe path component: letters, digits, `.`,
/// `_`, `-` only, and not `.`/`..` (so it can't escape the vault directory).
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("vault name cannot be empty");
    }
    if name == "." || name == ".." {
        bail!("invalid vault name");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        bail!("vault name may only contain letters, digits, '.', '_', and '-'");
    }
    Ok(())
}
