//! Launch a target program with the vault's variables merged into its
//! environment. The decrypted values live only in this process's memory and
//! are handed directly to the child — they never touch disk.

use crate::vault::EnvVault;
use anyhow::{Context, Result};
use std::process::Command;

/// Run `program args...` with `vault`'s entries added to the current
/// environment. On unix this replaces the current process (exec) so the
/// process tree stays clean and signals pass straight through; on other
/// platforms it spawns a child and propagates its exit code.
pub fn run(vault: &EnvVault, program: &str, args: &[String]) -> Result<()> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    for e in vault.entries() {
        cmd.env(&e.key, &e.value);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // On success this never returns; reaching past it means exec failed.
        let err = cmd.exec();
        Err(err).with_context(|| format!("failed to execute '{program}'"))
    }

    #[cfg(not(unix))]
    {
        let status = cmd
            .status()
            .with_context(|| format!("failed to execute '{program}'"))?;
        match status.code() {
            Some(0) => Ok(()),
            Some(code) => std::process::exit(code),
            None => anyhow::bail!("'{program}' terminated by signal"),
        }
    }
}
