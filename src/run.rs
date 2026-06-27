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
///
/// Unless `quiet`, a one-time caution is printed to stderr first: secrets handed
/// to a program via its environment are readable by any same-uid process through
/// `/proc/<pid>/environ` for the program's lifetime, and this is inherent to env
/// injection (a child's own `exec` resets its dumpable bit, so it can't be
/// hidden). For tools that can read a secret from a file, `dir run` avoids this.
pub fn run(vault: &EnvVault, program: &str, args: &[String], quiet: bool) -> Result<()> {
    if !quiet {
        eprintln!(
            "note: 'run' places these secrets in the program's environment; any process\n      \
             running as you can read them via /proc/<pid>/environ while it runs.\n      \
             For tools that read a secret from a file, prefer 'envvault dir run'.\n      \
             (silence: --quiet or ENVVAULT_QUIET=1)"
        );
    }

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
