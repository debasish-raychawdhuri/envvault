//! Password acquisition: interactive no-echo prompts, or stdin for scripting.
//! The returned password is wrapped in `Zeroizing` so it is wiped on drop.

use anyhow::{bail, Context, Result};
use std::io::{BufRead, IsTerminal};
use zeroize::Zeroizing;

/// Read a password from stdin (one line, trailing newline stripped). Used for
/// `--password-stdin` in non-interactive/scripted contexts.
pub fn read_stdin() -> Result<Zeroizing<String>> {
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("failed to read password from stdin")?;
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(Zeroizing::new(line))
}

/// Prompt for an existing password (single entry, no echo).
pub fn prompt(prompt_text: &str) -> Result<Zeroizing<String>> {
    require_tty()?;
    let pw = rpassword::prompt_password(prompt_text).context("failed to read password")?;
    Ok(Zeroizing::new(pw))
}

/// Prompt for a secret value with no echo. Used by `set` so the value never
/// appears in argv, shell history, or `/proc/<pid>/cmdline` the way a
/// command-line argument would.
pub fn prompt_value(key: &str) -> Result<Zeroizing<String>> {
    require_tty()?;
    let value = rpassword::prompt_password(format!("Value for {key}: "))
        .context("failed to read value")?;
    Ok(Zeroizing::new(value))
}

/// Prompt for a new password twice and require the two entries to match.
pub fn prompt_new() -> Result<Zeroizing<String>> {
    require_tty()?;
    let first = rpassword::prompt_password("New vault password: ")
        .context("failed to read password")?;
    if first.is_empty() {
        bail!("password cannot be empty");
    }
    let confirm = rpassword::prompt_password("Confirm password: ")
        .context("failed to read password")?;
    if first != confirm {
        bail!("passwords did not match");
    }
    Ok(Zeroizing::new(first))
}

fn require_tty() -> Result<()> {
    if !std::io::stdin().is_terminal() {
        bail!("no interactive terminal for password entry; use --password-stdin");
    }
    Ok(())
}
