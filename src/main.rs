//! envvault — store environment variables in password-encrypted vaults and run
//! programs with those variables set, without ever leaving secrets in your
//! shell, shell history, or on disk in plaintext.
//!
//! Vaults are named and live in a fixed per-user directory
//! (`$ENVVAULT_DIR`, else `<config-dir>/envvault`), one encrypted file each.

mod crypto;
mod dirvault;
mod harden;
mod password;
mod run;
mod sandbox;
mod store;
mod tui;
mod vault;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use crypto::Session;
use std::io::IsTerminal;
use std::path::Path;
use vault::EnvVault;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "envvault",
    version,
    about = "Run programs with secrets from password-encrypted, named environment vaults"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new named vault (then open it for editing).
    Init {
        /// Name of the vault to create.
        name: String,
        /// Read the password from stdin instead of prompting.
        #[arg(long)]
        password_stdin: bool,
        /// Don't open the interactive editor after creating.
        #[arg(long)]
        no_edit: bool,
    },
    /// Edit a vault's secrets interactively (view / add / modify / delete).
    Edit {
        name: String,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Change a vault's password, re-encrypting its contents under the new one.
    Passwd {
        name: String,
    },
    /// Rename a vault.
    Rename {
        old: String,
        new: String,
    },
    /// Decrypt in memory and run a program with the vault's secrets in its env.
    Run {
        name: String,
        #[arg(long)]
        password_stdin: bool,
        /// Suppress the environment-exposure warning (also via ENVVAULT_QUIET=1).
        #[arg(long, short)]
        quiet: bool,
        /// Linux only: keep the secrets out of /proc/<pid>/environ by preloading
        /// a shim that marks the program non-dumpable and receives the secrets
        /// over a pipe after it is safe. Fails closed if the shim can't load
        /// (e.g. a static or setuid binary).
        #[arg(long)]
        harden: bool,
        /// The program to run, followed by its arguments (use `--` first).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true, num_args = 1..)]
        command: Vec<String>,
    },
    /// Add or update one or more keys; prompts (no echo) for each value.
    Set {
        name: String,
        /// Key names to set. The value for each is entered at a no-echo prompt,
        /// so it never appears in argv, shell history, or /proc/<pid>/cmdline.
        #[arg(required = true, num_args = 1..)]
        keys: Vec<String>,
    },
    /// Remove one or more keys from a vault non-interactively.
    Rm {
        name: String,
        /// Keys to remove (repeatable).
        #[arg(required = true, num_args = 1..)]
        keys: Vec<String>,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Print a vault's decrypted KEY=VALUE pairs to stdout (exposes secrets!).
    Show {
        name: String,
        #[arg(long)]
        password_stdin: bool,
    },
    /// List all vaults in the vault directory.
    List,
    /// Manage directory vaults: keep a tool's config dir (e.g. ~/.claude)
    /// encrypted at rest, decrypted only in RAM while a program runs.
    Dir {
        #[command(subcommand)]
        command: DirCmd,
    },
}

#[derive(Subcommand)]
enum DirCmd {
    /// Encrypt a directory — or a single file — into a vault, then empty it.
    Init {
        /// Name for the new vault.
        name: String,
        /// Directory or file to encrypt (e.g. ~/.claude, or one file like
        /// ~/.local/share/opencode/auth.json that sits in a large directory).
        #[arg(long)]
        path: String,
        /// Skip the confirmation prompt before emptying the directory.
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Decrypt into RAM at the original path, run a program, re-encrypt on exit.
    Run {
        name: String,
        #[arg(long)]
        password_stdin: bool,
        /// Don't re-encrypt while the program runs (only on exit).
        #[arg(long)]
        no_autosave: bool,
        /// Seconds the directory must be unchanged before an autosave fires.
        #[arg(long, default_value_t = 2)]
        autosave_debounce: u64,
        /// The program to run, followed by its arguments (use `--` first).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true, num_args = 1..)]
        command: Vec<String>,
    },
    /// List all directory vaults.
    List,
    /// Print a directory vault's stored target path.
    Status {
        name: String,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Decrypt a directory vault's contents into a directory (writes plaintext!).
    Export {
        name: String,
        /// Destination directory (created if missing).
        #[arg(long)]
        to: String,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Rename a directory vault.
    Rename {
        old: String,
        new: String,
    },
    /// Delete a directory vault file (its encrypted contents are lost).
    Rm {
        name: String,
    },
}

fn main() {
    // Mark the process non-dumpable before any secret or password can enter
    // memory, so a same-uid attacker can't core-dump or ptrace it to read them.
    harden::protect_process();
    if let Err(e) = run_cli() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run_cli() -> Result<()> {
    match Cli::parse().command {
        Cmd::Init {
            name,
            password_stdin,
            no_edit,
        } => cmd_init(&name, password_stdin, no_edit),
        Cmd::Edit {
            name,
            password_stdin,
        } => cmd_edit(&name, password_stdin),
        Cmd::Passwd { name } => cmd_passwd(&name),
        Cmd::Rename { old, new } => cmd_rename(&old, &new),
        Cmd::Run {
            name,
            password_stdin,
            quiet,
            harden,
            command,
        } => cmd_run(&name, password_stdin, quiet, harden, &command),
        Cmd::Set { name, keys } => cmd_set(&name, &keys),
        Cmd::Rm {
            name,
            keys,
            password_stdin,
        } => cmd_rm(&name, &keys, password_stdin),
        Cmd::Show {
            name,
            password_stdin,
        } => cmd_show(&name, password_stdin),
        Cmd::List => cmd_list(),
        Cmd::Dir { command } => run_dir(command),
    }
}

fn run_dir(command: DirCmd) -> Result<()> {
    match command {
        DirCmd::Init {
            name,
            path,
            yes,
            password_stdin,
        } => cmd_dir_init(&name, &path, yes, password_stdin),
        DirCmd::Run {
            name,
            password_stdin,
            no_autosave,
            autosave_debounce,
            command,
        } => cmd_dir_run(&name, password_stdin, no_autosave, autosave_debounce, &command),
        DirCmd::List => cmd_dir_list(),
        DirCmd::Status {
            name,
            password_stdin,
        } => cmd_dir_status(&name, password_stdin),
        DirCmd::Export {
            name,
            to,
            password_stdin,
        } => cmd_dir_export(&name, &to, password_stdin),
        DirCmd::Rename { old, new } => cmd_dir_rename(&old, &new),
        DirCmd::Rm { name } => cmd_dir_rm(&name),
    }
}

/// Acquire a password for opening an existing vault.
fn get_password(password_stdin: bool) -> Result<Zeroizing<String>> {
    if password_stdin {
        password::read_stdin()
    } else {
        password::prompt("Vault password: ")
    }
}

/// Resolve a vault name to its file path, erroring (with the list of available
/// vaults) if it does not exist yet.
fn resolve_existing(name: &str) -> Result<std::path::PathBuf> {
    let path = store::vault_path(name)?;
    if !path.exists() {
        let available = store::list_vaults()?;
        if available.is_empty() {
            bail!("no vault named '{name}' (no vaults exist yet — create one with `envvault init {name}`)");
        }
        bail!(
            "no vault named '{name}'. Available: {}",
            available.join(", ")
        );
    }
    Ok(path)
}

/// Open an existing vault and parse its contents into the editable model.
fn open_vault(path: &Path, password_stdin: bool) -> Result<(Session, EnvVault)> {
    let pw = get_password(password_stdin)?;
    let (session, plaintext) = crypto::open(path, pw.as_bytes())?;
    let text = std::str::from_utf8(&plaintext).context("vault contains invalid UTF-8")?;
    Ok((session, EnvVault::parse(text)))
}

fn cmd_init(name: &str, password_stdin: bool, no_edit: bool) -> Result<()> {
    let path = store::vault_path(name)?;
    if path.exists() {
        bail!("a vault named '{name}' already exists — refusing to overwrite");
    }
    let pw = if password_stdin {
        password::read_stdin()?
    } else {
        password::prompt_new()?
    };
    let session = Session::create(pw.as_bytes())?;
    let vault = EnvVault::default();
    session.save(&path, vault.serialize().as_bytes())?;
    println!("Created vault '{name}' at {}", path.display());

    // Drop straight into the editor unless suppressed or non-interactive.
    if !no_edit && !password_stdin && std::io::stdin().is_terminal() {
        tui::run(&session, &path, vault)?;
    }
    Ok(())
}

fn cmd_edit(name: &str, password_stdin: bool) -> Result<()> {
    let path = resolve_existing(name)?;
    let (session, vault) = open_vault(&path, password_stdin)?;
    tui::run(&session, &path, vault)
}

fn cmd_passwd(name: &str) -> Result<()> {
    let path = resolve_existing(name)?;
    // Verify the current password by actually decrypting with it.
    let old_pw = password::prompt("Current vault password: ")?;
    let (_old_session, plaintext) = crypto::open(&path, old_pw.as_bytes())?;
    // Acquire and confirm the new password, then re-encrypt the same contents
    // under a fresh salt + key (Session::create generates a new salt).
    let new_pw = password::prompt_new()?;
    let new_session = Session::create(new_pw.as_bytes())?;
    new_session.save(&path, &plaintext)?;
    println!("Password changed for vault '{name}'");
    Ok(())
}

fn cmd_rename(old: &str, new: &str) -> Result<()> {
    let old_path = resolve_existing(old)?;
    let new_path = store::vault_path(new)?; // also validates the new name
    if new_path.exists() {
        bail!("a vault named '{new}' already exists — refusing to overwrite");
    }
    std::fs::rename(&old_path, &new_path)
        .with_context(|| format!("failed to rename vault '{old}' to '{new}'"))?;
    println!("Renamed vault '{old}' to '{new}'");
    Ok(())
}

fn cmd_run(
    name: &str,
    password_stdin: bool,
    quiet: bool,
    harden: bool,
    command: &[String],
) -> Result<()> {
    let path = resolve_existing(name)?;
    let (_session, vault) = open_vault(&path, password_stdin)?;
    let (program, args) = command
        .split_first()
        .expect("clap guarantees at least one element");
    let quiet = quiet || std::env::var_os("ENVVAULT_QUIET").is_some();
    run::run(&vault, program, args, quiet, harden)
}

// --- directory vaults -----------------------------------------------------

/// Resolve a directory-vault name to its file path, erroring (with the list of
/// available directory vaults) if it does not exist yet.
fn resolve_existing_dirvault(name: &str) -> Result<std::path::PathBuf> {
    let path = store::dirvault_path(name)?;
    if !path.exists() {
        let available = store::list_dirvaults()?;
        if available.is_empty() {
            bail!("no directory vault named '{name}' (create one with `envvault dir init {name} --path <dir>`)");
        }
        bail!(
            "no directory vault named '{name}'. Available: {}",
            available.join(", ")
        );
    }
    Ok(path)
}

/// Delete everything inside `dir` but keep `dir` itself, so it stays a valid
/// mountpoint for `dir run`.
fn empty_dir(dir: &Path) -> Result<()> {
    for entry in
        std::fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))?
    {
        let path = entry?.path();
        let meta = std::fs::symlink_metadata(&path)?;
        if meta.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        }
        .with_context(|| format!("failed to remove {}", path.display()))?;
    }
    Ok(())
}

fn cmd_dir_init(name: &str, path: &str, yes: bool, password_stdin: bool) -> Result<()> {
    let vault_path = store::dirvault_path(name)?;
    if vault_path.exists() {
        bail!("a vault named '{name}' already exists — refusing to overwrite");
    }
    let target = Path::new(path);
    if !target.exists() {
        bail!("{} does not exist", target.display());
    }
    let canonical = target
        .canonicalize()
        .with_context(|| format!("could not resolve {}", target.display()))?;
    let meta = std::fs::symlink_metadata(&canonical)?;
    let is_dir = meta.is_dir();
    if !is_dir && !meta.is_file() {
        bail!(
            "{} is neither a regular file nor a directory",
            canonical.display()
        );
    }

    // Emptying the target is destructive — confirm unless told not to.
    if !yes {
        if password_stdin {
            bail!(
                "refusing to empty {} without confirmation; pass --yes",
                canonical.display()
            );
        }
        let what = if is_dir {
            "DELETE its contents"
        } else {
            "empty the file"
        };
        eprint!(
            "This will encrypt {} into vault '{name}' and then {what}. Continue? [y/N] ",
            canonical.display()
        );
        use std::io::Write;
        std::io::stderr().flush().ok();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        if !matches!(line.trim(), "y" | "Y" | "yes") {
            bail!("aborted");
        }
    }

    let pw = if password_stdin {
        password::read_stdin()?
    } else {
        password::prompt_new()?
    };
    dirvault::create(&vault_path, pw.as_bytes(), &canonical)?;
    if is_dir {
        empty_dir(&canonical)?;
    } else {
        // Leave a 0-byte placeholder so the path stays a valid bind target.
        std::fs::write(&canonical, b"")
            .with_context(|| format!("failed to empty {}", canonical.display()))?;
    }
    let kind = if is_dir { "directory" } else { "file" };
    println!(
        "Created {kind} vault '{name}' from {} and emptied it.\n\
         Use it with: envvault dir run {name} -- <command>",
        canonical.display()
    );
    Ok(())
}

fn cmd_dir_run(
    name: &str,
    password_stdin: bool,
    no_autosave: bool,
    autosave_debounce: u64,
    command: &[String],
) -> Result<()> {
    let vault_path = resolve_existing_dirvault(name)?;
    let (program, args) = command
        .split_first()
        .expect("clap guarantees at least one element");
    let autosave = if no_autosave {
        None
    } else {
        Some(std::time::Duration::from_secs(autosave_debounce))
    };
    // The vault is opened (password prompt + decrypt) by this closure, which
    // `sandbox::run` calls only after setting up the namespace and re-hardening
    // the process — so no secret exists during the brief dumpable window.
    sandbox::run(&vault_path, program, args, autosave, || {
        let pw = get_password(password_stdin)?;
        dirvault::open(&vault_path, pw.as_bytes())
    })
}

fn cmd_dir_list() -> Result<()> {
    let vaults = store::list_dirvaults()?;
    if vaults.is_empty() {
        println!("No directory vaults yet. Create one with `envvault dir init <name> --path <dir>`.");
    } else {
        for name in vaults {
            println!("{name}");
        }
    }
    Ok(())
}

fn cmd_dir_status(name: &str, password_stdin: bool) -> Result<()> {
    let vault_path = resolve_existing_dirvault(name)?;
    let pw = get_password(password_stdin)?;
    let dv = dirvault::open(&vault_path, pw.as_bytes())?;
    let kind = match dv.kind() {
        dirvault::Kind::Dir => "directory",
        dirvault::Kind::File => "file",
    };
    println!("{name}: {kind} {}", dv.target().display());
    Ok(())
}

fn cmd_dir_export(name: &str, to: &str, password_stdin: bool) -> Result<()> {
    let vault_path = resolve_existing_dirvault(name)?;
    let pw = get_password(password_stdin)?;
    let dv = dirvault::open(&vault_path, pw.as_bytes())?;
    let dest = Path::new(to);
    std::fs::create_dir_all(dest)
        .with_context(|| format!("failed to create {}", dest.display()))?;
    dv.extract_into(dest)?;
    println!(
        "Exported '{name}' to {} (WARNING: this wrote the decrypted contents to disk).",
        dest.display()
    );
    Ok(())
}

fn cmd_dir_rename(old: &str, new: &str) -> Result<()> {
    let old_path = resolve_existing_dirvault(old)?;
    let new_path = store::dirvault_path(new)?; // also validates the new name
    if new_path.exists() {
        bail!("a directory vault named '{new}' already exists — refusing to overwrite");
    }
    std::fs::rename(&old_path, &new_path)
        .with_context(|| format!("failed to rename directory vault '{old}' to '{new}'"))?;
    println!("Renamed directory vault '{old}' to '{new}'");
    Ok(())
}

fn cmd_dir_rm(name: &str) -> Result<()> {
    let vault_path = resolve_existing_dirvault(name)?;
    std::fs::remove_file(&vault_path)
        .with_context(|| format!("failed to remove {}", vault_path.display()))?;
    println!("Removed directory vault '{name}'");
    Ok(())
}

fn cmd_set(name: &str, keys: &[String]) -> Result<()> {
    let path = resolve_existing(name)?;
    // Validate every key name before prompting, so a typo fails fast without
    // asking for the vault password or any values.
    for key in keys {
        vault::validate_key(key)?;
    }
    let (session, mut vault) = open_vault(&path, false)?;
    // Secret values are pasted, not typed, so wipe the system clipboard after
    // each one is entered. The handle is held across the loop so the emptied
    // selection keeps being served on X11; `None` if no clipboard is reachable
    // (e.g. headless / SSH without a display).
    let mut clipboard = arboard::Clipboard::new().ok();
    for key in keys {
        let value = password::prompt_value(key)?;
        vault.set(key, &value);
        if let Some(cb) = clipboard.as_mut() {
            let _ = cb.clear();
        }
    }
    session.save(&path, vault.serialize().as_bytes())?;
    let cleared = if clipboard.is_some() {
        " — clipboard cleared"
    } else {
        ""
    };
    println!(
        "Updated {} entr{}{cleared}",
        keys.len(),
        if keys.len() == 1 { "y" } else { "ies" }
    );
    Ok(())
}

fn cmd_rm(name: &str, keys: &[String], password_stdin: bool) -> Result<()> {
    let path = resolve_existing(name)?;
    let (session, mut vault) = open_vault(&path, password_stdin)?;
    for key in keys {
        match vault.entries().iter().position(|e| &e.key == key) {
            Some(i) => vault.remove_at(i),
            None => bail!("key '{key}' not found in vault '{name}'"),
        }
    }
    session.save(&path, vault.serialize().as_bytes())?;
    println!("Removed {} key(s)", keys.len());
    Ok(())
}

fn cmd_show(name: &str, password_stdin: bool) -> Result<()> {
    let path = resolve_existing(name)?;
    let (_session, vault) = open_vault(&path, password_stdin)?;
    // `serialize()` returns a `Zeroizing<String>` (wiped on drop); deref to
    // print its contents.
    print!("{}", *vault.serialize());
    Ok(())
}

fn cmd_list() -> Result<()> {
    let vaults = store::list_vaults()?;
    if vaults.is_empty() {
        println!(
            "No vaults yet in {}. Create one with `envvault init <name>`.",
            store::vault_dir()?.display()
        );
    } else {
        for name in vaults {
            println!("{name}");
        }
    }
    Ok(())
}
