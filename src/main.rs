//! envvault — store environment variables in password-encrypted vaults and run
//! programs with those variables set, without ever leaving secrets in your
//! shell, shell history, or on disk in plaintext.
//!
//! Vaults are named and live in a fixed per-user directory
//! (`$ENVVAULT_DIR`, else `<config-dir>/envvault`), one encrypted file each.

mod crypto;
mod harden;
mod password;
mod run;
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
    /// Decrypt in memory and run a program with the vault's secrets in its env.
    Run {
        name: String,
        #[arg(long)]
        password_stdin: bool,
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
        Cmd::Run {
            name,
            password_stdin,
            command,
        } => cmd_run(&name, password_stdin, &command),
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

fn cmd_run(name: &str, password_stdin: bool, command: &[String]) -> Result<()> {
    let path = resolve_existing(name)?;
    let (_session, vault) = open_vault(&path, password_stdin)?;
    let (program, args) = command
        .split_first()
        .expect("clap guarantees at least one element");
    run::run(&vault, program, args)
}

fn cmd_set(name: &str, keys: &[String]) -> Result<()> {
    let path = resolve_existing(name)?;
    // Validate every key name before prompting, so a typo fails fast without
    // asking for the vault password or any values.
    for key in keys {
        vault::validate_key(key)?;
    }
    let (session, mut vault) = open_vault(&path, false)?;
    for key in keys {
        let value = password::prompt_value(key)?;
        vault.set(key, &value);
    }
    session.save(&path, vault.serialize().as_bytes())?;
    println!(
        "Updated {} entr{}",
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
