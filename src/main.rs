//! envvault — store environment variables in password-encrypted vaults and run
//! programs with those variables set, without ever leaving secrets in your
//! shell, shell history, or on disk in plaintext.
//!
//! Vaults are named and live in a fixed per-user directory
//! (`$ENVVAULT_DIR`, else `<config-dir>/envvault`), one encrypted file each.

mod crypto;
mod dirvault;
mod harden;
mod integrity;
mod password;
mod run;
mod sandbox;
mod shim;
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
    /// Re-encrypt a vault under the current (stronger) Argon2id parameters.
    ///
    /// Vaults created before stronger key-derivation shipped use a legacy
    /// format (v1, Argon2id defaults: m=19 MiB, t=2). This command decrypts
    /// with the existing password and re-encrypts the same contents under a
    /// fresh v2 session (m=64 MiB, t=3) — without changing the password.
    /// No-op (and reports as such) if the vault is already current.
    Upgrade {
        name: String,
        #[arg(long)]
        password_stdin: bool,
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
        /// Linux: hide your credential files (~/.ssh, ~/.aws, …) from the program
        /// and everything it spawns, for the whole session. Structural — nothing
        /// inside the session can undo it.
        #[arg(long)]
        sandbox: bool,
        /// Linux: a credential path to leave visible under the sandbox
        /// (repeatable); implies --sandbox. Nested `unrun` inherits these.
        #[arg(long)]
        allow: Vec<String>,
        /// Linux: verify your config/trust files (~/.gitconfig, ~/.npmrc,
        /// ~/.pki, …) against the root-owned baseline and freeze the verified
        /// copy into the session. Fails closed on any mismatch. Requires a
        /// baseline (`sudo envvault baseline set`).
        #[arg(long)]
        verify: bool,
        /// The program to run, followed by its arguments (use `--` first).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true, num_args = 1..)]
        command: Vec<String>,
    },
    /// Run a command with your credential files hidden, so untested code (e.g.
    /// an AI agent's commands) can't read them. Hides a built-in set of secret
    /// paths (~/.ssh, ~/.aws, ~/.config/gh, …); everything else is unchanged.
    /// Linux only.
    Unrun {
        /// Extra path to hide, on top of the built-in credential list (repeatable).
        #[arg(long)]
        hide: Vec<String>,
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
    /// Manage the root-owned config-integrity baseline used by `run --verify`.
    /// It records BLAKE3 hashes of your trust/config files (~/.gitconfig,
    /// ~/.npmrc, ~/.pki, …) somewhere a same-uid attacker can't forge, so
    /// poisoning is detected and the verified copy frozen for the session.
    Baseline {
        #[command(subcommand)]
        command: BaselineCmd,
    },
}

#[derive(Subcommand)]
enum BaselineCmd {
    /// Record BLAKE3 hashes of the tracked trust/config set into the root-owned
    /// baseline (requires root — run with sudo). Re-run to re-bless after an
    /// intended change.
    Set {
        /// Extra path to track, on top of the built-in trust set (repeatable).
        #[arg(long)]
        add: Vec<String>,
        /// User whose files to baseline (default: $SUDO_USER).
        #[arg(long)]
        user: Option<String>,
        /// Also print the line-level content diff of what changed (off by
        /// default so contents aren't shown to an onlooker).
        #[arg(long)]
        show_diff: bool,
    },
    /// Add path(s) to the tracked set, hashing them at their current state
    /// (root). Re-pinning an already-tracked path re-blesses just that path;
    /// other entries are left untouched.
    Pin {
        /// Path(s) to start tracking.
        #[arg(required = true, num_args = 1.., value_name = "PATH")]
        paths: Vec<String>,
        /// User whose baseline to edit (default: $SUDO_USER).
        #[arg(long)]
        user: Option<String>,
    },
    /// Remove path(s) from the tracked set (root). Unpinning a tracked directory
    /// drops it and everything under it.
    Unpin {
        /// Path(s) to stop tracking.
        #[arg(required = true, num_args = 1.., value_name = "PATH")]
        paths: Vec<String>,
        /// User whose baseline to edit (default: $SUDO_USER).
        #[arg(long)]
        user: Option<String>,
    },
    /// Print the stored baseline for a user (default: you).
    Show {
        #[arg(long)]
        user: Option<String>,
    },
    /// Re-hash the tracked files and report any that differ from the baseline.
    Check {
        #[arg(long)]
        user: Option<String>,
    },
    /// Show the line-level content diff of what currently differs from the
    /// baseline (requires root — the content snapshot is root-only 0400).
    Diff {
        #[arg(long)]
        user: Option<String>,
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
        /// Preload a shim that marks the program non-dumpable, so a same-uid
        /// process can't core-dump/ptrace it to read the decrypted secret out of
        /// its memory. Best-effort (warns if the shim can't load); Linux only.
        #[arg(long)]
        harden: bool,
        /// Hide your credential files (~/.ssh, ~/.aws, …) from the program and
        /// everything it spawns, for the whole session (same as `run --sandbox`).
        #[arg(long)]
        sandbox: bool,
        /// A credential path to leave visible under the sandbox (repeatable);
        /// implies --sandbox.
        #[arg(long)]
        allow: Vec<String>,
        /// Verify your config/trust files against the root-owned baseline and
        /// freeze the verified copy into the session; fails closed on any
        /// mismatch (same as `run --verify`; needs `sudo envvault baseline set`).
        #[arg(long)]
        verify: bool,
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
    /// Re-encrypt a directory vault under the current (stronger) Argon2id
    /// parameters, preserving the password. No-op if already current.
    Upgrade {
        name: String,
        #[arg(long)]
        password_stdin: bool,
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
        Cmd::Upgrade {
            name,
            password_stdin,
        } => cmd_upgrade(&name, password_stdin),
        Cmd::Rename { old, new } => cmd_rename(&old, &new),
        Cmd::Run {
            name,
            password_stdin,
            quiet,
            harden,
            sandbox,
            allow,
            verify,
            command,
        } => cmd_run(
            &name,
            password_stdin,
            quiet,
            harden,
            sandbox,
            &allow,
            verify,
            &command,
        ),
        Cmd::Unrun { hide, command } => cmd_unrun(&hide, &command),
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
        Cmd::Baseline { command } => run_baseline(command),
    }
}

fn run_baseline(command: BaselineCmd) -> Result<()> {
    match command {
        BaselineCmd::Set { add, user, show_diff } => cmd_baseline_set(&add, user.as_deref(), show_diff),
        BaselineCmd::Pin { paths, user } => cmd_baseline_pin(&paths, user.as_deref()),
        BaselineCmd::Unpin { paths, user } => cmd_baseline_unpin(&paths, user.as_deref()),
        BaselineCmd::Show { user } => cmd_baseline_show(user.as_deref()),
        BaselineCmd::Check { user } => cmd_baseline_check(user.as_deref()),
        BaselineCmd::Diff { user } => cmd_baseline_diff(user.as_deref()),
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
            harden,
            sandbox,
            allow,
            verify,
            command,
        } => cmd_dir_run(
            &name,
            password_stdin,
            no_autosave,
            autosave_debounce,
            harden,
            sandbox,
            &allow,
            verify,
            &command,
        ),
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
        DirCmd::Upgrade {
            name,
            password_stdin,
        } => cmd_dir_upgrade(&name, password_stdin),
        DirCmd::Rm { name } => cmd_dir_rm(&name),
    }
}

/// Open a handle to the system clipboard so a pasted secret can be wiped after
/// use — unless `ENVVAULT_NO_CLIPBOARD` is set, in which case clipboard
/// integration is skipped entirely. Set that in headless/SSH/CI/automation
/// environments: some clipboard backends block indefinitely on connect when a
/// display socket is half-present, which would otherwise hang `set` and the
/// editor. Returns `None` when disabled or unreachable (callers treat that as
/// "can't wipe — say so").
pub(crate) fn open_clipboard() -> Option<arboard::Clipboard> {
    if std::env::var_os("ENVVAULT_NO_CLIPBOARD").is_some() {
        return None;
    }
    arboard::Clipboard::new().ok()
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
///
/// Opportunistically upgrades a legacy (v1) vault to the current (v2) Argon2id
/// parameters: the password is in hand here, so we re-key and re-save it once.
/// Best-effort — if the re-save fails (e.g. a read-only directory) we keep using
/// the legacy session so a read never breaks.
fn open_vault(path: &Path, password_stdin: bool) -> Result<(Session, EnvVault)> {
    let pw = get_password(password_stdin)?;
    let (session, plaintext) = crypto::open(path, pw.as_bytes())?;
    let session = auto_upgrade(session, path, pw.as_bytes(), &plaintext, "vault");
    let text = std::str::from_utf8(&plaintext).context("vault contains invalid UTF-8")?;
    Ok((session, EnvVault::parse(text)))
}

/// Best-effort re-key of a legacy (v1) session to the current (v2) Argon2id
/// parameters, re-saving `path` with `plaintext`. Returns the session to use
/// going forward: the new v2 session on success, or the original legacy session
/// (with a warning) if the re-save fails, so callers never break on a read.
/// `kind` is "vault" or "directory vault" for the messages.
fn auto_upgrade(session: Session, path: &Path, password: &[u8], plaintext: &[u8], kind: &str) -> Session {
    if session.is_current() {
        return session;
    }
    match Session::create(password).and_then(|v2| v2.save(path, plaintext).map(|()| v2)) {
        Ok(v2) => {
            eprintln!("note: upgraded {kind} to v2 (Argon2id m=64 MiB, t=3); password unchanged");
            v2
        }
        Err(e) => {
            eprintln!(
                "warning: could not upgrade {kind} to v2 ({e:#}); continuing with legacy \
                 parameters"
            );
            session
        }
    }
}

fn cmd_init(name: &str, password_stdin: bool, no_edit: bool) -> Result<()> {
    let path = store::vault_path(name)?;
    if path.exists() {
        bail!("a vault named '{name}' already exists — refusing to overwrite");
    }
    let pw = if password_stdin {
        let pw = password::read_stdin()?;
        if pw.is_empty() {
            bail!("refusing to create a vault with an empty password");
        }
        pw
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
    let (old_session, plaintext) = crypto::open(&path, old_pw.as_bytes())?;
    // Acquire and confirm the new password, then re-encrypt the same contents
    // under a fresh salt + key (Session::create generates a new salt).
    let new_pw = password::prompt_new()?;
    let new_session = Session::create(new_pw.as_bytes())?;
    new_session.save(&path, &plaintext)?;
    // `Session::create` always uses the current (v2) Argon2id parameters, so
    // a password change on a legacy v1 vault re-keys it to v2 as a free side
    // effect — surface that so the format change isn't silent.
    if !old_session.is_current() {
        println!(
            "Password changed for vault '{name}' (also upgraded to v2 Argon2id parameters)."
        );
    } else {
        println!("Password changed for vault '{name}'");
    }
    Ok(())
}

/// Re-encrypt a vault under the current (v2) Argon2id parameters, preserving
/// the password. Decrypts with the file's existing parameters (v1 or v2), then
/// mints a fresh v2 session (new salt + stronger KDF) and re-encrypts the same
/// plaintext. A no-op if the vault is already current.
fn cmd_upgrade(name: &str, password_stdin: bool) -> Result<()> {
    let path = resolve_existing(name)?;
    let pw = get_password(password_stdin)?;
    let (session, plaintext) = crypto::open(&path, pw.as_bytes())?;
    if session.is_current() {
        println!(
            "vault '{name}' is already using the current Argon2id parameters (v2); nothing to do"
        );
        return Ok(());
    }
    // Mint a fresh v2 session with a new salt under the same password and
    // re-encrypt. `Session::create` always uses the current parameters.
    let new_session = Session::create(pw.as_bytes())?;
    new_session.save(&path, &plaintext)?;
    println!(
        "Upgraded vault '{name}' to v2 (Argon2id m=64 MiB, t=3). The password is unchanged."
    );
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

/// Built-in credential paths `unrun` hides, relative to $HOME. Whether each is a
/// directory or a single file is detected at runtime. This is the credential-
/// stealer target set; extend per-invocation with `--hide`.
const UNRUN_DEFAULT_HIDE: &[&str] = &[
    ".ssh",
    ".aws",
    ".config/gh",
    ".config/gcloud",
    ".azure",
    ".kube",
    ".gnupg",
    ".config/op",
    ".terraform.d",
    ".config/envvault",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
    ".docker/config.json",
    ".cargo/credentials.toml",
    ".databrickscfg",
];

/// Expand a leading `~/` to the home directory; otherwise take the path as-is.
/// Used to normalize `--allow` / `--hide` / `$ENVVAULT_ALLOW` entries so they
/// compare equal to the absolute `default_cred_paths`.
fn normalize_path(s: &str) -> std::path::PathBuf {
    if let Some(rest) = s.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return home.join(rest);
    }
    std::path::PathBuf::from(s)
}

/// The built-in credential paths, resolved under $HOME.
fn default_cred_paths() -> Vec<std::path::PathBuf> {
    let mut v = Vec::new();
    if let Some(home) = dirs::home_dir() {
        for rel in UNRUN_DEFAULT_HIDE {
            v.push(home.join(rel));
        }
    }
    v
}

/// The soft allow-list a parent `run --allow` exported, parsed from
/// `$ENVVAULT_ALLOW` (colon-separated, normalized). Only affects which already-
/// visible paths `unrun` declines to re-hide; it can never expose a path the
/// parent structurally removed from the namespace.
fn inherited_allow() -> Vec<std::path::PathBuf> {
    std::env::var("ENVVAULT_ALLOW")
        .ok()
        .map(|s| s.split(':').filter(|x| !x.is_empty()).map(normalize_path).collect())
        .unwrap_or_default()
}

/// Resolve the invoking (effective) user's login name via the passwd database,
/// not `$USER` — env vars are same-uid-spoofable and we use this to locate the
/// trusted baseline.
#[cfg(unix)]
fn current_user() -> Result<String> {
    let uid = unsafe { libc::geteuid() };
    unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            bail!("could not resolve a login name for uid {uid}");
        }
        Ok(std::ffi::CStr::from_ptr((*pw).pw_name)
            .to_string_lossy()
            .into_owned())
    }
}

#[cfg(not(unix))]
fn current_user() -> Result<String> {
    bail!("the integrity baseline is only supported on Unix-like systems");
}

/// The home directory of `user` from the passwd database. Used by `baseline set`
/// (running as root) to find the *target* user's files — `$HOME`/`dirs` would
/// return root's home under sudo.
#[cfg(unix)]
fn home_for_user(user: &str) -> Result<std::path::PathBuf> {
    let c = std::ffi::CString::new(user).context("user name has a NUL byte")?;
    unsafe {
        let pw = libc::getpwnam(c.as_ptr());
        if pw.is_null() {
            bail!("no such user '{user}'");
        }
        let dir = std::ffi::CStr::from_ptr((*pw).pw_dir).to_string_lossy();
        if dir.is_empty() {
            bail!("user '{user}' has no home directory");
        }
        Ok(std::path::PathBuf::from(dir.into_owned()))
    }
}

#[cfg(not(unix))]
fn home_for_user(_user: &str) -> Result<std::path::PathBuf> {
    bail!("the integrity baseline is only supported on Unix-like systems");
}

/// Expand a leading `~/` against a *specific* home (the baselined user's),
/// otherwise take the path as-is. Like `normalize_path` but home-explicit, since
/// `baseline set` runs as root and must not use root's home.
fn expand_under(home: &Path, s: &str) -> std::path::PathBuf {
    if let Some(rest) = s.strip_prefix("~/") {
        home.join(rest)
    } else {
        std::path::PathBuf::from(s)
    }
}

/// Shared preamble for the root-only baseline editors (`set`/`pin`/`unpin`):
/// require root, resolve the target user (`--user` else `$SUDO_USER`, never
/// root), and return that user's name and home (from the passwd DB).
fn baseline_target(user: Option<&str>) -> Result<(String, std::path::PathBuf)> {
    #[cfg(unix)]
    if unsafe { libc::geteuid() } != 0 {
        bail!(
            "accessing the root-owned baseline files under {} requires root.\n\
             Try: sudo envvault baseline <set|pin|unpin|diff> …",
            integrity::BASELINE_DIR
        );
    }
    let target = match user {
        Some(u) => u.to_string(),
        None => std::env::var("SUDO_USER").map_err(|_| {
            anyhow::anyhow!(
                "could not determine whose baseline to edit; pass --user <login> \
                 (running directly as root, $SUDO_USER is unset)"
            )
        })?,
    };
    if target == "root" {
        bail!("refusing to baseline root's home; pass --user <your-login>");
    }
    let home = home_for_user(&target)?;
    Ok((target, home))
}

/// Pluralize "entr{y,ies}" for counts.
fn entries(n: usize) -> &'static str {
    if n == 1 { "y" } else { "ies" }
}

/// Print which tracked paths changed (names only — never content).
fn report_changes(c: &integrity::BaselineChanges) {
    let dump = |label: &str, v: &[std::path::PathBuf]| {
        if !v.is_empty() {
            println!("  {label}:");
            for p in v {
                println!("    {}", p.display());
            }
        }
    };
    dump("changed", &c.changed);
    dump("added", &c.added);
    dump("removed", &c.removed);
}

/// Print the line-level content diff for each changed path (old snapshot vs new).
/// Only called on an explicit opt-in (`set --show-diff` or `baseline diff`), since
/// it puts file contents on screen.
fn print_diffs(c: &integrity::BaselineChanges, old: &integrity::Snapshot, new: &integrity::Snapshot) {
    let lossy = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    for p in c.changed.iter().chain(&c.added).chain(&c.removed) {
        println!("=== {} ===", p.display());
        match (integrity::snapshot_get(old, p), integrity::snapshot_get(new, p)) {
            (Some(o), Some(n)) => print!("{}", integrity::line_diff(&lossy(o), &lossy(n))),
            (None, Some(n)) => print!("{}", integrity::line_diff("", &lossy(n))),
            (Some(o), None) => print!("{}", integrity::line_diff(&lossy(o), "")),
            (None, None) => println!("  (binary file — content not shown)"),
        }
    }
}

/// `sudo envvault baseline set` — record BLAKE3 hashes of the target user's
/// trust/config set into the root-owned baseline (full re-bless), and store a
/// root-only `0400` content snapshot for diffs. Must run as root. Reports which
/// paths changed since the previous baseline (names only; `--show-diff` to also
/// print the content diff).
fn cmd_baseline_set(add: &[String], user: Option<&str>, show_diff: bool) -> Result<()> {
    let (target, home) = baseline_target(user)?;
    let mut tracked: Vec<std::path::PathBuf> = integrity::TRUST_CONFIG_PATHS
        .iter()
        .map(|rel| home.join(rel))
        .collect();
    for a in add {
        tracked.push(expand_under(&home, a));
    }
    let new_baseline = integrity::compute(&tracked)?;
    let new_snap = integrity::collect_snapshot(&tracked)?;

    // Report what's about to change vs the previous baseline, so a re-bless is
    // never silent. Names by default; content only with --show-diff.
    if let Ok(old_baseline) = integrity::read(&target) {
        let changes = integrity::diff_baselines(&old_baseline, &new_baseline);
        if changes.is_empty() {
            println!("No changes since the last baseline for '{target}'.");
        } else {
            println!("Changes since the last baseline for '{target}':");
            report_changes(&changes);
            if show_diff {
                let old_snap = integrity::read_snapshot(&target).unwrap_or_default();
                println!();
                print_diffs(&changes, &old_snap, &new_snap);
            } else {
                println!("  (re-run with --show-diff to see the content changes)");
            }
        }
    }

    integrity::write(&target, &new_baseline)?;
    integrity::write_snapshot(&target, &new_snap)?;
    println!(
        "Wrote integrity baseline for user '{target}' to {} ({} tracked entr{}).",
        integrity::baseline_path(&target).display(),
        new_baseline.len(),
        entries(new_baseline.len())
    );
    Ok(())
}

/// `sudo envvault baseline diff` — show the line-level content diff of what
/// currently differs from the baseline. Root-only (the snapshot is `0400`).
fn cmd_baseline_diff(user: Option<&str>) -> Result<()> {
    let (target, _home) = baseline_target(user)?;
    let old_baseline = integrity::read(&target)?;
    let old_snap = integrity::read_snapshot(&target)?;
    let roots = old_baseline.tracked_roots();
    let cur_baseline = integrity::compute(&roots)?;
    let cur_snap = integrity::collect_snapshot(&roots)?;
    let changes = integrity::diff_baselines(&old_baseline, &cur_baseline);
    if changes.is_empty() {
        println!("No changes — the tracked files match the baseline for '{target}'.");
        return Ok(());
    }
    println!("Files that differ from the baseline for '{target}':");
    report_changes(&changes);
    println!();
    print_diffs(&changes, &old_snap, &cur_snap);
    Ok(())
}

/// `sudo envvault baseline pin <path>…` — add path(s) to the tracked set without
/// re-blessing the rest. Surgical: only the named paths are (re)hashed.
fn cmd_baseline_pin(paths: &[String], user: Option<&str>) -> Result<()> {
    let (target, home) = baseline_target(user)?;
    let baseline = integrity::read(&target)?;
    let add: Vec<std::path::PathBuf> = paths.iter().map(|s| expand_under(&home, s)).collect();
    let (baseline, rep) = integrity::pin(baseline, &add)?;
    for (p, dir) in &rep.skipped_covered {
        eprintln!(
            "note: {} is already covered by tracked directory {} — skipped",
            p.display(),
            dir.display()
        );
    }
    if rep.added.is_empty() && rep.repinned.is_empty() {
        bail!("nothing to pin (every path given was already covered by a tracked directory)");
    }
    integrity::write(&target, &baseline)?;
    // Keep the content snapshot in sync, surgically: replace only the pinned
    // paths' content, leave the rest as previously blessed.
    let pinned: Vec<std::path::PathBuf> = rep.added.iter().chain(&rep.repinned).cloned().collect();
    let mut snap = integrity::read_snapshot(&target).unwrap_or_default();
    snap.retain(|(p, _)| !pinned.iter().any(|pp| p == pp || p.starts_with(pp)));
    snap.extend(integrity::collect_snapshot(&pinned)?);
    snap.sort_by(|a, b| a.0.cmp(&b.0));
    integrity::write_snapshot(&target, &snap)?;
    println!(
        "Pinned for '{target}': {} added, {} re-blessed — {} tracked entr{} total.",
        rep.added.len(),
        rep.repinned.len(),
        baseline.len(),
        entries(baseline.len())
    );
    Ok(())
}

/// `sudo envvault baseline unpin <path>…` — remove path(s) from the tracked set.
fn cmd_baseline_unpin(paths: &[String], user: Option<&str>) -> Result<()> {
    let (target, home) = baseline_target(user)?;
    let baseline = integrity::read(&target)?;
    let remove: Vec<std::path::PathBuf> = paths.iter().map(|s| expand_under(&home, s)).collect();
    let (baseline, rep) = integrity::unpin(baseline, &remove);
    for p in &rep.not_found {
        eprintln!(
            "note: {} was not a top-level tracked path — skipped (a file inside a \
             tracked directory can only be removed by unpinning that directory)",
            p.display()
        );
    }
    if rep.removed.is_empty() {
        bail!("nothing removed — none of the given paths were tracked");
    }
    integrity::write(&target, &baseline)?;
    // Drop the unpinned paths from the content snapshot too.
    let mut snap = integrity::read_snapshot(&target).unwrap_or_default();
    snap.retain(|(p, _)| !rep.removed.iter().any(|pp| p == pp || p.starts_with(pp)));
    integrity::write_snapshot(&target, &snap)?;
    println!(
        "Unpinned for '{target}': {} removed — {} tracked entr{} remain.",
        rep.removed.len(),
        baseline.len(),
        entries(baseline.len())
    );
    Ok(())
}

/// `envvault baseline show` — print the stored baseline (plain text).
fn cmd_baseline_show(user: Option<&str>) -> Result<()> {
    let target = match user {
        Some(u) => u.to_string(),
        None => current_user()?,
    };
    let path = integrity::baseline_path(&target);
    let text = std::fs::read_to_string(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            anyhow::anyhow!(
                "no integrity baseline for user '{target}' at {}.\n\
                 Create one with: sudo envvault baseline set",
                path.display()
            )
        } else {
            anyhow::Error::new(e).context(format!("failed to read {}", path.display()))
        }
    })?;
    print!("{text}");
    Ok(())
}

/// `envvault baseline check` — re-hash the tracked files and report any drift,
/// without running anything (a dry run of what `run --verify` would enforce).
fn cmd_baseline_check(user: Option<&str>) -> Result<()> {
    let target = match user {
        Some(u) => u.to_string(),
        None => current_user()?,
    };
    let baseline = integrity::read(&target)?;
    let problems = integrity::check(&baseline);
    if problems.is_empty() {
        println!(
            "baseline OK: all {} tracked entr{} match.",
            baseline.len(),
            if baseline.len() == 1 { "y" } else { "ies" }
        );
        return Ok(());
    }
    for p in &problems {
        println!("MISMATCH: {p}");
    }
    eprintln!("Run `sudo envvault baseline diff` to see the line-level changes.");
    bail!(
        "{} tracked path(s) differ from the baseline. If the changes are intended, \
         re-bless with `sudo envvault baseline set`.",
        problems.len()
    );
}

fn cmd_unrun(extra_hide: &[String], command: &[String]) -> Result<()> {
    let allow = inherited_allow();
    let mut paths: Vec<std::path::PathBuf> = default_cred_paths()
        .into_iter()
        .filter(|p| !allow.contains(p))
        .collect();
    for p in extra_hide {
        paths.push(normalize_path(p));
    }
    let (program, args) = command
        .split_first()
        .expect("clap guarantees at least one element");
    sandbox::unrun(program, args, &paths)
}

/// Apply `--verify`/`--sandbox`/`--allow` hardening inside the already-entered
/// private namespace (non-dumpable), before the child runs. Shared by `run` and
/// `dir run`:
/// - `--verify`: check the config/trust files against the root-owned baseline
///   and freeze the verified copy in. **Fails closed** on any mismatch.
/// - `--sandbox`/`--allow`: structurally mask every default credential path
///   except the allowed and frozen ones, and export the soft allow-list so a
///   nested `unrun` knows what to leave visible.
///
/// Must be called single-threaded (before any child or autosaver thread), since
/// it `set_var`s `ENVVAULT_ALLOW`.
fn harden_session_in_ns(verify: bool, sandbox: bool, allow: &[String]) -> Result<()> {
    let allow_paths: Vec<std::path::PathBuf> = allow.iter().map(|s| normalize_path(s)).collect();
    let mut frozen_paths: Vec<std::path::PathBuf> = Vec::new();
    if verify {
        let user = current_user()?;
        let items = integrity::verify_and_collect(&integrity::read(&user)?)?;
        frozen_paths = items.iter().map(|i| i.path().to_path_buf()).collect();
        sandbox::freeze_items(&items)?;
    }
    if sandbox || !allow.is_empty() {
        // Frozen paths must not also be masked (freeze wins for shared paths
        // like ~/.npmrc); allowed paths stay visible.
        let mask: Vec<std::path::PathBuf> = default_cred_paths()
            .into_iter()
            .filter(|p| !allow_paths.contains(p) && !frozen_paths.contains(p))
            .collect();
        sandbox::mask_paths(&mask)?;
        let allow_env = allow_paths
            .iter()
            .filter_map(|p| p.to_str())
            .collect::<Vec<_>>()
            .join(":");
        // SAFETY: single-threaded here, before any child is spawned.
        unsafe { std::env::set_var("ENVVAULT_ALLOW", allow_env) };
    }
    Ok(())
}

fn cmd_run(
    name: &str,
    password_stdin: bool,
    quiet: bool,
    harden: bool,
    sandbox: bool,
    allow: &[String],
    verify: bool,
    command: &[String],
) -> Result<()> {
    let path = resolve_existing(name)?;
    let (program, args) = command
        .split_first()
        .expect("clap guarantees at least one element");
    let quiet = quiet || std::env::var_os("ENVVAULT_QUIET").is_some();

    // Any of --sandbox, --allow (implies --sandbox), or --verify needs the
    // private namespace established before any untrusted code runs.
    let need_ns = sandbox || !allow.is_empty() || verify;
    if need_ns {
        // Enter the namespace BEFORE decrypting (no secret in memory during the
        // brief dumpable id-map window), decrypt, then apply the in-namespace
        // hardening, then exec/fork the child (which inherits all of it).
        sandbox::enter_user_mount_ns()?;
        let (_session, vault) = open_vault(&path, password_stdin)?;
        harden_session_in_ns(verify, sandbox, allow)?;
        return run::run(&vault, program, args, quiet, harden);
    }

    let (_session, vault) = open_vault(&path, password_stdin)?;
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

/// Return the first path under `root` that lives on a different filesystem than
/// `root` itself (i.e. a mount point). `dir init` archives a directory with
/// `append_dir_all`, which crosses mount boundaries, and then deletes what it
/// packed — so we use this to refuse before vaulting an unintended mount.
#[cfg(unix)]
fn find_submount(root: &Path) -> Result<Option<std::path::PathBuf>> {
    use std::os::unix::fs::MetadataExt;
    let root_dev = std::fs::symlink_metadata(root)?.dev();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let p = entry.path();
            let m = match std::fs::symlink_metadata(&p) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if m.file_type().is_symlink() {
                continue; // don't follow symlinks out of the tree
            }
            if m.dev() != root_dev {
                return Ok(Some(p));
            }
            if m.is_dir() {
                stack.push(p);
            }
        }
    }
    Ok(None)
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

    // A mount point inside the directory would be archived by `append_dir_all`
    // and then DELETED by `empty_dir` — refuse rather than vault+destroy an
    // unintended filesystem's contents.
    #[cfg(unix)]
    if is_dir
        && let Some(mp) = find_submount(&canonical)?
    {
        bail!(
            "{} contains a mount point ({}); refusing — `dir init` would archive and \
             then delete its contents. Unmount it first, or vault a different path.",
            canonical.display(),
            mp.display()
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
    harden: bool,
    sandbox: bool,
    allow: &[String],
    verify: bool,
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
    // Owned copy of the allow-list for the prepare closure (it outlives `allow`).
    let allow: Vec<String> = allow.to_vec();
    // The vault is opened (password prompt + decrypt) by the first closure, which
    // `sandbox::run` calls only after setting up the namespace and re-hardening
    // the process — so no secret exists during the brief dumpable window. The
    // second closure runs inside that namespace, after the contents are exposed
    // and before the child starts, applying --verify/--sandbox/--allow (and
    // failing closed there if --verify detects tampering).
    sandbox::run(
        &vault_path,
        program,
        args,
        autosave,
        harden,
        || {
            let pw = get_password(password_stdin)?;
            dirvault::open(&vault_path, pw.as_bytes())
        },
        move || harden_session_in_ns(verify, sandbox, &allow),
    )
}

fn cmd_dir_list() -> Result<()> {
    let names = store::list_dirvaults()?;
    if names.is_empty() {
        println!("No directory vaults yet. Create one with `envvault dir init <name> --path <dir>`.");
        return Ok(());
    }
    let mut rows: Vec<(String, &'static str)> = Vec::with_capacity(names.len());
    for name in &names {
        let path = store::dirvault_path(name)?;
        let tier = match crypto::detect_version(&path) {
            Ok(2) => "v2",
            Ok(1) => "v1 (legacy — `envvault dir upgrade {name}`)",
            _ => "?",
        };
        rows.push((name.clone(), tier));
    }
    let width = rows.iter().map(|(n, _)| n.len()).max().unwrap_or(0);
    for (name, tier) in rows {
        println!("{name:<width$}  {tier}");
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

/// Re-encrypt a directory vault under the current (v2) Argon2id parameters,
/// preserving the password. A no-op if already current.
fn cmd_dir_upgrade(name: &str, password_stdin: bool) -> Result<()> {
    let vault_path = resolve_existing_dirvault(name)?;
    // Note the on-disk version before opening, since `dirvault::open` upgrades a
    // legacy vault on the way in (best-effort).
    let was_legacy = crypto::detect_version(&vault_path)? == 1;
    let pw = get_password(password_stdin)?;
    let dv = dirvault::open(&vault_path, pw.as_bytes())?;
    if dv.is_current() {
        let msg = if was_legacy {
            format!("Upgraded directory vault '{name}' to v2 (Argon2id m=64 MiB, t=3). The password is unchanged.")
        } else {
            format!("directory vault '{name}' is already using the current Argon2id parameters (v2); nothing to do")
        };
        println!("{msg}");
        return Ok(());
    }
    // Open's best-effort upgrade couldn't write; do it explicitly so the failure
    // surfaces as an error on this explicit request. The container plaintext
    // (magic + kind + path + tar) is unchanged, so target and kind are preserved.
    let new_session = Session::create(pw.as_bytes())?;
    new_session.save(&vault_path, dv.plaintext())?;
    println!(
        "Upgraded directory vault '{name}' to v2 (Argon2id m=64 MiB, t=3). The password is unchanged."
    );
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
    // (e.g. headless / SSH without a display, or ENVVAULT_NO_CLIPBOARD).
    let mut clipboard = open_clipboard();
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
    let names = store::list_vaults()?;
    if names.is_empty() {
        println!(
            "No vaults yet in {}. Create one with `envvault init <name>`.",
            store::vault_dir()?.display()
        );
        return Ok(());
    }
    // Read each vault's on-disk header (no password needed) to show its KDF
    // tier: v2 = current Argon2id (m=64 MiB, t=3), v1 = legacy defaults
    // (m=19 MiB, t=2). A vault that fails to parse is shown as `?`.
    let mut rows: Vec<(String, &'static str)> = Vec::with_capacity(names.len());
    for name in &names {
        let path = store::vault_path(name)?;
        let tier = match crypto::detect_version(&path) {
            Ok(2) => "v2",
            Ok(1) => "v1 (legacy — `envvault upgrade {name}`)",
            _ => "?",
        };
        rows.push((name.clone(), tier));
    }
    let width = rows.iter().map(|(n, _)| n.len()).max().unwrap_or(0);
    for (name, tier) in rows {
        println!("{name:<width$}  {tier}");
    }
    Ok(())
}
