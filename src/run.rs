//! Launch a target program with the vault's variables in its environment.
//!
//! Two modes:
//! * **plain** (`run`): merge the secrets into the environment and `exec` the
//!   program. Simple, but the secrets are readable by any same-uid process via
//!   `/proc/<pid>/environ` for the program's lifetime (see the README).
//! * **hardened** (`run --harden`, Linux only): never put the secrets in the
//!   initial environment. Instead preload a tiny shim that marks the program
//!   non-dumpable and pulls the secrets in over a pipe *after* it is safe, so a
//!   same-uid attacker can read neither `/proc/<pid>/environ` nor
//!   `/proc/<pid>/mem`. Fails closed if the shim does not load.

use crate::vault::EnvVault;
use anyhow::{Context, Result};
use std::process::Command;

/// Run `program args...` with `vault`'s entries in its environment.
///
/// With `harden`, use the non-dumpable preload path (Linux only). Otherwise the
/// plain path prints a one-time exposure caution (unless `quiet`) and `exec`s.
pub fn run(
    vault: &EnvVault,
    program: &str,
    args: &[String],
    quiet: bool,
    harden: bool,
) -> Result<()> {
    if harden {
        #[cfg(target_os = "linux")]
        {
            return hardened::run(vault, program, args);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (vault, program, args);
            anyhow::bail!(
                "`--harden` is only supported on Linux: it relies on prctl(PR_SET_DUMPABLE) \
                 and an LD_PRELOAD shim to keep the secrets out of reach of same-uid processes."
            );
        }
    }

    if !quiet {
        eprintln!(
            "note: 'run' places these secrets in the program's environment; any process\n      \
             running as you can read them via /proc/<pid>/environ while it runs.\n      \
             For tools that read a secret from a file, prefer 'envvault dir run'.\n      \
             (silence: --quiet or ENVVAULT_QUIET=1; harden: --harden)"
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

#[cfg(target_os = "linux")]
mod hardened {
    use super::*;
    use crate::shim::{self, pipe, stage_shim, wait_for_ready, write_all};
    use anyhow::{bail, Context};
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use zeroize::Zeroize;

    pub fn run(vault: &EnvVault, program: &str, args: &[String]) -> Result<()> {
        // 1. Stage the shim in an anonymous sealed memfd (no on-disk name) and
        //    preload it via `/proc/self/fd/<n>`. A memfd lives only in this
        //    process's file table: there is no path an attacker can race, plant
        //    a symlink at, or rename over — so a same-uid attacker cannot
        //    substitute their own `.so` for the shim. Sealing prevents the
        //    loaded image from being mutated afterward.
        let (shim_path, memfd) = stage_shim().context("failed to stage the hardening shim")?;

        // 2. Build the secrets payload (KEY=VALUE, NUL-separated), kept zeroized.
        let mut payload = build_payload(vault);

        // 3. Pipes: ready (child -> parent), secret (parent -> child).
        let (ready_r, ready_w) = pipe().context("pipe() failed")?;
        let (secret_r, secret_w) = pipe().context("pipe() failed")?;

        // 4. Spawn the child with the shim preloaded; secrets are NOT in env.
        let mut cmd = Command::new(program);
        cmd.args(args);
        cmd.env("LD_PRELOAD", &shim_path);
        cmd.env("ENVVAULT_READY_FD", ready_w.to_string());
        cmd.env("ENVVAULT_SECRET_FD", secret_r.to_string());
        unsafe {
            cmd.pre_exec(move || {
                // Drop the parent-side fds in the child so the secret pipe sees
                // EOF when the parent closes its write end, and restore default
                // signal handling so Ctrl-C reaches the program.
                libc::close(ready_r);
                libc::close(secret_w);
                for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
                    libc::signal(sig, libc::SIG_DFL);
                }
                Ok(())
            });
        }

        // Supervisor ignores terminal signals so the child gets them and we
        // still reach cleanup.
        ignore_signals();
        let spawn_result = cmd.spawn();

        // Close the child-side fds in the parent regardless of spawn outcome.
        // The memfd is dropped here too: the child has inherited its own copy
        // (no CLOEXEC), so `/proc/self/fd/<n>` keeps resolving in its namespace
        // until ld.so has loaded the shim; the parent's copy is unneeded.
        drop(memfd);
        unsafe {
            libc::close(ready_w);
            libc::close(secret_r);
        }
        let mut child = match spawn_result {
            Ok(c) => c,
            Err(e) => {
                unsafe {
                    libc::close(ready_r);
                    libc::close(secret_w);
                }
                payload.zeroize();
                return Err(e).with_context(|| format!("failed to execute '{program}'"));
            }
        };

        // 5. Wait for the shim's "ready" signal. Until it arrives the child is
        //    not known to be non-dumpable, so we hold the secrets back.
        let got_ready = wait_for_ready(ready_r, shim::ready_timeout());
        unsafe {
            libc::close(ready_r);
        }

        if !got_ready {
            // Fail closed: never transmit the secrets.
            unsafe {
                libc::close(secret_w);
            }
            payload.zeroize();
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "hardened run aborted: '{program}' did not load the hardening shim \
                 (likely a static binary, a setuid program, or LD_PRELOAD was ignored). \
                 No secrets were sent. Run a dynamically-linked program, or use \
                 `envvault env run` if you accept the environment exposure."
            );
        }

        // 6. The child is non-dumpable now: send the secrets, then close.
        let write_result = write_all(secret_w, &payload);
        unsafe {
            libc::close(secret_w);
        }
        payload.zeroize();
        write_result.context("failed to send secrets to the hardened child")?;

        // 7. Wait and propagate the child's exit status.
        let status = child.wait().context("failed waiting for child process")?;
        match status.code() {
            Some(0) => Ok(()),
            Some(code) => std::process::exit(code),
            None => std::process::exit(128 + status.signal().unwrap_or(0)),
        }
    }

    /// Serialize the vault into `KEY=VALUE\0KEY=VALUE\0…` for the shim.
    fn build_payload(vault: &EnvVault) -> zeroize::Zeroizing<Vec<u8>> {
        let mut buf = zeroize::Zeroizing::new(Vec::new());
        for e in vault.entries() {
            buf.extend_from_slice(e.key.as_bytes());
            buf.push(b'=');
            buf.extend_from_slice(e.value.as_bytes());
            buf.push(0);
        }
        buf
    }

    fn ignore_signals() {
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
            unsafe {
                libc::signal(sig, libc::SIG_IGN);
            }
        }
    }
}
