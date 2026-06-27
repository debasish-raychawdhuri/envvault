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
    use anyhow::{bail, Context};
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::path::PathBuf;
    use std::time::Duration;
    use zeroize::Zeroize;

    /// The compiled LD_PRELOAD shim, embedded at build time (see build.rs).
    const SHIM_SO: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/harden.so"));

    /// How long to wait for the shim's "ready" signal before failing closed.
    /// Override with ENVVAULT_HARDEN_TIMEOUT (seconds) for slow systems/tests.
    fn ready_timeout() -> Duration {
        let secs = std::env::var("ENVVAULT_HARDEN_TIMEOUT")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&s| s > 0)
            .unwrap_or(5);
        Duration::from_secs(secs)
    }

    pub fn run(vault: &EnvVault, program: &str, args: &[String]) -> Result<()> {
        // 1. Stage the shim as a 0600 file the dynamic linker can preload.
        let shim_path = write_shim().context("failed to stage the hardening shim")?;
        let _cleanup = FileCleanup(shim_path.clone());

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
        let got_ready = wait_for_ready(ready_r, ready_timeout());
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

    /// Write the embedded shim to a private (0600) file under `$XDG_RUNTIME_DIR`
    /// (tmpfs) or the temp dir, named per-pid. Removed by `FileCleanup`.
    fn write_shim() -> Result<PathBuf> {
        use std::io::Write;
        let base = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let path = base.join(format!(".envvault-shim-{}.so", std::process::id()));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("failed to create {}", path.display()))?;
        f.write_all(SHIM_SO)
            .and_then(|_| f.sync_all())
            .with_context(|| format!("failed to write {}", path.display()))?;
        Ok(path)
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

    /// `pipe2(2)` with no flags -> (read_fd, write_fd). Both inherit across the
    /// child's exec (no CLOEXEC), which the shim needs.
    fn pipe() -> Result<(libc::c_int, libc::c_int)> {
        let mut fds = [0 as libc::c_int; 2];
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), 0) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error()).context("pipe2");
        }
        Ok((fds[0], fds[1]))
    }

    /// Poll `fd` for the shim's one-byte "R" signal, up to `timeout`. Returns
    /// false on timeout or EOF (shim never ran).
    fn wait_for_ready(fd: libc::c_int, timeout: Duration) -> bool {
        let mut remaining_ms = timeout.as_millis() as libc::c_int;
        loop {
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let start = remaining_ms;
            let rc = unsafe { libc::poll(&mut pfd, 1, remaining_ms) };
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    // Best-effort: keep waiting with the same budget.
                    remaining_ms = start;
                    continue;
                }
                return false;
            }
            if rc == 0 {
                return false; // timeout
            }
            let mut byte = [0u8; 1];
            let n = unsafe { libc::read(fd, byte.as_mut_ptr() as *mut libc::c_void, 1) };
            return n == 1 && byte[0] == b'R';
        }
    }

    /// Write all of `buf` to `fd`, handling partial writes and EINTR.
    fn write_all(fd: libc::c_int, buf: &[u8]) -> Result<()> {
        let mut off = 0;
        while off < buf.len() {
            let n = unsafe {
                libc::write(
                    fd,
                    buf[off..].as_ptr() as *const libc::c_void,
                    buf.len() - off,
                )
            };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(err).context("write");
            }
            off += n as usize;
        }
        Ok(())
    }

    fn ignore_signals() {
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
            unsafe {
                libc::signal(sig, libc::SIG_IGN);
            }
        }
    }

    /// Removes a staged file on drop.
    struct FileCleanup(PathBuf);
    impl Drop for FileCleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn shim_is_embedded_as_elf() {
            assert!(
                !super::SHIM_SO.is_empty(),
                "harden shim .so was not embedded — check build.rs"
            );
            assert_eq!(
                &super::SHIM_SO[..4],
                b"\x7fELF",
                "embedded shim is not an ELF shared object"
            );
        }
    }
}
