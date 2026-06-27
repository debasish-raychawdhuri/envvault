//! Run a child program with a directory vault's decrypted contents exposed at
//! the original path — in RAM only — then re-encrypt on exit.
//!
//! On Linux this creates a private user + mount namespace, mounts a tmpfs over
//! the target directory (visible only to this process and its children),
//! extracts the plaintext into it, runs the child, and re-encrypts from it when
//! the child exits. The tmpfs never appears in the host mount namespace and is
//! freed automatically when the process tree exits. Nothing else on the system
//! — not even another same-uid process — sees the plaintext at that path.
//!
//! The vault is decrypted via the caller-supplied `open` closure, which we call
//! *after* the namespace is set up and the process is re-hardened — see the
//! dumpability dance in `linux::run`.
//!
//! On other platforms this is unsupported (no unprivileged tmpfs-over-dir).

use crate::dirvault::DirVault;
use anyhow::Result;
use std::path::Path;

/// Set up the RAM sandbox at the vault's target path, run `program args...`,
/// and re-encrypt on exit. `open` decrypts the vault (prompting for the
/// password) and is invoked only after the process has been re-hardened, so the
/// secret never exists while the process is briefly dumpable. On a zero exit
/// this returns `Ok(())`; otherwise it calls `std::process::exit` with the
/// child's code.
#[cfg(target_os = "linux")]
pub fn run<F>(vault_path: &Path, program: &str, args: &[String], open: F) -> Result<()>
where
    F: FnOnce() -> Result<DirVault>,
{
    linux::run(vault_path, program, args, open)
}

#[cfg(not(target_os = "linux"))]
pub fn run<F>(_vault_path: &Path, _program: &str, _args: &[String], _open: F) -> Result<()>
where
    F: FnOnce() -> Result<DirVault>,
{
    anyhow::bail!(
        "directory vaults (`dir run`) are only supported on Linux — they rely on \
         unprivileged user + mount namespaces to expose the decrypted directory in \
         RAM. `dir init`, `dir export`, and `dir list` still work on this platform."
    )
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use anyhow::Context;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::Command;
    use std::ptr;

    pub fn run<F>(vault_path: &Path, program: &str, args: &[String], open: F) -> Result<()>
    where
        F: FnOnce() -> Result<DirVault>,
    {
        // Capture our real ids BEFORE unshare: inside an unmapped user
        // namespace the process appears as the overflow uid (65534/nobody), so
        // reading them afterwards would write a bogus map and be rejected.
        let euid = unsafe { libc::geteuid() };
        let egid = unsafe { libc::getegid() };

        // 1. Create the namespace and write the id maps. Writing
        //    /proc/self/{setgroups,uid_map,gid_map} requires the process to be
        //    dumpable, but `harden::protect_process()` set PR_SET_DUMPABLE=0 at
        //    startup (making those files root-owned). Re-enable dumpability for
        //    just this step — no secret is in memory yet — then re-harden before
        //    decrypting anything.
        set_dumpable(true);
        let ns_setup = (|| -> Result<()> {
            if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } != 0 {
                let err = std::io::Error::last_os_error();
                if matches!(err.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES)) {
                    return Err(userns_unavailable(&format!("unshare: {err}")));
                }
                return Err(
                    anyhow::Error::new(err).context("unshare(CLONE_NEWUSER|CLONE_NEWNS) failed")
                );
            }
            configure_id_maps(euid, egid)
        })();
        set_dumpable(false); // re-harden BEFORE any password or plaintext exists
        ns_setup?;

        // 2. Make mount propagation private so the tmpfs never escapes the ns.
        mount_private_root()?;

        // 3. Decrypt now that the process is non-dumpable again. `open` prompts
        //    for the password and returns the target path + plaintext.
        let dirvault = open()?;
        let target = dirvault.target().to_path_buf();

        // 4. Mount a fresh tmpfs over the target and extract into it (RAM only).
        std::fs::create_dir_all(&target)
            .with_context(|| format!("failed to create mountpoint {}", target.display()))?;
        mount_tmpfs(&target)?;
        dirvault
            .extract_into(&target)
            .context("failed to populate the in-memory directory")?;

        // 5. Ignore terminal signals in this supervisor so a Ctrl-C (or hang-up)
        //    goes to the child and we still reach the re-encrypt step.
        ignore_signals();

        // 6. Spawn the child (it inherits the namespace and the tmpfs view).
        let mut cmd = Command::new(program);
        cmd.args(args);
        unsafe {
            cmd.pre_exec(|| {
                for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
                    libc::signal(sig, libc::SIG_DFL);
                }
                Ok(())
            });
        }
        let status = cmd
            .spawn()
            .with_context(|| format!("failed to execute '{program}'"))?
            .wait()
            .context("failed waiting for child process")?;

        // 7. Re-encrypt whatever the child left behind, from the same ns.
        if let Err(e) = dirvault.save_from(vault_path, &target) {
            eprintln!(
                "error: failed to re-encrypt directory vault: {e:#}\n\
                 The child's changes were NOT saved; the vault on disk is unchanged."
            );
            drop(dirvault);
            std::process::exit(1);
        }
        drop(dirvault); // wipe decrypted plaintext before exiting

        // 8. Propagate the child's exit status. (Process exit tears down the
        //    namespace, unmounting and freeing the tmpfs automatically.)
        match status.code() {
            Some(0) => Ok(()),
            Some(code) => std::process::exit(code),
            None => std::process::exit(128 + status.signal().unwrap_or(0)),
        }
    }

    /// Toggle this process's dumpable attribute via `prctl(PR_SET_DUMPABLE)`.
    fn set_dumpable(on: bool) {
        let value: libc::c_ulong = if on { 1 } else { 0 };
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, value);
        }
    }

    /// Build the "unprivileged user namespaces are restricted" guidance error,
    /// shared by the `unshare` and id-map failure paths (both mean the same
    /// thing to the user).
    fn userns_unavailable(detail: &str) -> anyhow::Error {
        anyhow::anyhow!(
            "could not set up a user namespace ({detail}).\n\
             Directory vaults need unprivileged user namespaces, which this system \
             appears to restrict or disable. Enable them, for example:\n  \
             sudo sysctl -w kernel.unprivileged_userns_clone=1\n\
             (On Ubuntu 24.04+ you may also need: \
             sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0)"
        )
    }

    /// Map `euid`/`egid` (captured before unshare) 1:1 into the new user
    /// namespace, so the child runs as our own uid/gid inside it.
    fn configure_id_maps(euid: libc::uid_t, egid: libc::gid_t) -> Result<()> {
        write_proc_or_userns_err("/proc/self/setgroups", "deny")?;
        write_proc_or_userns_err("/proc/self/uid_map", &format!("{euid} {euid} 1"))?;
        write_proc_or_userns_err("/proc/self/gid_map", &format!("{egid} {egid} 1"))?;
        Ok(())
    }

    /// Write a `/proc/self` namespace file, mapping permission errors to the
    /// shared userns-restricted guidance.
    fn write_proc_or_userns_err(path: &str, content: &str) -> Result<()> {
        std::fs::write(path, content).map_err(|e| {
            if matches!(e.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES)) {
                userns_unavailable(&format!("{path}: {e}"))
            } else {
                anyhow::Error::new(e).context(format!("failed to write {path}"))
            }
        })
    }

    /// `mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL)` — turn off mount
    /// propagation so our later mounts stay inside this namespace.
    fn mount_private_root() -> Result<()> {
        let root = CString::new("/").unwrap();
        let rc = unsafe {
            libc::mount(
                ptr::null(),
                root.as_ptr(),
                ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                ptr::null(),
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to make the mount namespace private");
        }
        Ok(())
    }

    /// Mount a fresh tmpfs (owner-only) over `target`.
    fn mount_tmpfs(target: &Path) -> Result<()> {
        let src = CString::new("tmpfs").unwrap();
        let fstype = CString::new("tmpfs").unwrap();
        let tgt = CString::new(target.as_os_str().as_bytes())
            .context("target path contains a NUL byte")?;
        let opts = CString::new("mode=0700").unwrap();
        let rc = unsafe {
            libc::mount(
                src.as_ptr(),
                tgt.as_ptr(),
                fstype.as_ptr(),
                0,
                opts.as_ptr() as *const libc::c_void,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed to mount tmpfs at {}", target.display()));
        }
        Ok(())
    }

    /// Ignore the terminal/termination signals in the supervisor so a Ctrl-C
    /// (or hang-up) goes to the child and we still reach the re-encrypt step.
    fn ignore_signals() {
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
            unsafe {
                libc::signal(sig, libc::SIG_IGN);
            }
        }
    }
}
