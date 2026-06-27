//! Shared plumbing for the `LD_PRELOAD` hardening shim, used by both
//! `run --harden` (env-injected secrets, fail-closed) and `dir run --harden`
//! (non-dumpable preload only, best-effort).
//!
//! The shim is staged in an anonymous **sealed memfd** and preloaded via
//! `/proc/self/fd/<n>` — there is no on-disk path a same-uid attacker could
//! race, symlink, or substitute, and sealing freezes the loaded image.
//!
//! The whole module is Linux-only (memfd + file sealing + the shim itself).

#![cfg(target_os = "linux")]

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::time::Duration;

/// The compiled `LD_PRELOAD` shim, embedded at build time (see build.rs).
pub const SHIM_SO: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/harden.so"));

/// How long to wait for the shim's one-byte "ready" signal. Override with
/// `ENVVAULT_HARDEN_TIMEOUT` (seconds) for slow systems/tests.
pub fn ready_timeout() -> Duration {
    let secs = std::env::var("ENVVAULT_HARDEN_TIMEOUT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&s| s > 0)
        .unwrap_or(5);
    Duration::from_secs(secs)
}

/// Closes the staging memfd on drop. The parent drops its reference after the
/// child has been spawned; the child's inherited copy keeps `/proc/self/fd/<n>`
/// valid until ld.so finishes loading the shim, and is closed when it exits.
pub struct MemFd(pub libc::c_int);
impl Drop for MemFd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            unsafe {
                libc::close(self.0);
            }
        }
    }
}

/// Stage the embedded shim as a sealed `memfd_create` file and return a
/// `/proc/self/fd/<n>` path the dynamic linker can preload, plus a guard holding
/// the fd open. The fd is left inheritable (no `MFD_CLOEXEC`) so the child keeps
/// it across `execve` and `/proc/self/fd/<n>` resolves in the child; we then seal
/// it so the loaded image cannot be modified by anyone holding the fd.
pub fn stage_shim() -> Result<(PathBuf, MemFd)> {
    const MFD_ALLOW_SEALING: libc::c_uint = 0x0002;
    let name = std::ffi::CString::new("envvault-harden").unwrap();
    let raw = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr(),
            MFD_ALLOW_SEALING as libc::c_uint,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error())
            .context("memfd_create failed (the hardening shim needs Linux 3.17+)");
    }
    let fd = raw as libc::c_int;
    let guard = MemFd(fd);

    write_all(fd, SHIM_SO).context("failed to write the hardening shim to the memfd")?;

    let seals: libc::c_int =
        libc::F_SEAL_SEAL | libc::F_SEAL_WRITE | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW;
    let rc = unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals as libc::c_int) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to seal the hardening shim memfd");
    }

    let path = PathBuf::from(format!("/proc/self/fd/{fd}"));
    Ok((path, guard))
}

/// `pipe2(2)` with no flags -> (read_fd, write_fd). Both inherit across the
/// child's exec (no CLOEXEC), which the shim needs.
pub fn pipe() -> Result<(libc::c_int, libc::c_int)> {
    let mut fds = [0 as libc::c_int; 2];
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("pipe2");
    }
    Ok((fds[0], fds[1]))
}

/// Poll `fd` for the shim's one-byte "R" signal, up to `timeout`. Returns false
/// on timeout or EOF (shim never ran).
pub fn wait_for_ready(fd: libc::c_int, timeout: Duration) -> bool {
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
pub fn write_all(fd: libc::c_int, buf: &[u8]) -> Result<()> {
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
