//! Process hardening: prevent a same-privilege attacker from scraping secrets
//! out of this process's memory.
//!
//! Without this, any process running as the same user can send `envvault` a
//! core-dumping signal (e.g. `kill -QUIT <pid>`) while a decrypted vault or the
//! password is resident in memory, then read the resulting core file — or, on
//! Linux, `ptrace`-attach / read `/proc/<pid>/mem` directly.
//!
//! What we do depends on the platform:
//!
//! - **Linux / Android** — `prctl(PR_SET_DUMPABLE, 0)`. This both suppresses
//!   core dumps and flips ownership of `/proc/<pid>` to root, which also blocks
//!   same-uid `ptrace` and `/proc/<pid>/mem` access. Strongest option.
//! - **macOS / BSD** — no `prctl`; instead set `RLIMIT_CORE` to 0 to disable
//!   core dumps. Weaker (it does not block a debugger), but those platforms
//!   already restrict same-uid `ptrace` by default.
//! - **Windows / other** — no-op (no equivalent dumpable attribute here).
//!
//! This protects the `envvault` process itself for its lifetime. It deliberately
//! does not restrict a program launched by `run`: `execve` resets these limits,
//! so the child behaves like any normal process (and its secrets live in its
//! environment regardless, which this control was never meant to cover).
//!
//! Note: this is a defense against *same-privilege* attackers, not root. Root
//! can read any process's memory regardless of these settings.

/// Linux/Android: mark the process non-dumpable.
///
/// **Fatal on failure.** The only way `prctl(PR_SET_DUMPABLE, 0)` fails here is a
/// kernel that refuses it (e.g. a seccomp filter). On Linux this is the *whole*
/// protection — proceeding would leave secrets readable in memory by any same-uid
/// process — so we refuse to run rather than silently degrade.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn protect_process() {
    // SAFETY: `prctl(PR_SET_DUMPABLE, 0)` only toggles this process's dumpable
    // attribute; it reads/writes no caller-provided memory.
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        eprintln!(
            "error: could not mark this process non-dumpable ({err}).\n\
             On Linux this is the core protection against a same-uid process \
             reading secrets from memory; refusing to run rather than expose them. \
             (Is prctl(PR_SET_DUMPABLE) blocked by a seccomp filter?)"
        );
        std::process::exit(1);
    }
}

/// Other unix (macOS, the BSDs): disable core dumps via `RLIMIT_CORE = 0`.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
pub fn protect_process() {
    let rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `setrlimit` reads `rlim` (a valid local) and sets a resource
    // limit for this process; it writes no caller memory.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        eprintln!("warning: could not disable core dumps (they may expose secrets): {err}");
    }
}

/// No-op on non-unix platforms (no equivalent dumpable attribute).
#[cfg(not(unix))]
pub fn protect_process() {}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod tests {
    use super::*;

    #[test]
    fn process_becomes_non_dumpable() {
        protect_process();
        // PR_GET_DUMPABLE returns the current dumpable value (0 = off).
        let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
        assert_eq!(dumpable, 0, "process should be non-dumpable after hardening");
    }
}

#[cfg(all(test, unix, not(any(target_os = "linux", target_os = "android"))))]
mod tests {
    use super::*;

    #[test]
    fn core_dumps_are_disabled() {
        protect_process();
        let mut rlim = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut rlim) };
        assert_eq!(rc, 0, "getrlimit should succeed");
        assert_eq!(rlim.rlim_cur, 0, "core dump size limit should be 0");
    }
}
