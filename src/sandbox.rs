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
//! While the child runs, an optional background autosaver re-encrypts the
//! directory whenever its contents have been quiet for a debounce window, so a
//! SIGKILL or power loss costs at most the changes since the last quiet moment.
//!
//! The vault is decrypted via the caller-supplied `open` closure, which we call
//! *after* the namespace is set up and the process is re-hardened — see the
//! dumpability dance in `linux::run`.
//!
//! On other platforms this is unsupported (no unprivileged tmpfs-over-dir).

use crate::dirvault::DirVault;
use anyhow::Result;
use std::path::Path;
use std::time::Duration;

/// Set up the RAM sandbox at the vault's target path, run `program args...`,
/// and re-encrypt on exit. If `autosave` is `Some(debounce)`, also re-encrypt
/// during the run once changes have been quiet for `debounce`. `open` decrypts
/// the vault (prompting for the password) and is invoked only after the process
/// has been re-hardened, so the secret never exists while the process is briefly
/// dumpable. `prepare` runs inside the namespace after the decrypted contents
/// are exposed and *before* the child is spawned — the hook where `dir run`'s
/// `--verify`/`--sandbox` apply their in-namespace freeze/mask (and may fail
/// closed). On a zero exit this returns `Ok(())`; otherwise it calls
/// `std::process::exit` with the child's code.
#[cfg(target_os = "linux")]
pub fn run<F, G>(
    vault_path: &Path,
    program: &str,
    args: &[String],
    autosave: Option<Duration>,
    harden: bool,
    open: F,
    prepare: G,
) -> Result<()>
where
    F: FnOnce() -> Result<DirVault>,
    G: FnOnce() -> Result<()>,
{
    linux::run(vault_path, program, args, autosave, harden, open, prepare)
}

#[cfg(not(target_os = "linux"))]
pub fn run<F, G>(
    _vault_path: &Path,
    _program: &str,
    _args: &[String],
    _autosave: Option<Duration>,
    _harden: bool,
    _open: F,
    _prepare: G,
) -> Result<()>
where
    F: FnOnce() -> Result<DirVault>,
    G: FnOnce() -> Result<()>,
{
    anyhow::bail!(
        "directory vaults (`dir run`) are only supported on Linux — they rely on \
         unprivileged user + mount namespaces to expose the decrypted directory in \
         RAM. `dir init`, `dir export`, and `dir list` still work on this platform."
    )
}

/// Run `program args...` in a private mount namespace where each path in `hide`
/// is masked by an empty overlay, so the command — and everything it spawns —
/// cannot read those credentials. Everything else (home, env, agent sockets) is
/// inherited unchanged, so the command otherwise runs as if on the host. Pure
/// subtraction: the real files are never touched, and the namespace (with all
/// overlays) is discarded on exit — there is nothing to restore. Linux-only.
#[cfg(target_os = "linux")]
pub fn unrun(program: &str, args: &[String], hide: &[std::path::PathBuf]) -> Result<()> {
    linux::unrun(program, args, hide)
}

#[cfg(not(target_os = "linux"))]
pub fn unrun(_program: &str, _args: &[String], _hide: &[std::path::PathBuf]) -> Result<()> {
    anyhow::bail!(
        "`unrun` is only supported on Linux — it relies on unprivileged user + \
         mount namespaces to hide credential paths from the command."
    )
}

/// Enter a private user+mount namespace in the *current* process, so subsequent
/// `mask_paths` calls hide paths only from this process and its children. Used
/// by `run --sandbox` to establish the masked session before exec/harden. Linux
/// only — the boundary is the namespace, set up by the trusted launcher before
/// any untrusted code runs.
#[cfg(target_os = "linux")]
pub fn enter_user_mount_ns() -> Result<()> {
    linux::enter_user_mount_ns()
}

#[cfg(not(target_os = "linux"))]
pub fn enter_user_mount_ns() -> Result<()> {
    anyhow::bail!(
        "credential sandboxing (`run --sandbox`/`--allow`) is only supported on Linux — \
         it relies on unprivileged user + mount namespaces."
    )
}

/// Mask each path in `paths` with an empty overlay in the current mount
/// namespace (call after `enter_user_mount_ns`). Linux only.
#[cfg(target_os = "linux")]
pub fn mask_paths(paths: &[std::path::PathBuf]) -> Result<()> {
    linux::mask_paths(paths)
}

#[cfg(not(target_os = "linux"))]
pub fn mask_paths(_paths: &[std::path::PathBuf]) -> Result<()> {
    anyhow::bail!("credential sandboxing is only supported on Linux.")
}

/// Freeze each verified config/trust item into the current mount namespace (call
/// after `enter_user_mount_ns`): bind the verified bytes of a file over its path,
/// re-materialize a verified directory tree in a fresh tmpfs, and neutralize a
/// path that should be absent. The bound content can no longer change underneath
/// the program — a same-uid attacker outside the namespace writes under the mount
/// and is shadowed. Linux only. See `crate::integrity`.
#[cfg(target_os = "linux")]
pub fn freeze_items(items: &[crate::integrity::FrozenItem]) -> Result<()> {
    linux::freeze_items(items)
}

#[cfg(not(target_os = "linux"))]
pub fn freeze_items(_items: &[crate::integrity::FrozenItem]) -> Result<()> {
    anyhow::bail!("config integrity freezing (`run --verify`) is only supported on Linux.")
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::dirvault::Kind;
    use crate::shim;
    use anyhow::Context;
    use std::collections::hash_map::DefaultHasher;
    use std::ffi::CString;
    use std::hash::Hasher;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::path::PathBuf;
    use std::process::Command;
    use std::ptr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Instant;

    pub fn run<F, G>(
        vault_path: &Path,
        program: &str,
        args: &[String],
        autosave: Option<Duration>,
        harden: bool,
        open: F,
        prepare: G,
    ) -> Result<()>
    where
        F: FnOnce() -> Result<DirVault>,
        G: FnOnce() -> Result<()>,
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
        //    for the password and returns the target path + plaintext. Held in
        //    an Arc so the autosaver thread can share it.
        let dirvault = Arc::new(open()?);
        let target = dirvault.target().to_path_buf();

        // 4. Expose the decrypted contents at `target`, in RAM only.
        match dirvault.kind() {
            Kind::Dir => {
                // tmpfs over the directory, then extract the tree into it.
                std::fs::create_dir_all(&target)
                    .with_context(|| format!("failed to create mountpoint {}", target.display()))?;
                mount_tmpfs(&target)?;
                dirvault
                    .extract_into(&target)
                    .context("failed to populate the in-memory directory")?;
            }
            Kind::File => {
                // Virtualize at *directory* granularity so the app can atomically
                // rename-replace the secret file in RAM (you cannot rename over a
                // bind-mounted single file — the kernel returns EBUSY, or the new
                // file lands on real disk and is lost). We tmpfs the parent, bind
                // the real siblings (e.g. a live DB) back so their writes persist,
                // and drop the decrypted secret in as an ordinary tmpfs file.
                let parent = target
                    .parent()
                    .context("vaulted file has no parent directory")?;
                let basename = target.file_name().context("vaulted file has no file name")?;
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;

                // 1. Bind the real parent to a private stash so we can still
                //    reach the real siblings after tmpfs covers the parent.
                let stash = scratch_dir("stash")?;
                bind_dir(parent, &stash)?;

                // 2. tmpfs over the parent: a writable RAM directory at the real
                //    path. The real contents stay live, only via `stash`.
                mount_tmpfs(parent)?;

                // 3. Bind every real sibling (all but the vaulted file) back in,
                //    so persistent files keep living on real disk.
                rebind_siblings(&stash, parent, basename)?;

                // 4. Decrypt the secret into the tmpfs parent as an ordinary file
                //    (not a bind) so rename-replace happens entirely in RAM.
                dirvault
                    .extract_into(parent)
                    .context("failed to populate the in-memory file")?;
            }
        }

        // 4b. Apply any in-namespace hardening (`dir run --verify`/`--sandbox`):
        //     verify+freeze config and mask credential paths, before the child
        //     runs and while still non-dumpable. May fail closed — if it does we
        //     bail here, before spawning the child and before any re-encrypt, so
        //     the on-disk vault is left untouched.
        prepare()?;

        // 5. Optionally start the debounced autosaver (spawned after unshare, so
        //    the single-thread requirement for CLONE_NEWUSER was already met).
        let stop = Arc::new(AtomicBool::new(false));
        let autosaver = autosave.map(|debounce| {
            spawn_autosaver(
                Arc::clone(&dirvault),
                vault_path.to_path_buf(),
                target.clone(),
                debounce,
                Arc::clone(&stop),
            )
        });

        // 6. Ignore terminal signals in this supervisor so a Ctrl-C (or hang-up)
        //    goes to the child and we still reach the re-encrypt step.
        ignore_signals();

        // 7. Spawn the child (it inherits the namespace and the tmpfs view).
        let mut cmd = Command::new(program);
        cmd.args(args);

        // 7a. With `--harden`, preload the shim in non-dumpable-only mode so the
        //     program (and the secret it reads from the in-RAM file) can't be
        //     core-dumped / ptraced by a same-uid attacker. Best-effort: the
        //     secret reaches the program via the file regardless, so a failed
        //     preload only means "still dumpable" — we warn rather than abort.
        let mut memfd_guard: Option<shim::MemFd> = None;
        let mut ready_pipe: Option<(libc::c_int, libc::c_int)> = None; // (read, write)
        if harden {
            let (shim_path, memfd) =
                shim::stage_shim().context("failed to stage the hardening shim")?;
            let (ready_r, ready_w) = shim::pipe().context("pipe() failed")?;
            cmd.env("LD_PRELOAD", &shim_path);
            cmd.env("ENVVAULT_NODUMP", "1");
            cmd.env("ENVVAULT_READY_FD", ready_w.to_string());
            memfd_guard = Some(memfd);
            ready_pipe = Some((ready_r, ready_w));
        }

        let child_close = ready_pipe.map(|(r, _)| r); // parent's read end, closed in the child
        unsafe {
            cmd.pre_exec(move || {
                if let Some(fd) = child_close {
                    libc::close(fd);
                }
                for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
                    libc::signal(sig, libc::SIG_DFL);
                }
                Ok(())
            });
        }
        let mut child = cmd
            .spawn()
            .with_context(|| format!("failed to execute '{program}'"))?;

        // 7b. If hardening, verify the shim actually loaded (best-effort warn),
        //     then drop the parent's shim fds.
        if let Some((ready_r, ready_w)) = ready_pipe {
            drop(memfd_guard.take()); // the child holds its own inherited copy
            unsafe {
                libc::close(ready_w);
            }
            if !shim::wait_for_ready(ready_r, shim::ready_timeout()) {
                eprintln!(
                    "warning: '{program}' did not load the hardening shim; its memory (and the \
                     decrypted secrets it holds) is core-dumpable by a same-uid process — likely \
                     a static or setuid binary, or LD_PRELOAD was ignored."
                );
            }
            unsafe {
                libc::close(ready_r);
            }
        }

        let status = child.wait().context("failed waiting for child process")?;

        // 8. The child is gone; restore default signal handling so the final
        //    re-encrypt below is interruptible with Ctrl-C if it ever hangs
        //    (e.g. a full or stuck disk) rather than requiring `kill -9`.
        restore_default_signals();

        // Stop the autosaver and flush a final, authoritative snapshot.
        stop.store(true, Ordering::Relaxed);
        if let Some(handle) = autosaver {
            let _ = handle.join();
        }
        if let Err(e) = dirvault.save_from(vault_path, &target) {
            eprintln!(
                "error: failed to re-encrypt directory vault: {e:#}\n\
                 The child's latest changes were NOT saved; the vault on disk \
                 reflects the last successful save."
            );
            drop(dirvault);
            std::process::exit(1);
        }
        drop(dirvault); // wipe decrypted plaintext before exiting

        // 9. Propagate the child's exit status. (Process exit tears down the
        //    namespace, unmounting and freeing the tmpfs automatically.)
        match status.code() {
            Some(0) => Ok(()),
            Some(code) => std::process::exit(code),
            None => std::process::exit(128 + status.signal().unwrap_or(0)),
        }
    }

    /// Enter a fresh private user+mount namespace in the current process: the
    /// unshare + id-map + re-harden + private-root dance (same as `run`). Must be
    /// called while single-threaded. Afterwards, mounts made here are private to
    /// this process and its children.
    pub fn enter_user_mount_ns() -> Result<()> {
        // Capture real ids before unshare (inside an unmapped userns we'd read
        // the overflow uid and write a bogus map).
        let euid = unsafe { libc::geteuid() };
        let egid = unsafe { libc::getegid() };
        set_dumpable(true);
        let ns_setup = (|| -> Result<()> {
            if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } != 0 {
                let err = std::io::Error::last_os_error();
                if matches!(err.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES)) {
                    return Err(userns_unavailable(&format!("unshare: {err}")));
                }
                return Err(
                    anyhow::Error::new(err).context("unshare(CLONE_NEWUSER|CLONE_NEWNS) failed"),
                );
            }
            configure_id_maps(euid, egid)
        })();
        set_dumpable(false);
        ns_setup?;
        mount_private_root()
    }

    /// Mask each existing path in `paths` with an empty overlay in the current
    /// mount namespace: a directory gets an empty tmpfs, a regular file an
    /// empty-file bind. `metadata` follows symlinks so we mask whatever the path
    /// resolves to; missing/dangling/special paths are skipped. Call inside a
    /// private namespace (see `enter_user_mount_ns`).
    pub fn mask_paths(paths: &[PathBuf]) -> Result<()> {
        // One empty file on a private tmpfs, reused to mask regular files.
        let scratch = scratch_dir("mask")?;
        mount_tmpfs(&scratch)?;
        let empty = scratch.join("empty");
        std::fs::write(&empty, b"")
            .with_context(|| format!("failed to create {}", empty.display()))?;
        for path in paths {
            match std::fs::metadata(path) {
                Ok(m) if m.is_dir() => mount_tmpfs(path)?,
                Ok(m) if m.is_file() => bind_file(&empty, path)?,
                _ => continue, // missing, dangling, or special — nothing to hide
            }
        }
        Ok(())
    }

    /// Freeze verified config/trust content into the current namespace. Files
    /// are bound from a private tmpfs holding the exact verified bytes; tracked
    /// directories are re-materialized in a fresh tmpfs over the path; paths that
    /// should be absent are neutralized (emptied) if they reappeared. Reuses the
    /// same scratch-tmpfs + bind primitives as `mask_paths`.
    pub fn freeze_items(items: &[crate::integrity::FrozenItem]) -> Result<()> {
        use crate::integrity::FrozenItem;
        if items.is_empty() {
            return Ok(());
        }
        // One private tmpfs holds the verified file bytes we bind from, plus a
        // reusable empty file for neutralizing reappeared "absent" files.
        let scratch = scratch_dir("freeze")?;
        mount_tmpfs(&scratch)?;
        let empty = scratch.join("empty");
        std::fs::write(&empty, b"")
            .with_context(|| format!("failed to create {}", empty.display()))?;

        let mut n: usize = 0;
        for item in items {
            match item {
                FrozenItem::File { path, bytes } => {
                    // Stage the verified bytes on the private tmpfs, then bind
                    // them over the path (mount resolves a symlinked path to its
                    // target). The program now reads exactly what we verified.
                    let staged = scratch.join(format!("f{n}"));
                    n += 1;
                    std::fs::write(&staged, bytes.as_slice())
                        .with_context(|| format!("failed to stage {}", staged.display()))?;
                    bind_file(&staged, path)?;
                }
                FrozenItem::Dir { path, files } => {
                    // Empty the directory in RAM, then write the verified tree
                    // back into it. Host writes to the real dir are shadowed.
                    mount_tmpfs(path)?;
                    for (rel, bytes) in files {
                        let dst = path.join(rel);
                        if let Some(parent) = dst.parent() {
                            std::fs::create_dir_all(parent).with_context(|| {
                                format!("failed to create {}", parent.display())
                            })?;
                        }
                        std::fs::write(&dst, bytes.as_slice())
                            .with_context(|| format!("failed to write {}", dst.display()))?;
                    }
                }
                FrozenItem::Absent { path } => {
                    // The blessed state had nothing here. If an attacker created
                    // something, neutralize it (empty dir / empty file) so the
                    // tool falls back to defaults; otherwise nothing to do.
                    match std::fs::metadata(path) {
                        Ok(m) if m.is_dir() => mount_tmpfs(path)?,
                        Ok(m) if m.is_file() => bind_file(&empty, path)?,
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }

    /// Run `program` with every path in `hide` masked by an empty overlay, in a
    /// private mount namespace. Inverse of `run`: it hides instead of reveals,
    /// so there is no decrypt, no re-encrypt, and nothing to restore — the real
    /// files are never touched and the namespace is discarded on exit.
    pub fn unrun(program: &str, args: &[String], hide: &[PathBuf]) -> Result<()> {
        enter_user_mount_ns()?;
        mask_paths(hide)?;

        // Spawn the child (it inherits the namespace and every overlay). Restore
        // default signal handling in the child so Ctrl-C reaches it.
        ignore_signals();
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

        // Process exit tears down the namespace and all overlays automatically;
        // the host is untouched. Just propagate the child's exit status.
        match status.code() {
            Some(0) => Ok(()),
            Some(code) => std::process::exit(code),
            None => std::process::exit(128 + status.signal().unwrap_or(0)),
        }
    }

    /// Watch `target` and re-encrypt to `vault_path` once its contents have been
    /// unchanged for `debounce`. Polls a cheap fingerprint (paths + sizes +
    /// mtimes); credential dirs are tiny so this is negligible. Stops when
    /// `stop` is set.
    fn spawn_autosaver(
        dirvault: Arc<DirVault>,
        vault_path: PathBuf,
        target: PathBuf,
        debounce: Duration,
        stop: Arc<AtomicBool>,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let poll = Duration::from_millis(500);
            let mut last_seen = path_fingerprint(&target);
            let mut last_saved = last_seen; // the just-extracted state is on disk
            let mut last_change = Instant::now();
            while !stop.load(Ordering::Relaxed) {
                thread::sleep(poll);
                let fp = path_fingerprint(&target);
                if fp != last_seen {
                    last_seen = fp;
                    last_change = Instant::now();
                }
                // Save once changes have settled and there's something new.
                if last_seen != last_saved && last_change.elapsed() >= debounce {
                    match dirvault.save_from(&vault_path, &target) {
                        Ok(()) => last_saved = last_seen,
                        Err(e) => eprintln!("warning: autosave failed: {e:#}"),
                    }
                }
            }
        })
    }

    /// A cheap fingerprint of a path: for a directory, every entry's path/size/
    /// mtime folded together; for a single file, its size + mtime. Changes when
    /// content is added, removed, resized, or rewritten (which bumps mtime).
    fn path_fingerprint(path: &Path) -> u64 {
        let mut hasher = DefaultHasher::new();
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.is_dir() => fingerprint_into(path, &mut hasher),
            Ok(meta) => {
                hasher.write_u64(meta.len());
                hasher.write_i64(meta.mtime());
                hasher.write_i64(meta.mtime_nsec());
            }
            Err(_) => {}
        }
        hasher.finish()
    }

    fn fingerprint_into(dir: &Path, hasher: &mut DefaultHasher) {
        let read = match std::fs::read_dir(dir) {
            Ok(r) => r,
            Err(_) => return,
        };
        let mut paths: Vec<PathBuf> = read.flatten().map(|e| e.path()).collect();
        paths.sort();
        for path in &paths {
            hasher.write(path.as_os_str().as_bytes());
            if let Ok(meta) = std::fs::symlink_metadata(path) {
                hasher.write_u64(meta.len());
                hasher.write_i64(meta.mtime());
                hasher.write_i64(meta.mtime_nsec());
                if meta.is_dir() {
                    fingerprint_into(path, hasher);
                }
            }
        }
    }

    /// A fresh private scratch directory under `$XDG_RUNTIME_DIR` (already tmpfs,
    /// cleaned at logout) or the temp dir, tagged for its role and the pid.
    fn scratch_dir(tag: &str) -> Result<PathBuf> {
        let base = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let dir = base.join(format!(".envvault-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create scratch dir {}", dir.display()))?;
        Ok(dir)
    }

    /// `mount(src, target, NULL, MS_BIND, NULL)` — splice the file at `src` in
    /// at `target` (both must already exist).
    fn bind_file(src: &Path, target: &Path) -> Result<()> {
        bind(src, target, libc::MS_BIND)
    }

    /// Recursively bind-mount the directory `src` at `target` (carrying any
    /// submounts along), so the real directory's contents appear at `target`.
    fn bind_dir(src: &Path, target: &Path) -> Result<()> {
        bind(src, target, libc::MS_BIND | libc::MS_REC)
    }

    /// Shared bind-mount helper. `src` and `target` must both already exist and
    /// be of matching type (file→file, dir→dir).
    fn bind(src: &Path, target: &Path, flags: libc::c_ulong) -> Result<()> {
        let s = CString::new(src.as_os_str().as_bytes()).context("source path has a NUL byte")?;
        let t = CString::new(target.as_os_str().as_bytes()).context("target path has a NUL byte")?;
        let rc =
            unsafe { libc::mount(s.as_ptr(), t.as_ptr(), ptr::null(), flags, ptr::null()) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed to bind-mount onto {}", target.display()));
        }
        Ok(())
    }

    /// For a single-file vault: re-expose every real sibling of the vaulted file
    /// inside the tmpfs `parent`, so persistent neighbours (a live database, a
    /// cache) keep reading and writing real disk. `stash` is a bind of the real
    /// parent (made before the tmpfs went on); `exclude` is the vaulted file's
    /// own name, which we leave out so the decrypted copy can own that path.
    ///
    /// Directories and regular files are bind-mounted back (so their data and
    /// writes stay on real disk); symlinks are recreated in the tmpfs (binding
    /// through a symlink is fragile). Siblings *created* later land in the tmpfs
    /// and do not persist — a documented limitation of single-file vaults.
    fn rebind_siblings(stash: &Path, parent: &Path, exclude: &std::ffi::OsStr) -> Result<()> {
        for entry in std::fs::read_dir(stash)
            .with_context(|| format!("failed to read stashed dir {}", stash.display()))?
        {
            let entry = entry?;
            let name = entry.file_name();
            if name == exclude {
                continue;
            }
            let src = stash.join(&name);
            let dst = parent.join(&name);
            let ft = entry.file_type().with_context(|| {
                format!("failed to stat sibling {}", src.display())
            })?;
            if ft.is_symlink() {
                let link_target = std::fs::read_link(&src)
                    .with_context(|| format!("failed to read symlink {}", src.display()))?;
                std::os::unix::fs::symlink(&link_target, &dst)
                    .with_context(|| format!("failed to recreate symlink {}", dst.display()))?;
            } else if ft.is_dir() {
                std::fs::create_dir_all(&dst)
                    .with_context(|| format!("failed to create mountpoint {}", dst.display()))?;
                bind_dir(&src, &dst)?;
            } else {
                std::fs::write(&dst, b"")
                    .with_context(|| format!("failed to create mountpoint {}", dst.display()))?;
                bind_file(&src, &dst)?;
            }
        }
        Ok(())
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

    /// Restore default handling for the signals `ignore_signals` muted, so the
    /// supervisor is interruptible again once the child has exited.
    fn restore_default_signals() {
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
            unsafe {
                libc::signal(sig, libc::SIG_DFL);
            }
        }
    }
}
