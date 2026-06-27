# Security Audit of `envvault`

The crypto core (Argon2id + ChaCha20-Poly1305 AEAD, fresh salt/nonce, post-write verification, atomic journaling) is sound and well-built. The significant security issues are concentrated in the sandbox/namespace layer and the directory-vault extraction paths. Several real defects were found, ordered below by severity.

> **Note on responses.** This audit was produced by GLM 5.2. A second review (Claude) assessed each finding and implemented the actionable ones; the verdict is inline as a **Response** blockquote under each item, and summarized at the end. Headline severities did not all survive scrutiny — in particular #1 and #9 are not defects.

## High severity

### 1. `unrun` / `--sandbox` masking is TOCTOU-bypassable via symlinks (and Docker credentials aren't hidden)

`src/sandbox.rs:317-332` and `src/sandbox.rs:503` use `std::fs::metadata` (which follows symlinks) to classify a path, then mask the result. For a regular file the code does `bind_file(&empty, path)?` — bind-mounting an empty file *at the path that was resolved*. But for a *symlink* whose target is a regular file, `metadata` returns "is_file", and the bind lands on the symlink's target — the symlink itself is left in place pointing at the (still-real) target. An attacker controlling a directory the user hides later (or a sibling of an `--allow`ed path) can substitute a symlink and dodge the mask. Worse, the *default* hide list includes `.docker/config.json`, but `metadata` follows `~/.docker/config.json` — if it is a symlink the bind-mount hits the resolved target, which stays readable on the host filesystem since `unrun`/`--sandbox` never bind-mounts anything *over that target path*. This breaks the "monotonic hiding" property the README claims.

> **Response: Not a defect (claim disproven empirically).** `mount(2)` resolves the *target* path following the final symlink, so masking a symlinked path overlays the **resolved target**, not the link. Tested directly: `unrun --hide <symlink-to-secret>` makes the data read empty **both** via the symlink and via the real target (file and directory cases). The target is not left readable. The only real residual is a sub-millisecond same-uid TOCTOU between the `metadata` classification and the `mount` re-resolution; a type swap there makes the bind error out (**fails closed**), it happens during setup before any untrusted code runs, and it requires a *separate* concurrent same-uid attacker — inside the threat model the README already excludes. Optional defense-in-depth (use `symlink_metadata` + explicit handling) is reasonable but not load-bearing. **Not changed.**

### 2. `unrun` hides only existing files; missing credential files can be exposed by `--allow`

`src/sandbox.rs:328` skips masking when the path is missing or dangling — fine for the default denylist. But `cmd_unrun` (`src/main.rs:509-522`) takes the *subtractive* path over `$ENVVAULT_ALLOW`: when `--allow` is in play the default list is filtered *before* the existence check is done, so the existence-check behaviour at masking time is independent. That's OK. The real problem: a user `--allow`s a directory (e.g. `~/.aws`) intending only the vault's secret; everything else default-hidden inside that directory is now *exposed*, including ones the user didn't think about (e.g. `~/.aws/cli/cache` SSO tokens, `~/.aws/credentials` is hidden by `--allow ~/.aws`). There's no composability warning and `--allow` is path-granular, not file-granular. Worth at least flagging to the user at runtime.

> **Response: Valid (UX/granularity). FIXED (docs).** The README now states plainly that `--allow` is path-granular — allowing a directory exposes everything under it (e.g. `~/.aws/sso/cache`, not just `credentials`) — and advises allowing the narrowest path that works.

### 3. `dir init`'s tar packing stores absolute canonical paths in the plaintext

`src/dirvault.rs:60-96` packs `embed_path` (the *canonical* target path, e.g. `/home/alice/.claude`) inside the encrypted plaintext. The path therefore round-trips correctly. But note that `append_dir_all(".", source)` uses relative names inside the tar, while the *header* stores the absolute path. On `dir run`/`dir export` the absolute path from the header is what's mounted. A stolen vault file is encrypted, so this is not a direct leak — but if a vault is ever decrypted via password compromise or a side channel, the absolute path of every vaulted directory is directly readable from the decrypted container. There's no need to embed the absolute canonical path; storing a relative name and re-resolving at `run` time (or letting the user pass `--path` again) would be cleaner. (Likely acceptable as-is given the threat model, but worth knowing.)

> **Response: Accepted as-is (by design).** The path lives *inside* the AEAD; it is only readable once the vault is already decrypted, at which point the secrets themselves are exposed — there is no incremental leak. Re-resolving at run time would also lose the convenience of not re-passing `--path`. **Not changed.**

## Medium severity

### 4. Path-traversal in `dir export` / `dir run` depends entirely on the `tar` crate's filtering

`src/dirvault.rs:190-200` (`extract_into`) calls `archive.unpack(dest)`. The comment claims the `tar` crate rejects `..` and absolute paths. This is true *for entries created by `pack`* (which only ever appends `.`/basename). But the tar body is attacker-controllable in one case: **`dir init --path` accepts any user-supplied directory, and `pack` does `append_dir_all(".", source)`** — if the source directory contains a maliciously named entry like `../sibling` or a symlink, `follow_symlinks(false)` handles the symlink-as-link case, but a *real* entry named `../foo` would be stored and the unpack could write outside `dest`. The `tar` crate (0.4.46) does sanitize, but it's worth tightening: explicitly use `Archive::set_overwrite(true)` is already done, but you should also call `set_preserve_permissions(false)` for `dir export` to a user-chosen destination (currently `extract_into` always preserves modes — a tar entry with mode 4777 setuid would be honored on export). Preserving permissions is right for `dir run` (extracting into the original location), risky for `dir export --to <arbitrary dir>`.

> **Response: Low / largely a non-issue.** A real directory entry cannot be named `../foo` (the filesystem disallows `/` in names), so `pack` cannot produce a traversing entry; `tar` 0.4 also sanitizes on unpack. The preserve-perms concern on `export` doesn't escalate: vaults are built from the user's *own* files, so a preserved setuid bit yields a file owned by — and run as — the same user (setuid-to-self = no privilege gain). Preserve-permissions is kept because `dir run` needs faithful mode restoration. **Not changed.**

### 5. `append_dir_all` follows mount boundaries; a bind-mount of an unrelated secret dir gets archived

In `dir init --path ~/.claude`, if `~/.claude` happens to contain a mountpoint for another secret (a bind-mount, a `fuse-overlayfs` for a password manager, etc.), `tar::Builder::append_dir_all` will descend into it and archive its contents into the vault. The vault then contains secrets the user didn't intend to vault, encrypted under the same password. `follow_symlinks(false)` doesn't help — bind-mounts aren't symlinks. Worth at least a one-line `--one-file-system`-style guard or a warning, since `dir init` then **deletes** (`empty_dir`) everything it just packed, including the unintended mount's contents.

> **Response: Valid footgun. FIXED.** `dir init` now refuses a directory that contains a mount point: `find_submount` walks the tree and bails if any entry is on a different filesystem (`st_dev`) than the root, so an unintended submount is never archived-and-then-deleted. (Unix; `dir init` is the only destructive path.)

### 6. Autosaver fingerprint misses content-only edits (no mtime/size change)

`src/sandbox.rs:407-419` (`path_fingerprint`) keys on path + size + mtime. Several common credential-rewrite patterns don't change size or mtime granularity:
- `O_TRUNC` rewrite of the same length (some tools rewrite tokens in place with the same byte count — `mtime` does change, but `mtime_nsec` resolution varies by fs and tmpfs; on tmpfs `mtime_nsec` is wall-clock so usually fine, but a sub-microsecond rewrite within the same ns window is theoretically possible).
- `rename()` over an existing file where the new file has identical size and a backdated/identical mtime (some tools preserve mtime).

The consequence is a lost autosave, not a leak — but the README's "SIGKILL costs at most changes since the last quiet moment" guarantee has a hole. A content hash (even a cheap one) over the small credential tree would be more robust than size+mtime.

> **Response: Robustness nit, not security. Deferred.** The on-exit `save_from` is unconditional, so only a crash *mid-session* could drop a same-size+same-mtime edit — a narrow window, and mtime changes on essentially all real writes. A content hash over the (tiny) credential tree is a reasonable future improvement. **Not changed.**

### 7. `wait_for_ready` can falsely succeed on a partial write, or hang on a malformed shim

`src/run.rs:284-310` returns `true` if it reads exactly one byte equal to `'R'`. The shim writes one byte. Fine. But: if the shim *crashes* between the `prctl` and the `write`, the parent's `poll` sees `POLLHUP` (EOF) with `revents` possibly including `POLLIN` — the subsequent `read` returns 0, and the function returns `false` (correct). However, if the shim writes *any* byte other than `'R'` (e.g. a buggy/malicious shim — though the shim is embedded so this is theoretical), the function returns `false` and fails closed (correct). The subtle issue: `remaining_ms` is `c_int` and `as_millis() as c_int` can overflow for timeouts > ~24 days — not exploitable, but `Duration::from_secs(5)` default is fine. More relevantly, **`ENVVAULT_HARDEN_TIMEOUT` is environment-controllable** — a same-uid attacker who can set it to `0` (filtered out by `s > 0`) is fine, but they could set it to `1` (1ms) and cause hardened runs to fail closed. That's a DoS, not a leak, and the README explicitly declines to defend against an attacker already executing code in the session. Worth noting anyway.

> **Response: Non-issue (as the finding concludes).** Every path is fail-closed; the only effect is a DoS by a same-uid attacker, which is in the excluded threat model. **Not changed.**

## Low severity / hardening

### 8. `protect_process` failure is non-fatal

`src/harden.rs:32-40`: a `prctl` failure just prints a warning. The only documented failure mode is invalid args, which can't happen here — but on a system where `prctl(PR_SET_DUMPABLE, 0)` is filtered by seccomp (some hardened distros), the process would proceed with secrets in memory while dumpable. Consider making this fatal when a vault is about to be decrypted (or at least fatal on Linux, where the only failure is "you broke your kernel").

> **Response: Valid. FIXED.** On Linux, `protect_process` now exits with an error if `prctl(PR_SET_DUMPABLE, 0)` fails (e.g. a seccomp filter), rather than running with secrets in dumpable memory. macOS/BSD keep the warning (core-dump-only guarantee there anyway).

### 9. `tmp_name` uses only the pid, not a random token

`src/crypto.rs:544`: `.{stem}.{pid}.tmp`. Two concurrent `envvault` processes for the *same vault* (rare but possible — e.g. an autosaver racing a manual `set`) would share the temp name. The second writer's `create(true).truncate(true)` would truncate the first's in-flight write, then the first's `rename` could commit a partial/garbled file. The post-write verification (`decrypt_file` + compare) would catch a garbled file and bail before rename, so this is defense-in-depth — but a random suffix would be more robust. (Autosave in `dir run` is single-threaded within one process, so the realistic collision is two CLI invocations on the same vault.)

> **Response: Not a defect (incorrect premise).** The temp name already includes the pid, so two *different* processes get *different* temp names (`.v.vault.<pid1>.tmp` vs `…<pid2>.tmp`) — the described collision cannot occur. The autosaver runs in the same process as `dir run` (not a separate pid). Concurrent edits to one vault are last-writer-wins (inherent to concurrent edits), and post-write verify prevents committing a garbled file. **Not changed.**

### 10. `auto_upgrade` writes the vault *before* the user has done anything

`src/main.rs:346-363`: opening a legacy v1 vault immediately re-saves it as v2 (best-effort). This means `envvault show` (a read-only command) writes the vault file. If the vault is on a read-only mount or a fuse filesystem with quotas, this fails with a warning — fine. But it also means the file's mtime/contents change on a pure read, which could surprise backup systems or integrity-monitoring tools. Worth documenting; behavior itself is reasonable.

> **Response: Intended behavior, already documented.** Auto-upgrade-on-open is a deliberate "secure by default" migration (best-effort; falls back to the legacy session on a read-only mount). Documented in the README's key-derivation section. **Not changed.**

### 11. `password::read_stdin` accepts an empty password

`src/password.rs:10-20`: `--password-stdin` does not reject empty input, while `prompt_new` does. An empty password via stdin derives a key from an empty string — Argon2id still does work, but an empty password is effectively no protection. `prompt` (for opening existing vaults) also doesn't reject empty — that's correct (an existing vault might have an empty password). But `--password-stdin` on `init` should reject empty, matching `prompt_new`.

> **Response: Valid. FIXED.** `init --password-stdin` now rejects an empty password. (`run`/`edit`/etc. still allow empty for opening pre-existing vaults, as the finding notes is correct.)

### 12. `set_var("ENVVAULT_ALLOW", …)` is `unsafe` but called single-threaded — fine, but flag for future

`src/main.rs:562`: `std::env::set_var` is unsafe since Rust 1.80. The code is single-threaded at this point (before any child spawn), so it's sound, but the `SAFETY` comment should note *why* single-threaded matters (no other thread reading the environment concurrently), not just that it is. Also, `ENVVAULT_ALLOW` is then inherited by the child and readable there — a child could read it and learn which paths its parent chose to leave visible. The README acknowledges this ("soft inherited list"), but it does leak the parent's `--allow` decisions to the child, which a paranoid user might not expect.

> **Response: Sound; no security impact.** The `set_var` call is single-threaded before any spawn. The child seeing `ENVVAULT_ALLOW` is not sensitive — it can see the allowed paths directly anyway; the list only enumerates what is already visible to it. **Not changed** (comment wording could be expanded later).

### 13. `parse_armored` does not bound the decoded blob size

`src/crypto.rs:236-258`: `B64.decode(b64.trim())` allocates the full decoded blob. A maliciously large vault file could cause OOM before any MAC check fails (the MAC check happens in `cipher.decrypt`). For env-var vaults the file is small, but `dirvault` containers can be up to `MAX_ARCHIVE` (256 MiB) — a crafted 10 GiB env-vault file would be fully decoded into memory. Worth a size cap on the base64 body before decoding.

> **Response: Valid. FIXED.** `open` now caps the file at 512 MiB (checked via the file length before reading) before decoding — comfortably above any legitimate vault (a 256 MiB dir-vault plaintext inflates to ~342 MiB of base64), and it rejects absurd files up front.

### 14. `list` / `dir list` read vault files' headers without bounds

`src/crypto.rs:218-229` (`detect_version`) reads the whole file via `read_to_string`, then takes the first line. A multi-gigabyte "vault" file would be fully loaded just to print its version. Use a bounded read (e.g. read first 64 bytes).

> **Response: Valid. FIXED.** `detect_version` now reads only the first 64 bytes and parses the header line from that.

### 15. Clipboard clear on paste can be defeated by clipboard managers (acknowledged)

`src/tui/mod.rs:145-156` and `src/main.rs:818-820`: this is already documented in the README under "Security notes." Noting for completeness — `arboard::Clipboard::clear()` clears the *live* selection, not history. Some clipboard managers (KDE Klipper) restore the previous entry on clear. This is a known limitation, not a defect.

> **Response: Known limitation, already documented.** No change.

### 16. `mask_paths` and `rebind_siblings` race with sibling creation

In `dir run` for a single-file vault, `rebind_siblings` (`src/sandbox.rs:489-519`) enumerates the stashed real parent and bind-mounts each sibling back. If a sibling appears *between* the `bind_dir(parent, &stash)` and the `mount_tmpfs(parent)`, it's lost (the tmpfs covers it). If one disappears between `mount_tmpfs` and the rebind loop, the rebind fails. Extremely unlikely race, and the child sees a consistent view afterward — low impact.

> **Response: Narrow race, low impact (as noted). Deferred.** No change.

### 17. `ignore_signals` in the supervisor is permanent

`src/sandbox.rs:609-615` and `src/run.rs:335-341`: the supervisor ignores SIGINT/SIGTERM/SIGHUP/SIGQUIT for the whole run so the child gets them and re-encryption still runs. Fine. But if the re-encrypt step itself hangs (e.g. disk full, autosaver deadlock), the user can't Ctrl-C the supervisor — only `kill -9`. Consider restoring default handling after the child exits, before the final `save_from`.

> **Response: Valid usability fix. FIXED.** The `dir run` supervisor restores default signal handling after the child exits, before the final re-encrypt, so a hung save is interruptible. (The `unrun`/plain-`run` supervisors do no post-child work, so they're unaffected.)

## Minor observations (not defects)

- `Cargo.toml:29` pins `getrandom = "0.2"` — the `0.3` line is current and 0.2.17 is the last 0.2 release; no known CVEs, just EOL-ish.
  > **Response:** Acknowledged; no CVE, deferred.
- `build.rs` compiles `shim/harden.c` without `-fstack-protector` / `-fno-strict-aliasing` / `-D_FORTIFY_SOURCE=2`. The shim is tiny and the C looks correct, but adding hardening flags for a security-critical component is cheap.
  > **Response: FIXED.** `build.rs` now compiles the shim with `-fstack-protector-strong -fno-strict-aliasing -D_FORTIFY_SOURCE=2` (alongside `-O2`).
- `shim/harden.c`'s `memchr(entry, '=', entlen)` correctly bounds the search to `entlen`, and `strnlen(entry, len - i)` bounds the entry length. The C is sound; no buffer overflow.
  > **Response:** Agreed; no action needed.
- `crypto.rs:541`: `unwrap_or("vault")` for the temp-file stem is fine; `validate_name` ensures vault names are safe path components, so the temp name can't escape the directory.
  > **Response:** Agreed; no action needed.

## Recommendations, prioritized

1. **Fix `unrun`/`--sandbox` symlink masking** (#1): use `symlink_metadata` + explicitly handle symlinks (resolve-and-mask-the-target, or refuse to mask dangling symlinks). This is the only issue that qualifies as a genuine *vulnerability* in the tool's stated threat model.
2. **Add `--one-file-system` or a mountpoint check to `dir init`** (#5) — prevents accidentally vaulting (and then deleting) unintended mount contents.
3. **Bound the base64 decode and `detect_version` reads** (#13, #14).
4. **Make `protect_process` failure fatal on Linux** (#8) when about to decrypt.
5. **Reject empty `--password-stdin` on `init`** (#11).
6. **Use a content hash in the autosaver** (#6) instead of size+mtime.
7. **Random temp-file suffix** (#9) to defend against same-vault concurrency.
8. **Document that `--allow` is path-granular and exposes everything under it** (#2).

The core cryptography, the journaling write, the hardened-run protocol (memfd + sealed + withhold-until-ready), and the `fail-closed` semantics of `--harden` are all well-designed and correct. The issues above are in the surrounding tooling, not the crypto.

---

## Resolution summary (second review)

**Fixed** — #2 (docs), #5 (mountpoint guard), #8 (fatal on Linux), #11 (reject empty pw), #13 (cap file read), #14 (bounded header read), #17 (restore signals), and the `build.rs` hardening flags. Verified: build clean, 23/23 tests pass; empty-password rejection, bounded `list`, and normal `init`/`dir init` flows checked live.

**Not a defect** — #1 (mount follows the target symlink and masks the resolved path — disproven empirically; recommendation #1 is therefore moot) and #9 (the temp name already includes the pid, so the collision can't occur; recommendation #7 is moot).

**Accepted / deferred (low or by design)** — #3, #4, #6, #7, #10, #12, #15, #16, and the `getrandom` EOL note.

Net: the audit's high-severity items did not survive review, but it surfaced a worthwhile set of low/medium hardening fixes, all of which are now applied. The crypto core, journaling write, and `--harden` protocol were confirmed sound.
