//! Config-integrity baseline for `run --verify`.
//!
//! A same-uid attacker can poison the *config/trust* files a launched tool reads
//! directly — `~/.gitconfig` (`http.sslCAInfo`, `http.proxy`), `~/.curlrc`,
//! `~/.npmrc` (`cafile`), `~/.netrc`, `~/.config/pip/pip.conf`, a planted CA in
//! `~/.pki/nssdb` — none of which need an environment variable and any of which
//! can be planted *before* envvault starts. Masking removes those files (breaks
//! legitimate config); this module instead *verifies* them against a root-owned
//! baseline the attacker cannot forge, and (via [`crate::sandbox::freeze_items`])
//! freezes the verified bytes into the session so they cannot change underneath
//! the tool.
//!
//! The model: `sudo envvault baseline set` records BLAKE3 hashes of the tracked
//! set into `/etc/envvault/<user>.baseline` (root-owned — the trust anchor). At
//! launch, [`verify_and_collect`] re-hashes each path; **any divergence fails
//! closed**, and on a full match it returns the verified content to freeze. The
//! hash anchors integrity (clean at start?); the namespace freeze anchors time
//! (it can't change after the check — see `sandbox`).
//!
//! Honest limits (documented, not hidden): only *tracked* paths are protected;
//! `baseline set` blesses whatever is on disk at that instant; tracked paths are
//! followed through symlinks and it is the *content* that is verified/frozen, so
//! repointing a tracked symlink to identically-hashing content is undetected and
//! repointing it *after* the check is a residual; and this only governs what
//! `run` launches. It shrinks attack surface and detects poisoning — it does not
//! "prevent MITM" (that belongs in the client: cert pinning / challenge-response).

use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Root-owned directory holding per-user baselines. A same-uid attacker cannot
/// write here, which is the whole point — it is the trust anchor.
pub const BASELINE_DIR: &str = "/etc/envvault";

/// Per-file size cap when hashing, so a crafted huge file (or a symlink to one)
/// can't exhaust memory. Config files are tiny; an NSS cert DB is a few MiB.
const MAX_TRACKED_FILE: u64 = 64 * 1024 * 1024;

/// Default trust/config paths tracked by `baseline set`, relative to the user's
/// home. Whether each is a file or a directory is detected at runtime. Extend a
/// baseline with `baseline set --add <path>`.
pub const TRUST_CONFIG_PATHS: &[&str] = &[
    ".gitconfig",
    ".curlrc",
    ".wgetrc",
    ".npmrc",
    ".netrc",
    ".config/pip/pip.conf",
    ".pki",
];

/// One verified, content-addressed entry to reproduce in the session namespace.
/// Returned by [`verify_and_collect`]; consumed by `sandbox::freeze_items`.
pub enum FrozenItem {
    /// A regular file: bind these exact verified bytes over `path`.
    File {
        path: PathBuf,
        bytes: Zeroizing<Vec<u8>>,
    },
    /// A tracked directory tree: re-materialize these `(relative-path, bytes)`
    /// in a fresh tmpfs over `path`.
    Dir {
        path: PathBuf,
        files: Vec<(PathBuf, Zeroizing<Vec<u8>>)>,
    },
    /// A path that was absent when blessed: neutralize it if it now exists.
    Absent { path: PathBuf },
}

impl FrozenItem {
    /// The path this item governs (for excluding frozen paths from masking).
    pub fn path(&self) -> &Path {
        match self {
            FrozenItem::File { path, .. }
            | FrozenItem::Dir { path, .. }
            | FrozenItem::Absent { path } => path,
        }
    }
}

/// A standalone tracked file (or a file inside a tracked directory): its
/// absolute path and the BLAKE3 hex of its content.
struct FileEntry {
    path: PathBuf,
    hash: String,
}

/// A tracked directory and the full set of files it contained when blessed (so
/// additions and removals are detectable, not just edits).
struct DirGroup {
    path: PathBuf,
    files: Vec<FileEntry>,
}

/// A parsed baseline: standalone files, tracked directory trees, and paths that
/// were absent (and must stay neutralized).
pub struct Baseline {
    files: Vec<FileEntry>,
    dirs: Vec<DirGroup>,
    absent: Vec<PathBuf>,
}

impl Baseline {
    /// Total number of tracked entries (files + dir-contained files + absences),
    /// for status messages.
    pub fn len(&self) -> usize {
        self.files.len()
            + self.absent.len()
            + self.dirs.iter().map(|d| d.files.len()).sum::<usize>()
    }

    #[allow(dead_code)] // paired with `len` for clippy's len_without_is_empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Render to the on-disk text form (tab-separated `<kind>\t<hash|->\t<path>`).
    fn serialize(&self, user: &str) -> String {
        let mut s = String::new();
        s.push_str(&format!(
            "# envvault config-integrity baseline for user {user}\n"
        ));
        s.push_str(
            "# fields: <kind>\\t<blake3-hex|->\\t<path> — managed by `envvault baseline set`; do not edit\n",
        );
        for p in &self.absent {
            s.push_str(&format!("absent\t-\t{}\n", p.display()));
        }
        for fe in &self.files {
            s.push_str(&format!("file\t{}\t{}\n", fe.hash, fe.path.display()));
        }
        for g in &self.dirs {
            s.push_str(&format!("dir\t-\t{}\n", g.path.display()));
            for fe in &g.files {
                s.push_str(&format!("file\t{}\t{}\n", fe.hash, fe.path.display()));
            }
        }
        s
    }

    /// Parse the on-disk text form. `file` lines that fall under a declared
    /// `dir` are grouped into it; the rest are standalone.
    fn parse(text: &str) -> Result<Baseline> {
        let mut raw_files: Vec<FileEntry> = Vec::new();
        let mut dir_decls: Vec<PathBuf> = Vec::new();
        let mut absent: Vec<PathBuf> = Vec::new();
        for line in text.lines() {
            let line = line.trim_end_matches(['\r', '\n']);
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut it = line.splitn(3, '\t');
            let kind = it.next().unwrap_or("");
            let hash = it.next().unwrap_or("");
            let path = it.next().unwrap_or("");
            if path.is_empty() {
                bail!("malformed baseline line: {line:?}");
            }
            let path = PathBuf::from(path);
            match kind {
                "file" => raw_files.push(FileEntry {
                    path,
                    hash: hash.to_string(),
                }),
                "dir" => dir_decls.push(path),
                "absent" => absent.push(path),
                other => bail!("unknown baseline entry kind {other:?}"),
            }
        }
        // Longest dir path first, so a file is grouped under its most specific
        // tracked directory.
        dir_decls.sort_by_key(|d| std::cmp::Reverse(d.as_os_str().len()));
        let mut dirs: Vec<DirGroup> = dir_decls
            .into_iter()
            .map(|path| DirGroup {
                path,
                files: Vec::new(),
            })
            .collect();
        let mut files: Vec<FileEntry> = Vec::new();
        for fe in raw_files {
            match dirs.iter_mut().find(|g| fe.path.starts_with(&g.path)) {
                Some(g) => g.files.push(fe),
                None => files.push(fe),
            }
        }
        Ok(Baseline {
            files,
            dirs,
            absent,
        })
    }

    /// Whether `p` is a top-level tracked path.
    pub fn tracks(&self, p: &Path) -> bool {
        self.dirs.iter().any(|d| d.path == p)
            || self.files.iter().any(|f| f.path == p)
            || self.absent.iter().any(|a| a == p)
    }

    /// If `p` lies *inside* a tracked directory root (and isn't that root),
    /// return the covering root — pinning it separately would be redundant.
    pub fn covered_by_dir(&self, p: &Path) -> Option<PathBuf> {
        self.dirs
            .iter()
            .map(|d| &d.path)
            .find(|d| p != d.as_path() && p.starts_with(d))
            .cloned()
    }

    /// Remove the top-level entries for `paths` (removing a directory root drops
    /// its children too). Returns the paths actually removed.
    fn remove_top_level(&mut self, paths: &[PathBuf]) -> Vec<PathBuf> {
        let mut removed = Vec::new();
        for p in paths {
            let mut hit = false;
            let n = self.dirs.len();
            self.dirs.retain(|d| d.path != *p);
            hit |= self.dirs.len() != n;
            let n = self.files.len();
            self.files.retain(|f| f.path != *p);
            hit |= self.files.len() != n;
            let n = self.absent.len();
            self.absent.retain(|a| a != p);
            hit |= self.absent.len() != n;
            if hit {
                removed.push(p.clone());
            }
        }
        removed
    }

    fn merge(&mut self, other: Baseline) {
        self.files.extend(other.files);
        self.dirs.extend(other.dirs);
        self.absent.extend(other.absent);
    }

    fn sort(&mut self) {
        self.files.sort_by(|a, b| a.path.cmp(&b.path));
        self.dirs.sort_by(|a, b| a.path.cmp(&b.path));
        self.absent.sort();
    }
}

/// What a `pin`/`unpin` edit changed, for user-facing messages.
#[derive(Default)]
pub struct EditReport {
    /// Newly tracked paths.
    pub added: Vec<PathBuf>,
    /// Already-tracked paths whose hash was refreshed to the current state.
    pub repinned: Vec<PathBuf>,
    /// Paths skipped because a tracked directory already covers them: `(path, dir)`.
    pub skipped_covered: Vec<(PathBuf, PathBuf)>,
    /// Paths removed from tracking.
    pub removed: Vec<PathBuf>,
    /// `unpin` targets that weren't top-level tracked paths.
    pub not_found: Vec<PathBuf>,
}

/// Pin `add` into `base`: freshly hash those paths and merge them in, replacing
/// any existing top-level entry for the *same* path. Other entries keep their
/// stored hashes — pinning one file does **not** re-bless the rest (use
/// `baseline set` for a full re-bless). Paths already covered by a tracked
/// directory are skipped.
pub fn pin(mut base: Baseline, add: &[PathBuf]) -> Result<(Baseline, EditReport)> {
    let mut rep = EditReport::default();
    let mut to_compute: Vec<PathBuf> = Vec::new();
    for p in add {
        if let Some(dir) = base.covered_by_dir(p) {
            rep.skipped_covered.push((p.clone(), dir));
            continue;
        }
        if base.tracks(p) {
            rep.repinned.push(p.clone());
        } else {
            rep.added.push(p.clone());
        }
        to_compute.push(p.clone());
    }
    if !to_compute.is_empty() {
        let sub = compute(&to_compute)?;
        base.remove_top_level(&to_compute);
        base.merge(sub);
        base.sort();
    }
    Ok((base, rep))
}

/// Unpin `remove` from `base`: drop the matching top-level entries (a directory
/// root drops its children). Paths that weren't tracked are reported, not an error.
pub fn unpin(mut base: Baseline, remove: &[PathBuf]) -> (Baseline, EditReport) {
    let mut rep = EditReport::default();
    let removed = base.remove_top_level(remove);
    for p in remove {
        if removed.iter().any(|r| r == p) {
            rep.removed.push(p.clone());
        } else {
            rep.not_found.push(p.clone());
        }
    }
    base.sort();
    (base, rep)
}

/// BLAKE3 hex of `bytes`.
fn hash_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// Read a file's bytes (following symlinks), refusing one larger than
/// [`MAX_TRACKED_FILE`] before allocating.
fn read_capped(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let meta = std::fs::metadata(path)
        .with_context(|| format!("failed to stat {}", path.display()))?;
    if meta.len() > MAX_TRACKED_FILE {
        bail!(
            "{} is too large to track ({} bytes > {} MiB cap)",
            path.display(),
            meta.len(),
            MAX_TRACKED_FILE / (1024 * 1024)
        );
    }
    let bytes = std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(Zeroizing::new(bytes))
}

/// Recursively collect every regular file reachable under `dir`, as
/// `(absolute-path, bytes)`. Symlinked *files* are followed and their content
/// collected; symlinked *directories* are skipped (so the walk can't escape the
/// tree or loop). Special files (sockets, fifos) are ignored.
fn collect_dir_files(dir: &Path, out: &mut Vec<(PathBuf, Zeroizing<Vec<u8>>)>) -> Result<()> {
    let rd = std::fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))?;
    let mut paths: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
    paths.sort();
    for p in paths {
        let lmeta = match std::fs::symlink_metadata(&p) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if lmeta.file_type().is_symlink() {
            // Follow to a regular file only; never recurse through a symlinked dir.
            if let Ok(tm) = std::fs::metadata(&p) {
                if tm.is_file() {
                    out.push((p.clone(), read_capped(&p)?));
                }
            }
        } else if lmeta.is_dir() {
            collect_dir_files(&p, out)?;
        } else if lmeta.is_file() {
            out.push((p.clone(), read_capped(&p)?));
        }
    }
    Ok(())
}

/// Compute a fresh baseline over the given absolute paths. A missing path is
/// recorded as absent; a directory is walked into a tracked tree; a regular file
/// (or a symlink to one) is content-hashed. Special files are skipped.
pub fn compute(tracked: &[PathBuf]) -> Result<Baseline> {
    let mut files: Vec<FileEntry> = Vec::new();
    let mut dirs: Vec<DirGroup> = Vec::new();
    let mut absent: Vec<PathBuf> = Vec::new();
    for abs in tracked {
        match std::fs::metadata(abs) {
            Err(_) => absent.push(abs.clone()),
            Ok(m) if m.is_dir() => {
                let mut collected = Vec::new();
                collect_dir_files(abs, &mut collected)?;
                let mut group = DirGroup {
                    path: abs.clone(),
                    files: collected
                        .into_iter()
                        .map(|(p, b)| FileEntry {
                            path: p,
                            hash: hash_hex(&b),
                        })
                        .collect(),
                };
                group.files.sort_by(|a, b| a.path.cmp(&b.path));
                dirs.push(group);
            }
            Ok(m) if m.is_file() => {
                let b = read_capped(abs)?;
                files.push(FileEntry {
                    path: abs.clone(),
                    hash: hash_hex(&b),
                });
            }
            Ok(_) => { /* socket/fifo/device — not a config artifact, skip */ }
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    dirs.sort_by(|a, b| a.path.cmp(&b.path));
    absent.sort();
    Ok(Baseline {
        files,
        dirs,
        absent,
    })
}

/// Validate a user name used to build a baseline file path, refusing anything
/// that could escape `/etc/envvault` (`/`, `..`, control chars, empties).
fn valid_user(user: &str) -> bool {
    !user.is_empty()
        && user != "."
        && user != ".."
        && !user.contains('/')
        && !user.contains('\0')
        && user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// `/etc/envvault/<user>.baseline`.
pub fn baseline_path(user: &str) -> PathBuf {
    Path::new(BASELINE_DIR).join(format!("{user}.baseline"))
}

/// Read and parse the baseline for `user` (a normal-user, read-only operation —
/// the file is 0644 root-owned). Errors with guidance if none exists.
pub fn read(user: &str) -> Result<Baseline> {
    if !valid_user(user) {
        bail!("invalid user name {user:?}");
    }
    let path = baseline_path(user);
    let text = std::fs::read_to_string(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            anyhow::anyhow!(
                "no integrity baseline for user '{user}' at {}.\n\
                 Create one with: sudo envvault baseline set",
                path.display()
            )
        } else {
            anyhow::Error::new(e).context(format!("failed to read {}", path.display()))
        }
    })?;
    Baseline::parse(&text)
}

/// Write the baseline for `user` into the root-owned `/etc/envvault` (caller must
/// already be root). Journaled: temp file → fsync → atomic rename → dir fsync,
/// with explicit 0755 dir / 0644 file permissions.
#[cfg(unix)]
pub fn write(user: &str, baseline: &Baseline) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if !valid_user(user) {
        bail!("invalid user name {user:?}");
    }
    let dir = Path::new(BASELINE_DIR);
    std::fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755));

    let final_path = baseline_path(user);
    let tmp = dir.join(format!(".{user}.baseline.tmp.{}", std::process::id()));
    let text = baseline.serialize(user);
    std::fs::write(&tmp, text.as_bytes())
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644));
    if let Ok(f) = std::fs::File::open(&tmp) {
        let _ = f.sync_all();
    }
    std::fs::rename(&tmp, &final_path)
        .with_context(|| format!("failed to install {}", final_path.display()))?;
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn write(_user: &str, _baseline: &Baseline) -> Result<()> {
    bail!("the integrity baseline is only supported on Unix-like systems");
}

/// Verify every entry against the current filesystem, returning the items to
/// freeze plus a list of human-readable mismatches. Standalone files and tracked
/// directories must match exactly; absent paths are always reproduced (and
/// neutralized at freeze time if they reappeared) rather than treated as errors.
fn verify_entries(b: &Baseline) -> (Vec<FrozenItem>, Vec<String>) {
    let mut items: Vec<FrozenItem> = Vec::new();
    let mut problems: Vec<String> = Vec::new();

    for fe in &b.files {
        match read_capped(&fe.path) {
            Ok(bytes) => {
                if hash_hex(&bytes) == fe.hash {
                    items.push(FrozenItem::File {
                        path: fe.path.clone(),
                        bytes,
                    });
                } else {
                    problems.push(format!("content changed: {}", fe.path.display()));
                }
            }
            Err(_) => problems.push(format!("missing or unreadable: {}", fe.path.display())),
        }
    }

    for p in &b.absent {
        items.push(FrozenItem::Absent { path: p.clone() });
    }

    for g in &b.dirs {
        match verify_dir(g) {
            Ok(files) => items.push(FrozenItem::Dir {
                path: g.path.clone(),
                files,
            }),
            Err(mut probs) => problems.append(&mut probs),
        }
    }

    (items, problems)
}

/// Verify one tracked directory: the live recursive file set must equal the
/// blessed set exactly (no additions, removals, or content changes). On success
/// returns `(relative-path, bytes)` for every file, to re-materialize in tmpfs.
fn verify_dir(g: &DirGroup) -> std::result::Result<Vec<(PathBuf, Zeroizing<Vec<u8>>)>, Vec<String>> {
    let mut live: Vec<(PathBuf, Zeroizing<Vec<u8>>)> = Vec::new();
    if let Err(e) = collect_dir_files(&g.path, &mut live) {
        return Err(vec![format!(
            "cannot read tracked directory {}: {e:#}",
            g.path.display()
        )]);
    }
    let live_map: HashMap<&Path, &Zeroizing<Vec<u8>>> =
        live.iter().map(|(p, b)| (p.as_path(), b)).collect();
    let mut problems: Vec<String> = Vec::new();
    let mut frozen: Vec<(PathBuf, Zeroizing<Vec<u8>>)> = Vec::new();

    for fe in &g.files {
        match live_map.get(fe.path.as_path()) {
            Some(bytes) => {
                if hash_hex(bytes) == fe.hash {
                    let rel = fe
                        .path
                        .strip_prefix(&g.path)
                        .unwrap_or(&fe.path)
                        .to_path_buf();
                    frozen.push((rel, (*bytes).clone()));
                } else {
                    problems.push(format!(
                        "content changed in {}: {}",
                        g.path.display(),
                        fe.path.display()
                    ));
                }
            }
            None => problems.push(format!(
                "missing from {}: {}",
                g.path.display(),
                fe.path.display()
            )),
        }
    }
    for (p, _) in &live {
        if !g.files.iter().any(|fe| &fe.path == p) {
            problems.push(format!(
                "unexpected file in {}: {}",
                g.path.display(),
                p.display()
            ));
        }
    }

    if problems.is_empty() {
        Ok(frozen)
    } else {
        Err(problems)
    }
}

/// Verify and return the items to freeze, failing closed on **any** mismatch.
/// Used by `run --verify` before handing control to the program.
pub fn verify_and_collect(b: &Baseline) -> Result<Vec<FrozenItem>> {
    let (items, problems) = verify_entries(b);
    if !problems.is_empty() {
        bail!(
            "config integrity check failed — refusing to run:\n  {}\n\
             If these changes are intended, re-bless with `sudo envvault baseline set`.",
            problems.join("\n  ")
        );
    }
    Ok(items)
}

/// Report (without aborting) which tracked paths differ from the baseline.
/// Empty = everything matches. Used by `baseline check`.
pub fn check(b: &Baseline) -> Vec<String> {
    verify_entries(b).1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("envvault-integ-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn file_roundtrip_detects_change() {
        let home = tmp("file");
        let f = home.join(".gitconfig");
        std::fs::write(&f, b"[http]\n  proxy = none\n").unwrap();
        let b = compute(&[f.clone()]).unwrap();
        assert!(check(&b).is_empty(), "clean tree should verify");

        // Tamper → detected, and verify_and_collect fails closed.
        std::fs::write(&f, b"[http]\n  sslCAInfo = /tmp/evil\n").unwrap();
        assert_eq!(check(&b).len(), 1);
        assert!(verify_and_collect(&b).is_err());
    }

    #[test]
    fn absent_is_not_a_mismatch_and_yields_neutralize_item() {
        let home = tmp("absent");
        let missing = home.join(".curlrc");
        let b = compute(&[missing.clone()]).unwrap();
        // Even after an attacker creates it, this is reproduced (neutralized),
        // not reported as a mismatch.
        std::fs::write(&missing, b"proxy = http://evil\n").unwrap();
        assert!(check(&b).is_empty());
        let items = verify_and_collect(&b).unwrap();
        assert!(matches!(items.as_slice(), [FrozenItem::Absent { .. }]));
    }

    #[test]
    fn dir_completeness_catches_added_and_changed_files() {
        let home = tmp("dir");
        let pki = home.join(".pki");
        std::fs::create_dir_all(&pki).unwrap();
        std::fs::write(pki.join("cert9.db"), b"good").unwrap();
        let b = compute(&[pki.clone()]).unwrap();
        assert!(check(&b).is_empty());

        // Added file → mismatch.
        std::fs::write(pki.join("evil.pem"), b"planted CA").unwrap();
        assert!(!check(&b).is_empty());
        assert!(verify_and_collect(&b).is_err());
    }

    #[test]
    fn serialize_parse_roundtrip() {
        let home = tmp("ser");
        std::fs::write(home.join(".gitconfig"), b"x").unwrap();
        let pki = home.join(".pki");
        std::fs::create_dir_all(&pki).unwrap();
        std::fs::write(pki.join("a"), b"a").unwrap();
        let tracked = vec![home.join(".gitconfig"), home.join(".missing"), pki.clone()];
        let b = compute(&tracked).unwrap();
        let text = b.serialize("tester");
        let b2 = Baseline::parse(&text).unwrap();
        assert_eq!(b.len(), b2.len());
        assert!(check(&b2).is_empty(), "reparsed baseline still verifies");
    }

    #[test]
    fn pin_adds_without_reblessing_others() {
        let home = tmp("pin");
        let a = home.join(".gitconfig");
        let b = home.join(".curlrc");
        std::fs::write(&a, b"A1").unwrap();
        let base = compute(&[a.clone()]).unwrap();

        // Tamper A on disk, THEN pin B. Pin must not re-bless A.
        std::fs::write(&a, b"A2-tampered").unwrap();
        std::fs::write(&b, b"B1").unwrap();
        let (base, rep) = pin(base, &[b.clone()]).unwrap();
        assert_eq!(rep.added, vec![b.clone()]);
        assert!(rep.repinned.is_empty());

        // A is now tracked at its OLD hash → still flagged; B verifies clean.
        let problems = check(&base);
        assert_eq!(problems.len(), 1, "only A should mismatch: {problems:?}");
        assert!(problems[0].contains(".gitconfig"));
        assert!(base.tracks(&b));
    }

    #[test]
    fn repin_reblesses_only_that_path() {
        let home = tmp("repin");
        let a = home.join(".gitconfig");
        std::fs::write(&a, b"V1").unwrap();
        let base = compute(&[a.clone()]).unwrap();
        std::fs::write(&a, b"V2").unwrap();
        assert!(!check(&base).is_empty(), "edit should mismatch before re-pin");

        let (base, rep) = pin(base, &[a.clone()]).unwrap();
        assert_eq!(rep.repinned, vec![a.clone()]);
        assert!(check(&base).is_empty(), "re-pinning blesses the new content");
    }

    #[test]
    fn pin_skips_paths_covered_by_tracked_dir() {
        let home = tmp("cover");
        let pki = home.join(".pki");
        std::fs::create_dir_all(&pki).unwrap();
        let child = pki.join("cert9.db");
        std::fs::write(&child, b"c").unwrap();
        let base = compute(&[pki.clone()]).unwrap();

        let (base, rep) = pin(base, &[child.clone()]).unwrap();
        assert_eq!(rep.skipped_covered.len(), 1);
        assert_eq!(rep.skipped_covered[0].1, pki);
        assert!(!base.tracks(&child), "child stays covered by the dir, not standalone");
    }

    #[test]
    fn unpin_removes_and_reports_not_found() {
        let home = tmp("unpin");
        let a = home.join(".gitconfig");
        let b = home.join(".curlrc");
        std::fs::write(&a, b"a").unwrap();
        let base = compute(&[a.clone(), b.clone()]).unwrap(); // b is absent
        assert!(base.tracks(&a) && base.tracks(&b));

        let (base, rep) = unpin(base, &[a.clone(), home.join(".never")]);
        assert_eq!(rep.removed, vec![a.clone()]);
        assert_eq!(rep.not_found, vec![home.join(".never")]);
        assert!(!base.tracks(&a));
        assert!(base.tracks(&b), "untouched entries remain");
    }

    #[test]
    fn unpin_dir_drops_its_children() {
        let home = tmp("unpindir");
        let pki = home.join(".pki");
        std::fs::create_dir_all(&pki).unwrap();
        std::fs::write(pki.join("a"), b"a").unwrap();
        std::fs::write(pki.join("b"), b"b").unwrap();
        let base = compute(&[pki.clone()]).unwrap();
        assert!(base.len() >= 2);

        let (base, rep) = unpin(base, &[pki.clone()]);
        assert_eq!(rep.removed, vec![pki.clone()]);
        assert_eq!(base.len(), 0, "dir and all its children gone");
    }

    #[test]
    fn rejects_path_traversal_user() {
        assert!(!valid_user("../etc/shadow"));
        assert!(!valid_user("a/b"));
        assert!(!valid_user(""));
        assert!(valid_user("debasish"));
        assert!(valid_user("user.name-1"));
    }
}
