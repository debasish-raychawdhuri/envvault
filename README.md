# envvault

**Keep your API keys, tokens, and secrets in password-encrypted vaults — and
hand them only to the one program that needs them, never to your shell.**

`envvault` stores environment variables in named, encrypted files and launches
your programs with those variables injected into their environment. The secrets
are decrypted **in memory only**, passed straight to the child process, and
never written to disk in plaintext — and they never enter your interactive
shell, your shell history, or your clipboard.

```sh
envvault run work -- python train.py    # OPENAI_API_KEY etc. set only for this process
```

---

## The problem: secrets leak through everyday convenience

Storing credentials is easy. Storing them *safely* is not — the usual shortcuts
all leak:

### 1. Plaintext `.env` files and dotfiles
A `.env`, `~/.bashrc`, or `secrets.txt` with `OPENAI_API_KEY=sk-...` sits on
disk in the clear. Anything that can read your home directory can read your
keys: a malicious or compromised dependency, a backup that syncs to the cloud,
a misconfigured file share, a stolen or discarded laptop, or simply a
`git add .` that commits the file by accident. Once a key lands in git history
it is effectively public forever.

### 2. The shell environment
When you `export OPENAI_API_KEY=sk-...`, that value is inherited by **every**
process you launch from that shell — not just the program you meant it for.
Any of them can print, log, or exfiltrate it. On Linux a process's environment
is readable at `/proc/<pid>/environ`; crash reporters and error trackers
routinely capture the full environment and ship it to a third party. One
careless `env`, `printenv`, or a stack trace in a log file, and the key is out.

### 3. Shell history
`export KEY=...` or `KEY=... some-command` is written verbatim to
`~/.bash_history` / `~/.zsh_history`. Months later the secret is still sitting
in a plaintext file you forgot about — and gets copied to every machine you
sync your dotfiles to.

### 4. The clipboard
Copy-pasting a key from a password manager puts it on the system clipboard,
where it lingers until overwritten. Clipboard managers keep a searchable
**history** of everything copied, other apps can read the clipboard silently,
and browser pages can sometimes access it too. "Copy the key, paste it into the
terminal" quietly creates several new copies of your secret.

**The common thread:** secrets spread to places you didn't intend, persist
longer than you expect, and are exposed to far more code than the one program
that actually needs them.

## How envvault helps

`envvault` shrinks the exposure of a secret to the smallest possible window:

- **At rest**, secrets live only inside an encrypted vault file. Without your
  password the file is useless — safe to back up, sync, even commit.
- **In use**, the secret exists only in `envvault`'s memory (wiped on exit) and
  in the environment of the single child process you launched. It is never
  exported into your interactive shell, so nothing else inherits it. (For
  `run`, that one child's environment is still readable by a same-uid process
  via `/proc/<pid>/environ` — an inherent limit of env injection. When a tool
  can read its secret from a *file*, `dir run` removes even that exposure; see
  [`run` vs `dir run`](#run-vs-dir-run-keeping-secrets-off-the-environment).)
- **Nothing transient leaks**: no plaintext temp file, no shell-history line, no
  clipboard copy. You type a password, the program runs, the secret is gone.

It does **not** try to defend against a process that is *already* running as you
with a debugger attached, or malware with root — no userspace tool can. The goal
is to eliminate the casual, accidental leaks above, which are how secrets
actually escape in practice.

## How it works

- **Key derivation** — Argon2id (a memory-hard KDF) turns your password plus a
  per-vault random 16-byte salt into a 32-byte key. Argon2id makes brute-forcing
  a stolen vault file expensive. New vaults use OWASP-recommended parameters
  (m=64 MiB, t=3, p=1); vaults created before this shipped use the crate
  defaults (m=19 MiB, t=2). The on-disk header carries the version
  (`ENVVAULT v1` vs `ENVVAULT v2`), so existing vaults keep working unchanged.
  A legacy vault is **upgraded automatically the first time it is opened** (the
  password is in hand, so it's re-keyed to v2 and re-saved once; best-effort, so
  a read on a read-only directory still works and just stays v1). `envvault
  upgrade <name>` / `envvault dir upgrade <name>` force it explicitly without
  changing the password.
- **Encryption** — ChaCha20-Poly1305, an *authenticated* cipher, with a fresh
  random 12-byte nonce on every save. Authentication means a wrong password or a
  tampered file is **detected and rejected**, not silently mis-decrypted.
- **On-disk format** — a short text header plus a base64 body
  (`salt || nonce || ciphertext`). The file is plain UTF-8, so it survives
  copy-paste and is safe to commit to git or store in dotfiles.
- **Durable writes** — every save is journaled. The new ciphertext is written
  to a temp file, fsynced, **decrypted and verified** against what it should
  contain, and only then atomically renamed over the old vault (with the
  directory fsynced so the rename itself survives a power loss). A failed,
  corrupted, or interrupted write leaves the previous vault completely intact
  rather than truncating it — so a crash mid-re-encryption can never lose your
  secrets. The same path is used for env-var saves, the on-exit re-encrypt of a
  directory vault, and every debounced autosave during a `dir run`.
- **Hardening** — vault files are created `0600` and the vault directory `0700`
  (owner-only). Sensitive memory is zeroized on drop: the derived key, the
  password, the decrypted plaintext, the parsed vault entries, the editor's
  input buffer, and the serialized blob. On exit the interactive editor also
  overwrites ratatui's render buffers so a *revealed* value doesn't linger in
  freed terminal-cell memory. At startup the process also hardens itself against
  a same-user attacker dumping its memory: on **Linux** it marks itself
  **non-dumpable** (`prctl(PR_SET_DUMPABLE, 0)`), which blocks both core dumps
  (e.g. via `kill -QUIT`) and `ptrace`/`/proc/<pid>/mem` access; on **macOS/BSD**
  it disables core dumps (`RLIMIT_CORE = 0`). Windows has no equivalent step.

## Vaults are named

You refer to vaults by name (e.g. `work`, `personal`), not by path. Each is
encrypted separately with its own password and stored as one file in a fixed
per-user directory:

- `$ENVVAULT_DIR` if set, otherwise `<config-dir>/envvault` — that's
  `~/.config/envvault` on Linux and `~/Library/Application Support/envvault` on
  macOS.
- Files are named `<name>.vault`.

## How envvault compares — and why it exists

There are many good tools for handling secrets. Most of them, though, are built
for a *different* threat than the one a developer faces on their own laptop. The
question that separates them is simple:

> **When another program runs as *you* on your machine — a compromised npm/PyPI/
> cargo dependency, a postinstall script, malware launched under your account —
> can it walk away with your keys?**

This is the realistic attacker for most people. It isn't root, and it isn't a
remote intruder; it's code already executing at *your* privilege. The way most
tools lose to it is the same every time: **they leave a persistent secret at
rest that the attacker can simply read** — a plaintext file, a stored decryption
key, or an always-unlocked keyring daemon.

**This is the modern playbook, not a hypothetical.** The defining trait of
recent supply-chain attacks is that they exploit *no vulnerability on your
machine* — their code runs as you during an install, and the payload simply
**reads known credential paths and exfiltrates them**. The Codecov breach (2021)
shipped a tampered uploader that exfiltrated environment variables — and the CI
secrets in them. Waves of hijacked npm and PyPI packages have carried
credential-stealers that scan for and upload tokens, SSH keys, and cloud
credentials. The 2025 npm worm *Shai-Hulud* automated the whole loop: on install
it scanned the host for secrets and used the tokens it harvested to republish
itself into more packages. The job is always the same cheap one — get code
running as you, then read `~/.ssh`, `~/.aws/credentials`, `~/.npmrc`,
`~/.config/gh`, and the environment. envvault's bet is to make those reads come
up empty: an env-vault never exports into your shell, and a directory vault
leaves only an encrypted blob and an empty directory.

**And the personal machine is where this bites hardest.** A server or CI runner
is a controlled, boring place: a handful of vetted programs, installed on
purpose, each doing one job. Your laptop is the opposite — hundreds of processes
at any moment, and a constant churn of code you're just *trying out*: the latest
npm or PyPI package, a CLI you found on GitHub, an editor extension, the newest
game, a browser running untrusted JavaScript. Every one of them runs at your
privilege, and any one of them can read a secret left sitting at rest. So the
environment that holds your most personal, long-lived keys is also the one with
the largest population of untrusted code able to take them — precisely where
server- and team-oriented secret tooling offers the least protection. Closing
that gap is the point of envvault.

| Tool | How secrets sit at rest | What a process running as you can grab | Built for |
|------|-------------------------|----------------------------------------|-----------|
| plaintext `.env`, direnv | unencrypted on disk | the secrets, always — just read the file | convenience |
| dotenvx | encrypted `.env` (safe to commit) | the **private-key file** (`.env.keys`), then every secret | keeping secrets out of git |
| sops, age | encrypted file (age/PGP/KMS) | the decryption key (age/PGP keyfile or KMS creds), which usually sits in a local file or agent | teams, multi-recipient, many formats |
| envchain, OS keyring (GNOME Keyring / KWallet) | encrypted by the login keyring | **every secret, once the keyring is unlocked** — the Secret Service has no per-application access control, and the login keyring auto-unlocks at login | desktop convenience |
| Vault, Doppler, 1Password, Infisical, chamber | on a server / in the cloud | a token or session that fetches the secrets on demand | teams, infrastructure, audit |
| **envvault** | encrypted file (Argon2id + ChaCha20-Poly1305) | **nothing at rest** — the passphrase lives only in your head and, briefly, in a non-dumpable process | a solo developer's local keys on a shared-uid machine |

**Why envvault is built the way it is** — every design choice falls out of that
one threat:

- **No persistent unlock secret.** There is no stored key file and no
  always-on, auto-unlocked daemon. You type the passphrase per use; it exists
  only in your memory and transiently in the `envvault` process. A same-uid
  attacker has nothing sitting on disk to read — they'd have to catch the
  process *in the act*, keylog your typing, or replace the binary, all far
  harder and noisier than reading a file. This is the core advantage over
  dotenvx (a readable key file) and over the OS keyring (an unlocked daemon that
  serves any caller).
- **No plaintext on disk, ever — by construction.** The classic failure of
  "encrypt a file" tools is the *orphaned plaintext*: you create a cleartext
  file, encrypt it, and the original lingers — in the file you forgot to delete,
  in editor swap/backup files, in the shell history of how you made it, in a
  backup. envvault never creates that file. Secrets are entered directly into
  the encrypted store through the TUI or the no-echo `set` prompt, so there is no
  cleartext origin to leak. (This is also why `set` takes key *names*, never
  `KEY=VALUE` on the command line — argv would land in shell history and
  `/proc/<pid>/cmdline`.)
- **Smallest possible runtime window.** When you `run` a program, the secret is
  decrypted in memory and handed straight to that *one* child — never exported
  into your shell, so nothing else inherits it. The process marks itself
  non-dumpable so a same-uid attacker can't core-dump or `ptrace` it to scrape
  the secret out of memory.
- **No infrastructure.** One self-contained binary, one encrypted file per
  vault. No server to run, no account to create, no cloud KMS, no key
  distribution. Just a password and a file you can back up, sync, or even commit.

**What envvault is *not* for** — being honest about the trade-offs:

- **Teams.** A vault is locked by a single passphrase; there's no
  multi-recipient encryption or shared access. For a team, sops (multi-key) or a
  secret manager (Vault, Doppler, 1Password, Infisical) is the right tool.
- **CI / fully unattended automation.** The strength here is that *you* hold the
  passphrase. In CI you'd have to store it as a runner secret — at which point
  it's a persistent secret like everyone else's, and the advantage narrows. Tools
  designed around stored keys or fetch-tokens fit CI better.
- **Defeating root.** No userspace tool can. Root reads any process's memory,
  any file, and any TTY. envvault shrinks the exposure to same-privilege
  attackers and to secrets at rest — see *Security notes & limitations* below.

In short: **sops and dotenvx optimize for safely committing secrets to git;
keyrings and cloud managers optimize for team convenience and infrastructure.
envvault optimizes for the one program that needs a secret getting it, and
nothing else on your machine — not your shell, not your history, not a leftover
file, and not the next process that runs as you — ever does.**

---

## Install

`envvault` is a single self-contained binary. You need a Rust toolchain
([rustup.rs](https://rustup.rs)).

### From source

```sh
git clone https://github.com/debasish-raychawdhuri/envvault
cd envvault
cargo build --release
# the binary is now at ./target/release/envvault
```

### Install onto your PATH

```sh
# from inside the cloned repo
cargo install --path .

# …or straight from GitHub
cargo install --git https://github.com/debasish-raychawdhuri/envvault
```

This drops `envvault` into `~/.cargo/bin` (make sure that's on your `PATH`).

### Run the tests

```sh
cargo test
```

---

## Usage

```sh
# Create a new named vault and edit it in the interactive UI
envvault init work

# List all vaults
envvault list

# Edit a vault's secrets interactively (view / add / modify / delete)
envvault edit work

# Change a vault's password (asks for the current one, then the new one twice)
envvault passwd work

# Re-encrypt a vault under the stronger current Argon2id parameters (no-op if
# already current). The password is unchanged.
envvault upgrade work

# Run a program with the vault's variables in its environment
envvault run work -- python train.py
envvault run work -- bash -lc 'echo $OPENAI_API_KEY'

# Add or update secrets — prompts (no echo) for each value (so it never appears
# on the command line, in shell history, or in /proc/<pid>/cmdline), then wipes
# the clipboard after each value, since secrets are pasted rather than typed
envvault set work OPENAI_API_KEY DATABASE_URL

# Remove keys
envvault rm work DATABASE_URL

# Print decrypted contents to stdout (this exposes secrets!)
envvault show work

# Run an untrusted command with your credential files hidden from it (Linux):
# ~/.ssh, ~/.aws, ~/.config/gh, … read as empty inside, the rest is unchanged
envvault unrun -- npm install
envvault unrun --hide ~/.config/some-tool -- ./suspicious-script
```

### Commands

| Command | What it does |
|---------|--------------|
| `init <name>`            | Create a new vault (then open the editor). |
| `list`                   | List all vaults in the vault directory. |
| `edit <name>`            | Open the interactive TUI to manage secrets. |
| `passwd <name>`          | Change the vault's password (verifies the old one, re-encrypts under the new). |
| `upgrade <name>`         | Re-encrypt under the current Argon2id parameters (no-op if already current). |
| `run <name> -- <cmd>…`   | Decrypt in memory and run `<cmd>` with the secrets in its environment. |
| `unrun -- <cmd>…`        | Run `<cmd>` with your credential files **hidden** from it (Linux). `--hide <path>` adds more. |
| `set <name> KEY …`       | Add/update keys; each value entered at a no-echo prompt, then the clipboard is wiped. |
| `rename <old> <new>`     | Rename a vault. |
| `rm <name> KEY …`        | Remove one or more keys. |
| `show <name>`            | Print decrypted `KEY=VALUE` lines to stdout. |

By default you are prompted for the vault password with no echo. Add
`--password-stdin` to any command to read the password from stdin instead — for
automation, e.g. `echo "$PW" | envvault run work --password-stdin -- ./deploy`.
(`--password-stdin` isn't available on the interactive `edit`, `set`, and
`passwd` commands, which need the terminal to prompt you — `edit` for the UI,
`set` for each value, and `passwd` for the old and new passwords.)

### The interactive editor

In `envvault edit` / `envvault init`, values are **masked** by default. The
"add" prompt accepts either a bare key name (it then asks for the value) or a
full `KEY=VALUE` line typed in one go (surrounding quotes are stripped).

**Paste clears the clipboard.** When you paste a value into an input field, the
editor inserts it and then **wipes the system clipboard**, so the secret you
copied (e.g. from a password manager) doesn't linger there for the next app to
read. See the caveat about clipboard managers under *Security notes* below.

| Key | Action |
|-----|--------|
| `↑`/`↓`, `j`/`k` | move the selection |
| `a` | add an entry (key name, or `KEY=VALUE`) |
| `e` / `Enter` | edit the selected value |
| `d` | delete the selected entry (confirm) |
| `s` | show/hide the selected value |
| `w` | save (re-encrypt to disk) |
| `q` | quit (prompts to save if there are unsaved changes) |

---

## `run` vs `dir run`: keeping secrets off the environment

`envvault run` is the convenient fallback, but it is the **weaker** of the two
modes, and deliberately so — there is no way to make it stronger. It decrypts
the secrets and `exec`s your program with them in its **environment**. From that
moment until the program exits, any process running as you can read them from
`/proc/<pid>/environ`.

This is **inherent to env injection, not a bug we can fix.** You might hope
envvault could mark the program non-dumpable (`prctl(PR_SET_DUMPABLE, 0)`, which
*does* block `/proc/<pid>/environ` reads) — but a normal `execve` resets the
dumpable bit back to "dumpable" for any ordinary program, and envvault can't
stop the target's own exec from doing that. The secret is exposed for the
program's whole lifetime to exactly the same-uid attacker envvault exists to
resist. `run` prints a one-line reminder of this on each use (silence it with
`--quiet` or `ENVVAULT_QUIET=1`).

It's worth being clear where this sits relative to other tools, without
overstating it. **The runtime exposure is not specific to envvault** — it is
inherent to env injection, so every tool that hands a secret to a program
through its environment (`direnv`, `dotenvx`, the `run` commands of cloud secret
managers, `sops exec-env`, …) shares it. What still differs is two things:

- **At rest.** Even in `run` mode the secret stays encrypted whenever the
  program isn't running — there is no plaintext `.env` or key file sitting on
  disk the rest of the time. That makes `run` meaningfully safer than a plaintext
  dotenv file despite the identical *runtime* exposure.
- **Whether there's an off-environment path, and what it costs.** Some tools
  offer only env injection (`direnv`, `dotenvx`) with no alternative. Tools that
  can hand a secret to a *file* often write plaintext to disk by default (e.g.
  `sops exec-file`) — trading the environ exposure for an at-rest one — though
  some provide a no-disk option (e.g. `sops --fifo`, a named pipe). `dir run` is
  envvault's take: the plaintext exists only on a namespace-private tmpfs —
  encrypted at rest, hidden from other same-uid processes, re-encrypted in place
  on exit — so it avoids *both* leaks rather than swapping one for the other. It
  is not the only off-environment mechanism that exists, but it is built not to
  reintroduce a disk exposure in the process.

**So prefer `dir run` whenever the tool can read its secret from a file** — there
the plaintext lives only on a namespace-private tmpfs and never enters any
environment. Two patterns cover almost everything:

- **The tool reads a config file directly** (Claude Code's `~/.claude`, the AWS
  CLI's `~/.aws/credentials`, opencode's `auth.json`): vault that file or
  directory and use `dir run` — see the next section.
- **The tool takes a *file path* in an env var** (only a non-secret path is
  exposed, never the secret itself). Many tools support this convention:
  `GOOGLE_APPLICATION_CREDENTIALS`, `AWS_SHARED_CREDENTIALS_FILE`, `KUBECONFIG`,
  and assorted `*_TOKEN_FILE` / `*_PASSWORD_FILE` variables. Vault the file, and
  let the (harmless) path travel in the environment.

Reach for `run` only when a program accepts its secret **exclusively** as an
environment-variable value — and do so knowing the exposure above.

### Hardening env injection: `run --harden` (Linux)

For programs that *only* take a secret via the environment, `--harden` closes the
`/proc/<pid>/environ` exposure on Linux:

```sh
envvault run work --harden -- ./my-tool
```

It works by **not** putting the secrets in the program's initial environment.
Instead envvault preloads a tiny shim (`LD_PRELOAD`) that, before the program's
`main()` runs, marks the process **non-dumpable** (`prctl(PR_SET_DUMPABLE,0)`,
which blocks same-uid reads of *both* `/proc/<pid>/environ` and
`/proc/<pid>/mem`), signals envvault that it is safe, and only then receives the
secrets over a pipe and injects them with `setenv()` so the program reads them
normally via `getenv()`. Because the secrets are withheld until that signal,
there is no startup-race window.

**It fails closed.** If the shim doesn't load — a **statically-linked** binary, a
**setuid** program, or `LD_PRELOAD` otherwise ignored — envvault never receives
the signal, never sends the secrets, and aborts with an error. Nothing leaks; the
program simply doesn't run.

Limitations to know:

- **Linux only** (needs `prctl` + `LD_PRELOAD`); on other platforms `--harden`
  errors.
- **Dynamically-linked, non-setuid programs only** — static binaries can't be
  preloaded (they fail closed, by design).
- If the program **re-execs** itself or **spawns children**, those children are
  dumpable again and inherit the now-`setenv`'d secrets in their *initial*
  environment — so the protection covers the launched process, not arbitrary
  descendants it creates.
- It does not defend against root, or against the program leaking the secret
  itself.

Within those limits, `--harden` gives env-only tools the same same-uid runtime
protection that `dir run` gives file-based ones.

---

## Directory & file vaults: keep a tool's secrets encrypted at rest

Some tools insist on writing secrets to disk rather than reading them from the
environment — Claude Code's `~/.claude/`, the AWS CLI's `~/.aws/credentials`,
opencode's `~/.local/share/opencode/auth.json`, and so on. A **directory vault**
— or a **single-file vault**, when the secret is one file marooned in a big
directory — keeps such a path encrypted at rest and exposes its plaintext **only
in RAM**, at the original location, only while a program you launch is running —
then re-encrypts it on exit. `dir init` auto-detects whether `--path` is a
directory or a file.

```sh
# A whole config directory:
envvault dir init claude --path ~/.claude
envvault dir run  claude -- claude

# Or a single file that lives in a large directory (opencode keeps its keys next
# to a multi-hundred-MB database — vault only the file, leave the rest on disk):
envvault dir init opencode --path ~/.local/share/opencode/auth.json
envvault dir run  opencode -- opencode

# Manage vaults
envvault dir list
envvault dir status opencode             # show the stored target path
envvault dir export opencode --to ./bak  # decrypt to a directory (writes plaintext!)
envvault dir rm opencode
```

**How it works (Linux).** `dir run` creates a private **user + mount namespace**,
mounts a fresh **tmpfs** over the target directory, decrypts the vault into it,
runs your program (which sees a normal, populated `~/.claude`), and re-encrypts
from the tmpfs when the program exits. The tmpfs is **visible only to that
program and its children** — it never appears in the host mount namespace, so
every other process (even same-uid ones) sees only the empty real directory, and
it vanishes when the program exits. For a **single-file vault** it mounts a
tmpfs over the file's **parent directory**, **binds every real sibling back in**
(so a live database or cache next to the secret keeps reading and writing real
disk), and drops the decrypted file into that tmpfs as an ordinary file — leaving
the rest of the directory real and on disk. Virtualizing at directory
granularity means a program can rewrite the secret *in place* **or** replace it
atomically (the write-temp-then-`rename` pattern many tools and editors use)
entirely in RAM, and the change is still captured on exit. No root is needed, as
long as unprivileged user namespaces are enabled (the default on most desktop
distros). If they're disabled, `dir run` fails with a clear message rather than
writing plaintext to real disk.

| Command | What it does |
|---------|--------------|
| `dir init <name> --path <path>` | Encrypt a directory **or a single file** into a vault, then empty it. |
| `dir run <name> -- <cmd>…`     | Decrypt into RAM at the original path, run `<cmd>`, re-encrypt on changes and on exit. |
| `dir list`                     | List all directory vaults. |
| `dir status <name>`            | Print the vault's stored target path. |
| `dir rename <old> <new>`       | Rename a directory/file vault. |
| `dir upgrade <name>`           | Re-encrypt under the current Argon2id parameters (no-op if already current). |
| `dir export <name> --to <dir>` | Decrypt the contents into `<dir>` (writes plaintext to disk!). |
| `dir rm <name>`                | Delete the vault file. |

---

## `unrun`: run untested code blind to your credentials

The vaults above protect the secrets envvault *manages*. But most credentials on
a dev machine sit in plaintext files that no tool put in a vault — `~/.ssh`,
`~/.aws/credentials`, `~/.config/gh`, `~/.npmrc`, and so on. When you let an AI
coding agent (or any tool) run a command, that command and everything it spawns —
a `postinstall` script, a fetched binary, a build step — runs as *you* and can
read all of them.

`unrun` runs a command in a private mount namespace where a curated set of
credential paths is **masked** (each replaced by an empty overlay), so the
command can't read them. It is the inverse of `dir run`: instead of *revealing*
one decrypted secret, it *hides* many. Everything else — your home, caches,
toolchains, environment, agent sockets — is left exactly as on the host, so the
command otherwise runs normally.

```sh
envvault unrun -- npm install            # ~/.ssh, ~/.aws, … read as empty
envvault unrun --hide ~/.config/foo -- ./script   # add your own path
```

It's **safe by construction**: a mount namespace is a copy-on-create, discard-on-
exit view, so the real files are never moved or modified and there is nothing to
restore — even if the command crashes. The masking is inherited by every child
the command spawns.

**Hidden by default** (`--hide <path>` adds more): `~/.ssh`, `~/.aws`,
`~/.config/gh`, `~/.config/gcloud`, `~/.azure`, `~/.kube`, `~/.gnupg`,
`~/.config/op`, `~/.terraform.d`, `~/.config/envvault`, `~/.npmrc`, `~/.pypirc`,
`~/.netrc`, `~/.git-credentials`, `~/.docker/config.json`,
`~/.cargo/credentials.toml`, `~/.databrickscfg`.

**Limitations** — worth knowing, since this is a transparent denylist, not a
deny-everything jail:

- **It only hides what's on the list.** Anything not listed stays visible; the
  default is curated but not exhaustive, so add your own with `--hide`.
- **The environment and agent sockets are left native.** Secrets in environment
  variables aren't masked, and `$SSH_AUTH_SOCK` / gpg-agent stay reachable — so
  code can still *use* your SSH/GPG key via the agent (e.g. to sign or push), it
  just can't *read the key bytes*. This is deliberate, so normal workflows keep
  working.
- **Writes to a masked path are ephemeral** — they land in the throwaway overlay
  and vanish on exit; the real file is untouched.
- **Linux only** (needs unprivileged user + mount namespaces); errors clearly
  elsewhere, or if those namespaces are disabled.

## Security notes & limitations

- **Your password is the whole game.** Argon2id makes brute force costly, but a
  weak passphrase is still weak. Choose a strong one. When you create (`init`) or
  change (`passwd`) a vault password, envvault prints a strength estimate (via
  zxcvbn) — a 0–4 score, an estimated offline crack time, and concrete
  suggestions. It's advisory: a weak password is reported, never rejected.
- `show` and the editor's "reveal" deliberately display secrets on screen — use
  them intentionally.
- **`run` (env injection) cannot be secured against a same-uid attacker.** Once
  a secret is handed to a child via its environment it is readable through
  `/proc/<pid>/environ` for that program's whole lifetime, and there is no fix:
  a normal `execve` resets the child's dumpable bit, so it can't be hidden the
  way `envvault` hides itself. `envvault` only controls how the secret gets
  there, not what the program does with it afterward. Prefer `dir run` for
  file-based secrets — see
  [`run` vs `dir run`](#run-vs-dir-run-keeping-secrets-off-the-environment).
- `envvault` protects secrets *at rest* and limits their *exposure at runtime*.
  Marking the process non-dumpable stops a *same-user* attacker from core-dumping
  or debugging **the `envvault` process** to read its memory, but it does not make
  the tool root-proof: root can read any process's memory, any file, and any TTY
  regardless. A same-user attacker also retains other avenues it was never meant
  to block — replacing the `envvault` binary, logging your keystrokes, or reading
  a launched program's environment (`/proc/<pid>/environ`) once `run` hands it the
  secrets. Defending against an attacker who already executes code in your
  session is fundamentally beyond what any userspace tool can guarantee.
- Memory zeroization is best-effort. Rust may move values before they are
  wiped, and while a value is *revealed* in the editor, transient per-frame
  copies inside the terminal library may be freed before being overwritten. The
  guarantee is "no long-lived plaintext copies after exit," not "every byte
  scrubbed at every instant."
- **Directory vaults** (`dir run`) are Linux-only — they rely on unprivileged
  user + mount namespaces. `dir init`/`dir export`/`dir list` work everywhere.
- A **single-file vault** mounts a tmpfs over the file's *parent directory* and
  binds the real siblings back, so only the vaulted file lives in RAM while
  everything else in the directory stays real on disk. Because the file sits in a
  tmpfs directory (rather than being bind-mounted in place), a program can rewrite
  it *in place* **or** via atomic-rename (an OAuth token-refresh, an editor's
  write-temp-then-rename) and the change is captured. The one limitation: sibling
  files *created* during a session land in the tmpfs and do **not** persist after
  exit — siblings that already existed when the vault was opened do persist. A
  flagged limitation, not a silent one.
- `dir init` **deletes** the original files but does not *securely shred* them:
  the plaintext that was already on disk before you vaulted it may remain
  recoverable from free space until overwritten (especially on SSDs/CoW
  filesystems). Secrets written *later* by a tool inside `dir run` only ever
  live in the tmpfs, never on the real disk.
- While the program runs, envvault re-encrypts to disk automatically once the
  directory has been quiet for a debounce window (default 2s; tune with
  `--autosave-debounce <secs>`, turn off with `--no-autosave`), plus a final
  save on exit. So a `SIGKILL` or power loss costs at most the changes made
  since the last quiet moment — not the whole session. Ordinary exits, Ctrl-C,
  and `SIGTERM` always trigger a final re-encryption.
- The namespace-private tmpfs hides the plaintext from *passive* same-uid
  access, but not from a same-uid attacker who actively targets the running
  child (e.g. `/proc/<child_pid>/root/`, `setns`). After `exec` the child is
  dumpable again, and `PR_SET_DUMPABLE=0` only protects `envvault` itself, not
  the tool it launches.
- Clearing the clipboard on paste is best-effort. A **clipboard manager**
  (KDE Klipper, GPaste, GNOME's clipboard history, etc.) may have already
  captured the secret when you *copied* it, and some are configured to restore
  the previous entry when the clipboard is emptied — which can undo the wipe.
  envvault clears the live clipboard; it cannot reach into a manager's history.
  If no clipboard is reachable (e.g. over SSH without a display) the paste still
  works but can't be wiped, and the editor says so.

## License

MIT
