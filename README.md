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
  exported into your interactive shell, so nothing else inherits it.
- **Nothing transient leaks**: no plaintext temp file, no shell-history line, no
  clipboard copy. You type a password, the program runs, the secret is gone.

It does **not** try to defend against a process that is *already* running as you
with a debugger attached, or malware with root — no userspace tool can. The goal
is to eliminate the casual, accidental leaks above, which are how secrets
actually escape in practice.

## How it works

- **Key derivation** — Argon2id (a memory-hard KDF) turns your password plus a
  per-vault random 16-byte salt into a 32-byte key. Argon2id makes brute-forcing
  a stolen vault file expensive.
- **Encryption** — ChaCha20-Poly1305, an *authenticated* cipher, with a fresh
  random 12-byte nonce on every save. Authentication means a wrong password or a
  tampered file is **detected and rejected**, not silently mis-decrypted.
- **On-disk format** — a short text header plus a base64 body
  (`salt || nonce || ciphertext`). The file is plain UTF-8, so it survives
  copy-paste and is safe to commit to git or store in dotfiles.
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

# Run a program with the vault's variables in its environment
envvault run work -- python train.py
envvault run work -- bash -lc 'echo $OPENAI_API_KEY'

# Add or update secrets — prompts (no echo) for each value, so the secret
# never appears on the command line, in shell history, or in /proc/<pid>/cmdline
envvault set work OPENAI_API_KEY DATABASE_URL

# Remove keys
envvault rm work DATABASE_URL

# Print decrypted contents to stdout (this exposes secrets!)
envvault show work
```

### Commands

| Command | What it does |
|---------|--------------|
| `init <name>`            | Create a new vault (then open the editor). |
| `list`                   | List all vaults in the vault directory. |
| `edit <name>`            | Open the interactive TUI to manage secrets. |
| `passwd <name>`          | Change the vault's password (verifies the old one, re-encrypts under the new). |
| `run <name> -- <cmd>…`   | Decrypt in memory and run `<cmd>` with the secrets in its environment. |
| `set <name> KEY …`       | Add/update keys; the value for each is entered at a no-echo prompt. |
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

## Security notes & limitations

- **Your password is the whole game.** Argon2id makes brute force costly, but a
  weak passphrase is still weak. Choose a strong one.
- `show` and the editor's "reveal" deliberately display secrets on screen — use
  them intentionally.
- Once a secret is handed to a child process it lives in that child's
  environment like any other variable; `envvault` only controls how it gets
  there, not what the program does with it afterward.
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
- Clearing the clipboard on paste is best-effort. A **clipboard manager**
  (KDE Klipper, GPaste, GNOME's clipboard history, etc.) may have already
  captured the secret when you *copied* it, and some are configured to restore
  the previous entry when the clipboard is emptied — which can undo the wipe.
  envvault clears the live clipboard; it cannot reach into a manager's history.
  If no clipboard is reachable (e.g. over SSH without a display) the paste still
  works but can't be wiped, and the editor says so.

## License

MIT
