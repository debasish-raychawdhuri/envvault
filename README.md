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

# Run a program with the vault's variables in its environment
envvault run work -- python train.py
envvault run work -- bash -lc 'echo $OPENAI_API_KEY'

# Set / update secrets non-interactively (scriptable)
envvault set work OPENAI_API_KEY=sk-... DATABASE_URL=postgres://...

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
| `run <name> -- <cmd>…`   | Decrypt in memory and run `<cmd>` with the secrets in its environment. |
| `set <name> KEY=VAL …`   | Add or update one or more entries non-interactively. |
| `rm <name> KEY …`        | Remove one or more keys. |
| `show <name>`            | Print decrypted `KEY=VALUE` lines to stdout. |

By default you are prompted for the vault password with no echo. Add
`--password-stdin` to any command to read the password from stdin instead — for
automation, e.g. `echo "$PW" | envvault run work --password-stdin -- ./deploy`.
(`--password-stdin` can't be combined with the interactive `edit` UI, which
needs control of the terminal.)

### The interactive editor

In `envvault edit` / `envvault init`, values are **masked** by default. The
"add" prompt accepts either a bare key name (it then asks for the value) or a
full `KEY=VALUE` line typed in one go (surrounding quotes are stripped).

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

## License

MIT
