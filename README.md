# envvault

Store environment variables (API keys, tokens, secrets) in a single
**password-encrypted file**, and run programs with those variables set —
without ever leaving secrets in your shell, your shell history, or on disk in
plaintext.

## Why

Instead of `export OPENAI_API_KEY=sk-...` polluting your shell (and getting
captured by every other process you run, plus your history), keep the keys in
an encrypted vault and inject them only into the one program that needs them:

```sh
envvault run work -- python train.py
```

The secrets are decrypted **in memory only**, handed to the child process's
environment, and never touch disk.

## Vaults are named

You refer to vaults by name (e.g. `work`, `personal`), not by file path. Each
is encrypted separately with its own password and stored as one file in a
fixed per-user directory:

- `$ENVVAULT_DIR` if set, otherwise `<config-dir>/envvault`
  (`~/.config/envvault` on Linux, `~/Library/Application Support/envvault` on
  macOS).
- The directory is created `0700` and each `<name>.vault` file is `0600`.

## How it works

- **Key derivation**: Argon2id turns your password + a per-file random salt
  into a 32-byte key.
- **Encryption**: ChaCha20-Poly1305 (authenticated) with a fresh random nonce
  on every save — so tampering or a wrong password is detected, not silently
  mis-decrypted.
- **On-disk format**: a text header + base64 body, so the file is safe to
  commit to git / store in dotfiles and survives copy-paste.
- Files are written `0600` (owner read/write only).

## Usage

```sh
# Create a new named vault and edit it in the interactive UI
envvault init work

# List all vaults
envvault list

# Edit a vault's secrets interactively (view / add / modify / delete)
envvault edit work

# Run a program with the vault's variables in its environment
envvault run work -- bash -lc 'echo $OPENAI_API_KEY'

# Scriptable, non-interactive editing
envvault set work OPENAI_API_KEY=sk-... DATABASE_URL=postgres://...
envvault rm  work DATABASE_URL

# Print decrypted contents (this exposes secrets!)
envvault show work
```

Add `--password-stdin` to any command to read the password from stdin instead
of prompting (for automation). Note: `--password-stdin` is not compatible with
the interactive `edit` UI, which needs the terminal.

### Interactive editor keys

| Key        | Action                          |
|------------|---------------------------------|
| `↑`/`↓`, `j`/`k` | move selection            |
| `a`        | add a new entry                 |
| `e`/`Enter`| edit the selected value         |
| `d`        | delete the selected entry       |
| `s`        | show/hide the selected value    |
| `w`        | save (re-encrypt) to disk       |
| `q`        | quit (prompts if unsaved)       |

## Security notes

- The strength of the encryption rests on your password. Argon2id makes brute
  force expensive, but choose a strong passphrase.
- `show` and the editor's "reveal" deliberately display secrets on screen — use
  them intentionally.
- Secrets are zeroized from this process's memory on drop; once handed to a
  child process they live in that child's environment as usual.

## Build

```sh
cargo build --release
cargo test
```
