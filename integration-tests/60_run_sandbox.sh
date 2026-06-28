#!/usr/bin/env bash
# `run --sandbox`/`--allow`: the trusted launcher masks credential paths for the
# whole session before any untrusted code runs. The boundary is the namespace,
# not the binary — a fake `unrun` on $PATH cannot bring a masked path back.
# Hermetic under a fake $HOME.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
feature "run --sandbox/--allow"
new_work

mkdir -p "$HOME/.ssh" "$HOME/.aws"
printf 'KEYMAT\n' > "$HOME/.ssh/id_rsa"
printf 'AWSKEY\n' > "$HOME/.aws/credentials"
echo "$PW" | "$BIN" init work --password-stdin --no-edit >/dev/null
set_secret work TOKEN tok-sandbox-42 >/dev/null 2>&1

run_work() { echo "$PW" | "$BIN" run work --password-stdin --quiet "$@"; }

# --sandbox hides everything
assert_eq "sandbox: ~/.aws hidden" "$(run_work --sandbox -- bash -c 'ls -A ~/.aws | wc -l' 2>/dev/null)" "0"
assert_eq "sandbox: ~/.ssh hidden" "$(run_work --sandbox -- bash -c 'ls -A ~/.ssh | wc -l' 2>/dev/null)" "0"

# --allow keeps one visible, the rest hidden
out="$(run_work --allow "$HOME/.ssh" -- bash -c 'echo ssh=$(ls -A ~/.ssh | wc -l); echo aws=$(ls -A ~/.aws | wc -l)' 2>/dev/null)"
assert_contains "allow: ~/.ssh visible" "$out" "ssh=1"
assert_contains "allow: ~/.aws still hidden" "$out" "aws=0"

# secret still injected under the sandbox (compose: secret + mask)
assert_eq "sandbox: vault secret still injected" \
    "$(run_work --sandbox -- bash -c 'printf "%s" "$TOKEN"' 2>/dev/null)" "tok-sandbox-42"

# ENVVAULT_ALLOW exported for nested unrun
assert_contains "sandbox: ENVVAULT_ALLOW exported" \
    "$(run_work --allow "$HOME/.ssh" -- bash -c 'printf "%s" "$ENVVAULT_ALLOW"' 2>/dev/null)" "$HOME/.ssh"

# THE KEY PROPERTY: a fake `unrun` on $PATH cannot reveal a masked path
mkdir -p "$WORK/fakebin"
cat > "$WORK/fakebin/unrun" <<'EOF'
#!/bin/sh
exec "$@"
EOF
chmod +x "$WORK/fakebin/unrun"
got="$(run_work --sandbox -- bash -c "PATH='$WORK/fakebin:\$PATH' unrun cat ~/.aws/credentials 2>/dev/null | wc -c" 2>/dev/null)"
assert_eq "sandbox: fake unrun on PATH cannot unmask ~/.aws" "$got" "0"

# nested real unrun inherits the allow-list (keeps ~/.ssh, ~/.aws stays gone)
out="$(run_work --allow "$HOME/.ssh" -- "$BIN" unrun -- bash -c 'echo ssh=$(ls -A ~/.ssh | wc -l); echo aws=$(ls -A ~/.aws | wc -l)' 2>/dev/null)"
assert_contains "nested unrun keeps allowed ~/.ssh visible" "$out" "ssh=1"
assert_contains "nested unrun cannot reveal masked ~/.aws" "$out" "aws=0"

# host untouched
assert_contains "host creds intact after sandboxed session" "$(cat "$HOME/.aws/credentials")" "AWSKEY"
