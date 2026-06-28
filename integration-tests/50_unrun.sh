#!/usr/bin/env bash
# `unrun`: runs a command with the built-in credential paths masked (empty), the
# rest of the home untouched, masking inherited by grandchildren, and the host
# filesystem unchanged afterward. Hermetic: operates under a fake $HOME.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
feature "unrun"
new_work

mkdir -p "$HOME/.ssh" "$HOME/.aws" "$HOME/.config/gh"
printf 'PRIVATE-KEY\n'  > "$HOME/.ssh/id_rsa"
printf 'AWSKEY\n'       > "$HOME/.aws/credentials"
printf 'gh-token\n'     > "$HOME/.config/gh/hosts.yml"
printf 'notes-content\n'> "$HOME/.notes"

# sanity: outside unrun the creds are readable
assert_contains "creds readable outside unrun" "$(cat "$HOME/.aws/credentials")" "AWSKEY"

assert_eq "unrun: ~/.aws masked (empty)"        "$("$BIN" unrun -- bash -c 'ls -A ~/.aws | wc -l' 2>/dev/null)" "0"
assert_eq "unrun: ~/.ssh masked (empty)"        "$("$BIN" unrun -- bash -c 'ls -A ~/.ssh | wc -l' 2>/dev/null)" "0"
assert_eq "unrun: ~/.config/gh masked (empty)"  "$("$BIN" unrun -- bash -c 'ls -A ~/.config/gh | wc -l' 2>/dev/null)" "0"

# non-credential files are left alone
assert_contains "unrun: non-cred file still visible" "$("$BIN" unrun -- cat "$HOME/.notes" 2>/dev/null)" "notes-content"

# --hide adds a path
assert_eq "unrun --hide masks an extra path" \
    "$("$BIN" unrun --hide "$HOME/.notes" -- bash -c "cat '$HOME/.notes' 2>/dev/null | wc -c" 2>/dev/null)" "0"

# masking is inherited by grandchildren
assert_eq "unrun: masking inherited by grandchild" \
    "$("$BIN" unrun -- bash -c 'bash -c "ls -A ~/.aws | wc -l"' 2>/dev/null)" "0"

# host is untouched after exit
assert_contains "unrun: host creds intact afterward" "$(cat "$HOME/.aws/credentials")" "AWSKEY"
