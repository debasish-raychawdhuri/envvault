#!/usr/bin/env bash
# Directory & single-file vaults: init empties the target, `dir run` exposes the
# decrypted contents in RAM at the original path, edits persist via re-encrypt on
# exit, and export/status/list/upgrade/rm behave. Requires unprivileged user
# namespaces (for `dir run`).
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
feature "dir/file vaults"
new_work

# ---- single-file vault ----
app="$WORK/app"; mkdir -p "$app"
file="$app/auth.json"
printf '{"key":"secret-file-123"}\n' > "$file"

out="$(echo "$PW" | "$BIN" dir init fv --path "$file" --yes --password-stdin 2>&1)"
assert_contains "file vault: init reports a file vault" "$out" "Created file vault"
assert_eq "file vault: original file emptied" "$(stat -c '%s' "$file")" "0"
assert_contains "dir list shows the file vault" "$("$BIN" dir list 2>&1)" "fv"
assert_contains "dir status shows path+kind" "$(echo "$PW" | "$BIN" dir status fv --password-stdin 2>&1)" "file $file"

out="$(echo "$PW" | "$BIN" dir run fv --password-stdin -- cat "$file" 2>/dev/null)"
assert_contains "file vault: dir run exposes decrypted content" "$out" "secret-file-123"
assert_eq "file vault: file is empty again on host after exit" "$(stat -c '%s' "$file")" "0"

# in-place edit during a session persists (atomic-rename / rewrite captured)
echo "$PW" | "$BIN" dir run fv --password-stdin -- bash -c "printf 'rotated-789' > '$file'" >/dev/null 2>&1
out="$(echo "$PW" | "$BIN" dir run fv --password-stdin -- cat "$file" 2>/dev/null)"
assert_contains "file vault: edits persist across sessions" "$out" "rotated-789"

# export writes plaintext
exp="$WORK/exp"
echo "$PW" | "$BIN" dir export fv --to "$exp" --password-stdin >/dev/null 2>&1
assert_contains "file vault: export writes decrypted content" "$(cat "$exp/auth.json" 2>/dev/null)" "rotated-789"

assert_contains "file vault: upgrade already current" "$(echo "$PW" | "$BIN" dir upgrade fv --password-stdin 2>&1)" "already"
expect_ok "file vault: rm" bash -c "'$BIN' dir rm fv"

# ---- directory vault ----
conf="$WORK/conf"; mkdir -p "$conf/sub"
printf 'AAA\n' > "$conf/a.txt"
printf 'BBB\n' > "$conf/sub/b.txt"

out="$(echo "$PW" | "$BIN" dir init dv --path "$conf" --yes --password-stdin 2>&1)"
assert_contains "dir vault: init reports a directory vault" "$out" "Created directory vault"
assert_eq "dir vault: target emptied on host" "$(ls -A "$conf" | wc -l)" "0"

out="$(echo "$PW" | "$BIN" dir run dv --password-stdin -- bash -c "cat '$conf/a.txt'; cat '$conf/sub/b.txt'" 2>/dev/null)"
assert_contains "dir vault: nested files exposed (a)" "$out" "AAA"
assert_contains "dir vault: nested files exposed (b)" "$out" "BBB"
assert_eq "dir vault: emptied again on host after exit" "$(ls -A "$conf" | wc -l)" "0"

# a file created during a session persists for a directory vault
echo "$PW" | "$BIN" dir run dv --password-stdin -- bash -c "printf 'CCC' > '$conf/c.txt'" >/dev/null 2>&1
out="$(echo "$PW" | "$BIN" dir run dv --password-stdin -- cat "$conf/c.txt" 2>/dev/null)"
assert_contains "dir vault: new file created in session persists" "$out" "CCC"

expect_ok "dir vault: rm" bash -c "'$BIN' dir rm dv"
