#!/usr/bin/env bash
# Vault lifecycle: init / list / set / show / rm / rename / passwd / upgrade,
# plus the empty-password and wrong-password guards. `set` and `passwd` are
# driven through a pty with expect (they require a real terminal by design).
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
feature "vault basics"
new_work

# init + list
out="$(echo "$PW" | "$BIN" init work --password-stdin --no-edit 2>&1)"
assert_contains "init creates a vault" "$out" "Created vault 'work'"
assert_contains "list shows the new vault" "$("$BIN" list 2>&1)" "work"

# duplicate init refuses
out="$(echo "$PW" | "$BIN" init work --password-stdin --no-edit 2>&1)"; rc=$?
if [ $rc -ne 0 ] && [[ "$out" == *"already exists"* ]]; then pass "duplicate init refused"; else fail "duplicate init refused" "$out"; fi

# empty password via stdin refused
out="$(printf '\n' | "$BIN" init empty --password-stdin --no-edit 2>&1)"; rc=$?
if [ $rc -ne 0 ] && [[ "$out" == *"empty password"* ]]; then pass "empty password refused"; else fail "empty password refused" "rc=$rc $out"; fi

# set a secret (interactive value entry, via expect)
if set_secret work OPENAI_API_KEY sk-test-AAA; then pass "set OPENAI_API_KEY (expect)"; else fail "set OPENAI_API_KEY (expect)" "expect rc=$?"; fi
out="$(echo "$PW" | "$BIN" show work --password-stdin 2>&1)"
assert_contains "show reflects the set key" "$out" "OPENAI_API_KEY=sk-test-AAA"

# set a second key, both present
set_secret work DATABASE_URL postgres-local >/dev/null 2>&1
out="$(echo "$PW" | "$BIN" show work --password-stdin 2>&1)"
assert_contains "second key present" "$out" "DATABASE_URL=postgres-local"
assert_contains "first key still present" "$out" "OPENAI_API_KEY=sk-test-AAA"

# rm removes one key
expect_ok "rm removes a key" bash -c "echo '$PW' | '$BIN' rm work DATABASE_URL --password-stdin"
out="$(echo "$PW" | "$BIN" show work --password-stdin 2>&1)"
assert_not_contains "removed key is gone" "$out" "DATABASE_URL"

# wrong password fails to open
out="$(echo "wrong-pw" | "$BIN" show work --password-stdin 2>&1)"; rc=$?
if [ $rc -ne 0 ]; then pass "wrong password rejected"; else fail "wrong password rejected" "succeeded: $out"; fi

# rename
expect_ok "rename vault" "$BIN" rename work prod
out="$("$BIN" list 2>&1)"
assert_contains "renamed vault present" "$out" "prod"
assert_not_contains "old name gone" "$out" "$(printf 'work\n')"

# passwd: change, old fails, new works (via expect)
NEWPW="changed-pw-123"
if change_pw prod "$PW" "$NEWPW"; then pass "passwd changes password (expect)"; else fail "passwd changes password (expect)" "expect rc=$?"; fi
out="$(echo "$PW" | "$BIN" show prod --password-stdin 2>&1)"; rc=$?
if [ $rc -ne 0 ]; then pass "old password no longer opens"; else fail "old password no longer opens" "still opened"; fi
out="$(echo "$NEWPW" | "$BIN" show prod --password-stdin 2>&1)"
assert_contains "new password opens, content intact" "$out" "OPENAI_API_KEY=sk-test-AAA"

# upgrade on an already-current (v2) vault is a no-op
out="$(echo "$NEWPW" | "$BIN" upgrade prod --password-stdin 2>&1)"
assert_contains "upgrade reports already current" "$out" "already"
