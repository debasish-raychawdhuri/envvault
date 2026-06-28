#!/usr/bin/env bash
# `baseline pin` / `unpin`: surgical edits to the tracked set. Re-pinning re-blesses
# only that path (pinning one does NOT re-bless the rest); a path covered by a
# tracked directory is skipped; unpinning a directory drops its children. Root
# tests SKIP without sudo; the non-root refusal always runs.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
feature "baseline pin/unpin"
new_work

U="$(id -un)"
t="$WORK/trust"; mkdir -p "$t/store"
A="$t/a.conf"; B="$t/b.conf"; C="$t/c.conf"; DIR="$t/store"; CHILD="$DIR/cert.db"
printf 'A-v1\n' > "$A"; printf 'B-v1\n' > "$B"; printf 'C-v1\n' > "$C"; printf 'x\n' > "$CHILD"

shows() { as_root "$BIN" baseline show --user "$U" 2>/dev/null | grep -qF "$1"; }

# --- always: non-root guard ---
out="$("$BIN" baseline pin "$A" 2>&1)"; rc=$?
if [ $rc -ne 0 ] && [[ "$out" == *"must run as root"* ]]; then pass "pin refused without root"; else fail "pin refused without root" "rc=$rc $out"; fi
out="$("$BIN" baseline unpin "$A" 2>&1)"; rc=$?
if [ $rc -ne 0 ] && [[ "$out" == *"must run as root"* ]]; then pass "unpin refused without root"; else fail "unpin refused without root" "rc=$rc $out"; fi

# --- root-only ---
# NB: these files are executed (not sourced), so use `exit`, not `return`.
require_root "pin/unpin round-trip" || exit 0
as_root rm -rf /etc/envvault

# start tracking only A
as_root "$BIN" baseline set --user "$U" --add "$A" >/dev/null
shows "$A" && pass "set tracks A" || fail "set tracks A"
shows "$B" && fail "B not tracked yet" "unexpectedly present" || pass "B not tracked yet"

# pin B
as_root "$BIN" baseline pin --user "$U" "$B" >/dev/null
shows "$B" && pass "pin adds B" || fail "pin adds B"

# pin C while A is tampered must NOT re-bless A
printf 'A-v2-tampered\n' > "$A"
as_root "$BIN" baseline pin --user "$U" "$C" >/dev/null
out="$("$BIN" baseline check 2>&1)"
assert_contains "pin C leaves tampered A flagged (no silent re-bless)" "$out" "$A"
assert_not_contains "C verifies clean" "$out" "$C"
assert_not_contains "B verifies clean" "$out" "$B"

# re-pin A re-blesses only A
as_root "$BIN" baseline pin --user "$U" "$A" >/dev/null
assert_not_contains "re-pin A clears its mismatch" "$("$BIN" baseline check 2>&1)" "$A"

# unpin B
as_root "$BIN" baseline unpin --user "$U" "$B" >/dev/null
shows "$B" && fail "unpin removes B" "still present" || pass "unpin removes B"

# covered-by-dir: pin the dir, then pinning a child is skipped
as_root "$BIN" baseline pin --user "$U" "$DIR" >/dev/null
out="$(as_root "$BIN" baseline pin --user "$U" "$CHILD" 2>&1)"
assert_contains "child under tracked dir is skipped" "$out" "already covered by tracked directory"

# unpinning the dir drops its child
as_root "$BIN" baseline unpin --user "$U" "$DIR" >/dev/null
shows "$CHILD" && fail "unpin dir drops child" "child still tracked" || pass "unpin dir drops child"

# A pin's effect is enforced by BOTH run modes against the shared baseline.
# (A is currently pinned and clean; C is still tracked too.)
echo "$PW" | "$BIN" init wv --password-stdin --no-edit >/dev/null
ddir="$WORK/dv"; mkdir -p "$ddir"; printf 'x\n' > "$ddir/f"
echo "$PW" | "$BIN" dir init dv --path "$ddir" --yes --password-stdin >/dev/null

e="$(echo "$PW" | "$BIN" run wv --password-stdin --verify -- echo OK 2>&1)"
d="$(echo "$PW" | "$BIN" dir run dv --password-stdin --verify -- echo OK 2>&1)"
[[ "$e" == *OK* ]] && pass "env run --verify honors the pinned baseline (clean)" || fail "env run --verify honors the pinned baseline" "${e:0:200}"
[[ "$d" == *OK* ]] && pass "dir run --verify honors the pinned baseline (clean)" || fail "dir run --verify honors the pinned baseline" "${d:0:200}"

printf 'A-tampered-again\n' > "$A"   # tamper the pinned file
e="$(echo "$PW" | "$BIN" run wv --password-stdin --verify -- echo RAN 2>&1)"; re=$?
d="$(echo "$PW" | "$BIN" dir run dv --password-stdin --verify -- echo RAN 2>&1)"; rd=$?
if [ $re -ne 0 ] && [[ "$e" != *RAN* ]] && [[ "$e" == *"$A"* ]]; then pass "env run --verify aborts on tampered pinned file"; else fail "env run --verify aborts on tampered pinned file" "rc=$re ${e:0:160}"; fi
if [ $rd -ne 0 ] && [[ "$d" != *RAN* ]] && [[ "$d" == *"$A"* ]]; then pass "dir run --verify aborts on tampered pinned file"; else fail "dir run --verify aborts on tampered pinned file" "rc=$rd ${d:0:160}"; fi

as_root rm -rf /etc/envvault
