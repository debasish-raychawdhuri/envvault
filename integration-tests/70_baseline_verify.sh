#!/usr/bin/env bash
# Config-integrity baseline + `--verify` in BOTH run modes (env `run --verify`
# and `dir run --verify`), sharing one root-owned baseline. The root-owned
# write/perms, freeze, TOCTOU, dir-completeness, absent-neutralize and compose
# checks need sudo and SKIP cleanly without it; the non-root guards (root-
# required, fail-closed without a baseline, in both modes) always run.
#
# Tracks only temp paths under $WORK. NOTE: `baseline set` additionally hashes
# the invoking user's real trust files (read-only) because the default set is
# resolved from the passwd home; assertions key on the temp paths only.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
feature "baseline + verify (env + dir)"
new_work

U="$(id -un)"
echo "$PW" | "$BIN" init work --password-stdin --no-edit >/dev/null
# a directory vault, so we can exercise `dir run --verify` against the same baseline
dsrc="$WORK/dvsrc"; mkdir -p "$dsrc"; printf 'seed\n' > "$dsrc/f"
echo "$PW" | "$BIN" dir init dv --path "$dsrc" --yes --password-stdin >/dev/null
trust="$WORK/trust"; mkdir -p "$trust/store"
tfile="$trust/app.conf"
tdir="$trust/store"
tabsent="$trust/maybe.conf"
printf 'ca = local\nproxy = none\n' > "$tfile"
printf 'cert-bytes\n' > "$tdir/cert.db"
# tabsent intentionally does not exist at baseline time

# --- always: non-root guards ---
out="$("$BIN" baseline set 2>&1)"; rc=$?
if [ $rc -ne 0 ] && [[ "$out" == *"must run as root"* ]]; then pass "baseline set refused without root"; else fail "baseline set refused without root" "rc=$rc $out"; fi

# Ensure a clean slate so the no-baseline check is valid (only if we can).
if have_sudo; then as_root rm -rf /etc/envvault; fi
if [ ! -e "/etc/envvault/$U.baseline" ]; then
    out="$(echo "$PW" | "$BIN" run work --password-stdin --verify -- echo SHOULD_NOT_RUN 2>&1)"; rc=$?
    if [ $rc -ne 0 ] && [[ "$out" != *SHOULD_NOT_RUN* ]] && [[ "$out" == *"no integrity baseline"* ]]; then
        pass "run --verify fails closed without a baseline"
    else
        fail "run --verify fails closed without a baseline" "rc=$rc out=${out:0:200}"
    fi
    out="$(echo "$PW" | "$BIN" dir run dv --password-stdin --verify -- echo SHOULD_NOT_RUN 2>&1)"; rc=$?
    if [ $rc -ne 0 ] && [[ "$out" != *SHOULD_NOT_RUN* ]] && [[ "$out" == *"no integrity baseline"* ]]; then
        pass "dir run --verify fails closed without a baseline"
    else
        fail "dir run --verify fails closed without a baseline" "rc=$rc out=${out:0:200}"
    fi
else
    skip "run --verify fails closed without a baseline" "a baseline already exists for $U"
    skip "dir run --verify fails closed without a baseline" "a baseline already exists for $U"
fi

# --- root-only from here ---
# NB: these files are executed (not sourced), so use `exit`, not `return`.
require_root "baseline write/verify/freeze" || exit 0

as_root "$BIN" baseline set --user "$U" --add "$tfile" --add "$tdir" --add "$tabsent" >/dev/null
assert_eq "/etc/envvault perms root:root:755" "$(stat -c '%U:%G:%a' /etc/envvault 2>/dev/null)" "root:root:755"
assert_eq "baseline file perms root:root:644" "$(stat -c '%U:%G:%a' "/etc/envvault/$U.baseline" 2>/dev/null)" "root:root:644"
if touch "/etc/envvault/should-fail" 2>/dev/null; then fail "normal user cannot write /etc/envvault" "touch succeeded"; rm -f /etc/envvault/should-fail 2>/dev/null; else pass "normal user cannot write /etc/envvault"; fi

# clean tree: temp paths verify
out="$("$BIN" baseline check 2>&1)"
assert_not_contains "check: temp file clean" "$out" "$tfile"
assert_not_contains "check: temp dir clean" "$out" "$tdir"

# freeze: verified content is served to the program
out="$(echo "$PW" | "$BIN" run work --password-stdin --verify -- cat "$tfile" 2>/dev/null)"
assert_contains "verify: frozen content visible to program" "$out" "proxy = none"

# freeze/TOCTOU: a host overwrite AFTER the check is shadowed in-session
marker="$trust/ready"; rm -f "$marker"
# Wait (bounded) for the program to signal it is running, THEN overwrite. The
# bound guarantees this helper can never spin forever if the run aborts.
( i=0; while [ ! -e "$marker" ] && [ "$i" -lt 200 ]; do sleep 0.05; i=$((i + 1)); done
  [ -e "$marker" ] && { sleep 0.2; printf 'ca = /POISONED\n' > "$tfile"; } ) &
atk=$!
out="$(echo "$PW" | "$BIN" run work --password-stdin --verify -- \
      bash -c "cat '$tfile'; touch '$marker'; sleep 2; echo ---; cat '$tfile'" 2>&1)"
wait "$atk" 2>/dev/null
if [[ "$out" == *"---"* ]] && [ "$(grep -c 'proxy = none' <<<"$out")" -ge 2 ] && [[ "$out" != *POISONED* ]]; then
    pass "verify: post-check host overwrite shadowed in-session"
else
    fail "verify: post-check host overwrite shadowed in-session" "${out:0:200}"
fi
assert_contains "verify: host file shows overwrite after exit" "$(cat "$tfile")" "POISONED"
printf 'ca = local\nproxy = none\n' > "$tfile"  # restore + re-bless for later checks
as_root "$BIN" baseline pin --user "$U" "$tfile" >/dev/null 2>&1

# poison detection → fail closed
printf 'ca = /evil\n' > "$tfile"
out="$("$BIN" baseline check 2>&1)"
assert_contains "check: poisoned file flagged" "$out" "$tfile"
out="$(echo "$PW" | "$BIN" run work --password-stdin --verify -- echo RAN 2>&1)"; rc=$?
if [ $rc -ne 0 ] && [[ "$out" != *RAN* ]] && [[ "$out" == *"$tfile"* ]]; then pass "verify: poison aborts, names file"; else fail "verify: poison aborts, names file" "rc=$rc ${out:0:200}"; fi
printf 'ca = local\nproxy = none\n' > "$tfile"; as_root "$BIN" baseline pin --user "$U" "$tfile" >/dev/null 2>&1

# directory completeness: an added file is a mismatch
printf 'planted\n' > "$tdir/evil.pem"
out="$("$BIN" baseline check 2>&1)"
assert_contains "check: added file in tracked dir flagged" "$out" "$tdir"
rm -f "$tdir/evil.pem"

# absent-neutralize: an attacker-created file at an absent path is emptied, not an abort
printf 'proxy = http://evil\n' > "$tabsent"
out="$(echo "$PW" | "$BIN" run work --password-stdin --verify -- bash -c "wc -c < '$tabsent'" 2>/dev/null)"; rc=$?
if [ "${out//[[:space:]]/}" = "0" ]; then pass "verify: reappeared absent path neutralized (empty)"; else fail "verify: reappeared absent path neutralized" "rc=$rc bytes='$out'"; fi
rm -f "$tabsent"

# compose: --sandbox + --verify (+ --harden) together
mkdir -p "$HOME/.aws"; printf 'AWSKEY\n' > "$HOME/.aws/credentials"
out="$(echo "$PW" | "$BIN" run work --password-stdin --sandbox --verify --harden -- \
      bash -c "echo cfg=\$(cat '$tfile' | head -1); echo aws=\$(ls -A ~/.aws | wc -l)" 2>/dev/null)"
assert_contains "compose: frozen config visible" "$out" "cfg=ca = local"
assert_contains "compose: creds masked under sandbox" "$out" "aws=0"

# ---- dir mode: the SAME baseline is honored by `dir run --verify` ----
out="$(echo "$PW" | "$BIN" dir run dv --password-stdin --verify -- cat "$tfile" 2>/dev/null)"
assert_contains "dir run --verify: frozen config visible" "$out" "proxy = none"

printf 'ca = /evil-dir\n' > "$tfile"
out="$(echo "$PW" | "$BIN" dir run dv --password-stdin --verify -- echo RAN 2>&1)"; rc=$?
if [ $rc -ne 0 ] && [[ "$out" != *RAN* ]] && [[ "$out" == *"$tfile"* ]]; then
    pass "dir run --verify: poison aborts, names file"
else
    fail "dir run --verify: poison aborts, names file" "rc=$rc ${out:0:200}"
fi
printf 'ca = local\nproxy = none\n' > "$tfile"; as_root "$BIN" baseline pin --user "$U" "$tfile" >/dev/null 2>&1

# dir-mode full compose: --sandbox + --verify + --harden together
out="$(echo "$PW" | "$BIN" dir run dv --password-stdin --sandbox --verify --harden -- \
      bash -c "echo cfg=\$(cat '$tfile' | head -1); echo aws=\$(ls -A ~/.aws | wc -l)" 2>/dev/null)"
assert_contains "dir compose: frozen config visible" "$out" "cfg=ca = local"
assert_contains "dir compose: creds masked under sandbox" "$out" "aws=0"

# cleanup root state
as_root rm -rf /etc/envvault
