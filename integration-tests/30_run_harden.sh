#!/usr/bin/env bash
# `run --harden`: the program still gets the secret (delivered over a pipe after
# it is non-dumpable), but a same-uid attacker can no longer read it from
# /proc/<pid>/environ, and the process is non-dumpable. A static binary (no
# LD_PRELOAD) fails closed — no secret is sent.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
feature "run --harden"
new_work

echo "$PW" | "$BIN" init work --password-stdin --no-edit >/dev/null
set_secret work OPENAI_API_KEY sk-harden-XYZ >/dev/null 2>&1

# secret still reaches the program (getenv works post-injection)
out="$(echo "$PW" | "$BIN" run work --password-stdin --harden -- bash -c 'printf "%s" "$OPENAI_API_KEY"' 2>/dev/null)"
assert_eq "hardened program sees the secret (getenv)" "$out" "sk-harden-XYZ"

# launch a long-lived hardened program and inspect it from the outside
pidf="$WORK/pid"
# Trailing `; true` stops bash from exec-optimizing into `sleep` (which would
# replace the shim-loaded bash and reset dumpability), so we measure the actual
# hardened process.
echo "$PW" | "$BIN" run work --password-stdin --harden -- \
    bash -c "echo \$\$ > '$pidf'; sleep 47; true" &
launch=$!; track_bg "$launch"
if wait_for "$pidf" 8; then
    cpid="$(cat "$pidf")"
    # Non-dumpability is what actually blocks a same-uid attacker: it can read
    # neither the process's environ nor its memory. (/proc/<pid> *ownership* is
    # NOT a reliable signal — on this kernel a non-dumpable process's /proc dir
    # stays user-owned, yet ptrace_may_access still denies these reads.)
    env_denied=YES; cat "/proc/$cpid/environ" >/dev/null 2>&1 && env_denied=NO
    mem_denied=YES; dd if="/proc/$cpid/mem" bs=1 count=1 >/dev/null 2>&1 && mem_denied=NO
    assert_eq "hardened: /proc/<pid>/environ read denied to same uid" "$env_denied" "YES"
    assert_eq "hardened: /proc/<pid>/mem read denied to same uid" "$mem_denied" "YES"
else
    fail "hardened: child started" "pidfile never appeared"
fi
kill_tree "$launch" 2>/dev/null

# static binary → shim can't load → fail closed, no secret sent
CC="$(command -v cc || command -v gcc || true)"
if [ -n "$CC" ]; then
    printf 'int main(void){return 0;}\n' > "$WORK/s.c"
    if "$CC" -static -O2 -o "$WORK/s.bin" "$WORK/s.c" 2>/dev/null && \
       file "$WORK/s.bin" 2>/dev/null | grep -q 'statically linked'; then
        out="$(echo "$PW" | "$BIN" run work --password-stdin --harden -- "$WORK/s.bin" 2>&1)"; rc=$?
        if [ $rc -ne 0 ] && [[ "$out" == *"did not load the hardening shim"* ]]; then
            pass "static binary fails closed (no secret sent)"
        else
            fail "static binary fails closed" "rc=$rc out=${out:0:200}"
        fi
    else
        skip "static binary fails closed" "no static libc available to build a static test binary"
    fi
else
    skip "static binary fails closed" "no C compiler found"
fi
