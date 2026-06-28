#!/usr/bin/env bash
# `--harden` in BOTH modes:
#  * env `run --harden`: the program still gets the secret (delivered over a pipe
#    after it is non-dumpable), but a same-uid attacker can't read it from
#    /proc/<pid>/environ or /proc/<pid>/mem; a static binary fails closed.
#  * `dir run --harden`: the consumer (reading its secret from the in-RAM file)
#    is marked non-dumpable. From the host this is indistinguishable with/without
#    --harden (the user namespace already blocks a host attacker), so we verify
#    the shim's effect directly via the consumer's own PR_GET_DUMPABLE.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
feature "run/dir run --harden"
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

# Direct dumpability probe for BOTH modes: a tiny program that prints its own
# PR_GET_DUMPABLE. Under --harden the shim marks it non-dumpable (0); plain runs
# leave it dumpable (1). This is the only reliable way to check `dir run --harden`
# (host /proc reads are blocked by the namespace either way).
if [ -n "$CC" ]; then
    cat > "$WORK/dumpable.c" <<'CSRC'
#include <stdio.h>
#include <sys/prctl.h>
int main(void) { printf("dumpable=%d\n", prctl(PR_GET_DUMPABLE)); return 0; }
CSRC
    if "$CC" -O2 -o "$WORK/dumpable" "$WORK/dumpable.c" 2>/dev/null; then
        # env mode
        assert_contains "env run --harden: consumer non-dumpable (PR_GET_DUMPABLE=0)" \
            "$(echo "$PW" | "$BIN" run work --password-stdin --quiet --harden -- "$WORK/dumpable" 2>/dev/null)" "dumpable=0"
        assert_contains "env run (plain): consumer dumpable (=1)" \
            "$(echo "$PW" | "$BIN" run work --password-stdin --quiet -- "$WORK/dumpable" 2>/dev/null)" "dumpable=1"
        # dir mode: vault a throwaway file (in its own dir so the tmpfs-over-parent
        # doesn't shadow the probe binary), then run the probe as the consumer.
        mkdir -p "$WORK/seeddir"; printf 'x\n' > "$WORK/seeddir/seed.txt"
        echo "$PW" | "$BIN" dir init hv --path "$WORK/seeddir/seed.txt" --yes --password-stdin >/dev/null 2>&1
        assert_contains "dir run --harden: consumer non-dumpable (=0)" \
            "$(echo "$PW" | "$BIN" dir run hv --password-stdin --harden -- "$WORK/dumpable" 2>/dev/null)" "dumpable=0"
        assert_contains "dir run (plain): consumer dumpable (=1)" \
            "$(echo "$PW" | "$BIN" dir run hv --password-stdin -- "$WORK/dumpable" 2>/dev/null)" "dumpable=1"
    else
        skip "dumpability probe (env + dir)" "could not compile the probe"
    fi
else
    skip "dumpability probe (env + dir)" "no C compiler found"
fi
