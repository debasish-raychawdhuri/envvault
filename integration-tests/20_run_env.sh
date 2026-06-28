#!/usr/bin/env bash
# `run` (env injection): the program sees the secret via getenv; the warning is
# shown by default and silenced by --quiet; and a plain run's secret IS visible
# in /proc/<pid>/environ to the same uid (the documented exposure that --harden
# later closes).
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
feature "run (env injection)"
new_work

echo "$PW" | "$BIN" init work --password-stdin --no-edit >/dev/null
set_secret work OPENAI_API_KEY sk-env-SECRET-123 >/dev/null 2>&1

# secret reaches the program
out="$(echo "$PW" | "$BIN" run work --password-stdin --quiet -- bash -c 'printf "%s" "$OPENAI_API_KEY"' 2>/dev/null)"
assert_eq "program sees the injected secret" "$out" "sk-env-SECRET-123"

# warning shown by default, silenced by --quiet
warn="$(echo "$PW" | "$BIN" run work --password-stdin -- true 2>&1 >/dev/null)"
assert_contains "exposure warning shown by default" "$warn" "/proc/<pid>/environ"
warnq="$(echo "$PW" | "$BIN" run work --password-stdin --quiet -- true 2>&1 >/dev/null)"
assert_not_contains "warning silenced by --quiet" "$warnq" "/proc/<pid>/environ"
warne="$(echo "$PW" | ENVVAULT_QUIET=1 "$BIN" run work --password-stdin -- true 2>&1 >/dev/null)"
assert_not_contains "warning silenced by ENVVAULT_QUIET" "$warne" "/proc/<pid>/environ"

# plain run leaks the secret via /proc/<pid>/environ (same uid)
pidf="$WORK/pid"
echo "$PW" | "$BIN" run work --password-stdin --quiet -- \
    bash -c "echo \$\$ > '$pidf'; sleep 47" &
launch=$!; track_bg "$launch"
if wait_for "$pidf" 8; then
    cpid="$(cat "$pidf")"
    environ="$(tr '\0' '\n' < "/proc/$cpid/environ" 2>/dev/null)"
    assert_contains "plain run: secret readable in /proc/environ" "$environ" "sk-env-SECRET-123"
    owner="$(stat -c '%U' "/proc/$cpid" 2>/dev/null)"
    assert_eq "plain run: process is dumpable (proc owned by user)" "$owner" "$(id -un)"
else
    fail "plain run: child started" "pidfile never appeared"
fi
kill_tree "$launch" 2>/dev/null
