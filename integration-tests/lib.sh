#!/usr/bin/env bash
# Shared harness for the envvault integration tests.
#
# Each NN_<feature>.sh sources this, calls `feature <name>`, sets up a hermetic
# workspace with `new_work`, and uses the pass/fail/skip + assert_* helpers.
# Results are appended (one tab-separated line per check) to $ENVVAULT_IT_RESULTS;
# run_all.sh aggregates them into the final report. A file run on its own prints
# its own report at exit.
#
# Design notes:
#   * Hermetic: HOME and ENVVAULT_DIR are redirected into a fresh temp dir, so the
#     tests never touch your real dotfiles or vaults. (The one exception is the
#     root-owned baseline at /etc/envvault, which only the sudo tests write and
#     which they clean up.)
#   * Root: tests that need root call `require_root` and SKIP (not FAIL) when sudo
#     isn't available, so the suite is meaningful with or without a password.

[ -n "${_ENVVAULT_LIB:-}" ] && return 0
_ENVVAULT_LIB=1
set -uo pipefail

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$LIB_DIR/.." && pwd)"
BIN="${ENVVAULT_BIN:-$REPO/target/debug/envvault}"
PW="integration-test-pw"

# Tests run headless: disable clipboard integration so `set`/editor never block
# on a half-present clipboard backend (see `open_clipboard` in main.rs).
export ENVVAULT_NO_CLIPBOARD=1

# Results sink: shared (set by run_all) or private (standalone run).
if [ -z "${ENVVAULT_IT_RESULTS:-}" ]; then
    ENVVAULT_IT_RESULTS="$(mktemp)"
    _IT_STANDALONE=1
else
    _IT_STANDALONE=0
fi

if [ -t 1 ]; then
    G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; B=$'\e[1m'; N=$'\e[0m'
else
    G=; R=; Y=; B=; N=
fi

_BGPIDS=()
_WORKDIRS=()
FEATURE="general"

feature() { FEATURE="$1"; echo; echo "${B}== $1 ==${N}"; }

# status name [detail]
_record() {
    local status="$1" name="$2" detail="${3:-}"
    detail="${detail//$'\n'/ / }"
    printf '%s\t%s\t%s\t%s\n' "$status" "$FEATURE" "$name" "$detail" >>"$ENVVAULT_IT_RESULTS"
}
pass() { echo "  ${G}PASS${N} $1"; _record PASS "$1"; }
fail() { echo "  ${R}FAIL${N} $1${2:+ — $2}"; _record FAIL "$1" "${2:-}"; }
skip() { echo "  ${Y}SKIP${N} $1${2:+ — $2}"; _record SKIP "$1" "${2:-}"; }

# --- assertions ---------------------------------------------------------------
assert_contains()     { if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1" "expected to contain '$3'; got: ${2:0:300}"; fi; }
assert_not_contains() { if [[ "$2" != *"$3"* ]]; then pass "$1"; else fail "$1" "should NOT contain '$3'; got: ${2:0:300}"; fi; }
assert_eq()           { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1" "expected '$3', got '$2'"; fi; }

# name cmd...   — expect exit 0
expect_ok() {
    local name="$1"; shift
    local out rc
    out="$("$@" 2>&1)"; rc=$?
    if [ "$rc" -eq 0 ]; then pass "$name"; else fail "$name" "exit $rc: ${out:0:300}"; fi
}
# name cmd...   — expect non-zero exit
expect_err() {
    local name="$1"; shift
    local out rc
    out="$("$@" 2>&1)"; rc=$?
    if [ "$rc" -ne 0 ]; then pass "$name"; else fail "$name" "expected failure, succeeded: ${out:0:200}"; fi
}

# --- environment --------------------------------------------------------------
# Fresh hermetic workspace; redirects HOME + ENVVAULT_DIR into it.
new_work() {
    WORK="$(mktemp -d)"
    export WORK
    export HOME="$WORK/home"
    export ENVVAULT_DIR="$WORK/vaults"
    mkdir -p "$HOME" "$ENVVAULT_DIR"
    _WORKDIRS+=("$WORK")
}

# True if we can sudo without prompting (creds cached, or running as root).
have_sudo() {
    [ -z "${ENVVAULT_IT_NOSUDO:-}" ] || return 1
    [ "$(id -u)" = 0 ] && return 0
    sudo -n true 2>/dev/null
}
# Guard at the top of a root-only test group. Returns 1 (caller should `return`).
require_root() {
    if have_sudo; then return 0; fi
    skip "${1:-root test}" "no sudo (run interactively to include)"
    return 1
}
# Run as root (sudo, or directly if already root).
as_root() {
    if [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi
}

# --- process helpers ----------------------------------------------------------
# Wait until $1 exists and is non-empty (timeout $2 seconds, default 5).
wait_for() {
    local f="$1" t="${2:-5}" i=0 max
    max=$((t * 20))
    while [ ! -s "$f" ] && [ "$i" -lt "$max" ]; do sleep 0.05; i=$((i + 1)); done
    [ -s "$f" ]
}
# Track a background pid for cleanup.
track_bg() { _BGPIDS+=("$1"); }
# Kill a process and any descendants (best-effort).
kill_tree() {
    local pid="$1"
    pkill -P "$pid" 2>/dev/null
    kill "$pid" 2>/dev/null
}

# --- expect-driven interactive commands ---------------------------------------
# set_secret <vault> <key> <value>  — drives `envvault set` through a pty.
# Wrapped in `timeout` so a misbehaving prompt can never hang the whole suite.
# Sends are terminated with "\n", NOT "\r": rpassword reads the line in no-echo
# mode with ICRNL off, so a carriage return is never seen as end-of-line and the
# read blocks forever. The small `after` settles the tty into raw mode first.
set_secret() {
    timeout 40 expect >/dev/null 2>&1 <<EXP
set timeout 20
spawn env ENVVAULT_NO_CLIPBOARD=1 "$BIN" set "$1" "$2"
expect "Vault password:"
after 300; send -- "$PW\n"
expect "Value for $2:"
after 300; send -- "$3\n"
expect { "Updated" { exit 0 } timeout { exit 1 } eof { exit 1 } }
EXP
}
# change_pw <vault> <oldpw> <newpw>  — drives `envvault passwd` through a pty.
change_pw() {
    timeout 40 expect >/dev/null 2>&1 <<EXP
set timeout 20
spawn env ENVVAULT_NO_CLIPBOARD=1 "$BIN" passwd "$1"
expect "Current vault password:"
after 300; send -- "$2\n"
expect "New vault password:"
after 300; send -- "$3\n"
expect "Confirm password:"
after 300; send -- "$3\n"
expect { "changed" { exit 0 } timeout { exit 1 } eof { exit 1 } }
EXP
}

# --- reporting ----------------------------------------------------------------
it_report() {
    local rf="${1:-$ENVVAULT_IT_RESULTS}"
    [ -f "$rf" ] || { echo "no results"; return 0; }
    echo
    echo "${B}=================== INTEGRATION REPORT ===================${N}"
    printf "%-28s %5s %5s %5s\n" "FEATURE" "PASS" "FAIL" "SKIP"
    printf -- "---------------------------- ----- ----- -----\n"
    local feats ft p f s
    feats="$(awk -F'\t' '!seen[$2]++{print $2}' "$rf")"
    while IFS= read -r ft; do
        [ -z "$ft" ] && continue
        read -r p f s < <(awk -F'\t' -v ft="$ft" '
            $2==ft && $1=="PASS"{p++} $2==ft && $1=="FAIL"{f++} $2==ft && $1=="SKIP"{s++}
            END{printf "%d %d %d", p+0, f+0, s+0}' "$rf")
        printf "%-28s %5d %5d %5d\n" "$ft" "$p" "$f" "$s"
    done <<<"$feats"

    local P F S
    read -r P F S < <(awk -F'\t' '
        $1=="PASS"{p++} $1=="FAIL"{f++} $1=="SKIP"{s++}
        END{printf "%d %d %d", p+0, f+0, s+0}' "$rf")
    printf -- "---------------------------- ----- ----- -----\n"
    printf "%-28s %5d %5d %5d\n" "TOTAL" "$P" "$F" "$S"

    if [ "$F" -gt 0 ]; then
        echo; echo "${R}${B}FAILURES${N}"
        while IFS=$'\t' read -r st ft nm dt; do
            printf "  ${R}✗${N} [%s] %s\n      %s\n" "$ft" "$nm" "${dt:-(no detail)}"
        done < <(awk -F'\t' '$1=="FAIL"' "$rf")
    fi
    if [ "$S" -gt 0 ]; then
        echo; echo "${Y}${B}SKIPPED${N}"
        while IFS=$'\t' read -r st ft nm dt; do
            printf "  ${Y}-${N} [%s] %s — %s\n" "$ft" "$nm" "${dt:-}"
        done < <(awk -F'\t' '$1=="SKIP"' "$rf")
    fi
    echo
    if [ "$F" -gt 0 ]; then
        echo "${R}${B}RESULT: FAIL${N} ($F failed, $P passed, $S skipped)"
        return 1
    fi
    echo "${G}${B}RESULT: OK${N} ($P passed, $S skipped)"
    return 0
}

_cleanup_all() {
    local p d
    for p in "${_BGPIDS[@]:-}"; do [ -n "$p" ] && kill_tree "$p"; done
    for d in "${_WORKDIRS[@]:-}"; do [ -n "$d" ] && rm -rf "$d"; done
}

if [ "$_IT_STANDALONE" = 1 ]; then
    trap '{ rc=$?; _cleanup_all; it_report; exit $rc; }' EXIT
else
    trap _cleanup_all EXIT
fi
