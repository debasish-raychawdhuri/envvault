#!/usr/bin/env bash
# Run the full envvault integration suite and print one aggregated report.
#
#   ./integration-tests/run_all.sh            # build + run everything
#   ./integration-tests/run_all.sh 50_unrun.sh 60_run_sandbox.sh   # a subset
#
# Sudo is primed once up front (a single password prompt) and reused by the
# root-only tests; without it those tests SKIP rather than fail. Set
# ENVVAULT_SKIP_BUILD=1 to skip `cargo build`, or ENVVAULT_BIN=/path to use a
# specific binary. Exit code is non-zero iff any check FAILED.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"

if [ -z "${ENVVAULT_SKIP_BUILD:-}" ]; then
    echo "building envvault (debug)…"
    ( cd "$REPO" && cargo build ) || { echo "build failed"; exit 2; }
fi
export ENVVAULT_BIN="${ENVVAULT_BIN:-$REPO/target/debug/envvault}"
[ -x "$ENVVAULT_BIN" ] || { echo "binary not found: $ENVVAULT_BIN"; exit 2; }

export ENVVAULT_IT_RESULTS; ENVVAULT_IT_RESULTS="$(mktemp)"
export ENVVAULT_IT_RUNNER=1

# shellcheck source=lib.sh
source "$HERE/lib.sh"   # for it_report + colors (results already set → no standalone trap)

# Prime sudo once (or mark root tests to be skipped). `sudo -v` prompts on the
# controlling terminal (/dev/tty), so it works even when stdin isn't a tty; if
# there's no terminal or no rights, it fails fast (no hang) and we skip.
if [ "$(id -u)" = 0 ]; then
    echo "running as root (note: baseline tests expect a normal invoking user)."
elif sudo -n true 2>/dev/null; then
    echo "sudo: already authorized."
else
    echo "Priming sudo for the baseline tests (you'll be asked for your password once)…"
    if sudo -v; then
        echo "sudo: authorized for this run."
    else
        export ENVVAULT_IT_NOSUDO=1
        echo "${Y}note:${N} sudo unavailable — root-only tests (baseline write) will be SKIPPED."
    fi
fi

if [ "$#" -gt 0 ]; then
    files=()
    for a in "$@"; do
        if [ -f "$a" ]; then files+=("$a"); elif [ -f "$HERE/$a" ]; then files+=("$HERE/$a"); else echo "no such test file: $a"; fi
    done
else
    files=("$HERE"/[0-9]*.sh)
fi

for f in "${files[@]}"; do
    bash "$f"
done

it_report "$ENVVAULT_IT_RESULTS"
rc=$?
rm -f "$ENVVAULT_IT_RESULTS"
exit $rc
