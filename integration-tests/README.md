# envvault integration tests

End-to-end checks that exercise the real `envvault` binary across every feature,
complementing the in-crate unit tests (`cargo test`). They run actual programs
through `run`/`dir run`/`unrun`, set up user+mount namespaces, read `/proc`, and
(when sudo is available) write the root-owned baseline under `/etc/envvault`.

## Run

```sh
./integration-tests/run_all.sh                       # build, then run all
./integration-tests/run_all.sh 50_unrun.sh 60_run_sandbox.sh   # a subset
ENVVAULT_SKIP_BUILD=1 ./integration-tests/run_all.sh # reuse the current binary
```

You'll be asked for your sudo password **once** at the start. It's used only by
the baseline tests (which create and then delete `/etc/envvault/<user>.baseline`).
Run it as your **normal user** (not `sudo run_all.sh`) — sudo is invoked
internally where needed. Without sudo the root-only tests are **skipped**, not
failed, so the suite is still useful.

At the end you get one aggregated report: a per-feature PASS/FAIL/SKIP table, a
detailed list of every failure (with the captured detail), the skip list, and an
overall result. Exit code is non-zero iff anything failed.

## Layout

| File | Feature |
|------|---------|
| `lib.sh`                  | Shared harness: hermetic workspace, assertions, sudo handling, `expect`-driven `set`/`passwd`, reporting. |
| `10_vault_basics.sh`      | `init`/`list`/`set`/`show`/`rm`/`rename`/`passwd`/`upgrade`, empty- and wrong-password guards. |
| `20_run_env.sh`           | `run` env injection; the `/proc/<pid>/environ` exposure; `--quiet`/`ENVVAULT_QUIET`. |
| `30_run_harden.sh`        | `run --harden`: secret via pipe, non-dumpable, `/proc` denied, static binary fails closed. |
| `40_dir_vault.sh`         | Directory and single-file vaults: init/run/status/export/list/upgrade/rm + persistence. |
| `50_unrun.sh`             | `unrun` credential masking, `--hide`, inheritance, host untouched. |
| `60_run_sandbox.sh`       | `run --sandbox`/`--allow`: structural masking, fake-`unrun`-can't-escape, `ENVVAULT_ALLOW`. |
| `70_baseline_verify.sh`   | Baseline + `run --verify`: perms, fail-closed, freeze, TOCTOU, dir completeness, absent, compose *(sudo)*. |
| `80_baseline_pin_unpin.sh`| `baseline pin`/`unpin`: surgical edits, covered-by-dir, dir drop, root-gating *(sudo)*. |

## Notes

* **Hermetic:** each file redirects `HOME` and `ENVVAULT_DIR` into a fresh temp
  dir, so your real dotfiles and vaults are never touched. The one exception is
  `70_baseline_verify.sh`, where `baseline set` additionally hashes the invoking
  user's real trust files *read-only* (the default set is resolved from the
  passwd home); its assertions key only on temp paths, and `/etc/envvault` is
  removed afterward.
* **Linux-only:** the namespace features (`dir run`, `unrun`, `--sandbox`,
  `--verify`) require unprivileged user namespaces.
* **`expect`** is used to drive the interactive `set`/`passwd` prompts; install
  it if missing (those checks fail loudly otherwise).
