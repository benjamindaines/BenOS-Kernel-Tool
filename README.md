# benos-kernel-tool (`benos-kt`)

Backport triage for ACK android12-5.10 fixes into the Q25 kernel. For each candidate commit the spine
resets a reused work tree to the target base, cherry-picks the candidate, and — when it applies cleanly
— runs a configurable build command, then classifies the outcome.

## Status

Phase 1 of the build order (apply → build → classify) is implemented. Candidate
generation/ranking (CVE join, relevance) and the TUI front-end (gitomic's commit browser, reused) are
not yet built.

## Classification

| status           | meaning                                                            |
|------------------|--------------------------------------------------------------------|
| `builds`         | applied cleanly and the build command succeeded                    |
| `build_breaks`   | applied cleanly but the build command failed                       |
| `build_timeout`  | applied cleanly but the build exceeded `--timeout`                 |
| `conflict`       | did not apply; a hand merge is required                            |
| `already_applied`| the change is already present on base (empty cherry-pick)          |
| `irrelevant`     | touched no compiled path, or only `--ignore-paths` prefixes         |

## Usage

```
benos-kt run --repo <kernel> --base <target-tip> \
    ( --range <ack-tip | A..B> | --candidates <file> | --stdin ) \
    --build-cmd '<command>' [--run-dir <dir>] [--timeout <secs>] \
    [--compiled-set <paths-file>] [--ignore-paths <prefix,...>] [--redo] [--skip-baseline]

benos-kt report [<results.jsonl>] [--repo <dir>] [--name <label>] [--run-dir <dir>]
```

`report` with no arguments resolves the results from the run directory, the same place `run` writes: the `default` run under the repository, or the most recent run when runs are labelled with `--name`. Pass a file, `--run-dir`, or `--name` to pick a specific one.

`--range` takes either a bare ref or a range expression. A bare `TIP` means `base..TIP` — every upstream
commit past the apply base. A range `A..B` (or `A...B`) is passed to `git rev-list` verbatim, so an
arbitrary slice of upstream can be tested independently of the base, for example
`--range android12-5.10~1888..android12-5.10~1842`. The candidates are still applied onto `--base`.

The `--build-cmd` string is run via `sh -c` with these variables exported; it maps them onto the build
system's own, so this tool holds no build-system or credential specifics:

| variable        | value                                   |
|-----------------|-----------------------------------------|
| `BKT_WORKTREE`  | the work tree to build (`KERNEL_DIR`)   |
| `BKT_BASE`      | the resolved base sha                    |
| `BKT_CANDIDATE` | the candidate sha being classified       |
| `BKT_RUNDIR`    | the run directory (for an out-of-tree `O=`) |

By default the command runs in the candidate's work tree. A build wrapper that locates its toolchain
relative to its own directory must instead run from that directory; pass `--build-dir` for that, and the
work tree is still handed over as `BKT_WORKTREE`.

BenOS-tools `build.sh` (not posted yet) provides a `run-test` subcommand that consumes this contract (stock `defconfig` +
`build`, no features, device tree excluded, exit status as the verdict), so the wiring is:

```
benos-kt run --repo <kernel> --base <target-tip> --range <ack-tip> \
    --build-dir /path/to/BenOS-tools/kernel \
    --build-cmd './build.sh run-test'
```

`run-test` reads `BKT_WORKTREE` and `BKT_RUNDIR` itself, so no inline environment mapping is needed.
Build output lives out-of-tree under `BKT_RUNDIR`, so it survives the per-candidate reset and an
incremental rebuild compiles only what the candidate changed.

## Ignoring unenforced paths

`--ignore-paths <prefix,...>` classifies a candidate `irrelevant` when **every** path it changed begins
with one of the given prefixes, without applying or building it. This drops churn in tree regions the
target build does not enforce before it reaches the conflict list. For this kernel the GKI symbol lists
are the case: the build omits the `check_gki` gate, so symbol-list commits conflict noisily but mean
nothing to the build.

```
--ignore-paths android/abi_gki_
```

In one observed 8-candidate sweep, five of seven conflicts touched only `android/abi_gki_*`; the filter
reduces the hand-merge pile to the two genuine source conflicts.

## Stopping a run

One Ctrl-C (SIGINT) stops the run cleanly: the in-progress build is terminated, the current candidate is left unclassified so a resumed run re-evaluates it, the loop ends, and the summary prints. Results are written per candidate as the run proceeds, so a run killed by any means keeps everything already classified; `benos-kt report <results.jsonl>` prints the summary over a partial file.

## Results

`<run-dir>/results.jsonl` is append-only, one record per candidate, keyed by candidate sha. A re-run
without `--redo` skips candidates already recorded, so an interrupted run resumes. Per-candidate build
logs are under `<run-dir>/logs/`.
