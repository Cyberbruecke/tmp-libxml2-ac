# Artifact: post-parse algorithmic-complexity attacks on libxml2

This artifact supports the fuzzing evaluation (Table 3 and the surrounding
claims).

| tier | what it does | cost |
|---|---|---|
| **1** | Re-score the saved fuzzer-produced inputs and rebuild Table 3 | **~30 min** |
| 2 | Run one fuzzing arm against one sink, then score it with Tier 1 | ~24 h |
| 3 | Tier 2 repeated across all arms and sinks | 1,821 CPU-hours |

**Tier 1 is the one to run.** It verifies the measurements Table 3 is built
from. Tier 2 re-runs one search and is optional. Tier 3 is just Tier 2 repeated
across every arm and sink.

---

## Quick start

```sh
scripts/build.sh --instrumented    # libxml2 + the 5 measurement harnesses
scripts/score.sh --verify          # check saved inputs against their digests
scripts/score.sh --ops 8e6         # operation criterion
scripts/score.sh --bar 5           # CPU criterion, the paper's headline
scripts/score.sh --bar 2           # CPU criterion, the lower bar
```

Or in Docker, which needs nothing installed locally:

```sh
docker build -t ac-libxml2 .
docker run --rm ac-libxml2 scripts/score.sh --ops 8e6
```

Reference output is in `data/expected/`. Add `--json FILE` to any run for a
machine-diffable version.

---
## What reproduces, and what does not

| criterion | matches Table 3 |
|---|---|
| operation count | **exactly**, every cell, on every revision and build we tested |
| CPU, 2 s bar | every vector cell; the Informed run count is one lower |
| CPU, 5 s bar | four of five vectors; see the caveat below |

The operation counter is an exact count of sink iterations. It does not depend
on hardware, compiler or build flags, which is why it reproduces everywhere and
why we recommend it as the primary check.

**The 5 s FlAttr cell does not reproduce.** The paper records the informed arm
clearing FlAttr at 30.4 h. The input behind that cell measures a median of
**4.88 s** over 15 repetitions on the instrumented build, straddling the 5 s bar
(6 of 15 individual measurements exceed it). It is a genuinely borderline input
and a single measurement decides it either way, which is why `--reps` matters
here. The 2 s bar and the operation criterion are unaffected.

## Choosing a libxml2 revision

```sh
scripts/build.sh                     # c6324894, the revision the paper reports
scripts/build.sh --commit latest     # current upstream master
scripts/build.sh --commit v2.15.0    # any tag
scripts/build.sh --commit c43dc98d   # any commit
```

Each revision builds into its own `build/bin-<short>/`, so several coexist.
To check the sinks have not changed across revisions:

```sh
scripts/compare-revisions.sh v2.15.0 c6324894 latest
```

This replays one input per sink through each build and compares the operation
counters, which are exact. We checked the released `v2.15.0`, the commit the
paper reports, and upstream master as of 2026-09-23: the counters are identical
on all five sinks, so the vectors are unchanged on current libxml2.

The paper reports `v2.15.0-124-gc6324894`. That is `git describe` output, not a
tag: 124 commits past the `v2.15.0` tag, abbreviated hash `c6324894` (the `g`
means "git" and is not part of the hash). The tree's `VERSION` file reads
`2.16.0` there, so pin by commit, not by version string.

## Instrumented versus clean builds

**The paper's CPU figures were measured on an AFL-instrumented libxml2.** That
build does identical work, with bit-identical operation counters, but costs
more time, from 1.0x on `FlAttr` to 4.1x on `XPlode`. The overhead is not
uniform across sinks, which is a limitation of the CPU criterion.

Pass `--instrumented` to match the paper. It needs AFL++, via `AFL_PATH` or
`afl-clang-fast` on `PATH`; the Docker image installs it. Without it the
operation criterion still reproduces exactly, but fewer inputs cross the CPU
bars. Both variants are in `data/expected/`, suffixed `-instrumented` and
`-clean`, so the difference is visible rather than asserted.

## What you are scoring

`data/champions/` holds **161 inputs**: for each fuzzing run, the most expensive
input it produced under each criterion. Those differ in 68 of 70 runs, so each
criterion is scored against its own. `data/champions.tsv` records arm, engine,
sink, repetition, size and SHA-256.

Some runs recorded no input and appear as `NO_INPUT_RECORDED`. They cannot be
verified either way and count as *not cleared*, matching the paper. Five marked
`ok (recovered)` were recovered from the saved queues after the original scorer
failed to record which file produced its result.

## Measurement notes

**A single timing is not reproducible.** Across scoring passes the same input
varied by up to 4x in both directions. `score.py` replays each input `--reps`
times and keeps the median; the shipped reference output uses `--reps 5`. For a
threshold test the measurement is censored just above the bar, since only the
comparison matters.

`--reps` is unrelated to the paper's `n=2`. `n=2` is the number of independent
fuzzing trials and measures search variance; `--reps` re-measures one fixed
input and measures timer noise.

**Absolute CPU times are hardware-dependent.** The reference host was a 12-core
machine and the thresholds are absolute costs on it. `score.py` prints the host
it ran on. What should reproduce is the pattern: which cells clear.

## Tier 2: run a fuzzer, then score it

```sh
scripts/build.sh --instrumented                    # once
scripts/fuzz.sh --sink c2 --config stock --hours 24       # byte mutators only
scripts/fuzz.sh --sink c2 --config suite-only --hours 24  # XML-aware suite
scripts/score.sh --run-dir out-c2-suite-only/default/queue --sink c2 --bar 5
```

Needs AFL++ (`AFL_PATH`, or `afl-fuzz` on `PATH`). Sinks are `c1 c2 c3 c5 c7`.
The scorer reports the most expensive input found and, from AFL++'s `time:`
filename field, when the run first crossed the bar.

Three of Table 3's columns are runnable:

| `--config` | Table 3 column | what it runs |
|---|---|---|
| `stock` | Stock | AFL++ byte mutators only |
| `all-stages` | AFL++ all | suite plus AFL++'s own stages, havoc on |
| `suite-only` | AFL++ only | suite alone, havoc off (the default) |

Running `stock` against `suite-only` on one sink reproduces the paper's central
contrast in miniature: the stock run should find nothing, the suite run should
climb. `all-stages` against `suite-only` shows what AFL++'s native stages add,
or cost.

**The remaining columns are not runnable here.** PerfFuzz and SlowFuzz each need
their own fork and their own instrumented libxml2 build, with the operator suite
in a different host binding, and "Informed" uses per-sink operators written from
our own analysis of each sink. Tier 1 still verifies all of them, because the
scorer replays saved inputs through the sink and does not care which fuzzer
produced them.

Note that `n=2` in the paper means two independent trials per cell, so a single
run can differ from our figures by hours.

## Tier 3: the full campaign

Tier 3 is Tier 2 repeated: 9 arms across 5 sinks, 2 trials each, 90 runs and
1,821 CPU-hours in total. There is no separate script, because there is nothing
more to it than looping the command above over arms and sinks. We did not
expect reviewers to run it, and we state the budget so the cost is explicit
rather than implied.

The comparative claim in the paper, that stock finds nothing in 40 runs while
the suite finds three of four vectors, is inherently a many-run result. Tier 1
verifies every measurement behind it and Tier 2 reproduces any single cell.

## Layout

```
patches/      libxml2 counter instrumentation (5 globals, no algorithm change)
src/measure/  the five scoring harnesses, one per sink, engine-independent
src/harness/  the AFL++ fuzzing drivers (Tier 2)
src/mutator/  the generic XML-aware operator suite (Tier 2)
seeds/ dict/  benign seed documents and the XML token dictionary
scripts/
  build.sh              build libxml2 + harnesses at a chosen revision
  fuzz.sh               run one fuzzing arm against one sink (Tier 2)
  score.sh              score the saved inputs, or a fuzzer output directory
  compare-revisions.sh  check the sinks across several revisions
data/
  champions/      161 saved inputs
  champions.tsv   manifest with SHA-256 per input
  expected/       reference output at --reps 5
```

| harness | vector in the paper |
|---|---|
| `c1` | C14N1D3, exclusive canonicalization |
| `c2` | C14N1D3, inclusive canonicalization |
| `c3` | XPlode (XPath transform) |
| `c5` | FlAttr (attribute marshalling) |
| `c7` | Wreckoncile (namespace reconciliation) |

Four vectors through five harnesses, since C14N1D3 is driven separately in its
two canonicalization modes.