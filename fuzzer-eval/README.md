# CompleXML artifact

Artifact for "CompleXML: Denial-of-Service Through Post-Parse Algorithmic
Complexity". It supports the fuzzing evaluation in Table 3.

| tier | what it does | cost |
|---|---|---|
| 1 | Re-score the saved fuzzer inputs and rebuild Table 3's marks | ~30 min |
| 2 | Run one configuration of Table 3 against one sink | ~24 h |
| 3 | Tier 2 across all configurations and sinks | ~2,160 CPU-hours |

Tier 1 reproduces the operation block of Table 3 cell for cell. The two CPU
blocks depend on the measuring machine, and a cell whose best input costs close
to the bar can come out differently; "Reproducing the CPU blocks" below compares
the shipped reference with Table 3. Tier 1 does not reproduce the hour figures:
the saved inputs carry no timestamps, so time to first clear needs a Tier 2 run.

## Tier 1

```sh
docker build -t ac-libxml2 .
docker run --rm ac-libxml2 scripts/score.sh --verify
docker run --rm ac-libxml2 scripts/score.sh --ops 8e6
docker run --rm ac-libxml2 scripts/score.sh --bar 2
docker run --rm ac-libxml2 scripts/score.sh --bar 5
```

Or locally, which needs AFL++ for `--instrumented`:

```sh
scripts/build.sh --instrumented
scripts/score.sh --ops 8e6
```

The reference output is in `data/expected/`. `--json FILE` also writes the
result as JSON for diffing; from Docker, write it into a mounted directory.

### What is being scored

`data/champions/` holds 161 inputs, up to two per run: the input that maximised
the sink's operation counter (`_ops`) and the one that maximised CPU time as the
campaign recorded it (`_cpu`). The two differ in 69 of the 71 runs that recorded
both. The campaign recorded CPU time under load, so `_cpu` is not reliably the
more expensive of the two when re-measured. The operation criterion is scored on
`_ops`; a CPU criterion counts a run if either input reaches the bar, as for
Table 3. `data/champions.tsv` gives arm, engine, sink, repetition, kind, size
and SHA-256, and `--verify` checks them.

Runs with no recorded input appear as `NO_INPUT_RECORDED` and count as not
cleared, as in Table 3. The five marked `ok (recovered)` were located in the
saved queues afterwards, because the scorer had not recorded which file
produced its result.

### Reproducing the CPU blocks

`score.py` reports the median of `--reps` timings per input, 5 by default and in
the shipped reference, and prints the host it ran on. `--reps 2` is faster and
less stable. The paper's `n=2` is the number of fuzzing trials, not of timing
repetitions.

The operation counter is deterministic, so the operation block reproduces cell
for cell on any machine. CPU time depends on the machine and its state. On the
reference machine, an Intel i7-1355U with 12 logical CPUs, the same input
measured up to 2.3x apart on different days and up to 1.3x apart on one day,
idle both times. Other work running raised CPU times 2.4x to 3.9x, so measure on
an idle machine.

Table 3's CPU marks come from a pass on 2026-10-03, and `data/expected/` from a
pass on 2026-10-09. The two differ in two marks and three run counts of the 5 s
block, and in one mark and one run count of the 2 s block, all from these six
runs:

| run | bar | 2026-10-03 | 2026-10-09 |
|---|---|---|---|
| `AFL++ all`, XPlode, trial 1 | 5 s | 5.19 s | 3.51 s |
| `AFL++ only`, Wreckoncile, trial 1 | 5 s | 6.91 s | 2.97 s |
| `AFL++ only`, Wreckoncile, trial 2 | 5 s | 8.13 s | 3.88 s |
| `Informed`, FlAttr, trial 1 | 5 s | 5.13 s | 2.42 s |
| `Informed`, Wreckoncile, trial 2 | 5 s | 5.26 s | 3.65 s |
| `SlowFuzz`, C14N1D3 (incl.), trial 1 | 2 s | 2.18 s | 1.36 s |

Each figure is the more expensive of the run's two inputs; the 2026-10-09 column
was measured after the reference pass, on the same day. The Stock column is
0 of 40 in every pass.

### Instrumented build

Tier 1 measures CPU time on libxml2 compiled with `afl-clang-fast` from AFL++
5.03a, the build the paper's measurements used. `--instrumented` selects it, the
image builds it by default, and the image pins AFL++ by commit. The
instrumentation adds work on every edge, so a clean build gives lower CPU times
and clears fewer CPU cells; `data/expected/cpu-5s-clean.txt` is the clean-build
reference. Operation counts are identical between the two builds.

### libxml2 revision

The paper names the release, v2.15.0. The campaign and the measurements used
commit `c6324894` of the development branch, and
the artifact pins that commit. On the five sinks, the release, that commit and
upstream master as of 2026-09-23 give identical operation counts.

`scripts/compare-revisions.sh v2.15.0 c6324894 latest` repeats that check: it
builds each revision into its own `build/bin-<short>/`, replays one saved input
per sink through each, and compares the counters. Other revisions build the
same way:

```sh
scripts/build.sh --commit latest      # upstream master
scripts/build.sh --commit v2.15.0     # a tag
scripts/build.sh --commit c43dc98d    # any commit
docker build --build-arg BUILD_ARGS="--commit latest --instrumented" -t ac-libxml2-latest .
```

`build.sh` fetches from gitlab.gnome.org and falls back to GNOME's GitHub
mirror; the commit hash is checked either way. Set `LIBXML2_REPO` to use a
local clone offline.

## Tier 2

```sh
docker build --build-arg ENGINES=all -t ac-libxml2 .
mkdir -p runs
docker run --rm -v "$PWD/runs:/artifact/runs" \
    ac-libxml2 scripts/fuzz.sh --sink xplode --config suite-only --hours 24
docker run --rm -v "$PWD/runs:/artifact/runs" \
    ac-libxml2 scripts/score.sh --run-dir runs/out-c3-suite-only/default/queue \
    --sink xplode --bar 5
```

Mount the volume: without `-v`, a `--rm` container deletes the run when it
exits. Inside the image the output directory defaults to `/artifact/runs`, so
the mount is picked up with no other flags, and the run is made world-readable
when it finishes.

The container runs as root, so files under `runs/` are owned by root. To own
them yourself, add `--user "$(id -u):$(id -g)"` and create `runs/` before
starting: Docker creates a missing bind-mount source as root, and a `--user`
container cannot write to it.

Sinks take the paper's vector names: `c14n-exc`, `c14n-inc`, `xplode`, `flattr`,
`wreckoncile`. The codes `c1 c2 c3 c5 c7` also work and appear in output
directory names. `--hours` takes fractions; `--hours 0.05` is a three-minute
smoke run. Seeds come from `seeds/<sink>_b` (see `seeds/README.md`).

### Choosing the engine

`--config` selects both the engine and its mutation mode. Each engine has its
own instrumented libxml2 and its own interface for the suite, so the two are
chosen together.

| engine | `--config` | mutators | Table 3 column |
|---|---|---|---|
| AFL++ | `stock` | its own, byte-level | Stock |
| AFL++ | `mopt` | its own, MOpt schedule (`-L`) | Stock |
| AFL++ | `all-stages` | the suite plus its own stages | AFL++ all |
| AFL++ | `suite-only` | the suite alone, havoc off | AFL++ only |
| AFL++ | `informed` | one per-sink operator | Informed |
| PerfFuzz | `perffuzz` | its own, byte-level | Stock |
| PerfFuzz | `perffuzz-suite` | the suite after havoc, via `AFL_POST_LIBRARY` | PerfFuzz |
| SlowFuzz | `slowfuzz` | its own | Stock |
| SlowFuzz | `slowfuzz-suite` | the suite as one mutator among its defaults | SlowFuzz |

Only AFL++ can run the suite alone. It has `AFL_CUSTOM_MUTATOR_ONLY`; PerfFuzz
takes the suite through `AFL_POST_LIBRARY`, which runs after havoc and cannot
turn it off; SlowFuzz adds it as a fourteenth mutator beside its thirteen. The
comparable arms across engines are therefore `all-stages`, `perffuzz-suite` and
`slowfuzz-suite`, all default-plus-suite. `suite-only` has no counterpart in the
other two.

`n=2` in the paper means two trials, and trials of one cell can differ by hours.

### Output and scoring

```
out-<sink>-<config>/default/queue     AFL++, SlowFuzz
out-<sink>-<config>/queue             PerfFuzz (AFL 2.52b)
```

`fuzz.sh` prints the scoring command for the run it made. `score.sh --run-dir`
re-measures every input in the queue and reports the most expensive one. AFL++
names each input with the time it was found, so for AFL++ runs the scorer also
reports the time to first clear; PerfFuzz and SlowFuzz names carry no time.

CPU time records how long an input took, not where: an input can clear a CPU
bar while the sink's operation counter stays at zero. The scorer counts such
inputs and reports them as `non-sink cost: N input(s) met the CPU bar with 0
sink operations`; `--require-sink-ops` excludes them.

Under a CPU bar the scorer stops each measurement just past the bar, and a
stopped input prints no operation count. `--deep-timeout` (default 1800 s)
re-runs such an input once under a longer cap to recover it. That is cheap for
a fuzzer queue, where few inputs reach the cap, but the saved inputs are each
run's most expensive and two of them run for about 30 minutes, so
`--require-sink-ops` is accepted with `--run-dir` only.

### Engines and toolchains

`build-engines.sh` builds a separate instrumented libxml2 for each engine. All
three compile `src/harness/cputime_afl.c`.
A per-engine define changes only how the cost is reported (AFL++ receives it
through `ijon_max`; PerfFuzz and SlowFuzz use their own instrumentation) and the
entry point.

The image is Ubuntu 24.04 with the compilers the campaign used, clang 18.1.3 and
gcc 13.3.0, and pins the engine revisions: AFL++ 5.03a, PerfFuzz `f937f37`,
SlowFuzz `e124345`.

## Tier 3

9 configurations x 5 sinks x 2 trials = 90 runs of 24 h, about 2,160 CPU-hours
and up to 80 GB of disk, most of it for the 20 SlowFuzz runs. There is no
script: it is the Tier 2 command in a loop.

## Layout

```
patches/      libxml2 counter instrumentation, and the SlowFuzz mutator hook
src/measure/  the five scoring harnesses, one per sink
src/harness/  the fuzzing driver shared by all three engines, and the coverage
              shim SlowFuzz links against
src/mutator/  the operator suite and the five per-sink operators
seeds/        one seed corpus per sink
dict/         the AFL dictionaries the campaign used
scripts/
  build.sh              libxml2 and the measurement harnesses
  build-engines.sh      the Tier 2 fuzzing targets, per engine
  patch_slowfuzz_cm.py  enables SlowFuzz's custom-mutator hook
  fuzz.sh               run one configuration against one sink
  score.sh, score.py    score the saved inputs, or a fuzzer output directory
  compare-revisions.sh  compare the sinks across revisions
data/
  champions/      161 saved inputs
  champions.tsv   manifest with SHA-256
  expected/       reference output at --reps 5
```

| harness | vector |
|---|---|
| `c1` | C14N1D3, exclusive canonicalization |
| `c2` | C14N1D3, inclusive canonicalization |
| `c3` | XPlode (XPath transform) |
| `c5` | FlAttr (attribute marshaling) |
| `c7` | Wreckoncile (namespace reconciliation) |

Four vectors, five harnesses: C14N1D3 is run in both modes.
