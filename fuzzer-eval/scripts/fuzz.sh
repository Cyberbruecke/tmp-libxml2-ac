#!/usr/bin/env bash
# Tier 2: run one configuration of Table 3 against one sink.
#
#   scripts/fuzz.sh --sink xplode --config suite-only --hours 24
#
# --config  stock mopt all-stages suite-only informed       (AFL++)
#           perffuzz perffuzz-suite                          (PerfFuzz)
#           slowfuzz slowfuzz-suite                          (SlowFuzz)
# --sink    c14n-exc c14n-inc xplode flattr wreckoncile, or c1 c2 c3 c5 c7
# --hours   run length, fractions allowed
#
# Build the targets first with scripts/build-engines.sh. Output goes to
# out-<sink>-<config>/ under OUT_BASE, which defaults to /artifact/runs inside the
# container and to the artifact directory otherwise. Score it with score.sh
# --run-dir; this script prints the exact command when it finishes.
#
# The runs search for cost, not crashes, so AFL's crash-handling checks are
# waived instead of requiring core_pattern to be changed as root.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build"; EBIN="$BUILD/engines"
SINK=""; HOURS=24; CONFIG=suite-only
while [ $# -gt 0 ]; do
  case "$1" in
    --sink)   SINK="${2:?}"; shift 2 ;;
    --config) CONFIG="${2:?}"; shift 2 ;;
    --hours)  HOURS="${2:?}"; shift 2 ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
# Accept the vector names the paper uses, as well as the internal sink codes.
case "$SINK" in
  c14n-exc|C14N1D3-exc) SINK=c1 ;;
  c14n-inc|C14N1D3-inc) SINK=c2 ;;
  xplode|XPlode)        SINK=c3 ;;
  flattr|FlAttr)        SINK=c5 ;;
  wreckoncile|Wreckoncile) SINK=c7 ;;
esac
case "$SINK" in c1|c2|c3|c5|c7) ;;
  *) echo "--sink must be one of: c14n-exc c14n-inc xplode flattr wreckoncile" >&2
     echo "                   (or the internal codes c1 c2 c3 c5 c7)" >&2; exit 2 ;;
esac

# 1=parse only  2=exclusive C14N  3=inclusive C14N  4=XPath  5=cross-doc reconcile
declare -A OP=( [c1]=2 [c2]=3 [c3]=4 [c5]=1 [c7]=5 )
# the informed configuration drives a different operator at each sink
declare -A CEIL=( [c1]=mut_c1_fresh_ns_prop [c2]=mut_c2_two_axis_prop \
                  [c3]=mut_c3_sibling_axis  [c5]=mut_c5_fresh_attr_prop \
                  [c7]=mut_c7_deepen )

# The per-sink seed corpora the campaign used; see seeds/README.md.
SEEDS="$ROOT/seeds/${SINK}_b"
# The campaign's AFL settings. Trimming is off because it shrinks inputs, which
# works against a cost objective; timed-out inputs are kept; a hang is filed only
# after 10 s.
export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_NO_UI=1
export AFL_DISABLE_TRIM=1 AFL_KEEP_TIMEOUTS=1 AFL_HANG_TMOUT=10000

# AFL++ takes two dictionaries, as in the campaign: libxml2_auto.dict, extracted
# from libxml2's sources by AFL_LLVM_DICT2FILE, and the google/fuzzing XML list.
# PerfFuzz and SlowFuzz accept only one, so they get perffuzz_merged.dict, the
# union of the two (169 tokens).
DICTS=""
for d in libxml2_auto xml_google; do
  [ -s "$ROOT/dict/$d.dict" ] && DICTS="$DICTS -x $ROOT/dict/$d.dict"
done
# Inside the container, default to /artifact/runs, the directory the README
# mounts, so the run survives `docker run --rm`.
if [ -z "${OUT_BASE:-}" ] && [ -f /.dockerenv ] && [ -w /artifact/runs ]; then
  OUT_BASE=/artifact/runs
fi
OUT="${OUT_BASE:-$ROOT}/out-$SINK-$CONFIG"
OUTPARENT="$(dirname "$OUT")"
# Check writability up front; afl-fuzz would otherwise fail later with a generic
# "Permission denied" that does not name the cause.
if ! mkdir -p "$OUTPARENT" 2>/dev/null || [ ! -w "$OUTPARENT" ]; then
  echo "cannot write run output to $OUTPARENT" >&2
  if [ -d "$OUTPARENT" ]; then
    echo "  It exists but is owned by $(stat -c '%U:%G (uid %u)' "$OUTPARENT" 2>/dev/null)," >&2
    echo "  and this process runs as uid $(id -u)." >&2
    if [ -f /.dockerenv ]; then
      echo "  Docker creates a missing bind-mount source as root, so with --user the" >&2
      echo "  mount is unwritable. Either create it first on the host:" >&2
      echo "    mkdir -p runs    # before docker run" >&2
      echo "  or drop --user and let the container run as root (the default); the run" >&2
      echo "  output is made world-readable when it finishes." >&2
    fi
  else
    echo "  It does not exist and could not be created." >&2
  fi
  exit 1
fi
rm -rf "$OUT"
SECS=$(awk -v h="$HOURS" 'BEGIN{printf "%d", h*3600}')
[ "$SECS" -gt 0 ] 2>/dev/null || { echo "--hours must be a positive number" >&2; exit 2; }

run_aflpp() {   # <mutator.so or ""> <only:0|1> <extra afl args...>
  local mut="$1" only="$2"; shift 2
  local AFL="${AFL_PATH:-}"
  [ -x "$AFL/afl-fuzz" ] || AFL="$(dirname "$(command -v afl-fuzz 2>/dev/null || echo /nonexistent)")"
  [ -x "$AFL/afl-fuzz" ] || { echo "afl-fuzz not found; set AFL_PATH" >&2; exit 1; }
  local SRC; SRC=$(ls -d "$BUILD"/libxml2-*-afl 2>/dev/null | head -1)
  [ -n "$SRC" ] || { echo "no instrumented libxml2; run scripts/build.sh --instrumented" >&2; exit 1; }
  local BIN="$EBIN/fuzz_$SINK"
  [ -x "$BIN" ] || { echo "run scripts/build-engines.sh aflpp" >&2; exit 1; }
  env ${mut:+AFL_CUSTOM_MUTATOR_LIBRARY="$mut"} $([ "$only" = 1 ] && echo AFL_CUSTOM_MUTATOR_ONLY=1) \
    "$AFL/afl-fuzz" -i "$SEEDS" -o "$OUT" $DICTS -t 20000+ -V "$SECS" \
      "$@" -- "$BIN" @@
}

so() {  # a mutator built by scripts/build-engines.sh aflpp
  local out="$EBIN/$1.so"
  [ -f "$out" ] || { echo "run scripts/build-engines.sh aflpp" >&2; exit 1; }
  echo "$out"
}

case "$CONFIG" in
  stock)       run_aflpp "" 0 ;;
  all-stages)  run_aflpp "$(so mut_xml_suite)" 0 ;;
  suite-only)  run_aflpp "$(so mut_xml_suite)" 1 ;;
  mopt)        run_aflpp "" 0 -L ;;
  informed)    run_aflpp "$(so "${CEIL[$SINK]}")" 1 ;;

  perffuzz|perffuzz-suite)
    PF="${PERFFUZZ_SRC:-$BUILD/perffuzz}/afl-fuzz"
    [ -x "$PF" ] || { echo "run scripts/build-engines.sh perffuzz" >&2; exit 1; }
    [ -x "$EBIN/perf_$SINK" ] || { echo "missing $EBIN/perf_$SINK" >&2; exit 1; }
    MUT=""
    if [ "$CONFIG" = perffuzz-suite ]; then
      MUT="$EBIN/post_xml_suite.so"
      # the c3 harness reads "expression \n document"
      [ "$SINK" = c3 ] && MUT="$EBIN/post_xml_suite_split.so"
    fi
    # -p makes afl-fuzz search on the per-edge performance counters. Pass it only if
    # the target has them: the default afl-gcc build does not, and -p would then read
    # an all-zero map.
    NP=$(nm "$EBIN/perf_$SINK" 2>/dev/null | grep -c __afl_perf_ptr || true)
    PFLAG=""
    if [ "${NP:-0}" -gt 0 ]; then
      PFLAG="-p"
      echo "target carries perf counters -> passing -p"
    else
      echo "afl-gcc target, no perf counters -> omitting -p (searches on edge coverage)"
    fi
    # AFL 2.52b has no -V, so the run length is enforced with timeout, as in the
    # campaign. It exits 124 when the time is up, which is the normal end here.
    env ${MUT:+AFL_POST_LIBRARY="$MUT"} \
      timeout -s INT "$SECS" "$PF" -i "$SEEDS" -o "$OUT" -m none -t 20000 \
        -x "$ROOT/dict/perffuzz_merged.dict" $PFLAG \
        -- "$EBIN/perf_$SINK" @@ || [ $? -eq 124 ]
    ;;

  slowfuzz|slowfuzz-suite)
    TGT="$EBIN/slow_$SINK"; [ "$CONFIG" = slowfuzz-suite ] && TGT="$EBIN/slowcm_$SINK"
    [ -x "$TGT" ] || { echo "run scripts/build-engines.sh slowfuzz" >&2; exit 1; }
    mkdir -p "$OUT/default/queue"
    # SlowFuzz is a libFuzzer fork: it takes a corpus directory, not -i/-o, and
    # names saved units by content hash, so no per-entry timestamp exists.
    cp -r "$SEEDS"/. "$OUT/default/queue/" 2>/dev/null || true
    # libFuzzer exits with code 77 when one unit runs past its default -timeout of
    # 1200 s, and its -max_total_time follows the wall clock, which jumps after a
    # suspend. As in the campaign, restart it with the budget left on /proc/uptime;
    # it reloads the corpus directory, so the search resumes where it stopped.
    up() { awk '{printf "%d", $1}' /proc/uptime; }
    trap 'exit 130' INT
    start=$(up); rem=$SECS; attempt=0
    while :; do
      attempt=$((attempt+1)); t0=$(up); rc=0
      ( cd "$OUT/default/queue" && "$TGT" -max_total_time="$rem" -max_len=1048576 \
          -rss_limit_mb=0 -print_final_stats=1 -artifact_prefix="$OUT/" \
          -dict="$ROOT/dict/perffuzz_merged.dict" . ) || rc=$?
      ran=$(( $(up) - t0 ))
      [ "$rc" = 0 ] && [ "$ran" -ge $(( rem * 9 / 10 )) ] && break
      rem=$(( SECS - ($(up) - start) ))
      [ "$rem" -gt 60 ] || break
      echo "SlowFuzz attempt $attempt exited with $rc after ${ran}s; restarting with ${rem}s left"
    done
    ;;
  *) echo "unknown --config: $CONFIG (see --help)" >&2; exit 2 ;;
esac

echo
# AFL++ writes out/default/queue; PerfFuzz (AFL 2.52b) writes out/queue; the
# slowfuzz branch above creates out/default/queue.
case "$CONFIG" in
  perffuzz|perffuzz-suite) QDIR="$OUT/queue" ;;
  *)                                    QDIR="$OUT/default/queue" ;;
esac
# Output written as root is mode 0700; make it readable from the host.
if [ "$(id -u)" = 0 ] && [ -d "$OUT" ]; then
  chmod -R a+rX "$OUT" 2>/dev/null || true
fi

echo "score it with:"
echo "  scripts/score.sh --run-dir $QDIR --sink $SINK --bar 5"
