#!/usr/bin/env bash
# Tier 2: run one fuzzing arm against one sink.
#
#   scripts/fuzz.sh --sink c2 --config stock        AFL++ byte mutators only
#   scripts/fuzz.sh --sink c2 --config all-stages   suite + AFL++'s own stages
#   scripts/fuzz.sh --sink c2 --config suite-only   suite alone, havoc off
#
# These are the "Stock", "AFL++ all" and "AFL++ only" columns of Table 3. The
# table's other columns are not runnable here: PerfFuzz and SlowFuzz each need
# their own fork and instrumented libxml2 build with the operator suite in a
# different host binding, and "Informed" uses per-sink operators we wrote from
# our own analysis of each sink.
#
# Needs AFL++ (AFL_PATH, or afl-fuzz on PATH) and an instrumented libxml2 from
# scripts/build.sh --instrumented. Score the result with:
#
#   scripts/score.sh --run-dir out-c2/default/queue --sink c2 --bar 5
#
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SINK=""; HOURS=24; CONFIG=suite-only
while [ $# -gt 0 ]; do
  case "$1" in
    --sink)  SINK="${2:?}"; shift 2 ;;
    --hours) HOURS="${2:?}"; shift 2 ;;
    --config) CONFIG="${2:?}"; shift 2 ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
case "$SINK" in c1|c2|c3|c5|c7) ;; *) echo "--sink must be c1 c2 c3 c5 or c7" >&2; exit 2 ;; esac
case "$CONFIG" in stock|all-stages|suite-only) ;;
  *) echo "--config must be stock, all-stages or suite-only" >&2; exit 2 ;; esac

AFL="${AFL_PATH:-}"; [ -x "$AFL/afl-fuzz" ] || AFL="$(dirname "$(command -v afl-fuzz 2>/dev/null || echo /nonexistent)")"
[ -x "$AFL/afl-fuzz" ] || { echo "afl-fuzz not found; set AFL_PATH" >&2; exit 1; }

SRC=$(ls -d "$ROOT"/build/libxml2-*-afl 2>/dev/null | head -1)
[ -n "$SRC" ] || { echo "no instrumented libxml2; run scripts/build.sh --instrumented" >&2; exit 1; }

# Each sink has its own harness; cputime_afl.c selects it with a compile-time flag
# and drives AFL++'s value-maximising waypoint with measured CPU time.
case "$SINK" in
  c1) MODE=2 ;; c2) MODE=3 ;; c3) MODE=4 ;; c5) MODE=1 ;; c7) MODE=5 ;;
esac
BIN="$ROOT/build/fuzz_$SINK"
if [ ! -x "$BIN" ]; then
  echo "== building the $SINK fuzz target =="
  AFL_QUIET=1 "$AFL/afl-clang-fast" -O2 -DSINK_OP=$MODE -DIJON_BUILD \
    -I "$SRC/include" -I "$SRC" \
    "$ROOT/src/harness/cputime_afl.c" "$SRC/.libs/libxml2.a" \
    -o "$BIN" -lm -lpthread
fi

MUT=""
if [ "$CONFIG" != stock ]; then
  MUT="$ROOT/build/mut_xml_suite.so"
  [ -f "$MUT" ] || cc -O2 -shared -fPIC "$ROOT/src/mutator/mut_xml_suite.c" -o "$MUT"
fi
# suite-only runs the operator suite alone; all-stages lets AFL++'s native
# stages (havoc, splice, deterministic) run alongside it.
ONLY=""; [ "$CONFIG" = suite-only ] && ONLY=1

OUT="$ROOT/out-$SINK-$CONFIG"; rm -rf "$OUT"
echo "== fuzzing $SINK for ${HOURS}h ($CONFIG) =="
env ${MUT:+AFL_CUSTOM_MUTATOR_LIBRARY="$MUT"} ${ONLY:+AFL_CUSTOM_MUTATOR_ONLY=1} \
    AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 \
  "$AFL/afl-fuzz" -i "$ROOT/seeds/${SINK}_a" -o "$OUT" \
    -x "$ROOT/dict/xml.dict" -t 20000+ -V $((HOURS*3600)) -- "$BIN" @@

echo
echo "score it with:"
echo "  scripts/score.sh --run-dir $OUT/default/queue --sink $SINK --bar 5"
