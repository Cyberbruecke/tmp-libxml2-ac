#!/usr/bin/env bash
# Build the Tier 2 fuzzing targets. Each engine instruments libxml2 with its own
# compiler, so the three cannot share a build.
#
#   scripts/build-engines.sh aflpp
#   scripts/build-engines.sh perffuzz
#   scripts/build-engines.sh slowfuzz
#   scripts/build-engines.sh all
#
# All three compile src/harness/cputime_afl.c and select the sink with -DSINK_OP;
# a per-engine define changes only how the cost is reported and, for SlowFuzz,
# the entry point.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build"; BIN="$BUILD/engines"; LIB="$BUILD/engine-lib"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"
CLANG="${CLANG:-$(command -v clang || ls /usr/bin/clang-[0-9]* 2>/dev/null | sort -V | tail -1)}"
mkdir -p "$BIN" "$LIB"

# 1=parse only  2=exclusive C14N  3=inclusive C14N  4=XPath  5=cross-doc reconcile
declare -A OP=( [c1]=2 [c2]=3 [c3]=4 [c5]=1 [c7]=5 )

# A libxml2 checkout to copy from. build.sh --instrumented leaves only the
# -afl tree, and the sources there are the same patched checkout; each engine
# runs `make distclean` before configuring with its own compiler anyway.
PRISTINE=$(ls -d "$BUILD"/libxml2-* 2>/dev/null | grep -v -- '-perffuzz$\|-slowfuzz$' | head -1)
[ -n "$PRISTINE" ] || { echo "run scripts/build.sh first (need a libxml2 checkout)" >&2; exit 1; }

build_aflpp() {
  local AFL="${AFL_PATH:-}" XML
  [ -x "$AFL/afl-clang-fast" ] || AFL="$(dirname "$(command -v afl-clang-fast 2>/dev/null || echo /nonexistent)")"
  [ -x "$AFL/afl-clang-fast" ] || { echo "afl-clang-fast not found; set AFL_PATH" >&2; exit 1; }
  XML=$(ls -d "$BUILD"/libxml2-*-afl 2>/dev/null | head -1)
  [ -n "$XML" ] || { echo "run scripts/build.sh --instrumented first" >&2; exit 1; }

  for s in c1 c2 c3 c5 c7; do
    AFL_QUIET=1 "$AFL/afl-clang-fast" -O2 -DIJON_BUILD -DSINK_OP="${OP[$s]}" \
      -I "$XML/include" -I "$XML" "$ROOT/src/harness/cputime_afl.c" \
      "$XML/.libs/libxml2.a" -lm -lpthread -o "$BIN/fuzz_$s"
  done
  # the generic suite, plus the per-sink operators the informed configuration uses
  for m in mut_xml_suite mut_c1_fresh_ns_prop mut_c2_two_axis_prop \
           mut_c3_sibling_axis mut_c5_fresh_attr_prop mut_c7_deepen; do
    cc -O2 -shared -fPIC "$ROOT/src/mutator/$m.c" -o "$BIN/$m.so"
  done
  echo "  -> fuzz_c{1,2,3,5,7}, mut_xml_suite.so + 5 per-sink operators"
}

build_perffuzz() {
  local SRC="${PERFFUZZ_SRC:-$BUILD/perffuzz}" XML="$BUILD/libxml2-perffuzz"
  if [ ! -d "$SRC" ]; then
    git clone --quiet https://github.com/carolemieux/perffuzz "$SRC"
    ( cd "$SRC" && git checkout --quiet "${PERFFUZZ_REV:-f937f37}" )
  fi
  echo "  perffuzz: $SRC @ $(cd "$SRC" && git rev-parse --short HEAD)"
  # Serial make: PerfFuzz is an AFL 2.52b fork whose Makefile races under -j.
  ( cd "$SRC" && make >/dev/null )

  # Default: afl-gcc, as the campaign built this target. afl-gcc instruments the
  # assembly with the trampoline in afl-as.h, which updates only AFL's coverage map;
  # PerfFuzz's per-edge performance counters come from its llvm_mode pass. This
  # build is therefore searched on coverage, and fuzz.sh omits -p for it.
  #
  # PERFFUZZ_LLVM=1 builds llvm_mode instead. It needs LLVM 10-13: the pass uses
  # CreateLoad(Value*), removed in 14, and PassManagerBuilder.h, removed in 17.
  local CC_PF="$SRC/afl-gcc" LEGACY="" MODE="afl-gcc assembly (coverage only; the paper's build)"
  if [ "${PERFFUZZ_LLVM:-0}" = 1 ]; then
    local LC CL CXX LDIR LV
    LC="${LLVM_CONFIG:-$(ls /opt/llvm-13/bin/llvm-config /usr/bin/llvm-config-1[0-3] 2>/dev/null | head -1)}"
    [ -n "$LC" ] || LC="$(command -v llvm-config || true)"
    [ -x "$LC" ] || { echo "PERFFUZZ_LLVM=1 needs llvm-config from LLVM 10-13 (set LLVM_CONFIG)" >&2; exit 1; }
    # Use the clang next to llvm-config. In an unpacked release the binary has no
    # version suffix, so looking it up on PATH can find a newer clang that cannot
    # load the pass.
    LDIR="$(dirname "$LC")"
    CL="${CLANG_PF:-$LDIR/clang}"; CXX="${CLANGXX_PF:-$LDIR/clang++}"
    [ -x "$CL" ] || CL="$(command -v clang || true)"
    [ -x "$CXX" ] || CXX="$(command -v clang++ || true)"
    LV="$("$LC" --version 2>/dev/null | cut -d. -f1)"
    case "${LV:-0}" in ''|*[!0-9]*) LV=0 ;; esac
    [ "$LV" -ge 10 ] && [ "$LV" -le 13 ] || {
      echo "PERFFUZZ_LLVM=1 needs LLVM 10-13, found ${LV:-unknown} at $LC" >&2; exit 1; }
    # Build named targets rather than `all`, whose self-test compiles without the
    # legacy pass manager flag and fails. The pass is its own target
    # (llvm_mode/Makefile:82), and afl-clang-fast preloads the dlclose shim
    # (afl-clang-fast.c:352).
    ( cd "$SRC" && LLVM_CONFIG="$LC" CC="$CL" CXX="$CXX" \
        make -C llvm_mode ../afl-clang-fast ../afl-llvm-pass.so ../afl-llvm-rt.o \
                          ../afl-catch-dlclose.so >/dev/null )
    [ -f "$SRC/afl-llvm-pass.so" ] || { echo "llvm_mode produced no pass" >&2; exit 1; }
    CC_PF="$SRC/afl-clang-fast"
    export AFL_CC="$CL" AFL_CXX="$CXX"
    # Clang 13 uses the new pass manager by default, but the pass registers through
    # RegisterStandardPasses, which only the legacy manager runs. Without this flag
    # the build succeeds and the pass is silently skipped.
    LEGACY="-flegacy-pass-manager"
    MODE="llvm_mode via LLVM $LV (per-edge perf counters)"
  fi
  # afl-gcc finds afl-as through AFL_PATH.
  export AFL_PATH="$SRC"
  echo "  instrumentation: $MODE"

  [ -d "$XML" ] || cp -a "$PRISTINE" "$XML"
  ( cd "$XML" && make distclean >/dev/null 2>&1 || true
    CC="$CC_PF" CFLAGS="-O2 $LEGACY" ./configure --without-python --without-zlib \
       --without-iconv --without-icu --disable-shared >/dev/null
    make -j"$JOBS" >/dev/null )

  for s in c1 c2 c3 c5 c7; do
    AFL_QUIET=1 "$CC_PF" -O2 $LEGACY -DPERFFUZZ_BUILD -DSINK_OP="${OP[$s]}" \
      -I "$XML/include" -I "$XML" "$ROOT/src/harness/cputime_afl.c" \
      "$XML/.libs/libxml2.a" -lm -lpthread -o "$BIN/perf_$s"
  done
  # Check a tuple count rather than a symbol: __afl_perf_ptr comes from the runtime
  # object and is present even when the pass did not run.
  local HAVE NT SEED1
  HAVE=$(nm "$BIN/perf_c1" 2>/dev/null | grep -c "__afl_perf_ptr" || true)
  SEED1=$(find "$ROOT/seeds/c1_b" -maxdepth 1 -type f -print -quit 2>/dev/null)
  [ -n "$SEED1" ] || SEED1=$(find "$ROOT/seeds" -type f -print -quit 2>/dev/null)
  NT=0
  if [ -n "$SEED1" ] && [ -x "$SRC/afl-showmap" ]; then
    NT=$(AFL_QUIET=1 "$SRC/afl-showmap" -m none -q -o /dev/stdout -- \
           "$BIN/perf_c1" "$SEED1" 2>/dev/null | wc -l)
  fi
  [ "${NT:-0}" -ge 100 ] || { echo "perf_c1 reports only ${NT} tuples; instrumentation did not take" >&2; exit 1; }
  if [ "${PERFFUZZ_LLVM:-0}" = 1 ]; then
    [ "${HAVE:-0}" -gt 0 ] || { echo "llvm_mode requested but perf_c1 has no __afl_perf_ptr" >&2; exit 1; }
    echo "  verified: perf counters present, $NT tuples"
  else
    [ "${HAVE:-0}" -eq 0 ] || echo "  warning: afl-gcc build unexpectedly carries __afl_perf_ptr" >&2
    echo "  verified: $NT tuples (coverage only, no perf counters)"
  fi

  # Arm "PerfFuzz + suite": the same operator suite through the AFL_POST_LIBRARY ABI.
  cc -O2 -shared -fPIC -DPOST_BUILD "$ROOT/src/mutator/mut_xml_suite.c" \
     -o "$BIN/post_xml_suite.so"
  cc -O2 -shared -fPIC -DPOST_BUILD -DSUITE_SPLIT_LINE1 \
     "$ROOT/src/mutator/mut_xml_suite.c" -o "$BIN/post_xml_suite_split.so"
  echo "  -> perf_c{1,2,3,5,7}, post_xml_suite[_split].so"
}

build_slowfuzz() {
  local SRC="${SLOWFUZZ_SRC:-$BUILD/slowfuzz}" CM="$BUILD/slowfuzz-cm" XML="$BUILD/libxml2-slowfuzz"
  # trace-pc-guard drives SlowFuzz's objective; inline-8bit-counters backs the
  # legacy counter ABI. No trace-cmp: clang emits const-cmp hooks the 2017
  # libFuzzer fork does not define.
  local COV='-fsanitize-coverage=trace-pc-guard,inline-8bit-counters'
  # The authors' repository, pinned to the revision the campaign used.
  if [ ! -d "$SRC" ]; then
    git clone --quiet https://github.com/nettrino/slowfuzz "$SRC"
    ( cd "$SRC" && git checkout --quiet "${SLOWFUZZ_REV:-e124345}" )
  fi
  SFREV=$(cd "$SRC" && git rev-parse --short HEAD)
  echo "  slowfuzz: $SRC @ $SFREV"
  DIRTY=$(cd "$SRC" && git status --porcelain -- '*.cpp' '*.h' '*.def' | wc -l)
  [ "$DIRTY" -eq 0 ] || echo "  warning: $DIRTY SlowFuzz source files modified; it should be stock" >&2
  [ -d "$SRC/Fuzzer" ] || { echo "no Fuzzer/ in $SRC" >&2; exit 1; }

  build_lib() {  # <fuzzer-dir> <out.a>
    local FD="$1" OUT="$2" TMP; TMP=$(mktemp -d)
    ( cd "$TMP"
      for f in "$FD"/*.cpp; do
        "$CLANG" -c -g -O2 -std=c++11 -w -mpopcnt -fno-omit-frame-pointer -I"$FD" \
          "$f" -o "$(basename "$f" .cpp).o"
      done
      ar rcs "$OUT" ./*.o )
    rm -rf "$TMP"
  }
  build_lib "$SRC/Fuzzer" "$LIB/libSlowFuzz.a"

  # SlowFuzz ships with its custom-mutator hook disabled; enable it for the suite
  # configuration. The diff is in patches/slowfuzz-custom-mutator.patch.
  rm -rf "$CM"; mkdir -p "$CM"; cp -a "$SRC/Fuzzer" "$CM/Fuzzer"
  python3 "$ROOT/scripts/patch_slowfuzz_cm.py" \
      "$CM/Fuzzer/FuzzerMutate.cpp" "$CM/Fuzzer/FuzzerMutate.h"
  build_lib "$CM/Fuzzer" "$LIB/libSlowFuzzCM.a"

  "$CLANG" -c -O2 -Wall "$ROOT/src/harness/slowfuzz_sancov_shim.c" -o "$LIB/sancov_shim.o"
  "$CLANG" -c -O2 -DLIBFUZZER_BUILD "$ROOT/src/mutator/mut_xml_suite.c" -o "$LIB/lf_suite.o"
  "$CLANG" -c -O2 -DLIBFUZZER_BUILD -DSUITE_SPLIT_LINE1 \
      "$ROOT/src/mutator/mut_xml_suite.c" -o "$LIB/lf_suite_split.o"

  [ -d "$XML" ] || cp -a "$PRISTINE" "$XML"
  ( cd "$XML" && make distclean >/dev/null 2>&1 || true
    CC="$CLANG" CFLAGS="-O2 -g $COV" ./configure --without-python --without-zlib \
       --without-iconv --without-icu --disable-shared >/dev/null
    make -j"$JOBS" >/dev/null )

  for s in c1 c2 c3 c5 c7; do
    "$CLANG" -O2 -g $COV -DSLOWFUZZ_BUILD -DSINK_OP="${OP[$s]}" \
      -I "$XML/include" -I "$XML" "$ROOT/src/harness/cputime_afl.c" \
      "$XML/.libs/libxml2.a" "$LIB/libSlowFuzz.a" "$LIB/sancov_shim.o" \
      -lstdc++ -lpthread -lm -o "$BIN/slow_$s"
    # The c3 harness reads "expression \n document", so it needs the split suite.
    local SUITE="$LIB/lf_suite.o"; [ "$s" = c3 ] && SUITE="$LIB/lf_suite_split.o"
    "$CLANG" -O2 -g $COV -DSLOWFUZZ_BUILD -DSINK_OP="${OP[$s]}" \
      -I "$XML/include" -I "$XML" "$ROOT/src/harness/cputime_afl.c" "$SUITE" \
      "$XML/.libs/libxml2.a" "$LIB/libSlowFuzzCM.a" "$LIB/sancov_shim.o" \
      -lstdc++ -lpthread -lm -o "$BIN/slowcm_$s"
  done
  echo "  -> slow_c{1,2,3,5,7} (stock), slowcm_c{1,2,3,5,7} (+ suite)"
}

case "${1:-all}" in
  aflpp)    echo "== AFL++ =="; build_aflpp ;;
  perffuzz) echo "== PerfFuzz =="; build_perffuzz ;;
  slowfuzz) echo "== SlowFuzz =="; build_slowfuzz ;;
  all)      echo "== AFL++ =="; build_aflpp
            echo "== PerfFuzz =="; build_perffuzz
            echo "== SlowFuzz =="; build_slowfuzz ;;
  *) echo "usage: $0 [aflpp|perffuzz|slowfuzz|all]" >&2; exit 2 ;;
esac
echo; echo "targets in build/engines/"
