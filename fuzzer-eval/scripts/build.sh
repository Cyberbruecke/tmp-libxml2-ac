#!/usr/bin/env bash
# Build the measurement harnesses used to score fuzzer-produced inputs.
#
#   scripts/build.sh                     the revision the paper reports (default)
#   scripts/build.sh --commit latest     current upstream master
#   scripts/build.sh --commit v2.15.0    a tag
#   scripts/build.sh --commit c6324894   any commit
#   scripts/build.sh --instrumented      match the paper's CPU measurements
#
# The paper's CPU figures were taken on an AFL-instrumented libxml2, which costs
# 1.0x to 4.1x more than a clean build for identical work. --instrumented
# reproduces that; without it the operation counts still match exactly but CPU
# times are lower. Needs AFL++ (set AFL_PATH or put afl-clang-fast on PATH).
#
# Each revision builds into its own directory, so several can coexist and be
# compared. Nothing here builds or runs a fuzzer: Tier 1 only replays inputs we
# have already saved.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"
LIBXML2_REPO="${LIBXML2_REPO:-https://gitlab.gnome.org/GNOME/libxml2.git}"

# The revision the paper's measurements were taken on. `git describe` renders it
# v2.15.0-124-gc6324894: 124 commits past the v2.15.0 tag. The tree's own
# VERSION file reads 2.16.0 there, so pin by commit, not by version string.
DEFAULT_COMMIT="c63248941708bc1d2e3a4292954593312212f6ca"

WANT="$DEFAULT_COMMIT"
INSTR=0
while [ $# -gt 0 ]; do
  case "$1" in
    --commit) WANT="${2:?--commit needs a value}"; shift 2 ;;
    --instrumented) INSTR=1; shift ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

MIRROR="$BUILD/libxml2.git"
mkdir -p "$BUILD"

if [ ! -d "$MIRROR" ]; then
  echo "== fetching libxml2 =="
  git clone --quiet --bare "$LIBXML2_REPO" "$MIRROR"
elif [ "$WANT" = "latest" ]; then
  echo "== updating mirror =="
  git --git-dir="$MIRROR" fetch --quiet origin \
      '+refs/heads/*:refs/heads/*' '+refs/tags/*:refs/tags/*'
fi

if [ "$WANT" = "latest" ]; then
  REV=$(git --git-dir="$MIRROR" rev-parse HEAD)
else
  REV=$(git --git-dir="$MIRROR" rev-parse "$WANT^{commit}" 2>/dev/null) || {
    echo "cannot resolve '$WANT' in the libxml2 history." >&2
    echo "Try --commit latest to fetch newer revisions." >&2; exit 1; }
fi

SHORT=$(git --git-dir="$MIRROR" rev-parse --short=8 "$REV")
SUFFIX=""
if [ "$INSTR" = 1 ]; then
  CC_AFL="${AFL_PATH:-}/afl-clang-fast"
  [ -x "$CC_AFL" ] || CC_AFL="$(command -v afl-clang-fast || true)"
  [ -x "$CC_AFL" ] || { echo "--instrumented needs afl-clang-fast; set AFL_PATH" >&2; exit 1; }
  export CC="$CC_AFL" AFL_QUIET=1
  SUFFIX="-afl"
fi
SRC="$BUILD/libxml2-$SHORT$SUFFIX"
BIN="$BUILD/bin-$SHORT$SUFFIX"
DESC=$(git --git-dir="$MIRROR" describe --tags "$REV" 2>/dev/null || echo "$SHORT")

echo "== libxml2 $DESC ($REV) =="
mkdir -p "$BIN"

[ -d "$SRC" ] || git clone --quiet --no-checkout --shared "$MIRROR" "$SRC"
cd "$SRC"
git checkout --quiet --force "$REV"
git checkout --quiet -- .

echo "== applying sink iteration counters =="
# Hunk offsets shift between revisions, so allow fuzz. The counters are plain
# globals incremented in the hot loops; they change no algorithm.
if ! patch -p1 -l -F3 --no-backup-if-mismatch --silent \
       < "$ROOT/patches/libxml2-ac-counters.patch"; then
  echo "the counter patch does not apply to $DESC." >&2
  echo "That revision's sink code has diverged; use a nearer commit." >&2; exit 1
fi
for c in xmlC14NScanIters xmlC14NIncScanIters xmlC3AxisIters \
         xmlC5AttrWalkIters xmlC7ReconIters; do
  grep -qr "unsigned long $c" c14n.c tree.c xpath.c \
    || { echo "counter $c missing after patch" >&2; exit 1; }
done

if [ ! -f "$SRC/.libs/libxml2.a" ] || [ "$SRC/c14n.c" -nt "$SRC/.libs/libxml2.a" ]; then
  echo "== configuring and building libxml2 (a few minutes) =="
  # NOCONFIGURE stops autogen.sh running ./configure with its own flags; we need
  # a static, dependency-free build so the harnesses link without zlib.
  [ -f configure ] || NOCONFIGURE=1 ./autogen.sh >/dev/null
  ./configure --without-python --without-debug \
      --without-zlib --without-iconv --without-icu \
      --with-c14n --with-xpath --with-output --enable-static --disable-shared >/dev/null
  make -j"$JOBS" >/dev/null
fi
[ -f "$SRC/.libs/libxml2.a" ] || { echo "libxml2 build produced no static library" >&2; exit 1; }

echo "== building measurement harnesses =="
for s in c1 c2 c3 c5 c7; do
  "${CC:-cc}" -O2 -I "$SRC/include" -I "$SRC" \
     "$ROOT/src/measure/measure_$s.c" "$SRC/.libs/libxml2.a" \
     -o "$BIN/measure_$s" -lm -lpthread
done
printf '%s\t%s\t%s\n' "$REV" "$DESC" \
  "$([ "$INSTR" = 1 ] && echo instrumented || echo clean)" > "$BIN/REVISION"
ln -sfn "bin-$SHORT$SUFFIX" "$BUILD/bin-current"

echo
echo "built $DESC ($([ "$INSTR" = 1 ] && echo instrumented || echo clean)) -> build/bin-$SHORT$SUFFIX"
echo "Next:  scripts/score.sh --ops 8e6     reproduce Table 3's operation column"
