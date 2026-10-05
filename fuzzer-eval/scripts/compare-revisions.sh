#!/usr/bin/env bash
# Show that the sinks behave identically across libxml2 revisions.
#
#   scripts/compare-revisions.sh v2.15.0 c6324894 latest
#
# Builds each revision if needed, then replays one champion per sink through
# all of them and compares the operation counters. The counters are exact and
# hardware-independent, so any real change in the sink shows up here.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REVS=("${@:-v2.15.0 c6324894 latest}")
[ $# -gt 0 ] && REVS=("$@") || REVS=(v2.15.0 c6324894 latest)

declare -a BINS DESCS
for r in "${REVS[@]}"; do
  bash "$ROOT/scripts/build.sh" --commit "$r" >/dev/null
  b=$(readlink -f "$ROOT/build/bin-current")
  BINS+=("$b"); DESCS+=("$(cut -f2 "$b/REVISION")")
done

printf '%-6s %-30s' sink input
for d in "${DESCS[@]}"; do printf ' %-22s' "$d"; done; printf ' verdict\n'

status=0
for pair in c1:a9_aflpp_c1_r2_ops c2:a9_aflpp_c2_r2_cpu c3:a2_aflpp_c3_r2_cpu \
            c5:a9_aflpp_c5_r1_ops c7:a9_aflpp_c7_r2_cpu; do
  s="${pair%%:*}"; f="${pair##*:}"
  printf '%-6s %-30s' "$s" "$f"
  first=""; same=1
  for b in "${BINS[@]}"; do
    v=$("$b/measure_$s" "$ROOT/data/champions/$f.xml" 2>/dev/null | awk '{print $1}')
    printf ' %-22s' "${v:-ERR}"
    [ -z "$first" ] && first="$v" || { [ "$v" = "$first" ] || same=0; }
  done
  if [ "$same" = 1 ]; then printf ' identical\n'; else printf ' DIFFERS\n'; status=1; fi
done
exit $status
