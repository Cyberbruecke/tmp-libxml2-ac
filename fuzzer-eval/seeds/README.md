# Seeds — the actual bytes, committed

Phase 3 and Phase 4 seeds lived only in `/tmp` and were lost. Reconstructing them for the
FuzzFactory calibration cost real time, so the bytes now live here and the launch scripts read
them from here. **Do not synthesise seeds into `/tmp` again.**

Two conditions per sink, matching the campaign design:

- **`*_a` — minimal (`<a/>`).** The "from nothing" condition: can the fuzzer invent the cost
  structure with no hint? C1-a and C2-a scored **literally 0** here across 74 M executions each.
- **`*_c` — the attack shape shrunk to N=5.** The decisive condition: the fuzzer is handed the
  correct structure and only has to *scale* it. Every namespace declaration is **referenced** —
  unreferenced declarations are 520× cheaper, because exclusive C14N renders only *utilised*
  namespaces.

## Verification against recorded Phase 3 trajectories

Each `_c` seed was validated by scoring it and comparing to the `t=0` row of
`results/trajectory_*.tsv` — not by assuming the shape was right.

| seed | recorded t=0 | this file scores | |
|---|---|---|---|
| `c2_c` | 190 iters / 108 B | **190 / 108** | ✅ exact |
| `c5_c` | 6 iters / 34 B | **6 / 34** | ✅ exact |
| `c1_c` | 15 iters / 162 B | **15 / 160** | ⚠️ iterations exact, 2 B cosmetic |

On `c1_c`: at least five whitespace variants score 15 iterations at exactly 162 bytes, so the
recorded byte count does **not** uniquely determine the original file. The cost-relevant
structure is pinned by the iteration count; the missing 2 bytes are whitespace and change no
measurement. Recorded rather than papered over.

`c3_c` and `c7_c` have no Phase 3 trajectory (those sinks were first fuzzed in Phase 4), so
they could not be checked against a recording — and that gap bit immediately: the first `c3_c`
committed here used `<c/>` elements and scored **0**, because `measure_c3` evaluates
`//a[count(preceding-sibling::a) > 0]`, which matches elements named `a`. A seed that cannot
reach its own sink is worse than no seed. Fixed to `<a/>`; every seed is now checked to score
non-zero on its own sink:

| seed | scores |
|---|---|
| `c1_c` | 15 iters / 160 B |
| `c2_c` | 190 / 108 |
| `c3_c` | 15 / 27 |
| `c5_c` | 6 / 34 |
| `c7_c` | 10 / 191 |

## Re-verify

```sh
/tmp/claude-1000/measure_c1 seeds/c1_c/seed.xml   # -> 15  160  1
/tmp/claude-1000/measure_c2 seeds/c2_c/seed.xml   # -> 190 108  1
/tmp/claude-1000/measure_c5 seeds/c5_c/seed.xml   # -> 6   34   1
```

Scorers are built by `../README.md`; on an AFL-instrumented libxml2 they must be linked with
`afl-gcc-fast`, not plain `gcc` (the archive references `__afl_area_ptr`).
