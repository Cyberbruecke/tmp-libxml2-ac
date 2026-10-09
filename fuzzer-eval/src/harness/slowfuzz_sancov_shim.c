/* slowfuzz_sancov_shim.c: supply the legacy sanitizer-coverage symbols SlowFuzz needs.
 *
 * SlowFuzz is a fork of the 2017 libFuzzer and resolves six symbols from
 * compiler-rt's legacy sanitizer-coverage runtime, which LLVM has since removed;
 * clang 5.0.2, 10, 14 and 18 all lack them. Two are checked at start-up
 * (Fuzzer/FuzzerLoop.cpp:62 and :235), so without this file SlowFuzz exits with
 * "__sanitizer_reset_coverage is not defined" before its first execution.
 *
 * SlowFuzz's sources and fitness function are unchanged. Its objective does not use
 * these symbols: RunOne (FuzzerLoop.cpp:512) counts edges between TPC.ResetEdges()
 * and TPC.GetEdges() and marks a slow unit when the count exceeds
 * MaxCoverage.TotalEdges (FuzzerLoop.cpp:539). TotalEdges is incremented on every
 * __sanitizer_cov_trace_pc_guard callback (FuzzerTracePC.cpp:43), which clang 18
 * still provides. The legacy symbols are called only from ResetCoverage,
 * ResetCounters and PrepareCounters, and the objective discards their results.
 *
 * They are implemented with their original behaviour rather than stubbed, so that
 * SlowFuzz runs with its default flags (-use_counters=1, FuzzerFlags.def:45).
 * -fsanitize-coverage=inline-8bit-counters provides the per-edge u8 counters the
 * old runtime kept, and the bucket thresholds below follow compiler-rt's
 * CoverageData::Update8bitCounterBitsetAndClearCounters (1, 2, 3, 4-7, 8-15, 16-31,
 * 32-127, 128+).
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

static uint8_t *cnt_start, *cnt_stop;   /* the inline-8bit-counters section */
static uint8_t *ever_seen;              /* counter index -> was ever non-zero */
static size_t   ncounters;
static uint64_t unique_seen;

/* clang calls this once per instrumented module, before main. */
void __sanitizer_cov_8bit_counters_init(uint8_t *start, uint8_t *stop) {
  cnt_start = start;
  cnt_stop  = stop;
  ncounters = (size_t)(stop - start);
  /* One byte per counter, kept for the life of the process. */
  static uint8_t seen_storage_present;
  if (!seen_storage_present && ncounters) {
    extern void *calloc(size_t, size_t);
    ever_seen = (uint8_t *)calloc(ncounters, 1);
    seen_storage_present = 1;
  }
}

size_t __sanitizer_get_number_of_counters(void) { return ncounters; }

void __sanitizer_reset_coverage(void) {
  if (cnt_start) memset(cnt_start, 0, ncounters);
  if (ever_seen) memset(ever_seen, 0, ncounters);
  unique_seen = 0;
}

size_t __sanitizer_get_total_unique_coverage(void) { return (size_t)unique_seen; }

/* bitset == NULL means "just clear the counters" (SlowFuzz's ResetCounters path). */
uintptr_t __sanitizer_update_counter_bitset_and_clear_counters(uint8_t *bitset) {
  if (!cnt_start) return 0;
  if (!bitset) { memset(cnt_start, 0, ncounters); return 0; }

  uintptr_t num_new_bits = 0;
  for (size_t i = 0; i < ncounters; i++) {
    uint8_t counter = cnt_start[i];
    if (!counter) continue;
    cnt_start[i] = 0;
    if (ever_seen && !ever_seen[i]) { ever_seen[i] = 1; unique_seen++; }

    int bit;
    if      (counter >= 128) bit = 7;
    else if (counter >=  32) bit = 6;
    else if (counter >=  16) bit = 5;
    else if (counter >=   8) bit = 4;
    else if (counter >=   4) bit = 3;
    else if (counter >=   3) bit = 2;
    else if (counter >=   2) bit = 1;
    else                     bit = 0;

    uint8_t mask = (uint8_t)(1u << bit);
    if (!(bitset[i] & mask)) { bitset[i] |= mask; num_new_bits++; }
  }
  return num_new_bits;
}

/* __sanitizer_set_death_callback and __sanitizer_print_stack_trace are not defined
 * here: libclang_rt.ubsan_standalone, which a -fsanitize-coverage link pulls in,
 * already exports both (sanitizer_termination.cpp, ubsan_diag_standalone.cpp), and
 * defining them again fails to link. So of the two symbols SlowFuzz checks,
 * set_death_callback comes from that runtime and reset_coverage from this file. */
