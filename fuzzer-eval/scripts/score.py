#!/usr/bin/env python3
"""Re-score the saved champion inputs and rebuild Table 3 of the paper.

Each input is replayed through its sink's measurement harness REPS times and the
median CPU time is kept. A single timing does not reproduce: across scoring passes
the same input varied by up to 4x in both directions, so inputs are re-measured
rather than scored from the fuzzer's own records.

Usage:
    score.py --bar 5            CPU-time criterion, 5 s   (the paper's headline)
    score.py --bar 2            CPU-time criterion, 2 s
    score.py --ops 8e6          operation-count criterion
"""
import argparse, csv, hashlib, json, os, platform, re, statistics, subprocess, resource, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CHAMPS = os.path.join(ROOT, "data", "champions")
MANIFEST = os.path.join(ROOT, "data", "champions.tsv")
BIN = os.environ.get("MEASURE_BIN", os.path.join(ROOT, "build", "bin-current"))

# column layout of Table 3
COLUMNS = [("Stock", ["0", "1", "3", "5"]), ("AFL++ all", ["2"]),
           ("AFL++ only", ["9"]), ("PerfFuzz", ["4"]),
           ("SlowFuzz", ["6"]), ("Informed", ["7"])]
VECTORS = [("c1", "C14N1D3 (excl.)"), ("c2", "C14N1D3 (incl.)"),
           ("c3", "XPlode"), ("c5", "FlAttr"), ("c7", "Wreckoncile")]


def score_run_dir(d, sink, use_ops, bar, ops_bar, reps, timeout,
                  need_sink=False, deep=0):
    """Score a fuzzer output directory: the Tier 2 -> Tier 1 bridge.

    Walks every saved input, re-measures it, and reports the most expensive one
    and when the run first crossed the bar. AFL++ encodes milliseconds since
    start in each queue filename as `time:<ms>`; libFuzzer names units by
    content hash, so no time is recoverable there.
    """
    # Top level only: AFL keeps marker files in queue/.state/, which are not
    # inputs. Names are not filtered, so a libFuzzer corpus (content-hash names)
    # still scores.
    ents = []
    try:
        names = sorted(os.listdir(d))
    except OSError as e:
        sys.exit(f"cannot read {d}: {e}")
    for n in names:
        if n.startswith("."):
            continue
        path = os.path.join(d, n)
        if not os.path.isfile(path):
            continue
        m = re.search(r"time:(\d+)", n)
        ents.append(((int(m.group(1)) if m else None), path))
    if not ents:
        sys.exit(f"no inputs found under {d}")
    timed = [e for e in ents if e[0] is not None]
    ents.sort(key=lambda e: (e[0] is None, e[0]))
    print(f"  {len(ents)} inputs ({len(timed)} carry a timestamp)\n")

    # Track the two costs separately: below the timer's resolution every input
    # reads 0 ms, and ranking by CPU alone would pick an arbitrary input.
    best_ms = (0.0, None)
    best_ops = (0, None)
    first = None
    ncens = nonsink = 0
    for i, (t, path) in enumerate(ents, 1):
        print(f"\r  measuring {i}/{len(ents)} ...", end="", flush=True)
        ms, ops, cens = measure(sink, path, reps, timeout, deep)
        ncens += bool(cens)
        if use_ops:
            cleared = ops >= ops_bar
        else:
            cleared = ms >= bar * 1000.0
            # CPU time does not say where the cost was spent, so optionally
            # require the sink counter to have moved.
            if cleared and ops == 0:
                nonsink += 1
                if need_sink:
                    cleared = False
        if ms > best_ms[0] and not (need_sink and not use_ops and ops == 0):
            best_ms = (ms, path)
        if ops > best_ops[0]:
            best_ops = (ops, path)
        if cleared and first is None and t is not None:
            first = (t / 3600000.0, path)
    print("\r" + " " * 40 + "\r", end="")

    path = (best_ops[1] if use_ops else best_ms[1]) or best_ops[1] or ents[0][1]
    print(f"  best input   : {os.path.relpath(path, d)}")
    print(f"  most CPU     : {best_ms[0]/1000:.2f} s"
          + (f"  ({os.path.basename(best_ms[1])[:40]})" if best_ms[1] else ""))
    print(f"  most sink ops: {best_ops[0]}"
          + (f"  ({os.path.basename(best_ops[1])[:40]})" if best_ops[1] else ""))
    if ncens:
        print(f"  censored     : {ncens} input(s) hit the {timeout}s cap")
    if nonsink:
        print(f"  non-sink cost: {nonsink} input(s) met the CPU bar with 0 sink "
              f"operations" + (" (excluded)" if need_sink else " (counted; "
              "pass --require-sink-ops to exclude)"))
    if first:
        print(f"  first clear: {first[0]:.2f} h of active fuzzing")
    elif not timed:
        print("  first clear: unknown; this engine's file names carry no time")
    else:
        bar_s = f"{ops_bar:.0f} ops" if use_ops else f"{bar:g} s"
        print(f"  first clear: never reached {bar_s} in a timestamped input")
    return 0


def host_id():
    """Identify the machine, since CPU figures are hardware-dependent."""
    model = ""
    try:
        for line in open("/proc/cpuinfo"):
            if line.startswith("model name"):
                model = line.split(":", 1)[1].strip(); break
    except OSError:
        pass
    return f"{model or platform.processor() or 'unknown CPU'}, {os.cpu_count()} cores, {platform.system()}"


def verify(rows):
    """Check each saved input against its recorded digest."""
    bad = missing = ok = 0
    for r in rows:
        if not r["status"].startswith("ok"):
            continue
        path = os.path.join(CHAMPS, r["file"])
        if not os.path.isfile(path):
            print(f"  MISSING  {r['file']}"); missing += 1; continue
        got = hashlib.sha256(open(path, "rb").read()).hexdigest()
        if got != r["sha256"]:
            print(f"  CORRUPT  {r['file']}\n     expected {r['sha256']}\n     got      {got}")
            bad += 1
        else:
            ok += 1
    print(f"\n  {ok} inputs verified, {bad} corrupt, {missing} missing")
    return 0 if (bad == 0 and missing == 0) else 1


def measure(sink, path, reps, timeout, deep=0):
    """Return (median CPU ms, operation count, censored).

    The measurement is censored at `timeout`: deciding a threshold only needs to
    know whether the cost reaches the bar, and the most expensive inputs here
    cost close to a minute each. A censored run reports the cap, which is above
    the bar.

    A censored run prints nothing, so its operation count, which shows whether
    the cost was spent in the sink, is unknown. `deep` re-runs a censored input
    once under a longer cap to recover the count.
    """
    times, ops = [], 0
    for _ in range(reps):
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        t0 = before.ru_utime + before.ru_stime
        try:
            p = subprocess.run([os.path.join(BIN, "measure_" + sink), path],
                               capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            if deep > timeout:
                try:
                    q = subprocess.run(
                        [os.path.join(BIN, "measure_" + sink), path],
                        capture_output=True, timeout=deep)
                    f = q.stdout.decode("utf8", "ignore").split()
                    if f:
                        try: ops = max(ops, int(f[0]))
                        except ValueError: pass
                except (subprocess.TimeoutExpired, OSError):
                    pass
            return timeout * 1000.0, ops, True
        except OSError as e:
            sys.exit(f"cannot run measure_{sink}: {e}\nDid you run scripts/build.sh?")
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        times.append((after.ru_utime + after.ru_stime) - t0)
        out = p.stdout.decode("utf8", "ignore").split()
        if out:
            try: ops = max(ops, int(out[0]))
            except ValueError: pass
    return statistics.median(times) * 1000.0, ops, False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bar", type=float, default=5.0,
                    help="CPU-time criterion in seconds (default 5)")
    ap.add_argument("--ops", type=float, default=None,
                    help="use an operation-count criterion instead, e.g. 8e6")
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--verify", action="store_true",
                    help="check every input against its recorded SHA-256 and exit")
    ap.add_argument("--json", metavar="FILE",
                    help="also write the result as JSON for mechanical diffing")
    ap.add_argument("--run-dir", metavar="DIR",
                    help="score a fuzzer output directory instead of the saved "
                         "inputs (Tier 2); needs --sink")
    ap.add_argument("--sink",
                    help="which vector --run-dir was fuzzed against: "
                         "c14n-exc, c14n-inc, xplode, flattr or wreckoncile")
    ap.add_argument("--require-sink-ops", action="store_true",
                    help="under a CPU criterion, count an input only if the "
                         "sink's operation counter actually moved. Without this "
                         "an input whose cost falls outside the sink still "
                         "clears; see README")
    ap.add_argument("--deep-timeout", type=int, default=1800, metavar="S",
                    help="re-run a censored input once under this cap to "
                         "recover its operation count (default 1800)")
    ap.add_argument("--timeout", type=int, default=None,
                    help="per-measurement cap in seconds "
                         "(default: just above the bar, which is all a "
                         "threshold test needs)")
    a = ap.parse_args()

    rows = list(csv.DictReader(open(MANIFEST), delimiter="\t"))
    if a.verify:
        print(f"verifying {CHAMPS} against the manifest\n")
        sys.exit(verify(rows))
    use_ops = a.ops is not None

    if a.run_dir:
        # the paper's vector names, as well as the internal sink codes
        a.sink = {"c14n-exc": "c1", "c14n-inc": "c2", "xplode": "c3",
                  "flattr": "c5", "wreckoncile": "c7"}.get(
                      (a.sink or "").lower(), a.sink)
        if a.sink not in [v for v, _ in VECTORS]:
            sys.exit("--sink must be c14n-exc, c14n-inc, xplode, flattr or "
                     "wreckoncile (or c1 c2 c3 c5 c7)")
        if not a.sink:
            sys.exit("--run-dir needs --sink (one of c1 c2 c3 c5 c7)")
        if a.timeout is None:
            a.timeout = 180 if use_ops else max(2, int(a.bar * 1.5) + 1)
        print(f"host     : {host_id()}")
        print(f"scoring  : {a.run_dir}  (sink {a.sink})\n")
        sys.exit(score_run_dir(a.run_dir, a.sink, use_ops, a.bar,
                               a.ops or 0, a.reps, a.timeout,
                               a.require_sink_ops, a.deep_timeout))

    if a.require_sink_ops:
        sys.exit("--require-sink-ops applies to --run-dir. A saved input that "
                 "reaches the measurement cap\nprints no operation count, so it "
                 "cannot be checked here without hours of deep re-runs.")

    # Each run saved two inputs: the one that maximised the sink's operation
    # counter and the one that maximised CPU time as the campaign recorded it.
    # They differ in 69 of the 71 runs that recorded both. The operation
    # criterion is scored on the first. A CPU criterion counts the run if either
    # input reaches the bar when re-measured, as Table 3 does: the recorded CPU
    # times were taken under campaign load and do not reliably rank the two.
    order = ["ops"] if use_ops else ["cpu", "ops"]
    runs = {}
    for r in rows:
        if any(r["arm"] in arms for _, arms in COLUMNS):
            runs.setdefault((r["arm"], r["sink"], r["rep"]), {})[r["kind"]] = r
    if a.timeout is None:
        # An operation count needs the run to finish; a time threshold does not.
        a.timeout = 180 if use_ops else max(2, int(a.bar * 1.5) + 1)
    label = (f"operation count >= {a.ops:.0f}" if use_ops
             else f"CPU time >= {a.bar:g} s")
    rev = "unknown revision"
    try:
        with open(os.path.join(BIN, "REVISION")) as f:
            parts = f.read().strip().split("\t")
            sha, desc = parts[0], parts[1]
            kind = parts[2] if len(parts) > 2 else "clean"
            rev = f"{desc} ({sha[:8]}, {kind})"
    except (OSError, IndexError):
        pass
    print(f"host     : {host_id()}")
    print(f"libxml2  : {rev}")
    print(f"criterion: {label}   (median of {a.reps} runs per input)\n")

    # cell[(sink, column)] -> list of per-run booleans
    cell, per_run = {}, {}
    for i, ((arm, sink, _rep), kinds) in enumerate(runs.items(), 1):
        col = next(n for n, arms in COLUMNS if arm in arms)
        print(f"\r  measuring run {i}/{len(runs)} ...", end="", flush=True)
        # A run with no recorded input cannot be verified; Table 3 counts it
        # as not cleared. "ok (recovered)" inputs are measured like any other.
        ok = False
        for k in order:
            r = kinds.get(k)
            if r is None or not r["status"].startswith("ok"):
                continue
            ms, ops, _cens = measure(sink, os.path.join(CHAMPS, r["file"]),
                                     a.reps, a.timeout)
            ok = (ops >= a.ops) if use_ops else (ms >= a.bar * 1000.0)
            if ok:
                break
        cell.setdefault((sink, col), []).append(ok)
        per_run.setdefault(col, []).append(ok)
    print("\r" + " " * 40 + "\r", end="")

    names = [n for n, _ in COLUMNS]
    w = max(len(n) for n in names)
    print("vector             " + "  ".join(n.rjust(w) for n in names))
    for sink, vname in VECTORS:
        marks = []
        for n in names:
            hits = cell.get((sink, n), [])
            marks.append(("yes" if any(hits) else "-").rjust(w))
        print(f"{vname:<19}" + "  ".join(marks))
    print()
    print("runs clearing      " + "  ".join(
        f"{sum(per_run.get(n, [])):d}/{len(per_run.get(n, [])):d}".rjust(w)
        for n in names))

    if a.json:
        out = {
            "host": host_id(),
            "libxml2": rev,
            "criterion": label,
            "reps": a.reps,
            "vectors": {vname: {n: bool(any(cell.get((sink, n), [])))
                                for n in names}
                        for sink, vname in VECTORS},
            "runs_clearing": {n: [sum(per_run.get(n, [])), len(per_run.get(n, []))]
                              for n in names},
        }
        with open(a.json, "w") as f:
            json.dump(out, f, indent=2, sort_keys=True)
        print(f"\nwrote {a.json}")


if __name__ == "__main__":
    main()
