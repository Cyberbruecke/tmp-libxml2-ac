#!/usr/bin/env python3
"""Re-score the saved champion inputs and rebuild Table 3 of the paper.

Each input is replayed through its sink's measurement harness REPS times and the
median CPU time is kept. Medians are used because a single timing is not
reproducible: across our own scoring passes the same input varied by up to 4x in
both directions, which is why the paper's figures are re-measured rather than
taken from the fuzzer's own records.

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


def score_run_dir(d, sink, use_ops, bar, ops_bar, reps, timeout):
    """Score a fuzzer output directory: the Tier 2 -> Tier 1 bridge.

    Walks every saved input, re-measures it, and reports the most expensive one
    and when the run first crossed the bar. AFL++ encodes milliseconds since
    start in each queue filename as `time:<ms>`; libFuzzer names units by
    content hash, so no time is recoverable there.
    """
    ents = []
    for root, _, files in os.walk(d):
        for n in files:
            m = re.search(r"time:(\d+)", n)
            ents.append(((int(m.group(1)) if m else None), os.path.join(root, n)))
    if not ents:
        sys.exit(f"no inputs found under {d}")
    timed = [e for e in ents if e[0] is not None]
    ents.sort(key=lambda e: (e[0] is None, e[0]))
    print(f"  {len(ents)} inputs ({len(timed)} carry a timestamp)\n")

    best = (0.0, 0, None)
    first = None
    for i, (t, path) in enumerate(ents, 1):
        print(f"\r  measuring {i}/{len(ents)} ...", end="", flush=True)
        ms, ops = measure(sink, path, reps, timeout)
        cleared = (ops >= ops_bar) if use_ops else (ms >= bar * 1000.0)
        if (ops if use_ops else ms) > (best[1] if use_ops else best[0]):
            best = (ms, ops, path)
        if cleared and first is None and t is not None:
            first = (t / 3600000.0, path)
    print("\r" + " " * 40 + "\r", end="")

    ms, ops, path = best
    print(f"  best input : {os.path.relpath(path, d)}")
    print(f"  cost       : {ms/1000:.2f} s CPU, {ops} sink operations")
    if first:
        print(f"  first clear: {first[0]:.2f} h of active fuzzing")
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


def measure(sink, path, reps, timeout):
    """Return (median CPU ms, operation count).

    The measurement is censored at `timeout`: deciding a threshold only needs to
    know whether the cost reaches the bar, and the most expensive inputs here
    cost close to a minute each. A censored run reports the cap, which is above
    the bar and so still counts as cleared.
    """
    times, ops = [], 0
    for _ in range(reps):
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        t0 = before.ru_utime + before.ru_stime
        try:
            p = subprocess.run([os.path.join(BIN, "measure_" + sink), path],
                               capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return timeout * 1000.0, ops
        except OSError as e:
            sys.exit(f"cannot run measure_{sink}: {e}\nDid you run scripts/build.sh?")
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        times.append((after.ru_utime + after.ru_stime) - t0)
        out = p.stdout.decode("utf8", "ignore").split()
        if out:
            try: ops = max(ops, int(out[0]))
            except ValueError: pass
    return statistics.median(times) * 1000.0, ops


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bar", type=float, default=5.0,
                    help="CPU-time criterion in seconds (default 5)")
    ap.add_argument("--ops", type=float, default=None,
                    help="use an operation-count criterion instead, e.g. 8e6")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--verify", action="store_true",
                    help="check every input against its recorded SHA-256 and exit")
    ap.add_argument("--json", metavar="FILE",
                    help="also write the result as JSON for mechanical diffing")
    ap.add_argument("--run-dir", metavar="DIR",
                    help="score a fuzzer output directory instead of the saved "
                         "inputs (Tier 2); needs --sink")
    ap.add_argument("--sink", choices=[v for v, _ in VECTORS],
                    help="which sink --run-dir was fuzzed against")
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
        if not a.sink:
            sys.exit("--run-dir needs --sink (one of c1 c2 c3 c5 c7)")
        if a.timeout is None:
            a.timeout = 180 if use_ops else max(2, int(a.bar * 1.5) + 1)
        print(f"host     : {host_id()}")
        print(f"scoring  : {a.run_dir}  (sink {a.sink})\n")
        sys.exit(score_run_dir(a.run_dir, a.sink, use_ops, a.bar,
                               a.ops or 0, a.reps, a.timeout))

    # Each run contributes two saved inputs: the one that maximised the sink's
    # operation counter and the one that maximised CPU time. They are different
    # files in 68 of 70 runs, so each criterion must be scored against its own.
    want = "ops" if use_ops else "cpu"
    rows = [r for r in rows if r["kind"] == want]
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
    total = sum(1 for r in rows if r["status"] == "ok")
    done = 0
    for r in rows:
        col = next((n for n, arms in COLUMNS if r["arm"] in arms), None)
        if col is None:
            continue
        key = (r["sink"], col)
        if not r["status"].startswith("ok"):
            # No input was recorded for this run, so it cannot be verified.
            # The paper counts these as not cleared.
            cell.setdefault(key, []).append(False)
            per_run.setdefault(col, []).append(False)
            continue
        done += 1
        print(f"\r  measuring {done}/{total} ...", end="", flush=True)
        ms, ops = measure(r["sink"], os.path.join(CHAMPS, r["file"]),
                          a.reps, a.timeout)
        ok = (ops >= a.ops) if use_ops else (ms >= a.bar * 1000.0)
        cell.setdefault(key, []).append(ok)
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
