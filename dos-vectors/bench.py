#!/usr/bin/env python3
"""bench.py -- drive every payloadgen vector through GENERIC XML engines, no SAML product.

Two questions kept separate: COST (an XML-engine property, measured here) vs REACHABILITY
(a SAML-product property, measured by saml_dos against live targets).

Engines
  libxml2-parse   xmllint --noout                 parse (xmlNewNs / attr dup scan)
  libxml2-c14n    xmllint --c14n / --exc-c14n      canonicalization (C1/C2)
  libxml2-xpath   xmllint --xpath '(union)[pred]'  XPath engine (single eval)
  libxml2-tree    lxml set-attr loop / adoptNode   marshaller (C5) / xmlReconciliateNs (C7)
  xmlsec1         xmlsec1 --sign over a template   the REAL libxml2 DSig transform+C14N path
  expat           xml.parsers.expat (libexpat)     a second C parser, streaming
  xerces          Apache Xerces-J DocumentBuilder  Java DOM parser (SymbolTable)
  go              Go encoding/xml                   Go streaming tokenizer
  santuario       Apache Santuario canonicalizer   the Java DSig/C14N engine (OpenSAML/Shibboleth)

The per-engine timing primitives (t_* below) each take a document/fragment string and are
reused by plot.py to sweep N/K/D. Usage of the CLI:
  python3 bench.py                       # all vectors, default sweeps
  python3 bench.py c14n-inc,ns-flood     # named vectors
  python3 bench.py ns-flood 2000,4000,8000,16000
"""
import math, os, subprocess, sys, tempfile, time
import saml_payloadgen as spg
import lxml.etree as ET       # unified libxml2 == lxml's linked 2.14.6 (newest)

HERE = os.path.dirname(os.path.abspath(__file__))
# --- UNIFIED NEWEST STACK (2026-08) ---
#   libxml2 2.14.6  (all libxml2 ops go through lxml in-process; reconcile via recon_bench_214,
#                    a C harness compiled against the same 2.14.6)
#   Xerces-J 2.12.2, Santuario 3.0.4, expat 2.8.3, Go 1.22
XERCES_JAR = "/tmp/xercesImpl-2.12.2.jar"
XERCES_FACTORY = "org.apache.xerces.jaxp.DocumentBuilderFactoryImpl"
GOPARSE = "/tmp/goparse"
RECON_BENCH = "/tmp/recon_bench_214"          # importNode path on libxml2 2.14.6
# The DSig XPath transform wraps the attacker's <ds:XPath> (a node-set query) as a boolean
# predicate re-evaluated PER union node -> O(N^3): the REAL C3 (t_libxml2_xpath_dsig).
DSIG_XPATH_DSIG = f"(//. | //@* | //namespace::*)[boolean({spg.DEFAULT_XPATH})]"
# A single evaluation of a simplified predicate -> ~O(N^2): a raw-engine LOWER BOUND reference.
DSIG_XPATH_RAW = "(.//. | .//@* | .//namespace::*)[count(preceding-sibling::a) > 0]"
try:
    SANTUARIO_CP = open(os.path.join(HERE, ".santuario_cp_3")).read().strip()   # Santuario 3.0.4
except OSError:
    SANTUARIO_CP = ""


# --- timing / process helpers ----------------------------------------------------------
def _time(fn):
    t0 = time.perf_counter(); fn(); return time.perf_counter() - t0


def _tmp(xml, suffix=".xml"):
    f = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False)
    f.write(xml); f.close(); return f.name


def _run_cli(cmd):
    return _time(lambda: subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))


def _java_time(cmd):
    """Run a Java/Go harness that prints its own internal timing on the last stdout line
    (process/JVM startup excluded)."""
    out = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=HERE)
    txt = out.stdout.decode().strip().splitlines()
    try:
        return float(txt[-1])
    except (IndexError, ValueError):
        return float("nan")


# --- per-engine timing primitives (each takes an XML string) ---------------------------
# libxml2 == lxml (2.14.6), in-process. Parse cost is the DOM build; c14n/xpath run on the
# already-parsed tree (the flood cost, not the parse).
def t_libxml2_parse(xml):
    data = xml.encode()
    return _time(lambda: ET.fromstring(data))


def t_libxml2_c14n(xml, exclusive=False):
    el = ET.fromstring(xml.encode())
    return _time(lambda: ET.tostring(el, method="c14n", exclusive=exclusive))


def t_libxml2_xpath(xml):
    """Raw single-eval reference (greyed): one evaluation of a simplified predicate."""
    el = ET.fromstring(xml.encode()); xp = ET.XPath(DSIG_XPATH_RAW)
    return _time(lambda: xp(el))


def t_libxml2_xpath_dsig(xml):
    """The REAL C3: the DSig-wrapped predicate re-evaluated per union node -> O(N^3)."""
    el = ET.fromstring(xml.encode()); xp = ET.XPath(DSIG_XPATH_DSIG)
    return _time(lambda: xp(el))


def t_expat(xml):
    import xml.parsers.expat as ex
    data = xml.encode()
    def run():
        pr = ex.ParserCreate(namespace_separator=":"); pr.buffer_text = True
        pr.Parse(data, True)
    return _time(run)


def t_xerces(xml):
    p = _tmp(xml)
    try:
        return _java_time(["java", "-cp", f".:{XERCES_JAR}",
                           f"-Djavax.xml.parsers.DocumentBuilderFactory={XERCES_FACTORY}",
                           "XercesBench", p, "1"])
    finally: os.unlink(p)


def t_go(xml):
    p = _tmp(xml)
    try: return _java_time([GOPARSE, p, "1"])
    finally: os.unlink(p)


def t_santuario(xml, exclusive=False):
    return _t_santuario(xml, "exc" if exclusive else "inc")


def t_santuario_xpath(xml):
    """Santuario's DSig XPath Filter transform (Xalan engine) over the sibling flood."""
    return _t_santuario(xml, "xpath")


def _t_santuario(xml, mode):
    p = _tmp(xml)
    try:
        return _java_time(["java", "-cp", f".:{SANTUARIO_CP}", "SantuarioBench", p, mode, "1"])
    finally: os.unlink(p)


def t_xmlsec1(template):
    if not os.path.exists(KEY_PEM):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", KEY_PEM,
                        "-out", "/tmp/cert.pem", "-days", "1", "-nodes", "-subj", "/CN=t"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    p = _tmp(template)
    try:
        return _run_cli(["xmlsec1", "--sign", "--privkey-pem", KEY_PEM, "--id-attr:ID", "flood", p])
    finally: os.unlink(p)


def t_marshaller(n):
    """C5: build an element and set N namespaced attributes (xmlSetNsProp per attr), serialise."""
    from lxml import etree
    def run():
        el = etree.Element("e")
        for i in range(n):
            el.set(f"{{urn:x:{i}}}a", "")
        etree.tostring(el)
    return _time(run)


def t_reconcile(frag_xml):
    """C7: the FAITHFUL importNode path -- xmlDocCopyNode(deep) + xmlReconciliateNs (recon_bench,
    libxml2 2.14.6), what DOMDocument::importNode does. Returns the reconcile seconds (2nd field);
    NOT lxml adoptNode (which calls the cheaper xmlDOMWrapReconcileNamespaces)."""
    p = _tmp(frag_xml)
    try:
        out = subprocess.run([RECON_BENCH, p], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        return float(out.stdout.split()[1])
    finally:
        os.unlink(p)


# --- document builders -----------------------------------------------------------------
def _wrap(frag):
    return f'<r xmlns:x="urn:x">{frag}</r>'


def doc(vec, size):
    if vec == "ns-flood":  return _wrap(spg.flood_ns_parse(size, depth=1, utilized=False))
    if vec == "attr":      return _wrap(spg.flood_attr(size))
    if vec == "c14n-inc":  return _wrap(spg.flood_c14n_inc(size, size))
    if vec == "c14n-exc":  return _wrap(spg.flood_c14n_exc(size, utilized=True))
    if vec == "xpath":     return _wrap(spg.flood_xpath(size))
    if vec == "reconcile": return _wrap(spg.flood_reconcile(min(size, 250), max(size // 8, 8)))
    raise SystemExit(f"no doc builder for {vec}")


def sign_template(vec, size):
    """Minimal signed-doc template for xmlsec1 --sign: the flood in a referenced element plus
    a Signature whose transforms select the sink. Signing runs the same reference-transform +
    C14N pipeline a verifier runs, with a key we control."""
    algo = spg.C14N_EXCLUSIVE if vec in ("c14n-exc", "xpath") else spg.C14N_INCLUSIVE
    if vec == "xpath":
        frag = spg.flood_xpath(size)
        xt = (f'<ds:Transform Algorithm="{spg.XPATH_TRANSFORM}">'
              f'<ds:XPath>{spg.DEFAULT_XPATH}</ds:XPath></ds:Transform>')
    else:
        frag = spg.flood_c14n_inc(size, size) if vec == "c14n-inc" else spg.flood_c14n_exc(size, utilized=True)
        xt = ""
    DS, ENV = spg.DS, spg.ENVELOPED
    return (f'<?xml version="1.0"?>\n<doc><flood ID="_flood" xmlns:x="urn:x">{frag}</flood>\n'
            f'<ds:Signature xmlns:ds="{DS}"><ds:SignedInfo>'
            f'<ds:CanonicalizationMethod Algorithm="{algo}"/>'
            f'<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>'
            f'<ds:Reference URI="#_flood"><ds:Transforms>'
            f'<ds:Transform Algorithm="{ENV}"/>{xt}<ds:Transform Algorithm="{algo}"/>'
            f'</ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>'
            f'<ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo>'
            f'<ds:SignatureValue/></ds:Signature></doc>')


# --- CLI matrix runner -----------------------------------------------------------------
def _cell(eng, vec, size):
    if eng == "libxml2-parse": return t_libxml2_parse(doc(vec, size))
    if eng == "libxml2-c14n":  return t_libxml2_c14n(doc(vec, size), exclusive=(vec == "c14n-exc"))
    if eng == "libxml2-xpath": return t_libxml2_xpath(doc(vec, size))       # raw single-eval ref
    if eng == "libxml2-dsig":  return t_libxml2_xpath_dsig(doc(vec, size))  # real C3
    if eng == "santuario":
        return t_santuario_xpath(doc(vec, size)) if vec == "xpath" \
               else t_santuario(doc(vec, size), exclusive=(vec == "c14n-exc"))
    if eng == "expat":         return t_expat(doc(vec, size))
    if eng == "xerces":        return t_xerces(doc(vec, size))
    if eng == "go":            return t_go(doc(vec, size))
    if eng == "libxml2-tree":
        return t_marshaller(size) if vec == "attr" else t_reconcile(doc(vec, size))
    raise SystemExit(f"no cell for {eng}/{vec}")


MATRIX = {
    "ns-flood":  ["libxml2-parse", "expat", "xerces", "go"],
    "attr":      ["libxml2-parse", "expat", "xerces", "go", "libxml2-tree"],
    "c14n-inc":  ["libxml2-c14n", "santuario"],
    "c14n-exc":  ["libxml2-c14n", "santuario"],
    "xpath":     ["libxml2-xpath", "libxml2-dsig", "santuario"],
    "reconcile": ["libxml2-tree"],
}
DEFAULT_SIZES = {
    "ns-flood":  [2000, 4000, 8000, 16000], "attr":     [2000, 4000, 8000, 16000],
    "c14n-inc":  [250, 500, 1000, 1500],    "c14n-exc": [2000, 4000, 8000, 16000],
    "xpath":     [500, 1000, 2000, 4000],   "reconcile": [250, 500, 1000, 2000],
}


def _slope(pts):
    (s1, t1), (s2, t2) = pts[-2], pts[-1]
    if t1 <= 0 or t2 <= 0: return float("nan")
    return math.log(t2 / t1) / math.log(s2 / s1)


def main():
    vecs = sys.argv[1].split(",") if len(sys.argv) > 1 else list(MATRIX)
    sizes_override = [int(x) for x in sys.argv[2].split(",")] if len(sys.argv) > 2 else None
    for vec in vecs:
        sizes = sizes_override or DEFAULT_SIZES[vec]
        print(f"\n### {spg.fun_name(vec)} ({vec})   sizes={sizes}")
        for eng in MATRIX[vec]:
            pts = []
            for s in sizes:
                dt = _cell(eng, vec, s); pts.append((s, dt))
                print(f"  {eng:<14} size={s:<7} {dt:8.3f}s", flush=True)
            print(f"  => {eng:<14} b~{_slope(pts):.2f}", flush=True)


if __name__ == "__main__":
    main()
