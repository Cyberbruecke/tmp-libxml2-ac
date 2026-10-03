#!/usr/bin/env python3
"""plot.py -- one figure per vector, all engines overlaid on a shared LINEAR scale.

x = REQUEST BYTES: the base64 size of the payload an attacker actually sends (what a SAML
    payload-size cap limits). Swept up to 2 MiB (a typical cap).
y = processing time (s).
colour    = engine (consistent across figures)
linestyle = scaled shape param (N solid, K dashed, D dash-dot, W dotted)

For each line we choose param values that target request sizes spanning ~1.5 KB .. 2 MiB, then
plot the MEASURED byte size as x. A 12 s/point budget stops a line early (marker 'x'): the
byte size at which a sink blows the budget is the headline -- most explode far below the 2 MiB
cap. Non-swept params held at a middle constant (see caption). Structural caps (parser depth
<=250) end some lines below 2 MiB.

Usage: python3 plot.py [vector[,vector...]]
"""
import base64, os, sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
plt.rcParams.update({
    'font.size': 15,          # base -> everything readable when scaled down
    'axes.titlesize': 15,
    'axes.labelsize': 15,
    'xtick.labelsize': 14,
    'ytick.labelsize': 14,
    'legend.fontsize': 14,
    'legend.title_fontsize': 14,
})
from matplotlib.lines import Line2D
from matplotlib.ticker import FuncFormatter
import saml_payloadgen as spg
import bench

OUT = os.path.join(bench.HERE, "plots"); os.makedirs(OUT, exist_ok=True)
CAP_BYTES = 2 * 1024 * 1024
BUDGET, NPTS = 12.0, 10
W_MID, K_MID, N_MID, D_MID = 40, 200, 200, 60
# log-spaced request-byte targets, ~1.5 KB up to 2 MiB
TARGET_BYTES = [int(1500 * (CAP_BYTES / 1500) ** (i / (NPTS - 1))) for i in range(NPTS)]

# Unified newest stack: libxml2 2.14.6 (lxml), Xerces 2.12.2, Santuario 3.0.4, expat, Go.
ENGINE_COLOR = {
    "libxml2-parse": "C0", "libxml2-c14n": "C0", "libxml2-tree": "C1",
    "libxml2-xpath": "0.65", "libxml2-dsig": "C3",
    "santuario": "C2", "expat": "C4", "xerces": "C5", "go": "C6",
}
ENGINE_LABEL = {"libxml2-xpath": "libxml2 (raw single-eval ref)",
                "libxml2-dsig": "libxml2 (real DSig transform)",
                "libxml2-tree": "libxml2 (marshaller / importNode)"}
AXIS_STYLE = {"N": "-", "K": "--", "D": "-.", "W": ":"}
AXIS_LABEL = {"N": "N (per-node)", "K": "K (children)", "D": "D (depth)", "W": "W (ns/level)"}

VEC_ENGINES = {
    "ns-flood":  ["libxml2-parse", "expat", "xerces", "go"],
    "attr":      ["libxml2-parse", "expat", "xerces", "go", "libxml2-tree"],
    "c14n-inc":  ["libxml2-c14n", "santuario"],
    "c14n-exc":  ["libxml2-c14n", "santuario"],
    "xpath":     ["libxml2-xpath", "libxml2-dsig", "santuario"],
    "reconcile": ["libxml2-tree"],
}
CAPTION = {
    "ns-flood":  "N ns-decls on one element (utilization is a param, not shown). libxml2 2.14.6 "
                 "made this LINEAR; the superlinear line is Xerces (SymbolTable).",
    "attr":      "N attributes. libxml2 parse is linear on 2.14.6; the O(N^2) is the MARSHALLER "
                 "(setNsProp, libxml2-tree).",
    "c14n-inc":  f"N: apex ns, K={K_MID} children.  K: children, N={N_MID} ns.",
    "c14n-exc":  "N: namespaces on one wide element (utilized).",
    "xpath":     "N: flat <a/> siblings. real C3 = DSig transform (O(N^3) libxml2, O(N^2) Xalan); "
                 "grey = raw single-eval reference.",
    "reconcile": f"D: nesting, W={W_MID}/level (depth<=250).  W: ns/level, D={D_MID}. "
                 "Faithful importNode (xmlReconciliateNs), O(D^3 W^2).",
}


def _wrap(frag): return f'<r xmlns:x="urn:x">{frag}</r>'
def _b64len(xml): return len(base64.b64encode(xml.encode()))


def line_specs(vec, engine):
    """{axis: (make_xml, run, cap, pmin)}; make_xml(param)->the request document (for byte
    size), run(param)->seconds. cap = structural max param, pmin = min param."""
    def parse_fn(xml):
        return {"libxml2-parse": bench.t_libxml2_parse, "expat": bench.t_expat,
                "xerces": bench.t_xerces, "go": bench.t_go}[engine](xml)
    def c14n_fn(xml):
        exc = (vec == "c14n-exc")
        return (bench.t_libxml2_c14n(xml, exclusive=exc) if engine == "libxml2-c14n"
                else bench.t_santuario(xml, exclusive=exc))

    def spec(make, run, cap, pmin=20):
        return (make, run, cap, pmin)

    s = {}
    if vec == "ns-flood":
        mkN = lambda p: _wrap(spg.flood_ns_parse(p, 1, utilized=False))
        s["N"] = spec(mkN, lambda p: parse_fn(mkN(p)), 200000, 50)
    elif vec == "attr":
        mk = lambda p: _wrap(spg.flood_attr(p))
        if engine == "libxml2-tree":
            s["N"] = spec(mk, lambda p: bench.t_marshaller(p), 300000, 50)
        else:
            s["N"] = spec(mk, lambda p: parse_fn(mk(p)), 300000, 50)
    elif vec == "c14n-inc":
        mkN = lambda p: _wrap(spg.flood_c14n_inc(p, K_MID))
        mkK = lambda p: _wrap(spg.flood_c14n_inc(N_MID, p))
        s["N"] = spec(mkN, lambda p: c14n_fn(mkN(p)), 200000, 20)
        s["K"] = spec(mkK, lambda p: c14n_fn(mkK(p)), 1000000, 20)
    elif vec == "c14n-exc":
        mk = lambda p: _wrap(spg.flood_c14n_exc(p, utilized=True))
        s["N"] = spec(mk, lambda p: c14n_fn(mk(p)), 200000, 50)
    elif vec == "xpath":
        mk = lambda p: _wrap(spg.flood_xpath(p))
        if engine == "santuario":
            s["N"] = spec(mk, lambda p: bench.t_santuario_xpath(mk(p)), 800000, 50)
        elif engine == "libxml2-dsig":
            s["N"] = spec(mk, lambda p: bench.t_libxml2_xpath_dsig(mk(p)), 800000, 50)
        else:  # libxml2-xpath = raw single-eval reference
            s["N"] = spec(mk, lambda p: bench.t_libxml2_xpath(mk(p)), 800000, 50)
    elif vec == "reconcile":
        mkD = lambda p: _wrap(spg.flood_reconcile(p, W_MID))
        mkW = lambda p: _wrap(spg.flood_reconcile(D_MID, p))
        s["D"] = spec(mkD, lambda p: bench.t_reconcile(mkD(p)), 250, 8)
        s["W"] = spec(mkW, lambda p: bench.t_reconcile(mkW(p)), 50000, 8)
    return s


def _xmlsec_nk(n, k):
    frag = spg.flood_c14n_inc(n, k)
    DS, ENV, algo = spg.DS, spg.ENVELOPED, spg.C14N_INCLUSIVE
    return (f'<?xml version="1.0"?>\n<doc><flood ID="_flood" xmlns:x="urn:x">{frag}</flood>\n'
            f'<ds:Signature xmlns:ds="{DS}"><ds:SignedInfo>'
            f'<ds:CanonicalizationMethod Algorithm="{algo}"/>'
            f'<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>'
            f'<ds:Reference URI="#_flood"><ds:Transforms>'
            f'<ds:Transform Algorithm="{ENV}"/><ds:Transform Algorithm="{algo}"/></ds:Transforms>'
            f'<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>'
            f'<ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo>'
            f'<ds:SignatureValue/></ds:Signature></doc>')


def _find_hi(make, run, cap, pmin):
    """Geometric probe for the largest param whose time <= BUDGET and bytes <= 2 MiB (the 'knee').
    When bytes reach 2 MiB we still test time AT the 2-MiB param, so a line that would exceed the
    budget before 2 MiB is reported truncated and never extended past budget."""
    p, last_ok, trunc = pmin, pmin, False
    while True:
        if _b64len(make(p)) > CAP_BYTES:               # reached 2-MiB cap: pin p there, test time
            bpu = _b64len(make(last_ok)) / last_ok
            p = min(cap, int(CAP_BYTES / bpu))
            if run(p) > BUDGET:
                trunc = True
            else:
                last_ok = p
            break
        if run(p) > BUDGET:                            # budget knee before 2 MiB
            trunc = True
            break
        last_ok = p
        nxt = min(cap, int(p * 1.6))
        if nxt <= p:                                   # hit structural cap
            break
        p = nxt
    return last_ok, trunc


def measure(make, run, cap, pmin):
    """NPTS points evenly spaced in bytes from pmin up to the adaptive hi; a safety early-stop
    truncates the line if a measured point still exceeds the budget."""
    hi, trunc = _find_hi(make, run, cap, pmin)
    lo_b, hi_b = _b64len(make(pmin)), _b64len(make(hi))
    bpu = hi_b / hi
    params, seen = [], set()
    for i in range(NPTS):
        target_b = lo_b + (hi_b - lo_b) * i / (NPTS - 1)
        p = max(pmin, min(hi, int(round(target_b / bpu))))
        if p not in seen:
            seen.add(p); params.append(p)
    X, Y = [], []
    for p in sorted(params):
        y = run(p); X.append(_b64len(make(p))); Y.append(y)
        if y > BUDGET:
            trunc = True; break
    return X, Y, trunc


def _fmt_bytes(v, _):
    if v >= 1024 * 1024: return f"{v / 1024 / 1024:.1f}M"
    if v >= 1024: return f"{v / 1024:.0f}K"
    return f"{int(v)}"


def plot_vector(vec):
    fig, ax = plt.subplots(figsize=(9.2, 5.8))
    axes_seen, eng_seen, maxx = set(), [], 0
    for eng in VEC_ENGINES[vec]:
        for axis, (make, run, cap, pmin) in line_specs(vec, eng).items():
            X, Y, trunc = measure(make, run, cap, pmin)
            ax.plot(X, Y, color=ENGINE_COLOR[eng], linestyle=AXIS_STYLE[axis],
                    marker="x" if trunc else "o", ms=4, lw=1.6)
            axes_seen.add(axis); maxx = max(maxx, max(X))
            print(f"  {vec:<10} {eng:<14} {axis} -> {len(X)}pts, x<= {X[-1]/1024:.0f}KB, "
                  f"max {max(Y):.3f}s{' (trunc)' if trunc else ''}", flush=True)
        eng_seen.append(eng)
    xhi = min(CAP_BYTES * 1.08, maxx * 1.05)
    eng_h = [Line2D([], [], color=ENGINE_COLOR[e], lw=2, label=ENGINE_LABEL.get(e, e)) for e in eng_seen]
    ax_h = [Line2D([], [], color="0.3", linestyle=AXIS_STYLE[a], lw=1.6, label=AXIS_LABEL[a])
            for a in ["N", "U", "K", "D", "W"] if a in axes_seen]
    # engine legend sits top-left by default; these vectors leave the top-right empty
    ENG_LEG_LOC = {"attr": "upper right", "c14n-exc": "upper right",
                   "c14n-inc": "upper right", "xpath": "upper right"}
    leg1 = ax.legend(handles=eng_h, title="engine",
                     loc=ENG_LEG_LOC.get(vec, "upper left"), fontsize=14)
    ax.add_artist(leg1)
    if len(ax_h) > 1:
        ax.legend(handles=ax_h, title="scaled param", loc="lower right", fontsize=14)
    if xhi > 1.5 * 1024 * 1024:
        ax.axvline(CAP_BYTES, color="0.5", ls=":", lw=1)
        ax.text(CAP_BYTES, ax.get_ylim()[1] * 0.02, " 2 MiB cap", fontsize=12, color="0.4", va="bottom", ha="right", rotation=90)
    ax.set_title(f"{spg.fun_name(vec)}  ({vec})  —  processing time vs request bytes (linear)")
    ax.set_xlabel("request bytes (base64 SAML payload)"); ax.set_ylabel("processing time (s)")
    ax.set_xlim(0, xhi); ax.set_ylim(bottom=0); ax.grid(True, alpha=0.3)
    ax.xaxis.set_major_formatter(FuncFormatter(_fmt_bytes))
    fig.text(0.5, 0.012, CAPTION[vec], ha="center", fontsize=12, color="0.35")
    fig.tight_layout(rect=[0, 0.055, 1, 1])
    path = os.path.join(OUT, f"{vec}.png"); fig.savefig(path, dpi=110); plt.close(fig)
    print(f"  wrote {path}")


def main():
    for vec in (sys.argv[1].split(",") if len(sys.argv) > 1 else list(VEC_ENGINES)):
        print(f"### {vec}"); plot_vector(vec)


if __name__ == "__main__":
    main()
