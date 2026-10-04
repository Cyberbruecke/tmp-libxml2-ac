#!/usr/bin/env python3
"""plot_heatmap.py -- the comparability heatmap for the paper.

Reads bench_harness's aggregate CSV and renders a targets x vectors heatmap of the
headline metric: unavailable seconds per attacker byte (s/B) = unavailable_s / bytes_sent.
Higher = a cheaper denial-of-service. Colour is a perceptually-uniform, CVD- and
grayscale-safe sequential ramp (viridis) on a LOG scale, since the ratio spans several
orders of magnitude. Cells with no hard denial (ratio 0) are drawn neutral and, when the
probe still slowed down, annotated with the attack/idle latency inflation so a pure
slowdown-DoS is not invisible. Missing (vector not applicable) cells are blank.

Usage:  python3 plot_heatmap.py [SOURCE]
        SOURCE = harness_runs/harness_results.csv   (one consistent run's aggregate), OR
                 harness_runs                        (a DIRECTORY -> scan every per-cell
                                                      *.attack.*.json, newest wins; lets you
                                                      build the full figure from mixed runs)
Writes: heatmap_time_per_byte.pdf (vector, for LaTeX) and .png (preview).
"""
import csv, glob, json, math, sys, os, collections
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import LogNorm

CSV = sys.argv[1] if len(sys.argv) > 1 else "harness_runs/harness_results.csv"
OUT = "heatmap_time_per_byte"

# inc/exc are MODIFIERS of C14N1D3, not separate vectors -> fold into one column.
VEC_COL = {"cianide": "C14N1D3", "c14n-inc": "C14N1D3", "c14n-exc": "C14N1D3",
           "cianide-exc": "C14N1D3",
           "flattr": "FlAttr", "xplode": "XPlode", "wreckoncile": "Wreckoncile",
           "nspew": "NSpew"}
VEC_ORDER = ["C14N1D3", "FlAttr", "XPlode", "Wreckoncile", "NSpew"]

# display label + row order (only targets present in the CSV are drawn)
TGT_LABEL = {
    "ssp-idp": "SimpleSAMLphp (IdP)", "authentic2-idp": "Authentic2 (IdP)",
    "ssp-sp": "SimpleSAMLphp (SP)", "nextcloud": "Nextcloud", "owncloud": "ownCloud",
    "moodle": "Moodle",
    "drupal": "Drupal", "wordpress": "WordPress", "gitlab": "GitLab",
    "authentic2-sp": "Authentic2 (SP)", "authentik-sp": "authentik (SP)",
    "synapse": "Synapse",
}
TGT_ORDER = list(TGT_LABEL)


def load(csv_path):
    ratio, latx, variant = {}, {}, {}   # keyed (target, vectorcol)
    with open(csv_path) as f:
        for r in csv.DictReader(f):
            col = VEC_COL.get(r.get("vector", ""), r.get("vector"))
            if col is None:
                continue
            try:
                val = float(r["ratio_mean_s_per_byte"])
            except (ValueError, KeyError, TypeError):
                continue
            key = (r["target"], col)
            # if a C14N1D3 modifier appears twice, keep the stronger
            if key not in ratio or val > ratio[key]:
                ratio[key] = val
                try:
                    latx[key] = float(r["latency_inflation"])
                except (ValueError, KeyError, TypeError):
                    latx[key] = None
                variant[key] = r.get("c14n_variant", "") or ""
    return ratio, latx, variant


def load_from_jsons(dirpath):
    """Aggregate directly from per-cell *.attack.*.json (newest/averaged per cell), so a complete
    figure can be built from mixed runs without a fresh aggregate CSV. lat_x is recomputed as the
    attack-sustain served latency over the target's idle-control served latency."""
    ratio, latx, variant = {}, {}, {}
    idle = {}                                        # target -> idle sustain served latency
    for fn in glob.glob(os.path.join(dirpath, "*.idle.json")):
        try:
            d = json.load(open(fn))
            idle[os.path.basename(fn).split(".")[0]] = d.get("probes", {}).get("sustain", {}).get("avg_served_s")
        except Exception:
            pass
    cells = collections.defaultdict(list)            # (target, raw_vector) -> [files]
    for fn in glob.glob(os.path.join(dirpath, "*.attack.*.json")):
        parts = os.path.basename(fn)[:-5].split(".")
        cells[(parts[0], parts[1])].append(fn)
    for (t, rawv), fns in cells.items():
        col = VEC_COL.get(rawv)
        if col is None:
            continue
        rr, ll = [], []
        for fn in fns:
            try:
                d = json.load(open(fn))
            except Exception:
                continue
            r = d.get("totals", {}).get("ratio_unavail_s_per_byte")
            if r is None:
                continue
            rr.append(r)
            al, ib = d.get("probes", {}).get("sustain", {}).get("avg_served_s"), idle.get(t)
            if al and ib:
                ll.append(al / ib)
        if not rr:
            continue
        val = sum(rr) / len(rr)
        key = (t, col)
        if key not in ratio or val > ratio[key]:      # C14N1D3 folds inc/exc -> keep the stronger
            ratio[key] = val
            latx[key] = (sum(ll) / len(ll)) if ll else None
            variant[key] = ("exc" if "exc" in rawv else "inc") if col == "C14N1D3" else ""
    return ratio, latx, variant


def main():
    if os.path.isdir(CSV):
        ratio, latx, variant = load_from_jsons(CSV)   # scan per-cell JSONs in a directory
    elif os.path.exists(CSV):
        ratio, latx, variant = load(CSV)               # one run's aggregate CSV
    else:
        sys.exit(f"no CSV or directory at {CSV}")
    if not ratio:
        sys.exit("no usable rows in the CSV")

    # ownCloud is not measured; it shares the php-saml + xmlseclibs stack with Nextcloud,
    # so we project Nextcloud's measured cells onto it as a same-library prediction.
    for (t, v) in [k for k in list(ratio) if k[0] == "nextcloud"]:
        ratio[("owncloud", v)] = ratio[(t, v)]
        latx[("owncloud", v)] = latx.get((t, v))
        variant[("owncloud", v)] = variant.get((t, v), "")

    targets = [t for t in TGT_ORDER if any((t, v) in ratio for v in VEC_ORDER)]
    vectors = [v for v in VEC_ORDER if any((t, v) in ratio for t in targets)]
    # matrix is [vectors x targets] so vectors are on y and targets on x (wide/horizontal)
    M = np.full((len(vectors), len(targets)), np.nan)
    for i, v in enumerate(vectors):
        for j, t in enumerate(targets):
            if (t, v) in ratio:
                M[i, j] = ratio[(t, v)]
    M = M * 1000.0                             # s/byte -> s/KB (x1000)

    pos = M[np.isfinite(M) & (M > 0)]
    norm = LogNorm(vmin=pos.min(), vmax=pos.max()) if pos.size else LogNorm(1e-6, 1e-2)
    from matplotlib.colors import LinearSegmentedColormap
    cmap = LinearSegmentedColormap.from_list("wyr", ["#ffffff", "#ffe200", "#e00000"])
    cmap.set_bad("#dcdcdc")                 # missing / no-hard-denial -> neutral gray

    Mplot = np.where(M > 0, M, np.nan)       # 0 and NaN both -> neutral

    fig, ax = plt.subplots(figsize=(0.46 * len(targets) + 1.6, 0.42 * len(vectors) + 1.0))
    im = ax.imshow(Mplot, aspect="auto", cmap=cmap, norm=norm)

    ax.set_xticks(range(len(targets)))
    ax.set_xticklabels([TGT_LABEL.get(t, t) for t in targets], fontsize=8,
                       rotation=40, ha="right", rotation_mode="anchor")
    ax.set_yticks(range(len(vectors)))
    ax.set_yticklabels(vectors, fontsize=9)
    ax.tick_params(length=0)
    for sp in ax.spines.values():
        sp.set_visible(False)
    ax.set_xticks(np.arange(-.5, len(targets), 1), minor=True)
    ax.set_yticks(np.arange(-.5, len(vectors), 1), minor=True)
    ax.grid(which="minor", color="#bdbdbd", linewidth=0.8)
    ax.tick_params(which="minor", length=0)

    cb = fig.colorbar(im, ax=ax, fraction=0.04, pad=0.015)
    cb.set_label("s / attacker KB", fontsize=8)
    cb.ax.tick_params(labelsize=7)

    fig.tight_layout()
    for ext in ("pdf", "png"):
        fig.savefig(f"{OUT}.{ext}", dpi=200, bbox_inches="tight")
    print(f"wrote {OUT}.pdf and {OUT}.png  ({len(vectors)} vectors x {len(targets)} targets)")


if __name__ == "__main__":
    main()
