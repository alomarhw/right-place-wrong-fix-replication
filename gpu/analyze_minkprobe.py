"""analyze_minkprobe.py — contrasts C1-C3 of minkprobe.py (see its docstring for the design).

C1  drop = score(verbatim) - score(variant), certified variants only; pre- vs post-cutoff,
    Mann-Whitney U at the CVE level (mean over a CVE's two functions) + bootstrap CI of the
    difference in medians.
C2  gap = score(vulnerable) - score(fixed) per CVE; pre- vs post-cutoff, Mann-Whitney U.
C3  raw verbatim scores by provenance (confounded; descriptive).
Usage: python gpu/analyze_minkprobe.py results/minkprobe_<model>.jsonl
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
from scipy.stats import mannwhitneyu, wilcoxon

METRICS = ("minkpp", "mink", "mean_lp")


def boot_diff_median(a, b, n=10000, seed=1):
    rng = np.random.default_rng(seed)
    d = [np.median(rng.choice(a, len(a))) - np.median(rng.choice(b, len(b))) for _ in range(n)]
    return [float(np.percentile(d, 2.5)), float(np.percentile(d, 97.5))]


def main(path):
    recs = [json.loads(l) for l in Path(path).read_text().splitlines()]
    out = {"file": str(path), "n_functions": len(recs)}
    for m in METRICS:
        res = {}
        # C1: verbatim - variant drop, certified only, CVE-level mean
        drop = defaultdict(list)
        for r in recs:
            if r["variant_certified"]:
                drop[(r["cve_id"], r["provenance"])].append(r["verbatim"][m] - r["variant"][m])
        pre = np.array([np.mean(v) for (c, p), v in drop.items() if p == "pre_cutoff"])
        post = np.array([np.mean(v) for (c, p), v in drop.items() if p == "post_cutoff"])
        res["C1_drop"] = {"pre_median": float(np.median(pre)), "post_median": float(np.median(post)),
                          "n_pre": len(pre), "n_post": len(post),
                          "pre_vs_zero_p": float(wilcoxon(pre).pvalue), "post_vs_zero_p": float(wilcoxon(post).pvalue),
                          "pre_minus_post_ci": boot_diff_median(pre, post),
                          "mwu_p": float(mannwhitneyu(pre, post, alternative="two-sided").pvalue)}
        # C2: vulnerable - fixed, per CVE
        byc = defaultdict(dict)
        for r in recs:
            byc[(r["cve_id"], r["provenance"])][r["side"]] = r["verbatim"][m]
        g_pre = np.array([d["before"] - d["after"] for (c, p), d in byc.items() if p == "pre_cutoff" and len(d) == 2])
        g_post = np.array([d["before"] - d["after"] for (c, p), d in byc.items() if p == "post_cutoff" and len(d) == 2])
        res["C2_gap"] = {"pre_median": float(np.median(g_pre)), "post_median": float(np.median(g_post)),
                         "mwu_p": float(mannwhitneyu(g_pre, g_post, alternative="two-sided").pvalue)}
        # C3: raw verbatim score by provenance (confounded)
        v_pre = np.array([r["verbatim"][m] for r in recs if r["provenance"] == "pre_cutoff"])
        v_post = np.array([r["verbatim"][m] for r in recs if r["provenance"] == "post_cutoff"])
        res["C3_raw"] = {"pre_median": float(np.median(v_pre)), "post_median": float(np.median(v_post)),
                         "mwu_p": float(mannwhitneyu(v_pre, v_post, alternative="two-sided").pvalue)}
        out[m] = res
    out["certified_share"] = float(np.mean([r["variant_certified"] for r in recs]))
    dst = Path(path).with_name(Path(path).stem + "_analysis.json")
    dst.write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main(sys.argv[1])
