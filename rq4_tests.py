"""rq4_tests.py — CVE-level significance tests for RQ4 (porting known fixes), as reported in the paper.

Unit of analysis: the CVE. Each CVE's score per arm is its validated-patch rate averaged over its hard
targets and three repeats (results/porting_pilot.json; P4 from results/e2_slice_reduction.json).
Paired arms are compared with the exact Wilcoxon signed-rank test on the non-zero differences
(rp_stats.wilcoxon_paired) and Holm-corrected over the four RQ4 comparisons:

  P2 port            vs P1b invent + CVE text   (all 23 CVEs)
  P2 port            vs P0 plain text patch     (modified clones, 18 CVEs)
  P3 port + srcVul   vs P2 port                 (all 23 CVEs)
  P4 port from slices vs P2 port                (all 23 CVEs)

No LLM calls. Writes results/rq4_tests.json.
"""
import json
from pathlib import Path

import numpy as np

from rp_stats import Results


def cve_scores(rows, arm):
    by = {}
    for r in rows:
        v = r["validated"][arm]
        by.setdefault(r["cve_id"], []).append(float(np.mean(v if isinstance(v, list) else [v])))
    return {c: float(np.mean(x)) for c, x in by.items()}


def main():
    rows = json.loads(Path("results/porting_pilot.json").read_text())["per_target"]
    e2 = json.loads(Path("results/e2_slice_reduction.json").read_text())["per_cve"]
    cves = sorted({r["cve_id"] for r in rows})
    modified = [r for r in rows if r["clone_type"] == "modified"]
    mod_cves = sorted({r["cve_id"] for r in modified})
    s = {a: cve_scores(rows, a) for a in ("P0", "P1b", "P2", "P3")}
    m = {a: cve_scores(modified, a) for a in ("P0", "P2")}
    p4 = dict(zip(e2["cve_id"], e2["P4"]))

    res = Results()
    res.paired_counts("RQ4", "P2 port vs P1b invent", [s["P2"][c] for c in cves], [s["P1b"][c] for c in cves],
                      family="RQ4", baseline="invent")
    res.paired_counts("RQ4", "P2 port vs P0 plain text patch", [m["P2"][c] for c in mod_cves],
                      [m["P0"][c] for c in mod_cves], family="RQ4", baseline="plain text patch",
                      subset="modified clones")
    res.paired_counts("RQ4", "P3 port+srcVul vs P2 port", [s["P3"][c] for c in cves], [s["P2"][c] for c in cves],
                      family="RQ4", baseline="port")
    res.paired_counts("RQ4", "P4 port from slices vs P2 port", [p4[c] for c in cves], [s["P2"][c] for c in cves],
                      family="RQ4", baseline="port")
    out = res.finalize()["RQ4"]["statistical_tests"]["tests"]
    Path("results/rq4_tests.json").write_text(json.dumps(out, indent=1))
    for t in out:
        print(f"{t['name']:36s} better/worse={t['better']}/{t['worse']:<2d} {t['method']} "
              f"p={t['p_value']:.3g} Holm p={t['p_holm']:.3g}")


if __name__ == "__main__":
    main()
