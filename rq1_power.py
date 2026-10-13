"""rq1_power.py — how large a grounding effect on validated repair does the RQ1 null exclude?

Replays the frozen RQ1 ladder (150 Big-Vul CVEs x 3 repeats; no API calls), counts each CVE's
validated repeats per arm, and for every grounded arm reports the CVE-level paired difference in VPR
against the ungrounded arm A0: the number of discordant CVEs, the exact Wilcoxon test on the per-CVE
counts, and a 95% paired-bootstrap interval of the difference (2,000 resamples of CVEs, seed 42).
Writes results/rq1_power.json.
"""
import json
from pathlib import Path

import numpy as np

from detectors import LLMClient
from patch_agent import run_ladder
from paper_tables import ARMS
from rp_stats import paired_bootstrap_diff, wilcoxon_paired
from rq3_data import build_rq3_corpus


def main():
    items, _ = build_rq3_corpus(n_cves=300, allow_synthetic=False, seed=42)
    reps = 3
    ok = {k: np.zeros((len(items), reps), dtype=int) for k, _ in ARMS}
    for r in range(reps):
        lad = run_ladder(items, seed=42 + r)
        for key, _ in ARMS:
            for i, run in enumerate(lad[key]):
                ok[key][i, r] = int(run.validated)
    base = ok[ARMS[0][0]].sum(1) / reps
    out = {"n_cves": len(items), "repeats": reps, "vpr": {k: float(ok[k].mean()) for k, _ in ARMS}, "arms": {}}
    for key, name in ARMS[1:]:
        arm = ok[key].sum(1) / reps
        d = arm - base
        boot = paired_bootstrap_diff(arm, base, n_boot=2000, seed=42)
        out["arms"][key] = {"name": name, "better": int((d > 0).sum()), "worse": int((d < 0).sum()),
                            "discordant": int((d != 0).sum()), "mean_diff_pts": float(100 * d.mean()),
                            "boot95_pts": [float(100 * boot["lo"]), float(100 * boot["hi"])],
                            "wilcoxon": wilcoxon_paired(arm, base)}
    out["llm_usage"] = LLMClient.get().stats()
    Path("results/rq1_power.json").write_text(json.dumps(out, indent=1, default=float))
    for k, v in out["arms"].items():
        print(f"{v['name']:22s} better/worse {v['better']}/{v['worse']} discordant {v['discordant']} "
              f"diff {v['mean_diff_pts']:+.1f} pts 95% [{v['boot95_pts'][0]:+.1f}, {v['boot95_pts'][1]:+.1f}]")
    print(out["llm_usage"])


if __name__ == "__main__":
    main()
