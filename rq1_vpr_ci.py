"""rq1_vpr_ci.py — CVE-level bootstrap CIs for the RQ1 validated-patch rate (no model calls).

Replays the five-arm ladder from the frozen cache (3 repeats, seeds 42..44), counts validated patches
per CVE (0-3), and resamples CVEs with replacement (10,000 draws, seed 42), so the three repeats of a
CVE stay together. Also records the patch-outcome counts (validated / right place, wrong fix / wrong
place / unchanged or malformed) behind Fig. 2d.

Writes results/rq1_vpr_ci.json (read by paper_figures_ladder.py).
"""
import json
import random
from pathlib import Path

from paper_tables import ARMS, _changed_lines
from patch_agent import run_ladder
from rq3_data import build_rq3_corpus

REPEATS, SEED0, DRAWS = 3, 42, 10_000


def main():
    items, _ = build_rq3_corpus(n_cves=300, allow_synthetic=False, seed=42)
    off = [_changed_lines(it.vulnerable_code, it.official_fixed_code) for it in items]
    per = {k: [0] * len(items) for k, _ in ARMS}
    outcomes = {k: {"validated": 0, "right_place_wrong_fix": 0, "wrong_place": 0, "unchanged_or_malformed": 0}
                for k, _ in ARMS}
    for r in range(REPEATS):
        lad = run_ladder(items, seed=SEED0 + r)
        for key, _ in ARMS:
            for i, (it, run) in enumerate(zip(items, lad[key])):
                if run.validated:
                    per[key][i] += 1; outcomes[key]["validated"] += 1
                elif run.reason in ("unchanged", "unbalanced_braces"):
                    outcomes[key]["unchanged_or_malformed"] += 1
                elif off[i] & _changed_lines(it.vulnerable_code, run.final_patch):
                    outcomes[key]["right_place_wrong_fix"] += 1
                else:
                    outcomes[key]["wrong_place"] += 1
    n = len(items)
    res = {"n_cves": n, "repeats": REPEATS, "draws": DRAWS, "arms": {}}
    for key, _ in ARMS:
        rng = random.Random(42)
        bs = sorted(sum(per[key][rng.randrange(n)] for _ in range(n)) / (REPEATS * n) for _ in range(DRAWS))
        res["arms"][key] = {"vpr": sum(per[key]) / (REPEATS * n),
                            "ci95": [bs[int(0.025 * DRAWS) - 1], bs[int(0.975 * DRAWS) - 1]],
                            "outcomes": outcomes[key]}
    Path("results/rq1_vpr_ci.json").write_text(json.dumps(res, indent=1))
    print(json.dumps({k: (round(v["vpr"], 4), [round(x, 3) for x in v["ci95"]]) for k, v in res["arms"].items()}))


if __name__ == "__main__":
    main()
