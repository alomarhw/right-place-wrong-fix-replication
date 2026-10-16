"""e4_gap_ci.py — bootstrap CI for the A4-minus-A0 gap in VPR after counting equivalent fixes (no model calls).

For each LLM rater, the adjusted VPR of an arm is its oracle VPR plus the touch-but-rejected share times the
share of sampled rejected patches the rater labels equivalent (results/e4_allrepeats.json). The rated samples
(60 per arm) are resampled within arm (10,000 draws, seed 42); the oracle VPR and pool share are held fixed.
Writes results/e4_gap_ci.json.
"""
import json
import random
from pathlib import Path

ARMS = {"A0": "no_grounding_no_feedback", "A4": "slice_grounded_full"}


def main():
    d = json.loads(Path("results/e4_allrepeats.json").read_text())
    out = {}
    for m in d["raters"]:
        eq = {a: [it["labels"][m] == "equivalent" for it in d["items"] if it["arm"] == k] for a, k in ARMS.items()}
        base = {a: (d["arms"][k]["oracle_vpr"], d["arms"][k]["touch_rejected_share"]) for a, k in ARMS.items()}
        adj = lambda a, xs: base[a][0] + base[a][1] * sum(xs) / len(xs)  # noqa: E731
        rng = random.Random(42)
        bs = sorted(adj("A4", [rng.choice(eq["A4"]) for _ in eq["A4"]]) - adj("A0", [rng.choice(eq["A0"]) for _ in eq["A0"]])
                    for _ in range(10_000))
        out[m] = {"gap": adj("A4", eq["A4"]) - adj("A0", eq["A0"]), "ci95": [bs[249], bs[9749]],
                  "n": {a: len(v) for a, v in eq.items()}}
    Path("results/e4_gap_ci.json").write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
