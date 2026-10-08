"""e3_compare.py — paired comparison of the repeat-1 E3 runs (results/e3_<model>.json) across two models.

Per model: VPR and touch per RQ1 arm, grounding effect within the model (A2/A4 vs. A0, exact McNemar on
the same CVEs), and RQ4 invent vs. port. Across models: the same arm on the same CVEs (exact McNemar).
Writes results/e3_compare.json.
"""
import json
import sys
from pathlib import Path

from scipy.stats import binomtest

ARMS = {"no_grounding_no_feedback": "A0", "cve_text_rag": "A2", "slice_grounded_full": "A4"}


def mcnemar(a, b):
    """Exact McNemar on paired 0/1 lists: (#a only, #b only, p)."""
    a_only = sum(1 for x, y in zip(a, b) if x and not y)
    b_only = sum(1 for x, y in zip(a, b) if y and not x)
    n = a_only + b_only
    return {"a_only": a_only, "b_only": b_only, "p": float(binomtest(a_only, n, 0.5).pvalue) if n else 1.0}


def rate(x):
    return sum(x) / len(x)


def main():
    m1, m2 = (sys.argv[1:3] if len(sys.argv) > 2 else ("claude-haiku-4-5", "claude-sonnet-4-6"))
    R = {m: json.load(open(f"results/e3_{m}.json")) for m in (m1, m2)}
    out = {"models": [m1, m2], "per_model": {}, "across_models": {}}
    for m, r in R.items():
        pm = {"rq1": {}, "rq1_grounding_vs_A0": {}, "rq4": {}}
        for arm, tag in ARMS.items():
            pm["rq1"][tag] = {"vpr": rate(r["rq1"][arm]["validated"]), "touch": rate(r["rq1"][arm]["touch"])}
        a0 = r["rq1"]["no_grounding_no_feedback"]
        for arm in ("cve_text_rag", "slice_grounded_full"):
            pm["rq1_grounding_vs_A0"][ARMS[arm]] = {
                "vpr": mcnemar(r["rq1"][arm]["validated"], a0["validated"]),
                "touch": mcnemar(r["rq1"][arm]["touch"], a0["touch"])}
        p1, p2 = r["rq4"]["P1"]["validated"], r["rq4"]["P2"]["validated"]
        pm["rq4"] = {"P1_invent": rate(p1), "P2_port": rate(p2), "port_vs_invent": mcnemar(p2, p1)}
        for proj in sorted(set(r["rq4"]["project"])):
            idx = [i for i, p in enumerate(r["rq4"]["project"]) if p == proj]
            pm["rq4"][f"by_project_{proj}"] = {"n": len(idx), "P1": rate([p1[i] for i in idx]),
                                               "P2": rate([p2[i] for i in idx])}
        out["per_model"][m] = pm
    for arm, tag in ARMS.items():
        out["across_models"][tag] = {k: mcnemar(R[m2]["rq1"][arm][k], R[m1]["rq1"][arm][k]) for k in ("validated", "touch")}
    for arm in ("P1", "P2"):
        out["across_models"][arm] = mcnemar(R[m2]["rq4"][arm]["validated"], R[m1]["rq4"][arm]["validated"])
    out["llm_usage"] = {m: R[m]["llm_usage"] for m in R}
    Path("results/e3_compare.json").write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
