"""run_open_ladder.py -- sensitivity test: does an interprocedural srcSlice slice change RQ1 repair?

Runs the RQ1 ladder arms with a self-hosted open model (no paid API; RP_LOCAL_LLM_BASE_URL must point at an
OpenAI-compatible vLLM server and RP_LLM_MODEL name the model) on the 150 RQ1 CVEs, three repeats, with the
seeds of the Claude ladder (seed 42 + repeat, item seed + 101 * index):
  A2  cve_text_rag                     A3  slice_grounded_no_feedback (identifier slice)
  A4  slice_grounded_full              A3s srcslice_grounded_no_feedback (interprocedural srcSlice slice)
  A4s srcslice_grounded_full           A3c slice_plus_callees_no_feedback (identifier slice + same callees, unsliced)
Per item and arm it records validated and touch (the patch edits a line the official fix changes), as in
e3_cross_model.py. The pre-specified gate (CLAIMS.md, recorded before the run) is evaluated on per-item means over
the repeats, with exact paired tests, on all items and on the items that have a srcSlice slice.
Writes results/open_ladder_<model>.json. Usage: python gpu/run_open_ladder.py
"""

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
if not os.environ.get("RP_LOCAL_LLM_BASE_URL"):
    sys.exit("RP_LOCAL_LLM_BASE_URL is not set: this script only runs against a self-hosted model.")
os.environ.pop("ANTHROPIC_API_KEY", None)  # never reach a paid API from this script

import numpy as np  # noqa: E402
from scipy.stats import wilcoxon  # noqa: E402

import patch_agent  # noqa: E402
from detectors import LLM_MODEL, LLMClient  # noqa: E402
from paper_tables import _changed_lines  # noqa: E402
from rq3_data import build_rq3_corpus  # noqa: E402

ARMS = ["cve_text_rag", "slice_grounded_no_feedback", "slice_grounded_full",
        "srcslice_grounded_no_feedback", "srcslice_grounded_full", "slice_plus_callees_no_feedback"]
SHORT = dict(zip(ARMS, ["A2", "A3", "A4", "A3s", "A4s", "A3c"]))
REPEATS, SEED0 = 3, 42


def paired(a, b):
    a, b = np.asarray(a, float), np.asarray(b, float)
    d = a - b
    nz = d[d != 0]
    p = float(wilcoxon(nz).pvalue) if len(nz) else 1.0
    return {"diff_points": round(100 * float(d.mean()), 2), "p": p, "n_items": len(d), "n_nonzero": int(len(nz))}


def main() -> int:
    items, _ = build_rq3_corpus(n_cves=300, allow_synthetic=False, seed=42)
    covered = [bool(patch_agent._srcslice(it.vulnerable_code).get("ok")) for it in items]
    with_callees = [bool(patch_agent._srcslice(it.vulnerable_code).get("callees")) for it in items]
    res = {a: {"validated": [], "touch": []} for a in ARMS}
    for r in range(REPEATS):
        lad = patch_agent.run_ladder(items, seed=SEED0 + r, conditions=ARMS)
        for a in ARMS:
            v, t = [], []
            for it, run in zip(items, lad[a]):
                off = _changed_lines(it.vulnerable_code, it.official_fixed_code)
                v.append(int(run.validated))
                t.append(int(run.reason != "unchanged" and bool(off & _changed_lines(it.vulnerable_code, run.final_patch))))
            res[a]["validated"].append(v); res[a]["touch"].append(t)
        print(f"[open-ladder] repeat {r + 1}/{REPEATS} done; {LLMClient.get().stats()}")
    mean = {a: np.mean(res[a]["validated"], axis=0) for a in ARMS}
    summary = {SHORT[a]: {"vpr": round(100 * float(np.mean(res[a]["validated"])), 2),
                          "touch": round(100 * float(np.mean(res[a]["touch"])), 2)} for a in ARMS}
    sub = np.array(covered)
    tests = {}
    for name, x, y in (("A3s_vs_A3", "srcslice_grounded_no_feedback", "slice_grounded_no_feedback"),
                       ("A4s_vs_A4", "srcslice_grounded_full", "slice_grounded_full"),
                       ("A3s_vs_A3c", "srcslice_grounded_no_feedback", "slice_plus_callees_no_feedback"),
                       ("A3c_vs_A3", "slice_plus_callees_no_feedback", "slice_grounded_no_feedback")):
        tests[name] = {"all": paired(mean[x], mean[y]), "srcslice_covered": paired(mean[x][sub], mean[y][sub])}
    gate = ((tests["A3s_vs_A3"]["all"]["diff_points"] >= 3 and tests["A3s_vs_A3"]["all"]["p"] < 0.05) or
            (tests["A4s_vs_A4"]["all"]["diff_points"] >= 3 and tests["A4s_vs_A4"]["all"]["p"] < 0.05)) and \
           tests["A3s_vs_A3c"]["all"]["diff_points"] >= 0
    out = {"model": LLM_MODEL, "server": os.environ["RP_LOCAL_LLM_BASE_URL"], "repeats": REPEATS,
           "n_items": len(items), "srcslice_coverage": int(sum(covered)), "with_callees": int(sum(with_callees)),
           "summary": summary, "tests": tests, "gate_passed": bool(gate), "llm_usage": LLMClient.get().stats(),
           "cve_id": [it.cve_id for it in items], "covered": covered, "per_arm": res}
    dst = ROOT / "results" / f"open_ladder_{LLM_MODEL.split('/')[-1]}.json"
    dst.write_text(json.dumps(out, indent=1))
    print(json.dumps({k: out[k] for k in ("model", "srcslice_coverage", "with_callees", "summary", "tests", "gate_passed")}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
