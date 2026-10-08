"""e3_cross_model.py — do the repair (RQ1) and porting (RQ4) conclusions hold for a stronger model?

Re-runs repeat 1 of the key arms with the model given by RP_LLM_MODEL (set it before running), using
the unchanged agent loop, prompts, seeds, oracle and corpora:
  RQ1 (150 Big-Vul CVEs): no_grounding_no_feedback, cve_text_rag, slice_grounded_full
  RQ4 (88 hard clones)  : P1 invent (no grounding) and P2 port the known fix
Run once per model; the claude-haiku-4-5 run is served entirely from the frozen cache. The paired
comparison across models is done by e3_compare.py. Writes results/e3_<model>.json.
"""
import json
import sys
from pathlib import Path

import patch_agent
from detectors import LLM_MODEL, LLMClient, llm_map
from paper_tables import _changed_lines
from rq3_data import build_rq3_corpus, CVEPatchItem

sys.path.insert(0, str(Path(__file__).resolve().parent / "mining"))
import porting_pilot as pp  # noqa: E402

RQ1_ARMS = ["no_grounding_no_feedback", "cve_text_rag", "slice_grounded_full"]


def rq1():
    items, _ = build_rq3_corpus(n_cves=300, allow_synthetic=False, seed=42)
    jobs = [(i, it, a) for i, it in enumerate(items) for a in RQ1_ARMS]
    # seed as in patch_agent.run_ladder for repeat 1 (seed=42): 42 + item_index * 101
    runs = llm_map(lambda j: (j, patch_agent.run_agent_on_item(j[1], j[2], seed=42 + j[0] * 101)), jobs)
    out = {a: {"validated": [], "touch": [], "reason": []} for a in RQ1_ARMS}
    for (i, it, a), run in runs:
        off = _changed_lines(it.vulnerable_code, it.official_fixed_code)
        touch = run.reason != "unchanged" and bool(off & _changed_lines(it.vulnerable_code, run.final_patch))
        out[a]["validated"].append(int(run.validated)); out[a]["touch"].append(int(touch))
        out[a]["reason"].append(run.reason)
    out["cve_id"] = [it.cve_id for it in items]
    return out


def rq4():
    rows = pp.load_targets()
    descs = {c: pp.cve_description(c) for c in sorted({r["cve_id"] for r in rows})}
    patch_agent._cve_text("")
    patch_agent._CVE_TEXT.update({k: v for k, v in descs.items() if v})

    def job(args):
        i, arm = args
        r, seed = rows[i], 42 + i * 101  # repeat 1 seed, as in porting_pilot.main
        if arm == "P1":
            item = CVEPatchItem(cve_id=r["cve_id"], cwe="", vulnerable_code=r["target"]["func_before"],
                                official_fixed_code=r["target"]["func_after"])
            cand = patch_agent.run_agent_on_item(item, "no_grounding_no_feedback", seed).final_patch
        else:
            cand = pp.run_port(r, None, seed)
        return i, arm, pp.judge(cand, r)

    out = {a: {"validated": [0] * len(rows), "touch": [0] * len(rows)} for a in ("P1", "P2")}
    for i, arm, j in llm_map(job, [(i, a) for i in range(len(rows)) for a in ("P1", "P2")]):
        out[arm]["validated"][i] = int(j["validated"]); out[arm]["touch"][i] = int(j["touch"])
    out["cve_id"] = [r["cve_id"] for r in rows]
    out["project"] = [r["project"] for r in rows]
    out["clone_type"] = [r["target"].get("clone_type", "") for r in rows]
    return out


def main():
    res = {"model": LLM_MODEL, "rq1": rq1(), "rq4": rq4(), "llm_usage": LLMClient.get().stats()}
    dst = Path("results") / f"e3_{LLM_MODEL}.json"
    dst.write_text(json.dumps(res, indent=1))
    for a in RQ1_ARMS:
        v, t = res["rq1"][a]["validated"], res["rq1"][a]["touch"]
        print(f"RQ1 {a:26s} VPR={sum(v) / len(v):.3f} touch={sum(t) / len(t):.3f}")
    for a in ("P1", "P2"):
        v = res["rq4"][a]["validated"]
        print(f"RQ4 {a} VPR={sum(v) / len(v):.3f}")
    print(res["llm_usage"])


if __name__ == "__main__":
    main()
