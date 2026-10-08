"""porting_pilot.py — pilot: porting a known CVE fix to a vulnerable clone vs. inventing one.

Benchmark: the 'hard' cross-branch clones from data/porting/backport_families.jsonl (mining/mine_backports.py) — targets where the
source branch's fix does NOT reproduce the target's official fix by plain line-patching.

Arms (the same independent oracle judges every arm against the TARGET's official fix):
  P0  naive patch      source fix applied as an exact-context line patch (deterministic)
  P1  invent           patch_agent arm A0 (target function only)            — paper's agent
  P1b invent + CVE     patch_agent arm A2 (CVE text, static feedback <= 5)  — paper's agent
  P2  port             source vulnerable+fixed functions + target; static feedback <= 5
  P3  port + srcVul    P2 + srcVul grounding (vr_stmts, vr_vars mapped by slicing-vector cosine,
                       target slice lines; real srcML/srcSlice)
3 repeats; temperature 0.7; every response cached (data/_llm_cache.sqlite).
Writes results/porting_pilot.json.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.request
from pathlib import Path

import numpy as np

import patch_agent
from detectors import LLMClient, llm_map
from oracle import independent_oracle
from paper_tables import _changed_lines
from rq3_data import CVEPatchItem
from srcvul_ground import ground, render

sys.path.insert(0, str(Path(__file__).resolve().parent / "mining"))
from mine_backports import naive_port  # noqa: E402

FAM = Path("data") / "porting" / "backport_families.jsonl"
OUT = Path("results") / "porting_pilot.json"
REPEATS = 3
PORT_SYSTEM = (
    "You are a security engineer backporting a vulnerability fix. You are given the vulnerable and "
    "fixed versions of a function from one release branch, and a clone of the vulnerable function "
    "from another release branch. Apply the same fix to the clone, adapting it to the clone's code "
    "(names, APIs and surrounding statements may differ). Change nothing else. Return ONLY the "
    "complete patched clone in a single ```c code block.")


def cve_description(cve: str) -> str:
    for _ in range(3):
        try:
            with urllib.request.urlopen(f"https://cveawg.mitre.org/api/cve/{cve}", timeout=30) as r:
                d = json.load(r)
            cna = d.get("containers", {}).get("cna", {})
            return next((x.get("value", "") for x in cna.get("descriptions", []) if x.get("lang", "").startswith("en")), "")
        except Exception:  # noqa: BLE001
            time.sleep(2)
    return ""


def load_targets():
    rows = []
    for ln in FAM.read_text().splitlines():
        f = json.loads(ln)
        for t in f["targets"]:
            if not t["naive_port_equals_official"]:
                rows.append({"cve_id": f["cve_id"], "project": f["project"], "function": f["function"],
                             "source": f["source"], "target": t})
    return rows


def port_prompt(row, grounding: str | None, previous: str, feedback: list[str]) -> str:
    s, t = row["source"], row["target"]
    parts = [f"Source branch {s['branch']}, vulnerable function:\n```c\n{s['func_before']}\n```",
             f"Source branch {s['branch']}, fixed function:\n```c\n{s['func_after']}\n```",
             f"Clone to patch (branch {t['branch']}):\n```c\n{t['func_before']}\n```"]
    if grounding:
        parts.append(grounding)
    if feedback:
        parts.append(f"Your previous attempt:\n```c\n{previous}\n```\nIt was rejected by these checks; fix them "
                     "and return the complete patched clone again.\n- " + "\n- ".join(feedback))
    return "\n\n".join(parts)


def run_port(row, grounding, seed) -> str:
    client = LLMClient.get()
    cand, fb = "", []
    for it in range(1, patch_agent.RETRY_BUDGET + 1):
        text = client.complete(PORT_SYSTEM, port_prompt(row, grounding, cand, fb), max_tokens=4096,
                               temperature=patch_agent.PATCH_TEMPERATURE, sample=seed * 10 + it)
        cand = patch_agent._extract_code(text)
        fb = patch_agent._static_feedback(cand, row["target"]["func_before"])
        if not fb:
            break
    return cand or row["target"]["func_before"]


def judge(cand: str, row) -> dict:
    t = row["target"]
    v = independent_oracle(cand, t["func_after"], t["func_before"])
    off = _changed_lines(t["func_before"], t["func_after"])
    touch = bool(off & _changed_lines(t["func_before"], cand)) if v.reason != "unchanged" else False
    return {"validated": bool(v.validated), "reason": v.reason, "touch": touch}


def main() -> None:
    rows = load_targets()
    descs = {c: cve_description(c) for c in sorted({r["cve_id"] for r in rows})}
    patch_agent._cve_text("")  # initialise the module cache, then add the backport CVEs
    patch_agent._CVE_TEXT.update({k: v for k, v in descs.items() if v})
    groundings = [ground(r["source"]["func_before"], r["source"]["func_after"], r["target"]["func_before"]) for r in rows]
    print(f"[pilot] {len(rows)} hard targets, {len(descs)} CVEs; srcVul detects {sum(g['detected'] for g in groundings)}")

    res = {a: np.zeros((len(rows), REPEATS), dtype=int) for a in ("P0", "P1", "P1b", "P2", "P3")}
    touch = {a: np.zeros((len(rows), REPEATS), dtype=int) for a in res}
    reasons = {a: [] for a in res}
    cands = {a: [None] * len(rows) for a in res}
    for i, r in enumerate(rows):  # P0 deterministic
        ok, ported = naive_port(r["source"]["func_before"], r["source"]["func_after"], r["target"]["func_before"])
        j = judge(ported if ok else r["target"]["func_before"], r)
        res["P0"][i, :] = j["validated"]; touch["P0"][i, :] = j["touch"]; reasons["P0"].append(j["reason"])

    def job(args):
        i, rep, arm = args
        r, seed = rows[i], 42 + rep * 1000 + i * 101
        item = CVEPatchItem(cve_id=r["cve_id"], cwe="", vulnerable_code=r["target"]["func_before"],
                            official_fixed_code=r["target"]["func_after"])
        if arm == "P1":
            cand = patch_agent.run_agent_on_item(item, "no_grounding_no_feedback", seed).final_patch
        elif arm == "P1b":
            cand = patch_agent.run_agent_on_item(item, "cve_text_rag", seed).final_patch
        elif arm == "P2":
            cand = run_port(r, None, seed)
        else:
            cand = run_port(r, render(groundings[i]), seed)
        return i, rep, arm, {**judge(cand, r), "cand": cand}

    jobs = [(i, rep, arm) for rep in range(REPEATS) for i in range(len(rows)) for arm in ("P1", "P1b", "P2", "P3")]
    for i, rep, arm, j in llm_map(job, jobs):
        res[arm][i, rep] = j["validated"]; touch[arm][i, rep] = j["touch"]
        if rep == 0:
            reasons[arm].append(j["reason"])
            cands[arm][i] = j["cand"]
    print(f"[pilot] LLM usage: {LLMClient.get().stats()}")

    from scipy.stats import wilcoxon
    summary = {}
    for a in res:
        summary[a] = {"vpr": float(res[a].mean()), "touch": float(touch[a].mean()),
                      "cves_ever_validated": int((res[a].sum(1) > 0).sum())}
    for a in ("P1", "P1b", "P2", "P3"):
        for b in ("P2", "P3"):
            if a == b or (a, b) == ("P3", "P2"):
                continue
            d = res[b].sum(1) - res[a].sum(1)
            summary[f"{b}_vs_{a}_wilcoxon_p"] = float(wilcoxon(res[b].sum(1), res[a].sum(1)).pvalue) if np.any(d) else 1.0
    by_type = {}
    for ct in ("identical", "renamed", "modified"):
        idx = [k for k, r in enumerate(rows) if r["target"]["clone_type"] == ct]
        if idx:
            by_type[ct] = {"n": len(idx), **{a: float(res[a][idx].mean()) for a in res}}
    out = {"n_targets": len(rows), "n_cves": len(descs), "repeats": REPEATS, "summary": summary,
           "by_clone_type": by_type, "srcvul_detected": int(sum(g["detected"] for g in groundings)),
           "reasons_rep1": {a: {k: reasons[a].count(k) for k in set(reasons[a])} for a in reasons},
           "llm_usage": LLMClient.get().stats(),
           "per_target": [{"cve_id": r["cve_id"], "project": r["project"], "function": r["function"],
                           "source_branch": r["source"]["branch"], "target_branch": r["target"]["branch"],
                           "clone_type": r["target"]["clone_type"],
                           "validated": {a: res[a][k].tolist() for a in res},
                           "touch": {a: touch[a][k].tolist() for a in res},
                           "rep1_candidate": {a: cands[a][k] for a in ("P2", "P3")}}
                          for k, r in enumerate(rows)]}
    OUT.write_text(json.dumps(out, indent=1))
    for a in res:
        print(f"  {a:4s} VPR={summary[a]['vpr']:.3f} touch={summary[a]['touch']:.3f} "
              f"CVE-targets ever validated={summary[a]['cves_ever_validated']}/{len(rows)}")
    print(json.dumps({k: v for k, v in summary.items() if k.endswith("_p")}, indent=0))
    print(json.dumps(by_type, indent=0))


if __name__ == "__main__":
    main()
