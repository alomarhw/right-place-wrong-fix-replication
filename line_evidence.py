"""line_evidence.py — line-level evidence scoring of patches (cf. VulContextBench's P/R/F1 over gold
context): the lines an agent's patch modifies vs. the lines the official fix modifies, micro-averaged
over all patches (unchanged patches contribute no edited lines). RQ1: 150 Big-Vul CVEs x 3 repeats x 5
arms. RQ4: 88 hard clones (repeat 1 candidates stored by porting_pilot.py, plus P0). Served from the
LLM response cache; writes results/line_evidence.json."""
import json, sys
from pathlib import Path
from paper_tables import _changed_lines
from patch_agent import run_ladder, LADDER
from rq3_data import build_rq3_corpus
from detectors import LLMClient

def prf(pairs):
    inter = sum(len(a & f) for a, f in pairs); na = sum(len(a) for a, _ in pairs); nf = sum(len(f) for _, f in pairs)
    p = inter / na if na else 0.0; r = inter / nf if nf else 0.0
    return {"precision": p, "recall": r, "f1": 2 * p * r / (p + r) if p + r else 0.0}

out = {"rq1": {}, "rq4": {}}
items, _ = build_rq3_corpus(n_cves=300, allow_synthetic=False, seed=42)
off = [_changed_lines(i.vulnerable_code, i.official_fixed_code) for i in items]
acc = {c: [] for c in LADDER}
for r in range(3):
    lad = run_ladder(items, seed=42 + r)
    for c in LADDER:
        for i, (it, run) in enumerate(zip(items, lad[c])):
            a = set() if run.reason == "unchanged" else _changed_lines(it.vulnerable_code, run.final_patch)
            acc[c].append((a, off[i]))
out["rq1"] = {c: prf(v) for c, v in acc.items()}

sys.path.insert(0, str(Path(__file__).resolve().parent / "mining"))
from mine_backports import naive_port
pp = json.load(open("results/porting_pilot.json"))["per_target"]
fam = {}
for ln in open("data/porting/backport_families.jsonl"):
    f = json.loads(ln)
    for t in f["targets"]:
        fam[(f["cve_id"], f["function"], t["branch"])] = (f, t)
p4 = {"P0": [], "P2": [], "P3": []}
for t in pp:
    f, tg = fam[(t["cve_id"], t["function"], t["target_branch"])]
    F = _changed_lines(tg["func_before"], tg["func_after"])
    ok, ported = naive_port(f["source"]["func_before"], f["source"]["func_after"], tg["func_before"])
    p4["P0"].append((_changed_lines(tg["func_before"], ported) if ok else set(), F))
    for a in ("P2", "P3"):
        p4[a].append((_changed_lines(tg["func_before"], t["rep1_candidate"][a]), F))
out["rq4"] = {a: prf(v) for a, v in p4.items()}
out["llm_usage"] = LLMClient.get().stats()
Path("results/line_evidence.json").write_text(json.dumps(out, indent=1))
for k in ("rq1", "rq4"):
    for a, m in out[k].items():
        print(f"{k} {a:28s} P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f}")
print(out["llm_usage"])
