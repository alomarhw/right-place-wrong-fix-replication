"""srcVul retrieval test: build a vulnerability database from the SOURCE fix of every mined clone
family (183 entries: vr_slice vectors per paper Sec. III-A), then for each hard target clone rank the
database by slicing-vector similarity (paper Sec. III-B: cosine; an entry matches when its vr_slices
match target slices at >= 0.8). Score of an entry = mean over its vr_vars of the best cosine to any
target slice vector. Reports top-1 / top-5 retrieval of the correct family. Writes
results/srcvul_retrieval.json. No LLM calls."""
import json
from pathlib import Path
import numpy as np
from srcvul_ground import srcslice_profiles, vs_vector, cosine, vr_stmts
import re

fams = [json.loads(l) for l in open("data/porting/backport_families.jsonl")]
db = []
for k, f in enumerate(fams):
    s = f["source"]
    dl, al = vr_stmts(s["func_before"], s["func_after"])
    pv, pf = srcslice_profiles(s["func_before"]), srcslice_profiles(s["func_after"])
    toks = set(re.findall(r"[A-Za-z_]\w*", " ".join(dl + al)))
    ms = len(s["func_before"].splitlines())
    vecs = [vs_vector(pv.get(v) or pf.get(v), ms) for v in sorted((set(pv) | set(pf)) & toks)]
    db.append({"k": k, "cve": f["cve_id"], "func": f["function"], "vecs": vecs})

res = []
for k, f in enumerate(fams):
    for t in f["targets"]:
        if t["naive_port_equals_official"]:
            continue
        pt = srcslice_profiles(t["func_before"])
        mt = len(t["func_before"].splitlines())
        tv = [vs_vector(p, mt) for p in pt.values()]
        scores = []
        for e in db:
            if not e["vecs"] or not tv:
                scores.append(0.0); continue
            scores.append(float(np.mean([max(cosine(v, w) for w in tv) for v in e["vecs"]])))
        order = np.argsort(-np.array(scores), kind="stable")
        rank = int(np.where(order == k)[0][0]) + 1
        # ties: entries with the same score as the correct one
        ties = int(sum(abs(s - scores[k]) < 1e-12 for s in scores)) - 1
        above = sum(s >= 0.8 for s in scores)
        res.append({"cve": f["cve_id"], "func": f["function"], "branch": t["branch"], "rank": rank,
                    "ties": ties, "score": scores[k], "entries_above_0.8": int(above)})
r = np.array([x["rank"] for x in res])
out = {"db_entries": len(db), "targets": len(res), "top1": float((r == 1).mean()), "top5": float((r <= 5).mean()),
       "median_rank": float(np.median(r)), "median_entries_above_0.8": float(np.median([x["entries_above_0.8"] for x in res])),
       "per_target": res}
Path("results/srcvul_retrieval.json").write_text(json.dumps(out, indent=1))
print({k: v for k, v in out.items() if k != "per_target"})
