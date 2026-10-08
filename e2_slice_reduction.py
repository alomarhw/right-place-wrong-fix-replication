"""e2_slice_reduction.py — slicing as input REDUCTION for porting (Mystique/PPatHF-style), RQ4 set.

Arm P4: the agent receives the source fix reduced to srcVul vulnerability slices — for the source
vulnerable and fixed functions, only the lines on which a vulnerability-related variable (vr_var,
occurring in the changed statements) is defined or used, plus the changed lines themselves; gaps
are elided with '...' — together with the full target clone. Compared with P2 (full source
functions) and P3 (full functions + srcVul variable map) from porting_pilot.py, on the same 88 hard
clones, seeds, static feedback, temperature and oracle. Writes results/e2_slice_reduction.json.
"""
import json
import re
from pathlib import Path

import numpy as np

import patch_agent
from detectors import LLMClient, llm_map
from porting_pilot import PORT_SYSTEM, judge, load_targets, REPEATS
from srcvul_ground import srcslice_profiles, vr_stmts


def reduce_to_slices(code: str, changed: list[str], profiles: dict) -> str:
    lines = code.splitlines()
    toks = set(re.findall(r"[A-Za-z_]\w*", " ".join(changed)))
    keep = {0}  # keep the signature line
    for v, p in profiles.items():
        if v in toks:
            keep |= {n - 1 for n in p.defs + p.uses if 1 <= n <= len(lines)}
    cs = {c.strip() for c in changed}
    keep |= {i for i, l in enumerate(lines) if l.strip() in cs}
    out, prev = [], -2
    for i in sorted(keep):
        if i > prev + 1:
            out.append("    ...")
        out.append(lines[i]); prev = i
    if prev < len(lines) - 1:
        out.append("    ...")
    return "\n".join(out)


def prompt(row, red_vuln, red_fixed, previous, feedback):
    s, t = row["source"], row["target"]
    parts = [f"Source branch {s['branch']}, vulnerable function (reduced to its vulnerability slices; "
             f"'...' marks omitted code):\n```c\n{red_vuln}\n```",
             f"Source branch {s['branch']}, fixed function (reduced the same way):\n```c\n{red_fixed}\n```",
             f"Clone to patch (branch {t['branch']}):\n```c\n{t['func_before']}\n```"]
    if feedback:
        parts.append(f"Your previous attempt:\n```c\n{previous}\n```\nIt was rejected by these checks; fix them "
                     "and return the complete patched clone again.\n- " + "\n- ".join(feedback))
    return "\n\n".join(parts)


def main():
    rows = load_targets()
    reds = []
    for r in rows:
        dl, al = vr_stmts(r["source"]["func_before"], r["source"]["func_after"])
        reds.append((reduce_to_slices(r["source"]["func_before"], dl, srcslice_profiles(r["source"]["func_before"])),
                     reduce_to_slices(r["source"]["func_after"], al, srcslice_profiles(r["source"]["func_after"]))))
    ratio = float(np.mean([len(a.splitlines()) / max(1, len(r["source"]["func_before"].splitlines()))
                           for (a, _), r in zip(reds, rows)]))
    client = LLMClient.get()

    def job(args):
        i, rep = args
        r, seed = rows[i], 42 + rep * 1000 + i * 101
        cand, fb = "", []
        for it in range(1, patch_agent.RETRY_BUDGET + 1):
            text = client.complete(PORT_SYSTEM, prompt(r, reds[i][0], reds[i][1], cand, fb), max_tokens=4096,
                                   temperature=patch_agent.PATCH_TEMPERATURE, sample=seed * 10 + it)
            cand = patch_agent._extract_code(text)
            fb = patch_agent._static_feedback(cand, r["target"]["func_before"])
            if not fb:
                break
        return i, rep, judge(cand or r["target"]["func_before"], r)

    val = np.zeros((len(rows), REPEATS), dtype=int)
    for i, rep, j in llm_map(job, [(i, rep) for rep in range(REPEATS) for i in range(len(rows))]):
        val[i, rep] = j["validated"]
    pp = json.load(open("results/porting_pilot.json"))["per_target"]
    p2 = np.array([t["validated"]["P2"] for t in pp]); p3 = np.array([t["validated"]["P3"] for t in pp])
    cves = sorted({r["cve_id"] for r in rows})

    def cve_mean(m):
        return np.array([m[[k for k, r in enumerate(rows) if r["cve_id"] == c]].mean() for c in cves])

    from scipy.stats import wilcoxon
    c4, c2, c3 = cve_mean(val), cve_mean(p2), cve_mean(p3)
    mod = [k for k, r in enumerate(rows) if r["target"]["clone_type"] == "modified"]
    out = {"n_targets": len(rows), "n_cves": len(cves), "mean_reduction_ratio_source_lines": ratio,
           "pooled_vpr": {"P4_slice_reduced": float(val.mean()), "P2": float(p2.mean()), "P3": float(p3.mean())},
           "modified_pooled_vpr": {"P4_slice_reduced": float(val[mod].mean()), "P2": float(p2[mod].mean()),
                                   "P3": float(p3[mod].mean())},
           "cve_level_mean": {"P4": float(c4.mean()), "P2": float(c2.mean()), "P3": float(c3.mean())},
           "cve_level_mean_modified": (lambda cm: {"P4": float(np.mean([val[[k for k in mod if rows[k]["cve_id"] == c]].mean() for c in cm])),
                                                   "n_cves": len(cm)})(sorted({rows[k]["cve_id"] for k in mod})),
           "P4_vs_P2": {"better_worse": [int((c4 > c2).sum()), int((c4 < c2).sum())],
                        "p": float(wilcoxon(c4, c2).pvalue) if np.any(c4 != c2) else 1.0},
           "llm_usage": client.stats()}
    Path("results/e2_slice_reduction.json").write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
