"""e6_info_ladder.py -- what information does repair need? (the information ladder)

Runs, on the 150 Big-Vul and the 56 post-cutoff RQ1 CVEs with the ladder's seeds (42 + repeat; item seed
+ 101 * index) and three repeats, arm A2 (cve_text_rag, served from the frozen cache) and the three
information arms of patch_agent.INFO_ARMS, each A2 plus one kind of information a fix needs, never its code:
  L  location_oracle      the lines of the function the official fix changes (oracle fault localizer)
  M  remedy_message       the fix commit's message, cleaned of code (data/commit_messages.json)
  LM location_and_remedy  both
Per arm and set: VPR with a CVE-level bootstrap CI, touch, outcome shares (validated / right place, wrong
fix / wrong place / unchanged or malformed), line-level precision, recall and F1, and exact Wilcoxon tests
of per-CVE success counts against A2 (Holm over the three contrasts), for VPR and touch; post- vs
pre-cutoff Mann-Whitney U per arm. Items without a commit message (M, LM fall back to A2's prompt) are
counted and M is also reported on the covered items only. The pre-specified predictions are in CLAIMS.md
("information ladder"); this script evaluates them and prints the verdicts.
Writes results/e6_info_ladder.json and results/e6_info_ladder_patches.json.
Usage: python e6_info_ladder.py [--smoke N]   (--smoke: N items, 1 repeat, prints one prompt per arm)
"""

import json
import sys
from pathlib import Path

import numpy as np
from scipy.stats import mannwhitneyu, wilcoxon

import patch_agent
from detectors import LLM_MODEL, LLMClient
from paper_tables import _changed_lines
from rq3_data import build_rq3_corpus
from rq3_postcutoff import load_postcutoff

ROOT = Path(__file__).resolve().parent
RES = ROOT / "results"
ARMS = ["cve_text_rag", *patch_agent.INFO_ARMS]
SHORT = {"cve_text_rag": "A2", "location_oracle": "L", "remedy_message": "M", "location_and_remedy": "LM"}
REPEATS, SEED0, DRAWS = 3, 42, 10_000


def paired_wilcoxon(a, b) -> dict:
    d = np.asarray(a, float) - np.asarray(b, float)
    nz = d[d != 0]
    if len(nz) == 0:
        return {"diff_points": 0.0, "p": 1.0, "n_nonzero": 0, "better": 0, "worse": 0}
    method = "exact" if len(nz) <= 50 else "auto"
    p = float(wilcoxon(nz, method=method).pvalue)
    return {"diff_points": round(100 * float(d.mean()) / REPEATS, 2), "p": p, "n_nonzero": int(len(nz)),
            "better": int((d > 0).sum()), "worse": int((d < 0).sum())}


def holm(ps: list[float]) -> list[float]:
    order = np.argsort(ps); m = len(ps); out = [0.0] * m; running = 0.0
    for rank, i in enumerate(order):
        running = max(running, (m - rank) * ps[i]); out[i] = min(1.0, running)
    return out


def boot_ci(per_cve_counts: np.ndarray, rng: np.random.Generator) -> list[float]:
    n = len(per_cve_counts)
    draws = rng.integers(0, n, size=(DRAWS, n))
    means = per_cve_counts[draws].mean(axis=1) / REPEATS
    return [round(float(np.percentile(means, 2.5)), 4), round(float(np.percentile(means, 97.5)), 4)]


def run_set(name: str, items, repeats: int, smoke: bool) -> tuple[dict, dict]:
    n = len(items)
    rec = {a: {"validated": np.zeros((repeats, n), int), "touch": np.zeros((repeats, n), int),
               "outcome": [[""] * n for _ in range(repeats)], "iterations": np.zeros((repeats, n), int),
               "tp": 0, "np_": 0, "nf": 0} for a in ARMS}
    patches = {a: [[""] * n for _ in range(repeats)] for a in ARMS}
    for r in range(repeats):
        lad = patch_agent.run_ladder(items, seed=SEED0 + r, conditions=ARMS)
        for a in ARMS:
            for i, (it, run) in enumerate(zip(items, lad[a])):
                fix = _changed_lines(it.vulnerable_code, it.official_fixed_code)
                pl = _changed_lines(it.vulnerable_code, run.final_patch) if run.reason != "unchanged" else set()
                touch = bool(fix & pl)
                rec[a]["validated"][r, i] = int(run.validated); rec[a]["touch"][r, i] = int(touch)
                rec[a]["iterations"][r, i] = run.iterations
                rec[a]["outcome"][r][i] = ("validated" if run.validated else
                                           "unchanged_or_malformed" if run.reason == "unchanged" or not pl else
                                           "right_place_wrong_fix" if touch else "wrong_place")
                rec[a]["tp"] += len(fix & pl); rec[a]["np_"] += len(pl); rec[a]["nf"] += len(fix)
                patches[a][r][i] = run.final_patch
        print(f"[e6] {name}: repeat {r + 1}/{repeats} done; {LLMClient.get().stats()}")
        if smoke:
            for a in ARMS:
                print(f"\n----- prompt sample ({SHORT[a]}, {items[0].cve_id}) -----\n"
                      + patch_agent._prompt(items[0], a, "", [])[:2500])
    rng = np.random.default_rng(SEED0)
    summary, tests = {}, {}
    cnt = {a: rec[a]["validated"].sum(axis=0) for a in ARMS}
    tcnt = {a: rec[a]["touch"].sum(axis=0) for a in ARMS}
    for a in ARMS:
        outs = [o for row in rec[a]["outcome"] for o in row]
        pr = rec[a]["tp"] / max(1, rec[a]["np_"]); rc = rec[a]["tp"] / max(1, rec[a]["nf"])
        summary[SHORT[a]] = {
            "vpr": round(100 * float(rec[a]["validated"].mean()), 2), "vpr_ci95": [100 * x for x in boot_ci(cnt[a], rng)],
            "touch": round(100 * float(rec[a]["touch"].mean()), 2),
            "outcomes": {k: round(100 * outs.count(k) / len(outs), 1)
                         for k in ("validated", "right_place_wrong_fix", "wrong_place", "unchanged_or_malformed")},
            "line_precision": round(pr, 3), "line_recall": round(rc, 3),
            "line_f1": round(2 * pr * rc / max(1e-9, pr + rc), 3),
            "mean_iterations": round(float(rec[a]["iterations"].mean()), 2)}
    for metric, c in (("vpr", cnt), ("touch", tcnt)):
        rows = {SHORT[a]: paired_wilcoxon(c[a], c["cve_text_rag"]) for a in patch_agent.INFO_ARMS}
        hp = holm([rows[k]["p"] for k in rows])
        for k, h in zip(rows, hp):
            rows[k]["holm_p"] = h
        tests[f"{metric}_vs_A2"] = rows
    covered = np.array([bool(patch_agent._commit_message(it.cve_id)) for it in items])
    summary["remedy_message_coverage"] = {"items_with_message": int(covered.sum()), "items": n}
    if 0 < covered.sum() < n:
        for a in ("remedy_message", "location_and_remedy"):
            summary[SHORT[a]]["vpr_covered_only"] = round(100 * float(rec[a]["validated"][:, covered].mean()), 2)
            summary[SHORT[a]]["touch_covered_only"] = round(100 * float(rec[a]["touch"][:, covered].mean()), 2)
        summary["A2"]["vpr_covered_only"] = round(100 * float(rec["cve_text_rag"]["validated"][:, covered].mean()), 2)
    per_item = {SHORT[a]: {"validated": rec[a]["validated"].tolist(), "touch": rec[a]["touch"].tolist(),
                           "outcome": rec[a]["outcome"]} for a in ARMS}
    return {"n_items": n, "repeats": repeats, "cve_id": [it.cve_id for it in items], "summary": summary,
            "tests": tests, "per_item": per_item}, {SHORT[a]: patches[a] for a in ARMS}


def main() -> int:
    smoke = int(sys.argv[sys.argv.index("--smoke") + 1]) if "--smoke" in sys.argv else 0
    pre, _ = build_rq3_corpus(n_cves=300, allow_synthetic=False, seed=42)
    post = load_postcutoff()
    repeats = 1 if smoke else REPEATS
    if smoke:
        pre, post = pre[:smoke], post[:max(1, smoke // 2)]
    out, patches = {"model": LLM_MODEL, "arms": {SHORT[a]: a for a in ARMS}}, {}
    for name, items in (("bigvul", pre), ("postcutoff", post)):
        out[name], patches[name] = run_set(name, items, repeats, smoke)
    # post- vs pre-cutoff per arm (CVE-level means), as in rq3_postcutoff
    if not smoke:
        comp = {}
        for a in ARMS:
            k = SHORT[a]
            for metric in ("validated", "touch"):
                x = np.mean(out["postcutoff"]["per_item"][k][metric], axis=0)
                y = np.mean(out["bigvul"]["per_item"][k][metric], axis=0)
                comp[f"{k}_{metric}"] = {"post": round(100 * float(x.mean()), 2), "pre": round(100 * float(y.mean()), 2),
                                         "p": float(mannwhitneyu(x, y, alternative="two-sided").pvalue)}
        hp = holm([v["p"] for v in comp.values()])
        for v, h in zip(comp.values(), hp):
            v["holm_p"] = h
        out["post_vs_pre"] = comp
        s, t = out["bigvul"]["summary"], out["bigvul"]["tests"]
        out["predictions"] = {
            "L_touch_ge_95": s["L"]["touch"] >= 95,
            "L_vpr_gain_le_4": t["vpr_vs_A2"]["L"]["diff_points"] <= 4,
            "M_vpr_gain_ge_10_and_significant": t["vpr_vs_A2"]["M"]["diff_points"] >= 10 and t["vpr_vs_A2"]["M"]["holm_p"] < 0.05,
            "M_gain_ge_5_decision_rule": t["vpr_vs_A2"]["M"]["diff_points"] >= 5 and t["vpr_vs_A2"]["M"]["holm_p"] < 0.05,
            "LM_ge_M": s["LM"]["vpr"] >= s["M"]["vpr"]}
    out["llm_usage"] = LLMClient.get().stats()
    suffix = "_smoke" if smoke else ""
    (RES / f"e6_info_ladder{suffix}.json").write_text(json.dumps(out, indent=1))
    (RES / f"e6_info_ladder_patches{suffix}.json").write_text(json.dumps(patches))
    for name in ("bigvul", "postcutoff"):
        print(f"\n[e6] {name}:")
        for k, v in out[name]["summary"].items():
            print(f"  {k}: {v}")
        print("  tests:", json.dumps(out[name]["tests"]))
    if not smoke:
        print("[e6] post vs pre:", json.dumps(out["post_vs_pre"]))
        print("[e6] predictions:", out["predictions"])
    print("[e6] usage:", out["llm_usage"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
