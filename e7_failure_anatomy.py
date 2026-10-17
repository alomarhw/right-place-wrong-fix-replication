"""e7_failure_anatomy.py -- why is a right-place patch the wrong fix?

Part A (no model calls). For every rejected patch that touches a line the official fix changes ("right place,
wrong fix"), in arms A0, A2, A4 (replayed from the frozen cache) and L, M, LM (results/e6_info_ladder_patches.json
when present), compare the patch's statement changes with the official fix's:
  hunks        the fix's changed lines grouped into contiguous hunks; how many the patch touches (partial fix =
               touches some but not all);
  edit kind    of the fix and of the patch: guard (only inserted control statements: if/return/goto/break),
               bound (the same statements with only operators or constants changed), call (a function call added,
               removed or changed), other; and whether the kinds match;
  relation     of the two statement multisets: incomplete (patch changes are a proper subset of the fix's),
               overlapping (some shared, some not) or different (nothing shared);
  variables    Jaccard overlap of the identifiers in the fix's added statements and the patch's.
Part B (two LLM raters, as in E4). A five-way codebook on the E4 sample (60 A0 + 60 A4 right-place-wrong-fix
patches, all three repeats) and, when e6 results exist, 60 M patches drawn the same way: incomplete_condition,
wrong_bound_or_operator, wrong_remedy_type, missing_companion_change, different_bug, cannot_tell. Cohen's kappa
between raters; a blind 30-patch sheet (10 per arm) for the human check (results/e7_human_sheet.md/.csv; key kept
apart). Writes results/e7_anatomy.json. Usage: python e7_failure_anatomy.py [--no-raters]
"""

import csv
import difflib
import json
import random
import re
import sys
from collections import Counter
from pathlib import Path

import numpy as np
from scipy.stats import chi2_contingency

import patch_agent
from detectors import LLMClient, llm_map
from e4_judge import kappa
from oracle import _delta
from paper_tables import _changed_lines
from rq3_data import build_rq3_corpus

ROOT = Path(__file__).resolve().parent
RES = ROOT / "results"
BASE = {"A0": "no_grounding_no_feedback", "A2": "cve_text_rag", "A4": "slice_grounded_full"}
REPEATS, SEED0 = 3, 42
RATERS = ("claude-opus-5-5", "claude-opus-4-8")
CATS = ["incomplete_condition", "wrong_bound_or_operator", "wrong_remedy_type", "missing_companion_change",
        "different_bug", "cannot_tell"]
SAMPLE_SEED, PER_REPEAT, HUMAN_PER_ARM = 11, 20, 10
SYSTEM = (
    "You are a security engineer auditing patches for real CVEs in C/C++ code. You are given the CVE description, "
    "the official fix as a diff against the vulnerable function, and a candidate patch as a diff against the same "
    "function. The candidate edits at least one line that the official fix edits, but a strict oracle rejected it "
    "because it does not contain every statement change of the official fix. Explain WHY the candidate is the wrong "
    "fix with exactly one category:\n"
    "  incomplete_condition     - it handles some but not all of the cases the fix handles (e.g. one flag of two, "
    "one branch of two, one of several inputs)\n"
    "  wrong_bound_or_operator  - it changes the right expression but with the wrong bound, constant, operator or "
    "sign\n"
    "  wrong_remedy_type        - it applies a different kind of remedy at the right place (e.g. adds a check or an "
    "early return where the fix changes a computation, a call, or an allocation size; or vice versa)\n"
    "  missing_companion_change - the change at the marked place is right but a second change the fix makes "
    "elsewhere in the function is absent\n"
    "  different_bug            - it fixes something else at the same place and does not address the CVE\n"
    "  cannot_tell              - the code shown does not allow a judgement\n"
    "Judge only from the code shown. Reply with one JSON object and nothing else: "
    '{"category": "<category>", "reason": "<one sentence>"}')


# ---------------------------------------------------------------- Part A: automatic structure
def hunks(idx: set[int]) -> list[tuple[int, int]]:
    out, s = [], None
    for i in sorted(idx):
        if s is None:
            s = e = i
        elif i <= e + 2:
            e = i
        else:
            out.append((s, e)); s = e = i
    if s is not None:
        out.append((s, e))
    return out


_CTRL = re.compile(r"^(if\b|else\b|return\b|goto\b|break\b|continue\b|\}|\{)")
_CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(")


def skeleton(stmt: str) -> str:
    return re.sub(r"\b\d+\b|[<>=!]=?|&&|\|\||[+\-*/%&|^~]|\s+", "", stmt)


def edit_kind(removed: Counter, added: Counter) -> str:
    rem, add = list(removed.elements()), list(added.elements())
    if not rem and add and all(_CTRL.match(s.strip()) or "return" in s for s in add):
        return "guard"
    if rem and add and len(rem) == len(add) and sorted(skeleton(s) for s in rem) == sorted(skeleton(s) for s in add):
        return "bound"
    calls_r = {m for s in rem for m in _CALL.findall(s)} - {"if", "while", "for", "switch", "sizeof", "return"}
    calls_a = {m for s in add for m in _CALL.findall(s)} - {"if", "while", "for", "switch", "sizeof", "return"}
    if calls_r != calls_a:
        return "call"
    return "other"


def idents(stmts) -> set[str]:
    return {t for s in stmts for t in re.findall(r"[A-Za-z_]\w{2,}", s)} - {"int", "char", "return", "NULL", "sizeof",
                                                                            "const", "unsigned", "struct", "goto"}


def anatomy(vuln: str, fixed: str, patch: str) -> dict:
    fix_idx, pat_idx = _changed_lines(vuln, fixed), _changed_lines(vuln, patch)
    hs = hunks(fix_idx)
    covered = sum(1 for s, e in hs if any(s - 1 <= i <= e + 1 for i in pat_idx))
    fr, fa = _delta(vuln, fixed)
    pr, pa = _delta(vuln, patch)
    fset, pset = set(fr.elements()) | set(fa.elements()), set(pr.elements()) | set(pa.elements())
    shared = fset & pset
    relation = ("incomplete" if shared and pset < fset else "different" if not shared else "overlapping")
    fk, pk = edit_kind(fr, fa), edit_kind(pr, pa)
    fi, pi = idents(fa.elements()), idents(pa.elements())
    jac = len(fi & pi) / len(fi | pi) if (fi | pi) else 0.0
    return {"n_hunks": len(hs), "hunks_covered": covered, "partial": 0 < covered < len(hs),
            "fix_kind": fk, "patch_kind": pk, "kind_match": fk == pk, "relation": relation,
            "var_jaccard": round(jac, 3), "fix_stmts": sum(fr.values()) + sum(fa.values()),
            "patch_stmts": sum(pr.values()) + sum(pa.values())}


def udiff(a: str, b: str) -> str:
    return "\n".join(difflib.unified_diff(a.splitlines(), b.splitlines(), "vulnerable", "patched", n=2, lineterm=""))


def parse(text: str) -> dict:
    m = re.search(r"\{.*\}", text or "", re.S)
    try:
        d = json.loads(m.group(0)) if m else {}
    except json.JSONDecodeError:
        d = {}
    cat = d.get("category", "")
    return {"category": cat if cat in CATS else "cannot_tell", "reason": d.get("reason", ""), "raw_ok": cat in CATS}


def main() -> int:
    use_raters = "--no-raters" not in sys.argv
    items, _ = build_rq3_corpus(n_cves=300, allow_synthetic=False, seed=42)
    # patches per arm: (repeat, item) -> final patch, for right-place-wrong-fix cases only
    pools: dict[str, list[dict]] = {}
    for short, cond in BASE.items():
        pools[short] = []
        for r in range(REPEATS):
            lad = patch_agent.run_ladder(items, seed=SEED0 + r, conditions=[cond])
            for i, (it, run) in enumerate(zip(items, lad[cond])):
                off = _changed_lines(it.vulnerable_code, it.official_fixed_code)
                if run.reason != "unchanged" and off & _changed_lines(it.vulnerable_code, run.final_patch) and not run.validated:
                    pools[short].append({"arm": short, "repeat": r + 1, "item": i, "cve_id": it.cve_id, "patch": run.final_patch})
    e6p = RES / "e6_info_ladder_patches.json"
    if e6p.exists():
        pat = json.loads(e6p.read_text())["bigvul"]
        e6 = json.loads((RES / "e6_info_ladder.json").read_text())["bigvul"]["per_item"]
        for short in ("L", "M", "LM"):
            pools[short] = [{"arm": short, "repeat": r + 1, "item": i, "cve_id": items[i].cve_id, "patch": pat[short][r][i]}
                            for r in range(REPEATS) for i in range(len(items))
                            if e6[short]["outcome"][r][i] == "right_place_wrong_fix"]
    res = {"part_a": {}, "pools": {k: len(v) for k, v in pools.items()}}
    rel_table = {}
    for short, pool in pools.items():
        rows = [anatomy(items[p["item"]].vulnerable_code, items[p["item"]].official_fixed_code, p["patch"]) for p in pool]
        for p, a in zip(pool, rows):
            p["anatomy"] = a
        n = max(1, len(rows))
        res["part_a"][short] = {
            "n": len(rows),
            "partial_hunk_share": round(100 * sum(a["partial"] for a in rows) / n, 1),
            "multi_hunk_fix_share": round(100 * sum(a["n_hunks"] > 1 for a in rows) / n, 1),
            "relation": {k: round(100 * sum(a["relation"] == k for a in rows) / n, 1) for k in ("incomplete", "overlapping", "different")},
            "fix_kind": dict(Counter(a["fix_kind"] for a in rows)),
            "patch_kind": dict(Counter(a["patch_kind"] for a in rows)),
            "kind_match_share": round(100 * sum(a["kind_match"] for a in rows) / n, 1),
            "mean_var_jaccard": round(float(np.mean([a["var_jaccard"] for a in rows])) if rows else 0.0, 3),
            "median_fix_stmts": float(np.median([a["fix_stmts"] for a in rows])) if rows else 0.0,
            "median_patch_stmts": float(np.median([a["patch_stmts"] for a in rows])) if rows else 0.0}
        rel_table[short] = [sum(a["relation"] == k for a in rows) for k in ("incomplete", "overlapping", "different")]
    if all(k in rel_table for k in ("A0", "A4")):
        chi, p, _, _ = chi2_contingency([rel_table["A0"], rel_table["A4"]])
        res["part_a"]["A0_vs_A4_relation_chi2"] = {"chi2": round(float(chi), 2), "p": float(p)}

    # ---------------------------------------------------------------- Part B: codebook
    if use_raters:
        e4 = json.loads((RES / "e4_allrepeats.json").read_text())["items"]
        key = {("A0" if x["arm"] == "no_grounding_no_feedback" else "A4", x["repeat"], x["item"]) for x in e4}
        sample = [p for s in ("A0", "A4") for p in pools[s] if (s, p["repeat"], p["item"]) in key]
        if "M" in pools:
            rng = random.Random(SAMPLE_SEED)
            for r in range(1, REPEATS + 1):
                cand = [p for p in pools["M"] if p["repeat"] == r]
                sample += rng.sample(cand, min(PER_REPEAT, len(cand)))
        client = LLMClient.get()

        def ask(args):
            p, model = args
            it = items[p["item"]]
            user = (f"CVE {it.cve_id}: {patch_agent._cve_text(it.cve_id)[:400]}\n\nOfficial fix:\n```diff\n"
                    f"{udiff(it.vulnerable_code, it.official_fixed_code)}\n```\n\nCandidate patch:\n```diff\n"
                    f"{udiff(it.vulnerable_code, p['patch'])}\n```")
            out = parse(client.complete(SYSTEM, user, max_tokens=300, temperature=None, model=model))
            if not out["raw_ok"]:
                out = parse(client.complete(SYSTEM, user, max_tokens=1500, temperature=None, model=model))
            return out

        labels = {m: llm_map(ask, [(p, m) for p in sample]) for m in RATERS}
        for k, p in enumerate(sample):
            p["labels"] = {m: labels[m][k]["category"] for m in RATERS}
            p["reasons"] = {m: labels[m][k]["reason"] for m in RATERS}
        part_b = {"raters": RATERS, "n": len(sample), "arms": {}}
        for short in sorted({p["arm"] for p in sample}):
            s = [p for p in sample if p["arm"] == short]
            a, b = [p["labels"][RATERS[0]] for p in s], [p["labels"][RATERS[1]] for p in s]
            part_b["arms"][short] = {"n": len(s), "counts": {m: dict(Counter(p["labels"][m] for p in s)) for m in RATERS},
                                     "agreement": round(sum(x == y for x, y in zip(a, b)) / len(a), 3),
                                     "kappa": round(kappa(a, b, CATS), 3)}
        a, b = [p["labels"][RATERS[0]] for p in sample], [p["labels"][RATERS[1]] for p in sample]
        part_b["pooled_kappa"] = round(kappa(a, b, CATS), 3)
        part_b["items"] = [{k: p[k] for k in ("arm", "repeat", "item", "cve_id", "labels", "reasons")} for p in sample]
        res["part_b"] = part_b
        # blind human sheet: 10 per arm, shuffled; key kept apart
        human = []
        for short in sorted({p["arm"] for p in sample}):
            human += random.Random(SAMPLE_SEED).sample([p for p in sample if p["arm"] == short], HUMAN_PER_ARM)
        random.Random(SAMPLE_SEED).shuffle(human)
        md = ["# Why is the fix wrong? Blind check of right-place-wrong-fix patches\n",
              "For each case read the CVE, the official fix and the candidate patch, and write ONE category in "
              "results/e7_human_labels.csv: incomplete_condition (handles some but not all cases), "
              "wrong_bound_or_operator, wrong_remedy_type (a different kind of remedy at the right place), "
              "missing_companion_change (the marked change is right, a second change elsewhere is absent), "
              "different_bug (fixes something else), cannot_tell. The arm and repeat are hidden.\n"]
        for k, p in enumerate(human, 1):
            it = items[p["item"]]; p["case"] = f"W{k:02d}"
            md.append(f"## {p['case']}. {it.cve_id}\n\nCVE: {patch_agent._cve_text(it.cve_id)[:400]}\n")
            md.append("### Official fix\n```diff\n" + udiff(it.vulnerable_code, it.official_fixed_code) + "\n```\n")
            md.append("### Candidate patch\n```diff\n" + udiff(it.vulnerable_code, p["patch"]) + "\n```\n")
        (RES / "e7_human_sheet.md").write_text("\n".join(md))
        with open(RES / "e7_human_labels.csv", "w", newline="") as fh:
            w = csv.writer(fh); w.writerow(["case", "cve_id", "category", "note"])
            for p in human:
                w.writerow([p["case"], p["cve_id"], "", ""])
        (RES / "e7_human_key_DO_NOT_OPEN.json").write_text(json.dumps(
            [{"case": p["case"], "arm": p["arm"], "repeat": p["repeat"], "item": p["item"], "labels": p["labels"]} for p in human], indent=1))
    res["llm_usage"] = LLMClient.get().stats()
    (RES / "e7_anatomy.json").write_text(json.dumps(res, indent=1))
    print("[e7] pools:", res["pools"])
    for k, v in res["part_a"].items():
        print(f"[e7] {k}: {v}")
    if use_raters:
        print("[e7] codebook:", json.dumps({k: v for k, v in res["part_b"].items() if k != "items"}))
    print("[e7] usage:", res["llm_usage"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
