"""paper_tables.py — publication tables from the measured results (no new experiments).

Inputs: results/results.json, data/*/*_pairs.jsonl, and — for the RQ3 patch analysis — a replay of
ladder repeat 1 served from the LLM response cache (data/_llm_cache.sqlite; already-cached
responses cost nothing). Writes results/tables/paper/T{1..5}_*.csv and .tex (booktabs) plus
results/tables/paper/SUMMARY.md.

  T1 dataset composition          T2 RQ1 by CWE and by source
  T3 RQ1 pairwise analysis        T4 RQ3 outcome per ladder arm
  T5 RQ3 patch vs official fix (localization, edit size)
"""
from __future__ import annotations

import collections
import difflib
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent
RES = ROOT / "results"
OUT = RES / "tables" / "paper"

LLM_KEYS = {
    "Open-weight instruct LLM detector (e.g., StarCoder2/CodeLlama, elatoubi2025assessing-style prompting)": "Instruct",
    "RAG-based LLM vulnerability detector (antal2026evaluating / kaniewski2026revisiting style)": "RAG",
    "Ungrounded LLM patching (same LLM, no slice/CVE grounding) \u2014 primary RQ3 baseline": "Ungrounded",
}
OTHER_KEYS = {
    "VUDDY hashing-based vulnerable clone detector (from VUDDY corpus / salimi2022vulslicer comparison)": "VUDDY",
    "lexical_recall_control": "Lexical recall",
    "VulPecker code-similarity vulnerability detector (li2016vulpecker)": "VulPecker",
    "finetuned_encoder_llm": "TF-IDF + LR",
    "slice_matcher_src_vul": "SRC VUL slice",
    "VulSlicer slice-based detector (salimi2022vulslicer)": "VulSlicer",
}
ARMS = [("no_grounding_no_feedback", "Ungrounded"), ("compiler_test_feedback", "+ static feedback"),
        ("cve_text_rag", "+ CVE text"), ("slice_grounded_no_feedback", "+ CVE text + slice"),
        ("slice_grounded_full", "Full agent")]


def wilson(k, n, z=1.96):
    if n == 0:
        return float("nan"), float("nan"), float("nan")
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0.0, c - h), min(1.0, c + h)


def fmt_ci(k, n):
    p, lo, hi = wilson(k, n)
    return f"{p:.2f} [{lo:.2f}, {hi:.2f}]" if n else "--"


def md(df: pd.DataFrame) -> str:
    cols = [str(c) for c in df.columns]
    lines = ["| " + " | ".join(cols) + " |", "|" + "|".join("---" for _ in cols) + "|"]
    lines += ["| " + " | ".join(str(v) for v in row) + " |" for row in df.itertuples(index=False)]
    return "\n".join(lines)


def write(df: pd.DataFrame, name: str, caption: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUT / f"{name}.csv", index=False)
    cols = "l" + "r" * (len(df.columns) - 1)
    body = df.to_latex(index=False, escape=True, column_format=cols)
    body = body.replace("\\toprule", "\\toprule").replace("\\midrule", "\\midrule")
    tex = ("\\begin{table}[t]\n\\centering\\small\n"
           f"\\caption{{{caption}}}\n\\label{{tab:{name.split('_')[0].lower()}}}\n{body}\\end{{table}}\n")
    (OUT / f"{name}.tex").write_text(tex)
    print(f"[paper_tables] wrote {OUT / name}.{{csv,tex}}")


def load_pairs() -> dict:
    meta = {}
    # the two source files only (data/cve_patches/ is a derived copy without provenance/project)
    for p in (Path("data/bigvul/bigvul_pairs.jsonl"), Path("data/postcutoff/postcutoff_pairs.jsonl")):
        if not p.exists():
            continue
        for ln in p.read_text().splitlines():
            r = json.loads(ln)
            meta.setdefault(r["cve_id"], r)
    return meta


def matched_items(seed: int):
    """RQ1 matched items in the order invariance_contrast used (same matching rule)."""
    from data_prep import build_corpus
    from variant_builder import build_certified_variants
    items, _ = build_corpus(n_cves=300, allow_synthetic=False, seed=42)
    variants, _ = build_certified_variants(items, seed=seed)
    used, out = set(), []
    for it in items:
        for v in variants:
            if id(v) in used:
                continue
            if v.cve_id == it.cve_id and v.label == it.label and v.provenance == it.provenance:
                out.append(it)
                used.add(id(v))
                break
    return out


# ---------------------------------------------------------------------------
def t1_dataset(meta: dict) -> str:
    rows = []
    for src, prov in (("Big-Vul", "pre_cutoff"), ("Mined (post-cutoff)", "post_cutoff")):
        rs = [r for r in meta.values() if r.get("provenance") == prov]
        if not rs:
            continue
        loc = [r["func_before"].count("\n") + 1 for r in rs]
        projects = collections.Counter(r.get("project", "?") for r in rs)
        cwes = collections.Counter(r.get("cwe") or "unknown" for r in rs)
        years = [int(str(r.get("cve_year") or r.get("cve_published", "0"))[:4] or 0) for r in rs]
        rows.append({
            "Source": src, "CVE pairs": len(rs), "Projects": len(projects),
            "Top projects": ", ".join(f"{k} ({v})" for k, v in projects.most_common(3)),
            "Distinct CWEs": len(cwes),
            "Top CWEs": ", ".join(f"{k} ({v})" for k, v in cwes.most_common(3)),
            "LOC median [IQR]": f"{int(np.median(loc))} [{int(np.percentile(loc, 25))}-{int(np.percentile(loc, 75))}]",
            "CVE years": f"{min(y for y in years if y)}-{max(years)}" if any(years) else "--",
        })
    df = pd.DataFrame(rows)
    write(df, "T1_dataset", "Dataset composition. Each CVE contributes its vulnerable function "
          "(label 1) and the official fixed function (label 0).")
    return md(df)


def t2_t3_rq1(r1: dict, meta: dict) -> tuple[str, str]:
    items = matched_items(seed=42 + int(r1.get("repeats", 3)) - 1)
    per = r1["per_detector"]
    n = len(items)
    labels = np.array([it.label for it in items])
    cwe = np.array([it.cwe if it.cwe else "unknown" for it in items])
    common = {c for c, k in collections.Counter(cwe).items() if k >= 20}
    cwe_g = np.array([c if c in common else "Other CWEs" for c in cwe])
    src = np.array(["Big-Vul (seen)" if it.provenance == "seen" else
                    f"{meta.get(it.cve_id, {}).get('project', '?')} (unseen)" for it in items])
    src_g = np.array([s if s.startswith("Big-Vul") or s.startswith("openssl") else "other unseen"
                      for s in src])

    def correct(key, split):
        v = np.array(per[key]["verbatim_correct" if split == "v" else "variant_correct"], dtype=bool)
        assert len(v) == n, (key, len(v), n)
        return v

    # T2 — LLM verbatim accuracy by stratum (pooled over the 3 prompts) + VUDDY gap
    rows = []
    for dim, groups in (("CWE", cwe_g), ("Source", src_g)):
        for g in sorted(set(groups), key=lambda x: (x.startswith("Other") or x == "other unseen", x)):
            m = groups == g
            k_llm = sum(int(correct(key, "v")[m].sum()) for key in LLM_KEYS)
            n_llm = int(m.sum()) * len(LLM_KEYS)
            vk = "VUDDY hashing-based vulnerable clone detector (from VUDDY corpus / salimi2022vulslicer comparison)"
            gap_v = correct(vk, "v")[m].mean() - correct(vk, "t")[m].mean()
            gap_l = np.mean([correct(key, "v")[m].mean() - correct(key, "t")[m].mean() for key in LLM_KEYS])
            rows.append({"Stratum": dim, "Group": g, "n functions": int(m.sum()),
                         "LLM accuracy (pooled) [95% CI]": fmt_ci(k_llm, n_llm),
                         "LLM gap": f"{gap_l:+.2f}", "VUDDY gap": f"{gap_v:+.2f}"})
    t2 = pd.DataFrame(rows)
    write(t2, "T2_rq1_strata", "RQ1 by CWE and by source (matched functions, last repeat). LLM accuracy "
          "is pooled over the three prompting regimes; gap = accuracy(verbatim) - accuracy(variant).")

    # T3 — pairwise: CVEs whose vulnerable AND fixed function are both in the matched set
    by_cve = collections.defaultdict(dict)
    for i, it in enumerate(items):
        by_cve[it.cve_id][it.label] = i
    pairs = [(d[1], d[0]) for d in by_cve.values() if 1 in d and 0 in d]
    rows = []
    for key, name in list(LLM_KEYS.items()) + list(OTHER_KEYS.items()):
        cv = correct(key, "v")
        pred = np.where(cv, labels, 1 - labels)
        both = sum(bool(pred[b] == 1 and pred[a] == 0) for b, a in pairs)
        both_vuln = sum(bool(pred[b] == 1 and pred[a] == 1) for b, a in pairs)
        both_safe = sum(bool(pred[b] == 0 and pred[a] == 0) for b, a in pairs)
        rev = len(pairs) - both - both_vuln - both_safe
        rows.append({"Detector": name, "Positive rate": f"{pred.mean():.2f}",
                     "Pair-correct [95% CI]": fmt_ci(both, len(pairs)),
                     "Both vulnerable": both_vuln, "Both safe": both_safe, "Reversed": rev,
                     "Pairs": len(pairs)})
    t3 = pd.DataFrame(rows)
    write(t3, "T3_rq1_pairwise", "RQ1 pairwise analysis on verbatim functions: a CVE is pair-correct "
          "when the vulnerable version is flagged and its official fix is not. Positive rate = share of "
          "functions predicted vulnerable. The non-LLM detectors are fitted on these same verbatim "
          "functions (by design, as the memorization control), so their verbatim scores measure recall "
          "of their training data; the LLM detectors are not trained on them.")
    return md(t2), md(t3)


def _changed_lines(a: str, b: str) -> set[int]:
    """Indices of lines in `a` that are deleted or replaced on the way to `b` (+ insertion anchors)."""
    al, bl = [l.strip() for l in a.splitlines()], [l.strip() for l in b.splitlines()]
    out = set()
    for tag, i1, i2, _, _ in difflib.SequenceMatcher(None, al, bl, autojunk=False).get_opcodes():
        if tag in ("replace", "delete"):
            out.update(range(i1, i2))
        elif tag == "insert":
            out.add(max(0, i1 - 1))
    return out


def _edit_size(a: str, b: str) -> int:
    return sum(1 for d in difflib.ndiff([l.strip() for l in a.splitlines()],
                                        [l.strip() for l in b.splitlines()]) if d[:1] in "+-")


def t4_t5_rq3(r3: dict) -> tuple[str, str]:
    from detectors import LLMClient
    from patch_agent import run_ladder
    from rq3_data import build_rq3_corpus
    items, _ = build_rq3_corpus(n_cves=300, allow_synthetic=False, seed=42)
    lad = run_ladder(items, seed=42)
    print(f"[paper_tables] RQ3 replay LLM usage: {LLMClient.get().stats()}")
    per = r3["_rq3_e2_ladder"]["per_condition"]

    rows4, rows5 = [], []
    for key, name in ARMS:
        runs = lad[key]
        c = collections.Counter(r.reason for r in runs)
        val = c["equivalent_to_official_fix"] + c["covers_official_fix_changes"]
        v = per[key]
        rows4.append({"Arm": name,
                      "VPR (3 reps) [95% CI]": f"{v['validated_patch_rate_vpr']:.3f} "
                                              f"[{v['vpr_wilson_ci'][0]:.3f}, {v['vpr_wilson_ci'][1]:.3f}]",
                      "Validated (rep. 1)": val, "Exact official fix": c["equivalent_to_official_fix"],
                      "Misses fix changes": c["missing_official_fix_changes"],
                      "Unchanged": c["unchanged"] + c["unbalanced_braces"],
                      "Severed slice": sum(bool(r.severed_history and r.severed_history[-1]) for r in runs),
                      "Mean attempts": f"{np.mean([r.iterations for r in runs]):.2f}"})
        loc_hit, sizes, off_sizes = 0, [], []
        changed = [(it, r) for it, r in zip(items, runs) if r.reason != "unchanged"]
        for it, r in changed:
            off = _changed_lines(it.vulnerable_code, it.official_fixed_code)
            mine = _changed_lines(it.vulnerable_code, r.final_patch)
            loc_hit += bool(off & mine)
            sizes.append(_edit_size(it.vulnerable_code, r.final_patch))
            off_sizes.append(_edit_size(it.vulnerable_code, it.official_fixed_code))
        rows5.append({"Arm": name, "Changed patches": len(changed),
                      "Touches fix location [95% CI]": fmt_ci(loc_hit, len(changed)),
                      "Edit size median (agent)": int(np.median(sizes)) if sizes else 0,
                      "Edit size median (official)": int(np.median(off_sizes)) if off_sizes else 0})
    t4 = pd.DataFrame(rows4)
    write(t4, "T4_rq3_outcomes", "RQ3 outcome per ladder arm (150 Big-Vul CVEs). VPR is the mean over "
          "3 repeats; the remaining columns count repeat 1.")
    t5 = pd.DataFrame(rows5)
    write(t5, "T5_rq3_localization", "RQ3 patch localization (repeat 1): share of changed agent patches "
          "that modify at least one line the official fix modifies, and edit size in changed lines.")
    return md(t4), md(t5)


def t6_localization_test(r3: dict) -> str:
    """Paired test: does grounding raise the share of patches that touch the official fix's lines?

    Per CVE and arm, count the repeats (of 3) whose final patch modifies >= 1 line the official
    fix modifies (an unchanged function counts as a miss). Each grounded arm is compared with the
    ungrounded arm on the same CVEs: Wilcoxon signed-rank on the per-CVE counts (Holm across the
    four comparisons), plus an exact McNemar test on repeat 1 alone.
    """
    from scipy.stats import binomtest, wilcoxon
    from detectors import LLMClient
    from patch_agent import run_ladder
    from rq3_data import build_rq3_corpus
    items, _ = build_rq3_corpus(n_cves=300, allow_synthetic=False, seed=42)
    reps = int(r3.get("_rq3_e2_ladder", {}).get("repeats", 3) or 3)
    off = [_changed_lines(it.vulnerable_code, it.official_fixed_code) for it in items]
    hits = {k: np.zeros((len(items), reps), dtype=int) for k, _ in ARMS}
    prec = {k: [] for k, _ in ARMS}    # share of the agent's edited lines the official fix also edits
    chance = {k: [] for k, _ in ARMS}  # P(a random edit of the same size touches a fix line)
    nlines = [len(it.vulnerable_code.splitlines()) for it in items]
    for r in range(reps):
        lad = run_ladder(items, seed=42 + r)
        for key, _ in ARMS:
            for i, (it, run) in enumerate(zip(items, lad[key])):
                if run.reason == "unchanged":
                    continue
                mine = _changed_lines(it.vulnerable_code, run.final_patch)
                hits[key][i, r] = int(bool(off[i] & mine))
                if mine:
                    k, n, o = len(mine), nlines[i], len(off[i])
                    prec[key].append(len(mine & off[i]) / k)
                    chance[key].append(1 - math.comb(max(n - o, 0), k) / math.comb(n, k) if n >= k else 1.0)
    print(f"[paper_tables] T6 replay LLM usage: {LLMClient.get().stats()}")
    base = hits[ARMS[0][0]]
    rows, pvals = [{"Arm vs. ungrounded": ARMS[0][1] + " (reference)",
                    "Touch rate (3 reps)": f"{base.mean():.3f}",
                    "Chance touch rate": f"{np.mean(chance[ARMS[0][0]]):.3f}",
                    "Edited-line precision": f"{np.mean(prec[ARMS[0][0]]):.3f}",
                    "CVEs better / worse": "--", "Wilcoxon p": "--", "Rank-biserial r": "--",
                    "McNemar rep. 1 (b10/b01, p)": "--", "Holm p": "--"}], []
    for key, name in ARMS[1:]:
        h = hits[key]
        d = h.sum(1) - base.sum(1)
        w = wilcoxon(h.sum(1), base.sum(1), zero_method="wilcox") if np.any(d) else None
        p = float(w.pvalue) if w is not None else 1.0
        pos, neg = int((d > 0).sum()), int((d < 0).sum())
        # matched-pairs rank-biserial effect size
        nz = d[d != 0]
        from scipy.stats import rankdata
        rk = rankdata(np.abs(nz))
        rbc = float((rk[nz > 0].sum() - rk[nz < 0].sum()) / rk.sum()) if len(nz) else 0.0
        b10 = int(((h[:, 0] == 1) & (base[:, 0] == 0)).sum())
        b01 = int(((h[:, 0] == 0) & (base[:, 0] == 1)).sum())
        mc = binomtest(b10, b10 + b01, 0.5).pvalue if b10 + b01 else 1.0
        pvals.append(p)
        rows.append({"Arm vs. ungrounded": name,
                     "Touch rate (3 reps)": f"{h.mean():.3f}",
                     "Chance touch rate": f"{np.mean(chance[key]):.3f}",
                     "Edited-line precision": f"{np.mean(prec[key]):.3f}",
                     "CVEs better / worse": f"{pos} / {neg}",
                     "Wilcoxon p": p, "Rank-biserial r": f"{rbc:+.2f}",
                     "McNemar rep. 1 (b10/b01, p)": f"{b10}/{b01}, " + ("<0.001" if mc < 1e-3 else f"{mc:.3f}")})
    order = np.argsort(pvals)
    holm, running = [0.0] * len(pvals), 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (len(pvals) - rank) * pvals[i]))
        holm[i] = running
    fp = lambda v: "<0.0001" if v < 1e-4 else f"{v:.4f}"  # noqa: E731
    for row, p, ph in zip(rows[1:], pvals, holm):
        row["Wilcoxon p"] = fp(p)
        row["Holm p"] = fp(ph)
    t6 = pd.DataFrame(rows)
    write(t6, "T6_rq3_localization_test", "Paired test of patch localization against the ungrounded "
          "arm (150 CVEs). Per CVE, the number of repeats (of 3) whose patch modifies at least one line "
          "the official fix modifies; Wilcoxon signed-rank with Holm correction across the four arms, "
          "rank-biserial effect size, and an exact McNemar test on repeat 1. Chance touch rate: probability "
          "that a random edit of the same number of lines touches a fix line. Edited-line precision: share "
          "of the agent's edited lines that the official fix also edits. Arms share their first attempt's "
          "sampling seed (common random numbers), so arms without retries can tie exactly.")
    return md(t6)


def t7_postcutoff() -> str | None:
    p = RES / "rq3_postcutoff.json"
    if not p.exists():
        return None
    r = json.loads(p.read_text())
    rows = []
    for key, name in ARMS:
        a = r["arms"][key]
        ci = lambda v: f"{v[0]:.3f} [{v[1]:.3f}, {v[2]:.3f}]"  # noqa: E731
        rows.append({"Arm": name,
                     f"VPR post-cutoff (n={r['n_post']})": ci(a["vpr_post"]),
                     f"VPR Big-Vul (n={r['n_pre']})": ci(a["vpr_pre"]),
                     "VPR Holm p": f"{a['validated_mwu_p_holm']:.3f}",
                     "Touch post-cutoff": ci(a["touch_post"]), "Touch Big-Vul": ci(a["touch_pre"]),
                     "Touch Holm p": f"{a['touch_mwu_p_holm']:.3f}"})
    cv = r["covariates"]
    df = pd.DataFrame(rows)
    write(df, "T7_rq3_postcutoff", "RQ3 on CVEs published after the model's training cutoff vs. the "
          "pre-cutoff Big-Vul CVEs (3 repeats each; 95% Wilson CIs over CVE x repeat). Seen-vs-unseen "
          "tests are CVE-level Mann-Whitney U with Holm correction over the 10 tests. The sets also "
          f"differ in CVE description length (median {cv['cve_description_words_median']['post']:.0f} vs "
          f"{cv['cve_description_words_median']['pre']:.0f} words) and official-fix size "
          f"({cv['official_fix_edit_size_median']['post']:.1f} vs {cv['official_fix_edit_size_median']['pre']:.1f} lines).")
    return md(df)


def outcome_breakdown() -> None:
    """Per arm, over CVEs x 3 repeats: validated / right place, wrong fix / wrong place / unchanged.
    'Right place' = the rejected patch edits >= 1 line the official fix edits. Writes
    results/rq3_outcomes.json (read by paper_figures.py)."""
    from patch_agent import run_ladder
    from rq3_data import build_rq3_corpus
    items, _ = build_rq3_corpus(n_cves=300, allow_synthetic=False, seed=42)
    off = [_changed_lines(it.vulnerable_code, it.official_fixed_code) for it in items]
    out = {k: collections.Counter() for k, _ in ARMS}
    for r in range(3):
        lad = run_ladder(items, seed=42 + r)
        for key, _ in ARMS:
            for i, (it, run) in enumerate(zip(items, lad[key])):
                if run.validated:
                    out[key]["validated"] += 1
                elif run.reason in ("unchanged", "unbalanced_braces"):
                    out[key]["unchanged"] += 1
                elif off[i] & _changed_lines(it.vulnerable_code, run.final_patch):
                    out[key]["right_place_wrong_fix"] += 1
                else:
                    out[key]["wrong_place"] += 1
    (RES / "rq3_outcomes.json").write_text(json.dumps({k: dict(v) for k, v in out.items()}, indent=1))
    print(f"[paper_tables] wrote {RES / 'rq3_outcomes.json'}")


def main() -> None:
    r = json.loads((RES / "results.json").read_text())
    meta = load_pairs()
    out_md = ["# Paper tables (generated by paper_tables.py)\n"]
    out_md += ["## T1 Dataset\n", t1_dataset(meta), ""]
    t2, t3 = t2_t3_rq1(r["RQ1"], meta)
    out_md += ["## T2 RQ1 by stratum\n", t2, "", "## T3 RQ1 pairwise\n", t3, ""]
    t4, t5 = t4_t5_rq3(r["RQ3"])
    out_md += ["## T4 RQ3 outcomes\n", t4, "", "## T5 RQ3 localization\n", t5, ""]
    out_md += ["## T6 RQ3 localization test\n", t6_localization_test(r["RQ3"]), ""]
    outcome_breakdown()
    t7 = t7_postcutoff()
    if t7:
        out_md += ["## T7 RQ3 post-cutoff vs Big-Vul\n", t7, ""]
    (OUT / "SUMMARY.md").write_text("\n".join(out_md))
    print(f"[paper_tables] wrote {OUT / 'SUMMARY.md'}")


if __name__ == "__main__":
    main()
