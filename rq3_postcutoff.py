"""rq3_postcutoff.py — RQ3 on CVEs published after the patching model's training cutoff.

Same agent, ladder arms, retry budget, seeds and independent oracle as the main RQ3 run, applied
to the post-cutoff vulnerable/fixed pairs (data/postcutoff/, CVE published >= 2025-08-01), and
compared with the pre-cutoff Big-Vul run. Answers: are VPR and fault localization any different
for CVEs whose official fixes the model cannot have seen in training?

Writes results/rq3_postcutoff.json.
"""
from __future__ import annotations

import json
import math
from pathlib import Path

import numpy as np

from detectors import LLMClient
from oracle import calibrate_oracles
from patch_agent import LADDER, run_ladder
from paper_tables import _changed_lines
from rq3_data import CVEPatchItem, build_rq3_corpus

RES = Path("results")
REPEATS = 3
SEED = 42


def wilson(k, n, z=1.96):
    if n == 0:
        return [float("nan")] * 3
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [p, max(0.0, c - h), min(1.0, c + h)]


def load_postcutoff() -> list[CVEPatchItem]:
    rows = [json.loads(l) for l in Path("data/postcutoff/postcutoff_pairs.jsonl").read_text().splitlines()]
    return [CVEPatchItem(cve_id=r["cve_id"], cwe=r.get("cwe") or "CWE-unknown",
                         vulnerable_code=r["func_before"], official_fixed_code=r["func_after"])
            for r in rows]


def ladder_stats(items) -> dict:
    """Per arm: per-CVE validated and touch counts over REPEATS (replayed from cache if present)."""
    off = [_changed_lines(it.vulnerable_code, it.official_fixed_code) for it in items]
    val = {c: np.zeros((len(items), REPEATS), dtype=int) for c in LADDER}
    touch = {c: np.zeros((len(items), REPEATS), dtype=int) for c in LADDER}
    for r in range(REPEATS):
        lad = run_ladder(items, seed=SEED + r)
        for c in LADDER:
            for i, (it, run) in enumerate(zip(items, lad[c])):
                val[c][i, r] = int(run.validated)
                if run.reason != "unchanged":
                    touch[c][i, r] = int(bool(off[i] & _changed_lines(it.vulnerable_code, run.final_patch)))
    return {"validated": val, "touch": touch}


def main() -> None:
    post = load_postcutoff()
    pre, _ = build_rq3_corpus(n_cves=300, allow_synthetic=False, seed=SEED)
    print(f"[rq3_postcutoff] {len(post)} post-cutoff CVEs; {len(pre)} pre-cutoff (Big-Vul) CVEs")

    cal = calibrate_oracles(post, seed=SEED)
    print(f"[rq3_postcutoff] oracle on post-cutoff: official accept={cal['official_patch_accept_rate']:.3f}, "
          f"false accept={cal['oracle_false_accept_rate']:.4f}")

    s_post = ladder_stats(post)
    print(f"[rq3_postcutoff] LLM usage after post-cutoff ladder: {LLMClient.get().stats()}")
    s_pre = ladder_stats(pre)  # replay from cache
    print(f"[rq3_postcutoff] LLM usage after pre-cutoff replay: {LLMClient.get().stats()}")

    from scipy.stats import mannwhitneyu, wilcoxon
    from patch_agent import _cve_text
    from paper_tables import _edit_size
    out = {"n_post": len(post), "n_pre": len(pre), "repeats": REPEATS,
           "oracle_postcutoff": {k: cal[k] for k in ("confusion_matrix", "official_patch_accept_rate",
                                                      "oracle_false_accept_rate")},
           "arms": {}}
    base_post = s_post["touch"][LADDER[0]].sum(1)
    for c in LADDER:
        row = {}
        for tag, s, n in (("post", s_post, len(post)), ("pre", s_pre, len(pre))):
            v, t = s["validated"][c], s["touch"][c]
            row[f"vpr_{tag}"] = wilson(int(v.sum()), v.size)
            row[f"touch_{tag}"] = wilson(int(t.sum()), t.size)
        # seen vs unseen (independent CVE sets), tested at the CVE level — the unit of analysis is
        # the CVE (count of successful repeats, 0..3), not the pooled repeats
        for m in ("validated", "touch"):
            row[f"{m}_mwu_p"] = float(mannwhitneyu(s_post[m][c].sum(1), s_pre[m][c].sum(1),
                                                   alternative="two-sided").pvalue)
        # within post-cutoff: grounded arm vs ungrounded (paired by CVE)
        if c != LADDER[0]:
            d = s_post["touch"][c].sum(1) - base_post
            row["post_touch_vs_ungrounded_wilcoxon_p"] = (
                float(wilcoxon(s_post["touch"][c].sum(1), base_post).pvalue) if np.any(d) else 1.0)
            row["post_cves_better_worse"] = [int((d > 0).sum()), int((d < 0).sum())]
        out["arms"][c] = row
        print(f"  {c:28s} VPR post={row['vpr_post'][0]:.3f} pre={row['vpr_pre'][0]:.3f} (p={row['validated_mwu_p']:.3f})"
              f" | touch post={row['touch_post'][0]:.3f} pre={row['touch_pre'][0]:.3f} (p={row['touch_mwu_p']:.3f})")
    # Holm over the 10 seen-vs-unseen tests (5 arms x {VPR, touch})
    keys = [(c, m) for c in LADDER for m in ("validated", "touch")]
    ps = [out["arms"][c][f"{m}_mwu_p"] for c, m in keys]
    running = 0.0
    for rank, i in enumerate(np.argsort(ps)):
        running = max(running, min(1.0, (len(ps) - rank) * ps[i]))
        c, m = keys[i]
        out["arms"][c][f"{m}_mwu_p_holm"] = running
    # covariates that differ between the two CVE sets (confounds for any seen/unseen contrast)
    med = lambda xs: float(np.median(xs))  # noqa: E731
    out["covariates"] = {
        "cve_description_words_median": {"post": med([len(_cve_text(i.cve_id).split()) for i in post]),
                                         "pre": med([len(_cve_text(i.cve_id).split()) for i in pre])},
        "function_loc_median": {"post": med([len(i.vulnerable_code.splitlines()) for i in post]),
                                "pre": med([len(i.vulnerable_code.splitlines()) for i in pre])},
        "official_fix_edit_size_median": {"post": med([_edit_size(i.vulnerable_code, i.official_fixed_code) for i in post]),
                                          "pre": med([_edit_size(i.vulnerable_code, i.official_fixed_code) for i in pre])},
    }
    out["llm_usage"] = LLMClient.get().stats()
    (RES / "rq3_postcutoff.json").write_text(json.dumps(out, indent=1))
    print(f"[rq3_postcutoff] wrote {RES / 'rq3_postcutoff.json'}")


if __name__ == "__main__":
    main()
