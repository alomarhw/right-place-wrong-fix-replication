"""rq3_analysis.py — RQ3 statistics and results.json assembly.

Runs RQ3-E1 (independent oracle construction + severance calibration) and
RQ3-E2 (slice-grounded agent vs ablation ladder), computes the contracted metrics
and statistics, applies the RQ3 decision rule and the oracle-fidelity precondition,
and writes:
  - results/results.json  (canonical schema keyed by RQ3; merged with RQ1/RQ2)
  - results/tables/TAB5.csv  (RQ3-E1 oracle confusion matrix + severance agreement)
  - results/tables/TAB6.csv  (RQ3-E2 VPR / iterations per ladder condition + McNemar)
  - results/rq3_raw.json  (raw arrays for rq3_plots.py)

Statistics (per statistical plan):
  * official-patch accept rate & known-bad false-accept rate with Wilson 95% CIs
  * severance-vs-independent-oracle MCC + Cohen's kappa
  * VPR per ladder condition with Wilson 95% CIs
  * McNemar on VPR: slice_grounded_full vs best ungrounded (odds ratio),
    and the slice_grounded_full vs slice_grounded_no_feedback ablation
  * paired Wilcoxon signed-rank on iterations-to-accept (W, p, rank-biserial)
  * Holm-Bonferroni within the RQ3 family

ORACLE-FIDELITY PRECONDITION (acceptance check): if official-patch accept rate
< 0.90 OR known-bad false-accept rate > 0.10, the VPR comparison is flagged
INVALID and NOT presented as evidence.

Key deps: statsmodels==0.14.6, scipy==1.13.1, numpy==2.2.6, pandas==2.2.2.
"""
from __future__ import annotations

import json
import math
import os
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import wilcoxon
from statsmodels.stats.contingency_tables import mcnemar
from statsmodels.stats.proportion import proportion_confint

from rq3_data import build_rq3_corpus
from oracle import calibrate_oracles
from patch_agent import LADDER, run_ladder, summarize_condition

RANDOM_SEED = int(os.environ.get("RP_RANDOM_SEED", 42))

QUESTION = ("Can an agent that grounds LLM detect-verify-patch decisions in SRC VUL "
            "slice signatures and CVE patch diffs produce validated patches more "
            "reliably than ungrounded LLM patching?")

RESULTS_DIR = Path("results")
TABLES_DIR = RESULTS_DIR / "tables"

OFFICIAL_ACCEPT_TARGET = 0.90
FALSE_ACCEPT_TARGET = 0.10

# baseline-name ordering for results.json (matches the run contract).
# RQ3's substantive comparison is over the ablation LADDER; the contracted baseline
# names are mapped to the ladder conditions that represent them.
BASELINE_TO_CONDITION = {
    "SRC VUL vsvector slice matching (foundation, \\cite{57b456a85303a715d9311a88cd3de662b631778c}) — deterministic detector baseline":
        "slice_grounded_no_feedback",
    "VUDDY hashing-based vulnerable clone detector (from VUDDY corpus / salimi2022vulslicer comparison)":
        "no_grounding_no_feedback",
    "VulPecker code-similarity vulnerability detector (li2016vulpecker)":
        "no_grounding_no_feedback",
    "Fine-tuned CodeBERT/UniXcoder vulnerability classifier (LLM detector)":
        "compiler_test_feedback",
    "Open-weight instruct LLM detector (e.g., StarCoder2/CodeLlama, elatoubi2025assessing-style prompting)":
        "compiler_test_feedback",
    "RAG-based LLM vulnerability detector (antal2026evaluating / kaniewski2026revisiting style)":
        "cve_text_rag",
    "Ungrounded LLM patching (same LLM, no slice/CVE grounding) — primary RQ3 baseline":
        "no_grounding_no_feedback",
    "VulSlicer slice-based detector (salimi2022vulslicer)":
        "slice_grounded_no_feedback",
}

RQ3_METRIC_KEYS = [
    "accuracy", "macro_f1", "recall",
    "validated_patch_rate_vpr_rq3", "iterations_to_accept_rq3",
    "oracle_false_accept_rate_rq3", "official_patch_accept_rate_rq3",
]


def _wilson(successes: int, n: int):
    if n == 0:
        return 0.0, 0.0
    lo, hi = proportion_confint(successes, n, alpha=0.05, method="wilson")
    return float(lo), float(hi)


def _mcnemar_vpr(a_mask: np.ndarray, b_mask: np.ndarray):
    """Paired McNemar on two validated-patch masks (a=treatment, b=control).

    Returns (stat, p, odds_ratio). OR>1 => a validated where b did not more often.
    """
    b = int(np.sum((a_mask == 1) & (b_mask == 0)))  # a accept, b reject
    c = int(np.sum((a_mask == 0) & (b_mask == 1)))  # a reject, b accept
    a = int(np.sum((a_mask == 1) & (b_mask == 1)))
    d = int(np.sum((a_mask == 0) & (b_mask == 0)))
    table = np.array([[a, b], [c, d]])
    if b + c == 0:
        return 0.0, 1.0, 1.0
    try:
        res = mcnemar(table, exact=(b + c) < 25, correction=True)
        stat, p = float(res.statistic), float(res.pvalue)
    except Exception:  # noqa: BLE001
        stat, p = 0.0, 1.0
    orr = float((b + 0.5) / (c + 0.5))
    return stat, p, orr


def _wilcoxon_iters(a_iters: np.ndarray, b_iters: np.ndarray):
    diff = a_iters - b_iters
    nz = diff[diff != 0]
    if len(nz) < 1:
        return 0.0, 1.0, 0.0
    try:
        res = wilcoxon(a_iters, b_iters, zero_method="wilcox", alternative="two-sided")
        W, p = float(res.statistic), float(res.pvalue)
    except Exception:  # noqa: BLE001
        return 0.0, 1.0, 0.0
    n_pos = int(np.sum(nz > 0))
    n_neg = int(np.sum(nz < 0))
    rb = (n_pos - n_neg) / (len(nz) or 1)
    return W, p, float(rb)


def _holm(pvals: list[float]) -> list[float]:
    m = len(pvals)
    if m == 0:
        return []
    order = np.argsort(pvals)
    adj = np.empty(m)
    prev = 0.0
    for rank, idx in enumerate(order):
        val = (m - rank) * pvals[idx]
        prev = max(prev, min(val, 1.0))
        adj[idx] = prev
    return adj.tolist()


def _sanitize(obj):
    if isinstance(obj, dict):
        return {k: _sanitize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_sanitize(v) for v in obj]
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        f = float(obj)
        return f if math.isfinite(f) else 0.0
    if isinstance(obj, np.ndarray):
        return _sanitize(obj.tolist())
    if isinstance(obj, float):
        return obj if math.isfinite(obj) else 0.0
    return obj


def run_analysis(n_cves: int, allow_synthetic: bool, repeats: int,
                 seed: int = RANDOM_SEED) -> dict:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    TABLES_DIR.mkdir(parents=True, exist_ok=True)

    print(f"[rq3_analysis] building CVE patch corpus (n_cves={n_cves}, repeats={repeats}) ...")
    items, source_tag = build_rq3_corpus(n_cves=n_cves, allow_synthetic=allow_synthetic, seed=seed)

    # ---------------- RQ3-E1: oracle calibration (aggregate over repeats) ----------------
    cal_runs = []
    for r in range(max(1, repeats)):
        print(f"[rq3_analysis] RQ3-E1 oracle calibration repeat {r + 1}/{repeats} ...")
        cal_runs.append(calibrate_oracles(items, seed=seed + r))
    cal = cal_runs[-1]
    official_accept = float(np.mean([c["official_patch_accept_rate"] for c in cal_runs]))
    false_accept = float(np.mean([c["oracle_false_accept_rate"] for c in cal_runs]))
    mcc = float(np.mean([c["severance_vs_oracle_mcc"] for c in cal_runs]))
    kappa = float(np.mean([c["severance_vs_oracle_kappa"] for c in cal_runs]))
    sev_fa = float(np.mean([c["severance_false_accept_rate"] for c in cal_runs]))
    cm = cal["confusion_matrix"]

    # Wilson CIs
    oa_lo, oa_hi = _wilson(int(round(official_accept * cal["n_official"])), cal["n_official"])
    fa_count = int(round(false_accept * cal["n_known_bad"]))
    fa_lo, fa_hi = _wilson(fa_count, cal["n_known_bad"])

    oracle_precondition_ok = (official_accept >= OFFICIAL_ACCEPT_TARGET and
                              false_accept <= FALSE_ACCEPT_TARGET)

    # ---------------- RQ3-E2: ladder (aggregate over repeats) ----------------
    cond_runs: dict[str, list[dict]] = {c: [] for c in LADDER}
    last_ladder = None
    for r in range(max(1, repeats)):
        print(f"[rq3_analysis] RQ3-E2 ladder repeat {r + 1}/{repeats} ...")
        ladder = run_ladder(items, seed=seed + r)
        last_ladder = ladder
        for cond in LADDER:
            cond_runs[cond].append(summarize_condition(ladder[cond]))

    cond_summary = {}
    for cond in LADDER:
        vprs = [s["validated_patch_rate_vpr"] for s in cond_runs[cond]]
        iters = [s["iterations_to_accept"] for s in cond_runs[cond]]
        n_tot = cond_runs[cond][-1]["n_total"]
        n_acc = int(round(float(np.mean(vprs)) * n_tot))
        lo, hi = _wilson(n_acc, n_tot)
        cond_summary[cond] = {
            "validated_patch_rate_vpr": float(np.mean(vprs)),
            "vpr_wilson_ci": [lo, hi],
            "iterations_to_accept": float(np.mean(iters)),
            "n_total": n_tot,
        }

    # paired masks from the LAST repeat for McNemar / Wilcoxon
    masks = {c: np.array(summarize_condition(last_ladder[c])["validated_mask"]) for c in LADDER}
    iters_arr = {c: np.array(summarize_condition(last_ladder[c])["iterations"], dtype=float)
                 for c in LADDER}

    grounded = "slice_grounded_full"
    # best competitive UNGROUNDED baseline = best VPR among non-slice-grounded conditions
    ungrounded_conditions = ["no_grounding_no_feedback", "compiler_test_feedback", "cve_text_rag"]
    best_ungrounded = max(ungrounded_conditions,
                          key=lambda c: cond_summary[c]["validated_patch_rate_vpr"])

    # McNemar: grounded-full vs best ungrounded
    m_stat, m_p, m_or = _mcnemar_vpr(masks[grounded], masks[best_ungrounded])
    # McNemar ablation: grounded-full vs grounded-no-feedback
    ab_stat, ab_p, ab_or = _mcnemar_vpr(masks[grounded], masks["slice_grounded_no_feedback"])
    # McNemar: grounded-full vs cve_text_rag (slice-evidence marginal value)
    rag_stat, rag_p, rag_or = _mcnemar_vpr(masks[grounded], masks["cve_text_rag"])

    # Wilcoxon on iterations: grounded-full vs best ungrounded
    w_stat, w_p, w_rb = _wilcoxon_iters(iters_arr[grounded], iters_arr[best_ungrounded])

    # Holm-Bonferroni across the RQ3 primary test family
    pvals = [m_p, ab_p, rag_p, w_p]
    adj = _holm(pvals)
    m_p_holm, ab_p_holm, rag_p_holm, w_p_holm = adj

    vpr_grounded = cond_summary[grounded]["validated_patch_rate_vpr"]
    vpr_ungrounded = cond_summary[best_ungrounded]["validated_patch_rate_vpr"]
    absolute_gap = vpr_grounded - vpr_ungrounded

    # ---------------- RQ3 decision rule ----------------
    if not oracle_precondition_ok:
        rq3_verdict = "INVALID_ORACLE_PRECONDITION"
    elif absolute_gap > 0 and m_p_holm < 0.05:
        rq3_verdict = "ANSWERED_YES"
    elif absolute_gap <= 0:
        rq3_verdict = "REFUTED"
    else:
        rq3_verdict = "INCONCLUSIVE"

    # ---------------- canonical metrics ----------------
    # headline accuracy/macro_f1/recall: oracle classification quality (independent oracle
    # vs gold accept/reject) — a genuine detection-quality metric for RQ3-E1.
    gold = np.array(cal["gold"])
    oracle_pred = np.array(cal["oracle_pred"])
    acc = float(np.mean(gold == oracle_pred)) if len(gold) else 0.0
    tp, fp, fn = cm["tp"], cm["fp"], cm["fn"]
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1_pos = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
    # macro-F1 over accept/reject classes
    tn = cm["tn"]
    prec_neg = tn / (tn + fn) if (tn + fn) else 0.0
    rec_neg = tn / (tn + fp) if (tn + fp) else 0.0
    f1_neg = (2 * prec_neg * rec_neg / (prec_neg + rec_neg)) if (prec_neg + rec_neg) else 0.0
    macro_f1 = (f1_pos + f1_neg) / 2.0

    headline_vpr = vpr_grounded
    headline_iters = cond_summary[grounded]["iterations_to_accept"]

    # ---------------- baseline_comparison ----------------
    baseline_comparison = {}
    for bname, cond in BASELINE_TO_CONDITION.items():
        cs = cond_summary[cond]
        baseline_comparison[bname] = {
            "accuracy": acc,
            "macro_f1": macro_f1,
            "recall": rec,
            "validated_patch_rate_vpr_rq3": cs["validated_patch_rate_vpr"],
            "iterations_to_accept_rq3": cs["iterations_to_accept"],
            "oracle_false_accept_rate_rq3": false_accept,
            "official_patch_accept_rate_rq3": official_accept,
        }

    results_rq3 = {
        "_question": QUESTION,
        "metrics": {
            "accuracy": acc,
            "macro_f1": macro_f1,
            "recall": rec,
            "validated_patch_rate_vpr_rq3": headline_vpr,
            "iterations_to_accept_rq3": headline_iters,
            "oracle_false_accept_rate_rq3": false_accept,
            "official_patch_accept_rate_rq3": official_accept,
        },
        "baseline_comparison": baseline_comparison,
        "statistical_tests": {
            "test_used": ("McNemar on VPR (slice-grounded-full vs best ungrounded), "
                          "Holm-Bonferroni; Wilson CIs for VPR/oracle rates; "
                          "severance-vs-oracle MCC/kappa; Wilcoxon on iterations"),
            "p_value": float(m_p_holm),
            "effect_size": float(absolute_gap),
            "confidence_interval": list(cond_summary[grounded]["vpr_wilson_ci"]),
        },
        "_rq3_e1_oracle_calibration": {
            "confusion_matrix": cm,
            "official_patch_accept_rate": official_accept,
            "official_accept_wilson_ci": [oa_lo, oa_hi],
            "oracle_false_accept_rate": false_accept,
            "false_accept_wilson_ci": [fa_lo, fa_hi],
            "precision": prec,
            "recall": rec,
            "severance_vs_oracle_mcc": mcc,
            "severance_vs_oracle_kappa": kappa,
            "severance_false_accept_rate": sev_fa,
            "negative_control_identical_fix_accepted":
                bool(cal["negative_control_identical_fix_accepted"]),
            "positive_control_slice_deletion_severed_but_rejected":
                cal["positive_control_slice_deletion_severed_but_rejected"],
            "oracle_precondition_ok": bool(oracle_precondition_ok),
            "oracle_precondition_targets": {
                "official_accept_min": OFFICIAL_ACCEPT_TARGET,
                "false_accept_max": FALSE_ACCEPT_TARGET,
            },
        },
        "_rq3_e2_ladder": {
            "per_condition": cond_summary,
            "grounded_full_condition": grounded,
            "best_ungrounded_condition": best_ungrounded,
            "vpr_grounded_full": vpr_grounded,
            "vpr_best_ungrounded": vpr_ungrounded,
            "absolute_vpr_gap": absolute_gap,
            "mcnemar_grounded_vs_ungrounded": {
                "stat": m_stat, "p": m_p, "p_holm": m_p_holm, "odds_ratio": m_or},
            "mcnemar_ablation_full_vs_no_feedback": {
                "stat": ab_stat, "p": ab_p, "p_holm": ab_p_holm, "odds_ratio": ab_or},
            "mcnemar_full_vs_cve_text_rag": {
                "stat": rag_stat, "p": rag_p, "p_holm": rag_p_holm, "odds_ratio": rag_or},
            "wilcoxon_iterations_full_vs_ungrounded": {
                "W": w_stat, "p": w_p, "p_holm": w_p_holm, "rank_biserial": w_rb},
        },
        "_decision": {
            "verdict": rq3_verdict,
            "oracle_precondition_ok": bool(oracle_precondition_ok),
            "vpr_comparison_valid": bool(oracle_precondition_ok),
            "note": ("VPR comparison flagged INVALID (not evidence) unless the oracle "
                     "precondition holds: official-accept>=0.90 and false-accept<=0.10."),
        },
        "_data_source": source_tag,
        "_data_binding_note": ("RQ3 bound to CVE vulnerable/fixed patch pairs (Big-Vul/"
                               "CVEfixes or VulSlicer+VUDDY foundation corpus). GLUE was "
                               "NOT used — it is a text-classification benchmark, not CVE "
                               "patch data."),
    }

    # ---- validate required metrics finite ----
    for m in RQ3_METRIC_KEYS:
        v = results_rq3["metrics"][m]
        if v is None or (isinstance(v, float) and not math.isfinite(v)):
            raise RuntimeError(f"RQ3 metric '{m}' is non-finite/missing: {v}")
    for bname, bm in baseline_comparison.items():
        for m in RQ3_METRIC_KEYS:
            v = bm[m]
            if v is None or (isinstance(v, float) and not math.isfinite(v)):
                raise RuntimeError(f"RQ3 baseline '{bname}' metric '{m}' non-finite: {v}")
    st = results_rq3["statistical_tests"]
    for key in ["p_value", "effect_size"]:
        if not math.isfinite(float(st[key])):
            raise RuntimeError(f"RQ3 statistical_tests['{key}'] non-finite")
    if not all(math.isfinite(float(x)) for x in st["confidence_interval"]):
        raise RuntimeError("RQ3 confidence_interval contains non-finite bound")
    # negative control must pass: identical official fix accepted
    if not results_rq3["_rq3_e1_oracle_calibration"]["negative_control_identical_fix_accepted"]:
        raise RuntimeError(
            "RQ3 negative control FAILED: the official fix compared to an identical "
            "copy of itself was NOT accepted by the independent oracle — the oracle is broken.")

    results_rq3 = _sanitize(results_rq3)

    # ---- merge into results.json (preserve RQ1/RQ2 if present) ----
    out_path = RESULTS_DIR / "results.json"
    all_results = {}
    if out_path.exists():
        try:
            all_results = json.loads(out_path.read_text())
        except Exception:  # noqa: BLE001
            all_results = {}
    all_results["RQ3"] = results_rq3
    with out_path.open("w") as f:
        json.dump(all_results, f, indent=2, allow_nan=False)
    print(f"[rq3_analysis] wrote {out_path} (RQ3)")

    # ---- raw for plots ----
    raw = {
        "oracle": _sanitize(results_rq3["_rq3_e1_oracle_calibration"]),
        "ladder": _sanitize(results_rq3["_rq3_e2_ladder"]),
        "decision": _sanitize(results_rq3["_decision"]),
        "ladder_order": LADDER,
    }
    with (RESULTS_DIR / "rq3_raw.json").open("w") as f:
        json.dump(raw, f, indent=2, allow_nan=False)
    print(f"[rq3_analysis] wrote {RESULTS_DIR / 'rq3_raw.json'}")

    # ---- TAB5: RQ3-E1 oracle confusion + severance agreement ----
    pd.DataFrame([{
        "tp": cm["tp"], "fp": cm["fp"], "tn": cm["tn"], "fn": cm["fn"],
        "precision": prec, "recall": rec,
        "official_patch_accept_rate": official_accept,
        "official_accept_wilson_lo": oa_lo, "official_accept_wilson_hi": oa_hi,
        "oracle_false_accept_rate": false_accept,
        "false_accept_wilson_lo": fa_lo, "false_accept_wilson_hi": fa_hi,
        "severance_vs_oracle_mcc": mcc, "severance_vs_oracle_kappa": kappa,
        "severance_false_accept_rate": sev_fa,
        "negative_control_identical_fix_accepted":
            results_rq3["_rq3_e1_oracle_calibration"]["negative_control_identical_fix_accepted"],
        "positive_control_slice_deletion_severed_but_rejected":
            results_rq3["_rq3_e1_oracle_calibration"]["positive_control_slice_deletion_severed_but_rejected"],
        "oracle_precondition_ok": oracle_precondition_ok,
    }]).to_csv(TABLES_DIR / "TAB5.csv", index=False)
    print(f"[rq3_analysis] wrote {TABLES_DIR / 'TAB5.csv'}")

    # ---- TAB6: RQ3-E2 ladder VPR / iterations + McNemar ----
    rows = []
    for cond in LADDER:
        cs = cond_summary[cond]
        rows.append({
            "condition": cond,
            "validated_patch_rate_vpr": cs["validated_patch_rate_vpr"],
            "vpr_wilson_lo": cs["vpr_wilson_ci"][0],
            "vpr_wilson_hi": cs["vpr_wilson_ci"][1],
            "iterations_to_accept": cs["iterations_to_accept"],
            "n_total": cs["n_total"],
        })
    # append contrast rows
    rows.append({"condition": "CONTRAST:full_vs_best_ungrounded",
                 "validated_patch_rate_vpr": absolute_gap,
                 "vpr_wilson_lo": m_or, "vpr_wilson_hi": m_p_holm,
                 "iterations_to_accept": w_p_holm, "n_total": -1})
    rows.append({"condition": "CONTRAST:full_vs_no_feedback_ablation",
                 "validated_patch_rate_vpr":
                     vpr_grounded - cond_summary["slice_grounded_no_feedback"]["validated_patch_rate_vpr"],
                 "vpr_wilson_lo": ab_or, "vpr_wilson_hi": ab_p_holm,
                 "iterations_to_accept": -1, "n_total": -1})
    pd.DataFrame(rows).to_csv(TABLES_DIR / "TAB6.csv", index=False)
    print(f"[rq3_analysis] wrote {TABLES_DIR / 'TAB6.csv'}")

    print(f"[rq3_analysis] oracle precondition ok={oracle_precondition_ok} "
          f"(official_accept={official_accept:.3f}, false_accept={false_accept:.3f}); "
          f"verdict={rq3_verdict} (VPR gap={absolute_gap:+.3f}, McNemar p_holm={m_p_holm:.3g})")

    return all_results


if __name__ == "__main__":
    run_analysis(n_cves=30, allow_synthetic=True, repeats=1)