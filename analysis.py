#!/usr/bin/env python3
"""Study pipeline: analysis.py

Statistical analysis for a controlled within-CVE paired experiment on
LLM-based vulnerable-clone detection (memorization vs. slice-semantic
reasoning) and slice-grounded patching.

Runs AFTER main.py. Reads the canonical results/results.json (plus any CSVs
the experiment wrote) and produces:
    results/analysis_summary.csv
    results/analysis_summary.json

All quantitative comparisons report: metric, test used, raw p, Holm-Bonferroni
corrected p, named effect size + value, and a 95% CI for the primary estimate.
"""

import os
import json
import math
import warnings

import numpy as np
import pandas as pd
from scipy import stats

warnings.filterwarnings("ignore")

RESULTS_DIR = "results"
RESULTS_JSON = os.path.join(RESULTS_DIR, "results.json")
SUMMARY_CSV = os.path.join(RESULTS_DIR, "analysis_summary.csv")
SUMMARY_JSON = os.path.join(RESULTS_DIR, "analysis_summary.json")

RNG = np.random.default_rng(20240101)
N_BOOT = 1000
ALPHA = 0.05


# ----------------------------------------------------------------------------
# IO helpers
# ----------------------------------------------------------------------------
def load_results():
    if not os.path.exists(RESULTS_JSON):
        raise RuntimeError(
            f"Expected canonical results at {RESULTS_JSON}; main.py must run first."
        )
    with open(RESULTS_JSON, "r") as fh:
        return json.load(fh)


def finite(x):
    """Return a python float if finite, else None (will be omitted from output)."""
    try:
        v = float(x)
    except (TypeError, ValueError):
        return None
    if math.isnan(v) or math.isinf(v):
        return None
    return v


def require_finite(x, rq, metric):
    v = finite(x)
    if v is None:
        raise RuntimeError(
            f"Required metric is NaN/Infinity/missing for {rq} :: {metric}"
        )
    return v


def as_array(seq):
    arr = np.asarray([v for v in seq if v is not None], dtype=float)
    arr = arr[np.isfinite(arr)]
    return arr


# ----------------------------------------------------------------------------
# Statistics primitives
# ----------------------------------------------------------------------------
def wilson_ci(k, n, conf=0.95):
    """Wilson score interval for a proportion."""
    if n <= 0:
        return (None, None, None)
    z = stats.norm.ppf(1 - (1 - conf) / 2)
    phat = k / n
    denom = 1 + z**2 / n
    center = (phat + z**2 / (2 * n)) / denom
    half = (z * math.sqrt((phat * (1 - phat) + z**2 / (4 * n)) / n)) / denom
    return (phat, max(0.0, center - half), min(1.0, center + half))


def bootstrap_ci_mean(values, conf=0.95, n_boot=N_BOOT):
    arr = as_array(values)
    if arr.size == 0:
        return (None, None, None)
    if arr.size < 30:
        # small n: use t-based analytic interval
        m = float(np.mean(arr))
        if arr.size == 1:
            return (m, None, None)
        se = stats.sem(arr)
        h = se * stats.t.ppf(1 - (1 - conf) / 2, arr.size - 1)
        return (m, m - h, m + h)
    boots = np.array(
        [np.mean(RNG.choice(arr, size=arr.size, replace=True)) for _ in range(n_boot)]
    )
    lo, hi = np.percentile(boots, [100 * (1 - conf) / 2, 100 * (1 + conf) / 2])
    return (float(np.mean(arr)), float(lo), float(hi))


def bootstrap_ci_diff(a, b, conf=0.95, n_boot=N_BOOT):
    """Paired bootstrap CI for mean(a) - mean(b). a,b aligned per-CVE arrays."""
    a = np.asarray(a, dtype=float)
    b = np.asarray(b, dtype=float)
    mask = np.isfinite(a) & np.isfinite(b)
    a, b = a[mask], b[mask]
    if a.size == 0:
        return (None, None, None)
    point = float(np.mean(a) - np.mean(b))
    if a.size < 10:
        return (point, None, None)
    idx = np.arange(a.size)
    boots = []
    for _ in range(n_boot):
        s = RNG.choice(idx, size=a.size, replace=True)
        boots.append(np.mean(a[s]) - np.mean(b[s]))
    lo, hi = np.percentile(boots, [100 * (1 - conf) / 2, 100 * (1 + conf) / 2])
    return (point, float(lo), float(hi))


def mcnemar_paired(correct_a, correct_b):
    """McNemar's test on paired binary correctness vectors.

    Returns dict with chi2/statistic, p (exact binomial when discordant small),
    odds ratio (b10/b01), and discordant counts.
    """
    a = np.asarray(correct_a, dtype=float)
    b = np.asarray(correct_b, dtype=float)
    mask = np.isfinite(a) & np.isfinite(b)
    a, b = a[mask].astype(int), b[mask].astype(int)
    if a.size == 0:
        return dict(stat=None, p=None, odds_ratio=None, b10=0, b01=0, n=0)
    b10 = int(np.sum((a == 1) & (b == 0)))  # a correct, b wrong
    b01 = int(np.sum((a == 0) & (b == 1)))  # a wrong, b correct
    n_disc = b10 + b01
    if n_disc == 0:
        return dict(stat=0.0, p=1.0, odds_ratio=1.0, b10=b10, b01=b01, n=int(a.size))
    if n_disc < 25:
        # exact binomial two-sided
        p = float(stats.binomtest(b10, n_disc, 0.5).pvalue)
        stat = float(min(b10, b01))
    else:
        stat = float((abs(b10 - b01) - 1) ** 2 / n_disc)  # continuity-corrected chi2
        p = float(stats.chi2.sf(stat, df=1))
    odds = (b10 + 0.5) / (b01 + 0.5)  # Haldane-Anscombe corrected OR
    return dict(stat=stat, p=p, odds_ratio=float(odds), b10=b10, b01=b01, n=int(a.size))


def cliffs_delta(a, b):
    a = as_array(a)
    b = as_array(b)
    if a.size == 0 or b.size == 0:
        return None
    gt = sum(np.sum(x > b) for x in a)
    lt = sum(np.sum(x < b) for x in a)
    return float((gt - lt) / (a.size * b.size))


def rank_biserial_wilcoxon(deltas):
    """Matched-pairs rank-biserial effect size + Wilcoxon signed-rank test."""
    d = as_array(deltas)
    d = d[d != 0]
    if d.size < 1:
        return dict(stat=None, p=None, rank_biserial=None, n=0)
    if d.size < 2:
        return dict(stat=None, p=None, rank_biserial=float(np.sign(d[0])), n=int(d.size))
    try:
        w = stats.wilcoxon(d, zero_method="wilcox", correction=True)
        stat, p = float(w.statistic), float(w.pvalue)
    except ValueError:
        stat, p = None, None
    ranks = stats.rankdata(np.abs(d))
    rpos = np.sum(ranks[d > 0])
    rneg = np.sum(ranks[d < 0])
    total = rpos + rneg
    rb = float((rpos - rneg) / total) if total > 0 else None
    return dict(stat=stat, p=p, rank_biserial=rb, n=int(d.size))


def cohens_kappa(labels_a, labels_b):
    a = np.asarray(labels_a)
    b = np.asarray(labels_b)
    mask = np.array([x is not None and y is not None for x, y in zip(a, b)])
    a, b = a[mask], b[mask]
    if a.size == 0:
        return None
    cats = sorted(set(a.tolist()) | set(b.tolist()))
    idx = {c: i for i, c in enumerate(cats)}
    k = len(cats)
    m = np.zeros((k, k))
    for x, y in zip(a, b):
        m[idx[x], idx[y]] += 1
    n = m.sum()
    if n == 0:
        return None
    po = np.trace(m) / n
    pe = np.sum(m.sum(0) * m.sum(1)) / (n * n)
    if abs(1 - pe) < 1e-12:
        return 1.0
    return float((po - pe) / (1 - pe))


def holm_bonferroni(pvals):
    """Return corrected p-values in original order. None entries pass through."""
    items = [(i, p) for i, p in enumerate(pvals) if p is not None]
    corrected = [None] * len(pvals)
    if not items:
        return corrected
    items.sort(key=lambda t: t[1])
    m = len(items)
    prev = 0.0
    for rank, (orig_i, p) in enumerate(items):
        adj = min(1.0, (m - rank) * p)
        adj = max(adj, prev)  # enforce monotonicity
        prev = adj
        corrected[orig_i] = adj
    return corrected


# ----------------------------------------------------------------------------
# Row accumulator
# ----------------------------------------------------------------------------
def new_row(rq, comparison, metric, test, effect_name):
    return {
        "rq": rq,
        "comparison": comparison,
        "metric": metric,
        "test": test,
        "n": None,
        "estimate": None,
        "ci95_low": None,
        "ci95_high": None,
        "effect_size_name": effect_name,
        "effect_size_value": None,
        "statistic": None,
        "p_raw": None,
        "p_corrected": None,
    }


def apply_holm_within_family(rows):
    """Group rows by rq and apply Holm-Bonferroni across each rq's tested rows."""
    by_rq = {}
    for i, r in enumerate(rows):
        if r["p_raw"] is not None:
            by_rq.setdefault(r["rq"], []).append(i)
    for rq, idxs in by_rq.items():
        praw = [rows[i]["p_raw"] for i in idxs]
        corr = holm_bonferroni(praw)
        for i, c in zip(idxs, corr):
            rows[i]["p_corrected"] = c


# ----------------------------------------------------------------------------
# Generic extraction helpers (robust to schema variations in results.json)
# ----------------------------------------------------------------------------
def get_rq_block(results, rq):
    if rq in results:
        return results[rq]
    # case-insensitive fallback
    for k, v in results.items():
        if str(k).lower() == rq.lower():
            return v
    return {}


def paired_correctness(block, key_a, key_b):
    """Try to find aligned per-item correctness vectors for two conditions.

    Looks under block['paired'][...]/block['per_item']/block['raw'] etc.
    Returns (vec_a, vec_b) or (None, None).
    """
    candidates = []
    for container_key in ("paired", "per_item", "per_cve", "raw", "predictions"):
        c = block.get(container_key)
        if isinstance(c, dict):
            candidates.append(c)
    for c in candidates:
        if key_a in c and key_b in c:
            try:
                a = [float(x) for x in c[key_a]]
                b = [float(x) for x in c[key_b]]
                if len(a) == len(b) and len(a) > 0:
                    return a, b
            except (TypeError, ValueError):
                continue
    return None, None


# ----------------------------------------------------------------------------
# RQ1 : memorization gap (verbatim vs variant) per LLM detector
# ----------------------------------------------------------------------------
def analyze_rq1(results, rows):
    rq = "RQ1"
    block = get_rq_block(results, rq)
    metrics = block.get("metrics", {}) if isinstance(block, dict) else {}

    # Descriptive accuracy metrics that may live directly on the RQ block
    for mname in ("accuracy", "macro_f1", "recall"):
        if mname in metrics:
            val = finite(metrics[mname])
            if val is not None:
                r = new_row(rq, "overall", mname, "descriptive", "")
                r["estimate"] = val
                rows.append(r)

    # Memorization gap and pooled odds ratio summary metrics
    if "memorization_gap_acc_rq1" in metrics:
        gap = require_finite(metrics["memorization_gap_acc_rq1"], rq, "memorization_gap_acc_rq1")
        r = new_row(rq, "verbatim_vs_variant", "memorization_gap_acc_rq1", "bootstrap_ci", "delta_acc")
        # if per-detector gaps exist, bootstrap over them
        per_det = None
        if isinstance(block.get("per_detector_gap"), list):
            per_det = block["per_detector_gap"]
        if per_det:
            est, lo, hi = bootstrap_ci_mean(per_det)
            r["estimate"], r["ci95_low"], r["ci95_high"] = est, lo, hi
            r["n"] = len(as_array(per_det))
        else:
            r["estimate"] = gap
        r["effect_size_value"] = gap
        rows.append(r)

    if "pooled_split_odds_ratio_rq1" in metrics:
        orr = require_finite(metrics["pooled_split_odds_ratio_rq1"], rq, "pooled_split_odds_ratio_rq1")
        r = new_row(rq, "pooled_split_mixed_effects", "pooled_split_odds_ratio_rq1",
                    "logistic_mixed_effects", "odds_ratio")
        r["estimate"] = orr
        r["effect_size_value"] = orr
        # optional p from mixed model
        mm_p = finite(metrics.get("pooled_split_p"))
        if mm_p is not None:
            r["p_raw"] = mm_p
        rows.append(r)

    # Per-detector McNemar on paired correctness, if raw vectors available
    detectors = []
    if isinstance(block.get("detectors"), list):
        detectors = block["detectors"]
    elif isinstance(block.get("per_detector"), dict):
        detectors = list(block["per_detector"].keys())

    for det in detectors:
        vb, va = paired_correctness(block, f"{det}__verbatim", f"{det}__variant")
        if vb is None and isinstance(block.get("per_detector"), dict):
            d = block["per_detector"].get(det, {})
            try:
                vb = [float(x) for x in d.get("verbatim_correct", [])]
                va = [float(x) for x in d.get("variant_correct", [])]
                if len(vb) != len(va) or len(vb) == 0:
                    vb = va = None
            except (TypeError, ValueError):
                vb = va = None
        if vb is not None and va is not None:
            mc = mcnemar_paired(vb, va)
            r = new_row(rq, f"{det}: verbatim_vs_variant", "accuracy", "McNemar", "odds_ratio")
            r["n"] = mc["n"]
            r["statistic"] = finite(mc["stat"])
            r["p_raw"] = finite(mc["p"])
            r["effect_size_value"] = finite(mc["odds_ratio"])
            gap_est, glo, ghi = bootstrap_ci_mean(
                [1.0 if x else 0.0 for x in vb]
            )
            # Δ_acc point + CI via paired bootstrap of (verbatim - variant)
            de, dlo, dhi = bootstrap_ci_diff(vb, va)
            r["estimate"], r["ci95_low"], r["ci95_high"] = de, dlo, dhi
            rows.append(r)


# ----------------------------------------------------------------------------
# RQ2 : construction validity + invariance contrast (DiD)
# ----------------------------------------------------------------------------
def analyze_rq2(results, rows):
    rq = "RQ2"
    block = get_rq_block(results, rq)
    metrics = block.get("metrics", {}) if isinstance(block, dict) else {}

    # Construction validity: accepted-variant yield (Wilson CI)
    if "accepted_variant_yield" in metrics:
        y = require_finite(metrics["accepted_variant_yield"], rq, "accepted_variant_yield_rq2")
        k = block.get("accepted_count")
        n = block.get("attempted_count")
        r = new_row(rq, "construction_validity", "accepted_variant_yield_rq2", "wilson_ci", "proportion")
        if isinstance(k, (int, float)) and isinstance(n, (int, float)) and n > 0:
            phat, lo, hi = wilson_ci(int(k), int(n))
            r["estimate"], r["ci95_low"], r["ci95_high"], r["n"] = phat, lo, hi, int(n)
            r["effect_size_value"] = phat
        else:
            r["estimate"] = y
            r["effect_size_value"] = y
        rows.append(r)

    # vsvector invariance pass rate (Wilson CI)
    if "vsvector_invariance_pass_rate_rq2" in metrics:
        p = require_finite(metrics["vsvector_invariance_pass_rate_rq2"], rq, "vsvector_invariance_pass_rate_rq2")
        k = block.get("invariance_pass_count")
        n = block.get("invariance_checked_count")
        r = new_row(rq, "invariance_spot_check", "vsvector_invariance_pass_rate_rq2", "wilson_ci", "proportion")
        if isinstance(k, (int, float)) and isinstance(n, (int, float)) and n > 0:
            phat, lo, hi = wilson_ci(int(k), int(n))
            r["estimate"], r["ci95_low"], r["ci95_high"], r["n"] = phat, lo, hi, int(n)
            r["effect_size_value"] = phat
        else:
            r["estimate"] = p
            r["effect_size_value"] = p
        rows.append(r)

    # Manual audit agreement (Cohen's kappa)
    if "annotator_agreement_cohen_s_kappa_rq2" in metrics:
        kap = require_finite(metrics["annotator_agreement_cohen_s_kappa_rq2"], rq, "annotator_agreement_cohen_s_kappa_rq2")
        r = new_row(rq, "manual_audit_agreement", "annotator_agreement_cohen_s_kappa_rq2", "cohens_kappa", "kappa")
        # recompute if raw annotations provided
        la = block.get("annotator_a_labels")
        lb = block.get("annotator_b_labels")
        if isinstance(la, list) and isinstance(lb, list) and len(la) == len(lb) and la:
            kk = cohens_kappa(la, lb)
            if kk is not None:
                kap = kk
                r["n"] = len(la)
        r["estimate"] = kap
        r["effect_size_value"] = kap
        rows.append(r)

    # Invariance contrast: DiD = Δ_acc(LLM) - Δ_acc(SRC VUL) with paired bootstrap + Wilcoxon
    if "difference_in_differences_did_rq2" in metrics:
        did = require_finite(metrics["difference_in_differences_did_rq2"], rq, "difference_in_differences_did_rq2")
        r = new_row(rq, "DiD: LLM_drop_minus_slice_matcher_drop",
                    "difference_in_differences_did_rq2", "paired_bootstrap+wilcoxon", "rank_biserial")
        # Per-CVE deltas, if available: llm_delta[i] - slice_delta[i]
        llm_delta = block.get("per_cve_llm_delta")
        slice_delta = block.get("per_cve_slice_delta")
        if isinstance(llm_delta, list) and isinstance(slice_delta, list) and \
                len(llm_delta) == len(slice_delta) and llm_delta:
            diff = [a - b for a, b in zip(llm_delta, slice_delta)]
            est, lo, hi = bootstrap_ci_mean(diff)
            r["estimate"], r["ci95_low"], r["ci95_high"] = est, lo, hi
            wr = rank_biserial_wilcoxon(diff)
            r["statistic"] = wr["stat"]
            r["p_raw"] = wr["p"]
            r["effect_size_value"] = wr["rank_biserial"]
            r["n"] = wr["n"]
        else:
            r["estimate"] = did
            r["effect_size_value"] = did
        rows.append(r)


# ----------------------------------------------------------------------------
# RQ3 : slice-grounded detect-verify-patch agent vs ungrounded
# ----------------------------------------------------------------------------
def analyze_rq3(results, rows):
    rq = "RQ3"
    block = get_rq_block(results, rq)
    metrics = block.get("metrics", {}) if isinstance(block, dict) else {}

    # Validated patch rate (VPR) with Wilson CI per condition
    def vpr_row(label, rate_key, count_key_k, count_key_n, metric_name):
        if rate_key not in metrics:
            return
        rate = require_finite(metrics[rate_key], rq, metric_name)
        r = new_row(rq, label, metric_name, "wilson_ci", "proportion")
        k = block.get(count_key_k)
        n = block.get(count_key_n)
        if isinstance(k, (int, float)) and isinstance(n, (int, float)) and n > 0:
            phat, lo, hi = wilson_ci(int(k), int(n))
            r["estimate"], r["ci95_low"], r["ci95_high"], r["n"] = phat, lo, hi, int(n)
            r["effect_size_value"] = phat
        else:
            r["estimate"] = rate
            r["effect_size_value"] = rate
        rows.append(r)

    vpr_row("grounded_agent: VPR", "validated_patch_rate_vpr_rq3",
            "vpr_validated_count", "vpr_total_count", "validated_patch_rate_vpr_rq3")

    # Oracle fidelity preconditions
    for key, name in (
        ("oracle_false_accept_rate_rq3", "oracle_false_accept_rate_rq3"),
        ("official_patch_accept_rate_rq3", "official_patch_accept_rate_rq3"),
    ):
        if key in metrics:
            val = require_finite(metrics[key], rq, name)
            r = new_row(rq, "oracle_fidelity", name, "wilson_ci", "proportion")
            kk = block.get(name.replace("_rq3", "") + "_count")
            nn = block.get(name.replace("_rq3", "") + "_total")
            if isinstance(kk, (int, float)) and isinstance(nn, (int, float)) and nn > 0:
                phat, lo, hi = wilson_ci(int(kk), int(nn))
                r["estimate"], r["ci95_low"], r["ci95_high"], r["n"] = phat, lo, hi, int(nn)
                r["effect_size_value"] = phat
            else:
                r["estimate"] = val
                r["effect_size_value"] = val
            rows.append(r)

    # McNemar: grounded vs best ungrounded baseline on per-CVE validated correctness
    gvec, uvec = paired_correctness(block, "grounded_validated", "ungrounded_validated")
    if gvec is None:
        g = block.get("grounded_validated_correct")
        u = block.get("ungrounded_validated_correct")
        if isinstance(g, list) and isinstance(u, list) and len(g) == len(u) and g:
            gvec, uvec = [float(x) for x in g], [float(x) for x in u]
    if gvec is not None and uvec is not None:
        mc = mcnemar_paired(gvec, uvec)
        r = new_row(rq, "grounded_vs_best_ungrounded", "validated_patch_rate_vpr_rq3",
                    "McNemar", "odds_ratio")
        r["n"] = mc["n"]
        r["statistic"] = finite(mc["stat"])
        r["p_raw"] = finite(mc["p"])
        r["effect_size_value"] = finite(mc["odds_ratio"])
        de, dlo, dhi = bootstrap_ci_diff(gvec, uvec)
        r["estimate"], r["ci95_low"], r["ci95_high"] = de, dlo, dhi
        rows.append(r)
    elif "vpr_gain_grounded_vs_ungrounded" in metrics:
        gain = finite(metrics["vpr_gain_grounded_vs_ungrounded"])
        if gain is not None:
            r = new_row(rq, "grounded_vs_best_ungrounded", "vpr_gain", "descriptive", "abs_gap")
            r["estimate"] = gain
            r["effect_size_value"] = gain
            rows.append(r)

    # McNemar ablation: grounded-full vs grounded-no-feedback
    fvec, nfvec = paired_correctness(block, "grounded_full_validated", "grounded_nofeedback_validated")
    if fvec is not None and nfvec is not None:
        mc = mcnemar_paired(fvec, nfvec)
        r = new_row(rq, "grounded_full_vs_no_feedback", "validated_patch_rate_vpr_rq3",
                    "McNemar", "odds_ratio")
        r["n"] = mc["n"]
        r["statistic"] = finite(mc["stat"])
        r["p_raw"] = finite(mc["p"])
        r["effect_size_value"] = finite(mc["odds_ratio"])
        rows.append(r)

    # Paired Wilcoxon on iterations-to-accept
    gi = block.get("grounded_iterations")
    ui = block.get("ungrounded_iterations")
    if isinstance(gi, list) and isinstance(ui, list) and len(gi) == len(ui) and gi:
        deltas = [float(a) - float(b) for a, b in zip(gi, ui)]
        wr = rank_biserial_wilcoxon(deltas)
        r = new_row(rq, "grounded_vs_ungrounded: iterations_to_accept",
                    "iterations_to_accept_rq3", "Wilcoxon_signed_rank", "rank_biserial")
        est, lo, hi = bootstrap_ci_mean(deltas)
        r["estimate"], r["ci95_low"], r["ci95_high"] = est, lo, hi
        r["statistic"] = wr["stat"]
        r["p_raw"] = wr["p"]
        r["effect_size_value"] = wr["rank_biserial"]
        r["n"] = wr["n"]
        rows.append(r)
    elif "iterations_to_accept_rq3" in metrics:
        v = require_finite(metrics["iterations_to_accept_rq3"], rq, "iterations_to_accept_rq3")
        r = new_row(rq, "grounded_agent", "iterations_to_accept_rq3", "descriptive", "mean")
        r["estimate"] = v
        rows.append(r)


# ----------------------------------------------------------------------------
# Fallback: ensure every RQ present in results is represented
# ----------------------------------------------------------------------------
def ensure_rq_coverage(results, rows):
    represented = {r["rq"] for r in rows}
    for rq_key in results.keys():
        block = results[rq_key]
        if not isinstance(block, dict):
            continue
        norm = str(rq_key).upper()
        already = any(r["rq"].upper() == norm for r in rows)
        if already:
            continue
        metrics = block.get("metrics", {})
        if isinstance(metrics, dict):
            for mname, mval in metrics.items():
                v = finite(mval)
                if v is not None:
                    r = new_row(rq_key, "overall", mname, "descriptive", "")
                    r["estimate"] = v
                    rows.append(r)


# ----------------------------------------------------------------------------
# Output sanitation
# ----------------------------------------------------------------------------
def sanitize_rows(rows):
    numeric_cols = [
        "n", "estimate", "ci95_low", "ci95_high",
        "effect_size_value", "statistic", "p_raw", "p_corrected",
    ]
    clean = []
    for r in rows:
        out = dict(r)
        for col in numeric_cols:
            out[col] = finite(out.get(col))
        clean.append(out)
    return clean


# ----------------------------------------------------------------------------
# RQ1 experiment driver (called by main.py): runs RQ1-E0 + RQ1-E1 and writes the
# RQ1 block of results/results.json, then the analysis summary.
# ----------------------------------------------------------------------------
def run_analysis(n_cves, allow_synthetic, repeats, seed=42):
    from data_prep import build_corpus
    from detectors import LLMClient, LLMDetector, build_all_detectors
    from invariance_contrast import run_invariance_contrast
    from membership_probe import run_membership_probe

    items, source_tag = build_corpus(n_cves=n_cves, allow_synthetic=allow_synthetic, seed=seed)
    runs = []
    for r in range(max(1, repeats)):
        print(f"[analysis] RQ1 repeat {r + 1}/{repeats} ...")
        runs.append(run_invariance_contrast(items, seed=seed + r))
    last = runs[-1]
    membership = run_membership_probe(items, seed=seed)
    llm_keys = [k for k, d in build_all_detectors(seed).items() if isinstance(d, LLMDetector)]

    per_detector = {}
    for name, res in last["per_detector"].items():
        prov = np.array(last["provenance"])
        cv = np.array(res["correct_verbatim"], dtype=bool)
        mean = lambda key: float(np.mean([run["per_detector"][name][key] for run in runs]))  # noqa: E731
        per_detector[name] = {
            "accuracy": mean("accuracy"), "macro_f1": mean("macro_f1"), "recall": mean("recall"),
            "acc_verbatim": mean("acc_verbatim"), "acc_variant": mean("acc_variant"),
            "delta_acc": mean("delta_acc"),
            "pooled_split_odds_ratio": mean("pooled_split_odds_ratio"),
            "gap_seen": mean("gap_seen"), "gap_unseen": mean("gap_unseen"),
            "provenance_component": mean("provenance_component"),
            # verbatim accuracy by provenance: pre-cutoff (seen) vs post-cutoff (unseen) CVEs
            "acc_verbatim_seen": float(cv[prov == "seen"].mean()) if (prov == "seen").any() else 0.0,
            "acc_verbatim_unseen": float(cv[prov == "unseen"].mean()) if (prov == "unseen").any() else 0.0,
            "mcnemar_table": res["mcnemar_table"],
            "verbatim_correct": res["correct_verbatim"],
            "variant_correct": res["correct_variant"],
            "is_llm": name in llm_keys,
        }

    llm = [per_detector[k] for k in llm_keys if k in per_detector] or list(per_detector.values())
    n_v = len(last["labels"])
    pooled_or = (lambda a, b, c, d: (a / b) / (c / d))(
        sum(sum(d["verbatim_correct"]) for d in llm) + 0.5,
        sum(n_v - sum(d["verbatim_correct"]) for d in llm) + 0.5,
        sum(sum(d["variant_correct"]) for d in llm) + 0.5,
        sum(n_v - sum(d["variant_correct"]) for d in llm) + 0.5)
    metrics = {
        "accuracy": float(np.mean([d["accuracy"] for d in llm])),
        "macro_f1": float(np.mean([d["macro_f1"] for d in llm])),
        "recall": float(np.mean([d["recall"] for d in llm])),
        "memorization_gap_acc_rq1": float(np.mean([d["delta_acc"] for d in llm])),
        "pooled_split_odds_ratio_rq1": float(pooled_or),
        "llm_acc_verbatim_seen": float(np.mean([d["acc_verbatim_seen"] for d in llm])),
        "llm_acc_verbatim_unseen": float(np.mean([d["acc_verbatim_unseen"] for d in llm])),
    }
    baseline_comparison = {
        name: {"accuracy": d["accuracy"], "macro_f1": d["macro_f1"], "recall": d["recall"],
               "memorization_gap_acc_rq1": d["delta_acc"],
               "pooled_split_odds_ratio_rq1": d["pooled_split_odds_ratio"]}
        for name, d in per_detector.items()}
    # Paired test of the LLM memorization gap (last repeat): exact McNemar on the pooled
    # per-(detector, item) correctness, verbatim vs variant; CI = paired bootstrap over
    # items of the per-item mean correctness across the LLM detectors.
    pooled_v = [x for d in llm for x in d["verbatim_correct"]]
    pooled_t = [x for d in llm for x in d["variant_correct"]]
    mc = mcnemar_paired(pooled_v, pooled_t)
    item_v = np.mean([d["verbatim_correct"] for d in llm], axis=0)
    item_t = np.mean([d["variant_correct"] for d in llm], axis=0)
    gap_pt, gap_lo, gap_hi = bootstrap_ci_diff(item_v.tolist(), item_t.tolist())
    statistical_tests = {
        "test_used": "McNemar (exact binomial for few discordant pairs), LLM detectors' pooled per-item correctness, verbatim vs "
                     "certified variant; effect = accuracy gap; 95% paired bootstrap CI over items",
        "p_value": float(mc["p"] if mc["p"] is not None else 1.0),
        "effect_size": float(gap_pt if gap_pt is not None else 0.0),
        "confidence_interval": [float(gap_lo if gap_lo is not None else 0.0),
                                float(gap_hi if gap_hi is not None else 0.0)],
        "mcnemar_b10_verbatim_only": int(mc["b10"]),
        "mcnemar_b01_variant_only": int(mc["b01"]),
        "n_pairs": int(mc["n"]),
    }
    block = {
        "_question": "Do LLM vulnerable-clone detectors rely on memorized surface form "
                     "(verbatim vs certified slice-preserving variant; seen vs unseen CVEs)?",
        "metrics": metrics,
        "baseline_comparison": baseline_comparison,
        "statistical_tests": statistical_tests,
        "per_detector": per_detector,
        "per_detector_gap": [d["delta_acc"] for d in llm],
        "llm_detectors": llm_keys,
        # lexical proxy; seen items are its reference set, so its AUC is trivially high
        "membership_probe": {**membership, "_note": "lexical proxy, not an LLM likelihood "
                             "probe; seen items form the reference set, so AUC ~1 is trivial"},
        "variant_yield": last["yield_stats"],
        "n_items": len(items),
        "n_matched_items": int(last["n_matched_cves"]),
        "n_unseen_items": int(sum(p == "unseen" for p in last["provenance"])),
        "repeats": int(max(1, repeats)),
        "llm_usage": LLMClient.get().stats() if llm_keys else {},
        "_data_source": source_tag,
    }
    all_results = {}
    if os.path.exists(RESULTS_JSON):
        try:
            all_results = load_results()
        except Exception:  # noqa: BLE001
            all_results = {}
    all_results["RQ1"] = json.loads(json.dumps(block, default=float))
    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(RESULTS_JSON, "w") as fh:
        json.dump(all_results, fh, indent=2, allow_nan=False)
    print(f"[analysis] wrote {RESULTS_JSON} (RQ1): gap={metrics['memorization_gap_acc_rq1']:+.3f} "
          f"OR={pooled_or:.2f} LLM acc seen={metrics['llm_acc_verbatim_seen']:.3f} "
          f"unseen={metrics['llm_acc_verbatim_unseen']:.3f}")
    main()
    return all_results


def main():
    results = load_results()
    rows = []

    analyze_rq1(results, rows)
    analyze_rq2(results, rows)
    analyze_rq3(results, rows)
    ensure_rq_coverage(results, rows)

    if not rows:
        raise RuntimeError(
            "No analysis rows were produced from results/results.json; "
            "cannot write an empty summary. Check that main.py populated metrics."
        )

    apply_holm_within_family(rows)
    rows = sanitize_rows(rows)

    # Validate coverage: at least one row per RQ present in results.json
    result_rqs = {str(k).upper() for k, v in results.items() if isinstance(v, dict)}
    covered = {r["rq"].upper() for r in rows}
    missing = result_rqs - covered
    if missing:
        raise RuntimeError(
            f"RQ(s) present in results.json but absent from analysis summary: {sorted(missing)}"
        )

    df = pd.DataFrame(rows)
    col_order = [
        "rq", "comparison", "metric", "test", "n",
        "estimate", "ci95_low", "ci95_high",
        "effect_size_name", "effect_size_value",
        "statistic", "p_raw", "p_corrected",
    ]
    df = df[[c for c in col_order if c in df.columns]]

    os.makedirs(RESULTS_DIR, exist_ok=True)
    df.to_csv(SUMMARY_CSV, index=False)

    # JSON: strict, no NaN/Inf
    payload = {
        "alpha": ALPHA,
        "multiple_comparison_correction": "Holm-Bonferroni within each RQ family",
        "bootstrap_resamples": N_BOOT,
        "n_rows": len(rows),
        "rows": rows,
    }
    with open(SUMMARY_JSON, "w") as fh:
        json.dump(payload, fh, indent=2, allow_nan=False)

    print(f"[analysis] wrote {len(rows)} rows -> {SUMMARY_CSV} and {SUMMARY_JSON}")
    for rq in sorted(covered):
        n = sum(1 for r in rows if r["rq"].upper() == rq)
        print(f"  {rq}: {n} comparison/metric rows")


if __name__ == "__main__":
    main()
