#!/usr/bin/env python3
"""Study pipeline: plots.py

Publication-ready figures for the controlled within-CVE paired experiment on
LLM-based vulnerable-clone detection (memorization vs. slice-semantic reasoning)
and slice-grounded patching.

Runs AFTER main.py -> analysis.py. Reads ONLY:
    results/analysis_summary.json  (primary; written by analysis.py)
    results/analysis_summary.csv   (fallback)
    results/results.json           (canonical; for richer per-item series)

Writes one or more figures per RQ to figures/{rq_id}_{name}.png at 300 DPI.
"""

import matplotlib
matplotlib.use("Agg")
import rp_style  # noqa: E402  house style AFTER backend selection

import os  # noqa: E402
import json  # noqa: E402
import math  # noqa: E402

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402

RESULTS_DIR = "results"
FIG_DIR = "figures"
SUMMARY_JSON = os.path.join(RESULTS_DIR, "analysis_summary.json")
SUMMARY_CSV = os.path.join(RESULTS_DIR, "analysis_summary.csv")
RESULTS_JSON = os.path.join(RESULTS_DIR, "results.json")

PALETTE = getattr(rp_style, "PALETTE", [
    "#0072B2", "#D55E00", "#009E73", "#CC79A7",
    "#E69F00", "#56B4E9", "#F0E442", "#000000",
])
CMAP = getattr(rp_style, "CMAP", "viridis")


# ---------------------------------------------------------------------------
# IO
# ---------------------------------------------------------------------------
def _finite(x):
    try:
        v = float(x)
    except (TypeError, ValueError):
        return None
    if math.isnan(v) or math.isinf(v):
        return None
    return v


def load_summary():
    if os.path.exists(SUMMARY_JSON):
        with open(SUMMARY_JSON, "r") as fh:
            payload = json.load(fh)
        rows = payload.get("rows", [])
        df = pd.DataFrame(rows)
    elif os.path.exists(SUMMARY_CSV):
        df = pd.read_csv(SUMMARY_CSV)
    else:
        raise RuntimeError(
            "Neither analysis_summary.json nor analysis_summary.csv found; "
            "analysis.py must run before plots.py."
        )
    if df.empty:
        raise RuntimeError("analysis summary is empty; nothing to plot.")
    for c in ("n", "estimate", "ci95_low", "ci95_high",
              "effect_size_value", "statistic", "p_raw", "p_corrected"):
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")
    return df


def load_results():
    if os.path.exists(RESULTS_JSON):
        try:
            with open(RESULTS_JSON, "r") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def get_block(results, rq):
    if not isinstance(results, dict):
        return {}
    if rq in results:
        return results[rq]
    for k, v in results.items():
        if str(k).lower() == rq.lower():
            return v
    return {}


def _assert_visible(values, name):
    arr = np.asarray([v for v in values if v is not None], dtype=float)
    arr = arr[np.isfinite(arr)]
    if arr.size == 0:
        raise RuntimeError(
            f"Plot series '{name}' has no finite values; pipeline bug."
        )


def _sig_stars(p):
    if p is None or not np.isfinite(p):
        return ""
    if p < 0.001:
        return "***"
    if p < 0.01:
        return "**"
    if p < 0.05:
        return "*"
    return "n.s."


def _err_pair(est, lo, hi):
    """Return (lower_err, upper_err) non-negative, or None if no CI."""
    est = _finite(est)
    lo = _finite(lo)
    hi = _finite(hi)
    if est is None or lo is None or hi is None:
        return None
    return (abs(est - lo), abs(hi - est))


def color_for(i):
    return PALETTE[i % len(PALETTE)]


# ---------------------------------------------------------------------------
# RQ1: memorization gap -- per-detector McNemar gaps (bar + CI + sig + OR)
# ---------------------------------------------------------------------------
def plot_rq1(df, results):
    sub = df[df["rq"].str.upper() == "RQ1"].copy()
    if sub.empty:
        return

    # Per-detector verbatim-vs-variant rows carry Δ_acc estimate + McNemar p + OR
    det_rows = sub[sub["test"] == "McNemar"].copy()
    det_rows = det_rows[det_rows["comparison"].str.contains("verbatim_vs_variant", case=False, na=False)]

    if not det_rows.empty and det_rows["estimate"].notna().any():
        det_rows = det_rows[det_rows["estimate"].notna()].reset_index(drop=True)
        labels = [c.split(":")[0].strip() for c in det_rows["comparison"]]
        ests = det_rows["estimate"].tolist()
        _assert_visible(ests, "RQ1 per-detector Δ_acc")

        fig, ax = plt.subplots(figsize=(max(7.5, 1.4 * len(labels) + 3), 4.8))
        x = np.arange(len(labels))
        errs = [[], []]
        have_err = False
        for _, r in det_rows.iterrows():
            ep = _err_pair(r["estimate"], r["ci95_low"], r["ci95_high"])
            if ep is None:
                errs[0].append(0.0)
                errs[1].append(0.0)
            else:
                errs[0].append(ep[0])
                errs[1].append(ep[1])
                have_err = True
        colors = [color_for(i) for i in range(len(labels))]
        bars = ax.bar(x, ests, color=colors, edgecolor="black", linewidth=0.6,
                      yerr=(np.array(errs) if have_err else None),
                      capsize=4, error_kw=dict(ecolor="#333333", lw=1.1))

        ax.axhline(0.0, color="#555555", lw=1.0)
        ax.axhline(0.10, color="#D55E00", lw=1.2, ls="--",
                   label="non-trivial gap target (0.10)")

        # significance stars + odds ratio annotation above each bar
        ymax = max([e for e in ests] + [0.1])
        for i, (_, r) in enumerate(det_rows.iterrows()):
            star = _sig_stars(r.get("p_corrected") if _finite(r.get("p_corrected")) is not None
                              else r.get("p_raw"))
            orr = _finite(r.get("effect_size_value"))
            top = ests[i] + (errs[1][i] if have_err else 0.0)
            txt = star
            if orr is not None:
                txt = f"{star}\nOR={orr:.2f}" if star else f"OR={orr:.2f}"
            if txt:
                ax.annotate(txt, xy=(x[i], top), xytext=(0, 6),
                            textcoords="offset points", ha="center", va="bottom",
                            fontsize=9)

        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=30, ha="right")
        ax.set_ylabel(r"Memorization gap  $\Delta_{acc}$ = Acc(verbatim) $-$ Acc(variant)")
        ax.set_xlabel("Detector")
        ax.legend(loc="best", frameon=False)
        rp_style.save(plt.gcf(), os.path.join(FIG_DIR, "RQ1_memorization_gap_per_detector.png"))
        plt.close(fig)
    else:
        # Fallback: summary gap + pooled odds ratio as two annotated bars
        gap_row = sub[sub["metric"] == "memorization_gap_acc_rq1"]
        or_row = sub[sub["metric"] == "pooled_split_odds_ratio_rq1"]
        vals, labels, kinds = [], [], []
        if not gap_row.empty and _finite(gap_row.iloc[0]["estimate"]) is not None:
            vals.append(float(gap_row.iloc[0]["estimate"]))
            labels.append(r"$\Delta_{acc}$ (pooled)")
            kinds.append("gap")
        if not or_row.empty and _finite(or_row.iloc[0]["estimate"]) is not None:
            vals.append(float(or_row.iloc[0]["estimate"]))
            labels.append("Pooled odds ratio")
            kinds.append("or")
        if not vals:
            return
        _assert_visible(vals, "RQ1 summary")
        fig, ax = plt.subplots(figsize=(7, 4.5))
        x = np.arange(len(vals))
        colors = [color_for(i) for i in range(len(vals))]
        ax.bar(x, vals, color=colors, edgecolor="black", linewidth=0.6)
        for i, (v, k) in enumerate(zip(vals, kinds)):
            ax.annotate(f"{v:.2f}", xy=(x[i], v), xytext=(0, 5),
                        textcoords="offset points", ha="center", fontsize=10)
        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=20, ha="right")
        ax.set_ylabel("Value")
        rp_style.save(plt.gcf(), os.path.join(FIG_DIR, "RQ1_memorization_summary.png"))
        plt.close(fig)


# ---------------------------------------------------------------------------
# RQ2a: construction validity -- yield / invariance / kappa proportions w/ CI
# ---------------------------------------------------------------------------
def plot_rq2_validity(df):
    sub = df[df["rq"].str.upper() == "RQ2"].copy()
    if sub.empty:
        return
    wanted = {
        "accepted_variant_yield_rq2": ("Accepted-variant\nyield", 0.60),
        "vsvector_invariance_pass_rate_rq2": ("vsvector invariance\npass rate", 0.95),
        "annotator_agreement_cohen_s_kappa_rq2": ("Audit agreement\n(Cohen's $\\kappa$)", None),
    }
    rows = sub[sub["metric"].isin(wanted.keys())].copy()
    rows = rows[rows["estimate"].notna()]
    if rows.empty:
        return
    labels, vals, los, his, targets = [], [], [], [], []
    for metric, (lab, tgt) in wanted.items():
        r = rows[rows["metric"] == metric]
        if r.empty:
            continue
        r = r.iloc[0]
        labels.append(lab)
        vals.append(float(r["estimate"]))
        los.append(_finite(r["ci95_low"]))
        his.append(_finite(r["ci95_high"]))
        targets.append(tgt)
    _assert_visible(vals, "RQ2 construction validity")

    fig, ax = plt.subplots(figsize=(7.2, 4.6))
    x = np.arange(len(labels))
    errs = [[], []]
    have_err = False
    for v, lo, hi in zip(vals, los, his):
        ep = _err_pair(v, lo, hi)
        if ep is None:
            errs[0].append(0.0)
            errs[1].append(0.0)
        else:
            errs[0].append(ep[0])
            errs[1].append(ep[1])
            have_err = True
    colors = [color_for(i) for i in range(len(labels))]
    ax.bar(x, vals, color=colors, edgecolor="black", linewidth=0.6,
           yerr=(np.array(errs) if have_err else None), capsize=4,
           error_kw=dict(ecolor="#333333", lw=1.1))

    # target reference ticks (small horizontal segments over each relevant bar)
    for i, tgt in enumerate(targets):
        if tgt is not None:
            ax.plot([x[i] - 0.4, x[i] + 0.4], [tgt, tgt],
                    color="#D55E00", ls="--", lw=1.3,
                    label="target" if i == 0 else None)
    for i, v in enumerate(vals):
        top = v + (errs[1][i] if have_err else 0.0)
        ax.annotate(f"{v:.2f}", xy=(x[i], top), xytext=(0, 5),
                    textcoords="offset points", ha="center", fontsize=10)

    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel("Proportion / agreement")
    ax.set_ylim(0, max(1.0, max(vals) * 1.15))
    handles, lbls = ax.get_legend_handles_labels()
    if handles:
        ax.legend(loc="lower right", frameon=False)
    rp_style.save(plt.gcf(), os.path.join(FIG_DIR, "RQ2_construction_validity.png"))
    plt.close(fig)


# ---------------------------------------------------------------------------
# RQ2b: invariance contrast -- DiD, prefer per-CVE delta distributions
# ---------------------------------------------------------------------------
def plot_rq2_did(df, results):
    sub = df[df["rq"].str.upper() == "RQ2"].copy()
    block = get_block(results, "RQ2")
    llm_delta = block.get("per_cve_llm_delta") if isinstance(block, dict) else None
    slice_delta = block.get("per_cve_slice_delta") if isinstance(block, dict) else None

    # Preferred: paired per-CVE drops as side-by-side box/strip (distribution)
    if (isinstance(llm_delta, list) and isinstance(slice_delta, list)
            and len(llm_delta) == len(slice_delta) and len(llm_delta) > 0):
        ld = np.asarray([_finite(v) for v in llm_delta], dtype=float)
        sd = np.asarray([_finite(v) for v in slice_delta], dtype=float)
        mask = np.isfinite(ld) & np.isfinite(sd)
        ld, sd = ld[mask], sd[mask]
        if ld.size > 0:
            _assert_visible(ld, "RQ2 LLM per-CVE deltas")
            _assert_visible(sd, "RQ2 slice per-CVE deltas")
            fig, ax = plt.subplots(figsize=(7, 4.6))
            data = [ld, sd]
            bp = ax.boxplot(data, patch_artist=True, widths=0.55,
                            showmeans=True, meanline=True,
                            medianprops=dict(color="black", lw=1.3),
                            meanprops=dict(color="#D55E00", lw=1.4, ls="--"))
            for i, box in enumerate(bp["boxes"]):
                box.set(facecolor=color_for(i), alpha=0.65, edgecolor="black")
            # jittered points
            for i, arr in enumerate(data):
                jit = np.random.default_rng(7).normal(0, 0.05, size=arr.size)
                ax.scatter(np.full(arr.size, i + 1) + jit, arr,
                           color=color_for(i), edgecolor="black",
                           linewidth=0.3, s=22, alpha=0.7, zorder=3)
            ax.axhline(0.0, color="#555555", lw=1.0)
            ax.set_xticks([1, 2])
            ax.set_xticklabels(["LLM detectors\n(verbatim$\\rightarrow$variant drop)",
                                "SRC VUL slice matcher\n(verbatim$\\rightarrow$variant drop)"])
            ax.set_ylabel(r"Per-CVE accuracy drop  $\Delta_{acc}$")

            # annotate DiD point + CI + p
            did_row = sub[sub["metric"] == "difference_in_differences_did_rq2"]
            if not did_row.empty:
                r = did_row.iloc[0]
                est = _finite(r["estimate"])
                lo = _finite(r["ci95_low"])
                hi = _finite(r["ci95_high"])
                p = _finite(r.get("p_corrected")) or _finite(r.get("p_raw"))
                parts = []
                if est is not None:
                    parts.append(f"DiD = {est:.3f}")
                if lo is not None and hi is not None:
                    parts.append(f"95% CI [{lo:.3f}, {hi:.3f}]")
                if p is not None:
                    parts.append(f"p={p:.3g} {_sig_stars(p)}")
                if parts:
                    ax.annotate("  ".join(parts), xy=(0.5, 0.97),
                                xycoords="axes fraction", ha="center", va="top",
                                fontsize=9,
                                bbox=dict(boxstyle="round", fc="white", ec="#888888"))
            rp_style.save(plt.gcf(), os.path.join(FIG_DIR, "RQ2_invariance_contrast_DiD.png"))
            plt.close(fig)
            return

    # Fallback: single DiD estimate with CI as a horizontal bar
    did_row = sub[sub["metric"] == "difference_in_differences_did_rq2"]
    if did_row.empty or _finite(did_row.iloc[0]["estimate"]) is None:
        return
    r = did_row.iloc[0]
    est = float(r["estimate"])
    _assert_visible([est], "RQ2 DiD estimate")
    ep = _err_pair(est, r["ci95_low"], r["ci95_high"])
    fig, ax = plt.subplots(figsize=(7, 3.6))
    err = np.array([[ep[0]], [ep[1]]]) if ep else None
    ax.barh([0], [est], color=color_for(2), edgecolor="black", linewidth=0.6,
            xerr=err, capsize=5, error_kw=dict(ecolor="#333333", lw=1.1), height=0.5)
    ax.axvline(0.0, color="#555555", lw=1.0)
    ax.axvline(0.08, color="#D55E00", ls="--", lw=1.2, label="target (>0.08)")
    ax.set_yticks([0])
    ax.set_yticklabels([r"DiD = $\Delta_{acc}$(LLM) $-$ $\Delta_{acc}$(slice matcher)"])
    ax.set_xlabel("Difference-in-differences")
    p = _finite(r.get("p_corrected")) or _finite(r.get("p_raw"))
    lab = f"{est:.3f}"
    if p is not None:
        lab += f"  (p={p:.3g} {_sig_stars(p)})"
    ax.annotate(lab, xy=(est, 0), xytext=(6, 10), textcoords="offset points",
                ha="left", fontsize=10)
    ax.legend(loc="best", frameon=False)
    rp_style.save(plt.gcf(), os.path.join(FIG_DIR, "RQ2_invariance_contrast_DiD.png"))
    plt.close(fig)


# ---------------------------------------------------------------------------
# RQ3a: VPR + oracle fidelity proportions (grouped bar with Wilson CI)
# ---------------------------------------------------------------------------
def plot_rq3_rates(df):
    sub = df[df["rq"].str.upper() == "RQ3"].copy()
    if sub.empty:
        return
    wanted = [
        ("validated_patch_rate_vpr_rq3", "Validated patch\nrate (VPR)", 0.80),
        ("official_patch_accept_rate_rq3", "Official patch\naccept rate", None),
        ("oracle_false_accept_rate_rq3", "Oracle false\naccept rate", None),
    ]
    labels, vals, los, his, targets = [], [], [], [], []
    for metric, lab, tgt in wanted:
        r = sub[sub["metric"] == metric]
        r = r[r["estimate"].notna()]
        if r.empty:
            continue
        r = r.iloc[0]
        labels.append(lab)
        vals.append(float(r["estimate"]))
        los.append(_finite(r["ci95_low"]))
        his.append(_finite(r["ci95_high"]))
        targets.append(tgt)
    if not vals:
        return
    _assert_visible(vals, "RQ3 rates")

    fig, ax = plt.subplots(figsize=(7.4, 4.6))
    x = np.arange(len(labels))
    errs = [[], []]
    have_err = False
    for v, lo, hi in zip(vals, los, his):
        ep = _err_pair(v, lo, hi)
        if ep is None:
            errs[0].append(0.0)
            errs[1].append(0.0)
        else:
            errs[0].append(ep[0])
            errs[1].append(ep[1])
            have_err = True
    colors = [color_for(i) for i in range(len(labels))]
    ax.bar(x, vals, color=colors, edgecolor="black", linewidth=0.6,
           yerr=(np.array(errs) if have_err else None), capsize=4,
           error_kw=dict(ecolor="#333333", lw=1.1))
    for i, tgt in enumerate(targets):
        if tgt is not None:
            ax.plot([x[i] - 0.4, x[i] + 0.4], [tgt, tgt], color="#D55E00",
                    ls="--", lw=1.3, label="VPR target (0.80)" if i == 0 else None)
    for i, v in enumerate(vals):
        top = v + (errs[1][i] if have_err else 0.0)
        ax.annotate(f"{v:.2f}", xy=(x[i], top), xytext=(0, 5),
                    textcoords="offset points", ha="center", fontsize=10)
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel("Rate")
    ax.set_ylim(0, max(1.0, max(vals) * 1.15))
    handles, lbls = ax.get_legend_handles_labels()
    if handles:
        ax.legend(loc="best", frameon=False)
    rp_style.save(plt.gcf(), os.path.join(FIG_DIR, "RQ3_patch_and_oracle_rates.png"))
    plt.close(fig)


# ---------------------------------------------------------------------------
# RQ3b: grounded vs ungrounded VPR gap (McNemar) + iterations-to-accept
# ---------------------------------------------------------------------------
def plot_rq3_comparison(df, results):
    sub = df[df["rq"].str.upper() == "RQ3"].copy()
    if sub.empty:
        return

    # Prefer per-CVE iterations distribution (paired) if available
    block = get_block(results, "RQ3")
    gi = block.get("grounded_iterations") if isinstance(block, dict) else None
    ui = block.get("ungrounded_iterations") if isinstance(block, dict) else None
    if (isinstance(gi, list) and isinstance(ui, list)
            and len(gi) == len(ui) and len(gi) > 0):
        g = np.asarray([_finite(v) for v in gi], dtype=float)
        u = np.asarray([_finite(v) for v in ui], dtype=float)
        mask = np.isfinite(g) & np.isfinite(u)
        g, u = g[mask], u[mask]
        if g.size > 0:
            _assert_visible(g, "RQ3 grounded iterations")
            _assert_visible(u, "RQ3 ungrounded iterations")
            fig, ax = plt.subplots(figsize=(7, 4.6))
            vp = ax.violinplot([g, u], showmeans=True, showextrema=True, widths=0.7)
            for i, body in enumerate(vp["bodies"]):
                body.set_facecolor(color_for(i))
                body.set_alpha(0.55)
                body.set_edgecolor("black")
            for key in ("cmeans", "cmins", "cmaxes", "cbars"):
                if key in vp:
                    vp[key].set_color("#333333")
            for i, arr in enumerate([g, u]):
                jit = np.random.default_rng(3).normal(0, 0.04, size=arr.size)
                ax.scatter(np.full(arr.size, i + 1) + jit, arr,
                           color=color_for(i), edgecolor="black",
                           linewidth=0.3, s=20, alpha=0.7, zorder=3)
            ax.set_xticks([1, 2])
            ax.set_xticklabels(["Slice-grounded\nagent", "Ungrounded\nLLM patching"])
            ax.set_ylabel("Iterations to accept (k$\\leq$5)")
            it_row = sub[sub["metric"] == "iterations_to_accept_rq3"]
            if not it_row.empty:
                r = it_row.iloc[0]
                p = _finite(r.get("p_corrected")) or _finite(r.get("p_raw"))
                rb = _finite(r.get("effect_size_value"))
                parts = []
                if p is not None:
                    parts.append(f"Wilcoxon p={p:.3g} {_sig_stars(p)}")
                if rb is not None:
                    parts.append(f"rank-biserial={rb:.2f}")
                if parts:
                    ax.annotate("  ".join(parts), xy=(0.5, 0.97),
                                xycoords="axes fraction", ha="center", va="top",
                                fontsize=9,
                                bbox=dict(boxstyle="round", fc="white", ec="#888888"))
            rp_style.save(plt.gcf(), os.path.join(FIG_DIR, "RQ3_iterations_to_accept.png"))
            plt.close(fig)

    # VPR gap: grounded vs best ungrounded (McNemar) -- Δ with CI + OR + p
    cmp_row = sub[sub["comparison"].str.contains("grounded_vs_best_ungrounded", case=False, na=False)]
    cmp_row = cmp_row[cmp_row["estimate"].notna()]
    if not cmp_row.empty:
        r = cmp_row.iloc[0]
        est = float(r["estimate"])
        _assert_visible([est], "RQ3 VPR gap")
        ep = _err_pair(est, r["ci95_low"], r["ci95_high"])
        fig, ax = plt.subplots(figsize=(7, 3.6))
        err = np.array([[ep[0]], [ep[1]]]) if ep else None
        ax.barh([0], [est], color=color_for(0), edgecolor="black", linewidth=0.6,
                xerr=err, capsize=5, error_kw=dict(ecolor="#333333", lw=1.1),
                height=0.5)
        ax.axvline(0.0, color="#555555", lw=1.0)
        ax.axvline(0.10, color="#D55E00", ls="--", lw=1.2, label="target (+0.10)")
        ax.set_yticks([0])
        ax.set_yticklabels(["VPR gap\n(grounded $-$ ungrounded)"])
        ax.set_xlabel("Validated-patch-rate difference")
        p = _finite(r.get("p_corrected")) or _finite(r.get("p_raw"))
        orr = _finite(r.get("effect_size_value"))
        lab = f"{est:+.3f}"
        extra = []
        if orr is not None:
            extra.append(f"OR={orr:.2f}")
        if p is not None:
            extra.append(f"p={p:.3g} {_sig_stars(p)}")
        if extra:
            lab += "  (" + ", ".join(extra) + ")"
        ax.annotate(lab, xy=(est, 0), xytext=(6, 10), textcoords="offset points",
                    ha="left", fontsize=10)
        ax.legend(loc="best", frameon=False)
        rp_style.save(plt.gcf(), os.path.join(FIG_DIR, "RQ3_vpr_gap_grounded_vs_ungrounded.png"))
        plt.close(fig)


# ---------------------------------------------------------------------------
# Generic fallback: any RQ with no dedicated figure gets a descriptive bar
# ---------------------------------------------------------------------------
def plot_generic_fallback(df, produced_rqs):
    for rq in sorted(df["rq"].str.upper().unique()):
        if rq in produced_rqs:
            continue
        sub = df[df["rq"].str.upper() == rq].copy()
        sub = sub[sub["estimate"].notna()]
        if sub.empty:
            continue
        sub = sub.head(10)
        labels = [f"{m}" for m in sub["metric"]]
        vals = sub["estimate"].tolist()
        _assert_visible(vals, f"{rq} fallback")
        fig, ax = plt.subplots(figsize=(max(7, 1.2 * len(labels) + 2), 4.6))
        x = np.arange(len(labels))
        errs = [[], []]
        have_err = False
        for _, r in sub.iterrows():
            ep = _err_pair(r["estimate"], r["ci95_low"], r["ci95_high"])
            if ep is None:
                errs[0].append(0.0)
                errs[1].append(0.0)
            else:
                errs[0].append(ep[0])
                errs[1].append(ep[1])
                have_err = True
        colors = [color_for(i) for i in range(len(labels))]
        ax.bar(x, vals, color=colors, edgecolor="black", linewidth=0.6,
               yerr=(np.array(errs) if have_err else None), capsize=4,
               error_kw=dict(ecolor="#333333", lw=1.1))
        for i, v in enumerate(vals):
            top = v + (errs[1][i] if have_err else 0.0)
            ax.annotate(f"{v:.3g}", xy=(x[i], top), xytext=(0, 5),
                        textcoords="offset points", ha="center", fontsize=9)
        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=30, ha="right")
        ax.set_ylabel("Estimate")
        rp_style.save(plt.gcf(), os.path.join(FIG_DIR, f"{rq}_summary.png"))
        plt.close(fig)


def main():
    os.makedirs(FIG_DIR, exist_ok=True)
    df = load_summary()
    results = load_results()

    df["rq"] = df["rq"].astype(str)

    plot_rq1(df, results)
    plot_rq2_validity(df)
    plot_rq2_did(df, results)
    plot_rq3_rates(df)
    plot_rq3_comparison(df, results)

    # ensure every RQ has at least one figure
    plot_generic_fallback(df, produced_rqs={"RQ1", "RQ2", "RQ3"})

    print(f"[plots] figures written to {FIG_DIR}/")


if __name__ == "__main__":
    main()
