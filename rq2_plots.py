"""rq2_plots.py — RQ2 figures.

Reads results/rq2_raw.json (written by rq2_analysis.py) and renders:
  - figures/rq2_e1_results.png  : RQ2-E1 construction validity
                                  (yield + Wilson CI, invariance, surface disruption,
                                   recall-collapse fingerprint-match drop)
  - figures/rq2_e2_results.png  : RQ2-E2 per-detector verbatim→variant Δ_acc with the
                                   SRC VUL slice matcher highlighted + DiD annotation
  - figures/rq2_alt1_results.png: contract alias of the main RQ2 result
  - figures/slice_worked_example.png : method figure (input artifact, slicing criterion,
                                   retained slice, removed/transformed context), rendered
                                   from the implemented slicer on a representative example.

Figures are generated from SAVED results, except the method figure which is
rendered from the implemented slicer/transformer on a representative example.

Key deps: matplotlib==3.9.1, numpy==2.2.6.
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

import rp_style  # noqa: E402
from data_prep import extract_slice, generate_synthetic_corpus  # noqa: E402
from variant_builder import build_variant  # noqa: E402

RANDOM_SEED = int(os.environ.get("RP_RANDOM_SEED", 42))
RESULTS_DIR = Path("results")
FIG_DIR = Path("figures")


def _load_raw() -> dict:
    p = RESULTS_DIR / "rq2_raw.json"
    if not p.exists():
        raise RuntimeError("results/rq2_raw.json missing — run rq2_analysis.py first.")
    return json.loads(p.read_text())


def _short(name: str) -> str:
    repl = {
        "lexical_recall_control": "Lexical ctrl",
        "finetuned_encoder_llm": "Encoder LLM",
        "slice_matcher_src_vul": "SRC VUL slice",
    }
    if name in repl:
        return repl[name]
    if "VUDDY" in name:
        return "VUDDY"
    if "VulPecker" in name:
        return "VulPecker"
    if "CodeBERT" in name:
        return "CodeBERT ft"
    if "instruct LLM" in name:
        return "Instruct LLM"
    if "RAG" in name:
        return "RAG LLM"
    if "Ungrounded" in name:
        return "Ungrounded LLM"
    if "VulSlicer" in name:
        return "VulSlicer"
    if "SRC VUL" in name:
        return "SRC VUL (base)"
    return name[:12]


def plot_rq2_e1(raw: dict) -> None:
    rp_style.apply()
    cons = raw["construction"]
    disr = raw["disruption"]
    rc = raw["recall_collapse"]

    fig, axes = plt.subplots(1, 3, figsize=(14, 4.5))

    # Panel 1: yield + invariance with Wilson CIs
    ax = axes[0]
    labels = ["Accepted\nyield Y", "vsvector\ninvariance"]
    vals = [cons["accepted_variant_yield"], cons["vsvector_invariance_pass_rate"]]
    cis = [cons["yield_wilson_ci"], cons["invariance_wilson_ci"]]
    err_lo = [v - ci[0] for v, ci in zip(vals, cis)]
    err_hi = [ci[1] - v for v, ci in zip(vals, cis)]
    ax.bar(labels, vals, yerr=[err_lo, err_hi], capsize=6,
           color=[rp_style.PALETTE[2], rp_style.PALETTE[0]])
    ax.axhline(0.60, ls="--", color="gray", lw=1, label="Y≥0.60 target")
    ax.axhline(0.95, ls=":", color="black", lw=1, label="inv≥0.95 target")
    ax.set_ylim(0, 1.1)
    ax.set_ylabel("Rate")
    ax.set_title(f"RQ2-E1 construction validity\nverdict: {cons['verdict']}")
    ax.legend(fontsize=7, loc="lower right")
    for i, v in enumerate(vals):
        ax.annotate(f"{v:.2f}", (i, v + 0.03), ha="center", fontsize=9)

    # Panel 2: surface-disruption calibration (semantics held, surface broken)
    ax = axes[1]
    dlabels = ["Norm.\nLevenshtein", "Token\nJaccard", "n-gram\noverlap", "vsvector\nsim"]
    dvals = [disr["norm_levenshtein_mean"], disr["token_jaccard_mean"],
             disr["ngram_overlap_mean"], disr["vsvector_similarity_mean"]]
    colors = [rp_style.PALETTE[1], rp_style.PALETTE[1], rp_style.PALETTE[1], rp_style.PALETTE[2]]
    ax.bar(dlabels, dvals, color=colors)
    ax.set_ylim(0, 1.1)
    ax.set_ylabel("Mean value")
    ax.set_title("Surface disruption vs. semantic preservation")
    for i, v in enumerate(dvals):
        ax.annotate(f"{v:.2f}", (i, v + 0.03), ha="center", fontsize=8)

    # Panel 3: recall-collapse positive control (fingerprint match drop)
    ax = axes[2]
    cats = ["Verbatim", "Accepted\nvariant"]
    fp = [rc["fingerprint_match_rate_verbatim"], rc["fingerprint_match_rate_variant"]]
    ax.bar(cats, fp, color=[rp_style.PALETTE[0], rp_style.PALETTE[5]])
    ax.set_ylim(0, 1.15)
    ax.set_ylabel("Exact fingerprint-match rate")
    ax.set_title(f"Recall-collapse control\nMcNemar p={rc['mcnemar_p']:.3g}, OR={rc['fingerprint_collapse_odds_ratio']:.2f}")
    for i, v in enumerate(fp):
        ax.annotate(f"{v:.2f}", (i, v + 0.03), ha="center", fontsize=9)

    rp_style.save(fig, FIG_DIR / "rq2_e1_results.png")


def plot_rq2_e2(raw: dict) -> None:
    rp_style.apply()
    per = raw["per_detector"]
    contrast = raw["invariance_contrast"]
    slice_key = raw["slice_matcher_key"]
    recall_keys = set(raw["recall_sensitive_keys"])

    names = list(per.keys())
    # order: slice matcher first, then recall-sensitive, then others
    def _rank(n):
        if n == slice_key:
            return 0
        if n in recall_keys:
            return 1
        return 2
    names.sort(key=_rank)

    labels = [_short(n) for n in names]
    acc_v = [per[n]["acc_verbatim"] for n in names]
    acc_t = [per[n]["acc_variant"] for n in names]
    deltas = [per[n]["delta_acc"] for n in names]

    x = np.arange(len(names))
    w = 0.38
    fig, ax = plt.subplots(figsize=(max(9, len(names) * 1.1), 5.2))
    colors_v = [rp_style.PALETTE[3] if n == slice_key else rp_style.PALETTE[0] for n in names]
    colors_t = [rp_style.PALETTE[6] if n == slice_key else rp_style.PALETTE[1] for n in names]
    ax.bar(x - w / 2, acc_v, w, label="Verbatim", color=colors_v)
    ax.bar(x + w / 2, acc_t, w, label="Accepted variant", color=colors_t)
    for i, d in enumerate(deltas):
        ytop = max(acc_v[i], acc_t[i]) + 0.02
        ax.annotate(f"Δ={d:+.2f}", (x[i], ytop), ha="center", fontsize=7)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.set_ylabel("Accuracy")
    ax.set_ylim(0, 1.2)
    did = contrast["difference_in_differences"]
    ci = contrast["did_bootstrap_ci"]
    verdict = contrast["verdict"]
    ax.set_title(
        "RQ2-E2 invariance contrast: verbatim vs. accepted-variant accuracy\n"
        f"DiD(recall−SRC VUL)={did:+.3f}  95% CI=[{ci[0]:+.3f}, {ci[1]:+.3f}]  "
        f"Wilcoxon p={contrast['wilcoxon_p']:.3g}  →  {verdict}"
    )
    ax.legend(loc="upper right")
    # highlight SRC VUL label
    for tick, n in zip(ax.get_xticklabels(), names):
        if n == slice_key:
            tick.set_fontweight("bold")
            tick.set_color(rp_style.PALETTE[3])
    out = rp_style.save(fig, FIG_DIR / "rq2_e2_results.png")
    shutil.copyfile(out, FIG_DIR / "rq2_alt1_results.png")
    print(f"[rq2_plots] copied -> {FIG_DIR / 'rq2_alt1_results.png'}")


def plot_did_forest(raw: dict) -> None:
    """Per-detector DiD vs SRC VUL with bootstrap CIs (forest-style)."""
    rp_style.apply()
    pdd = raw["invariance_contrast"].get("per_detector_did", {})
    if not pdd:
        return
    names = list(pdd.keys())
    labels = [_short(n) for n in names]
    dids = [pdd[n]["did_vs_src_vul"] for n in names]
    los = [pdd[n]["did_ci_low"] for n in names]
    his = [pdd[n]["did_ci_high"] for n in names]
    y = np.arange(len(names))
    fig, ax = plt.subplots(figsize=(7.5, max(4, len(names) * 0.55)))
    for i in range(len(names)):
        color = rp_style.PALETTE[2] if los[i] > 0 else rp_style.PALETTE[5]
        ax.plot([los[i], his[i]], [y[i], y[i]], color=color, lw=2)
        ax.plot(dids[i], y[i], "o", color=color)
    ax.axvline(0, color="k", lw=0.8, ls="--")
    ax.set_yticks(y)
    ax.set_yticklabels(labels)
    ax.set_xlabel("DiD (detector Δ_acc − SRC VUL Δ_acc), bootstrap 95% CI")
    ax.set_title("RQ2-E2: provenance delta over the deterministic slice matcher")
    rp_style.save(fig, FIG_DIR / "rq2_did_forest.png")


def plot_slice_worked_example() -> None:
    """Method figure: input artifact, slicing criterion, retained slice, removed context."""
    rp_style.apply()
    items = generate_synthetic_corpus(1, seed=RANDOM_SEED)
    vuln = items[0]
    variant = build_variant(vuln, seed=RANDOM_SEED)
    slice_lines = set(l.strip() for l in extract_slice(vuln.code))

    fig, axes = plt.subplots(1, 3, figsize=(15, 5))

    ax = axes[0]
    ax.axis("off")
    ax.set_title("Input CVE clone\n(criterion = vuln sink, red)", fontsize=10)
    y = 0.95
    for ln in vuln.code.splitlines():
        s = ln.strip()
        in_slice = s in slice_lines
        is_sink = any(k in s for k in ["strcpy", "memcpy", "free", "malloc"])
        color = "#c53030" if is_sink else ("#2f855a" if in_slice else "#a0aec0")
        weight = "bold" if (in_slice or is_sink) else "normal"
        ax.text(0.02, y, ln, fontsize=8, family="monospace", color=color,
                fontweight=weight, transform=ax.transAxes)
        y -= 0.08

    ax = axes[1]
    ax.axis("off")
    ax.set_title("Retained vulnerability slice (vsvector)\n(kept — defines semantics)", fontsize=10)
    y = 0.95
    for ln in extract_slice(vuln.code):
        ax.text(0.02, y, ln, fontsize=8, family="monospace", color="#2f855a",
                fontweight="bold", transform=ax.transAxes)
        y -= 0.09

    ax = axes[2]
    ax.axis("off")
    cert = "ACCEPTED (vsvector invariant)" if variant.certified else "REJECTED"
    ax.set_title(f"Slice-preserving variant\nT={'+'.join(variant.ops_applied)} — {cert}",
                 fontsize=10)
    var_slice = set(l.strip() for l in extract_slice(variant.code))
    y = 0.95
    for ln in variant.code.splitlines():
        s = ln.strip()
        in_slice = s in var_slice
        color = "#2f855a" if in_slice else "#a0aec0"
        ax.text(0.02, y, ln, fontsize=7.5, family="monospace", color=color,
                fontweight="bold" if in_slice else "normal", transform=ax.transAxes)
        y -= 0.07

    fig.suptitle("SliceGuard worked example (RQ2): retained vulnerability slice is held "
                 "invariant while surface context is transformed (muted = removed/irrelevant)",
                 fontsize=11)
    rp_style.save(fig, FIG_DIR / "slice_worked_example.png")


def main() -> None:
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    raw = _load_raw()
    plot_rq2_e1(raw)
    plot_rq2_e2(raw)
    plot_did_forest(raw)
    plot_slice_worked_example()
    print("[rq2_plots] all RQ2 figures generated.")


if __name__ == "__main__":
    main()