"""rq3_plots.py — RQ3 figures.

Reads results/rq3_raw.json (written by rq3_analysis.py) and renders:
  - figures/rq3_e1_results.png : RQ3-E1 oracle calibration — confusion matrix,
                                 official-accept vs false-accept (with targets),
                                 severance-vs-oracle agreement (MCC/kappa),
                                 and the negative/positive controls.
  - figures/rq3_e2_results.png : RQ3-E2 ladder VPR per condition with Wilson 95% CIs,
                                 slice_grounded_full highlighted, gap + McNemar p annotated.
  - figures/rq3_alt1_results.png : contract alias of the main RQ3 result.
  - figures/slice_worked_example.png : method figure (input artifact, slicing criterion,
                                 retained slice, removed/transformed context), rendered from
                                 the implemented slicer + the slice-grounded repair operator.

All result panels are generated from SAVED results; the method figure is rendered
from the implemented slicer/agent on a representative example.

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
from data_prep import extract_slice  # noqa: E402
from rq3_data import generate_synthetic_patch_corpus  # noqa: E402

RANDOM_SEED = int(os.environ.get("RP_RANDOM_SEED", 42))
RESULTS_DIR = Path("results")
FIG_DIR = Path("figures")


def _load_raw() -> dict:
    p = RESULTS_DIR / "rq3_raw.json"
    if not p.exists():
        raise RuntimeError("results/rq3_raw.json missing — run rq3_analysis.py first.")
    return json.loads(p.read_text())


_COND_SHORT = {
    "no_grounding_no_feedback": "Ungrounded\n(no feedback)",
    "compiler_test_feedback": "Compiler/test\nfeedback",
    "cve_text_rag": "CVE-text\nRAG",
    "slice_grounded_no_feedback": "Slice-grounded\n(no feedback)",
    "slice_grounded_full": "Slice-grounded\nFULL agent",
}


def plot_rq3_e1(raw: dict) -> None:
    rp_style.apply()
    o = raw["oracle"]
    cm = o["confusion_matrix"]

    fig, axes = plt.subplots(1, 3, figsize=(15, 4.6))

    # Panel 1: confusion matrix heatmap
    ax = axes[0]
    mat = np.array([[cm["tp"], cm["fn"]], [cm["fp"], cm["tn"]]])
    im = ax.imshow(mat, cmap="Blues")
    ax.set_xticks([0, 1]); ax.set_xticklabels(["pred Accept", "pred Reject"])
    ax.set_yticks([0, 1]); ax.set_yticklabels(["gold Accept\n(official fix)", "gold Reject\n(known-bad)"])
    for i in range(2):
        for j in range(2):
            ax.text(j, i, str(mat[i, j]), ha="center", va="center",
                    color="black", fontsize=12, fontweight="bold")
    ax.set_title("RQ3-E1 independent-oracle\nconfusion matrix")
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)

    # Panel 2: official-accept vs false-accept with targets
    ax = axes[1]
    oa = o["official_patch_accept_rate"]
    fa = o["oracle_false_accept_rate"]
    oa_ci = o["official_accept_wilson_ci"]
    fa_ci = o["false_accept_wilson_ci"]
    labels = ["Official-patch\naccept", "Known-bad\nfalse-accept"]
    vals = [oa, fa]
    cis = [oa_ci, fa_ci]
    err_lo = [max(0.0, v - ci[0]) for v, ci in zip(vals, cis)]
    err_hi = [max(0.0, ci[1] - v) for v, ci in zip(vals, cis)]
    colors = [rp_style.PALETTE[2], rp_style.PALETTE[1]]
    ax.bar(labels, vals, yerr=[err_lo, err_hi], capsize=6, color=colors)
    ax.axhline(0.90, ls="--", color="green", lw=1, label="accept≥0.90 target")
    ax.axhline(0.10, ls=":", color="red", lw=1, label="false-accept≤0.10 target")
    ax.set_ylim(0, 1.1)
    ax.set_ylabel("Rate (Wilson 95% CI)")
    precond = "PASS" if o["oracle_precondition_ok"] else "FAIL"
    ax.set_title(f"Oracle fidelity precondition: {precond}")
    ax.legend(fontsize=7, loc="center right")
    for i, v in enumerate(vals):
        ax.annotate(f"{v:.2f}", (i, v + 0.03), ha="center", fontsize=9)

    # Panel 3: severance-vs-oracle agreement + controls
    ax = axes[2]
    cats = ["Severance\nMCC", "Severance\nkappa", "Severance\nfalse-accept",
            "Pos.ctrl\n(del→rej)"]
    vals3 = [o["severance_vs_oracle_mcc"], o["severance_vs_oracle_kappa"],
             o["severance_false_accept_rate"],
             o["positive_control_slice_deletion_severed_but_rejected"]]
    colors3 = [rp_style.PALETTE[0], rp_style.PALETTE[3], rp_style.PALETTE[1],
               rp_style.PALETTE[2]]
    ax.bar(cats, vals3, color=colors3)
    ax.axhline(0, color="k", lw=0.6)
    ax.set_ylim(min(-0.2, min(vals3) - 0.1), 1.1)
    neg = "OK" if o["negative_control_identical_fix_accepted"] else "FAIL"
    ax.set_title(f"Severance = intermediate signal\n(neg ctrl identical-fix accept: {neg})")
    for i, v in enumerate(vals3):
        ax.annotate(f"{v:.2f}", (i, v + 0.03), ha="center", fontsize=8)

    rp_style.save(fig, FIG_DIR / "rq3_e1_results.png")


def plot_rq3_e2(raw: dict) -> None:
    rp_style.apply()
    ladder = raw["ladder"]
    order = raw["ladder_order"]
    per = ladder["per_condition"]

    labels = [_COND_SHORT.get(c, c) for c in order]
    vprs = [per[c]["validated_patch_rate_vpr"] for c in order]
    cis = [per[c]["vpr_wilson_ci"] for c in order]
    err_lo = [max(0.0, v - ci[0]) for v, ci in zip(vprs, cis)]
    err_hi = [max(0.0, ci[1] - v) for v, ci in zip(vprs, cis)]
    grounded = ladder["grounded_full_condition"]
    colors = [rp_style.PALETTE[2] if c == grounded else rp_style.PALETTE[0] for c in order]

    x = np.arange(len(order))
    fig, ax = plt.subplots(figsize=(max(9, len(order) * 1.3), 5.2))
    ax.bar(x, vprs, yerr=[err_lo, err_hi], capsize=6, color=colors)
    for i, v in enumerate(vprs):
        ax.annotate(f"{v:.2f}", (x[i], v + 0.03), ha="center", fontsize=9)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=8)
    ax.set_ylabel("Validated-Patch Rate (VPR), Wilson 95% CI")
    ax.set_ylim(0, 1.2)

    gap = ladder["absolute_vpr_gap"]
    mc = ladder["mcnemar_grounded_vs_ungrounded"]
    ab = ladder["mcnemar_ablation_full_vs_no_feedback"]
    verdict = raw["decision"]["verdict"]
    ax.set_title(
        "RQ3-E2 detect-verify-patch ladder: VPR under the INDEPENDENT oracle\n"
        f"gap(full − best ungrounded)={gap:+.3f}  McNemar p_holm={mc['p_holm']:.3g} "
        f"OR={mc['odds_ratio']:.2f}  |  ablation(full vs no-feedback) p_holm={ab['p_holm']:.3g}\n"
        f"verdict: {verdict}"
    )
    # highlight the full-agent tick
    for tick, c in zip(ax.get_xticklabels(), order):
        if c == grounded:
            tick.set_fontweight("bold")
            tick.set_color(rp_style.PALETTE[2])
    out = rp_style.save(fig, FIG_DIR / "rq3_e2_results.png")
    shutil.copyfile(out, FIG_DIR / "rq3_alt1_results.png")
    print(f"[rq3_plots] copied -> {FIG_DIR / 'rq3_alt1_results.png'}")


def plot_slice_worked_example() -> None:
    """Method figure on a REAL Big-Vul CVE: input vulnerable function, retained
    vulnerability slice, and the full agent's actual LLM patch for it (the first,
    shortest CVE whose slice_grounded_full patch the independent oracle validated;
    responses come from the run's LLM cache, same seeds as ladder repeat 1)."""
    rp_style.apply()
    from patch_agent import run_agent_on_item
    from rq3_data import build_rq3_corpus

    items, _ = build_rq3_corpus(n_cves=300, allow_synthetic=False, seed=RANDOM_SEED)
    chosen = None
    for i, it in sorted(enumerate(items), key=lambda p: len(p[1].vulnerable_code.splitlines())):
        if len(it.vulnerable_code.splitlines()) > 22:
            break
        run = run_agent_on_item(it, "slice_grounded_full", seed=RANDOM_SEED + i * 101)
        if run.validated:
            chosen = (it, run)
            break
    if chosen is None:
        print("[rq3_plots] no short validated full-agent patch; worked example skipped")
        return
    item, run = chosen
    slice_lines = set(l.strip() for l in extract_slice(item.vulnerable_code))
    patched = run.final_patch
    vuln_lines = set(l.strip() for l in item.vulnerable_code.splitlines())

    fig, axes = plt.subplots(1, 3, figsize=(15, 5))

    # Panel 1: input vulnerable function + criterion
    ax = axes[0]
    ax.axis("off")
    ax.set_title("Input vulnerable function\n(green = slice statements, red = sink call)", fontsize=10)
    y = 0.95
    for ln in item.vulnerable_code.splitlines():
        s = ln.strip()
        in_slice = s in slice_lines
        is_sink = any(k in s for k in ["strcpy", "memcpy", "free", "malloc"])
        color = "#c53030" if is_sink else ("#2f855a" if in_slice else "#a0aec0")
        weight = "bold" if (in_slice or is_sink) else "normal"
        ax.text(0.02, y, ln, fontsize=8, family="monospace", color=color,
                fontweight=weight, transform=ax.transAxes)
        y -= 0.08

    # Panel 2: retained vulnerability slice (vrslice / vsvector)
    ax = axes[1]
    ax.axis("off")
    ax.set_title(f"Retained vulnerability slice (vrslice)\ngiven to the agent with {item.cve_id} text", fontsize=10)
    y = 0.95
    for ln in extract_slice(item.vulnerable_code):
        ax.text(0.02, y, ln, fontsize=8, family="monospace", color="#2f855a",
                fontweight="bold", transform=ax.transAxes)
        y -= 0.09

    # Panel 3: slice-grounded repair (added guard statements highlighted)
    ax = axes[2]
    ax.axis("off")
    ax.set_title(f"Agent's LLM patch (validated, {run.iterations} attempt(s))\n(green=added/changed line, muted=unchanged)", fontsize=10)
    y = 0.95
    for ln in patched.splitlines():
        s = ln.strip()
        added = bool(s) and s not in vuln_lines
        in_slice = s in slice_lines
        if added:
            color = "#2f855a"
        elif in_slice:
            color = "#2b6cb0"
        else:
            color = "#a0aec0"
        ax.text(0.02, y, ln, fontsize=7.5, family="monospace", color=color,
                fontweight="bold" if added else "normal", transform=ax.transAxes)
        y -= 0.065

    fig.suptitle(f"Worked example (RQ3, {item.cve_id}, {item.cwe}): the vulnerability slice and CVE "
                 "text ground the LLM repair; the official fix is never shown to the agent",
                 fontsize=11)
    rp_style.save(fig, FIG_DIR / "slice_worked_example.png")


def main() -> None:
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    raw = _load_raw()
    plot_rq3_e1(raw)
    plot_rq3_e2(raw)
    plot_slice_worked_example()
    print("[rq3_plots] all RQ3 figures generated.")


if __name__ == "__main__":
    main()