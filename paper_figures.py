"""paper_figures.py — publication figures for RQ1-RQ3, drawn from the measured results only.

Reads results/results.json (and results/rq3_failure_reasons.json if present); makes no LLM
calls. Writes figures/paper/fig{1,2,3}_*.{pdf,png}.

Encoding: one validated categorical palette (blue / orange / aqua, checked for CVD separation),
assigned by detector FAMILY — LLM, surface-similarity, slice-based — and each family also has
its own marker shape, so identity never rests on colour alone (greyscale/print safe). Every
proportion carries a 95% Wilson interval; every point is direct-labelled.
"""
from __future__ import annotations

import json
import math
import os
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

ROOT = Path(__file__).resolve().parent
RES = ROOT / "results"
OUT = ROOT / "figures" / "paper"

INK, INK2, GRID, SURFACE = "#0b0b0b", "#52514e", "#e6e5e1", "#ffffff"
FAMILY = {  # colour + marker per detector family (palette validated: scripts/validate_palette.js)
    "LLM": ("#2a78d6", "o"),
    "Surface similarity": ("#eb6834", "s"),
    "Slice-based": ("#1baf7a", "^"),
}
# (results key, display name, family) — duplicated registry aliases are omitted
DETECTORS = [
    ("Open-weight instruct LLM detector (e.g., StarCoder2/CodeLlama, elatoubi2025assessing-style prompting)",
     "Instruct prompt", "LLM"),
    ("RAG-based LLM vulnerability detector (antal2026evaluating / kaniewski2026revisiting style)",
     "RAG prompt", "LLM"),
    ("Ungrounded LLM patching (same LLM, no slice/CVE grounding) — primary RQ3 baseline",
     "Ungrounded prompt", "LLM"),
    ("lexical_recall_control", "Lexical recall (1-NN)", "Surface similarity"),
    ("VUDDY hashing-based vulnerable clone detector (from VUDDY corpus / salimi2022vulslicer comparison)",
     "VUDDY-style hash", "Surface similarity"),
    ("VulPecker code-similarity vulnerability detector (li2016vulpecker)", "VulPecker-style", "Surface similarity"),
    ("finetuned_encoder_llm", "TF-IDF + LR", "Surface similarity"),
    ("slice_matcher_src_vul", "Slice-signature match", "Slice-based"),
    ("VulSlicer slice-based detector (salimi2022vulslicer)", "VulSlicer-style", "Slice-based"),
]
ARMS = [
    ("no_grounding_no_feedback", "Ungrounded"),
    ("compiler_test_feedback", "+ static feedback"),
    ("cve_text_rag", "+ CVE text"),
    ("slice_grounded_no_feedback", "+ CVE text + slice"),
    ("slice_grounded_full", "Full agent\n(+ slice feedback)"),
]


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float, float]:
    if n == 0:
        return 0.0, 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0.0, c - h), min(1.0, c + h)


def style() -> None:
    plt.rcParams.update({
        "font.family": "DejaVu Sans", "font.size": 8, "axes.titlesize": 8.5,
        "axes.labelsize": 8, "xtick.labelsize": 7.5, "ytick.labelsize": 7.5,
        "legend.fontsize": 7.5, "axes.edgecolor": INK2, "axes.labelcolor": INK,
        "xtick.color": INK2, "ytick.color": INK2, "axes.spines.top": False,
        "axes.spines.right": False, "axes.grid": False, "figure.facecolor": SURFACE,
        "axes.facecolor": SURFACE, "savefig.dpi": 300, "pdf.fonttype": 42,
        "figure.constrained_layout.use": True,
    })


def save(fig, name: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for ext in ("pdf", "png"):
        fig.savefig(OUT / f"{name}.{ext}", bbox_inches="tight")
    plt.close(fig)
    print(f"[paper_figures] wrote {OUT / name}.{{pdf,png}}")


def _provenance_of_matched(seed: int) -> list[str]:
    """Provenance of the RQ1 matched items in the order invariance_contrast used (last repeat)."""
    from data_prep import build_corpus
    from variant_builder import build_certified_variants
    items, _ = build_corpus(n_cves=300, allow_synthetic=False, seed=42)
    variants, _ = build_certified_variants(items, seed=seed)
    used, prov = set(), []
    for it in items:
        for v in variants:
            if id(v) in used:
                continue
            if v.cve_id == it.cve_id and v.label == it.label and v.provenance == it.provenance:
                prov.append(it.provenance)
                used.add(id(v))
                break
    return prov


# ---------------------------------------------------------------------------
# Figure 0 — study overview (what was actually implemented and run)
# ---------------------------------------------------------------------------
def fig0() -> None:
    from matplotlib.patches import FancyBboxPatch
    fig, ax = plt.subplots(figsize=(7.1, 4.45))
    ax.set_xlim(0, 100)
    ax.set_ylim(-16.5, 49.5)
    ax.axis("off")
    LLM, SURF, SLICE = FAMILY["LLM"][0], FAMILY["Surface similarity"][0], FAMILY["Slice-based"][0]

    def box(x, y, w, h, title, sub="", edge=INK2, lw=1.0, fill=SURFACE, bold=False):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.25,rounding_size=0.8",
                                    fc=fill, ec=edge, lw=lw))
        cy = y + h / 2 + (1.1 if sub else 0)
        ax.text(x + w / 2, cy, title, ha="center", va="center", fontsize=7.2, color=INK,
                fontweight="bold" if bold else "normal")
        if sub:
            ax.text(x + w / 2, y + h / 2 - 1.6, sub, ha="center", va="center", fontsize=6.0,
                    color=INK2, linespacing=1.15)

    def arrow(x0, y0, x1, y1, ls="-", label="", lx=None, ly=None):
        ax.annotate("", xy=(x1, y1), xytext=(x0, y0),
                    arrowprops=dict(arrowstyle="-|>", color=INK2, lw=0.9, ls=ls,
                                    shrinkA=1, shrinkB=1, mutation_scale=7))
        if label:
            ax.text(lx if lx is not None else (x0 + x1) / 2, ly if ly is not None else (y0 + y1) / 2 + 1.0,
                    label, ha="center", va="bottom", fontsize=5.8, color=INK2, style="italic")

    # lane labels
    for y, lab in ((41.0, "DATA"), (24.0, "RQ2 / RQ3"), (8.0, "RQ1, RQ3"), (-8.8, "RQ4")):
        ax.text(0.3, y, lab, ha="left", va="center", fontsize=6.5, color=INK2, fontweight="bold", rotation=90)
    ax.plot([3, 100], [32.2, 32.2], color=GRID, lw=0.8)
    ax.plot([3, 100], [16.0, 16.0], color=GRID, lw=0.8)

    # DATA lane
    box(4, 43, 27, 5.4, "Big-Vul pairs (150 CVEs)", "pre-cutoff = 'seen'")
    box(4, 34.2, 27, 7.0, "Mined fix commits (56 CVEs)", "VUDDY FuncParser; CVE published\n>= 2025-08-01 = 'unseen'")
    box(38, 37.5, 24, 8.0, "Vulnerable / fixed function pairs", "func_before = 1, func_after = 0\nCVE id, CWE, CVE text")
    arrow(31.6, 45.7, 37.6, 43.4)
    arrow(31.6, 37.7, 37.6, 39.6)
    box(69, 37.5, 28, 8.0, "Program slice per function", "backward slice from sink statements")
    arrow(62.6, 41.5, 68.6, 41.5)

    # RQ1 / RQ2 lane
    box(4, 19, 19, 9.5, "Variant builder", "rename params/locals,\nreformat, dead code")
    box(28, 19, 19, 9.5, "Slice certification", "slice identical\nmodulo renaming\n(73% certified)")
    arrow(23.6, 23.7, 27.6, 23.7)
    box(52, 25, 21, 5.4, "LLM detectors", "Claude Haiku 4.5, 3 prompts", edge=LLM, lw=1.3)
    box(52, 18.6, 21, 5.4, "Clone & slice detectors", "VUDDY, lexical, VulPecker, slice", edge=SURF, lw=1.3)
    arrow(47.6, 25.5, 51.6, 27.4)
    arrow(47.6, 22.0, 51.6, 21.2)
    box(78, 19, 19.5, 9.5, "Accuracy gap", "verbatim vs variant;\nseen vs unseen;\nMcNemar, DiD")
    arrow(73.6, 27.6, 77.6, 25.5)
    arrow(73.6, 21.2, 77.6, 22.4)
    arrow(50, 37.2, 14, 28.9)
    ax.text(41, 34.0, "verbatim functions", ha="left", va="center", fontsize=5.8, color=INK2, style="italic")

    # RQ3 lane
    box(4, 3, 19, 9.5, "Vulnerable function", "+ CVE text, + slice\n(per ladder arm)")
    box(28, 3, 21, 9.5, "LLM patch agent", "Claude Haiku 4.5\nreturns full function", edge=LLM, lw=1.3)
    arrow(23.6, 7.7, 27.6, 7.7)
    box(54, 3, 18, 9.5, "Agent's own checks", "static; slice severance\n(retry <= 5)")
    arrow(49.6, 9.4, 53.6, 9.4)
    arrow(53.6, 6.0, 49.6, 6.0, ls=(0, (2, 1.5)), label="feedback", lx=51.6, ly=1.4)
    box(77, 3, 20.5, 9.5, "Independent oracle", "only component that sees\nthe official fix -> VPR", edge=INK, lw=1.4, bold=True)
    arrow(72.6, 7.7, 76.6, 7.7)
    # RQ4 lane: retrieve and port a known fix to cross-branch clones
    ax.plot([3, 100], [-1.2, -1.2], color=GRID, lw=0.8)
    box(4, -13.5, 19, 9.5, "Backport clone families", "183 families, 63 CVEs\n88 hard clones")
    box(28, -13.5, 21, 9.5, "srcVul retrieval", "slicing vectors (srcSlice)\nof source fixes")
    arrow(23.6, -8.8, 27.6, -8.8)
    box(54, -13.5, 18, 9.5, "LLM porting agent", "source fix + clone\n(+ srcVul variable map)", edge=LLM, lw=1.3)
    arrow(49.6, -8.8, 53.6, -8.8)
    box(77, -13.5, 20.5, 9.5, "Independent oracle", "vs. the clone's own\nofficial fix -> VPR", edge=INK, lw=1.4, bold=True)
    arrow(72.6, -8.8, 76.6, -8.8)
    save(fig, "fig0_overview")


# ---------------------------------------------------------------------------
# Figure 1 — RQ1: verbatim vs certified-variant accuracy; LLM seen vs unseen
# ---------------------------------------------------------------------------
def fig1(r1: dict) -> None:
    per = r1["per_detector"]
    fig, (ax, bx) = plt.subplots(1, 2, figsize=(7.1, 3.0), width_ratios=[1.75, 1])

    rows = [d for d in DETECTORS if d[0] in per]
    y = np.arange(len(rows))[::-1]
    for yi, (key, name, fam) in zip(y, rows):
        col, mk = FAMILY[fam]
        cv, ct = per[key]["verbatim_correct"], per[key]["variant_correct"]
        pv, lv, hv = wilson(sum(cv), len(cv))
        pt, lt, ht = wilson(sum(ct), len(ct))
        ax.plot([pv, pt], [yi + 0.17, yi - 0.17], color=col, lw=1.2, solid_capstyle="round", zorder=2)
        ax.errorbar(pv, yi + 0.17, xerr=[[pv - lv], [hv - pv]], fmt=mk, ms=5.5, mfc=SURFACE,
                    mec=col, mew=1.4, ecolor=col, elinewidth=0.8, capsize=0, zorder=3)
        ax.errorbar(pt, yi - 0.17, xerr=[[pt - lt], [ht - pt]], fmt=mk, ms=5.5, mfc=col,
                    mec=SURFACE, mew=0.6, ecolor=col, elinewidth=0.8, capsize=0, zorder=3)
        gap = pv - pt
        ax.text(1.005, yi, f"{gap:+.2f}", va="center", ha="left", fontsize=7,
                color=INK if abs(gap) >= 0.1 else INK2,
                fontweight="bold" if abs(gap) >= 0.1 else "normal")
    ax.axvline(0.5, color=INK2, lw=0.8, ls=(0, (3, 2)), zorder=1)
    ax.text(0.5, len(rows) - 0.35, "chance", ha="center", va="bottom", fontsize=7, color=INK2)
    ax.set_yticks(y, [n for _, n, _ in rows])
    ax.set_xlim(0.38, 1.0)
    ax.set_ylim(-0.7, len(rows) - 0.1)
    ax.set_xlabel("Accuracy (95% Wilson CI)")
    ax.set_title("(a) Verbatim vs. certified slice-preserving variant", loc="left")
    ax.text(1.005, len(rows) - 0.35, "gap", ha="left", va="bottom", fontsize=7, color=INK2)
    ax.xaxis.grid(True, color=GRID, lw=0.6)
    # legend: open = verbatim, filled = variant; one entry per family
    from matplotlib.lines import Line2D
    handles = [Line2D([], [], marker="o", ls="", mfc=SURFACE, mec=INK2, mew=1.2, ms=5, label="verbatim"),
               Line2D([], [], marker="o", ls="", mfc=INK2, mec=SURFACE, ms=5, label="variant")]
    handles += [Line2D([], [], marker=mk, ls="-", color=c, ms=5, label=f) for f, (c, mk) in FAMILY.items()]
    ax.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.45, -0.17), frameon=False, ncol=5,
              handlelength=1.4, columnspacing=1.0, handletextpad=0.4)

    # (b) LLM verbatim accuracy on pre-cutoff (seen) vs post-cutoff (unseen) CVEs
    prov = np.array(_provenance_of_matched(seed=42 + int(r1.get("repeats", 3)) - 1))
    llm = [d for d in DETECTORS if d[2] == "LLM" and d[0] in per]
    col, mk = FAMILY["LLM"]
    for i, (key, name, _) in enumerate(llm):
        cv = np.array(per[key]["verbatim_correct"], dtype=int)
        if len(cv) != len(prov):
            continue
        for j, (grp, lab) in enumerate((("seen", "seen"), ("unseen", "unseen"))):
            m = prov == grp
            p, lo, hi = wilson(int(cv[m].sum()), int(m.sum()))
            x = i + (j - 0.5) * 0.32
            bx.errorbar(x, p, yerr=[[p - lo], [hi - p]], fmt=mk, ms=5.5,
                        mfc=SURFACE if grp == "seen" else col, mec=col, mew=1.3,
                        ecolor=col, elinewidth=0.8, capsize=0)
    bx.axhline(0.5, color=INK2, lw=0.8, ls=(0, (3, 2)))
    from matplotlib.lines import Line2D as _L
    bx.legend(handles=[_L([], [], marker=mk, ls="", mfc=SURFACE, mec=col, mew=1.3, ms=5,
                          label=f"pre-cutoff (n={int((prov == 'seen').sum())})"),
                       _L([], [], marker=mk, ls="", mfc=col, mec=col, ms=5,
                          label=f"post-cutoff (n={int((prov == 'unseen').sum())})")],
              loc="upper left", frameon=False, handletextpad=0.3)
    bx.set_xticks(range(len(llm)), [n.replace(" prompt", "\nprompt") for _, n, _ in llm])
    bx.set_ylim(0.3, 0.82)
    bx.set_ylabel("Verbatim accuracy (95% CI)")
    bx.set_title("(b) LLM: pre- vs. post-cutoff CVEs", loc="left")
    bx.yaxis.grid(True, color=GRID, lw=0.6)
    save(fig, "fig1_rq1_memorization")


# ---------------------------------------------------------------------------
# Figure 2 — RQ2: difference-in-differences vs the SRC VUL slice matcher
# ---------------------------------------------------------------------------
def fig2(r2: dict) -> None:
    did = r2["_invariance_contrast"]["per_detector_did"]
    rows = [d for d in DETECTORS if d[0] in did and d[0] != "slice_matcher_src_vul"]
    fig, ax = plt.subplots(figsize=(3.5, 2.7))
    y = np.arange(len(rows))[::-1]
    for yi, (key, name, fam) in zip(y, rows):
        col, mk = FAMILY[fam]
        d = did[key]
        est, lo, hi = d["did_vs_src_vul"], d["did_ci_low"], d["did_ci_high"]
        ax.errorbar(est, yi, xerr=[[est - lo], [hi - est]], fmt=mk, ms=5, mfc=col, mec=SURFACE,
                    mew=0.6, ecolor=col, elinewidth=1.0, capsize=0)
        ph = d.get("wilcoxon_p_holm", 1.0)
        ax.text(0.40, yi, f"p$_{{Holm}}$={ph:.2f}" if ph >= 0.01 else "p$_{Holm}$<0.01",
                va="center", ha="left", fontsize=6.5, color=INK if ph < 0.05 else INK2)
    ax.axvline(0, color=INK2, lw=0.8)
    ax.set_yticks(y, [n for _, n, _ in rows])
    ax.set_xlim(-0.15, 0.40)
    ax.set_xlabel("DiD vs. slice-signature match (95% CI)\n> 0: degrades more than the slice matcher")
    ax.xaxis.grid(True, color=GRID, lw=0.6)
    save(fig, "fig2_rq2_did")


# ---------------------------------------------------------------------------
# Figure 3 — RQ3: oracle calibration, VPR per ladder arm, outcome breakdown
# ---------------------------------------------------------------------------
def fig3(r3: dict, reasons: dict | None = None) -> None:
    cal = r3["_rq3_e1_oracle_calibration"]
    lad = r3["_rq3_e2_ladder"]["per_condition"]
    fig = plt.figure(figsize=(7.1, 2.35))
    gs = fig.add_gridspec(1, 3, width_ratios=[0.62, 1.0, 1.0])
    cx = fig.add_subplot(gs[0])
    ax = fig.add_subplot(gs[1])
    bx = fig.add_subplot(gs[2], sharey=ax)

    # (a) oracle calibration — accepted share with Wilson CI
    cm = cal["confusion_matrix"]
    pts = [("Official fixes", cm["tp"], cm["tp"] + cm["fn"]),
           ("Known-bad", cm["fp"], cm["fp"] + cm["tn"])]
    for yi, (lab, k, n) in zip([1, 0], pts):
        p, lo, hi = wilson(k, n)
        cx.barh(yi, p, height=0.5, color=INK2 if k else "#b9b8b3")
        cx.text(max(p, 0.0) + 0.04 if p < 0.6 else p - 0.04, yi, f"{k}/{n}", va="center",
                ha="left" if p < 0.6 else "right", fontsize=7, color=INK if p < 0.6 else SURFACE)
    cx.set_yticks([1, 0], [p[0] for p in pts])
    cx.set_xlim(0, 1)
    cx.set_ylim(-0.6, 1.6)
    cx.set_xticks([0, 1.0], ["0%", "100%"])
    cx.set_xlabel("Accepted by oracle")
    cx.set_title("(a) Oracle calibration", loc="left")

    # (b) VPR per arm — horizontal, rows shared with (c)
    y = np.arange(len(ARMS))[::-1]
    col = FAMILY["LLM"][0]
    for yi, (key, name) in zip(y, ARMS):
        v = lad[key]
        p, (lo, hi) = v["validated_patch_rate_vpr"], v["vpr_wilson_ci"]
        ax.errorbar(p, yi, xerr=[[p - lo], [hi - p]], fmt="o", ms=5, color=col, mfc=col,
                    mec=SURFACE, elinewidth=1.0, capsize=0)
        ax.text(hi + 0.004, yi, f"{p:.1%}", va="center", ha="left", fontsize=6.5, color=INK2)
    ax.set_yticks(y, [n.replace("\n", " ") for _, n in ARMS])
    ax.set_xlim(0, 0.15)
    ax.set_xticks([0, 0.05, 0.10, 0.15], ["0%", "5%", "10%", "15%"])
    ax.set_xlabel("VPR, 150 CVEs x 3 reps (95% CI)")
    ax.set_title("(b) Validated-patch rate", loc="left")
    ax.xaxis.grid(True, color=GRID, lw=0.6)

    # (c) outcome breakdown over CVEs x 3 repeats (results/rq3_outcomes.json)
    oc_p = RES / "rq3_outcomes.json"
    if oc_p.exists():
        oc = json.loads(oc_p.read_text())
        cats = [("validated", "Validated", "#1baf7a"),
                ("right_place_wrong_fix", "Right place, wrong fix", "#eb6834"),
                ("wrong_place", "Wrong place", "#8a8984"),
                ("unchanged", "Unchanged", "#d4d2cc")]
        for yi, (key, name) in zip(y, ARMS):
            rr = oc[key]
            n = sum(rr.values())
            left = 0.0
            for ck, cl, cc in cats:
                w = rr.get(ck, 0) / n
                bx.barh(yi, w, left=left, color=cc, height=0.62, edgecolor=SURFACE, linewidth=1.0)
                if ck == "right_place_wrong_fix":
                    bx.text(left + w / 2, yi, f"{w:.0%}", ha="center", va="center", fontsize=6.3, color=SURFACE)
                left += w
        bx.tick_params(axis="y", labelleft=False)
        bx.set_xlim(0, 1)
        bx.set_xticks([0, 0.5, 1.0], ["0%", "50%", "100%"])
        bx.set_xlabel("Share of patches")
        bx.set_title("(c) Patch outcome", loc="left")
        from matplotlib.patches import Patch
        bx.legend(handles=[Patch(color=cc, label=cl) for _, cl, cc in cats], loc="upper center",
                  bbox_to_anchor=(0.3, -0.3), ncol=2, frameon=False, fontsize=6.5,
                  handlelength=1.0, columnspacing=0.8)
    save(fig, "fig3_rq3_patching")


def main() -> None:
    style()
    r = json.loads((RES / "results.json").read_text())
    reasons_p = RES / "rq3_failure_reasons.json"
    reasons = json.loads(reasons_p.read_text()) if reasons_p.exists() else None
    # Fig. 1 (architecture) is drawn in TikZ: figures/src/fig1_architecture.tex
    if "RQ1" in r:
        fig1(r["RQ1"])
    if "RQ2" in r:
        fig2(r["RQ2"])
    if "RQ3" in r:
        fig3(r["RQ3"], reasons)


if __name__ == "__main__":
    main()
