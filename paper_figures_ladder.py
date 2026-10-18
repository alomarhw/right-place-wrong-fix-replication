"""paper_figures_ladder.py — small-multiple figures for RQ1 (grounding ladder) and RQ4 (retrieval).

One metric per panel, the ladder (or k) on the x-axis, every point labelled with its value. Reads only
measured results (no LLM calls):
  results/rq3_outcomes.json, results/rq3_postcutoff.json, results/e3_compare.json,
  results/line_evidence.json, results/rq1_vpr_ci.json, results/tables/paper/T6_rq3_localization_test.csv, results/srcvul_retrieval.json
Writes figures/paper/fig3_rq1_ladder.{pdf,png} and figures/paper/fig4_rq4_retrieval.{pdf,png}.

Palette: the validated categorical palette of paper_figures.py (blue / orange / aqua) in fixed order,
plus grey for reference lines; each series also has its own marker and line style, so identity
never rests on colour alone.
"""
from __future__ import annotations

import csv
import json
import math
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parent
RES = ROOT / "results"
OUT = ROOT / "figures" / "paper"

INK, INK2, GRID, SURFACE = "#0b0b0b", "#52514e", "#e6e5e1", "#ffffff"
BLUE, ORANGE, AQUA, GREY = "#2a78d6", "#eb6834", "#1baf7a", "#8a8984"
PURPLE, BROWN = "#7b4fa8", "#8c5a2b"  # panels (c)-(d) only, so they never reuse a shared-legend encoding
ARMS = ["no_grounding_no_feedback", "compiler_test_feedback", "cve_text_rag",
        "slice_grounded_no_feedback", "slice_grounded_full"]
LABELS = ["A0", "A1", "A2", "A3", "A4"]
SONNET_IDX = {"A0": 0, "A2": 2, "A4": 4}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float, float]:
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0.0, c - h), min(1.0, c + h)


def style() -> None:
    plt.rcParams.update({
        "font.family": "DejaVu Sans", "font.size": 7.5, "axes.titlesize": 8, "axes.titleweight": "bold",
        "axes.labelsize": 7.5, "xtick.labelsize": 7, "ytick.labelsize": 7, "legend.fontsize": 7,
        "axes.edgecolor": INK2, "axes.labelcolor": INK, "xtick.color": INK2, "ytick.color": INK2,
        "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True, "grid.color": GRID,
        "grid.linewidth": 0.6, "axes.axisbelow": True, "figure.facecolor": SURFACE, "axes.facecolor": SURFACE,
        "savefig.dpi": 300, "pdf.fonttype": 42, "figure.constrained_layout.use": True,
        "lines.linewidth": 1.6, "lines.markersize": 4.5,
    })


def save(fig, name: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for ext in ("pdf", "png"):
        fig.savefig(OUT / f"{name}.{ext}", bbox_inches="tight", pad_inches=0.02)
    plt.close(fig)
    print(f"[paper_figures_ladder] wrote {OUT / name}.{{pdf,png}}")


def label_points(ax, xs, ys, color, dy=4, fmt="{:.0f}", scale=100.0):
    for x, y in zip(xs, ys):
        ax.annotate(fmt.format(y * scale), (x, y), textcoords="offset points", xytext=(0, dy),
                    ha="center", va="bottom" if dy >= 0 else "top", fontsize=6.3, color=INK)


def fig3_ladder() -> None:
    out = json.loads((RES / "rq3_outcomes.json").read_text())
    post = json.loads((RES / "rq3_postcutoff.json").read_text())["arms"]
    son = json.loads((RES / "e3_compare.json").read_text())["per_model"]["claude-sonnet-4-6"]["rq1"]
    ev = json.loads((RES / "line_evidence.json").read_text())["rq1"]
    with open(RES / "tables" / "paper" / "T6_rq3_localization_test.csv") as fh:
        t6 = list(csv.DictReader(fh))
    chance = [float(r["Chance touch rate"]) for r in t6]
    touch = [float(r["Touch rate (3 reps)"]) for r in t6]  # same values as Table IV and the text
    n = sum(out[ARMS[0]].values())  # CVEs x repeats = 450
    x = list(range(5))
    # Information arms (e6_info_ladder.py): A2 plus the fix's location (L), the fix commit's message (M), or both
    # (LM); drawn to the right of a separator, in the same encodings. Absent until that experiment has run.
    e6p = RES / "e6_info_ladder.json"
    e6 = json.loads(e6p.read_text()) if e6p.exists() else None
    INFO, xi = ["L", "M", "LM"], [5.4, 6.4, 7.4]
    def info(set_name, key, scale=0.01):
        return [e6[set_name]["summary"][k][key] * scale for k in INFO] if e6 else []

    ci = json.loads((RES / "rq1_vpr_ci.json").read_text())["arms"]  # CVE-level bootstrap (rq1_vpr_ci.py)
    vpr = [(ci[a]["vpr"], *ci[a]["ci95"]) for a in ARMS]
    rpwf = [out[a]["right_place_wrong_fix"] / n for a in ARMS]
    wrong = [out[a]["wrong_place"] / n for a in ARMS]
    sx = [SONNET_IDX[k] for k in ("A0", "A2", "A4")]

    fig, axs = plt.subplots(1, 4, figsize=(7.0, 2.45))
    pre_v, post_v = [v[0] for v in vpr], [post[a]["vpr_post"][0] for a in ARMS]
    son_v, son_t = [son[k]["vpr"] for k in ("A0", "A2", "A4")], [son[k]["touch"] for k in ("A0", "A2", "A4")]
    post_t = [post[a]["touch_post"][0] for a in ARMS]
    # (a) validated-patch rate: pre labelled below, post above, Sonnet to the right
    ax = axs[0]
    ax.fill_between(x, [v[1] for v in vpr], [v[2] for v in vpr], color=BLUE, alpha=0.12, lw=0)
    ax.plot(x, pre_v, "-o", color=BLUE, label="Haiku 4.5, pre-cutoff")
    ax.plot(x, post_v, "--s", color=ORANGE, label="Haiku 4.5, post-cutoff")
    ax.plot(sx, son_v, "^", color=AQUA, linestyle="none", label="Sonnet 4.6, pre-cutoff (1 rep.; A0, A2, A4)")
    label_points(ax, x, pre_v, BLUE, dy=-5)
    label_points(ax, x, post_v, ORANGE)
    for xx, yy in zip(sx, son_v):
        ax.annotate(f"{yy * 100:.0f}", (xx, yy), textcoords="offset points", xytext=(-7, 1), ha="right",
                    va="center", fontsize=6.3, color=INK)
    ymax_a = 0.17
    if e6:
        lo = [e6["bigvul"]["summary"][k]["vpr_ci95"][0] / 100 for k in INFO]
        hi = [e6["bigvul"]["summary"][k]["vpr_ci95"][1] / 100 for k in INFO]
        ax.fill_between(xi, lo, hi, color=BLUE, alpha=0.12, lw=0)
        ax.plot(xi, info("bigvul", "vpr"), "-o", color=BLUE)
        ax.plot(xi, info("postcutoff", "vpr"), "--s", color=ORANGE)
        label_points(ax, xi, info("bigvul", "vpr"), BLUE, dy=-5)
        label_points(ax, xi, info("postcutoff", "vpr"), ORANGE)
        ymax_a = max(ymax_a, 1.18 * max(hi + info("postcutoff", "vpr")))
    ax.set_title("(a) Validated patches"); ax.set_ylabel("% of patches")
    ax.set_ylim(0, ymax_a)
    ax.yaxis.set_major_locator(matplotlib.ticker.MultipleLocator(0.05 if ymax_a < 0.3 else 0.1))
    # (b) touch rate, with the chance line
    ax = axs[1]
    ax.plot(x, chance, "-", color=GREY, lw=1.0, label="Chance (random edit)")
    ax.plot(x, touch, "-o", color=BLUE)
    ax.plot(x, post_t, "--s", color=ORANGE)
    ax.plot(sx, son_t, "^", color=AQUA, linestyle="none")
    label_points(ax, x, touch, BLUE, dy=-5)
    label_points(ax, x, post_t, ORANGE)
    label_points(ax, x, chance, GREY, dy=-4)
    ymax_b = 0.75
    if e6:
        ax.plot(xi, info("bigvul", "touch"), "-o", color=BLUE)
        ax.plot(xi, info("postcutoff", "touch"), "--s", color=ORANGE)
        label_points(ax, xi, info("bigvul", "touch"), BLUE, dy=-5)
        label_points(ax, xi, info("postcutoff", "touch"), ORANGE)
        ymax_b = min(1.08, max(ymax_b, 0.1 + max(info("bigvul", "touch") + info("postcutoff", "touch"))))
    ax.set_title("(b) Touch a fix line"); ax.set_ylabel("% of patches")
    ax.set_ylim(0, ymax_b)
    # (c) line-level evidence, pre-cutoff Haiku
    ax = axs[2]
    rec, f1 = [ev[a]["recall"] for a in ARMS], [ev[a]["f1"] for a in ARMS]
    ax.plot(x, f1, "-D", color=INK2, lw=1.2, label="F1")
    ax.plot(x, rec, "--v", color=PURPLE, label="Recall")
    label_points(ax, x, f1, INK2)
    label_points(ax, x, rec, PURPLE, dy=-5)
    ymax_c = 0.33
    if e6:
        ax.plot(xi, info("bigvul", "line_f1", 1.0), "-D", color=INK2, lw=1.2)
        ax.plot(xi, info("bigvul", "line_recall", 1.0), "--v", color=PURPLE)
        label_points(ax, xi, info("bigvul", "line_f1", 1.0), INK2)
        label_points(ax, xi, info("bigvul", "line_recall", 1.0), PURPLE, dy=-5)
        ymax_c = min(1.05, max(ymax_c, 0.08 + max(info("bigvul", "line_f1", 1.0) + info("bigvul", "line_recall", 1.0))))
    ax.set_title("(c) Fix lines found"); ax.set_ylabel("% (recall, F1)")
    ax.set_ylim(0.08, ymax_c)
    ax.legend(loc="upper left", frameon=False, handlelength=1.4, borderaxespad=0.1)
    # (d) outcome shares, pre-cutoff Haiku
    ax = axs[3]
    ax.plot(x, wrong, "-p", color=GREY, label="Wrong place")
    ax.plot(x, rpwf, "-.X", color=BROWN, label="Right place,\nwrong fix")
    label_points(ax, x, wrong, GREY)
    label_points(ax, x, rpwf, BROWN, dy=-5)
    if e6:
        w_i = [e6["bigvul"]["summary"][k]["outcomes"]["wrong_place"] / 100 for k in INFO]
        r_i = [e6["bigvul"]["summary"][k]["outcomes"]["right_place_wrong_fix"] / 100 for k in INFO]
        ax.plot(xi, w_i, "-p", color=GREY)
        ax.plot(xi, r_i, "-.X", color=BROWN)
        label_points(ax, xi, w_i, GREY)
        label_points(ax, xi, r_i, BROWN, dy=-5)
    ax.set_title("(d) Rejected patches"); ax.set_ylabel("% of patches")
    ax.set_ylim(0.0, 0.72)
    ax.legend(loc="lower right", frameon=False, handlelength=1.4, borderaxespad=0.1)

    for ax in axs:
        if e6:
            ax.set_xticks(x + xi, LABELS + INFO)
            ax.set_xlim(-0.4, 7.8)
            ax.axvline(4.9, color=GRID, lw=0.8)
        else:
            ax.set_xticks(x, LABELS)
            ax.set_xlim(-0.4, 4.4)
        ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v * 100:.0f}"))
    h, lab = axs[0].get_legend_handles_labels()
    h2, lab2 = axs[1].get_legend_handles_labels()
    fig.legend(h + h2, lab + lab2, loc="outside lower center", ncol=4, frameon=False, handlelength=2.0,
               columnspacing=1.0)
    save(fig, "fig3_rq1_ladder")


def fig4_retrieval() -> None:
    r = json.loads((RES / "srcvul_retrieval.json").read_text())
    ranks = [t["rank"] for t in r["per_target"]]
    above = [t["entries_above_0.8"] for t in r["per_target"]]
    ks = list(range(1, 11))
    hit = [sum(rk <= k for rk in ranks) / len(ranks) for k in ks]

    fig, axs = plt.subplots(1, 2, figsize=(3.5, 1.6), gridspec_kw={"width_ratios": [1.15, 1]})
    ax = axs[0]
    ax.plot(ks, hit, "-o", color=BLUE)
    label_points(ax, ks, hit, BLUE)
    ax.set_title("(a) Right fix in top-$k$"); ax.set_ylabel("% of hard targets")
    ax.set_xlabel("$k$ (of %d fixes)" % r["db_entries"])
    ax.set_xticks(ks)
    ax.set_ylim(0.3, 0.9)
    ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v * 100:.0f}"))
    ax = axs[1]
    ax.hist(above, bins=range(164, r["db_entries"] + 2, 2), color=ORANGE, edgecolor=SURFACE, lw=0.6)
    ax.axvline(r["db_entries"], color=GREY, lw=1.0, ls="--")
    ax.set_title("(b) Fixes with cosine $\\geq$ 0.8")
    ax.set_xlabel("fixes over threshold (of %d)" % r["db_entries"])
    ax.set_ylabel("number of hard targets")
    save(fig, "fig4_rq4_retrieval")


if __name__ == "__main__":
    style()
    fig3_ladder()
    fig4_retrieval()
