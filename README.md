# Replication package: *Right Place, Wrong Fix*

This package contains the data, code, frozen model responses and results behind every number in the paper *Right Place, Wrong Fix: A Contamination-Controlled Study of Grounding in LLM Vulnerability-Repair Agents*.

**Everything replays offline.** All 12,000+ LLM responses are frozen in `data/_llm_cache.sqlite`, so the scripts below regenerate the paper's numbers **without an API key and without API cost**. An API key (`ANTHROPIC_API_KEY`) is needed only to run new configurations; a cache miss without a key fails loudly instead of falling back to a proxy.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Python 3.11–3.12. The GPU experiments have their own environment (see `gpu/README.md`).

## Where each result comes from

Script names follow the pipeline's internal numbering, which differs from the paper's research questions. This table maps them.

| Paper | What | Script(s) | Output |
|---|---|---|---|
| Table I, §III-A | Big-Vul sample and post-cutoff mining | `mining/build_bigvul.py`, `mining/mine_postcutoff.py`, `mining/enrich_validate.py` | `data/bigvul/`, `data/postcutoff/`, `data/VALIDATION.json` |
| §III-B | Certified slice-preserving variants | `variant_builder.py` (called by `main.py`) | `results/results.json` |
| §III-E, Eq. (1)–(2) | Oracle and its calibration | `oracle.py` (called by `rq3_main.py`) | `results/results.json` (`RQ3`) |
| **RQ1** Fig. 2, Table III | Grounding ladder, VPR, localization (paper RQ1 = internal "RQ3") | `rq3_main.py`, then `paper_tables.py` | `results/results.json`, `results/rq3_outcomes.json`, `paper_tables/` |
| RQ1 | Line-level evidence P/R/F1 | `line_evidence.py` | `results/line_evidence.json` |
| RQ1 | Oracle-strictness check (two LLM raters) | `e4_sample.py [arm]`, `e4_judge.py` | `results/e4_*.json`, `results/e4_sample*.md` |
| RQ1 | Second closed model (Claude Sonnet 4.6, exploratory) | `RP_LLM_MODEL=claude-sonnet-4-6 python3 e3_cross_model.py`, `e3_compare.py` | `results/e3_*.json` |
| **RQ2** Table IV, Fig. 3 | Detection, pairwise analysis (paper RQ2 = internal "RQ1") | `main.py`, `paper_tables.py` | `results/results.json` |
| RQ2 Table V | Reasoning and contrastive probes | `e1_absolute_reason.py`, `e1_contrastive.py [--reason]` | `results/e1_*.json` |
| RQ2 Table V | Open-weight replication (Qwen2.5-Coder) | `gpu/open_detect.py` | `results/open_detect_*.json` |
| **RQ3** Fig. 4 | Variant invariance and DiD (internal "RQ1"/"RQ2") | `main.py` (or `rq2_main.py`) | `results/results.json` |
| RQ3 Table VI | Repair on post-cutoff CVEs | `rq3_postcutoff.py` | `results/rq3_postcutoff.json` |
| RQ3 | Min-K%++ memorization probe and positive control | `gpu/minkprobe.py`, `gpu/minkprobe_lines.py`, `gpu/positive_control.py`, `gpu/analyze_minkprobe.py` | `results/minkprobe_*`, `results/positive_control_*.json` |
| **RQ4** Table VII | Porting vs. inventing on 88 hard clones | `mining/mine_backports.py`, `porting_pilot.py` | `data/porting/`, `results/porting_pilot.json` |
| RQ4 | srcVul grounding (P3) and retrieval | `srcvul_ground.py`, `srcvul_retrieval.py` | `results/srcvul_retrieval.json` |
| RQ4 | Porting from slices (P4) | `e2_slice_reduction.py` | `results/e2_slice_reduction.json` |
| RQ4 | CVE-level tests (exact Wilcoxon, Holm over the four RQ4 comparisons) | `rq4_tests.py` | `results/rq4_tests.json` |
| Figures | Figs. 2–4 | `paper_figures.py` | `figures/paper/` |
| Fig. 1 | Architecture (TikZ) | `pdflatex figures/src/fig1_architecture.tex` | `figures/paper/fig0_overview.pdf` |

`paper_tables.py` and `paper_figures.py` make no LLM calls beyond cache replays.

## Quick check

```bash
python3 e3_cross_model.py      # Haiku repeat-1 RQ1/RQ4 arms from the cache (~10 s, 0 API calls)
python3 e3_compare.py          # Haiku vs Sonnet paired comparison
python3 paper_tables.py        # paper tables, replaying the full ladder from the cache
```

## Statistics

All paired arm comparisons use the exact Wilcoxon signed-rank test when at most 50 differences are non-zero
(`rp_stats.wilcoxon_paired`), and Holm correction within each family. An earlier version let SciPy fall back to a
normal approximation for a few comparisons with only 2-5 non-zero CVEs; the exact values are reported in the paper.

## Reproducibility note

`patch_agent._cve_text` used to fill its CVE-description table lazily without a lock, so under the thread pool two
of the 168 post-cutoff CVE-text first attempts were sent without their description. The table is now built under a
lock; those calls were regenerated with the description and no result changed. Replays are deterministic.

## Models

- Closed models via the Anthropic API: `claude-haiku-4-5` (all experiments), `claude-sonnet-4-6` (one exploratory repair repeat), `claude-opus-4-8` (blind second rater in the oracle-strictness check). Detection runs at temperature 0, repair at 0.7 with the repeat seed in the cache key.
- Open-weight models (GPU): Qwen2.5-Coder-7B (base) and 7B/14B-Instruct, on one 48 GB NVIDIA RTX 6000 Ada.

## Data notes

- Big-Vul pairs come from the public `bstee615/bigvul` dataset. Post-cutoff pairs and the backport clone families were mined from public fix commits of OpenSSL, php-src, FFmpeg, curl and libexpat; re-mining needs local clones (`RP_MINING_ROOT`).
- `data/VALIDATION.json` lists every dropped candidate and why.
- Three inspected Big-Vul pairs carry an official fix unrelated to their CVE (see `results/e4_labels_*.json`).

## Licence

Code: MIT. Data derived from Big-Vul and from public project repositories keeps the licences of its sources.
