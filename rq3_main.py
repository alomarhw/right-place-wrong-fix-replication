"""rq3_main.py — RQ3 orchestrator.

Runs the RQ3 controlled experiment end-to-end:
  1. Resolve/parse the CVE vulnerable/fixed patch corpus (rq3_data) — real data
     from data/ (Big-Vul/CVEfixes or VulSlicer+VUDDY foundation corpus) when
     present; strict-mode failure otherwise unless synthetic smoke is approved.
     GLUE is explicitly NOT used (it is text classification, not CVE patch data).
  2. RQ3-E1: construct the INDEPENDENT exploit/official-fix oracle and calibrate it
     (and the vsvector-severance intermediate signal) against official + known-bad
     patches (oracle.calibrate_oracles via rq3_analysis).
  3. RQ3-E2: run the slice-grounded detect-verify-patch agent + the competitive
     ablation ladder under identical model/retry budget/oracle (patch_agent).
  4. Compute all RQ3 statistics, apply the oracle-fidelity precondition + decision
     rule, and write results/results.json keyed by RQ3 (rq3_analysis).
  5. Generate RQ3 figures + the method worked-slice example (rq3_plots).

Imported and invoked by the top-level main.py. Running directly executes the full
RQ3 path with default (strict) settings.

Key deps (pinned): pandas==2.2.2, numpy==2.2.6, scikit-learn==1.5.1,
scipy==1.13.1, statsmodels==0.14.6, matplotlib==3.9.1.
"""
from __future__ import annotations

import json
import os
import random
import traceback
from pathlib import Path
from typing import Any

import numpy as np

RANDOM_SEED = int(os.environ.get("RP_RANDOM_SEED", 42))

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
FIGURES = ROOT / "figures"
TABLES = RESULTS / "tables"


def _ensure_dirs() -> None:
    for d in (RESULTS, FIGURES, TABLES):
        d.mkdir(parents=True, exist_ok=True)


def _resolve_mode(mode_info: dict[str, Any] | None) -> dict[str, Any]:
    if mode_info is not None:
        return mode_info
    try:
        from rp_run_modes import resolve_scale
        import sys
        requested = "smoke" if "--smoke" in sys.argv else (
            "full" if ("--full" in sys.argv or
                       os.environ.get("STRICT_REAL_DATA_MODE", "1") not in ("0", "false", "False"))
            else "smoke")
        scale = resolve_scale(requested)
        return {
            "mode": scale["mode"],
            "rows_or_items": scale["n_cves"],
            "repeats": scale["repeats"],
            "paper_grade": scale["paper_grade"],
            "strict_real_data": scale["mode"] != "smoke",
            "allow_synthetic": scale["allow_synthetic"],
        }
    except Exception:
        strict = os.environ.get("STRICT_REAL_DATA_MODE", "1") not in ("0", "false", "False")
        return {
            "mode": "paper_grade" if strict else "smoke",
            "rows_or_items": 300 if strict else 30,
            "repeats": 3 if strict else 1,
            "paper_grade": bool(strict),
            "strict_real_data": strict,
            "allow_synthetic": not strict,
        }


def run_rq3(mode_info: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute the full RQ3 pipeline. Returns the RQ3 result block."""
    random.seed(RANDOM_SEED)
    np.random.seed(RANDOM_SEED)
    _ensure_dirs()

    mode_info = _resolve_mode(mode_info)
    mode = mode_info.get("mode", "smoke")
    n_rows = int(mode_info.get("rows_or_items", mode_info.get("n_cves", 30)))
    repeats = int(mode_info.get("repeats", 1))
    paper_grade = bool(mode_info.get("paper_grade", False))
    strict = bool(mode_info.get("strict_real_data", True))
    allow_synthetic = bool(mode_info.get("allow_synthetic", not strict))

    print("=" * 72)
    print("RQ3 : slice-grounded detect-verify-patch agent + independent-oracle calibration")
    print(f"  mode={mode}  rows/items={n_rows}  repeats={repeats}  "
          f"paper_grade={paper_grade}  strict_real_data={strict}  "
          f"allow_synthetic={allow_synthetic}")
    print("  NOTE: RQ3 ground truth = CVE vulnerable/fixed patch pairs (NOT GLUE).")
    print("=" * 72)

    # -- run analysis (loads corpus, RQ3-E1 + RQ3-E2, writes results.json) --
    from rq3_analysis import run_analysis

    all_results = run_analysis(n_cves=n_rows, allow_synthetic=allow_synthetic,
                               repeats=repeats, seed=RANDOM_SEED)
    rq3_block = all_results.get("RQ3", {})

    source_tag = rq3_block.get("_data_source", "unknown")
    _write_provenance(source_tag, n_rows)
    _write_run_metadata(mode, n_rows, repeats, paper_grade, source_tag)

    # -- figures --
    print("[rq3_main] generating RQ3 figures ...")
    try:
        from rq3_plots import main as make_figs
        make_figs()
    except Exception as exc:  # figures must not nuke computed numbers
        print(f"[rq3_main] WARNING: figure generation failed: {exc}")
        traceback.print_exc()

    verdict = rq3_block.get("_decision", {}).get("verdict", "unknown")
    print(f"[rq3_main] RQ3 complete. verdict={verdict}")
    if source_tag == "synthetic":
        print("[rq3_main] *** SMOKE RUN on synthetic CVE pairs — NOT paper-grade evidence. ***")
    return rq3_block


def _write_provenance(source_tag: str, n_rows: int) -> None:
    out = RESULTS / "data_provenance.json"
    used_synthetic = source_tag == "synthetic"
    dataset_name = ("CVE vulnerable/fixed patch pairs (Big-Vul/CVEfixes or "
                    "VulSlicer+VUDDY foundation)") if not used_synthetic else \
        "Synthetic CVE patch pairs (smoke only)"
    rec = {
        "name": dataset_name,
        "source": "synthetic" if used_synthetic else "real",
        "path": "data/",
        "rows": int(n_rows),
        "version": "",
        "license": "research use",
        "citation": "salimi2022vulslicer; Big-Vul; CVEfixes; "
                    "SRC VUL foundation (\\cite{57b456a85303a715d9311a88cd3de662b631778c})",
        "checksum": "",
        "recordCount": int(n_rows),
        "schema": ["cve_id", "cwe", "vulnerable_code", "official_fixed_code", "poc_available"],
    }
    merged: dict[str, Any] = {}
    mined = ROOT / "data" / "data_provenance.json"
    if mined.exists():
        try:
            prev = json.loads(mined.read_text())
            if prev.get("usedMinedData"):
                merged["usedMinedData"] = True
        except Exception:
            pass
    # merge manifest lineage if available
    try:
        from rp_run_modes import merge_manifest_lineage
        datasets = merge_manifest_lineage([rec], data_root="data")
    except Exception:
        datasets = [rec]
    merged["usedSynthetic"] = bool(used_synthetic)
    merged["datasets"] = datasets
    out.write_text(json.dumps(merged, indent=2, default=_json_default))
    print(f"[rq3_main] wrote {out} (usedSynthetic={used_synthetic})")


def _write_run_metadata(mode: str, n_rows: int, repeats: int,
                        paper_grade: bool, source_tag: str) -> None:
    meta = {
        "mode": mode,
        "run_tier": mode,
        "rows_or_items": int(n_rows),
        "repeats": int(repeats),
        "datasets": ["CVE vulnerable/fixed patch pairs (NOT GLUE)"],
        "data_source": source_tag,
        "paper_grade": bool(paper_grade and source_tag == "real"
                            and n_rows >= 300 and repeats >= 3),
        "random_seed": RANDOM_SEED,
        "strict_real_data_mode": mode != "smoke",
        "experiment_id": "RQ3-E1+RQ3-E2",
        "rq": "RQ3",
    }
    out = RESULTS / "run_metadata.json"
    out.write_text(json.dumps(meta, indent=2))
    tier = "PAPER-GRADE run mode" if meta["paper_grade"] else f"{mode.upper()} run mode"
    print(f"[rq3_main] {tier}: rows={n_rows}, repeats={repeats}, "
          f"data_source={source_tag}, paper_grade={meta['paper_grade']}")
    print(f"[rq3_main] wrote {out}")


def _json_default(o: Any) -> Any:
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    return str(o)


if __name__ == "__main__":
    run_rq3()