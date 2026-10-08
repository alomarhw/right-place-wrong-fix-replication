"""rq2_main.py — RQ2-ALT1 orchestrator.

Runs the RQ2 controlled experiment end-to-end:
  1. Resolve/parse the VulSlicer+VUDDY corpus (data_prep) — real data from data/
     when present; strict-mode failure otherwise unless synthetic smoke is approved.
  2. Build certified slice-preserving variants + measure construction validity
     (rq2_invariance / variant_builder).
  3. Evaluate every contracted detector verbatim-vs-variant and compute the
     invariance contrast (difference-in-differences).
  4. Compute all RQ2 statistics and write results/results.json keyed by RQ2
     (rq2_analysis).
  5. Generate RQ2 figures + the method worked-slice example (rq2_plots).

This module is imported and invoked by the top-level main.py; it does not define
its own CLI. Running it directly executes the full RQ2 path with default settings.

Key deps (pinned): pandas==2.2.2, numpy==2.2.6, scikit-learn==1.5.1,
scipy==1.13.1, statsmodels==0.14.6, datasketch==1.6.5, matplotlib==3.9.1.
"""
from __future__ import annotations

import os
import json
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


def run_rq2(mode_info: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute the full RQ2-ALT1 pipeline.

    Parameters
    ----------
    mode_info : dict or None
        Run-mode descriptor produced by rp_run_modes.resolve_mode(). If None, a
        default is resolved here so rq2_main stays runnable standalone.

    Returns
    -------
    dict
        The RQ2 result block that was written into results/results.json.
    """
    import random

    random.seed(RANDOM_SEED)
    np.random.seed(RANDOM_SEED)
    _ensure_dirs()

    # Resolve run mode (smoke vs paper-grade) ------------------------------
    if mode_info is None:
        try:
            from rp_run_modes import resolve_mode

            mode_info = resolve_mode()
        except Exception:
            # Minimal self-contained default so the module is runnable alone.
            strict = os.environ.get("STRICT_REAL_DATA_MODE", "1") not in ("0", "false", "False")
            mode_info = {
                "mode": "paper_grade" if strict else "smoke",
                "rows_or_items": 300 if strict else 30,
                "repeats": 3 if strict else 1,
                "paper_grade": bool(strict),
                "strict_real_data": strict,
            }

    mode = mode_info.get("mode", "smoke")
    n_rows = int(mode_info.get("rows_or_items", 30))
    repeats = int(mode_info.get("repeats", 1))
    paper_grade = bool(mode_info.get("paper_grade", False))
    strict = bool(mode_info.get("strict_real_data", True))

    print("=" * 72)
    print("RQ2-ALT1 : slice-preserving benchmark construction + invariance contrast")
    print(f"  mode={mode}  rows/items={n_rows}  repeats={repeats}  "
          f"paper_grade={paper_grade}  strict_real_data={strict}")
    print("=" * 72)

    # 1. Load corpus -------------------------------------------------------
    print("[1/5] Resolving + parsing CVE clone corpus (VulSlicer+VUDDY) ...")
    from data_prep import load_corpus

    corpus, provenance = load_corpus(
        n_items=n_rows,
        strict_real_data=strict,
        seed=RANDOM_SEED,
    )
    print(f"      loaded {len(corpus)} CVE clone records "
          f"(source={provenance.get('primary_source', 'unknown')})")
    _write_provenance(provenance)

    # 2. Construct certified variants + construction validity ---------------
    print("[2/5] Building certified slice-preserving variants (RQ2-E1) ...")
    from rq2_invariance import build_construction_validity

    construction = build_construction_validity(
        corpus, repeats=repeats, seed=RANDOM_SEED
    )
    print(f"      accepted-variant yield = "
          f"{construction['accepted_variant_yield_rq2']:.3f} "
          f"(Wilson95 = [{construction['yield_ci'][0]:.3f}, "
          f"{construction['yield_ci'][1]:.3f}])")
    print(f"      vsvector invariance pass rate = "
          f"{construction['vsvector_invariance_pass_rate_rq2']:.3f}")
    print(f"      self-similarity negative control = "
          f"{construction['self_similarity_control']:.3f} (expect ~1.0)")

    # 3. Invariance contrast across detectors (RQ2-E2) ---------------------
    print("[3/5] Evaluating detectors verbatim-vs-variant + DiD (RQ2-E2) ...")
    from rq2_invariance import run_invariance_contrast

    contrast = run_invariance_contrast(
        corpus, construction, repeats=repeats, seed=RANDOM_SEED
    )
    print(f"      SRC VUL slice matcher Δ_acc = "
          f"{contrast['reference_delta_acc']:.3f}")
    print(f"      mean recall-sensitive detector Δ_acc = "
          f"{contrast['mean_recall_detector_delta_acc']:.3f}")

    # 4. Statistics + results.json ----------------------------------------
    print("[4/5] Computing RQ2 statistics and writing results.json ...")
    from rq2_analysis import compute_and_write

    rq2_block = compute_and_write(
        construction=construction,
        contrast=contrast,
        provenance=provenance,
        mode_info=mode_info,
    )
    print(f"      DiD (RQ2) = {rq2_block['metrics']['difference_in_differences_did_rq2']:.4f}")
    print(f"      wrote {RESULTS / 'results.json'}")

    # 5. Figures -----------------------------------------------------------
    print("[5/5] Generating RQ2 figures ...")
    try:
        from rq2_plots import make_all_figures

        figs = make_all_figures()
        for f in figs:
            print(f"      figure: {f}")
    except Exception as exc:  # figures must not nuke computed numbers
        print(f"      WARNING: figure generation failed: {exc}")
        traceback.print_exc()

    print("RQ2-ALT1 complete.")
    return rq2_block


def _write_provenance(provenance: dict[str, Any]) -> None:
    """Write/merge results/data_provenance.json preserving auto-mined flags."""
    out = RESULTS / "data_provenance.json"
    merged: dict[str, Any] = {}
    # Preserve an upstream auto-mined flag from data/ if present.
    mined = ROOT / "data" / "data_provenance.json"
    if mined.exists():
        try:
            prior = json.loads(mined.read_text())
            if prior.get("usedMinedData"):
                merged["usedMinedData"] = True
        except Exception:
            pass
    merged["usedSynthetic"] = bool(provenance.get("usedSynthetic", False))
    merged["datasets"] = provenance.get("datasets", [])
    out.write_text(json.dumps(merged, indent=2, default=_json_default))


def _json_default(o: Any) -> Any:
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    return str(o)


if __name__ == "__main__":
    run_rq2()