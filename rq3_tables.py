"""
rq3_tables.py

Materialize the RQ3 result tables required by the Engineer run contract:

  - TAB5 : RQ3-E1 oracle calibration + severance-vs-independent-oracle agreement
           (official-patch accept rate, known-bad false-accept rate, Wilson CIs,
            severance MCC / Cohen's kappa).
  - TAB6 : RQ3-E2 competitive ablation ladder validated-patch rate (VPR) per
           condition/baseline, iterations-to-accept, with Wilson CIs.

These CSVs are written to results/tables/ from the canonical results/results.json
(keyed by RQ3) plus, when available, the richer intermediate artifacts written by
rq3_analysis.py. This module is a pure CONSUMER of saved results — it never
recomputes science — so it is safe to call at the end of the RQ3 pipeline or
standalone after a run.

Usage:
    python3 rq3_tables.py                 # read results/, write results/tables/TAB5.csv, TAB6.csv
    from rq3_tables import write_rq3_tables
    write_rq3_tables()

Key dependencies (pinned in requirements.txt):
    pandas==2.2.2, numpy==2.2.6, scipy==1.13.1, statsmodels==0.14.6
"""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

RANDOM_SEED = int(os.environ.get("RP_RANDOM_SEED", 42))

ROOT = Path(__file__).resolve().parent
RESULTS_DIR = ROOT / "results"
TABLES_DIR = RESULTS_DIR / "tables"


# --------------------------------------------------------------------------- #
# Small statistics helper (self-contained so this file has no hard dep on      #
# rq3_analysis internals; uses statsmodels when present, else a safe fallback) #
# --------------------------------------------------------------------------- #
def wilson_ci(successes: float, n: float, alpha: float = 0.05) -> List[float]:
    """Return a finite Wilson score interval [low, high] for a proportion."""
    try:
        from statsmodels.stats.proportion import proportion_confint

        if n is None or n <= 0:
            return [0.0, 0.0]
        k = int(round(max(0.0, min(float(successes), float(n)))))
        lo, hi = proportion_confint(k, int(round(n)), alpha=alpha, method="wilson")
        lo = 0.0 if (lo is None or math.isnan(lo)) else float(lo)
        hi = 0.0 if (hi is None or math.isnan(hi)) else float(hi)
        return [round(lo, 4), round(hi, 4)]
    except Exception:
        # Manual Wilson fallback (z for 95%).
        if n is None or n <= 0:
            return [0.0, 0.0]
        z = 1.959963984540054
        p = max(0.0, min(1.0, float(successes) / float(n)))
        denom = 1.0 + z * z / n
        centre = (p + z * z / (2 * n)) / denom
        half = (z * math.sqrt((p * (1 - p) + z * z / (4 * n)) / n)) / denom
        return [round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)]


def _finite(x: Any, default: float = 0.0) -> float:
    try:
        v = float(x)
        if math.isnan(v) or math.isinf(v):
            return default
        return v
    except Exception:
        return default


def _load_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        if path.exists():
            with path.open("r", encoding="utf-8") as fh:
                return json.load(fh)
    except Exception as exc:  # pragma: no cover - defensive
        print(f"[rq3_tables] WARNING: could not read {path}: {exc}")
    return None


# --------------------------------------------------------------------------- #
# TAB5 — RQ3-E1 oracle calibration + severance agreement                       #
# --------------------------------------------------------------------------- #
def _build_tab5(results: Dict[str, Any], e1: Optional[Dict[str, Any]]) -> pd.DataFrame:
    """
    One row per labelled patch-set measurement for the INDEPENDENT oracle, plus
    severance-vs-independent-oracle agreement summary rows.
    """
    rows: List[Dict[str, Any]] = []

    # Prefer the detailed RQ3-E1 artifact (written by rq3_analysis / oracle.py);
    # fall back to the canonical metrics in results.json.
    rq3 = results.get("RQ3", {}) if results else {}
    metrics = rq3.get("metrics", {}) if isinstance(rq3, dict) else {}

    e1 = e1 or {}

    # --- Independent-oracle confusion on labelled patch classes --------------
    # Expected shape from rq3_analysis (defensive if absent):
    #   e1["oracle"]["classes"] = {
    #       "official_fix": {"should": "accept", "n": int, "accepted": int},
    #       "whole_slice_deletion": {"should": "reject", "n": int, "accepted": int},
    #       "no_op": {...}, "semantics_breaking": {...} }
    oracle = e1.get("oracle", {}) if isinstance(e1, dict) else {}
    classes = oracle.get("classes", {}) if isinstance(oracle, dict) else {}

    if classes:
        for cls_name, info in classes.items():
            n = _finite(info.get("n"), 0.0)
            accepted = _finite(info.get("accepted"), 0.0)
            should = str(info.get("should", ""))
            accept_rate = (accepted / n) if n > 0 else 0.0
            ci = wilson_ci(accepted, n)
            rows.append(
                {
                    "table": "TAB5",
                    "section": "independent_oracle_confusion",
                    "patch_class": cls_name,
                    "expected_decision": should,
                    "n": int(round(n)),
                    "accepted": int(round(accepted)),
                    "accept_rate": round(accept_rate, 4),
                    "accept_rate_ci_low": ci[0],
                    "accept_rate_ci_high": ci[1],
                    "metric": "accept_rate",
                }
            )
    else:
        # Fall back to the two headline oracle rates in results.json so TAB5 is
        # never empty, even in a minimal smoke run.
        opa = _finite(metrics.get("official_patch_accept_rate_rq3"))
        far = _finite(metrics.get("oracle_false_accept_rate_rq3"))
        n_official = _finite(oracle.get("n_official"), e1.get("n_official", 0.0) if isinstance(e1, dict) else 0.0)
        n_badpool = _finite(oracle.get("n_known_bad"), e1.get("n_known_bad", 0.0) if isinstance(e1, dict) else 0.0)
        rows.append(
            {
                "table": "TAB5",
                "section": "independent_oracle_confusion",
                "patch_class": "official_fix",
                "expected_decision": "accept",
                "n": int(round(n_official)),
                "accepted": int(round(opa * n_official)) if n_official > 0 else 0,
                "accept_rate": round(opa, 4),
                "accept_rate_ci_low": wilson_ci(opa * n_official, n_official)[0] if n_official > 0 else 0.0,
                "accept_rate_ci_high": wilson_ci(opa * n_official, n_official)[1] if n_official > 0 else 0.0,
                "metric": "official_patch_accept_rate_rq3",
            }
        )
        rows.append(
            {
                "table": "TAB5",
                "section": "independent_oracle_confusion",
                "patch_class": "known_bad_pool",
                "expected_decision": "reject",
                "n": int(round(n_badpool)),
                "accepted": int(round(far * n_badpool)) if n_badpool > 0 else 0,
                "accept_rate": round(far, 4),
                "accept_rate_ci_low": wilson_ci(far * n_badpool, n_badpool)[0] if n_badpool > 0 else 0.0,
                "accept_rate_ci_high": wilson_ci(far * n_badpool, n_badpool)[1] if n_badpool > 0 else 0.0,
                "metric": "oracle_false_accept_rate_rq3",
            }
        )

    # --- Oracle precondition flag -------------------------------------------
    opa = _finite(metrics.get("official_patch_accept_rate_rq3"))
    far = _finite(metrics.get("oracle_false_accept_rate_rq3"))
    precondition_ok = bool(opa >= 0.90 and far <= 0.10)
    rows.append(
        {
            "table": "TAB5",
            "section": "oracle_precondition",
            "patch_class": "ALL",
            "expected_decision": "official>=0.90 & false_accept<=0.10",
            "n": "",
            "accepted": "",
            "accept_rate": "",
            "accept_rate_ci_low": "",
            "accept_rate_ci_high": "",
            "metric": "precondition_ok",
            "value": int(precondition_ok),
            "note": "If 0, RQ3-E2 VPR results are flagged INVALID (oracle not calibrated).",
        }
    )

    # --- Severance vs independent-oracle agreement ---------------------------
    sev = e1.get("severance_agreement", {}) if isinstance(e1, dict) else {}
    mcc = _finite(sev.get("mcc"), float("nan"))
    kappa = _finite(sev.get("cohen_kappa"), float("nan"))
    sev_far = _finite(sev.get("severance_false_accept_rate"), float("nan"))
    rows.append(
        {
            "table": "TAB5",
            "section": "severance_vs_independent_oracle",
            "patch_class": "ALL",
            "expected_decision": "intermediate_signal_only",
            "n": int(round(_finite(sev.get("n"), 0.0))),
            "accepted": "",
            "accept_rate": "",
            "accept_rate_ci_low": "",
            "accept_rate_ci_high": "",
            "metric": "matthews_corrcoef",
            "value": round(mcc, 4) if not math.isnan(mcc) else "",
        }
    )
    rows.append(
        {
            "table": "TAB5",
            "section": "severance_vs_independent_oracle",
            "patch_class": "ALL",
            "expected_decision": "intermediate_signal_only",
            "n": int(round(_finite(sev.get("n"), 0.0))),
            "accepted": "",
            "accept_rate": "",
            "accept_rate_ci_low": "",
            "accept_rate_ci_high": "",
            "metric": "cohen_kappa",
            "value": round(kappa, 4) if not math.isnan(kappa) else "",
        }
    )
    rows.append(
        {
            "table": "TAB5",
            "section": "severance_vs_independent_oracle",
            "patch_class": "whole_slice_deletion",
            "expected_decision": "severance_accepts_oracle_rejects (positive control)",
            "n": int(round(_finite(sev.get("n"), 0.0))),
            "accepted": "",
            "accept_rate": round(sev_far, 4) if not math.isnan(sev_far) else "",
            "accept_rate_ci_low": "",
            "accept_rate_ci_high": "",
            "metric": "severance_false_accept_rate",
            "value": round(sev_far, 4) if not math.isnan(sev_far) else "",
        }
    )

    return pd.DataFrame(rows)


# --------------------------------------------------------------------------- #
# TAB6 — RQ3-E2 ladder VPR per condition / baseline                            #
# --------------------------------------------------------------------------- #
def _build_tab6(results: Dict[str, Any], e2: Optional[Dict[str, Any]]) -> pd.DataFrame:
    """
    One row per ladder condition / baseline with VPR (Wilson CI) and
    iterations-to-accept, plus McNemar annotations for the key contrasts.
    """
    rows: List[Dict[str, Any]] = []
    rq3 = results.get("RQ3", {}) if results else {}
    metrics = rq3.get("metrics", {}) if isinstance(rq3, dict) else {}
    baseline_cmp = rq3.get("baseline_comparison", {}) if isinstance(rq3, dict) else {}
    e2 = e2 or {}

    # Per-condition detail if rq3_analysis recorded it; else reconstruct from
    # baseline_comparison + the grounded-agent headline metrics.
    conditions = e2.get("conditions", {}) if isinstance(e2, dict) else {}

    def _row_for(name: str, vpr: float, n: float, iters: float, kind: str) -> Dict[str, Any]:
        ci = wilson_ci(vpr * n, n) if n > 0 else [0.0, 0.0]
        return {
            "table": "TAB6",
            "condition": name,
            "kind": kind,
            "n": int(round(n)),
            "validated_patch_rate_vpr": round(_finite(vpr), 4),
            "vpr_ci_low": ci[0],
            "vpr_ci_high": ci[1],
            "iterations_to_accept": round(_finite(iters), 4),
        }

    if conditions:
        for cond_name, info in conditions.items():
            vpr = _finite(info.get("vpr") or info.get("validated_patch_rate_vpr_rq3"))
            n = _finite(info.get("n"), 0.0)
            iters = _finite(info.get("iterations_to_accept") or info.get("iterations_to_accept_rq3"))
            kind = str(info.get("kind", "ladder_condition"))
            rows.append(_row_for(cond_name, vpr, n, iters, kind))
    else:
        # Grounded agent (proposed) — headline RQ3 metrics.
        n_items = _finite(e2.get("n_items"), 0.0)
        rows.append(
            _row_for(
                "SliceGuard slice-grounded agent (proposed, full feedback)",
                _finite(metrics.get("validated_patch_rate_vpr_rq3")),
                n_items,
                _finite(metrics.get("iterations_to_accept_rq3")),
                "proposed",
            )
        )
        # Every contracted baseline.
        for bname, bmetrics in baseline_cmp.items():
            if not isinstance(bmetrics, dict):
                continue
            rows.append(
                _row_for(
                    bname,
                    _finite(bmetrics.get("validated_patch_rate_vpr_rq3")),
                    n_items,
                    _finite(bmetrics.get("iterations_to_accept_rq3")),
                    "baseline",
                )
            )

    # McNemar / statistical annotations for the headline contrasts.
    stats = rq3.get("statistical_tests", {}) if isinstance(rq3, dict) else {}
    contrasts = e2.get("contrasts", {}) if isinstance(e2, dict) else {}
    if not contrasts and stats:
        contrasts = {
            "grounded_full_vs_best_ungrounded": {
                "test_used": stats.get("test_used", ""),
                "p_value": _finite(stats.get("p_value"), float("nan")),
                "effect_size": _finite(stats.get("effect_size"), float("nan")),
                "ci": stats.get("confidence_interval", ["", ""]),
            }
        }
    for cname, cinfo in (contrasts or {}).items():
        if not isinstance(cinfo, dict):
            continue
        ci = cinfo.get("ci") or cinfo.get("confidence_interval") or ["", ""]
        rows.append(
            {
                "table": "TAB6",
                "condition": f"CONTRAST::{cname}",
                "kind": "statistical_test",
                "n": "",
                "validated_patch_rate_vpr": "",
                "vpr_ci_low": ci[0] if isinstance(ci, (list, tuple)) and len(ci) == 2 else "",
                "vpr_ci_high": ci[1] if isinstance(ci, (list, tuple)) and len(ci) == 2 else "",
                "iterations_to_accept": "",
                "test_used": cinfo.get("test_used", ""),
                "p_value": "" if math.isnan(_finite(cinfo.get("p_value"), float("nan"))) else round(_finite(cinfo.get("p_value")), 6),
                "effect_size": "" if math.isnan(_finite(cinfo.get("effect_size"), float("nan"))) else round(_finite(cinfo.get("effect_size")), 4),
            }
        )

    return pd.DataFrame(rows)


# --------------------------------------------------------------------------- #
# Public API                                                                   #
# --------------------------------------------------------------------------- #
def write_rq3_tables(results_dir: Path = RESULTS_DIR) -> Dict[str, str]:
    """
    Read saved RQ3 results and write results/tables/TAB5.csv and TAB6.csv.
    Returns {table_id: path} for the files written.
    """
    results_dir = Path(results_dir)
    tables_dir = results_dir / "tables"
    tables_dir.mkdir(parents=True, exist_ok=True)

    results = _load_json(results_dir / "results.json") or {}
    # Optional richer intermediates (written by rq3_analysis / oracle / agent).
    e1 = _load_json(results_dir / "rq3_e1_detail.json")
    e2 = _load_json(results_dir / "rq3_e2_detail.json")

    written: Dict[str, str] = {}

    tab5 = _build_tab5(results, e1)
    if tab5.empty:
        # Never write an empty table silently — emit a single explicit note row.
        tab5 = pd.DataFrame(
            [{"table": "TAB5", "note": "DATA NEEDED: no RQ3-E1 oracle results available to tabulate."}]
        )
    p5 = tables_dir / "TAB5.csv"
    tab5.to_csv(p5, index=False)
    written["TAB5"] = str(p5)
    print(f"[rq3_tables] wrote {p5} ({len(tab5)} rows)")

    tab6 = _build_tab6(results, e2)
    if tab6.empty:
        tab6 = pd.DataFrame(
            [{"table": "TAB6", "note": "DATA NEEDED: no RQ3-E2 ladder results available to tabulate."}]
        )
    p6 = tables_dir / "TAB6.csv"
    tab6.to_csv(p6, index=False)
    written["TAB6"] = str(p6)
    print(f"[rq3_tables] wrote {p6} ({len(tab6)} rows)")

    return written


def main() -> None:
    written = write_rq3_tables()
    print("[rq3_tables] done:", ", ".join(f"{k}={v}" for k, v in written.items()))


if __name__ == "__main__":
    main()