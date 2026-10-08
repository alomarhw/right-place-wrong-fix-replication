"""Sanity tests for RQ2-ALT1 (construction + invariance contrast).

Fast structural/behavioural checks, NOT scientific validation:
  * RQ2-E1 produces accepted variants with the self-similarity negative control ~1.0,
  * every contracted RQ2 metric is a finite number,
  * the DiD confidence interval bounds are finite,
  * the recall-collapse positive control is present,
  * figures are produced.

These tests import the RQ2 modules directly and run a tiny in-process pipeline so
they do not depend on main.py's CLI.

Run with:  pytest -q test_rq2_alt1.py
"""
from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent

RQ2_CONTRACT_METRICS = [
    "accuracy",
    "macro_f1",
    "recall",
    "accepted_variant_yield_rq2",
    "vsvector_invariance_pass_rate_rq2",
    "difference_in_differences_did_rq2",
    "annotator_agreement_cohen_s_kappa_rq2",
]


def _finite(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(float(x))


@pytest.fixture(scope="module")
def rq2_results():
    """Run a tiny RQ2 analysis in-process (smoke scale) and load results.json."""
    import rq2_analysis
    all_results = rq2_analysis.run_analysis(n_cves=20, allow_synthetic=True, repeats=1)
    assert "RQ2" in all_results
    return all_results["RQ2"]


def test_rq2_key_and_question(rq2_results):
    assert "_question" in rq2_results
    assert "metrics" in rq2_results


def test_rq2_metrics_finite(rq2_results):
    metrics = rq2_results["metrics"]
    for m in RQ2_CONTRACT_METRICS:
        assert m in metrics, f"missing RQ2 metric: {m}"
        assert _finite(metrics[m]), f"metric {m} not finite: {metrics[m]!r}"


def test_rq2_baselines_finite(rq2_results):
    bc = rq2_results.get("baseline_comparison", {})
    assert bc, "baseline_comparison empty"
    for name, d in bc.items():
        for m in RQ2_CONTRACT_METRICS:
            assert m in d, f"baseline {name} missing {m}"
            assert _finite(d[m]), f"baseline {name} metric {m} not finite"


def test_rq2_statistical_tests(rq2_results):
    st = rq2_results["statistical_tests"]
    assert _finite(st["p_value"])
    assert _finite(st["effect_size"])
    ci = st["confidence_interval"]
    assert isinstance(ci, (list, tuple)) and len(ci) == 2
    assert _finite(ci[0]) and _finite(ci[1])


def test_self_similarity_negative_control(rq2_results):
    """vsvector(c, c) must be ~1.0 — the estimator's sanity check."""
    nc = rq2_results["_negative_controls"]
    assert _finite(nc["self_similarity_vsvector_mean"])
    assert nc["self_similarity_vsvector_mean"] >= 0.90, (
        "self-similarity negative control failed (vsvector estimator broken)"
    )
    # verbatim-vs-verbatim Δ_acc must be exactly 0 by construction
    assert nc["verbatim_vs_verbatim_delta_acc"] == 0.0


def test_recall_collapse_control_present(rq2_results):
    rc = rq2_results["_recall_collapse_positive_control"]
    for k in ["mcnemar_p", "fingerprint_collapse_odds_ratio",
              "fingerprint_match_rate_verbatim", "fingerprint_match_rate_variant"]:
        assert k in rc and _finite(rc[k])


def test_construction_validity_block(rq2_results):
    cv = rq2_results["_construction_validity"]
    assert _finite(cv["accepted_variant_yield"])
    assert _finite(cv["vsvector_invariance_pass_rate"])
    assert isinstance(cv["yield_wilson_ci"], list) and len(cv["yield_wilson_ci"]) == 2
    assert cv["verdict"] in {"ANSWERED_YES", "REFUTED", "INCONCLUSIVE"}


def test_invariance_contrast_block(rq2_results):
    ic = rq2_results["_invariance_contrast"]
    assert _finite(ic["difference_in_differences"])
    assert isinstance(ic["did_bootstrap_ci"], list) and len(ic["did_bootstrap_ci"]) == 2
    assert _finite(ic["slice_matcher_delta_acc"])
    assert _finite(ic["pooled_recall_sensitive_delta_acc"])


def test_rq2_figures_exist():
    import rq2_plots
    rq2_plots.main()
    figs = ROOT / "figures"
    main_fig = figs / "rq2_alt1_results.png"
    e2_fig = figs / "rq2_e2_results.png"
    method_fig = figs / "slice_worked_example.png"
    assert main_fig.exists() or e2_fig.exists(), "RQ2 main result figure missing"
    assert method_fig.exists(), "method worked-slice figure missing"


def test_tables_written():
    tabs = ROOT / "results" / "tables"
    assert (tabs / "TAB3.csv").exists(), "TAB3.csv (RQ2-E1) missing"
    assert (tabs / "TAB4.csv").exists(), "TAB4.csv (RQ2-E2) missing"