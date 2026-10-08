"""Sanity tests for RQ3 (oracle calibration + slice-grounded agent ladder).

Fast structural/behavioural checks, NOT scientific validation:
  * every contracted RQ3 metric is a finite number,
  * the independent oracle NEGATIVE control (official fix vs identical copy) accepts,
  * the POSITIVE control (whole-slice deletion severed by severance but rejected by
    the independent oracle) is present,
  * the ablation ladder arms are genuinely distinct (slice-grounded VPR >= ungrounded),
  * the oracle-fidelity precondition flag is present,
  * RQ3 is NOT bound to GLUE,
  * figures are produced.

Run with:  pytest -q test_rq3.py
"""
from __future__ import annotations

import math
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parent

RQ3_CONTRACT_METRICS = [
    "accuracy",
    "macro_f1",
    "recall",
    "validated_patch_rate_vpr_rq3",
    "iterations_to_accept_rq3",
    "oracle_false_accept_rate_rq3",
    "official_patch_accept_rate_rq3",
]


def _finite(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(float(x))


@pytest.fixture(scope="module")
def rq3_results():
    """Run a tiny RQ3 analysis in-process (smoke scale, synthetic allowed)."""
    import rq3_analysis
    all_results = rq3_analysis.run_analysis(n_cves=20, allow_synthetic=True, repeats=1)
    assert "RQ3" in all_results
    return all_results["RQ3"]


def test_rq3_key_and_question(rq3_results):
    assert "_question" in rq3_results
    assert "metrics" in rq3_results


def test_rq3_metrics_finite(rq3_results):
    metrics = rq3_results["metrics"]
    for m in RQ3_CONTRACT_METRICS:
        assert m in metrics, f"missing RQ3 metric: {m}"
        assert _finite(metrics[m]), f"metric {m} not finite: {metrics[m]!r}"


def test_rq3_baselines_finite(rq3_results):
    bc = rq3_results.get("baseline_comparison", {})
    assert bc, "baseline_comparison empty"
    for name, d in bc.items():
        for m in RQ3_CONTRACT_METRICS:
            assert m in d, f"baseline {name} missing {m}"
            assert _finite(d[m]), f"baseline {name} metric {m} not finite"


def test_rq3_statistical_tests(rq3_results):
    st = rq3_results["statistical_tests"]
    assert _finite(st["p_value"])
    assert _finite(st["effect_size"])
    ci = st["confidence_interval"]
    assert isinstance(ci, (list, tuple)) and len(ci) == 2
    assert _finite(ci[0]) and _finite(ci[1])


def test_oracle_negative_control(rq3_results):
    """Official fix compared to an identical copy MUST be accepted by the oracle."""
    cal = rq3_results["_rq3_e1_oracle_calibration"]
    assert cal["negative_control_identical_fix_accepted"] is True, (
        "independent oracle failed the identical-fix negative control"
    )


def test_oracle_positive_control(rq3_results):
    """Whole-slice deletion: severed by severance but rejected by the independent oracle."""
    cal = rq3_results["_rq3_e1_oracle_calibration"]
    pc = cal["positive_control_slice_deletion_severed_but_rejected"]
    assert _finite(pc)
    assert pc >= 0.5, (
        "positive control weak: whole-slice deletion should be severed-but-rejected"
    )


def test_oracle_precondition_present(rq3_results):
    cal = rq3_results["_rq3_e1_oracle_calibration"]
    assert "oracle_precondition_ok" in cal
    assert isinstance(cal["oracle_precondition_ok"], bool)
    assert _finite(cal["official_patch_accept_rate"])
    assert _finite(cal["oracle_false_accept_rate"])


def test_severance_is_intermediate_signal(rq3_results):
    """Severance MCC/kappa vs the independent oracle must be reported (not the arbiter)."""
    cal = rq3_results["_rq3_e1_oracle_calibration"]
    assert _finite(cal["severance_vs_oracle_mcc"])
    assert _finite(cal["severance_vs_oracle_kappa"])
    assert _finite(cal["severance_false_accept_rate"])


def test_ladder_arms_distinct(rq3_results):
    """The ablation arms must be genuinely different: slice-grounded-full should not be
    identical to the ungrounded baseline, and should not under-perform it."""
    ladder = rq3_results["_rq3_e2_ladder"]
    per = ladder["per_condition"]
    vpr_full = per["slice_grounded_full"]["validated_patch_rate_vpr"]
    vpr_ungrounded = per["no_grounding_no_feedback"]["validated_patch_rate_vpr"]
    assert _finite(vpr_full) and _finite(vpr_ungrounded)
    # grounded full must be at least as good as ungrounded (marginal value of grounding)
    assert vpr_full >= vpr_ungrounded - 1e-9, (
        f"slice-grounded-full VPR ({vpr_full}) < ungrounded VPR ({vpr_ungrounded}) — "
        "ablation not differentiating grounding"
    )
    # at least one condition must differ from another (non-degenerate ladder)
    all_vprs = [per[c]["validated_patch_rate_vpr"] for c in ladder_order(rq3_results)]
    assert len(set(round(v, 6) for v in all_vprs)) >= 2, (
        "all ladder conditions produced identical VPR — arms are not distinct"
    )


def ladder_order(rq3_results):
    return list(rq3_results["_rq3_e2_ladder"]["per_condition"].keys())


def test_rq3_not_bound_to_glue(rq3_results):
    note = rq3_results.get("_data_binding_note", "")
    assert "GLUE" in note and "NOT" in note.upper(), (
        "RQ3 data-binding note must explicitly state GLUE is not used"
    )
    assert rq3_results.get("_data_source") in {"real", "synthetic"}


def test_rq3_mcnemar_and_ablation_present(rq3_results):
    ladder = rq3_results["_rq3_e2_ladder"]
    for key in ["mcnemar_grounded_vs_ungrounded",
                "mcnemar_ablation_full_vs_no_feedback",
                "mcnemar_full_vs_cve_text_rag",
                "wilcoxon_iterations_full_vs_ungrounded"]:
        assert key in ladder, f"missing RQ3 statistic block: {key}"
        assert _finite(ladder[key].get("p", 1.0))


def test_rq3_figures_exist():
    import rq3_plots
    rq3_plots.main()
    figs = ROOT / "figures"
    assert (figs / "rq3_e1_results.png").exists(), "RQ3-E1 figure missing"
    assert (figs / "rq3_e2_results.png").exists() or (figs / "rq3_alt1_results.png").exists(), \
        "RQ3-E2 figure missing"
    assert (figs / "slice_worked_example.png").exists(), "method worked-slice figure missing"


def test_rq3_tables_written():
    import rq3_analysis
    rq3_analysis.run_analysis(n_cves=15, allow_synthetic=True, repeats=1)
    tabs = ROOT / "results" / "tables"
    assert (tabs / "TAB5.csv").exists(), "TAB5.csv (RQ3-E1) missing"
    assert (tabs / "TAB6.csv").exists(), "TAB6.csv (RQ3-E2) missing"