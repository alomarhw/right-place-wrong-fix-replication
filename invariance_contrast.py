"""invariance_contrast.py — RQ1-E1 verbatim-vs-variant paired evaluation.

For each detector, trains ONLY on verbatim data, then evaluates on both the
verbatim split and the certified slice-preserving variant split over the SAME
CVE ids. Produces, per detector:
  - accuracy (overall), macro_f1, recall
  - per-split accuracy and Δ_acc = Acc(verbatim) - Acc(variant)
  - paired 2x2 McNemar table + pooled split odds ratio
  - provenance vs. difficulty decomposition using the seen/unseen control:
    gap_seen (train-exposed CVEs) vs gap_unseen (held-out CVEs); a surface-token
    memorization effect shows gap_seen > gap_unseen.

Key deps: scikit-learn==1.5.1, numpy==2.2.6.
"""
from __future__ import annotations

import os

import numpy as np
from sklearn.metrics import f1_score, recall_score

from data_prep import CVEItem
from detectors import BaseDetector, build_all_detectors
from variant_builder import Variant, build_certified_variants

RANDOM_SEED = int(os.environ.get("RP_RANDOM_SEED", 42))


def _mcnemar_table(correct_v: np.ndarray, correct_t: np.ndarray) -> dict:
    """2x2 table: b = verbatim-correct & variant-wrong, c = verbatim-wrong & variant-correct."""
    a = int(np.sum(correct_v & correct_t))
    b = int(np.sum(correct_v & ~correct_t))
    c = int(np.sum(~correct_v & correct_t))
    d = int(np.sum(~correct_v & ~correct_t))
    return {"a": a, "b": b, "c": c, "d": d}


def _pooled_odds_ratio(n_v_correct, n_v_total, n_t_correct, n_t_total) -> float:
    """OR of being correct on verbatim vs variant (Haldane-Anscombe corrected)."""
    v_wrong = n_v_total - n_v_correct
    t_wrong = n_t_total - n_t_correct
    a, b = n_v_correct + 0.5, v_wrong + 0.5
    c, d = n_t_correct + 0.5, t_wrong + 0.5
    return float((a / b) / (c / d))


def evaluate_split(det: BaseDetector, codes: list[str], labels: list[int]) -> dict:
    pred = det.predict(codes)
    y = np.array(labels)
    correct = (pred == y)
    acc = float(correct.mean()) if len(y) else 0.0
    macro_f1 = float(f1_score(y, pred, average="macro", zero_division=0)) if len(set(y)) > 1 else acc
    rec = float(recall_score(y, pred, average="macro", zero_division=0)) if len(set(y)) > 1 else acc
    return {"pred": pred, "correct": correct, "accuracy": acc,
            "macro_f1": macro_f1, "recall": rec}


def run_invariance_contrast(items: list[CVEItem], seed: int = RANDOM_SEED) -> dict:
    """Return per-detector paired verbatim/variant results + aggregate metrics."""
    rng = np.random.default_rng(seed)

    # Build certified variants aligned to items (one variant per certified item)
    variants, yield_stats = build_certified_variants(items, seed=seed)
    # align: keep only items whose variant was certified, in matched order
    cert_ids = {}
    for v in variants:
        cert_ids.setdefault((v.cve_id, v.code is not None), v)
    # Build matched verbatim/variant lists keyed positionally
    matched_items: list[CVEItem] = []
    matched_variants: list[Variant] = []
    used = set()
    for it in items:
        # find a certified variant produced from THIS item (match by cve_id+label+provenance)
        for v in variants:
            vid = id(v)
            if vid in used:
                continue
            if v.cve_id == it.cve_id and v.label == it.label and v.provenance == it.provenance:
                matched_items.append(it)
                matched_variants.append(v)
                used.add(vid)
                break
    if not matched_items:
        # fallback: all items, re-run variant build per item to guarantee alignment
        matched_items = items
        matched_variants = [build_certified_variants([it], seed=seed + i)[0][0]
                            if build_certified_variants([it], seed=seed + i)[0]
                            else None
                            for i, it in enumerate(items)]
        keep = [(it, v) for it, v in zip(matched_items, matched_variants) if v is not None]
        matched_items = [k[0] for k in keep]
        matched_variants = [k[1] for k in keep]

    verbatim_codes = [it.code for it in matched_items]
    variant_codes = [v.code for v in matched_variants]
    labels = [it.label for it in matched_items]
    provenance = [it.provenance for it in matched_items]

    detectors = build_all_detectors(seed)
    per_detector = {}
    for name, det in detectors.items():
        # train ONLY on verbatim
        try:
            det.set_groups([it.cve_id for it in matched_items])  # RAG: no same-CVE retrieval
            det.fit(verbatim_codes, labels)
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"Detector '{name}' failed to fit: {exc}") from exc
        ev = evaluate_split(det, verbatim_codes, labels)
        et = evaluate_split(det, variant_codes, labels)
        correct_v = ev["correct"]
        correct_t = et["correct"]
        delta_acc = ev["accuracy"] - et["accuracy"]
        table = _mcnemar_table(correct_v, correct_t)
        orr = _pooled_odds_ratio(int(correct_v.sum()), len(correct_v),
                                 int(correct_t.sum()), len(correct_t))

        # provenance vs difficulty: compute gap separately on seen vs unseen
        prov = np.array(provenance)
        gap_seen = _subset_gap(correct_v, correct_t, prov == "seen")
        gap_unseen = _subset_gap(correct_v, correct_t, prov == "unseen")

        per_detector[name] = {
            "accuracy": ev["accuracy"],
            "macro_f1": ev["macro_f1"],
            "recall": ev["recall"],
            "acc_verbatim": ev["accuracy"],
            "acc_variant": et["accuracy"],
            "delta_acc": float(delta_acc),
            "mcnemar_table": table,
            "pooled_split_odds_ratio": orr,
            "correct_verbatim": correct_v.astype(int).tolist(),
            "correct_variant": correct_t.astype(int).tolist(),
            "gap_seen": gap_seen,
            "gap_unseen": gap_unseen,
            "provenance_component": float(gap_seen - gap_unseen),  # memorization-attributable
        }
        print(f"[invariance] {name[:38]:38s} acc_v={ev['accuracy']:.3f} "
              f"acc_t={et['accuracy']:.3f} Δ={delta_acc:+.3f} OR={orr:.2f} "
              f"gap_seen={gap_seen:+.3f} gap_unseen={gap_unseen:+.3f}")

    return {
        "per_detector": per_detector,
        "yield_stats": yield_stats,
        "n_matched_cves": len(matched_items),
        "provenance": provenance,
        "labels": labels,
    }


def _subset_gap(correct_v: np.ndarray, correct_t: np.ndarray, mask: np.ndarray) -> float:
    if mask.sum() == 0:
        return 0.0
    acc_v = float(correct_v[mask].mean())
    acc_t = float(correct_t[mask].mean())
    return acc_v - acc_t


if __name__ == "__main__":
    from data_prep import build_corpus
    items, _ = build_corpus(n_cves=30, allow_synthetic=True)
    out = run_invariance_contrast(items)
    print("matched CVEs:", out["n_matched_cves"])