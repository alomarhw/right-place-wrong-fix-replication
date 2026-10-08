"""rq2_invariance.py — RQ2-E1 (benchmark construction) + RQ2-E2 (invariance contrast).

See module header in the original; this version additionally exposes thin wrapper
functions (build_construction_validity / run_invariance_contrast) used by
rq2_main.py so that orchestrator runs without AttributeErrors.

Key deps: datasketch==1.6.5, scikit-learn==1.5.1, scipy==1.13.1, numpy==2.2.6.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

import numpy as np
from sklearn.metrics import f1_score, recall_score

from data_prep import CVEItem, canonical_slice, extract_slice
from detectors import build_all_detectors
from variant_builder import Variant, build_variant, undo_rename

RANDOM_SEED = int(os.environ.get("RP_RANDOM_SEED", 42))

try:
    from datasketch import MinHash
    _HAVE_DATASKETCH = True
except Exception:  # noqa: BLE001
    _HAVE_DATASKETCH = False

LSH_THRESHOLD = float(os.environ.get("RP_LSH_THRESHOLD", 0.90))

SLICE_MATCHER_KEY = "slice_matcher_src_vul"
SRC_VUL_BASELINE = ("SRC VUL vsvector slice matching (foundation, "
                    "\\cite{57b456a85303a715d9311a88cd3de662b631778c}) — deterministic detector baseline")

RECALL_SENSITIVE_KEYS = [
    "lexical_recall_control",
    "finetuned_encoder_llm",
    "Fine-tuned CodeBERT/UniXcoder vulnerability classifier (LLM detector)",
    "VUDDY hashing-based vulnerable clone detector (from VUDDY corpus / salimi2022vulslicer comparison)",
    "VulPecker code-similarity vulnerability detector (li2016vulpecker)",
    "Open-weight instruct LLM detector (e.g., StarCoder2/CodeLlama, elatoubi2025assessing-style prompting)",
    "RAG-based LLM vulnerability detector (antal2026evaluating / kaniewski2026revisiting style)",
    "Ungrounded LLM patching (same LLM, no slice/CVE grounding) — primary RQ3 baseline",
]


def _slice_tokens(code: str) -> list[str]:
    canon = canonical_slice(code)
    toks = re.findall(r"[A-Za-z_]\w*|[^\sA-Za-z_]", canon)
    return toks or ["_empty_"]


def _minhash(tokens: list[str], num_perm: int = 128):
    if _HAVE_DATASKETCH:
        mh = MinHash(num_perm=num_perm)
        for t in tokens:
            mh.update(t.encode("utf-8"))
        return mh
    return set(tokens)


def vsvector_similarity(code_a: str, code_b: str) -> float:
    ta, tb = _slice_tokens(code_a), _slice_tokens(code_b)
    mha, mhb = _minhash(ta), _minhash(tb)
    if _HAVE_DATASKETCH:
        return float(mha.jaccard(mhb))
    inter = len(mha & mhb)  # type: ignore[operator]
    union = len(mha | mhb) or 1  # type: ignore[operator]
    return inter / union


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    prev = list(range(lb + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * lb
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[lb]


def normalized_levenshtein(a: str, b: str) -> float:
    m = max(len(a), len(b)) or 1
    return _levenshtein(a, b) / m


def _token_set(code: str) -> set[str]:
    return set(re.findall(r"[A-Za-z_]\w*|[^\sA-Za-z_]", code))


def token_jaccard(a: str, b: str) -> float:
    sa, sb = _token_set(a), _token_set(b)
    union = len(sa | sb) or 1
    return len(sa & sb) / union


def _char_ngrams(code: str, n: int = 4) -> set[str]:
    s = re.sub(r"\s+", "", code)
    return {s[i:i + n] for i in range(max(0, len(s) - n + 1))}


@dataclass
class AcceptedPair:
    cve_id: str
    cwe: str
    label: int
    provenance: str
    verbatim_code: str
    variant_code: str
    vsvector_similarity: float
    ops_applied: list
    norm_levenshtein: float
    token_jaccard: float
    ngram_overlap_verbatim: float
    ngram_overlap_variant: float
    fingerprint_match_verbatim: int
    fingerprint_match_variant: int


def _normalized_fingerprint(code: str) -> str:
    code = re.sub(r"/\*.*?\*/", " ", code, flags=re.S)
    code = re.sub(r"//[^\n]*", " ", code)
    code = re.sub(r"[A-Za-z_]\w*", "X", code)
    return re.sub(r"\s+", "", code)


def build_accepted_variants(items: list[CVEItem], seed: int = RANDOM_SEED):
    accepted: list[AcceptedPair] = []
    n_total = 0
    n_accepted = 0
    per_cwe = {}
    op_counter = {}
    invariance_pass = 0
    self_sim_scores = []

    for i, item in enumerate(items):
        n_total += 1
        per_cwe.setdefault(item.cwe, [0, 0])
        per_cwe[item.cwe][0] += 1

        var: Variant = build_variant(item, seed=seed + i)
        # slice signatures compared modulo the variant's consistent renaming
        var_norm = undo_rename(var.code, var.rename_map)
        sim = vsvector_similarity(item.code, var_norm)
        accept = var.certified and (sim >= LSH_THRESHOLD)

        self_sim = vsvector_similarity(item.code, item.code)
        self_sim_scores.append(self_sim)

        if accept:
            n_accepted += 1
            per_cwe[item.cwe][1] += 1
            for op in var.ops_applied:
                op_counter[op] = op_counter.get(op, 0) + 1
            if canonical_slice(item.code) == canonical_slice(var_norm):
                invariance_pass += 1

            nlev = normalized_levenshtein(item.code, var.code)
            tjac = token_jaccard(item.code, var.code)
            gv = _char_ngrams(item.code)
            gt = _char_ngrams(var.code)
            overlap_vt = (len(gv & gt) / (len(gv) or 1))
            fp_v = _normalized_fingerprint(item.code)
            fp_t = _normalized_fingerprint(var.code)
            fp_match = int(fp_v == fp_t)

            accepted.append(AcceptedPair(
                cve_id=item.cve_id, cwe=item.cwe, label=item.label,
                provenance=item.provenance,
                verbatim_code=item.code, variant_code=var.code,
                vsvector_similarity=sim, ops_applied=var.ops_applied,
                norm_levenshtein=nlev, token_jaccard=tjac,
                ngram_overlap_verbatim=1.0, ngram_overlap_variant=overlap_vt,
                fingerprint_match_verbatim=1, fingerprint_match_variant=fp_match,
            ))

    yield_ = n_accepted / n_total if n_total else 0.0
    inv_pass_rate = invariance_pass / n_accepted if n_accepted else 1.0
    per_cwe_yield = {cwe: (a / t if t else 0.0) for cwe, (t, a) in per_cwe.items()}

    stats = {
        "accepted_variant_yield": yield_,
        "n_total": n_total,
        "n_accepted": n_accepted,
        "vsvector_invariance_pass_rate": inv_pass_rate,
        "per_cwe_yield": per_cwe_yield,
        "per_cwe_counts": {k: {"total": v[0], "accepted": v[1]} for k, v in per_cwe.items()},
        "transformation_mix": op_counter,
        "self_similarity_mean": float(np.mean(self_sim_scores)) if self_sim_scores else 1.0,
        "lsh_threshold": LSH_THRESHOLD,
    }
    return accepted, stats


def _eval(det, codes, labels):
    pred = det.predict(codes)
    y = np.array(labels)
    correct = (pred == y)
    acc = float(correct.mean()) if len(y) else 0.0
    if len(set(y.tolist())) > 1:
        f1 = float(f1_score(y, pred, average="macro", zero_division=0))
        rec = float(recall_score(y, pred, average="macro", zero_division=0))
    else:
        f1 = acc
        rec = acc
    return correct, acc, f1, rec


def run_rq2(items: list[CVEItem], seed: int = RANDOM_SEED) -> dict:
    accepted, cons = build_accepted_variants(items, seed=seed)
    if not accepted:
        raise RuntimeError(
            "RQ2-E1 produced ZERO accepted variants — the slice-preserving "
            "transformation certification failed on every item. Check the "
            "transformation operators / LSH threshold."
        )

    verbatim_codes = [p.verbatim_code for p in accepted]
    variant_codes = [p.variant_code for p in accepted]
    labels = [p.label for p in accepted]
    provenance = [p.provenance for p in accepted]

    detectors = build_all_detectors(seed)
    per_detector = {}
    for name, det in detectors.items():
        det.set_groups([p.cve_id for p in accepted])  # RAG: no same-CVE retrieval
        det.fit(verbatim_codes, labels)
        cv, acc_v, f1_v, rec_v = _eval(det, verbatim_codes, labels)
        ct, acc_t, f1_t, rec_t = _eval(det, variant_codes, labels)
        delta = acc_v - acc_t
        per_detector[name] = {
            "accuracy": acc_t,
            "macro_f1": f1_t,
            "recall": rec_t,
            "acc_verbatim": acc_v,
            "acc_variant": acc_t,
            "f1_verbatim": f1_v,
            "f1_variant": f1_t,
            "delta_acc": float(delta),
            "correct_verbatim": cv.astype(int).tolist(),
            "correct_variant": ct.astype(int).tolist(),
        }

    fp_verbatim = np.array([p.fingerprint_match_verbatim for p in accepted])
    fp_variant = np.array([p.fingerprint_match_variant for p in accepted])
    nlev = np.array([p.norm_levenshtein for p in accepted])
    tjac = np.array([p.token_jaccard for p in accepted])
    ngram_overlap = np.array([p.ngram_overlap_variant for p in accepted])

    return {
        "per_detector": per_detector,
        "construction": cons,
        "accepted_pairs_meta": {
            "n_accepted": len(accepted),
            "norm_levenshtein_mean": float(nlev.mean()),
            "norm_levenshtein_std": float(nlev.std()),
            "token_jaccard_mean": float(tjac.mean()),
            "ngram_overlap_mean": float(ngram_overlap.mean()),
            "fingerprint_match_verbatim": fp_verbatim.astype(int).tolist(),
            "fingerprint_match_variant": fp_variant.astype(int).tolist(),
            "vsvector_similarity_mean": float(np.mean([p.vsvector_similarity for p in accepted])),
        },
        "labels": labels,
        "provenance": provenance,
        "slice_matcher_key": SLICE_MATCHER_KEY,
        "recall_sensitive_keys": [k for k in RECALL_SENSITIVE_KEYS if k in per_detector],
    }


# ----------------------------------------------------------------------------
# Thin wrappers used by rq2_main.py (kept for API compatibility)
# ----------------------------------------------------------------------------
def _records_to_items(corpus) -> list[CVEItem]:
    items = []
    for r in corpus:
        if isinstance(r, CVEItem):
            items.append(r)
        elif isinstance(r, dict):
            items.append(CVEItem(
                cve_id=r.get("cve_id", "NA"), cwe=r.get("cwe", "CWE-119"),
                code=r.get("code", ""), label=int(r.get("label", 0)),
                provenance=r.get("provenance", "seen"),
            ))
    return items


def _wilson(k, n):
    try:
        from statsmodels.stats.proportion import proportion_confint
        if n <= 0:
            return [0.0, 0.0]
        lo, hi = proportion_confint(int(round(k)), int(n), alpha=0.05, method="wilson")
        return [float(lo), float(hi)]
    except Exception:  # noqa: BLE001
        return [0.0, 0.0]


def build_construction_validity(corpus, repeats: int = 1, seed: int = RANDOM_SEED) -> dict:
    items = _records_to_items(corpus)
    accepted, cons = build_accepted_variants(items, seed=seed)
    k = cons["n_accepted"]
    n = cons["n_total"]
    return {
        "accepted_variant_yield_rq2": cons["accepted_variant_yield"],
        "yield_ci": _wilson(k, n),
        "vsvector_invariance_pass_rate_rq2": cons["vsvector_invariance_pass_rate"],
        "self_similarity_control": cons["self_similarity_mean"],
        "_accepted": accepted,
        "_cons": cons,
    }


def run_invariance_contrast(corpus, construction: dict | None = None,
                            repeats: int = 1, seed: int = RANDOM_SEED) -> dict:
    items = _records_to_items(corpus)
    out = run_rq2(items, seed=seed)
    slice_key = out["slice_matcher_key"]
    recall_keys = out["recall_sensitive_keys"]
    ref_delta = out["per_detector"][slice_key]["delta_acc"]
    mean_recall_delta = float(np.mean(
        [out["per_detector"][k]["delta_acc"] for k in recall_keys])) if recall_keys else 0.0
    out["reference_delta_acc"] = ref_delta
    out["mean_recall_detector_delta_acc"] = mean_recall_delta
    return out


if __name__ == "__main__":
    from data_prep import build_corpus
    items, tag = build_corpus(n_cves=20, allow_synthetic=True)
    out = run_rq2(items)
    print("yield:", out["construction"]["accepted_variant_yield"])
    print("invariance:", out["construction"]["vsvector_invariance_pass_rate"])
    sm = out["per_detector"][out["slice_matcher_key"]]
    print("slice matcher Δ_acc:", sm["delta_acc"])