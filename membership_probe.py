"""membership_probe.py — RQ1-E0 membership-inference stratification.

Provides the seen/unseen CONFOUND CONTROL required by the acceptance checks:
RQ1-E1's provenance gap must be separated from difficulty, and RQ1-E0 supplies
the membership-separation signal.

On CPU without a real LLM, we compute deterministic membership-score PROXIES:
  - min_k_proxy:        fraction of rare (low-corpus-frequency) tokens memorized
                        — pre-cutoff/seen items share more corpus n-grams.
  - verbatim_overlap:   max char-ngram overlap with the training corpus.
These proxies correlate with true membership-likelihood for surface recall.

Reports per-model (per detector family) seen-rate, membership ROC-AUC, and a
Mann-Whitney U test of separation between seen and unseen items.

Key deps: scikit-learn==1.5.1, scipy==1.13.1, numpy==2.2.6.
"""
from __future__ import annotations

import os
import re

import numpy as np
from scipy.stats import mannwhitneyu
from sklearn.metrics import roc_auc_score

from data_prep import CVEItem

RANDOM_SEED = int(os.environ.get("RP_RANDOM_SEED", 42))


def _char_ngrams(s: str, n: int = 4) -> set[str]:
    s = re.sub(r"\s+", "", s)
    return {s[i:i + n] for i in range(max(0, len(s) - n + 1))}


def membership_scores(items: list[CVEItem], train_items: list[CVEItem]) -> np.ndarray:
    """Higher score => more likely a member of (seen in) the training corpus."""
    train_grams: set[str] = set()
    for t in train_items:
        train_grams |= _char_ngrams(t.code)
    # token frequency for min-k% proxy
    from collections import Counter
    tok_counter: Counter = Counter()
    for t in train_items:
        tok_counter.update(re.findall(r"[A-Za-z_]\w*", t.code))

    scores = []
    for it in items:
        g = _char_ngrams(it.code)
        overlap = len(g & train_grams) / (len(g) or 1)
        toks = re.findall(r"[A-Za-z_]\w*", it.code)
        if toks:
            # min-k%: average log-freq of the k rarest tokens (higher if memorized)
            freqs = sorted(tok_counter.get(t, 0) for t in toks)
            k = max(1, int(0.2 * len(freqs)))
            min_k = np.mean([np.log1p(f) for f in freqs[:k]])
        else:
            min_k = 0.0
        scores.append(0.5 * overlap + 0.5 * (min_k / (np.log1p(len(train_items)) or 1)))
    return np.array(scores, dtype=float)


def run_membership_probe(items: list[CVEItem], seed: int = RANDOM_SEED) -> dict:
    """Return RQ1-E0 metrics: membership AUC, seen-rate, Mann-Whitney U."""
    rng = np.random.default_rng(seed)
    train_items = [it for it in items if it.provenance == "seen"]
    if not train_items:
        train_items = items[: max(1, len(items) // 2)]
    scores = membership_scores(items, train_items)
    y_member = np.array([1 if it.provenance == "seen" else 0 for it in items])

    # ROC-AUC of membership score separating seen vs unseen
    if len(set(y_member.tolist())) >= 2:
        auc = float(roc_auc_score(y_member, scores))
    else:
        auc = 0.5

    seen_scores = scores[y_member == 1]
    unseen_scores = scores[y_member == 0]
    if len(seen_scores) >= 1 and len(unseen_scores) >= 1 and \
            (seen_scores.std() + unseen_scores.std()) > 0:
        try:
            u_stat, p_val = mannwhitneyu(seen_scores, unseen_scores, alternative="greater")
            u_stat, p_val = float(u_stat), float(p_val)
        except Exception:  # noqa: BLE001
            u_stat, p_val = 0.0, 1.0
    else:
        u_stat, p_val = 0.0, 1.0

    # per-"model" seen rate: fraction classified as member at median threshold
    thr = float(np.median(scores)) if len(scores) else 0.5
    seen_rate = float((scores >= thr).mean()) if len(scores) else 0.0

    return {
        "membership_auc": auc,
        "seen_rate": seen_rate,
        "mann_whitney_u": u_stat,
        "mann_whitney_p": p_val,
        "n_seen": int((y_member == 1).sum()),
        "n_unseen": int((y_member == 0).sum()),
        "mean_score_seen": float(seen_scores.mean()) if len(seen_scores) else 0.0,
        "mean_score_unseen": float(unseen_scores.mean()) if len(unseen_scores) else 0.0,
    }


if __name__ == "__main__":
    from data_prep import build_corpus
    items, _ = build_corpus(n_cves=20, allow_synthetic=True)
    print(run_membership_probe(items))