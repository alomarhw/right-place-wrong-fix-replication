"""logit_rank.py — threshold or comprehension? Label-token scores of open-weight detectors (GPU).

Same 150 vulnerable/fixed CVE pairs and the same one-word audit prompt as the RQ2 detector
(detectors._DETECT_SYSTEM, chat template, as in open_detect.py). For each function we read the
next-token logits after the prompt and take P(vulnerable) as the softmax over the first tokens of
"VULNERABLE" and "SAFE" (the two-label-token score of Li et al., ASE'26, Eq. 1). Then:

  ranking      share of CVEs whose vulnerable version scores above its fix (ties count 1/2),
               with a 95% bootstrap CI over CVEs: can single-function scores separate the pair?
  pair-correct at the default threshold (0.5), and at a threshold tuned by 5-fold cross-validation
               grouped by CVE (the best possible single cut-off, chosen on the training folds)
  calibration  ECE (10 bins) and Brier score, before and after temperature scaling fitted by
               grouped 5-fold CV; temperature is monotone in the score, so it cannot change labels,
               pair-correctness, or ranking — only confidence.

Ranking well above pair-correctness would mean the information is present but the threshold fails;
ranking near 0.5 means the model does not separate a vulnerable function from its fix at all.
Writes results/logit_rank_<model>.json.
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from data_prep import build_corpus  # noqa: E402
from detectors import _DETECT_SYSTEM  # noqa: E402

SEED = 42


def wilson(k, n, z=1.96):
    p = k / n; d = 1 + z * z / n; c = (p + z * z / (2 * n)) / d
    h = z * (p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5 / d
    return [p, max(0.0, c - h), min(1.0, c + h)]


@torch.no_grad()
def label_logits(model, tok, users, vul_id, safe_id, bs):
    """(n, 2) next-token logits for [VULNERABLE, SAFE] after the chat prompt."""
    out = []
    for i in range(0, len(users), bs):
        texts = [tok.apply_chat_template([{"role": "system", "content": _DETECT_SYSTEM},
                                          {"role": "user", "content": u}],
                                         tokenize=False, add_generation_prompt=True) for u in users[i:i + bs]]
        enc = tok(texts, return_tensors="pt", padding=True).to(model.device)
        last = model(**enc).logits[:, -1, :].float()   # left padding: the last position is the next token
        out.append(torch.stack([last[:, vul_id], last[:, safe_id]], 1).cpu().numpy())
        print(f"  scored {min(i + bs, len(users))}/{len(users)}", flush=True)
    return np.concatenate(out)


def ece(p, y, bins=10):
    edges = np.linspace(0, 1, bins + 1)
    conf = np.where(p >= 0.5, p, 1 - p); pred = (p >= 0.5).astype(int)
    total = 0.0
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (conf > lo) & (conf <= hi) if lo > 0 else (conf >= lo) & (conf <= hi)
        if m.any():
            total += m.mean() * abs((pred[m] == y[m]).mean() - conf[m].mean())
    return float(total)


def brier(p, y):
    return float(np.mean((p - y) ** 2))


def folds(n_pairs, k=5, seed=SEED):
    idx = np.random.default_rng(seed).permutation(n_pairs)
    return [idx[i::k] for i in range(k)]


def fit_temperature(margin, y):
    """Temperature T minimizing NLL of sigmoid(margin / T)."""
    from scipy.optimize import minimize_scalar

    def nll(logt):
        p = 1 / (1 + np.exp(-margin / np.exp(logt)))
        p = np.clip(p, 1e-9, 1 - 1e-9)
        return -np.mean(y * np.log(p) + (1 - y) * np.log(1 - p))
    return float(np.exp(minimize_scalar(nll, bounds=(-5, 5), method="bounded").x))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="Qwen/Qwen2.5-Coder-7B-Instruct")
    ap.add_argument("--bs", type=int, default=8)
    a = ap.parse_args()
    tok = AutoTokenizer.from_pretrained(a.model, padding_side="left")
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    model = AutoModelForCausalLM.from_pretrained(a.model, dtype=torch.bfloat16, device_map="cuda").eval()
    vul_id = tok.encode("VULNERABLE", add_special_tokens=False)[0]
    safe_id = tok.encode("SAFE", add_special_tokens=False)[0]
    assert vul_id != safe_id, "label tokens collide"

    items, _ = build_corpus(n_cves=300, allow_synthetic=False, seed=42)
    by = {}
    for it in items:
        by.setdefault(it.cve_id, {})[it.label] = it
    pairs = [(c, d[1], d[0]) for c, d in by.items() if 1 in d and 0 in d]
    users = [f"Function under review:\n```c\n{x.code}\n```" for _, v, f in pairs for x in (v, f)]
    lg = label_logits(model, tok, users, vul_id, safe_id, a.bs).reshape(len(pairs), 2, 2)
    margin = lg[:, :, 0] - lg[:, :, 1]                 # (pairs, [vuln, fix]) logit margin for VULNERABLE
    p = 1 / (1 + np.exp(-margin))
    s_v, s_f = p[:, 0], p[:, 1]
    rank_each = (s_v > s_f).astype(float) + 0.5 * (s_v == s_f)
    rng = np.random.default_rng(SEED)
    boots = [rank_each[rng.integers(0, len(pairs), len(pairs))].mean() for _ in range(2000)]
    pc_default = (s_v >= 0.5) & (s_f < 0.5)

    # cross-validated best single threshold (chosen on training folds, applied to the held-out fold)
    pc_tuned = np.zeros(len(pairs), dtype=bool)
    grid = np.unique(np.concatenate([s_v, s_f]))
    for test in folds(len(pairs)):
        train = np.setdiff1d(np.arange(len(pairs)), test)
        best = max(grid, key=lambda t: ((s_v[train] >= t) & (s_f[train] < t)).mean())
        pc_tuned[test] = (s_v[test] >= best) & (s_f[test] < best)

    y = np.tile([1, 0], len(pairs)); flat_m = margin.reshape(-1); flat_p = p.reshape(-1)
    p_cal = np.zeros_like(flat_p)
    for test in folds(len(pairs)):
        tr = np.setdiff1d(np.arange(len(pairs)), test)
        tri = np.concatenate([2 * tr, 2 * tr + 1]); tei = np.concatenate([2 * test, 2 * test + 1])
        t = fit_temperature(flat_m[tri], y[tri])
        p_cal[tei] = 1 / (1 + np.exp(-flat_m[tei] / t))

    prov = np.array([v.provenance for _, v, _ in pairs])
    res = {
        "model": a.model, "n_pairs": len(pairs), "label_tokens": [tok.decode([vul_id]), tok.decode([safe_id])],
        "ranking_accuracy": [float(rank_each.mean()), float(np.quantile(boots, 0.025)), float(np.quantile(boots, 0.975))],
        "pair_correct_default": wilson(int(pc_default.sum()), len(pairs)),
        "pair_correct_cv_tuned_threshold": wilson(int(pc_tuned.sum()), len(pairs)),
        "positive_rate_default": float((p >= 0.5).mean()),
        "accuracy_default": float(((p[:, 0] >= 0.5).sum() + (p[:, 1] < 0.5).sum()) / p.size),
        "calibration": {"ece_raw": ece(flat_p, y), "brier_raw": brier(flat_p, y),
                        "ece_temperature_cv": ece(p_cal, y), "brier_temperature_cv": brier(p_cal, y),
                        "accuracy_temperature_cv": float(((p_cal >= 0.5).astype(int) == y).mean())},
        "ranking_by_provenance": {q: float(rank_each[prov == q].mean()) for q in ("seen", "unseen")},
        "per_pair": {"cve_id": [c for c, _, _ in pairs], "p_vulnerable": s_v.tolist(), "p_fixed": s_f.tolist()},
    }
    dst = ROOT / "results" / f"logit_rank_{a.model.split('/')[-1]}.json"
    dst.write_text(json.dumps(res, indent=1))
    print(json.dumps({k: v for k, v in res.items() if k != "per_pair"}, indent=1))


if __name__ == "__main__":
    main()
