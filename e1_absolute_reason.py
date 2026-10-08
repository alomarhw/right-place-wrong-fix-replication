"""e1_absolute_reason.py — single-function detection WITH reasoning (fairness check for RQ2).

Same 150 vulnerable/fixed CVE pairs (300 functions) and the same instruct-style audit instruction as
the RQ2 detector, but the model may reason before answering (max 700 tokens) and ends with
'Answer: VULNERABLE' or 'Answer: SAFE'. Temperature 0, cached. Reports accuracy, positive rate,
pair-correctness (vulnerable flagged AND fix cleared), and the same split by provenance.
Writes results/e1_absolute_reason.json.
"""
import json
import re
from pathlib import Path

import numpy as np

from data_prep import build_corpus
from detectors import LLMClient, llm_map, _DETECT_SYSTEM

SYSTEM = _DETECT_SYSTEM.replace(
    "Answer with exactly one word: VULNERABLE or SAFE.",
    "Reason briefly about the function first. End with a final line of the form 'Answer: VULNERABLE' or "
    "'Answer: SAFE'.")


def verdict(text: str) -> int:
    m = re.findall(r"ANSWER:\s*\**\s*(VULNERABLE|SAFE)", text.upper())
    if m:
        return int(m[-1] == "VULNERABLE")
    return int("VULNERABLE" in text.upper()[-200:] and "NOT VULNERABLE" not in text.upper()[-200:])


def wilson(k, n, z=1.96):
    p = k / n; d = 1 + z * z / n; c = (p + z * z / (2 * n)) / d
    h = z * (p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5 / d
    return [p, max(0, c - h), min(1, c + h)]


def main():
    items, _ = build_corpus(n_cves=300, allow_synthetic=False, seed=42)
    client = LLMClient.get()
    preds = llm_map(lambda it: verdict(client.complete(
        SYSTEM, f"Function under review:\n```c\n{it.code}\n```", max_tokens=700)), items)
    y = np.array([it.label for it in items]); p = np.array(preds)
    by = {}
    for it, pr in zip(items, preds):
        by.setdefault(it.cve_id, {})[it.label] = (pr, it.provenance)
    pc = [(d[1][0] == 1 and d[0][0] == 0, d[1][1]) for d in by.values() if 1 in d and 0 in d]
    ok = np.array([x for x, _ in pc]); prov = np.array([q for _, q in pc])
    out = {"n_functions": len(items), "accuracy": float((p == y).mean()), "positive_rate": float(p.mean()),
           "pair_correct": wilson(int(ok.sum()), len(ok)),
           "by_provenance": {q: wilson(int(ok[prov == q].sum()), int((prov == q).sum())) for q in ("seen", "unseen")},
           "llm_usage": client.stats()}
    Path("results/e1_absolute_reason.json").write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
