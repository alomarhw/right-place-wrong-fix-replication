"""e1_contrastive.py — contrastive detection: calibration vs. comprehension.

For each of the 150 vulnerable/fixed CVE pairs of the RQ2/RQ3 corpus, the model sees BOTH versions,
is told that exactly one contains a vulnerability that the other fixes, and must say which one is
vulnerable. Each pair is asked in both orders (temperature 0, cached); a pair is correct only if both
orders are answered correctly. Control: the "longer function is the fix" heuristic (fixes usually add
code). Writes results/e1_contrastive.json.
"""
import json
from pathlib import Path

import numpy as np

from data_prep import build_corpus
from detectors import LLMClient, llm_map

SYSTEM = ("You are a security auditor. You are shown two versions, A and B, of the same C function. Exactly one "
          "of them contains a security vulnerability that the other version fixes. Answer with exactly one "
          "letter: A if version A is the vulnerable one, B if version B is the vulnerable one.")


SYSTEM_REASON = ("You are a security auditor. You are shown two versions, A and B, of the same C function. Exactly "
                 "one of them contains a security vulnerability that the other version fixes. First compare the two "
                 "versions and reason briefly about which change removes a vulnerability. End with a final line "
                 "of the form 'Answer: A' or 'Answer: B', naming the vulnerable version.")


def prompt(a: str, b: str) -> str:
    return f"Version A:\n```c\n{a}\n```\n\nVersion B:\n```c\n{b}\n```\n\nWhich version is vulnerable?"


def answer(text: str) -> str:
    import re
    m = re.findall(r"ANSWER:\s*\**\s*([AB])", text.upper())
    if m:
        return m[-1]
    t = text.strip().upper()
    return t[:1] if t[:1] in "AB" else ("A" if "A" in t[:5] else "B")


def wilson(k, n, z=1.96):
    p = k / n; d = 1 + z * z / n; c = (p + z * z / (2 * n)) / d
    h = z * (p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5 / d
    return [p, max(0, c - h), min(1, c + h)]


def main():
    import sys
    reason = "--reason" in sys.argv
    items, _ = build_corpus(n_cves=300, allow_synthetic=False, seed=42)
    pairs = {}
    for it in items:
        pairs.setdefault(it.cve_id, {})[it.label] = it
    pairs = [(c, d[1], d[0]) for c, d in pairs.items() if 1 in d and 0 in d]
    client = LLMClient.get()
    jobs = [(i, order) for i in range(len(pairs)) for order in ("VF", "FV")]

    def run(job):
        i, order = job
        _, v, f = pairs[i]
        a, b = (v.code, f.code) if order == "VF" else (f.code, v.code)
        got = answer(client.complete(SYSTEM_REASON if reason else SYSTEM, prompt(a, b),
                                     max_tokens=700 if reason else 4))
        return i, order, got == ("A" if order == "VF" else "B")

    ok = {(i, o): c for i, o, c in llm_map(run, jobs)}
    both = np.array([ok[(i, "VF")] and ok[(i, "FV")] for i in range(len(pairs))])
    per_order = {o: float(np.mean([ok[(i, o)] for i in range(len(pairs))])) for o in ("VF", "FV")}
    longer_fix = np.array([len(f.code) > len(v.code) for _, v, f in pairs])  # heuristic: longer = fixed
    prov = np.array([v.provenance for _, v, _ in pairs])
    from scipy.stats import binomtest
    b10 = int((both & ~longer_fix).sum()); b01 = int((~both & longer_fix).sum())
    out = {
        "n_pairs": len(pairs),
        "pair_correct_contrastive": wilson(int(both.sum()), len(pairs)),
        "per_order_accuracy": per_order,
        "position_bias_A_rate": float(np.mean([ok[(i, "VF")] for i in range(len(pairs))]) -
                                      np.mean([ok[(i, "FV")] for i in range(len(pairs))])),
        "heuristic_longer_is_fix": wilson(int(longer_fix.sum()), len(pairs)),
        "mcnemar_vs_heuristic": {"llm_only": b10, "heuristic_only": b01,
                                 "p": float(binomtest(b10, b10 + b01, 0.5).pvalue) if b10 + b01 else 1.0},
        "by_provenance": {p: wilson(int(both[prov == p].sum()), int((prov == p).sum())) for p in ("seen", "unseen")},
        "llm_usage": client.stats(),
    }
    out["mode"] = "reason-then-answer (max 700 tokens)" if reason else "answer only"
    Path("results/e1_contrastive_reason.json" if reason else "results/e1_contrastive.json").write_text(json.dumps(out, indent=1))
    print(json.dumps({k: v for k, v in out.items()}, indent=1))


if __name__ == "__main__":
    main()
