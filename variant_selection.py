"""variant_selection.py — do functions that fail certification differ from those that pass?

Rebuilds the RQ3 certified-variant pass deterministically (same corpus, same seeds as variant_builder.
build_certified_variants; no model calls) and compares certified with uncertified functions by length (lines),
label (vulnerable vs. fixed), provenance (seen vs. unseen), and CWE. Mann-Whitney U for length, Fisher's exact
test for the binary splits, chi-square for the top CWEs.

Writes results/variant_selection.json.
"""
import json
from collections import Counter
from pathlib import Path

from scipy.stats import chi2_contingency, fisher_exact, mannwhitneyu

from data_prep import build_corpus
from variant_builder import RANDOM_SEED, build_variant


def main():
    items, _ = build_corpus(n_cves=300, allow_synthetic=False, seed=RANDOM_SEED)
    cert = [bool(build_variant(it, seed=RANDOM_SEED + i).certified) for i, it in enumerate(items)]
    lines = [it.code.count("\n") + 1 for it in items]
    ok = [l for l, c in zip(lines, cert) if c]
    bad = [l for l, c in zip(lines, cert) if not c]

    def fisher(attr, val):
        t = [[sum(1 for it, c in zip(items, cert) if c and getattr(it, attr) == val),
              sum(1 for it, c in zip(items, cert) if c and getattr(it, attr) != val)],
             [sum(1 for it, c in zip(items, cert) if not c and getattr(it, attr) == val),
              sum(1 for it, c in zip(items, cert) if not c and getattr(it, attr) != val)]]
        return {"table": t, "p": float(fisher_exact(t)[1]),
                "rate_certified_if_true": t[0][0] / max(1, t[0][0] + t[1][0]),
                "rate_certified_if_false": t[0][1] / max(1, t[0][1] + t[1][1])}

    top = [c for c, _ in Counter(it.cwe for it in items).most_common(5)]
    tab = [[sum(1 for it, c in zip(items, cert) if it.cwe == w and c) for w in top],
           [sum(1 for it, c in zip(items, cert) if it.cwe == w and not c) for w in top]]
    med = lambda xs: sorted(xs)[len(xs) // 2] if xs else None  # noqa: E731
    res = {"n": len(items), "certified": sum(cert), "yield": sum(cert) / len(items),
           "lines_median": {"certified": med(ok), "uncertified": med(bad)},
           "lines_mannwhitney_p": float(mannwhitneyu(ok, bad).pvalue),
           "label_vulnerable": fisher("label", 1), "provenance_unseen": fisher("provenance", "unseen"),
           "top_cwes": top, "cwe_table": tab, "cwe_chi2_p": float(chi2_contingency(tab)[1])}
    Path("results/variant_selection.json").write_text(json.dumps(res, indent=1))
    print(json.dumps({k: v for k, v in res.items() if k not in ("cwe_table",)}, indent=1))


if __name__ == "__main__":
    main()
