"""e4_sample.py — manual check of the official-fix oracle's rejections on RQ1 (how loose is the VPR lower bound?).

Draws a fixed random sample (seed 7) of 50 repeat-1 patches of one arm (argv[1], default slice_grounded_full) that touch
the official fix's lines but are rejected by the oracle ("right place, wrong fix"), and writes, for each,
the CVE, CWE, CVE description, the official fix's diff and the agent's diff to
results/e4_sample.md for manual labelling. Labels go in results/e4_labels.json:
  equivalent  same fix as the official one, written differently
  plausible   blocks the same flaw by a different, sound route (guard elsewhere, stricter check)
  incorrect   does not remove the flaw, or breaks valid-input behaviour
Served from the LLM response cache (no API calls).
"""
import difflib
import json
import random
import sys
from pathlib import Path

import patch_agent
from paper_tables import _changed_lines
from rq3_data import build_rq3_corpus

N, SEED = 50, 7
ARM = sys.argv[1] if len(sys.argv) > 1 else "slice_grounded_full"
SUFFIX = "" if ARM == "slice_grounded_full" else f"_{ARM}"


def udiff(a, b):
    return "\n".join(difflib.unified_diff(a.splitlines(), b.splitlines(), "vulnerable", "patched", n=2, lineterm=""))


def main():
    items, _ = build_rq3_corpus(n_cves=300, allow_synthetic=False, seed=42)
    lad = patch_agent.run_ladder(items, seed=42)
    pool = []
    for i, (it, run) in enumerate(zip(items, lad[ARM])):
        off = _changed_lines(it.vulnerable_code, it.official_fixed_code)
        touch = run.reason != "unchanged" and bool(off & _changed_lines(it.vulnerable_code, run.final_patch))
        if touch and not run.validated:
            pool.append((i, it, run))
    sample = random.Random(SEED).sample(pool, min(N, len(pool)))
    sample.sort(key=lambda x: x[0])
    out = [f"# E4 sample: {len(sample)} of {len(pool)} touch-but-rejected {ARM} patches (repeat 1)\n"]
    for k, (i, it, run) in enumerate(sample, 1):
        out.append(f"## {k}. {it.cve_id} ({it.cwe}) item={i}\n")
        out.append(f"CVE: {patch_agent._cve_text(it.cve_id)[:400]}\n")
        out.append("### Official fix\n```diff\n" + udiff(it.vulnerable_code, it.official_fixed_code) + "\n```\n")
        out.append("### Agent patch\n```diff\n" + udiff(it.vulnerable_code, run.final_patch) + "\n```\n")
    Path(f"results/e4_sample{SUFFIX}.md").write_text("\n".join(out))
    Path(f"results/e4_sample_ids{SUFFIX}.json").write_text(json.dumps(
        {"pool": len(pool), "items": [{"k": k, "item": i, "cve_id": it.cve_id} for k, (i, it, _) in enumerate(sample, 1)]}, indent=1))
    print(f"pool={len(pool)} sampled={len(sample)}")


if __name__ == "__main__":
    main()
