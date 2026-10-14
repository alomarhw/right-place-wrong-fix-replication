"""e4_allrepeats.py — the E4 oracle-strictness check extended to all three repeats, plus a human-audit sheet.

E4 (e4_sample.py, e4_judge.py) labelled repeat-1 "right place, wrong fix" patches (they touch a line the official fix
changes but the oracle rejects them). Here the pool is those patches from ALL THREE repeats of arms A0
(no_grounding_no_feedback) and A4 (slice_grounded_full). From each arm we draw a fixed sample (seed 11) stratified by
repeat, label it with both LLM raters under the E4 rubric (the same system prompt as e4_judge.py), and estimate per
arm and pooled over repeats the share of rejected-but-touching patches that are equivalent to the official fix (and
equivalent or plausible), with Wilson CIs, inter-rater agreement (Cohen's kappa), and the validated-patch rate
adjusted for equivalent fixes. A 30-patch subset (15 per arm, 5 per repeat) is written as a blind sheet for human
adjudication (no rater labels shown).

Writes results/e4_allrepeats.json, results/e4_human_audit.md and results/e4_human_audit_labels.csv.
"""
import csv
import difflib
import json
import math
import random
from pathlib import Path

import patch_agent
from detectors import LLMClient, llm_map
from e4_judge import LABELS, SYSTEM, kappa, parse
from paper_tables import _changed_lines
from rq3_data import build_rq3_corpus

ARMS = ("no_grounding_no_feedback", "slice_grounded_full")
REPEATS, SEED0 = 3, 42
PER_REPEAT, HUMAN_PER_REPEAT, SAMPLE_SEED = 20, 5, 11
RATERS = ("claude-opus-5-5", "claude-opus-4-8")


def wilson(k, n, z=1.96):
    if n == 0:
        return [float("nan")] * 3
    p = k / n; d = 1 + z * z / n; c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [p, max(0.0, c - h), min(1.0, c + h)]


def udiff(a, b):
    return "\n".join(difflib.unified_diff(a.splitlines(), b.splitlines(), "vulnerable", "patched", n=2, lineterm=""))


def main():
    items, _ = build_rq3_corpus(n_cves=300, allow_synthetic=False, seed=42)
    rng = random.Random(SAMPLE_SEED)
    pools, sample, totals = {a: {} for a in ARMS}, [], {a: {} for a in ARMS}
    for r in range(REPEATS):
        lad = patch_agent.run_ladder(items, seed=SEED0 + r)
        for arm in ARMS:
            pool, val = [], 0
            for i, (it, run) in enumerate(zip(items, lad[arm])):
                val += int(run.validated)
                off = _changed_lines(it.vulnerable_code, it.official_fixed_code)
                if run.reason != "unchanged" and off & _changed_lines(it.vulnerable_code, run.final_patch) and not run.validated:
                    pool.append({"arm": arm, "repeat": r + 1, "item": i, "cve_id": it.cve_id,
                                 "desc": patch_agent._cve_text(it.cve_id)[:400],
                                 "official": udiff(it.vulnerable_code, it.official_fixed_code),
                                 "agent": udiff(it.vulnerable_code, run.final_patch)})
            pools[arm][r + 1] = len(pool)
            totals[arm][r + 1] = {"n": len(items), "validated": val}
            sample += rng.sample(pool, min(PER_REPEAT, len(pool)))

    client = LLMClient.get()

    def ask(args):
        it, model = args
        user = (f"CVE {it['cve_id']}: {it['desc']}\n\nOfficial fix:\n```diff\n{it['official']}\n```\n\n"
                f"Candidate patch:\n```diff\n{it['agent']}\n```")
        out = parse(client.complete(SYSTEM, user, max_tokens=300, temperature=None, model=model))
        if not out["raw_ok"]:
            out = parse(client.complete(SYSTEM, user, max_tokens=1500, temperature=None, model=model))
        return out

    labels = {m: llm_map(ask, [(it, m) for it in sample]) for m in RATERS}
    for k, it in enumerate(sample):
        it["labels"] = {m: labels[m][k]["label"] for m in RATERS}

    res = {"raters": RATERS, "sample_seed": SAMPLE_SEED, "pool_sizes": pools, "arms": {}}
    coarse = lambda xs: ["acceptable" if x in ("equivalent", "plausible") else "not" for x in xs]  # noqa: E731
    for arm in ARMS:
        s = [it for it in sample if it["arm"] == arm]
        n_total = sum(t["n"] for t in totals[arm].values())
        vpr = sum(t["validated"] for t in totals[arm].values()) / n_total
        pool_share = sum(pools[arm].values()) / n_total  # share of all patches that touch but are rejected
        out = {"n": len(s), "oracle_vpr": vpr, "touch_rejected_share": pool_share, "by_rater": {}}
        for m in RATERS:
            labs = [it["labels"][m] for it in s]
            eq, ep = labs.count("equivalent"), sum(x in ("equivalent", "plausible") for x in labs)
            per_rep = {r: wilson(sum(1 for it in s if it["repeat"] == r and it["labels"][m] == "equivalent"),
                                 sum(1 for it in s if it["repeat"] == r)) for r in range(1, REPEATS + 1)}
            out["by_rater"][m] = {"counts": {c: labs.count(c) for c in LABELS},
                                  "share_equivalent": wilson(eq, len(s)),
                                  "share_equiv_or_plausible": wilson(ep, len(s)),
                                  "share_equivalent_by_repeat": per_rep,
                                  "vpr_with_equivalent": vpr + pool_share * eq / len(s),
                                  "vpr_with_equiv_or_plausible": vpr + pool_share * ep / len(s)}
        a, b = [it["labels"][RATERS[0]] for it in s], [it["labels"][RATERS[1]] for it in s]
        out["agreement"] = sum(x == y for x, y in zip(a, b)) / len(a)
        out["kappa_4class"] = kappa(a, b, LABELS)
        out["kappa_acceptable_vs_not"] = kappa(coarse(a), coarse(b), ["acceptable", "not"])
        res["arms"][arm] = out
    res["llm_usage"] = client.stats()
    res["items"] = [{k: it[k] for k in ("arm", "repeat", "item", "cve_id", "labels")} for it in sample]
    Path("results/e4_allrepeats.json").write_text(json.dumps(res, indent=1))

    # Blind human-audit subset: 15 per arm, 5 per repeat; rater labels are NOT shown.
    human = []
    for arm in ARMS:
        for r in range(1, REPEATS + 1):
            cand = [it for it in sample if it["arm"] == arm and it["repeat"] == r]
            human += random.Random(SAMPLE_SEED + r).sample(cand, min(HUMAN_PER_REPEAT, len(cand)))
    random.Random(SAMPLE_SEED).shuffle(human)
    md = ["# Human audit of rejected-but-touching patches (blind)\n",
          "For each case, read the CVE, the official fix and the candidate patch, and label the candidate in "
          "results/e4_human_audit_labels.csv with exactly one of: equivalent (same fix, written differently), "
          "plausible (different but sound fix that keeps valid-input behaviour), over_restrictive (removes the flaw "
          "but breaks legitimate use), incorrect (does not or only partly removes the flaw, or breaks the function). "
          "If unsure whether it removes the vulnerability, choose incorrect. The arm and repeat are hidden.\n"]
    for k, it in enumerate(human, 1):
        it["case"] = f"H{k:02d}"
        md.append(f"## {it['case']}. {it['cve_id']}\n\nCVE: {it['desc']}\n")
        md.append("### Official fix\n```diff\n" + it["official"] + "\n```\n")
        md.append("### Candidate patch\n```diff\n" + it["agent"] + "\n```\n")
    Path("results/e4_human_audit.md").write_text("\n".join(md))
    with open("results/e4_human_audit_labels.csv", "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(["case", "cve_id", "label", "note"])
        for it in human:
            w.writerow([it["case"], it["cve_id"], "", ""])
    Path("results/e4_human_audit_key.json").write_text(json.dumps(
        [{"case": it["case"], "arm": it["arm"], "repeat": it["repeat"], "item": it["item"], "labels": it["labels"]}
         for it in human], indent=1))
    for arm, out in res["arms"].items():
        print(arm, "n", out["n"], "| kappa", round(out["kappa_4class"], 2), "| acceptable kappa",
              round(out["kappa_acceptable_vs_not"], 2), "|", {m: (round(v["share_equivalent"][0], 3),
              round(v["vpr_with_equivalent"], 3)) for m, v in out["by_rater"].items()})
    print("usage", res["llm_usage"])


if __name__ == "__main__":
    main()
