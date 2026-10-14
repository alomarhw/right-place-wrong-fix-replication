"""e5_false_accept.py — how often does the oracle accept a patch it should reject?

The oracle (oracle.independent_oracle) accepts a patch when it removes and adds every statement the official fix
does; extra edits are allowed. Its false-accept risk is therefore the near-miss "complete official fix plus a
harmful extra edit". This collects every validated RQ1 patch (all five arms, all three repeats) whose statement
changes go beyond the official fix's, and has both LLM raters of E4 judge whether the extra edits are harmless or
break the function (blind, rubric below; uncertain counts as harmful, i.e. against the oracle). Validated patches
with no extra edits are the official fix's changes exactly and are counted as correct.

Writes results/e5_false_accept.json.
"""
import difflib
import json
import math
import re
from pathlib import Path

import patch_agent
from detectors import LLMClient, llm_map
from oracle import _delta
from patch_agent import LADDER
from rq3_data import build_rq3_corpus

REPEATS, SEED0 = 3, 42
RATERS = ("claude-opus-5-5", "claude-opus-4-8")
SYSTEM = (
    "You are a security engineer auditing patches for real CVEs in C/C++ code. You are given the CVE description, "
    "the official fix as a diff against the vulnerable function, and a candidate patch as a diff against the same "
    "function. The candidate already makes every change of the official fix, but it also makes extra edits. Judge "
    "only the EXTRA edits beyond the official fix:\n"
    "  harmless - they keep the function's behaviour on valid inputs and introduce no new defect (e.g. extra checks "
    "that only reject invalid input, comments, logging, equivalent rewrites)\n"
    "  harmful  - they change behaviour on valid inputs, reject legitimate use, break the function, or introduce a "
    "new defect\n"
    "If you are uncertain, answer harmful. Reply with one JSON object and nothing else: "
    '{"label": "harmless" | "harmful", "reason": "<one sentence>"}')


def wilson(k, n, z=1.96):
    if n == 0:
        return [float("nan")] * 3
    p = k / n; d = 1 + z * z / n; c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [p, max(0.0, c - h), min(1.0, c + h)]


def udiff(a, b):
    return "\n".join(difflib.unified_diff(a.splitlines(), b.splitlines(), "vulnerable", "patched", n=2, lineterm=""))


def parse(text):
    m = re.search(r"\{.*\}", text or "", re.S)
    try:
        d = json.loads(m.group(0)) if m else {}
    except ValueError:
        d = {}
    lab = str(d.get("label", "")).strip().lower()
    return lab if lab in ("harmless", "harmful") else "harmful"


def main():
    items, _ = build_rq3_corpus(n_cves=300, allow_synthetic=False, seed=42)
    validated, extra = [], []
    for r in range(REPEATS):
        lad = patch_agent.run_ladder(items, seed=SEED0 + r)
        for arm in LADDER:
            for i, (it, run) in enumerate(zip(items, lad[arm])):
                if not run.validated:
                    continue
                rem_o, add_o = _delta(it.vulnerable_code, it.official_fixed_code)
                rem_c, add_c = _delta(it.vulnerable_code, run.final_patch)
                has_extra = bool((rem_c - rem_o) or (add_c - add_o))
                rec = {"arm": arm, "repeat": r + 1, "item": i, "cve_id": it.cve_id, "extra_edits": has_extra}
                validated.append(rec)
                if has_extra:
                    extra.append({**rec, "desc": patch_agent._cve_text(it.cve_id)[:400],
                                  "official": udiff(it.vulnerable_code, it.official_fixed_code),
                                  "agent": udiff(it.vulnerable_code, run.final_patch)})
    client = LLMClient.get()

    def ask(args):
        it, model = args
        user = (f"CVE {it['cve_id']}: {it['desc']}\n\nOfficial fix:\n```diff\n{it['official']}\n```\n\n"
                f"Candidate patch:\n```diff\n{it['agent']}\n```")
        return parse(client.complete(SYSTEM, user, max_tokens=400, temperature=None, model=model))

    labels = {m: llm_map(ask, [(it, m) for it in extra]) for m in RATERS}
    n_val = len(validated)
    harmful_any = [i for i in range(len(extra)) if any(labels[m][i] == "harmful" for m in RATERS)]
    harmful_both = [i for i in range(len(extra)) if all(labels[m][i] == "harmful" for m in RATERS)]
    agree = sum(labels[RATERS[0]][i] == labels[RATERS[1]][i] for i in range(len(extra))) / max(1, len(extra))
    res = {"validated_patches": n_val, "with_extra_edits": len(extra),
           "harmful_by_either_rater": len(harmful_any), "harmful_by_both_raters": len(harmful_both),
           "false_accept_upper": wilson(len(harmful_any), n_val), "false_accept_both": wilson(len(harmful_both), n_val),
           "rater_agreement": agree,
           "by_arm": {a: {"validated": sum(v["arm"] == a for v in validated),
                          "with_extra": sum(e["arm"] == a for e in extra),
                          "harmful_either": sum(extra[i]["arm"] == a for i in harmful_any)} for a in LADDER},
           "items": [{k: e[k] for k in ("arm", "repeat", "item", "cve_id")} | {m: labels[m][k] for m in RATERS}
                     for k, e in enumerate(extra)],
           "llm_usage": client.stats()}
    Path("results/e5_false_accept.json").write_text(json.dumps(res, indent=1))
    print(json.dumps({k: v for k, v in res.items() if k not in ("items", "by_arm")}, indent=1))


if __name__ == "__main__":
    main()
