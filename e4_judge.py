"""e4_judge.py — blind second rater for the E4 manual oracle check.

Labels every patch in results/e4_sample.md (A4) and results/e4_sample_no_grounding_no_feedback.md (A0)
with an LLM judge (default claude-opus-4-8, default sampling; the model rejects a temperature setting) that sees only the CVE description, the
official fix's diff and the agent's diff — never the first rater's labels. Same rubric as the first
rater; uncertain cases count as incorrect. Responses are cached (detectors.LLMClient). Then computes
Cohen's kappa against results/e4_labels_*.json and writes results/e4_judge.json.
"""
import json
import os
import re
import sys
from pathlib import Path

from detectors import LLMClient, llm_map

JUDGE = os.environ.get("RP_E4_JUDGE", "claude-opus-4-8")
LABELS = ["equivalent", "plausible", "over_restrictive", "incorrect"]
SYSTEM = (
    "You are a security engineer auditing patches for real CVEs in C/C++ code. You are given the CVE "
    "description, the official fix as a diff against the vulnerable function, and a candidate patch as a "
    "diff against the same function. The candidate touches lines the official fix touches but was "
    "rejected by a strict oracle that requires every statement change of the official fix. Classify the "
    "candidate with exactly one label:\n"
    "  equivalent       - the same fix as the official one, written differently (e.g. reordered "
    "conditions, a renamed local, an equivalent library call)\n"
    "  plausible        - a different but sound fix: it removes the vulnerability and keeps "
    "valid-input behaviour\n"
    "  over_restrictive - removes the vulnerability but rejects or breaks legitimate use\n"
    "  incorrect        - does not remove the vulnerability, only partly removes it, breaks the "
    "function, or introduces a new defect\n"
    "Judge only from the code shown. If you are uncertain whether it removes the vulnerability, answer "
    "incorrect. Reply with one JSON object and nothing else: "
    '{"label": "<label>", "reason": "<one sentence>"}')


def sections(md: str) -> list[dict]:
    out = []
    for block in re.split(r"\n(?=## \d+\. )", md)[1:]:
        k = int(re.match(r"## (\d+)\.", block).group(1))
        cve = re.search(r"## \d+\. (\S+)", block).group(1)
        desc = re.search(r"\nCVE: (.*?)\n", block, re.S)
        off = re.search(r"### Official fix\n```diff\n(.*?)\n```", block, re.S).group(1)
        agent = re.search(r"### Agent patch\n```diff\n(.*?)\n```", block, re.S).group(1)
        out.append({"k": k, "cve_id": cve, "desc": desc.group(1).strip() if desc else "", "official": off, "agent": agent})
    return out


def parse(text: str) -> dict:
    m = re.search(r"\{.*\}", text, re.S)
    try:
        d = json.loads(m.group(0)) if m else {}
    except ValueError:
        d = {}
    lab = str(d.get("label", "")).strip().lower().replace("-", "_").replace(" ", "_")
    return {"label": lab if lab in LABELS else "incorrect", "reason": d.get("reason", ""), "raw_ok": lab in LABELS}


def kappa(a: list[str], b: list[str], cats: list[str]) -> float:
    n = len(a)
    po = sum(x == y for x, y in zip(a, b)) / n
    pe = sum((a.count(c) / n) * (b.count(c) / n) for c in cats)
    return (po - pe) / (1 - pe) if pe < 1 else 1.0


def main():
    client = LLMClient.get()
    res = {"judge": JUDGE, "arms": {}}
    pooled_a, pooled_b = [], []
    for arm, md, lab in (("slice_grounded_full", "results/e4_sample.md", "results/e4_labels_full.json"),
                         ("no_grounding_no_feedback", "results/e4_sample_no_grounding_no_feedback.md",
                          "results/e4_labels_no_grounding_no_feedback.json")):
        items = sections(Path(md).read_text())
        first = {x["k"]: x["label"] for x in json.load(open(lab))["labels"]}

        def ask(it):
            user = (f"CVE {it['cve_id']}: {it['desc']}\n\nOfficial fix:\n```diff\n{it['official']}\n```\n\n"
                    f"Candidate patch:\n```diff\n{it['agent']}\n```")
            out = parse(client.complete(SYSTEM, user, max_tokens=300, temperature=None, model=JUDGE))
            if not out["raw_ok"]:  # the judge reasoned past the budget before answering: one longer retry
                out = parse(client.complete(SYSTEM, user, max_tokens=1500, temperature=None, model=JUDGE))
            return out

        judged = llm_map(ask, items)
        a = [first[it["k"]] for it in items]
        b = [j["label"] for j in judged]
        pooled_a += a; pooled_b += b
        coarse = lambda xs: ["acceptable" if x in ("equivalent", "plausible") else "not" for x in xs]  # noqa: E731
        res["arms"][arm] = {
            "n": len(items), "judge_counts": {c: b.count(c) for c in LABELS},
            "rater1_counts": {c: a.count(c) for c in LABELS},
            "agreement": sum(x == y for x, y in zip(a, b)) / len(a),
            "kappa_4class": kappa(a, b, LABELS),
            "kappa_acceptable_vs_not": kappa(coarse(a), coarse(b), ["acceptable", "not"]),
            "unparsed": sum(not j["raw_ok"] for j in judged),
            "items": [{"k": it["k"], "cve_id": it["cve_id"], "rater1": x, "judge": j["label"], "reason": j["reason"]}
                      for it, x, j in zip(items, a, judged)]}
    coarse = lambda xs: ["acceptable" if x in ("equivalent", "plausible") else "not" for x in xs]  # noqa: E731
    eq = lambda xs: ["eq" if x == "equivalent" else "not" for x in xs]  # noqa: E731
    res["pooled"] = {"n": len(pooled_a), "agreement": sum(x == y for x, y in zip(pooled_a, pooled_b)) / len(pooled_a),
                     "kappa_4class": kappa(pooled_a, pooled_b, LABELS),
                     "kappa_equivalent_vs_not": kappa(eq(pooled_a), eq(pooled_b), ["eq", "not"]),
                     "kappa_acceptable_vs_not": kappa(coarse(pooled_a), coarse(pooled_b), ["acceptable", "not"])}
    res["llm_usage"] = {**client.stats(), "model": JUDGE}
    Path("results/e4_judge.json").write_text(json.dumps(res, indent=1))
    print(json.dumps({k: v for k, v in res.items() if k != "arms"}, indent=1))
    for arm, r in res["arms"].items():
        print(arm, {k: v for k, v in r.items() if k != "items"})


if __name__ == "__main__":
    sys.exit(main())
