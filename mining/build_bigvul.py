"""Seeded sample of real Big-Vul C vulnerable/fixed function pairs (one per CVE) for project 7Ac77.
Source: Hugging Face bstee615/bigvul (Big-Vul, Fan et al., MSR 2020). Selection rules:
vul == 1, lang == C, at least one statement changed (comments/whitespace ignored), balanced braces
on both sides, 5-120 lines, CWE present, first function per CVE;
candidates collected in stream order until 3000, then a seed-42 random sample of N."""
import json, random, re, sys
from collections import Counter
from datasets import load_dataset


def _stmts(code):
    code = re.sub(r"/\*.*?\*/", " ", code, flags=re.S)
    out = []
    for ln in code.splitlines():
        s = re.sub(r"\s+", "", re.sub(r"//.*", "", ln))
        if s and s not in {"{", "}", "};"}:
            out.append(s)
    return out


def _balanced(code):
    d = 0
    for ch in code:
        d += (ch == "{") - (ch == "}")
        if d < 0:
            return False
    return d == 0 and "{" in code
N, CAP = int(sys.argv[1]), 3000
ds = load_dataset("bstee615/bigvul", split="train", streaming=True)
seen, cands, scanned = set(), [], 0
for r in ds:
    scanned += 1
    if str(r.get("vul")) != "1" or (r.get("lang") or "").upper() != "C":
        continue
    b, a, cve, cwe = r.get("func_before") or "", r.get("func_after") or "", r.get("CVE ID") or "", (r.get("CWE ID") or "").strip()
    if not cve or cve in seen or b.strip() == a.strip() or not cwe.startswith("CWE-"):
        continue
    if not (5 <= b.count("\n") + 1 <= 120):
        continue
    if Counter(_stmts(b)) == Counter(_stmts(a)) or not (_balanced(b) and _balanced(a)):
        continue  # no real statement change, or truncated function
    seen.add(cve)
    cands.append({"cve_id": cve, "cwe": cwe, "project": r.get("project"), "commit_id": r.get("commit_id"),
                  "func_before": b, "func_after": a, "provenance": "pre_cutoff",
                  "source": "Big-Vul (bstee615/bigvul)", "cve_year": int(cve.split("-")[1])})
    if len(cands) >= CAP:
        break
rng = random.Random(42)
sample = rng.sample(cands, min(N, len(cands)))
with open("bigvul/bigvul_pairs.jsonl", "w") as f:
    for s in sorted(sample, key=lambda x: x["cve_id"]):
        f.write(json.dumps(s) + "\n")
years = sorted(s["cve_year"] for s in sample)
print(f"scanned {scanned} rows; {len(cands)} candidates; wrote {len(sample)} pairs; CVE years {years[0]}-{years[-1]}")
