"""e8_cve_text_cues.py -- what does the CVE description carry: the place, or the remedy?

For every RQ1 CVE (150 Big-Vul, 56 post-cutoff) the description is scored for two cues, computed from text
and code only (no model calls):
  location cue  the description names an identifier that occurs on a line the official fix changes
                (function, variable, field, macro or API name; tokens of >= 4 characters that are not
                English words common in advisories), or the vulnerable function's own name;
  remedy cue    the description states what the code fails to do or what the fix must do (a phrase such as
                "missing/lack of ... check", "does not validate", "fails to", "improper(ly)", "insufficient",
                "unchecked", "should/must", "off-by-one"), as opposed to describing only the consequence
                ("allows remote attackers to cause a denial of service via ...").
Then, within arms A2 (CVE text) and A4 (full agent), replayed from the frozen cache, it reports per cue the
touch rate and VPR of CVEs with and without the cue (CVE-level Mann-Whitney U on per-CVE counts over the
three repeats), per set, and the cue prevalence pre- vs post-cutoff (Fisher). Association, not causation.
Writes results/e8_cve_cues.json. Usage: python e8_cve_text_cues.py
"""

import json
import re
import sys
from pathlib import Path

import numpy as np
from scipy.stats import fisher_exact, mannwhitneyu

import patch_agent
from detectors import LLMClient
from paper_tables import _changed_lines
from rq3_data import build_rq3_corpus
from rq3_postcutoff import load_postcutoff

ROOT = Path(__file__).resolve().parent
ARMS = {"A2": "cve_text_rag", "A4": "slice_grounded_full"}
REPEATS, SEED0 = 3, 42
REMEDY = re.compile(
    r"\b(missing|lack(s|ing)? of|lacks|without (a |any |proper(ly)? )?(check|valid|verif|bound|sanit|limit)|"
    r"does not (properly |correctly |always )?(check|validat|verif|ensure|handle|sanitiz|limit|bound|free|release|"
    r"initializ|restrict|reject|account|consider|enforce|clear|reset|lock|prevent|confirm|compare|detect|test)|"
    r"doesn'?t (check|validat|verif|ensure|handle)|fail(s|ed|ing)? to|improper(ly)?|insufficient(ly)?|"
    r"incorrect(ly)? (check|validat|verif|handl|comput|calculat|bound|limit|compar|account)|"
    r"unchecked|unvalidated|unverified|unbounded|unsanitized|uninitiali[sz]ed|not (properly |correctly )?"
    r"(checked|validated|verified|bounded|sanitized|initialized|handled|released|freed)|should (be |have )?|must (be )?|"
    r"off[- ]by[- ]one|wrong (check|comparison|bound|length|size|sign|type|order)|"
    r"mishandl|miscalculat|miscomput|forget(s)? to|neglect(s)? to|omit(s|ted)? )", re.I)
STOP = set("""the and for with from that this which when then than into onto over under about after before while
allows allow allowed attacker attackers remote local users user cause causes caused denial service crash
arbitrary code execution information disclosure leak leaks obtain sensitive memory consumption corruption
heap stack buffer overflow overread read write access vector vectors crafted malformed invalid large long
file files function functions kernel linux before through version versions related issue vulnerability
vulnerabilities impact might could would possible possibly other unspecified unknown certain some many
bytes byte data value values pointer null dereference integer signed unsigned negative zero application
applications module modules library libraries server client request requests response packet packets
message messages header headers field fields input inputs output process processing handling handle
handler handlers parsing parser parse parsed string strings format option options parameter parameters
argument arguments array arrays index length size count number numbers offset bound bounds check checks
checking validation validate verify condition conditions error errors failure return returns returned
during because there their these those where which while within without also been being does doing
makes make made used using uses use via can may will not non into due each only such same""".split())


def identifiers(code: str) -> set[str]:
    return {t for t in re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", code)}


def cues(item, desc: str) -> dict:
    vl = item.vulnerable_code.splitlines()
    fix_idx = _changed_lines(item.vulnerable_code, item.official_fixed_code)
    before = {_norm(l) for l in vl}
    fix_text = "\n".join(vl[i] for i in sorted(fix_idx) if i < len(vl)) + "\n" + "\n".join(
        l for l in item.official_fixed_code.splitlines() if _norm(l) not in before)
    code_ids = {t.lower() for t in identifiers(fix_text)}
    desc_ids = {t.lower() for t in identifiers(desc)} - STOP
    fname = patch_agent._func_name(item.vulnerable_code)
    hits = sorted(desc_ids & code_ids)
    names_function = bool(fname) and fname.lower() in {t.lower() for t in identifiers(desc)}
    m = REMEDY.search(desc or "")
    return {"location": bool(hits) or names_function, "location_hits": hits[:8], "names_function": names_function,
            "remedy": bool(m), "remedy_phrase": m.group(0) if m else "", "words": len((desc or "").split())}


def _norm(s: str) -> str:
    return re.sub(r"\s+", "", s)


def replay(items) -> dict:
    out = {k: {"validated": np.zeros((REPEATS, len(items)), int), "touch": np.zeros((REPEATS, len(items)), int)}
           for k in ARMS}
    fix = [_changed_lines(it.vulnerable_code, it.official_fixed_code) for it in items]
    for r in range(REPEATS):
        lad = patch_agent.run_ladder(items, seed=SEED0 + r, conditions=list(ARMS.values()))
        for k, cond in ARMS.items():
            for i, (it, run) in enumerate(zip(items, lad[cond])):
                out[k]["validated"][r, i] = int(run.validated)
                out[k]["touch"][r, i] = int(run.reason != "unchanged" and
                                            bool(fix[i] & _changed_lines(it.vulnerable_code, run.final_patch)))
    return out


def assoc(counts: np.ndarray, flag: np.ndarray) -> dict:
    a, b = counts[:, flag].sum(axis=0), counts[:, ~flag].sum(axis=0)
    res = {"with_cue": {"n": int(flag.sum()), "rate": round(100 * float(a.mean()) / REPEATS, 1) if flag.sum() else None},
           "without_cue": {"n": int((~flag).sum()), "rate": round(100 * float(b.mean()) / REPEATS, 1) if (~flag).sum() else None}}
    if flag.sum() and (~flag).sum():
        res["p_mannwhitney"] = float(mannwhitneyu(a, b, alternative="two-sided").pvalue)
    return res


def main() -> int:
    sets = {"bigvul": build_rq3_corpus(n_cves=300, allow_synthetic=False, seed=42)[0], "postcutoff": load_postcutoff()}
    out = {"cue_definitions": __doc__.split("Then,")[0].strip()}
    prevalence = {}
    for name, items in sets.items():
        c = [cues(it, patch_agent._cve_text(it.cve_id)) for it in items]
        rp = replay(items)
        loc = np.array([x["location"] for x in c]); rem = np.array([x["remedy"] for x in c])
        prevalence[name] = {"n": len(items), "location": int(loc.sum()), "remedy": int(rem.sum()),
                            "both": int((loc & rem).sum()), "neither": int((~loc & ~rem).sum()),
                            "median_words": int(np.median([x["words"] for x in c]))}
        res = {"prevalence": prevalence[name], "association": {}, "per_cve": []}
        for k in ARMS:
            res["association"][k] = {
                "touch_by_location_cue": assoc(rp[k]["touch"], loc), "vpr_by_location_cue": assoc(rp[k]["validated"], loc),
                "touch_by_remedy_cue": assoc(rp[k]["touch"], rem), "vpr_by_remedy_cue": assoc(rp[k]["validated"], rem)}
        for it, x in zip(items, c):
            res["per_cve"].append({"cve_id": it.cve_id, **x})
        out[name] = res
    # prevalence pre vs post (Fisher)
    b, p = prevalence["bigvul"], prevalence["postcutoff"]
    out["pre_vs_post"] = {
        cue: {"pre": round(100 * b[cue] / b["n"], 1), "post": round(100 * p[cue] / p["n"], 1),
              "fisher_p": float(fisher_exact([[b[cue], b["n"] - b[cue]], [p[cue], p["n"] - p[cue]]])[1])}
        for cue in ("location", "remedy")}
    out["llm_usage"] = LLMClient.get().stats()
    (ROOT / "results" / "e8_cve_cues.json").write_text(json.dumps(out, indent=1))
    for name in sets:
        print(f"[e8] {name}: prevalence {out[name]['prevalence']}")
        for k in ARMS:
            print(f"   {k}: " + json.dumps(out[name]["association"][k]))
    print("[e8] pre vs post:", out["pre_vs_post"])
    print("[e8] usage:", out["llm_usage"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
