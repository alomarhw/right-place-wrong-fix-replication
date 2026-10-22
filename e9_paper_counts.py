"""e9_paper_counts.py -- four counts the paper states that no other script writes. No LLM calls.

  1. near_fix_location: share of patches per information arm (Big-Vul, three repeats) whose edited lines
     lie at or within two lines of a line the official fix changes ("edits at or within two lines of the
     marked place"), next to the strict touch rate, which must equal e6_info_ladder.json's.
  2. p3_failures_rep1: the P3 (port + srcVul) patches of repeat 1 that the oracle rejects, split into those
     that omit part of the SOURCE fix and those that make every change of the source fix (faithful ports
     rejected because the target's own backport differs from the source fix).
  3. unrelated_fix_cves: Big-Vul CVEs that the oracle-strictness inspection (e4_labels_full.json) marks as
     carrying a fix unrelated to the CVE.
  4. postcutoff_cve_commits: commits after 2025-08-01 whose message names a CVE, in the 12 projects of
     mining/mine_postcutoff.py, up to the mining date. Needs the miner's blobless clones (pass --clones
     DIR); without it the value recorded from the 2026-10-21 recount is kept.
Writes results/e9_paper_counts.json.
Usage: python e9_paper_counts.py [--clones DIR]
"""

import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

from oracle import _delta
from paper_tables import _changed_lines
from porting_pilot import load_targets
from rq3_data import build_rq3_corpus

ROOT = Path(__file__).resolve().parent
RES = ROOT / "results"
MINING_UNTIL = "2026-10-08"  # the post-cutoff pairs entered the package on 2026-10-08; newest commit 2026-09-29
RECOUNT_2026_10_21 = 143      # the count is the same for every --until date from 2026-09-29 to 2026-10-08


def near_fix_location() -> dict:
    items, _ = build_rq3_corpus(n_cves=300, allow_synthetic=False, seed=42)
    patches = json.loads((RES / "e6_info_ladder_patches.json").read_text())["bigvul"]
    pub = json.loads((RES / "e6_info_ladder.json").read_text())["bigvul"]["per_item"]
    out = {}
    for arm in ("A2", "L", "M", "LM"):
        n = touch = near = 0
        for r, reps in enumerate(patches[arm]):
            for i, (it, p) in enumerate(zip(items, reps)):
                fix = _changed_lines(it.vulnerable_code, it.official_fixed_code)
                edited = _changed_lines(it.vulnerable_code, p)
                if pub[arm]["outcome"][r][i] == "unchanged_or_malformed" and not pub[arm]["touch"][r][i]:
                    edited = set()  # e6 counts no edited lines for an unchanged candidate
                hit = bool(fix & edited)
                assert hit == bool(pub[arm]["touch"][r][i]), (arm, r, i)
                n += 1
                touch += hit
                near += any(abs(a - b) <= 2 for a in edited for b in fix)
        out[arm] = {"patches": n, "touch_pct": round(100 * touch / n, 1), "within_two_lines_pct": round(100 * near / n, 1)}
    return out


def p3_failures_rep1() -> dict:
    rows = {(r["cve_id"], r["function"], r["target"]["branch"]): r for r in load_targets()}
    per = json.loads((RES / "porting_pilot.json").read_text())["per_target"]
    omit, faithful = [], []
    for t in per:
        if t["validated"]["P3"][0]:
            continue
        row = rows[(t["cve_id"], t["function"], t["target_branch"])]
        src, tgt, cand = row["source"], row["target"], t["rep1_candidate"]["P3"]
        rem_s, add_s = _delta(src["func_before"], src["func_after"])
        rem_c, add_c = _delta(tgt["func_before"], cand)
        (faithful if not (rem_s - rem_c) and not (add_s - add_c) else omit).append(
            {"cve_id": t["cve_id"], "target_branch": t["target_branch"], "clone_type": t["clone_type"]})
    return {"rejected": len(omit) + len(faithful), "omit_part_of_source_fix": len(omit),
            "faithful_to_source_fix": len(faithful), "faithful": faithful, "omit": omit}


def unrelated_fix_cves() -> dict:
    labels = json.loads((RES / "e4_labels_full.json").read_text())["labels"]
    cves = sorted({x["cve_id"] for x in labels if "unrelated" in str(x.get("note", "")).lower()})
    return {"n": len(cves), "cve_ids": cves, "source": "e4_labels_full.json notes"}


def postcutoff_cve_commits(clones: Path | None) -> dict:
    if clones is None:
        return {"n": RECOUNT_2026_10_21, "until": MINING_UNTIL, "source": "recount of 2026-10-21 (pass --clones to redo)"}
    per = {}
    for repo in sorted(p for p in clones.iterdir() if p.is_dir()):
        out = subprocess.run(["git", "-C", str(repo), "log", "--since=2025-08-01", f"--until={MINING_UNTIL}", "-E", "-i",
                              "--grep=CVE-20[0-9]{2}-[0-9]+", "--format=%H"], capture_output=True, text=True, check=True)
        per[repo.name] = len(out.stdout.split())
    return {"n": sum(per.values()), "until": MINING_UNTIL, "per_repo": per, "repos": len(per)}


def main() -> int:
    clones = Path(sys.argv[sys.argv.index("--clones") + 1]) if "--clones" in sys.argv else None
    res = {"near_fix_location": near_fix_location(), "p3_failures_rep1": p3_failures_rep1(),
           "unrelated_fix_cves": unrelated_fix_cves(), "postcutoff_cve_commits": postcutoff_cve_commits(clones)}
    (RES / "e9_paper_counts.json").write_text(json.dumps(res, indent=1))
    p3 = res["p3_failures_rep1"]
    print("L within two lines:", res["near_fix_location"]["L"]["within_two_lines_pct"], "% | P3 rep-1 failures:",
          p3["rejected"], f"({p3['omit_part_of_source_fix']} omit, {p3['faithful_to_source_fix']} faithful)",
          "| unrelated-fix CVEs:", res["unrelated_fix_cves"]["n"], "| post-cutoff CVE commits:", res["postcutoff_cve_commits"]["n"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
