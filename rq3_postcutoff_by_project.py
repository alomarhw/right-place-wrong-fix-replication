"""rq3_postcutoff_by_project.py — the post-cutoff RQ3 replication split by project (OpenSSL vs. the rest).

44 of the 56 post-cutoff CVEs come from OpenSSL. This replays the same ladder runs as rq3_postcutoff.py (from the
frozen cache; no API calls) and reports, per arm and per project group, the localization (touch) rate and the
validated-patch rate with Wilson 95% CIs, plus the within-group change in touch from the ungrounded arm.

Writes results/rq3_postcutoff_by_project.json.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from patch_agent import LADDER
from rq3_postcutoff import RES, ladder_stats, load_postcutoff, wilson


def main() -> None:
    rows = [json.loads(l) for l in Path("data/postcutoff/postcutoff_pairs.jsonl").read_text().splitlines()]
    items = load_postcutoff()
    assert [r["cve_id"] for r in rows] == [it.cve_id for it in items]
    groups = {"openssl": [i for i, r in enumerate(rows) if r["project"] == "openssl"],
              "other": [i for i, r in enumerate(rows) if r["project"] != "openssl"]}
    s = ladder_stats(items)
    out = {"n": {g: len(ix) for g, ix in groups.items()},
           "other_projects": sorted({r["project"] for r in rows if r["project"] != "openssl"}), "arms": {}}
    for c in LADDER:
        out["arms"][c] = {}
        for g, ix in groups.items():
            t, v = s["touch"][c][ix], s["validated"][c][ix]
            out["arms"][c][g] = {"touch": wilson(int(t.sum()), t.size), "vpr": wilson(int(v.sum()), v.size),
                                 "touch_gain_vs_ungrounded_pts":
                                     100 * (t.mean() - s["touch"][LADDER[0]][ix].mean())}
        print(c, {g: f"touch {out['arms'][c][g]['touch'][0]:.2f} vpr {out['arms'][c][g]['vpr'][0]:.3f}"
                  for g in groups})
    (RES / "rq3_postcutoff_by_project.json").write_text(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
