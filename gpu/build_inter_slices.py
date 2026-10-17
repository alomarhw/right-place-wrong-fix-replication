"""Precompute interprocedural srcSlice slices for the RQ1 items from their source archives.

For every item fetched by fetch_archives.py: srcML (--position) the archive, run srcSlice once, slice the vulnerable
function (srcslice_inter.slice_function) and store the rendered slice, the unsliced callees (A3c control) and
statistics in data/srcslice_inter.json, keyed by the SHA-256 of the vulnerable function text.

Usage: RP_ARCHIVE_DIR=... python gpu/build_inter_slices.py
"""

import hashlib
import json
import os
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import srcslice_inter as si  # noqa: E402

ARCH = Path(os.environ.get("RP_ARCHIVE_DIR", ROOT / "data" / "archives"))


def one(args):
    rec, code = args
    out = {"commit_id": rec["commit_id"], "cve_id": rec.get("cve_id")}
    if not rec.get("ok"):
        return out | {"ok": False, "reason": "source not fetched: " + rec.get("error", "")[:120]}
    try:
        # Archives are stored under the hash in the code link; some Big-Vul commit_id values carry URL
        # suffixes (?w=1, #diff-...) or differ from the link, so look the directory up both ways.
        import re
        hashes = re.findall(r"[0-9a-f]{40}", rec.get("codeLink", ""))
        d = next((ARCH / h for h in reversed(hashes) if (ARCH / h).is_dir()), ARCH / rec["commit_id"])
        arch = si.build(d)
        sl = si.slice_function(arch, rec["file"], rec["function"])
        if not sl.get("ok"):
            return out | {"ok": False, "reason": sl.get("reason")}
        return out | {"ok": True, "slice": si.render(sl), "callees_unsliced": si.render_callees_unsliced(arch, sl),
                      "local_text": sl["local_text"], "seeds": sl["seeds"], "n_local": len(sl["local_lines"]),
                      "function_lines": sl["function"]["end"] - sl["function"]["start"] + 1,
                      "callees": [{"file": c["file"], "function": c["function"], "n_lines": len(c["lines"])}
                                  for c in sl["callees"]],
                      "archive_files": len(rec["files"])}
    except Exception as e:  # noqa: BLE001
        return out | {"ok": False, "reason": f"{type(e).__name__}: {e}"[:200]}


def main() -> int:
    manifest = json.loads((ROOT / "data" / "archives_manifest.json").read_text())
    pairs = {json.loads(l)["commit_id"]: json.loads(l) for l in open(ROOT / "data" / "bigvul" / "bigvul_pairs.jsonl")}
    jobs = [(r, pairs[r["commit_id"]]["func_before"]) for r in manifest]
    with ProcessPoolExecutor(int(os.environ.get("RP_WORKERS", 6))) as ex:
        res = list(ex.map(one, jobs))
    table = {}
    for (rec, code), r in zip(jobs, res):
        table[hashlib.sha256(code.strip().encode()).hexdigest()] = r
    (ROOT / "data" / "srcslice_inter.json").write_text(json.dumps(table, indent=1))
    ok = [r for r in res if r["ok"]]
    inter = [r for r in ok if r["callees"]]
    print(f"slices: {len(ok)}/{len(res)} ok; with resolved callees: {len(inter)}; "
          f"median local lines {sorted(r['n_local'] for r in ok)[len(ok)//2] if ok else 0}")
    for r in res:
        if not r["ok"]:
            print("  no slice:", r["commit_id"][:10], r["reason"][:120])
    return 0


if __name__ == "__main__":
    sys.exit(main())
