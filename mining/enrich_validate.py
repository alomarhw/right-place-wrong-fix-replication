"""Validate and enrich both 7Ac77 datasets from the official CVE records (cveawg.mitre.org).

For every pair: fetch the CVE record; add `description` (CNA English description) and
`affected_products`. Post-cutoff pairs are kept only if (a) the changed function is not in a test
file, and (b) the CVE record's affected vendor/product or description names the mined project.
Big-Vul pairs are kept if the CVE record exists (they were curated by Big-Vul). Writes
final/bigvul/bigvul_pairs.jsonl, final/postcutoff/postcutoff_pairs.jsonl and final/VALIDATION.json.
"""
import json, time, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ALIASES = {"php-src": ["php"], "cpython": ["python", "cpython"], "FFmpeg": ["ffmpeg"],
           "openssl": ["openssl"], "libexpat": ["expat", "libexpat"], "curl": ["curl", "libcurl"]}


def record(cve):
    for _ in range(4):
        try:
            with urllib.request.urlopen(f"https://cveawg.mitre.org/api/cve/{cve}", timeout=30) as r:
                d = json.load(r)
            cna = d.get("containers", {}).get("cna", {})
            desc = next((x.get("value", "") for x in cna.get("descriptions", []) if x.get("lang", "").startswith("en")), "")
            prods = [f"{a.get('vendor', '')} {a.get('product', '')}".strip() for a in cna.get("affected", []) or []]
            return {"description": desc, "affected_products": prods}
        except Exception:
            time.sleep(2)
    return None


def main():
    report = {}
    for name in ["bigvul", "postcutoff"]:
        src = HERE / name / f"{name}_pairs.jsonl"
        rows = [json.loads(l) for l in open(src)]
        kept, dropped = [], []
        for r in rows:
            if name == "postcutoff" and (r.get("file", "").startswith("test/") or r.get("function") == "setup_tests"):
                dropped.append((r["cve_id"], "test file")); continue
            rec = record(r["cve_id"])
            if not rec:
                dropped.append((r["cve_id"], "no CVE record")); continue
            r.update(rec)
            if name == "postcutoff":
                hay = (" ".join(rec["affected_products"]) + " " + rec["description"]).lower()
                if not any(a in hay for a in ALIASES.get(r["project"], [r["project"].lower()])):
                    dropped.append((r["cve_id"], "CVE record does not name project")); continue
            kept.append(r)
            time.sleep(0.15)
        out = HERE / "final" / name
        out.mkdir(parents=True, exist_ok=True)
        with open(out / f"{name}_pairs.jsonl", "w") as f:
            for r in kept:
                f.write(json.dumps(r) + "\n")
        report[name] = {"input": len(rows), "kept": len(kept), "dropped": dropped}
        print(name, {"input": len(rows), "kept": len(kept), "dropped": len(dropped)}, flush=True)
    (HERE / "final" / "VALIDATION.json").write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
