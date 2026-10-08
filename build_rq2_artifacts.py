"""build_rq2_artifacts.py — producer for the RQ2 certified-variant benchmark.

RQ2-E1 constructs a NEW benchmark: certified slice-preserving variants of
verbatim CVE clones. That benchmark is a research artifact in its own right, so
this script PRODUCES it under artifacts/ with a manifest, independent of the
figures/metrics path. main.py / rq2_main.py may call build_benchmark() to ensure
the artifact exists before consumers read it.

Outputs:
  artifacts/SliceGuardVariantBench/variants.jsonl  — one record per (verbatim,
      certified-variant) pair with CWE label, transform mix, vsvector LSH
      similarity, edit distance, token Jaccard.
  artifacts/manifest.json — describes the artifact (producer, inputs, schema,
      counts, checksum, consuming RQs).

Deterministic given RP_RANDOM_SEED. In strict real-data mode the source corpus
must be real; synthetic is only used when approved upstream by data_prep.
"""
from __future__ import annotations

import os
import json
import hashlib
from pathlib import Path
from typing import Any

import numpy as np

RANDOM_SEED = int(os.environ.get("RP_RANDOM_SEED", 42))

ROOT = Path(__file__).resolve().parent
ARTIFACT_DIR = ROOT / "artifacts" / "SliceGuardVariantBench"
MANIFEST = ROOT / "artifacts" / "manifest.json"


def _sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_benchmark(
    n_items: int = 30,
    strict_real_data: bool = True,
    seed: int = RANDOM_SEED,
) -> dict[str, Any]:
    """Build and persist the certified-variant benchmark; return manifest entry."""
    import random

    random.seed(seed)
    np.random.seed(seed)
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

    from data_prep import load_corpus
    from variant_builder import build_certified_variant

    corpus, provenance = load_corpus(
        n_items=n_items, strict_real_data=strict_real_data, seed=seed
    )

    records: list[dict[str, Any]] = []
    for rec in corpus:
        cv_code = rec["code"]
        cwe = rec.get("cwe", "UNKNOWN")
        cve_id = rec.get("cve_id", rec.get("id", "NA"))
        try:
            variant = build_certified_variant(rec, seed=seed)
        except Exception as exc:
            # A single hard function should not break the whole benchmark; record
            # it as a rejection with reason rather than silently skipping.
            records.append({
                "cve_id": cve_id,
                "cwe": cwe,
                "accepted": False,
                "reject_reason": f"transform_error:{exc}",
            })
            continue
        records.append({
            "cve_id": cve_id,
            "cwe": cwe,
            "verbatim_code": cv_code,
            "variant_code": variant.get("variant_code", ""),
            "accepted": bool(variant.get("accepted", False)),
            "lsh_similarity": float(variant.get("lsh_similarity", 0.0)),
            "edit_distance_norm": float(variant.get("edit_distance_norm", 0.0)),
            "token_jaccard": float(variant.get("token_jaccard", 0.0)),
            "transform_mix": variant.get("transform_mix", []),
            "reject_reason": variant.get("reject_reason", ""),
        })

    out_jsonl = ARTIFACT_DIR / "variants.jsonl"
    with out_jsonl.open("w") as fh:
        for r in records:
            fh.write(json.dumps(r, default=_json_default) + "\n")

    accepted = sum(1 for r in records if r.get("accepted"))
    entry = {
        "name": "SliceGuardVariantBench",
        "version": "1.0",
        "producer": "build_rq2_artifacts.py",
        "sourceInputs": ["VulSlicer + VUDDY (SRC VUL corpora) via data_prep.load_corpus"],
        "schema": [
            "cve_id", "cwe", "verbatim_code", "variant_code", "accepted",
            "lsh_similarity", "edit_distance_norm", "token_jaccard",
            "transform_mix", "reject_reason",
        ],
        "recordCount": len(records),
        "acceptedCount": int(accepted),
        "path": str(out_jsonl.relative_to(ROOT)),
        "checksum": _sha256_of_file(out_jsonl),
        "license": "Derived from VulSlicer/VUDDY (Zenodo 6059924); research use.",
        "usedSynthetic": bool(provenance.get("usedSynthetic", False)),
        "consumedBy": ["RQ2-E1", "RQ2-E2"],
        "note": "Certified slice-preserving CVE-clone variants (benchmark artifact).",
    }
    _update_manifest(entry)
    print(f"[build_rq2_artifacts] wrote {out_jsonl} "
          f"({len(records)} records, {accepted} accepted)")
    return entry


def _update_manifest(entry: dict[str, Any]) -> None:
    manifest: dict[str, Any] = {"artifacts": []}
    if MANIFEST.exists():
        try:
            manifest = json.loads(MANIFEST.read_text())
            manifest.setdefault("artifacts", [])
        except Exception:
            manifest = {"artifacts": []}
    manifest["artifacts"] = [
        a for a in manifest["artifacts"] if a.get("name") != entry["name"]
    ]
    manifest["artifacts"].append(entry)
    MANIFEST.write_text(json.dumps(manifest, indent=2, default=_json_default))


def _json_default(o: Any) -> Any:
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    return str(o)


if __name__ == "__main__":
    strict = os.environ.get("STRICT_REAL_DATA_MODE", "1") not in ("0", "false", "False")
    build_benchmark(n_items=30, strict_real_data=strict)