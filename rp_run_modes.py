"""rp_run_modes.py — run-mode resolution, scale contract, and metadata/provenance.

Centralizes the smoke / pilot / paper-grade (full) scale decisions for RQ1-ALT1 so
main.py (generated separately) and analysis.py agree on sizes, repeats, and the
real-vs-synthetic data policy.

Study-scale contract (from the Engineer execution contract):
  smoke : maxRows=30,  maxRepeats=1  (NOT evidence)
  pilot : minRows=100, minRepeats=2
  paper : minRows=300, minRepeats=3  (default full path in STRICT_REAL_DATA_MODE)

STRICT_REAL_DATA_MODE: the default (full) path must NOT silently fall back to
synthetic data. Only the explicit --smoke path is allowed to use the deterministic
synthetic paired-function generator (annotated fallback), and it is labelled as
such in results/run_metadata.json and results/data_provenance.json.

Public helpers:
  - resolve_scale(mode) -> dict(mode, n_cves, repeats, paper_grade, allow_synthetic, run_tier)
  - write_run_metadata(scale, datasets, data_source, results_dir="results")
  - write_data_provenance(datasets_info, used_synthetic, results_dir="results")
  - merge_manifest_lineage(datasets_info, data_root="data")

Key deps: stdlib only (json, hashlib, pathlib, os).
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List

RANDOM_SEED = int(os.environ.get("RP_RANDOM_SEED", 42))

# --- study-scale contract constants ------------------------------------------------
SMOKE_MAX_ROWS = 30
SMOKE_MAX_REPEATS = 1
PILOT_MIN_ROWS = 100
PILOT_MIN_REPEATS = 2
PAPER_MIN_ROWS = 300
PAPER_MIN_REPEATS = 3


def resolve_scale(mode: str,
                  n_cves: int | None = None,
                  repeats: int | None = None) -> Dict[str, Any]:
    """Return a concrete scale config for the requested mode.

    mode is one of {"smoke", "pilot", "full", "paper_grade"}. 'full' == 'paper_grade'.
    Explicit n_cves / repeats overrides are honored but clamped to the mode's tier
    so a --smoke run can never silently become paper-grade.
    """
    mode = (mode or "full").lower()
    if mode in {"full", "paper", "paper_grade", "papergrade"}:
        base_rows, base_reps, paper_grade, tier, allow_syn = (
            PAPER_MIN_ROWS, PAPER_MIN_REPEATS, True, "paper_grade", False
        )
        mode = "paper_grade"
    elif mode == "pilot":
        base_rows, base_reps, paper_grade, tier, allow_syn = (
            PILOT_MIN_ROWS, PILOT_MIN_REPEATS, False, "pilot", False
        )
    elif mode == "smoke":
        base_rows, base_reps, paper_grade, tier, allow_syn = (
            SMOKE_MAX_ROWS, SMOKE_MAX_REPEATS, False, "smoke", True
        )
    else:
        # unknown -> default to full/paper-grade per strict runtime policy
        base_rows, base_reps, paper_grade, tier, allow_syn = (
            PAPER_MIN_ROWS, PAPER_MIN_REPEATS, True, "paper_grade", False
        )
        mode = "paper_grade"

    final_rows = int(n_cves) if n_cves else base_rows
    final_reps = int(repeats) if repeats else base_reps

    # clamp smoke so an override cannot inflate it past the smoke ceiling
    if mode == "smoke":
        final_rows = min(final_rows, SMOKE_MAX_ROWS)
        final_reps = min(final_reps, SMOKE_MAX_REPEATS)

    return {
        "mode": mode,
        "n_cves": max(1, final_rows),
        "repeats": max(1, final_reps),
        "paper_grade": bool(paper_grade and final_rows >= PAPER_MIN_ROWS
                            and final_reps >= PAPER_MIN_REPEATS),
        "allow_synthetic": bool(allow_syn),
        "run_tier": tier,
    }


def _sha256_file(path: Path, limit_bytes: int = 64 * 1024 * 1024) -> str:
    try:
        h = hashlib.sha256()
        read = 0
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
                read += len(chunk)
                if read >= limit_bytes:
                    break
        return h.hexdigest()
    except Exception:  # noqa: BLE001
        return ""


def merge_manifest_lineage(datasets_info: List[dict], data_root: str = "data") -> List[dict]:
    """Copy version/license/citation/checksum/recordCount/columns from fetch_manifest.

    Matches manifest 'ok' entries to datasets_info records by name substring.
    """
    mpath = Path(data_root) / "fetch_manifest.json"
    if not mpath.exists():
        return datasets_info
    try:
        manifest = json.loads(mpath.read_text())
    except Exception:  # noqa: BLE001
        return manifest_fallback(datasets_info)
    ok = manifest.get("ok", []) or []
    for rec in datasets_info:
        rname = (rec.get("name") or "").lower()
        for entry in ok:
            cname = ((entry.get("contract", {}) or {}).get("datasetName") or "").lower()
            if not cname:
                continue
            if cname in rname or rname in cname or rname.split()[0] in cname:
                rec.setdefault("version", entry.get("version", ""))
                rec.setdefault("license", entry.get("license", ""))
                rec.setdefault("citation", entry.get("citation", ""))
                rec.setdefault("checksum", entry.get("checksum", ""))
                rec.setdefault("recordCount", entry.get("recordCount"))
                if entry.get("columns"):
                    rec.setdefault("schema", entry.get("columns"))
                break
    return datasets_info


def manifest_fallback(datasets_info: List[dict]) -> List[dict]:
    return datasets_info


def write_run_metadata(scale: Dict[str, Any],
                       datasets: List[str],
                       data_source: str,
                       results_dir: str = "results",
                       extra: Dict[str, Any] | None = None) -> Path:
    """Write results/run_metadata.json describing the active mode and scale."""
    rd = Path(results_dir)
    rd.mkdir(parents=True, exist_ok=True)
    meta = {
        "mode": scale["mode"],
        "run_tier": scale["run_tier"],
        "rows_or_items": int(scale["n_cves"]),
        "repeats": int(scale["repeats"]),
        "datasets": list(datasets),
        "data_source": data_source,            # "real" or "synthetic"
        "paper_grade": bool(scale["paper_grade"] and data_source == "real"),
        "random_seed": RANDOM_SEED,
        "strict_real_data_mode": scale["mode"] != "smoke",
        "experiment_id": "RQ1-ALT1",
        "rq": "RQ1",
    }
    if extra:
        meta.update(extra)
    out = rd / "run_metadata.json"
    out.write_text(json.dumps(meta, indent=2))
    tier_note = "PAPER-GRADE run mode" if meta["paper_grade"] else f"{scale['mode'].upper()} run mode"
    print(f"[run_modes] {tier_note}: rows={meta['rows_or_items']}, "
          f"repeats={meta['repeats']}, data_source={data_source}, "
          f"paper_grade={meta['paper_grade']}")
    print(f"[run_modes] wrote {out}")
    return out


def build_dataset_record(name: str, path: str | Path | None, source: str,
                         rows: int | None = None, generated: bool = False) -> dict:
    """Construct a single data_provenance datasets[] record with checksum if real."""
    rec: dict = {
        "name": name,
        "source": source,            # "real" or "synthetic"
        "path": str(path) if path else "",
        "rows": int(rows) if rows is not None else None,
        "version": "",
        "license": "",
        "citation": "salimi2022vulslicer; SRC VUL foundation (\\cite{57b456a85303a715d9311a88cd3de662b631778c})",
        "checksum": "",
        "recordCount": int(rows) if rows is not None else None,
        "schema": [],
    }
    if generated:
        rec["generated"] = True
    if source == "real" and path:
        p = Path(path)
        if p.is_file():
            rec["checksum"] = _sha256_file(p)
    return rec


def write_data_provenance(datasets_info: List[dict],
                          used_synthetic: bool,
                          results_dir: str = "results",
                          data_root: str = "data") -> Path:
    """Write results/data_provenance.json, preserving any auto-mined flag.

    datasets_info: list of records from build_dataset_record / merge_manifest_lineage.
    """
    rd = Path(results_dir)
    rd.mkdir(parents=True, exist_ok=True)

    datasets_info = merge_manifest_lineage(list(datasets_info), data_root=data_root)

    provenance: Dict[str, Any] = {
        "usedSynthetic": bool(used_synthetic),
        "datasets": datasets_info,
    }

    # preserve usedMinedData flag written by any auto-mining recipe
    existing = Path(data_root) / "data_provenance.json"
    if existing.exists():
        try:
            prev = json.loads(existing.read_text())
            if prev.get("usedMinedData"):
                provenance["usedMinedData"] = True
        except Exception:  # noqa: BLE001
            pass

    out = rd / "data_provenance.json"
    out.write_text(json.dumps(provenance, indent=2))
    print(f"[run_modes] wrote {out} (usedSynthetic={used_synthetic})")
    return out


if __name__ == "__main__":
    for m in ["smoke", "pilot", "full"]:
        print(m, "->", resolve_scale(m))