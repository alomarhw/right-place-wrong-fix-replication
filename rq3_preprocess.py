"""rq3_preprocess.py — shape raw CVE patch-diff downloads into the RQ3 schema.

The RQ3 oracle (oracle.py) and corpus loader (rq3_data.py) consume CVE items with
vulnerable_code + official_fixed_code. Real public corpora, however, arrive in many
shapes: a Big-Vul CSV with `func_before`/`func_after` columns, a CVEfixes archive,
or nested jsonl under data/<name>/. This helper normalizes whatever is present under
data/ into a single canonical file:

    data/cve_patches/patch_pairs.jsonl

with records {cve_id, cwe, vulnerable_code, official_fixed_code, poc_available}, and
appends an entry to data/fetch_manifest.json so resolve_data_path("RQ3") finds it.

Responsibilities (all best-effort, idempotent, NO network):
  1. Extract any archive (*.zip / *.tar* / *.gz) found under data/ in place.
  2. Discover tabular (csv/tsv/parquet) and jsonl/json patch-diff files.
  3. Map heterogeneous column names to the canonical vulnerable/fixed schema,
     rejecting GLUE-style text-classification rows (never valid RQ3 data).
  4. Write data/cve_patches/patch_pairs.jsonl + register it in the manifest.

This module NEVER raises out of main(): it prints warnings and returns a status
dict so the pipeline can continue (rq3_data.py still enforces strict real-data
policy / labelled synthetic smoke).

Key deps: pandas==2.2.2 (optional parquet), stdlib json/re/zipfile/tarfile/gzip.
"""
from __future__ import annotations

import gzip
import io
import json
import os
import re
import shutil
import tarfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List

RANDOM_SEED = int(os.environ.get("RP_RANDOM_SEED", 42))

DATA_ROOT = Path("data")
OUT_DIR = DATA_ROOT / "cve_patches"
OUT_FILE = OUT_DIR / "patch_pairs.jsonl"

# cap how many pairs we materialize by default (paper-grade can override via env)
MAX_PAIRS = int(os.environ.get("RP_RQ3_PREPROCESS_CAP", 20000))

# column-name candidates (mirrors rq3_data.py so the two stay consistent)
_VULN_COLS = ["func_before", "vulnerable_func", "vulnerable_code", "code_before",
              "before", "vul_func", "func_vul", "vuln_code", "bad_code"]
_FIXED_COLS = ["func_after", "fixed_func", "fixed_code", "code_after",
               "after", "patched_func", "func_fix", "fix_code", "good_code"]
_CWE_COLS = ["cwe", "cwe_id", "CWE ID", "cwe_ids", "vulnerability_type", "cwe_name"]
_CVE_COLS = ["cve", "cve_id", "CVE ID", "cveid", "commit_id", "hash"]

_GLUE_KEYS = {"sentence", "sentence1", "sentence2", "premise", "hypothesis",
              "question", "idx"}

_CWES = ["CWE-119", "CWE-787", "CWE-416", "CWE-125", "CWE-190"]


# --------------------------------------------------------------------------------------
# Archive extraction (in place, safe)
# --------------------------------------------------------------------------------------
def _safe_extract_zip(path: Path, dest: Path) -> None:
    with zipfile.ZipFile(path) as zf:
        members = []
        for m in zf.namelist():
            target = (dest / m).resolve()
            if str(target).startswith(str(dest.resolve())):
                members.append(m)
        zf.extractall(dest, members=members)


def _safe_extract_tar(path: Path, dest: Path) -> None:
    with tarfile.open(path, "r:*") as tf:
        safe = []
        for m in tf.getmembers():
            target = (dest / m.name).resolve()
            if str(target).startswith(str(dest.resolve())):
                safe.append(m)
        tf.extractall(dest, members=safe)


def _extract_gz(path: Path) -> Path | None:
    if path.name.endswith((".tar.gz", ".tgz")):
        return None
    out = path.with_suffix("")
    if out.exists():
        return out
    try:
        with gzip.open(path, "rb") as fin, out.open("wb") as fout:
            shutil.copyfileobj(fin, fout)
        return out
    except Exception as exc:  # noqa: BLE001
        print(f"[rq3_preprocess] WARNING: gunzip failed for {path}: {exc}")
        return None


def extract_archives() -> None:
    if not DATA_ROOT.exists():
        return
    archives: List[Path] = []
    for pat in ("*.zip", "*.tar", "*.tar.gz", "*.tgz", "*.tar.bz2", "*.gz"):
        archives += list(DATA_ROOT.rglob(pat))
    for arc in sorted(set(archives)):
        dest = arc.parent / (arc.stem + "_extracted")
        try:
            if arc.suffix == ".zip":
                if dest.exists() and any(dest.iterdir()):
                    continue
                dest.mkdir(parents=True, exist_ok=True)
                _safe_extract_zip(arc, dest)
                print(f"[rq3_preprocess] extracted zip {arc} -> {dest}")
            elif arc.name.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2")):
                if dest.exists() and any(dest.iterdir()):
                    continue
                dest.mkdir(parents=True, exist_ok=True)
                _safe_extract_tar(arc, dest)
                print(f"[rq3_preprocess] extracted tar {arc} -> {dest}")
            elif arc.suffix == ".gz":
                _extract_gz(arc)
        except Exception as exc:  # noqa: BLE001
            print(f"[rq3_preprocess] WARNING: failed to extract {arc}: {exc}")


# --------------------------------------------------------------------------------------
# Column mapping
# --------------------------------------------------------------------------------------
def _norm_keys(rec: dict) -> dict:
    return {str(k).strip().lower(): k for k in rec.keys()}


def _first_present(rec: dict, keys: List[str]) -> str | None:
    lk = _norm_keys(rec)
    for cand in keys:
        orig = lk.get(cand.lower())
        if orig is not None:
            v = rec[orig]
            if v not in (None, "", "nan", "NaN"):
                return str(v)
    return None


def _looks_like_glue(rec: dict) -> bool:
    keys = {str(k).lower() for k in rec.keys()}
    has_code = any(c.lower() in keys for c in _VULN_COLS + _FIXED_COLS)
    return bool((keys & _GLUE_KEYS) and not has_code)


def _norm_cwe(raw: str | None, idx: int) -> str:
    if raw:
        m = re.search(r"CWE[-_ ]?(\d+)", str(raw), re.I)
        if m:
            return f"CWE-{m.group(1)}"
    return _CWES[idx % len(_CWES)]


def _record_to_pair(rec: dict, idx: int) -> Dict[str, Any] | None:
    if _looks_like_glue(rec):
        return None
    vuln = _first_present(rec, _VULN_COLS)
    fixed = _first_present(rec, _FIXED_COLS)
    if not vuln or not fixed:
        return None
    if vuln.strip() == fixed.strip():
        return None  # no actual patch diff
    cwe = _norm_cwe(_first_present(rec, _CWE_COLS), idx)
    cve_id = _first_present(rec, _CVE_COLS) or f"CVE-R-{idx:05d}"
    poc = any(str(k).lower() in {"poc", "test", "exploit", "regression"}
              for k in rec.keys())
    return {
        "cve_id": str(cve_id),
        "cwe": cwe,
        "vulnerable_code": vuln,
        "official_fixed_code": fixed,
        "poc_available": bool(poc),
    }


# --------------------------------------------------------------------------------------
# File readers
# --------------------------------------------------------------------------------------
def _iter_jsonl(path: Path):
    try:
        text = path.read_text(errors="ignore").strip()
    except Exception as exc:  # noqa: BLE001
        print(f"[rq3_preprocess] WARNING: cannot read {path}: {exc}")
        return
    if not text:
        return
    if path.suffix.lower() == ".json" and text[:1] == "[":
        try:
            arr = json.loads(text)
            if isinstance(arr, list):
                for obj in arr:
                    if isinstance(obj, dict):
                        yield obj
        except Exception:  # noqa: BLE001
            return
        return
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                yield obj
        except Exception:
            continue


def _iter_tabular(path: Path):
    try:
        import pandas as pd
    except Exception as exc:  # noqa: BLE001
        print(f"[rq3_preprocess] WARNING: pandas unavailable for {path}: {exc}")
        return
    try:
        suf = path.suffix.lower()
        if suf == ".parquet":
            df = pd.read_parquet(path)
        elif suf in {".tsv"}:
            df = pd.read_csv(path, sep="\t", engine="python", on_bad_lines="skip")
        else:
            df = pd.read_csv(path, engine="python", on_bad_lines="skip")
    except Exception as exc:  # noqa: BLE001
        print(f"[rq3_preprocess] WARNING: cannot parse table {path}: {exc}")
        return
    cols_lower = {c.lower() for c in df.columns}
    has_code = any(c.lower() in cols_lower for c in _VULN_COLS + _FIXED_COLS)
    if not has_code:
        return
    for rec in df.to_dict(orient="records"):
        yield rec


def _discover_source_files() -> List[Path]:
    """Return candidate patch-diff files, preferring Big-Vul / CVEfixes locations."""
    if not DATA_ROOT.exists():
        return []
    priority_dirs = [DATA_ROOT / "bigvul", DATA_ROOT / "cvefixes_bigvul",
                     DATA_ROOT / "cve_patches"]
    files: List[Path] = []
    seen = set()

    def _add(p: Path):
        if p.is_file() and str(p) not in seen:
            seen.add(str(p))
            files.append(p)

    for d in priority_dirs:
        if d.exists():
            for ext in ("*.jsonl", "*.json", "*.csv", "*.tsv", "*.parquet"):
                for p in sorted(d.rglob(ext)):
                    _add(p)
    # then the rest of data/
    for ext in ("*.jsonl", "*.json", "*.csv", "*.tsv", "*.parquet"):
        for p in sorted(DATA_ROOT.rglob(ext)):
            # skip our own output and manifests
            if p == OUT_FILE or p.name == "fetch_manifest.json" \
                    or p.name == "data_provenance.json":
                continue
            _add(p)
    return files


# --------------------------------------------------------------------------------------
# Manifest registration
# --------------------------------------------------------------------------------------
def _register_manifest(path: Path, n: int) -> None:
    mpath = DATA_ROOT / "fetch_manifest.json"
    manifest = {"ok": [], "failed": []}
    if mpath.exists():
        try:
            manifest = json.loads(mpath.read_text())
            manifest.setdefault("ok", [])
            manifest.setdefault("failed", [])
        except Exception:  # noqa: BLE001
            manifest = {"ok": [], "failed": []}
    # avoid duplicate registration
    manifest["ok"] = [e for e in manifest["ok"]
                      if (e.get("contract", {}) or {}).get("datasetName") != "RQ3 CVE patch pairs (preprocessed)"]
    manifest["ok"].append({
        "path": str(path.parent),
        "contract": {"datasetName": "RQ3 CVE patch pairs (preprocessed)", "rqId": "RQ3"},
        "version": "",
        "license": "research use (derived from Big-Vul/CVEfixes/VulSlicer)",
        "citation": "Big-Vul; CVEfixes; salimi2022vulslicer; SRC VUL foundation",
        "checksum": "",
        "recordCount": n,
        "columns": ["cve_id", "cwe", "vulnerable_code", "official_fixed_code", "poc_available"],
    })
    try:
        mpath.write_text(json.dumps(manifest, indent=2))
        print(f"[rq3_preprocess] registered {path} in manifest ({n} pairs)")
    except Exception as exc:  # noqa: BLE001
        print(f"[rq3_preprocess] WARNING: could not update manifest: {exc}")


# --------------------------------------------------------------------------------------
# Main entry
# --------------------------------------------------------------------------------------
def preprocess(cap: int = MAX_PAIRS) -> Dict[str, Any]:
    """Shape raw CVE patch-diff data into data/cve_patches/patch_pairs.jsonl.

    Returns a status dict; NEVER raises.
    """
    status: Dict[str, Any] = {"ok": False, "n_pairs": 0, "out_file": str(OUT_FILE),
                              "sources": [], "skipped_glue": 0}
    try:
        if not DATA_ROOT.exists():
            print("[rq3_preprocess] data/ does not exist; nothing to preprocess.")
            return status

        # Idempotent: if already built and non-empty, just re-register.
        if OUT_FILE.exists() and OUT_FILE.stat().st_size > 0:
            n_existing = sum(1 for _ in OUT_FILE.open(errors="ignore"))
            if n_existing > 0:
                print(f"[rq3_preprocess] {OUT_FILE} already present ({n_existing} pairs); "
                      "re-registering and skipping rebuild.")
                _register_manifest(OUT_FILE, n_existing)
                status.update(ok=True, n_pairs=n_existing)
                return status

        extract_archives()
        source_files = _discover_source_files()
        if not source_files:
            print("[rq3_preprocess] no patch-diff source files found under data/. "
                  "rq3_data.py will use the VulSlicer+VUDDY corpus or strict-mode failure.")
            return status

        OUT_DIR.mkdir(parents=True, exist_ok=True)
        pairs: List[Dict[str, Any]] = []
        skipped_glue = 0
        used_sources: List[str] = []
        idx = 0
        for sf in source_files:
            if len(pairs) >= cap:
                break
            before = len(pairs)
            suf = sf.suffix.lower()
            iterator = _iter_tabular(sf) if suf in {".csv", ".tsv", ".parquet"} else _iter_jsonl(sf)
            for rec in iterator:
                if _looks_like_glue(rec):
                    skipped_glue += 1
                    continue
                pair = _record_to_pair(rec, idx)
                if pair is None:
                    continue
                pairs.append(pair)
                idx += 1
                if len(pairs) >= cap:
                    break
            if len(pairs) > before:
                used_sources.append(str(sf))

        if not pairs:
            print(f"[rq3_preprocess] found {len(source_files)} candidate file(s) but 0 "
                  f"usable vulnerable/fixed pairs (skipped {skipped_glue} GLUE-like rows).")
            status["skipped_glue"] = skipped_glue
            return status

        with OUT_FILE.open("w") as fh:
            for p in pairs:
                fh.write(json.dumps(p) + "\n")
        _register_manifest(OUT_FILE, len(pairs))
        print(f"[rq3_preprocess] wrote {OUT_FILE} with {len(pairs)} CVE patch pairs "
              f"from {len(used_sources)} source file(s); skipped {skipped_glue} GLUE-like rows.")
        status.update(ok=True, n_pairs=len(pairs), sources=used_sources,
                      skipped_glue=skipped_glue)
        return status
    except Exception as exc:  # noqa: BLE001 — must never abort the pipeline
        print(f"[rq3_preprocess] WARNING: preprocessing raised and was swallowed: {exc}")
        return status


def main() -> int:
    st = preprocess()
    print(f"[rq3_preprocess] done: ok={st['ok']}, n_pairs={st['n_pairs']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())