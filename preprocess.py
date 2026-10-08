"""Preprocessing helpers for RQ1-ALT1.

Responsibilities (all best-effort, idempotent):
  1. Extract any archive (*.zip / *.tar* / *.gz) found under data/ in place, so the
     researcher can upload a raw archive instead of ready files.
  2. Walk the extracted tree and surface the usable data files (C/C++ sources, csv,
     json/jsonl, parquet-ish) by returning their paths.
  3. Provide a light C-function extractor so raw .c/.cpp/.h corpora (e.g. VUDDY repos)
     can be turned into the function records data_prep.py consumes.

This module performs NO synthesis and NO network access. It only reshapes files that
already exist under data/.
"""
from __future__ import annotations

import gzip
import json
import os
import re
import shutil
import tarfile
import zipfile
from pathlib import Path
from typing import Dict, Iterable, List

RANDOM_SEED = int(os.environ.get("RP_RANDOM_SEED", 42))

DATA_FILE_EXTS = {
    ".csv", ".tsv", ".json", ".jsonl", ".parquet", ".txt",
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp",
}


# --------------------------------------------------------------------------------------
# Archive extraction
# --------------------------------------------------------------------------------------
def _safe_extract_zip(path: Path, dest: Path) -> None:
    with zipfile.ZipFile(path) as zf:
        for member in zf.namelist():
            target = dest / member
            if not str(target.resolve()).startswith(str(dest.resolve())):
                # path traversal guard
                continue
        zf.extractall(dest)


def _safe_extract_tar(path: Path, dest: Path) -> None:
    mode = "r:*"
    with tarfile.open(path, mode) as tf:
        safe_members = []
        for m in tf.getmembers():
            target = dest / m.name
            if str(target.resolve()).startswith(str(dest.resolve())):
                safe_members.append(m)
        tf.extractall(dest, members=safe_members)


def _extract_gz(path: Path) -> Path | None:
    """Decompress a bare .gz (not a tarball) into a sibling file."""
    if path.suffixes[-2:] == [".tar", ".gz"] or path.name.endswith(".tgz"):
        return None
    out = path.with_suffix("")  # strip .gz
    if out.exists():
        return out
    try:
        with gzip.open(path, "rb") as fin, out.open("wb") as fout:
            shutil.copyfileobj(fin, fout)
        return out
    except Exception as exc:  # noqa: BLE001
        print(f"[preprocess] WARNING: failed to gunzip {path}: {exc}")
        return None


def extract_archives(data_root: str | Path = "data") -> List[Path]:
    """Extract every archive found anywhere under data_root. Returns new dirs/files."""
    root = Path(data_root)
    if not root.exists():
        return []
    created: List[Path] = []
    archives = (
        list(root.rglob("*.zip"))
        + list(root.rglob("*.tar"))
        + list(root.rglob("*.tar.gz"))
        + list(root.rglob("*.tgz"))
        + list(root.rglob("*.tar.bz2"))
        + list(root.rglob("*.gz"))
    )
    seen = set()
    for arc in sorted(set(archives)):
        if arc in seen:
            continue
        seen.add(arc)
        dest = arc.parent / (arc.stem + "_extracted")
        if dest.exists() and any(dest.iterdir()):
            created.append(dest)
            continue
        try:
            if arc.suffix == ".zip":
                dest.mkdir(parents=True, exist_ok=True)
                _safe_extract_zip(arc, dest)
                created.append(dest)
                print(f"[preprocess] extracted zip {arc} -> {dest}")
            elif arc.name.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2")):
                dest.mkdir(parents=True, exist_ok=True)
                _safe_extract_tar(arc, dest)
                created.append(dest)
                print(f"[preprocess] extracted tar {arc} -> {dest}")
            elif arc.suffix == ".gz":
                out = _extract_gz(arc)
                if out is not None:
                    created.append(out)
                    print(f"[preprocess] gunzipped {arc} -> {out}")
        except Exception as exc:  # noqa: BLE001
            print(f"[preprocess] WARNING: failed to extract {arc}: {exc}")
    return created


# --------------------------------------------------------------------------------------
# Usable-file discovery
# --------------------------------------------------------------------------------------
def discover_data_files(data_root: str | Path = "data") -> Dict[str, List[Path]]:
    """Recursively group usable data files by category."""
    root = Path(data_root)
    out: Dict[str, List[Path]] = {"tabular": [], "code": [], "jsonl": [], "other": []}
    if not root.exists():
        return out
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        ext = p.suffix.lower()
        if ext in {".csv", ".tsv", ".parquet"}:
            out["tabular"].append(p)
        elif ext in {".json", ".jsonl"}:
            out["jsonl"].append(p)
        elif ext in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}:
            out["code"].append(p)
        elif ext in DATA_FILE_EXTS:
            out["other"].append(p)
    for k in out:
        out[k].sort()
    return out


# --------------------------------------------------------------------------------------
# Light C-function extraction (for raw source corpora such as VUDDY repos)
# --------------------------------------------------------------------------------------
_FUNC_HEAD = re.compile(
    r"(?m)^[A-Za-z_][\w\s\*\(\),]*?\b([A-Za-z_]\w*)\s*\([^;{]*\)\s*\{"
)


def extract_c_functions(source_text: str, max_funcs: int = 500) -> List[Dict[str, str]]:
    """Brace-match top-level C function definitions out of raw source text.

    Returns records: {"name": <fn name>, "code": <full function text>}.
    Deterministic and dependency-free (no tree-sitter required).
    """
    funcs: List[Dict[str, str]] = []
    n = len(source_text)
    for m in _FUNC_HEAD.finditer(source_text):
        name = m.group(1)
        brace_start = source_text.find("{", m.start())
        if brace_start < 0:
            continue
        depth = 0
        i = brace_start
        end = -1
        while i < n:
            ch = source_text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
            i += 1
        if end < 0:
            continue
        code = source_text[m.start():end]
        if 1 <= code.count("\n") <= 400:  # skip absurdly large blobs
            funcs.append({"name": name, "code": code})
        if len(funcs) >= max_funcs:
            break
    return funcs


def extract_c_functions_from_paths(paths: Iterable[Path], cap: int = 2000) -> List[Dict[str, str]]:
    """Extract functions across a set of C/C++ files; caps total for tractability."""
    out: List[Dict[str, str]] = []
    for p in paths:
        if len(out) >= cap:
            break
        try:
            text = p.read_text(errors="ignore")
        except Exception:  # noqa: BLE001
            continue
        for rec in extract_c_functions(text):
            rec = dict(rec)
            rec["source_file"] = str(p)
            out.append(rec)
            if len(out) >= cap:
                break
    return out


def load_jsonl_records(path: Path, cap: int | None = None) -> List[dict]:
    """Load a .jsonl (or a .json array) file into a list of dicts."""
    records: List[dict] = []
    try:
        text = path.read_text(errors="ignore").strip()
    except Exception as exc:  # noqa: BLE001
        print(f"[preprocess] WARNING: cannot read {path}: {exc}")
        return records
    if not text:
        return records
    if path.suffix.lower() == ".json" and text[0] == "[":
        try:
            arr = json.loads(text)
            if isinstance(arr, list):
                records = [r for r in arr if isinstance(r, dict)]
        except Exception as exc:  # noqa: BLE001
            print(f"[preprocess] WARNING: cannot parse json array {path}: {exc}")
    else:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    records.append(obj)
            except Exception:
                continue
            if cap is not None and len(records) >= cap:
                break
    if cap is not None:
        records = records[:cap]
    return records


def prepare(data_root: str | Path = "data") -> Dict[str, List[Path]]:
    """Top-level entry: extract archives then return discovered usable files."""
    extract_archives(data_root)
    return discover_data_files(data_root)


if __name__ == "__main__":
    found = prepare("data")
    for cat, paths in found.items():
        print(f"[preprocess] {cat}: {len(paths)} file(s)")
        for p in paths[:5]:
            print(f"    {p}")