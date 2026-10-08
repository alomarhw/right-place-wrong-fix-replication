"""fetch_data.py — Best-effort acquisition of RQ1 datasets.

Downloads the VulSlicer + VUDDY corpus (Zenodo record 6059924) and related
fallbacks into data/, decompresses archives, and records a fetch manifest at
data/fetch_manifest.json so main.py can resolve real paths deterministically.

This script is RESILIENT: every download is wrapped in try/except, prints a
clear warning on failure, and ALWAYS exits 0. main.py enforces the real-data
policy (strict failure vs. approved synthetic smoke).

Key deps: requests (or urllib fallback), zipfile/tarfile/gzip (stdlib).
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

DATA_ROOT = Path("data")
ZENODO_RECORD = "6059924"
ZENODO_API = f"https://zenodo.org/api/records/{ZENODO_RECORD}"


def _safe_get(url: str, timeout: int = 60) -> bytes | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "replication-package/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except Exception as exc:  # noqa: BLE001
        print(f"[fetch_data] WARNING: GET failed for {url}: {exc}")
        return None


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _extract_archive(raw: bytes, dest: Path) -> list[Path]:
    """Extract zip/tar/gz bytes into dest; return list of extracted data files."""
    extracted: list[Path] = []
    dest.mkdir(parents=True, exist_ok=True)
    # try zip
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            zf.extractall(dest)
            print(f"[fetch_data] extracted zip into {dest}")
    except zipfile.BadZipFile:
        # try tar (handles tar.gz / tar.bz2 / tgz)
        try:
            with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
                tf.extractall(dest)  # noqa: S202
                print(f"[fetch_data] extracted tar into {dest}")
        except tarfile.TarError:
            print(f"[fetch_data] WARNING: not a recognized archive for {dest}")
            return extracted
    exts = {".csv", ".tsv", ".json", ".jsonl", ".parquet", ".xlsx", ".txt", ".c", ".cpp", ".h"}
    for p in dest.rglob("*"):
        if p.is_file() and p.suffix.lower() in exts:
            extracted.append(p)
    return extracted


def fetch_zenodo(manifest_ok: list) -> None:
    print(f"[fetch_data] querying Zenodo record {ZENODO_RECORD} ...")
    meta_raw = _safe_get(ZENODO_API)
    if meta_raw is None:
        print("[fetch_data] WARNING: could not reach Zenodo API; skipping.")
        return
    try:
        meta = json.loads(meta_raw.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        print(f"[fetch_data] WARNING: could not parse Zenodo metadata: {exc}")
        return

    dest = DATA_ROOT / "vulslicer"
    dest.mkdir(parents=True, exist_ok=True)
    files = meta.get("files", [])
    license_name = (meta.get("metadata", {}) or {}).get("license", {})
    if isinstance(license_name, dict):
        license_name = license_name.get("id", "")
    saved_any = False
    for f in files:
        fname = f.get("key") or f.get("filename") or "download.bin"
        link = (f.get("links", {}) or {}).get("self")
        if not link:
            continue
        print(f"[fetch_data] downloading {fname} ...")
        raw = _safe_get(link, timeout=180)
        if raw is None:
            continue
        out_path = dest / fname
        try:
            out_path.write_bytes(raw)
            saved_any = True
            print(f"[fetch_data] saved {out_path} ({len(raw)} bytes)")
            # try to extract if archive
            if out_path.suffix.lower() in {".zip", ".gz", ".tgz", ".tar", ".bz2"}:
                _extract_archive(raw, dest / (out_path.stem + "_extracted"))
        except Exception as exc:  # noqa: BLE001
            print(f"[fetch_data] WARNING: failed to write {out_path}: {exc}")

    if saved_any:
        manifest_ok.append({
            "path": str(dest),
            "contract": {"datasetName": "VulSlicer + VUDDY (pre-cutoff verbatim / SRC VUL corpora)"},
            "version": meta.get("metadata", {}).get("version", ""),
            "license": str(license_name),
            "citation": "salimi2022vulslicer; SRC VUL foundation",
            "checksum": "",
            "recordCount": None,
            "columns": [],
        })


def main() -> int:
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    manifest_path = DATA_ROOT / "fetch_manifest.json"
    manifest = {"ok": [], "failed": []}

    try:
        fetch_zenodo(manifest["ok"])
    except Exception as exc:  # noqa: BLE001
        print(f"[fetch_data] WARNING: Zenodo fetch raised: {exc}")
        manifest["failed"].append({"datasetName": "VulSlicer + VUDDY", "error": str(exc)})

    # Record failures for the other listed sources we do not actively crawl here;
    # main.py will fall back / fail per policy.
    for name in [
        "VUDDY corpus (github squizz617/vuddy)",
        "Post-cutoff CVE control (cve.org)",
        "Big-Vul (bstee615/bigvul)",
    ]:
        if not any(name.split(" (")[0] in e.get("contract", {}).get("datasetName", "")
                   for e in manifest["ok"]):
            manifest["failed"].append({"datasetName": name, "error": "not fetched (best-effort)"})

    try:
        manifest_path.write_text(json.dumps(manifest, indent=2))
        print(f"[fetch_data] wrote {manifest_path}: "
              f"{len(manifest['ok'])} ok, {len(manifest['failed'])} failed")
    except Exception as exc:  # noqa: BLE001
        print(f"[fetch_data] WARNING: could not write manifest: {exc}")

    return 0


if __name__ == "__main__":
    sys.exit(main())