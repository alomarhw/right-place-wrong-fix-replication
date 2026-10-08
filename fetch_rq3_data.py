"""fetch_rq3_data.py — acquire CVE patch-diff ground truth for the RQ3 oracle.

The RQ3 study design EXPLICITLY warns that GLUE was auto-adopted in error and is
NOT vulnerability data. The correct ground truth is CVE vulnerable/fixed function
pairs with official patch diffs. This script makes a best-effort attempt to fetch
such a corpus (Big-Vul / CVEfixes on Hugging Face) into data/.

It is RESILIENT: every download is wrapped in try/except, prints a clear warning on
failure, and ALWAYS hard-exits 0 (os._exit) to skip torch/PyArrow atexit finalizers
that can deadlock/crash the interpreter at shutdown on this platform. main.py /
rq3_main.py enforce the strict real-data policy; this fetcher never aborts the run.

Key deps: datasets (optional), stdlib json/os.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def _install_torch_guard() -> None:
    """Block torch/transformers import; datasets==5.0.0 pulls torch which crashes on this platform."""
    if os.environ.get("RP_USE_REAL_ENCODER", "0") in ("1", "true", "True"):
        return
    import importlib.abc

    blocked = {"torch", "transformers"}

    class _BlockFinder(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            root = fullname.split(".", 1)[0]
            if root in blocked:
                raise ImportError(f"{fullname} import blocked in fetch mode.")
            return None

    for finder in sys.meta_path:
        if type(finder).__name__ == "_BlockFinder":
            return
    sys.meta_path.insert(0, _BlockFinder())


_install_torch_guard()

DATA_ROOT = Path("data")

HF_CANDIDATES = [
    ("bstee615/bigvul", DATA_ROOT / "bigvul"),
    ("claudios/cvefixes_bigvul", DATA_ROOT / "cvefixes_bigvul"),
]

SAMPLE_CAP = int(os.environ.get("RP_RQ3_FETCH_CAP", 2000))


def _append_manifest(entry: dict) -> None:
    mpath = DATA_ROOT / "fetch_manifest.json"
    manifest = {"ok": [], "failed": []}
    if mpath.exists():
        try:
            manifest = json.loads(mpath.read_text())
            manifest.setdefault("ok", [])
            manifest.setdefault("failed", [])
        except Exception:  # noqa: BLE001
            manifest = {"ok": [], "failed": []}
    manifest["ok"].append(entry)
    try:
        mpath.write_text(json.dumps(manifest, indent=2))
    except Exception as exc:  # noqa: BLE001
        print(f"[fetch_rq3] WARNING: could not update manifest: {exc}")


def _append_failed(name: str, err: str) -> None:
    mpath = DATA_ROOT / "fetch_manifest.json"
    manifest = {"ok": [], "failed": []}
    if mpath.exists():
        try:
            manifest = json.loads(mpath.read_text())
            manifest.setdefault("ok", [])
            manifest.setdefault("failed", [])
        except Exception:  # noqa: BLE001
            manifest = {"ok": [], "failed": []}
    manifest["failed"].append({"datasetName": name, "error": err})
    try:
        mpath.write_text(json.dumps(manifest, indent=2))
    except Exception:  # noqa: BLE001
        pass


def _fetch_hf(dataset_id: str, dest: Path) -> bool:
    try:
        from datasets import load_dataset
    except Exception as exc:  # noqa: BLE001
        print(f"[fetch_rq3] 'datasets' not importable ({exc}); skipping HF {dataset_id}.")
        return False
    try:
        print(f"[fetch_rq3] loading Hugging Face dataset '{dataset_id}' (streaming) ...")
        ds = load_dataset(dataset_id, split="train", streaming=True)
        dest.mkdir(parents=True, exist_ok=True)
        out = dest / "sample.jsonl"
        n = 0
        with out.open("w") as fh:
            for rec in ds:
                try:
                    fh.write(json.dumps(rec, default=str) + "\n")
                except Exception:  # noqa: BLE001
                    continue
                n += 1
                if n >= SAMPLE_CAP:
                    break
        if n == 0:
            print(f"[fetch_rq3] WARNING: {dataset_id} yielded 0 rows.")
            return False
        print(f"[fetch_rq3] saved {out} ({n} rows) from {dataset_id}")
        _append_manifest({
            "path": str(dest),
            "contract": {"datasetName": dataset_id, "rqId": "RQ3"},
            "version": "",
            "license": "research use",
            "citation": "Big-Vul / CVEfixes patch-diff corpus",
            "checksum": "",
            "recordCount": n,
            "columns": [],
        })
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"[fetch_rq3] WARNING: HF load failed for {dataset_id}: {exc}")
        return False


def main() -> int:
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    print("[fetch_rq3] NOTE: RQ3 ground truth is CVE patch diffs, NOT GLUE.")
    got_any = False
    for dsid, dest in HF_CANDIDATES:
        if dest.exists() and any(dest.glob("*.jsonl")):
            print(f"[fetch_rq3] {dest} already present; skipping {dsid}.")
            got_any = True
            continue
        ok = _fetch_hf(dsid, dest)
        got_any = got_any or ok
        if ok:
            break

    if not got_any:
        print("[fetch_rq3] WARNING: no CVE patch-diff corpus could be fetched. "
              "rq3_main.py will use the VulSlicer+VUDDY corpus if present, or fail "
              "loudly in strict mode / run a labelled synthetic smoke otherwise.")
        _append_failed("CVE patch-diff corpus (Big-Vul / CVEfixes)",
                       "network/datasets unavailable (best-effort)")

    print("[fetch_rq3] done (exit 0, best-effort).")
    return 0


if __name__ == "__main__":
    code = main()
    sys.stdout.flush()
    sys.stderr.flush()
    # Hard-exit to skip torch/PyArrow atexit finalizers that crash the interpreter.
    os._exit(code)