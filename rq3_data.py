"""rq3_data.py — RQ3 CVE patch corpus (vulnerable/fixed function pairs).

Each RQ3 item is a CVE with:
  cve_id, cwe,
  vulnerable_code (the vulnerable function),
  official_fixed_code (the function after the official CVE patch),
  vulnerable_slice / fixed_slice (vulnerability-relevant program slice),
  poc_available (bool — whether a behavioural/PoC validation is possible).

Data resolution (STRICT real-data mode):
  1. A fetched CVE patch-diff corpus (Big-Vul / CVEfixes) under data/ with
     vulnerable+fixed function columns — the preferred ground truth.
  2. The VulSlicer+VUDDY corpus (foundation) parsed into paired functions.
  3. If neither real source is available AND synthetic is NOT approved -> raise.
  4. If synthetic IS approved (smoke) -> deterministic paired generator, clearly
     labelled. This path is NEVER paper-grade.

CRITICAL: GLUE is a text-classification benchmark and is NOT valid RQ3 data; this
module never treats GLUE as CVE patch data. If only GLUE-like data is present we
treat real CVE data as UNAVAILABLE.

Key deps: pandas==2.2.2, numpy==2.2.6 (stdlib json, re, pathlib).
"""
from __future__ import annotations

import json
import os
import random
import re
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

try:
    from rp_data_runtime import resolve_data_path, load_manifest
except Exception:  # noqa: BLE001
    resolve_data_path = None  # type: ignore
    load_manifest = None  # type: ignore

# Reuse the foundation slice extraction / canonicalization.
from data_prep import extract_slice, canonical_slice, generate_synthetic_corpus

RANDOM_SEED = int(os.environ.get("RP_RANDOM_SEED", 42))

CWES = ["CWE-119", "CWE-787", "CWE-416", "CWE-125", "CWE-190"]

# column-name candidates seen across Big-Vul / CVEfixes variants
_VULN_COLS = ["func_before", "vulnerable_func", "vulnerable_code", "code_before",
              "before", "vul_func", "func_vul"]
_FIXED_COLS = ["func_after", "fixed_func", "fixed_code", "code_after",
               "after", "patched_func", "func_fix"]
_CWE_COLS = ["cwe", "cwe_id", "CWE ID", "cwe_ids", "vulnerability_type"]
_CVE_COLS = ["cve", "cve_id", "CVE ID", "cveid"]


@dataclass
class CVEPatchItem:
    cve_id: str
    cwe: str
    vulnerable_code: str
    official_fixed_code: str
    poc_available: bool = False
    vulnerable_slice: list = field(default_factory=list)
    fixed_slice: list = field(default_factory=list)

    def __post_init__(self):
        if not self.vulnerable_slice:
            self.vulnerable_slice = extract_slice(self.vulnerable_code)
        if not self.fixed_slice:
            self.fixed_slice = extract_slice(self.official_fixed_code)


# ----------------------------------------------------------------------------
# Real patch-diff corpus loader (Big-Vul / CVEfixes jsonl)
# ----------------------------------------------------------------------------
def _first_present(rec: dict, keys: list[str]) -> str | None:
    for k in keys:
        if k in rec and rec[k] not in (None, "", "nan"):
            return str(rec[k])
    # case-insensitive fallback
    lk = {k.lower(): k for k in rec.keys()}
    for cand in keys:
        if cand.lower() in lk:
            v = rec[lk[cand.lower()]]
            if v not in (None, "", "nan"):
                return str(v)
    return None


def _looks_like_glue(rec: dict) -> bool:
    """Reject GLUE-style records masquerading as RQ3 data."""
    glue_keys = {"sentence", "sentence1", "sentence2", "premise", "hypothesis",
                 "question", "label", "idx"}
    keys = {k.lower() for k in rec.keys()}
    has_code = any(c.lower() in keys for c in _VULN_COLS + _FIXED_COLS)
    return (keys & glue_keys) and not has_code


def _load_jsonl(path: Path, cap: int) -> list[dict]:
    out = []
    try:
        with path.open(errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        out.append(obj)
                except Exception:  # noqa: BLE001
                    continue
                if len(out) >= cap:
                    break
    except Exception:  # noqa: BLE001
        return out
    return out


def _as_path(value) -> Path | None:
    """Coerce a manifest path (possibly str/None) into a Path, defensively."""
    if value is None:
        return None
    try:
        return Path(value)
    except Exception:  # noqa: BLE001
        return None


def load_real_patch_corpus(max_items: int, seed: int = RANDOM_SEED) -> list[CVEPatchItem]:
    """Load vulnerable/fixed function pairs from a real patch-diff corpus in data/.

    Returns [] if no usable real CVE patch pairs were found.
    """
    rng = random.Random(seed)
    candidate_dirs: list[Path] = []

    # manifest-resolved RQ3 corpora first
    if load_manifest is not None:
        try:
            man = load_manifest()
            for entry in man.get("ok", []):
                c = entry.get("contract", {}) or {}
                raw = entry.get("path", "")
                if c.get("rqId") == "RQ3" or "bigvul" in str(raw).lower() \
                        or "cvefixes" in str(raw).lower():
                    p = _as_path(raw)
                    if p is not None and p.exists():
                        candidate_dirs.append(p)
        except Exception:  # noqa: BLE001
            pass

    for sub in ["bigvul", "cvefixes_bigvul", "cve_patches"]:
        p = Path("data") / sub
        if p.exists():
            candidate_dirs.append(p)

    # dedup preserving order
    seen = set()
    dirs = []
    for d in candidate_dirs:
        if str(d) not in seen:
            seen.add(str(d))
            dirs.append(d)

    items: list[CVEPatchItem] = []
    idx = 0
    for d in dirs:
        try:
            jsonls = sorted(d.rglob("*.jsonl")) + sorted(d.rglob("*.json"))
        except Exception:  # noqa: BLE001
            continue
        for jf in jsonls:
            recs = _load_jsonl(jf, cap=max_items * 4)
            for rec in recs:
                if _looks_like_glue(rec):
                    continue
                vuln = _first_present(rec, _VULN_COLS)
                fixed = _first_present(rec, _FIXED_COLS)
                if not vuln or not fixed:
                    continue
                if vuln.strip() == fixed.strip():
                    continue  # no actual patch diff
                cwe = _first_present(rec, _CWE_COLS) or CWES[idx % len(CWES)]
                cwe = _norm_cwe(cwe)
                cve_id = _first_present(rec, _CVE_COLS) or f"CVE-R-{idx:05d}"
                # PoC availability heuristic: presence of a test/commit/poc field.
                poc = any(k.lower() in {"poc", "test", "exploit", "regression"}
                          for k in rec.keys())
                items.append(CVEPatchItem(
                    cve_id=str(cve_id), cwe=cwe,
                    vulnerable_code=vuln, official_fixed_code=fixed,
                    poc_available=bool(poc),
                ))
                idx += 1
                if len(items) >= max_items * 2:
                    break
            if len(items) >= max_items * 2:
                break
        if len(items) >= max_items * 2:
            break

    rng.shuffle(items)
    return items[:max_items]


def _norm_cwe(raw: str) -> str:
    m = re.search(r"CWE[-_ ]?(\d+)", str(raw), re.I)
    if m:
        return f"CWE-{m.group(1)}"
    return CWES[0]


# ----------------------------------------------------------------------------
# VulSlicer+VUDDY fallback: pair vulnerable (label=1) with fixed (label=0)
# ----------------------------------------------------------------------------
def load_from_foundation_corpus(max_items: int, seed: int = RANDOM_SEED) -> list[CVEPatchItem]:
    """Build CVE patch pairs from the foundation VulSlicer+VUDDY corpus via data_prep.

    data_prep.build_corpus yields paired vulnerable/fixed functions sharing a cve_id
    (for synthetic) and heuristic labels (for real). We pair them here.
    """
    try:
        from data_prep import build_corpus
        corpus, tag = build_corpus(n_cves=max_items * 2, allow_synthetic=False, seed=seed)
    except Exception:  # noqa: BLE001
        return []
    if not corpus:
        return []
    # group by cve_id
    by_cve: dict[str, dict[int, object]] = {}
    for it in corpus:
        by_cve.setdefault(it.cve_id, {})[it.label] = it
    items: list[CVEPatchItem] = []
    for cve_id, bylab in by_cve.items():
        vuln = bylab.get(1)
        fixed = bylab.get(0)
        if vuln is None or fixed is None:
            continue
        items.append(CVEPatchItem(
            cve_id=cve_id, cwe=getattr(vuln, "cwe", CWES[0]),
            vulnerable_code=vuln.code, official_fixed_code=fixed.code,
            poc_available=True,  # paired fix available -> fix-equivalence check possible
        ))
        if len(items) >= max_items:
            break
    return items


# ----------------------------------------------------------------------------
# Deterministic synthetic fallback (smoke only; clearly labelled)
# ----------------------------------------------------------------------------
def generate_synthetic_patch_corpus(n_cves: int, seed: int = RANDOM_SEED) -> list[CVEPatchItem]:
    """Deterministic vulnerable/fixed CVE patch pairs for smoke validation."""
    paired = generate_synthetic_corpus(n_cves, seed=seed)  # vuln + fixed share cve_id
    by_cve: dict[str, dict[int, object]] = {}
    for it in paired:
        by_cve.setdefault(it.cve_id, {})[it.label] = it
    items: list[CVEPatchItem] = []
    for cve_id, bylab in by_cve.items():
        vuln = bylab.get(1)
        fixed = bylab.get(0)
        if vuln is None or fixed is None:
            continue
        items.append(CVEPatchItem(
            cve_id=cve_id, cwe=vuln.cwe,
            vulnerable_code=vuln.code, official_fixed_code=fixed.code,
            poc_available=True,
        ))
    return items


def build_rq3_corpus(n_cves: int, allow_synthetic: bool, seed: int = RANDOM_SEED):
    """Return (items, source_tag). Prefers real CVE patch data; synthetic only if allowed."""
    real = load_real_patch_corpus(max_items=n_cves, seed=seed)
    if real:
        print(f"[rq3_data] loaded {len(real)} real CVE patch pairs from a patch-diff corpus.")
        return real, "real"
    found = load_from_foundation_corpus(max_items=n_cves, seed=seed)
    if found:
        print(f"[rq3_data] loaded {len(found)} CVE patch pairs from the VulSlicer+VUDDY foundation corpus.")
        return found, "real"
    if not allow_synthetic:
        raise RuntimeError(
            "RQ3 requires real CVE patch-diff data (vulnerable/fixed function pairs). "
            "None found in data/ (looked for Big-Vul / CVEfixes jsonl and the "
            "VulSlicer+VUDDY corpus). NOTE: GLUE is NOT valid RQ3 data and is ignored. "
            "Run fetch_rq3_data.py / fetch_data.py, or place a patch-diff corpus under "
            "data/bigvul/ or data/cvefixes_bigvul/. Synthetic fallback is NOT approved "
            "(strict real-data mode)."
        )
    print(f"[rq3_data] REAL CVE PATCH DATA UNAVAILABLE — using deterministic synthetic "
          f"fallback ({n_cves} CVEs). THIS IS A SMOKE RUN, NOT EVIDENCE.")
    return generate_synthetic_patch_corpus(n_cves, seed=seed), "synthetic"


if __name__ == "__main__":
    np.random.seed(RANDOM_SEED)
    items, tag = build_rq3_corpus(n_cves=10, allow_synthetic=True)
    print(f"source={tag}, items={len(items)}")
    for it in items[:3]:
        print(it.cve_id, it.cwe, "poc=", it.poc_available,
              "vuln_slice=", len(it.vulnerable_slice))