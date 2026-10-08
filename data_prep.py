"""data_prep.py — build the RQ1 CVE function corpus.

Produces a list of CVE items, each with:
  cve_id, cwe, code (verbatim C function), label (1=vulnerable), provenance
  ('seen'/pre-cutoff or 'unseen'/post-cutoff), and the vulnerability-relevant
  program slice (sink lines) used to certify semantics.

STRICT real-data mode: loads real C functions from data/ when available.
Synthetic fallback is ONLY used when explicitly requested (smoke mode) since the
benchmark is annotated with a deterministic synthetic paired-function fallback.

Key deps: pandas==2.2.2, numpy==2.2.6 (stdlib re, pathlib).
"""
from __future__ import annotations

import os
import random
import re
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

try:
    from rp_data_runtime import resolve_data_path
except Exception:  # noqa: BLE001
    resolve_data_path = None  # type: ignore

RANDOM_SEED = int(os.environ.get("RP_RANDOM_SEED", 42))

CWES = ["CWE-119", "CWE-787", "CWE-416", "CWE-125", "CWE-190"]


@dataclass
class CVEItem:
    cve_id: str
    cwe: str
    code: str
    label: int  # 1 vulnerable, 0 fixed/benign
    provenance: str  # 'seen' or 'unseen'
    slice_lines: list = field(default_factory=list)  # list of slice statements (str)


# ----------------------------------------------------------------------------
# Slice extraction (lightweight backward slice from the CVE sink)
# ----------------------------------------------------------------------------
SINK_PATTERNS = [
    r"\bstrcpy\b", r"\bstrcat\b", r"\bmemcpy\b", r"\bsprintf\b", r"\bgets\b",
    r"\bmalloc\b", r"\bfree\b", r"\[\s*\w+\s*\]",
]


def _canonicalize(code: str) -> str:
    """Normalize whitespace/comments for certification comparison."""
    # remove block comments
    code = re.sub(r"/\*.*?\*/", " ", code, flags=re.S)
    # remove line comments
    code = re.sub(r"//[^\n]*", " ", code)
    # collapse whitespace
    code = re.sub(r"\s+", " ", code)
    return code.strip()


# public alias used by tests / other modules
def canonicalize(code: str) -> str:
    return _canonicalize(code)


def extract_slice(code: str) -> list[str]:
    """Backward data/control slice: keep lines touching sink vars + their defs."""
    lines = [ln.strip() for ln in code.splitlines() if ln.strip()]
    sink_idx = []
    for i, ln in enumerate(lines):
        if any(re.search(p, ln) for p in SINK_PATTERNS):
            sink_idx.append(i)
    if not sink_idx:
        # fall back to lines with assignments/calls
        sink_idx = [i for i, ln in enumerate(lines) if "=" in ln or "(" in ln]
    # collect identifiers used in sink lines
    sink_vars: set[str] = set()
    for i in sink_idx:
        sink_vars.update(re.findall(r"[A-Za-z_]\w*", lines[i]))
    kept = []
    for i, ln in enumerate(lines):
        toks = set(re.findall(r"[A-Za-z_]\w*", ln))
        if i in sink_idx or (toks & sink_vars):
            kept.append(ln)
    return kept


def canonical_slice(code: str) -> str:
    return _canonicalize("\n".join(extract_slice(code)))


# ----------------------------------------------------------------------------
# Real-data loader: discover C functions in data/ corpus
# ----------------------------------------------------------------------------
_FUNC_RE = re.compile(
    r"([A-Za-z_][\w\s\*]*?\b\w+\s*\([^;{]*\)\s*\{)", re.M
)


def _split_functions(text: str) -> list[str]:
    """Crudely split C source text into top-level function bodies via brace counting."""
    funcs = []
    for m in _FUNC_RE.finditer(text):
        start = m.start()
        depth = 0
        i = text.find("{", m.end() - 1)
        if i < 0:
            continue
        j = i
        while j < len(text):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    funcs.append(text[start:j + 1])
                    break
            j += 1
    return [f for f in funcs if 30 < len(f) < 4000]


def _resolve_corpus_root() -> Path:
    """Resolve the data root for the VulSlicer corpus, always returning a Path.

    Defensive against resolve_data_path returning a str (or None) — we never call
    .exists() on anything but a Path object.
    """
    resolved = None
    if resolve_data_path is not None:
        try:
            resolved = resolve_data_path("VulSlicer", required=False)
        except Exception:  # noqa: BLE001
            resolved = None
    if resolved:
        try:
            return Path(resolved)
        except Exception:  # noqa: BLE001
            pass
    return Path("data")


def _pair_files() -> list[Path]:
    """All vulnerable/fixed pair files: data/bigvul (pre-cutoff) and data/postcutoff."""
    roots = [Path("data")]
    other = _resolve_corpus_root()
    if other not in roots:
        roots.append(other)
    files = []
    for r in roots:
        try:
            files += sorted(r.rglob("*_pairs.jsonl"))
        except Exception:  # noqa: BLE001
            continue
    return list(dict.fromkeys(files))


def load_real_corpus(max_items: int | None, seed: int = RANDOM_SEED) -> list[CVEItem]:
    """Load real labelled CVE functions from the vulnerable/fixed pair files.

    Each pair yields two items with ground-truth labels: func_before (label 1,
    vulnerable) and func_after (label 0, the official fix). cve_id and cwe come
    from the CVE record. Provenance: 'pre_cutoff' (Big-Vul, CVEs that may be in
    the detector LLM's training data) -> 'seen'; 'post_cutoff' (mined with VUDDY's
    FuncParser, CVE published after the LLM's training cutoff) -> 'unseen'.
    Pairs are sampled whole (both sides kept); up to half of the pairs are unseen
    (at full scale every unseen pair is used, since they are scarcer). Returns [] if no pair file exists (caller decides policy).
    """
    import json
    rng = random.Random(seed)
    pairs = {"seen": [], "unseen": []}
    seen_ids = set()
    for p in _pair_files():
        try:
            lines = p.read_text(errors="ignore").splitlines()
        except Exception:  # noqa: BLE001
            continue
        for ln in lines:
            try:
                r = json.loads(ln)
            except Exception:  # noqa: BLE001
                continue
            before, after = r.get("func_before"), r.get("func_after")
            cve = r.get("cve_id")
            if not before or not after or not cve or cve in seen_ids:
                continue
            seen_ids.add(cve)
            prov = "unseen" if r.get("provenance") == "post_cutoff" else "seen"
            pairs[prov].append((cve, r.get("cwe") or "CWE-unknown", before, after))
    if not pairs["seen"] and not pairs["unseen"]:
        return []
    for k in pairs:
        rng.shuffle(pairs[k])
    n_pairs = (max_items // 2) if max_items else len(pairs["seen"]) + len(pairs["unseen"])
    # up to half unseen (all of them at full scale), the rest seen, topped up if short
    n_un = min(len(pairs["unseen"]), max(n_pairs - len(pairs["seen"]), (n_pairs + 1) // 2))
    chosen = [("unseen", x) for x in pairs["unseen"][:n_un]]
    chosen += [("seen", x) for x in pairs["seen"][:max(0, n_pairs - len(chosen))]]
    items: list[CVEItem] = []
    for prov, (cve, cwe, before, after) in chosen:
        for code, label in ((before, 1), (after, 0)):
            items.append(CVEItem(cve_id=cve, cwe=cwe, code=code, label=label,
                                 provenance=prov, slice_lines=extract_slice(code)))
    rng.shuffle(items)
    return items


# ----------------------------------------------------------------------------
# Deterministic synthetic fallback (smoke mode only)
# ----------------------------------------------------------------------------
_VULN_TEMPLATES = [
    # CWE-119/787 buffer overflow
    (
        "CWE-119",
        "void copy_{id}(char *src) {{\n"
        "    char buf[{sz}];\n"
        "    int i = {i};\n"
        "    strcpy(buf, src);\n"   # vulnerable sink: no bounds check
        "    process(buf, i);\n"
        "}}",
        "void copy_{id}(char *src) {{\n"
        "    char buf[{sz}];\n"
        "    int i = {i};\n"
        "    strncpy(buf, src, sizeof(buf)-1);\n"  # fixed
        "    buf[sizeof(buf)-1] = 0;\n"
        "    process(buf, i);\n"
        "}}",
    ),
    (
        "CWE-416",
        "int uaf_{id}(int n) {{\n"
        "    char *p = malloc(n);\n"
        "    free(p);\n"
        "    p[0] = {i};\n"    # use after free
        "    return p[0];\n"
        "}}",
        "int uaf_{id}(int n) {{\n"
        "    char *p = malloc(n);\n"
        "    int v = {i};\n"
        "    p[0] = v;\n"
        "    free(p);\n"       # fixed: free after last use
        "    return v;\n"
        "}}",
    ),
    (
        "CWE-190",
        "int ovf_{id}(int a) {{\n"
        "    int sz = a * {sz};\n"
        "    char *buf = malloc(sz);\n"  # integer overflow -> small alloc
        "    memcpy(buf, src, a);\n"
        "    return sz;\n"
        "}}",
        "int ovf_{id}(int a) {{\n"
        "    if (a > MAXA) return -1;\n"  # fixed: guard
        "    int sz = a * {sz};\n"
        "    char *buf = malloc(sz);\n"
        "    memcpy(buf, src, a);\n"
        "    return sz;\n"
        "}}",
    ),
]


def generate_synthetic_corpus(n_cves: int, seed: int = RANDOM_SEED) -> list[CVEItem]:
    """Deterministic paired vulnerable/fixed C functions for a fixed CWE set."""
    rng = random.Random(seed)
    items: list[CVEItem] = []
    for k in range(n_cves):
        cwe, vt, ft = _VULN_TEMPLATES[k % len(_VULN_TEMPLATES)]
        sz = rng.choice([8, 16, 32, 64])
        i = rng.randint(0, 255)
        vuln_code = vt.format(id=k, sz=sz, i=i)
        fixed_code = ft.format(id=k, sz=sz, i=i)
        prov = "seen" if (k % 3 != 0) else "unseen"
        items.append(CVEItem(
            cve_id=f"CVE-S-{k:05d}",
            cwe=cwe,
            code=vuln_code,
            label=1,
            provenance=prov,
            slice_lines=extract_slice(vuln_code),
        ))
        items.append(CVEItem(
            cve_id=f"CVE-S-{k:05d}",  # same CVE id -> paired; fixed=benign
            cwe=cwe,
            code=fixed_code,
            label=0,
            provenance=prov,
            slice_lines=extract_slice(fixed_code),
        ))
    return items


def build_corpus(n_cves: int, allow_synthetic: bool, seed: int = RANDOM_SEED):
    """Return (items, source_tag). Prefers real data; synthetic only if allowed."""
    real = load_real_corpus(max_items=n_cves, seed=seed)
    if real:
        n_un = sum(it.provenance == "unseen" for it in real)
        print(f"[data_prep] loaded {len(real)} real labelled C functions "
              f"({len(real) // 2} vulnerable/fixed CVE pairs; {n_un} unseen/post-cutoff) from data/")
        return real, "real"
    if not allow_synthetic:
        raise RuntimeError(
            "Required dataset 'VulSlicer + VUDDY (Zenodo 6059924)' not found in data/ "
            "and synthetic fallback is NOT approved (strict real-data mode). "
            "Run fetch_data.py or place C source under data/vulslicer/."
        )
    print(f"[data_prep] REAL DATA UNAVAILABLE — using deterministic synthetic fallback "
          f"({n_cves} paired CVEs).")
    return generate_synthetic_corpus(n_cves, seed=seed), "synthetic"


# ----------------------------------------------------------------------------
# Compatibility shim: some RQ3 modules call load_corpus(...) with a different
# signature. Provide it here mapping onto build_corpus.
# ----------------------------------------------------------------------------
def load_corpus(n_items: int = 30, strict_real_data: bool = True,
                seed: int = RANDOM_SEED):
    """Return (corpus_records, provenance_dict).

    corpus_records is a list of dicts {cve_id, cwe, code, label, provenance}.
    """
    items, tag = build_corpus(n_cves=n_items, allow_synthetic=not strict_real_data,
                              seed=seed)
    records = [{
        "cve_id": it.cve_id, "cwe": it.cwe, "code": it.code,
        "label": it.label, "provenance": it.provenance,
    } for it in items]
    provenance = {
        "primary_source": tag,
        "usedSynthetic": tag == "synthetic",
        "datasets": [{
            "name": "Big-Vul (pre-cutoff) + VUDDY-mined post-cutoff CVE pairs",
            "source": "real" if tag == "real" else "synthetic",
            "rows": len(records),
        }],
    }
    return records, provenance


if __name__ == "__main__":
    np.random.seed(RANDOM_SEED)
    items, tag = build_corpus(n_cves=10, allow_synthetic=True)
    print(f"source={tag}, items={len(items)}")
    for it in items[:3]:
        print(it.cve_id, it.cwe, it.label, it.provenance, "slice_lines=", len(it.slice_lines))