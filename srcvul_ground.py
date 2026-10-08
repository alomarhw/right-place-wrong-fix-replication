"""srcvul_ground.py — srcVul's vulnerability-slice machinery, as described in the paper
(Alomari et al., arXiv:2505.02349, Sec. III), on top of the real srcML + srcSlice tools.

  1. vr_stmts : statements deleted/added between a vulnerable function and its fix (diff).
  2. vr_vars  : variables (per srcSlice profiles) that occur in vr_stmts.
  3. vr_slices: srcSlice profiles of the vr_vars (def, use, dvars, pointers, cfuncs).
  4. vs_vector: <SC, SCvg, SI, SS> per vr_slice (paper Algorithm 1):
        SC   = (1 + |dvars| + |ptrs|) / module_size    (slice profiles combined)
        SZ   = |def U use|;  SCvg = SZ / module_size
        SI   = (|dvars| + |ptrs| + |cfuncs|) / module_size
        SS   = (last use - first def) / module_size
  5. Matching : cosine similarity between vs_vectors, threshold 0.8 (paper Sec. III-B).

Parsing is brace-aware (srcSlice emits lists such as pointers{a,b,c} and cfuncs{f{1},g{2}}).
"""
from __future__ import annotations

import difflib
import math
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field

MATCH_THRESHOLD = 0.8


@dataclass
class Profile:
    variable: str
    defs: list = field(default_factory=list)
    uses: list = field(default_factory=list)
    dvars: list = field(default_factory=list)
    ptrs: list = field(default_factory=list)
    cfuncs: list = field(default_factory=list)


def _split_top(s: str) -> list[str]:
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    out.append(cur)
    return [x.strip() for x in out]


def _inner(field_text: str) -> str:
    i = field_text.find("{")
    return field_text[i + 1:field_text.rfind("}")] if i >= 0 else ""


def parse_srcslice(text: str) -> dict[str, Profile]:
    profs: dict[str, Profile] = {}
    for line in text.splitlines():
        parts = _split_top(line)
        if len(parts) < 4 or "{" not in line:
            continue
        p = Profile(variable=parts[2])
        for f in parts[3:]:
            body = _inner(f)
            items = [x for x in _split_top(body) if x] if body else []
            if f.startswith("def"):
                p.defs = [int(x) for x in items if x.isdigit()]
            elif f.startswith("use"):
                p.uses = [int(x) for x in items if x.isdigit()]
            elif f.startswith("dvars"):
                p.dvars = items
            elif f.startswith("pointers") or f.startswith("ptrs"):
                p.ptrs = items
            elif f.startswith("cfuncs"):
                p.cfuncs = [x.split("{")[0] for x in items]
        profs[p.variable] = p
    return profs


def srcslice_profiles(code: str) -> dict[str, Profile]:
    """Run srcML (--position) + srcSlice on one function."""
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "f.c")
        xml = os.path.join(td, "f.xml")
        with open(src, "w") as fh:
            fh.write(code)
        subprocess.run(["srcml", "--position", src, "-o", xml], check=True, capture_output=True, timeout=120)
        r = subprocess.run(["srcslice", xml], capture_output=True, text=True, timeout=120)
    return parse_srcslice(r.stdout)


def vs_vector(p: Profile, module_size: int) -> tuple[float, float, float, float]:
    m = max(1, module_size)
    sc = (1 + len(p.dvars) + len(p.ptrs)) / m
    scvg = len(set(p.defs) | set(p.uses)) / m
    si = (len(p.dvars) + len(p.ptrs) + len(p.cfuncs)) / m
    sf = min(p.defs) if p.defs else 0
    sl = max(p.uses) if p.uses else 0
    ss = abs(sl - sf) / m
    return sc, scvg, si, ss


def cosine(a, b) -> float:
    na, nb = math.sqrt(sum(x * x for x in a)), math.sqrt(sum(x * x for x in b))
    return sum(x * y for x, y in zip(a, b)) / (na * nb) if na and nb else 0.0


def vr_stmts(vuln: str, fixed: str) -> tuple[list[str], list[str]]:
    a, b = [l.strip() for l in vuln.splitlines()], [l.strip() for l in fixed.splitlines()]
    deleted, added = [], []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag in ("replace", "delete"):
            deleted += [x for x in a[i1:i2] if x]
        if tag in ("replace", "insert"):
            added += [x for x in b[j1:j2] if x]
    return deleted, added


def ground(src_vuln: str, src_fixed: str, tgt_vuln: str) -> dict:
    """srcVul grounding for porting the source fix to the target clone."""
    deleted, added = vr_stmts(src_vuln, src_fixed)
    pv, pf, pt = srcslice_profiles(src_vuln), srcslice_profiles(src_fixed), srcslice_profiles(tgt_vuln)
    toks = set(re.findall(r"[A-Za-z_]\w*", " ".join(deleted + added)))
    vr_vars = sorted(v for v in (set(pv) | set(pf)) if v in toks)
    ms, mt = len(src_vuln.splitlines()), len(tgt_vuln.splitlines())
    mapping = []
    for v in vr_vars:
        sp = pv.get(v) or pf.get(v)
        sv = vs_vector(sp, ms)
        best, best_sim = None, 0.0
        for tv, tp in pt.items():
            sim = cosine(sv, vs_vector(tp, mt))
            # prefer the same name when similarity ties (identity mapping for unrenamed clones)
            if sim > best_sim + 1e-9 or (abs(sim - best_sim) <= 1e-9 and tv == v):
                best, best_sim = tv, sim
        tp = pt.get(best) if best else None
        mapping.append({"source_var": v, "target_var": best if best_sim >= MATCH_THRESHOLD else None,
                        "similarity": round(best_sim, 4),
                        "target_slice_lines": sorted(set(tp.defs) | set(tp.uses)) if (tp and best_sim >= MATCH_THRESHOLD) else []})
    # srcVul detection: does any target vr_slice match a source vr_slice at the threshold?
    detected = any(m["target_var"] for m in mapping)
    return {"vr_stmts_deleted": deleted, "vr_stmts_added": added, "vr_vars": vr_vars,
            "mapping": mapping, "detected": detected}


def render(g: dict) -> str:
    """Grounding as prompt text."""
    lines = ["Vulnerability-related statements (srcVul vr_stmts) from the source fix:"]
    lines += [f"  - removed: {s}" for s in g["vr_stmts_deleted"][:20]]
    lines += [f"  + added:   {s}" for s in g["vr_stmts_added"][:30]]
    lines.append("Vulnerability-related variables mapped to the target clone by slicing-vector similarity "
                 "(srcSlice profiles; cosine >= 0.8):")
    for m in g["mapping"]:
        if m["target_var"]:
            lines.append(f"  {m['source_var']} -> {m['target_var']} (similarity {m['similarity']}; "
                         f"target slice lines {m['target_slice_lines'][:15]})")
        else:
            lines.append(f"  {m['source_var']} -> no confident match in the target")
    return "\n".join(lines)
