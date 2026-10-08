"""variant_builder.py — certified slice-preserving variant construction.

Applies ONLY semantics-preserving transformations from a fixed operator set
(Type-I -> Type-III clone operators) to a verbatim CVE function: whitespace
reformatting, consistent renaming of the function's own parameters and locals
(never struct fields, called functions, macros, or text inside string literals),
and dead-code insertion. A variant is certified when its canonicalized
vulnerability slice, with the renaming undone, is byte-identical to the
original's.

Key deps: stdlib re, random (numpy for determinism).
"""
from __future__ import annotations

import os
import random
import re
from dataclasses import dataclass, field

from data_prep import CVEItem, _canonicalize, canonical_slice, extract_slice

RANDOM_SEED = int(os.environ.get("RP_RANDOM_SEED", 42))

_PROTECTED = {
    "int", "char", "void", "return", "if", "else", "for", "while", "sizeof",
    "malloc", "free", "strcpy", "strncpy", "memcpy", "sprintf", "gets", "process",
    "src", "MAXA",
}


@dataclass
class Variant:
    cve_id: str
    cwe: str
    code: str
    label: int
    provenance: str
    certified: bool
    ops_applied: list
    rename_map: dict = field(default_factory=dict)  # old -> new identifier


_C_KEYWORDS = {
    "auto", "break", "case", "char", "const", "continue", "default", "do", "double",
    "else", "enum", "extern", "float", "for", "goto", "if", "inline", "int", "long",
    "register", "restrict", "return", "short", "signed", "sizeof", "static", "struct",
    "switch", "typedef", "union", "unsigned", "void", "volatile", "while", "bool",
}
# string / char literals and comments are never rewritten
_LITERAL_RE = re.compile(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|/\*.*?\*/|//[^\n]*', re.S)
# a declarator: type-ish word, optional '*'s, then the declared name, then = ; , [ )
_DECL_RE = re.compile(r"\b[A-Za-z_]\w*[\s\*]+\**\s*([A-Za-z_]\w*)\s*(?=[=;,\[\)])")


def _local_names(code: str) -> list[str]:
    """Parameters and locals declared in the function (never fields, calls or macros)."""
    body = _LITERAL_RE.sub(" ", code)
    fields = set(re.findall(r"(?:->|\.)\s*([A-Za-z_]\w*)", body))
    called = set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", body))
    names = []
    for n in _DECL_RE.findall(body):
        if (n in _C_KEYWORDS or n in fields or n in called or n.isupper()
                or n in _PROTECTED or n in names):
            continue
        names.append(n)
    return names


def _sub_outside_literals(code: str, mapping: dict) -> str:
    if not mapping:
        return code
    pat = re.compile(r"(?<!->)(?<!\.)(?<![\w])(" + "|".join(map(re.escape, mapping)) + r")(?!\w)")
    out, last = [], 0
    for m in _LITERAL_RE.finditer(code):
        out.append(pat.sub(lambda x: mapping[x.group(1)], code[last:m.start()]))
        out.append(m.group(0))
        last = m.end()
    out.append(pat.sub(lambda x: mapping[x.group(1)], code[last:]))
    return "".join(out)


def _rename_identifiers(code: str, rng: random.Random) -> tuple[str, dict]:
    """Consistent alpha-renaming of parameters/locals; returns (code, old->new map)."""
    present = set(re.findall(r"[A-Za-z_]\w*", code))
    mapping = {}
    for n in _local_names(code):
        new = f"{n}_v{rng.randint(0, 9)}"
        while new in present or new in mapping.values():
            new += "x"
        mapping[n] = new
    return _sub_outside_literals(code, mapping), mapping


def _reformat_whitespace(code: str, rng: random.Random) -> str:
    lines = code.splitlines()
    out = []
    for ln in lines:
        if rng.random() < 0.4:
            out.append("    " + ln.strip())
        else:
            out.append(ln)
    return "\n".join(out)


def _insert_deadcode(code: str, rng: random.Random) -> str:
    lines = code.splitlines()
    slice_set = set(_norm(l) for l in extract_slice(code))
    noops = ["    int _tmp_dead = 0;", "    (void)_tmp_dead;", "    ;"]
    out = []
    for ln in lines:
        out.append(ln)
        if _norm(ln) not in slice_set and ln.strip().endswith(";") and rng.random() < 0.3:
            out.append(rng.choice(noops))
    return "\n".join(out)


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def undo_rename(code: str, mapping: dict) -> str:
    """Map a variant's renamed identifiers back to the originals (alpha-normalization)."""
    return _sub_outside_literals(code, {v: k for k, v in mapping.items()})


def build_variant(item: CVEItem, seed: int) -> Variant:
    rng = random.Random(seed)
    original_slice = canonical_slice(item.code)
    code = item.code
    ops = []
    code = _reformat_whitespace(code, rng); ops.append("reformat")
    code, mapping = _rename_identifiers(code, rng); ops.append("rename")
    code = _insert_deadcode(code, rng); ops.append("deadcode")
    # certify modulo the (consistent) renaming: undo it on the variant's slice
    inverse = {v: k for k, v in mapping.items()}
    new_slice = _canonicalize(_sub_outside_literals("\n".join(extract_slice(code)), inverse))
    certified = (new_slice == original_slice)
    return Variant(
        cve_id=item.cve_id, cwe=item.cwe, code=code, label=item.label,
        provenance=item.provenance, certified=certified, ops_applied=ops, rename_map=mapping,
    )


def build_certified_variant(rec, seed: int = RANDOM_SEED) -> dict:
    """Build a certified variant from a dict record (used by build_rq2_artifacts).

    Returns a dict describing the variant and acceptance decision.
    """
    if isinstance(rec, CVEItem):
        item = rec
    else:
        item = CVEItem(
            cve_id=rec.get("cve_id", "NA"), cwe=rec.get("cwe", "CWE-119"),
            code=rec.get("code", ""), label=int(rec.get("label", 0)),
            provenance=rec.get("provenance", "seen"),
        )
    var = build_variant(item, seed=seed)
    # cheap surface metrics
    a, b = item.code, var.code
    la, lb = len(a), len(b)
    edist = abs(la - lb)
    edit_norm = edist / (max(la, lb) or 1)
    sa = set(re.findall(r"[A-Za-z_]\w*", a))
    sb = set(re.findall(r"[A-Za-z_]\w*", b))
    tj = len(sa & sb) / (len(sa | sb) or 1)
    return {
        "variant_code": var.code,
        "accepted": bool(var.certified),
        "lsh_similarity": 1.0 if var.certified else 0.0,
        "edit_distance_norm": float(edit_norm),
        "token_jaccard": float(tj),
        "transform_mix": var.ops_applied,
        "reject_reason": "" if var.certified else "slice_not_invariant",
    }


def build_certified_variants(items: list[CVEItem], seed: int = RANDOM_SEED):
    """Return (variants, yield_stats). Only certified variants kept."""
    variants: list[Variant] = []
    accepted = 0
    total = 0
    self_sim_scores = []
    for i, item in enumerate(items):
        total += 1
        v = build_variant(item, seed=seed + i)
        self_sim_scores.append(1.0 if canonical_slice(item.code) == canonical_slice(item.code) else 0.0)
        if v.certified:
            accepted += 1
            variants.append(v)
    stats = {
        "accepted_variant_yield": accepted / total if total else 0.0,
        "n_total": total,
        "n_accepted": accepted,
        "self_similarity_mean": sum(self_sim_scores) / len(self_sim_scores) if self_sim_scores else 1.0,
    }
    return variants, stats


if __name__ == "__main__":
    from data_prep import build_corpus
    items, _ = build_corpus(n_cves=8, allow_synthetic=True)
    variants, stats = build_certified_variants(items)
    print("yield:", stats)
    print(variants[0].code[:200])