"""srcslice_inter.py -- interprocedural srcSlice slices over a source archive.

srcML converts the whole archive (with --position) and srcSlice computes a forward slice profile for every
variable in it: def and use lines, dependent variables (dvars), aliases (pointers), and the called functions with
the argument position each variable is passed in (cfuncs, e.g. memcpy{3}). The slice of a function is built from
its seed variables:
  - the seed's def/use lines inside the function (srcSlice also folds callee lines into a caller's use set, but
    without a file name, so lines outside the function's own span are taken from the callee profiles instead);
  - closure over dvars and pointers within the function;
  - for every cfuncs entry f{k} whose callee f is defined in the archive, the slice of f's k-th parameter, followed
    transitively up to MAX_DEPTH, each callee line keeping its own file.
Seeds use the same sink criterion as data_prep.extract_slice (identifiers on sink statements), so the only
difference from the identifier slice is how the slice is computed.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from data_prep import SINK_PATTERNS

MAX_DEPTH = 3
MAX_CALLEE_LINES = 60
POS = "{http://www.srcML.org/srcML/position}"
SRC = "{http://www.srcML.org/srcML/src}"
_KEYWORDS = {"if", "else", "for", "while", "do", "return", "sizeof", "switch", "case", "break", "continue",
             "int", "char", "unsigned", "signed", "long", "short", "void", "const", "static", "struct", "NULL",
             "goto", "default", "float", "double", "size_t", "bool", "true", "false", "enum", "union"}
_LINE = re.compile(r"^(.*?),([^,]*),([^,]*),def\{(.*?)\},use\{(.*?)\},dvars\{(.*?)\},pointers\{(.*?)\},cfuncs\{(.*)\}$")


@dataclass
class Func:
    file: str
    name: str
    start: int
    end: int
    params: list = field(default_factory=list)
    qual: str = ""
    sname: str = ""  # the function's name in srcSlice's output (C++ methods: class and method joined)


@dataclass
class Archive:
    root: Path
    profiles: dict      # (file, func, var) -> {"def", "use", "dvars", "pointers", "cfuncs"}
    functions: dict     # name -> [Func]
    lines: dict         # file -> list of source lines


def _nums(s: str) -> set:
    return {int(x) for x in re.findall(r"\d+", s)}


def _names(s: str) -> list:
    return [x for x in re.split(r"\s*,\s*", s.strip()) if x]


def _norm(path: str, root: str = "") -> str:
    """Archive-relative path (srcML records absolute paths when given a directory)."""
    if root and path.startswith(root):
        path = path[len(root):].lstrip("/")
    return path[2:] if path.startswith("./") else path


def _text(el) -> str:
    return "".join(el.itertext()).strip()


def build(root: Path) -> Archive:
    """srcML (--position) the archive, run srcSlice once, and index profiles and function spans."""
    root = Path(root).resolve(); rs = str(root)
    with tempfile.TemporaryDirectory() as td:
        xml = Path(td) / "archive.xml"
        subprocess.run(["srcml", "--position", ".", "-o", str(xml)], cwd=root, check=True,
                       capture_output=True, timeout=1800)
        out = subprocess.run(["srcslice", str(xml)], capture_output=True, text=True, timeout=1800).stdout
        tree = ET.parse(xml)
    profiles = {}
    for ln in out.splitlines():
        m = _LINE.match(ln.strip())
        if not m:
            continue
        f, fn, var, d, u, dv, ptr, cf = m.groups()
        profiles[(_norm(f, rs), fn, var)] = {"def": _nums(d), "use": _nums(u), "dvars": _names(dv),
                                         "pointers": _names(ptr),
                                         "cfuncs": [(a, int(b)) for a, b in re.findall(r"([\w:~]+)\{(\d+)\}", cf)]}
    functions: dict = {}
    for unit in tree.getroot().iter(f"{SRC}unit"):
        fname = unit.get("filename")
        if not fname:
            continue
        fname = _norm(fname, rs)
        for tag in ("function", "constructor", "destructor"):
            for el in unit.iter(f"{SRC}{tag}"):
                name_el = el.find(f"{SRC}name")
                if name_el is None:
                    continue
                qual = re.sub(r"\s+", "", _text(name_el)); name = qual.split("::")[-1]
                try:
                    start = int(el.get(f"{POS}start").split(":")[0]); end = int(el.get(f"{POS}end").split(":")[0])
                except (AttributeError, ValueError):
                    continue
                params = []
                plist = el.find(f"{SRC}parameter_list")
                if plist is not None:
                    for prm in plist.findall(f"{SRC}parameter"):
                        names = [n for n in prm.iter(f"{SRC}name")]
                        params.append(_text(names[-1]) if names else "")
                functions.setdefault(name, []).append(Func(fname, name, start, end, params, qual))
    have = {(k[0], k[1]) for k in profiles}
    for fs in functions.values():
        for fn in fs:
            joined = fn.qual.replace("::", "")
            for cand in (joined, f"{joined}{fn.start}", fn.name, f"{fn.name}{fn.start}"):
                if (fn.file, cand) in have:
                    fn.sname = cand
                    break
    lines = {}
    for f in {k[0] for k in profiles} | {fn.file for fs in functions.values() for fn in fs}:
        p = root / f
        if p.exists():
            lines[f] = p.read_text(errors="replace").splitlines()
    return Archive(root, profiles, functions, lines)


def _find(arch: Archive, name: str, prefer_file: str | None = None) -> Func | None:
    cands = arch.functions.get(name, [])
    for c in cands:
        if c.file == prefer_file:
            return c
    return cands[0] if cands else None


def seeds(code_lines: list[str]) -> list[str]:
    """Identifiers on sink statements, as in data_prep.extract_slice (keywords removed)."""
    sink = [ln for ln in code_lines if any(re.search(p, ln) for p in SINK_PATTERNS)]
    if not sink:
        sink = [ln for ln in code_lines if "=" in ln or "(" in ln]
    out = []
    for ln in sink:
        for tok in re.findall(r"[A-Za-z_]\w*", ln):
            if tok not in _KEYWORDS and tok not in out:
                out.append(tok)
    return out


def slice_function(arch: Archive, file: str, func: str) -> dict:
    """Interprocedural slice of `func` (defined in `file`); returns local lines, callee slices and text."""
    fn = _find(arch, func, file)
    if fn is None:
        return {"ok": False, "reason": "function not found in archive"}
    src = arch.lines.get(fn.file, [])
    body = src[fn.start - 1: fn.end]
    seed_vars = [v for v in seeds(body) if (fn.file, fn.sname, v) in arch.profiles]
    if not seed_vars:
        return {"ok": False, "reason": "no seed variable has a srcSlice profile"}
    picked: dict = {}  # (file, func) -> set(lines)
    queue = deque((fn.file, fn.sname, v, 0) for v in seed_vars)
    byname = {(f.file, f.sname): f for fs in arch.functions.values() for f in fs if f.sname}
    seen = set()
    while queue:
        f, g, v, depth = queue.popleft()
        if (f, g, v) in seen:
            continue
        seen.add((f, g, v))
        prof = arch.profiles.get((f, g, v))
        span = byname.get((f, g))
        if prof is None or span is None:
            continue
        own = {n for n in prof["def"] | prof["use"] if span.start <= n <= span.end}
        picked.setdefault((f, g), set()).update(own)
        for w in prof["dvars"] + prof["pointers"]:
            queue.append((f, g, w, depth))
        if depth >= MAX_DEPTH:
            continue
        for callee, k in prof["cfuncs"]:
            c = _find(arch, callee, f)
            if c is None or not (0 < k <= len(c.params)) or not c.params[k - 1]:
                continue
            if not c.sname:
                continue
            picked.setdefault((c.file, c.sname), set()).add(c.start)  # keep the callee's signature line
            queue.append((c.file, c.sname, c.params[k - 1], depth + 1))
    local = sorted(picked.pop((fn.file, fn.sname), set()))
    callees = []
    for (f, g), ls in sorted(picked.items()):
        text = [arch.lines[f][n - 1].rstrip() for n in sorted(ls) if f in arch.lines and n <= len(arch.lines[f])]
        callees.append({"file": f, "function": byname[(f, g)].qual if (f, g) in byname else g, "lines": sorted(ls), "text": text})
    return {"ok": True, "function": {"file": fn.file, "start": fn.start, "end": fn.end}, "seeds": seed_vars,
            "local_lines": local, "local_text": [src[n - 1].strip() for n in local if n <= len(src)],
            "callees": callees}


def render(sl: dict) -> str:
    """Prompt text: the function's slice statements, then each callee's slice labelled file:function."""
    out = list(sl["local_text"])
    budget = MAX_CALLEE_LINES
    for c in sl["callees"]:
        if budget <= 0:
            break
        out.append(f"/* called function {c['function']} ({c['file']}) */")
        out += [t.strip() for t in c["text"][:budget]]
        budget -= len(c["text"])
    return "\n".join(out)


def render_callees_unsliced(arch: Archive, sl: dict) -> str:
    """Control (A3c): the full text of the same callee functions, without slicing."""
    out, budget = [], 4 * MAX_CALLEE_LINES
    for c in sl["callees"]:
        fn = _find(arch, c["function"].split("::")[-1], c["file"])
        if fn is None or budget <= 0:
            continue
        body = arch.lines.get(fn.file, [])[fn.start - 1: fn.end][:budget]
        out.append(f"/* called function {fn.name} ({fn.file}) */")
        out += [b.rstrip() for b in body]
        budget -= len(body)
    return "\n".join(out)
