"""Mine post-cutoff CVE fixes that were applied on several maintained release branches.

Each branch's copy of a vulnerable function is a real clone, with its own official fix (the
branch's backport). Same CVE + same function on >= 2 branches = one clone family. The first branch
in BRANCH_ORDER that has the fix is the *source* (its vulnerable/fixed pair plays the role of the
known vulnerability in srcVul's database); every other branch is a *target* clone to patch.

Per target we record:
  clone_type   identical (Type-1, normalized text equal), renamed (Type-2, equal after identifier
               abstraction), modified (Type-3)
  naive_port   does the source fix apply as a plain line-based patch, and does the result equal the
               target's official fix? (the trivial baseline an agent must beat)

Output: porting/backport_families.jsonl + porting/backport_log.json
"""
from __future__ import annotations

import difflib, json, re, sys, time, urllib.request
from collections import defaultdict
from pathlib import Path
import os

HERE = Path(os.environ.get("RP_MINING_ROOT", Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from mine_postcutoff import functions, sh, CVE_RE  # noqa: E402  (VUDDY FuncParser extraction)

CUTOFF = "2025-08-01"
BRANCH_ORDER = {
    "openssl": ["master", "openssl-3.6", "openssl-3.5", "openssl-3.4", "openssl-3.3", "openssl-3.2", "openssl-3.0"],
    "php-src": ["master", "PHP-8.5", "PHP-8.4", "PHP-8.3", "PHP-8.2", "PHP-8.1"],
    "FFmpeg": ["master", "release/8.1", "release/8.0", "release/7.1", "release/7.0"],
}
CLONES = HERE / "clones"
OUT = HERE / "porting"
_CVE_CACHE: dict = {}


def cve_published(cve: str) -> str:
    if cve in _CVE_CACHE:
        return _CVE_CACHE[cve]
    pub = ""
    for _ in range(3):
        try:
            with urllib.request.urlopen(f"https://cveawg.mitre.org/api/cve/{cve}", timeout=30) as r:
                d = json.load(r)
            m = d.get("cveMetadata", {})
            pub = (m.get("datePublished") or "")[:10] if m.get("state") == "PUBLISHED" else ""
            break
        except Exception:  # noqa: BLE001
            time.sleep(2)
    _CVE_CACHE[cve] = pub
    return pub


def norm(code: str) -> str:
    code = re.sub(r"/\*.*?\*/|//[^\n]*", " ", code, flags=re.S)
    return "\n".join(re.sub(r"\s+", " ", l).strip() for l in code.splitlines() if l.strip())


def abstract(code: str) -> str:
    kw = r"\b(?:if|else|for|while|do|return|switch|case|break|continue|goto|sizeof|struct|const|static|unsigned|signed|int|char|void|long|short)\b"
    s = norm(code)
    s = re.sub(r"\b[A-Za-z_]\w*\b", lambda m: m.group(0) if re.fullmatch(kw, m.group(0)) else "ID", s)
    return s


def clone_type(src_vuln: str, tgt_vuln: str) -> str:
    if norm(src_vuln) == norm(tgt_vuln):
        return "identical"
    if abstract(src_vuln) == abstract(tgt_vuln):
        return "renamed"
    return "modified"


def naive_port(src_vuln: str, src_fixed: str, tgt_vuln: str) -> tuple[bool, str]:
    """Apply the source fix's line hunks to the target by exact context match (like `patch` with no
    fuzz). Returns (applied, patched_text)."""
    a, b, t = [l.rstrip() for l in src_vuln.splitlines()], [l.rstrip() for l in src_fixed.splitlines()], \
              [l.rstrip() for l in tgt_vuln.splitlines()]
    out, ti = [], 0
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        # locate the source lines a[i1:i2] (or the anchor line before an insertion) in the target
        anchor = a[i1:i2] if i2 > i1 else a[max(0, i1 - 1):i1]
        if not anchor:
            return False, ""
        pos = next((k for k in range(ti, len(t) - len(anchor) + 1)
                    if [x.strip() for x in t[k:k + len(anchor)]] == [x.strip() for x in anchor]), None)
        if pos is None:
            return False, ""
        if i2 > i1:
            out += t[ti:pos] + b[j1:j2]
            ti = pos + len(anchor)
        else:
            out += t[ti:pos + 1] + b[j1:j2]
            ti = pos + 1
    out += t[ti:]
    return True, "\n".join(out)


def changed_functions(repo: Path, commit: str, parent: str) -> dict:
    """{(file, func): (before, after)} for every C function whose body the commit changes."""
    res = {}
    files = [f for f in sh(["git", "diff", "--name-only", parent, commit], cwd=repo).stdout.decode().split()
             if f.endswith(".c") and "/test" not in f and not f.startswith("test")]
    for path in files:
        old = sh(["git", "show", f"{parent}:{path}"], cwd=repo, check=False).stdout
        new = sh(["git", "show", f"{commit}:{path}"], cwd=repo, check=False).stdout
        if not old or not new:
            continue
        fo, fn = functions(old), functions(new)
        for name in fo.keys() & fn.keys():
            bfr, aft = fo[name], fn[name]
            if norm(bfr) != norm(aft) and 3 <= bfr.count("\n") + 1 <= 200:
                res[(path, name)] = (bfr, aft)
    return res


def main() -> None:
    OUT.mkdir(exist_ok=True)
    log, families = {}, []
    for proj, branches in BRANCH_ORDER.items():
        repo = CLONES / proj
        per = defaultdict(dict)  # (cve, func) -> branch -> record
        stats = {}
        for br in branches:
            ref = f"origin/{br}"
            raw = sh(["git", "log", ref, f"--since={CUTOFF}", "-E", "-i", "--grep=CVE-20[0-9]{2}-[0-9]+",
                      "--format=%H%x1f%P%x1f%B%x1e"], cwd=repo, check=False).stdout.decode("utf-8", "ignore")
            commits = [c.strip().split("\x1f") for c in raw.split("\x1e") if c.strip()]
            stats[br] = len(commits)
            for h, parents, msg in commits:
                par = parents.split()
                if len(par) != 1:
                    continue
                cves = list(dict.fromkeys(c.upper() for c in CVE_RE.findall(msg.upper())))
                if len(cves) != 1:
                    continue  # ambiguous commit: skip
                cve = cves[0]
                for (path, name), (bfr, aft) in changed_functions(repo, h, par[0]).items():
                    per[(cve, name)].setdefault(br, {"branch": br, "commit": h, "file": path,
                                                      "func_before": bfr, "func_after": aft})
        fam_n = 0
        for (cve, name), by_br in per.items():
            if len(by_br) < 2:
                continue
            pub = cve_published(cve)
            if not pub or pub < CUTOFF:
                continue
            order = [b for b in branches if b in by_br]
            src = by_br[order[0]]
            targets = []
            for br in order[1:]:
                t = by_br[br]
                ok, ported = naive_port(src["func_before"], src["func_after"], t["func_before"])
                targets.append({**t, "clone_type": clone_type(src["func_before"], t["func_before"]),
                                "naive_port_applies": ok,
                                "naive_port_equals_official": bool(ok and norm(ported) == norm(t["func_after"]))})
            families.append({"project": proj, "cve_id": cve, "cve_published": pub, "function": name,
                             "source": src, "targets": targets})
            fam_n += 1
        log[proj] = {"cve_commits_per_branch": stats, "families": fam_n}
        print(f"[{proj}] {log[proj]}", flush=True)
    with open(OUT / "backport_families.jsonl", "w") as f:
        for fam in sorted(families, key=lambda x: (x["project"], x["cve_id"], x["function"])):
            f.write(json.dumps(fam) + "\n")
    tg = [t for fam in families for t in fam["targets"]]
    summary = {"families": len(families), "targets": len(tg),
               "clone_type": {k: sum(t["clone_type"] == k for t in tg) for k in ("identical", "renamed", "modified")},
               "naive_port_applies": sum(t["naive_port_applies"] for t in tg),
               "naive_port_equals_official": sum(t["naive_port_equals_official"] for t in tg),
               "cves": len({f["cve_id"] for f in families})}
    log["summary"] = summary
    (OUT / "backport_log.json").write_text(json.dumps(log, indent=2))
    print("SUMMARY", json.dumps(summary), flush=True)


if __name__ == "__main__":
    main()
