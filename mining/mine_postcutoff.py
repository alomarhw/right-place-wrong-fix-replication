"""Mine post-cutoff CVE vulnerable/fixed C function pairs (project 7Ac77, 'unseen' set).

Method (VUDDY-style, using VUDDY's own FuncParser-opt.jar for function extraction):
  1. Blobless, shallow clone of active C projects (history since 2025-06-01).
  2. Commits after CUTOFF whose message names a CVE id.
  3. For each changed .c file, parse the parent and fixed versions with FuncParser and pair
     functions by name; keep the function whose body changed most (5-120 lines).
  4. Look up the CVE record (cveawg.mitre.org) for datePublished and CWE; keep the pair only if
     the CVE was PUBLISHED on/after CUTOFF (after the detector model's training data).
Output: postcutoff/postcutoff_pairs.jsonl (one pair per CVE) and postcutoff/mining_log.json.
"""
import difflib, json, os, re, subprocess, sys, tempfile, time, urllib.request
from pathlib import Path

CUTOFF = "2025-08-01"
REPOS = {
    "curl": "https://github.com/curl/curl.git",
    "libxml2": "https://gitlab.gnome.org/GNOME/libxml2.git",
    "openssl": "https://github.com/openssl/openssl.git",
    "ImageMagick": "https://github.com/ImageMagick/ImageMagick.git",
    "libexpat": "https://github.com/libexpat/libexpat.git",
    "radare2": "https://github.com/radareorg/radare2.git",
    "php-src": "https://github.com/php/php-src.git",
    "cpython": "https://github.com/python/cpython.git",
    "vim": "https://github.com/vim/vim.git",
    "libssh2": "https://github.com/libssh2/libssh2.git",
    "mruby": "https://github.com/mruby/mruby.git",
    "FFmpeg": "https://github.com/FFmpeg/FFmpeg.git",
}
HERE = Path(os.environ.get("RP_MINING_ROOT", Path(__file__).resolve().parent))
JAR = HERE / "vuddy" / "hmark" / "FuncParser-opt.jar"
CLONES = HERE / "clones"
OUT = HERE / "postcutoff"
DELIM = b"\r\0?\r?\0\r"
CVE_RE = re.compile(r"CVE-20\d\d-\d{4,7}")


def sh(args, cwd=None, check=True, timeout=1800):
    return subprocess.run(args, cwd=cwd, capture_output=True, check=check, timeout=timeout)


def functions(src: bytes) -> dict:
    """name -> source text, via VUDDY's FuncParser (line ranges sliced from the file)."""
    with tempfile.NamedTemporaryFile(suffix=".c", delete=False) as f:
        f.write(src)
        path = f.name
    try:
        out = sh(["java", "-Xmx1024m", "-jar", str(JAR), path, "0"], check=False, timeout=120).stdout
    finally:
        os.unlink(path)
    lines = src.decode("utf-8", "ignore").split("\n")
    res = {}
    for block in out.split(DELIM)[1:]:
        el = block.split(b"\n")[1:-1]
        if len(el) > 9:
            try:
                name = el[2].decode("utf-8", "ignore")
                s, e = (int(x) for x in el[3].split(b"\t")[:2])
            except ValueError:
                continue
            res.setdefault(name, "\n".join(lines[s - 1:e]))
    return res


def cve_record(cve: str) -> dict:
    url = f"https://cveawg.mitre.org/api/cve/{cve}"
    for _ in range(3):
        try:
            with urllib.request.urlopen(url, timeout=30) as r:
                d = json.load(r)
            meta = d.get("cveMetadata", {})
            cwes = []
            for c in [d.get("containers", {}).get("cna", {})] + d.get("containers", {}).get("adp", []):
                for pt in c.get("problemTypes", []) or []:
                    for desc in pt.get("descriptions", []) or []:
                        if desc.get("cweId"):
                            cwes.append(desc["cweId"])
            return {"state": meta.get("state"), "published": (meta.get("datePublished") or "")[:10],
                    "cwe": cwes[0] if cwes else ""}
        except Exception:
            time.sleep(2)
    return {}


def main():
    CLONES.mkdir(exist_ok=True)
    OUT.mkdir(exist_ok=True)
    log, pairs, done_cves = {}, [], set()
    for name, url in REPOS.items():
        repo = CLONES / name
        try:
            if not repo.exists():
                sh(["git", "clone", "-q", "--filter=blob:none", "--single-branch",
                    "--shallow-since=2025-06-01", url, str(repo)])
            fmt = "%H%x1f%cI%x1f%P%x1f%B%x1e"
            raw = sh(["git", "log", f"--since={CUTOFF}", "-E", "-i", "--grep=CVE-20[0-9]{2}-[0-9]+",
                      f"--format={fmt}"], cwd=repo).stdout.decode("utf-8", "ignore")
        except Exception as exc:
            log[name] = {"error": f"{type(exc).__name__}: {str(exc)[:200]}"}
            print(f"[{name}] clone/log failed: {exc}", flush=True)
            continue
        commits = [c.strip().split("\x1f") for c in raw.split("\x1e") if c.strip()]
        stats = {"cve_commits": len(commits), "pairs": 0, "skipped": {}}
        for h, date, parents, msg in commits:
            cves = [c.upper() for c in dict.fromkeys(CVE_RE.findall(msg.upper()))]
            par = parents.split()
            if len(par) != 1 or not cves:
                stats["skipped"]["merge_or_nocve"] = stats["skipped"].get("merge_or_nocve", 0) + 1
                continue
            cve = next((c for c in cves if c not in done_cves), None)
            if cve is None:
                continue
            files = [f for f in sh(["git", "diff", "--name-only", par[0], h], cwd=repo).stdout.decode().split()
                     if f.endswith(".c")]
            best = None
            for path in files:
                old = sh(["git", "show", f"{par[0]}:{path}"], cwd=repo, check=False).stdout
                new = sh(["git", "show", f"{h}:{path}"], cwd=repo, check=False).stdout
                if not old or not new:
                    continue
                fo, fn = functions(old), functions(new)
                for fname in fo.keys() & fn.keys():
                    b, a = fo[fname], fn[fname]
                    if b.strip() == a.strip() or not (5 <= b.count("\n") + 1 <= 120):
                        continue
                    changed = sum(1 for d in difflib.ndiff(b.splitlines(), a.splitlines()) if d[:1] in "+-")
                    if best is None or changed > best[0]:
                        best = (changed, path, fname, b, a)
            if best is None:
                stats["skipped"]["no_function_pair"] = stats["skipped"].get("no_function_pair", 0) + 1
                continue
            rec = cve_record(cve)
            if rec.get("state") != "PUBLISHED" or not rec.get("published") or rec["published"] < CUTOFF:
                stats["skipped"]["published_before_cutoff_or_unknown"] = \
                    stats["skipped"].get("published_before_cutoff_or_unknown", 0) + 1
                continue
            done_cves.add(cve)
            pairs.append({"cve_id": cve, "cwe": rec.get("cwe") or "CWE-unknown", "project": name,
                          "commit_id": h, "commit_date": date[:10], "cve_published": rec["published"],
                          "file": best[1], "function": best[2], "func_before": best[3], "func_after": best[4],
                          "provenance": "post_cutoff", "source": f"mined from {url} (VUDDY FuncParser)"})
            stats["pairs"] += 1
        log[name] = stats
        print(f"[{name}] {stats}", flush=True)
    with open(OUT / "postcutoff_pairs.jsonl", "w") as f:
        for p in sorted(pairs, key=lambda x: x["cve_id"]):
            f.write(json.dumps(p) + "\n")
    (OUT / "mining_log.json").write_text(json.dumps({"cutoff": CUTOFF, "repos": log,
                                                     "total_pairs": len(pairs)}, indent=2))
    print(f"TOTAL post-cutoff pairs: {len(pairs)}", flush=True)


if __name__ == "__main__":
    main()
