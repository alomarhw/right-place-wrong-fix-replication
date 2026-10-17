"""Fetch a srcML source archive for each RQ1 item: the file that contains the vulnerable function and every C/C++
file in the same directory, at the vulnerable commit (the parent of the fix commit).

Inputs: data/bigvul/bigvul_pairs.jsonl and a codeLink map (commit -> Big-Vul codeLink) built from Big-Vul's metadata.
Output: data/archives/<commit>/<repo path...> plus data/archives/manifest.json (repo, fix commit, parent, file,
directory, files with SHA-256, or the reason an item could not be fetched).

Usage: python gpu/fetch_archives.py CODELINKS.json [--workers 8]
"""

import base64
import os
import hashlib
import json
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Archives can be large; RP_ARCHIVE_DIR keeps them outside a synced folder. The manifest is also copied to
# data/archives_manifest.json so the exact inputs are recorded with the package.
OUT = Path(os.environ.get("RP_ARCHIVE_DIR", ROOT / "data" / "archives"))
EXTS = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh")
MAX_FILES, MAX_BYTES = 400, 20_000_000

# Official mirrors for Big-Vul's non-GitHub hosts (same commit hashes).
MIRRORS = {"openssh.git": "openssh/openssh-portable", "samba.git": "samba-team/samba", "qemu.git": "qemu/qemu",
           "libksba.git": "gpg/libksba", "php-src.git": "php/php-src", "mupdf.git": "ArtifexSoftware/mupdf",
           "openssl.git": "openssl/openssl", "pcmanfm.git": "lxde/pcmanfm", "barebox": "barebox/barebox"}
FDO = {"xorg/lib/libXfont": "xorg/lib/libxfont", "xorg/xserver": "xorg/xserver", "dbus/dbus": "dbus/dbus",
       "accountsservice": "accountsservice/accountsservice"}


def http(url: str, raw: bool = False):
    import time
    req = urllib.request.Request(url, headers={"User-Agent": "replication-fetch"})
    for attempt in range(8):  # googlesource rate-limits bursts (HTTP 429): back off and retry
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                data = r.read()
            break
        except urllib.error.HTTPError as e:
            if e.code != 429 or attempt == 7:
                raise
            time.sleep(10 * (attempt + 1))
    return data if raw else data.decode("utf-8", "replace")


def gh(path: str):
    out = subprocess.run(["gh", "api", "-H", "Accept: application/vnd.github+json", path],
                         capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip()[:200])
    return json.loads(out.stdout)


def resolve(link: str):
    """codeLink -> (kind, repo, commit)."""
    m = re.match(r"https?://github\.com/([^/]+/[^/]+)/(?:commit|pull/\d+/commits)/([0-9a-f]{7,40})", link)
    if m:
        return "github", m.group(1), m.group(2)
    m = re.match(r"https?://android\.googlesource\.com/(.+?)/\+/([0-9a-f]{40})", link)
    if m:
        return "gsource", m.group(1), m.group(2)
    m = re.match(r"https?://cgit\.freedesktop\.org/(.+?)/commit/.*?id=([0-9a-f]{40})", link)
    if m and m.group(1) in FDO:
        return "gitlab", FDO[m.group(1)], m.group(2)
    sha = re.search(r"(?:[?;&]h=|[?&]id=)([0-9a-f]{40})", link)
    for key, mirror in MIRRORS.items():
        if key in link and sha:
            return "github", mirror, sha.group(1)
    raise ValueError(f"unsupported host: {link}")


class GitHub:
    def __init__(self, repo):
        self.repo = repo

    def commit(self, sha):
        c = gh(f"repos/{self.repo}/commits/{sha}")
        return c["parents"][0]["sha"], [f["filename"] for f in c.get("files", [])]

    def listdir(self, ref, d):
        items = gh(f"repos/{self.repo}/contents/{urllib.parse.quote(d)}?ref={ref}") if d else gh(f"repos/{self.repo}/contents?ref={ref}")
        return [x["path"] for x in items if x["type"] == "file"]

    def read(self, ref, path):
        return http(f"https://raw.githubusercontent.com/{self.repo}/{ref}/{urllib.parse.quote(path)}", raw=True)


class GSource:
    base = "https://android.googlesource.com"

    def __init__(self, repo):
        self.repo = repo

    def _json(self, url):
        return json.loads(http(url).split("\n", 1)[1])

    def commit(self, sha):
        c = self._json(f"{self.base}/{self.repo}/+/{sha}?format=JSON")
        return c["parents"][0], [d.get("new_path") or d.get("old_path") for d in c.get("tree_diff", [])]

    def listdir(self, ref, d):
        t = self._json(f"{self.base}/{self.repo}/+/{ref}/{d}?format=JSON")
        return [f"{d}/{e['name']}" if d else e["name"] for e in t.get("entries", []) if e.get("type") == "blob"]

    def read(self, ref, path):
        return base64.b64decode(http(f"{self.base}/{self.repo}/+/{ref}/{path}?format=TEXT"))


class GitLab:
    base = "https://gitlab.freedesktop.org/api/v4/projects/"

    def __init__(self, repo):
        self.pid = urllib.parse.quote(repo, safe="")

    def commit(self, sha):
        c = json.loads(http(f"{self.base}{self.pid}/repository/commits/{sha}"))
        diff = json.loads(http(f"{self.base}{self.pid}/repository/commits/{sha}/diff?per_page=100"))
        return c["parent_ids"][0], [d["new_path"] for d in diff]

    def listdir(self, ref, d):
        q = f"?ref={ref}&per_page=100" + (f"&path={urllib.parse.quote(d)}" if d else "")
        return [x["path"] for x in json.loads(http(f"{self.base}{self.pid}/repository/tree{q}")) if x["type"] == "blob"]

    def read(self, ref, path):
        return http(f"{self.base}{self.pid}/repository/files/{urllib.parse.quote(path, safe='')}/raw?ref={ref}", raw=True)


def func_name(code: str) -> str:
    """Name of the defined function: the identifier before the parameter list that closes the signature
    (skips constructor initializer lists and macros inside parameter types such as Elf_(Shdr))."""
    head = code.split("{", 1)[0]
    m = re.search(r"\)\s*:\s*[A-Za-z_]", head)  # constructor initializer list
    if m:
        head = head[: m.start() + 1]
    end = head.rfind(")")
    if end < 0:
        return ""
    depth = 0
    for i in range(end, -1, -1):
        depth += head[i] == ")"; depth -= head[i] == "("
        if depth == 0:
            name = re.search(r"([A-Za-z_~][\w]*)\s*$", head[:i])
            return name.group(1) if name else ""
    return ""


def _sig(code: str) -> str:
    return re.sub(r"\s+", "", code.split("{", 1)[0])[:160]


def fetch(item: dict, link: str) -> dict:
    sha = item["commit_id"]; rec = {"commit_id": sha, "cve_id": item.get("cve_id"), "codeLink": link}
    try:
        kind, repo, sha = resolve(link)
        src = {"github": GitHub, "gsource": GSource, "gitlab": GitLab}[kind](repo)
        parent, changed = src.commit(sha)
        name = func_name(item["func_before"])
        # Prefer the file holding the definition (its normalized signature), source files before headers.
        cands = sorted((f for f in changed if f and f.endswith(EXTS)), key=lambda f: f.endswith((".h", ".hpp", ".hh")))
        target, sig, loose = None, _sig(item["func_before"]), None
        for f in cands:
            try:
                text = src.read(parent, f).decode("utf-8", "replace")
            except Exception:
                continue
            if sig and sig in re.sub(r"\s+", "", text):
                target = f; break
            if loose is None and name and re.search(r"\b" + re.escape(name) + r"\s*\(", text):
                loose = f
        target = target or loose
        if target is None:
            raise LookupError(f"function {name!r} not found in changed files {cands[:5]}")
        d = target.rsplit("/", 1)[0] if "/" in target else ""
        files = sorted(f for f in src.listdir(parent, d) if f.endswith(EXTS))
        files = [target] + [f for f in files if f != target][: MAX_FILES - 1]
        dst = OUT / sha; total, saved = 0, []
        for f in files:
            data = src.read(parent, f); total += len(data)
            if total > MAX_BYTES:
                break
            p = dst / f; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(data)
            saved.append({"path": f, "sha256": hashlib.sha256(data).hexdigest()})
        rec.update({"ok": True, "kind": kind, "repo": repo, "parent": parent, "file": target, "dir": d,
                    "function": name, "files": saved, "truncated": len(saved) < len(files)})
    except Exception as e:  # recorded, never silently dropped
        rec.update({"ok": False, "error": f"{type(e).__name__}: {e}"[:300]})
    return rec


def main() -> int:
    links = json.loads(Path(sys.argv[1]).read_text())
    workers = int(sys.argv[sys.argv.index("--workers") + 1]) if "--workers" in sys.argv else 8
    items = [json.loads(l) for l in open(ROOT / "data" / "bigvul" / "bigvul_pairs.jsonl")]
    OUT.mkdir(parents=True, exist_ok=True)
    prev = {}
    if (OUT / "manifest.json").exists() and "--retry-failed" in sys.argv:  # keep fetched items, redo failures
        redo = set(Path(sys.argv[sys.argv.index("--redo") + 1]).read_text().split()) if "--redo" in sys.argv else set()
        prev = {r["commit_id"]: r for r in json.loads((OUT / "manifest.json").read_text())
                if r.get("ok") and r["commit_id"] not in redo}
    todo = [it for it in items if it["commit_id"] not in prev]
    with ThreadPoolExecutor(workers) as ex:
        new = dict(zip([it["commit_id"] for it in todo], ex.map(lambda it: fetch(it, links[it["commit_id"]]), todo)))
    recs = [prev.get(it["commit_id"]) or new[it["commit_id"]] for it in items]
    (OUT / "manifest.json").write_text(json.dumps(recs, indent=1))
    (ROOT / "data" / "archives_manifest.json").write_text(json.dumps(recs, indent=1))
    ok = [r for r in recs if r["ok"]]
    print(f"fetched {len(ok)}/{len(recs)} items; files {sum(len(r['files']) for r in ok)}")
    for r in recs:
        if not r["ok"]:
            print("  FAIL", r["commit_id"][:10], r["error"][:150])
    return 0


if __name__ == "__main__":
    sys.exit(main())
