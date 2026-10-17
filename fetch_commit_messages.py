"""fetch_commit_messages.py -- the developer's description of each fix (its commit message), code removed.

For every RQ1 CVE (150 Big-Vul, 56 post-cutoff) fetch the fix commit's message from the project's host and
clean it so that it DESCRIBES the remedy without CONTAINING it:
  - diff-like lines (leading +/-/@@, code fences, lines ending in ';' or '{' or '}') are dropped;
  - trailers (Signed-off-by, Reviewed-by, Change-Id, Bug:, Cc:, Fixes:, Link:, ...) are dropped;
  - any line whose whitespace-normalized text occurs in the official fix's ADDED statements is dropped
    (leak guard; the count is reported and the paper cites it);
  - the result is truncated to MAX_CHARS.
Items whose message cannot be fetched or is empty after cleaning are flagged (ok=false); the remedy arms
then fall back to the plain CVE-text prompt for them, and the paper reports the count.
Writes data/commit_messages.json keyed by fix commit id. Usage: python fetch_commit_messages.py [--workers 8]
"""

import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "gpu"))
from fetch_archives import gh, http  # noqa: E402

MAX_CHARS = 1500
POST_REPOS = {"openssl": "openssl/openssl", "php-src": "php/php-src", "FFmpeg": "FFmpeg/FFmpeg",
              "libexpat": "libexpat/libexpat", "curl": "curl/curl"}
# Trailers are `Key: value` lines (and a few `KEY=value` forms); a subject such as "Bug 701292: Fix ..." is kept.
TRAILER = re.compile(r"^((signed-off-by|reviewed-by|reviewed-on|tested-by|acked-by|cc|change-id|bug|fixes|link|"
                     r"reported-by|suggested-by|co-authored-by|closes|resolves|see-also|commit-queue|cr-commit-position|"
                     r"review url|bug-?id|tbr|r|notry|notreechecks|cq-include-trybots)\s*[:=]|"
                     r"(merged|merge) (from|revision|r\d)|\(cherry picked|\[\d+\.\d+(\.\d+)?\]\s*$)", re.I)
DIFFLIKE = re.compile(r"^(\+|-|@@|```|diff |index |--- |\+\+\+ )")


def _norm(s: str) -> str:
    return re.sub(r"\s+", "", s)


def added_statements(before: str, after: str) -> set[str]:
    b = {_norm(l) for l in before.splitlines() if l.strip()}
    return {_norm(l) for l in after.splitlines() if l.strip() and _norm(l) not in b}


def clean(raw: str, before: str, after: str) -> dict:
    added = added_statements(before, after)
    kept, removed_code, removed_leak, removed_trailer = [], 0, 0, 0
    for line in raw.replace("\r", "").split("\n"):
        s = line.strip()
        if not s:
            kept.append("")
            continue
        if TRAILER.match(s) or re.match(r"^[A-Za-z-]+:\s*(https?://|\S+@\S+)", s):
            removed_trailer += 1
            continue
        if DIFFLIKE.match(s) or s.endswith((";", "{", "}")):
            removed_code += 1
            continue
        if len(_norm(s)) >= 8 and _norm(s) in added:
            removed_leak += 1
            continue
        kept.append(s)
    text = re.sub(r"\n{3,}", "\n\n", "\n".join(kept)).strip()
    truncated = len(text) > MAX_CHARS
    if truncated:
        text = text[:MAX_CHARS].rsplit(" ", 1)[0] + " [...]"
    return {"cleaned": text, "removed_code_lines": removed_code, "removed_leak_lines": removed_leak,
            "removed_trailer_lines": removed_trailer, "truncated": truncated, "chars": len(text)}


def fetch_message(kind: str, repo: str, sha: str) -> str:
    if kind == "github":
        return gh(f"repos/{repo}/commits/{sha}")["commit"]["message"]
    if kind == "gsource":
        return json.loads(http(f"https://android.googlesource.com/{repo}/+/{sha}?format=JSON").split("\n", 1)[1])["message"]
    if kind == "gitlab":
        import urllib.parse
        pid = urllib.parse.quote(repo, safe="")
        return json.loads(http(f"https://gitlab.freedesktop.org/api/v4/projects/{pid}/repository/commits/{sha}"))["message"]
    raise ValueError(f"unsupported host kind {kind!r}")


def main() -> int:
    workers = int(sys.argv[sys.argv.index("--workers") + 1]) if "--workers" in sys.argv else 8
    manifest = {r["commit_id"]: r for r in json.loads((ROOT / "data" / "archives_manifest.json").read_text())}
    jobs = []
    for r in map(json.loads, open(ROOT / "data" / "bigvul" / "bigvul_pairs.jsonl")):
        m = manifest.get(r["commit_id"], {})
        # Big-Vul's commit_id sometimes carries a typo or a URL suffix; the code link holds the real hash.
        hashes = re.findall(r"[0-9a-f]{40}", m.get("codeLink", ""))
        kind, repo = m.get("kind"), m.get("repo")
        if not repo:  # the archive fetch failed, but the message may still be reachable from the link
            gh_m = re.match(r"https?://github\.com/([^/]+/[^/]+)/commit/", m.get("codeLink", ""))
            if gh_m:
                kind, repo = "github", gh_m.group(1)
        jobs.append({"commit_id": r["commit_id"], "cve_id": r["cve_id"], "set": "bigvul", "kind": kind,
                     "repo": repo, "sha": hashes[-1] if hashes else r["commit_id"],
                     "before": r["func_before"], "after": r["func_after"]})
    for r in map(json.loads, open(ROOT / "data" / "postcutoff" / "postcutoff_pairs.jsonl")):
        jobs.append({"commit_id": r["commit_id"], "cve_id": r["cve_id"], "set": "postcutoff", "kind": "github",
                     "repo": POST_REPOS.get(r["project"]), "sha": r["commit_id"],
                     "before": r["func_before"], "after": r["func_after"]})

    def one(j):
        rec = {k: j[k] for k in ("commit_id", "cve_id", "set", "repo")}
        if not j["kind"] or not j["repo"]:
            return rec | {"ok": False, "error": "no repository for this commit"}
        try:
            raw = fetch_message(j["kind"], j["repo"], j["sha"])
        except Exception as e:  # noqa: BLE001
            return rec | {"ok": False, "error": f"{type(e).__name__}: {e}"[:200]}
        c = clean(raw, j["before"], j["after"])
        return rec | {"raw": raw, **c, "ok": bool(c["cleaned"])}

    with ThreadPoolExecutor(workers) as ex:
        recs = list(ex.map(one, jobs))
    out = {r["commit_id"]: r for r in recs}
    (ROOT / "data" / "commit_messages.json").write_text(json.dumps(out, indent=1))
    ok = [r for r in recs if r["ok"]]
    for s in ("bigvul", "postcutoff"):
        rs = [r for r in recs if r["set"] == s]
        oks = [r for r in rs if r["ok"]]
        print(f"{s}: {len(oks)}/{len(rs)} messages; leak lines removed in {sum(1 for r in oks if r['removed_leak_lines'])} "
              f"items ({sum(r['removed_leak_lines'] for r in oks)} lines); code-like lines removed in "
              f"{sum(1 for r in oks if r['removed_code_lines'])} items; truncated {sum(r['truncated'] for r in oks)}; "
              f"median chars {sorted(r['chars'] for r in oks)[len(oks)//2] if oks else 0}")
    for r in recs:
        if not r["ok"]:
            print("  FAIL", r["set"], r["cve_id"], r["commit_id"][:10], r.get("error", "empty after cleaning"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
