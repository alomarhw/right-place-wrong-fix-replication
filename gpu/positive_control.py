"""positive_control.py — does the likelihood probe detect code membership at all? (GPU)

Within one project (OpenSSL), so project and style are held constant:
  members     functions in current master whose text is byte-identical to the OpenSSL_1_1_1 release
              (Sep 2018): unchanged for years, certainly in a 2024 code model's training data;
  non-members functions in current master whose name does not occur anywhere in the tree at the last
              master commit before 2025-08-01: first written after the model's training.
Functions of 5-120 lines; extracted with tree-sitter-c. Scores: mean log-prob, Min-K% and Min-K%++
(k = 20%, as in minkprobe.py). Reports ROC-AUC (member vs non-member) overall and within length
tertiles. Writes results/positive_control_<model>.json.
Requires: a partial clone of https://github.com/openssl/openssl at --repo; pip install tree-sitter tree-sitter-c
"""
import argparse
import json
import random
import subprocess
from pathlib import Path

import numpy as np
import torch
import tree_sitter_c
from sklearn.metrics import roc_auc_score
from transformers import AutoModelForCausalLM, AutoTokenizer
from tree_sitter import Language, Parser

from minkprobe import score

ROOT = Path(__file__).resolve().parent.parent
PARSER = Parser(Language(tree_sitter_c.language()))


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=True).stdout


def functions(src: bytes) -> dict:
    out = {}
    stack = [PARSER.parse(src).root_node]
    while stack:
        n = stack.pop()
        if n.type == "function_definition":
            d = n.child_by_field_name("declarator")
            while d is not None and d.type not in ("identifier",):
                d = d.child_by_field_name("declarator")
            if d is not None:
                text = src[n.start_byte:n.end_byte].decode("utf-8", "ignore")
                if 5 <= text.count("\n") + 1 <= 120:
                    out.setdefault(d.text.decode(), text)
        else:
            stack.extend(n.children)
    return out


def tree_functions(repo, rev):
    files = [f for f in git(repo, "ls-tree", "-r", "--name-only", rev).decode().split("\n")
             if f.endswith(".c") and not f.startswith(("test/", "fuzz/", "demos/"))]
    res = {}
    for f in files:
        try:
            src = git(repo, "show", f"{rev}:{f}")
        except subprocess.CalledProcessError:
            continue
        for name, text in functions(src).items():
            res[(f, name)] = text
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=str(Path.home() / "rpw" / "openssl"))
    ap.add_argument("--model", default="Qwen/Qwen2.5-Coder-7B")
    ap.add_argument("--max-members", type=int, default=400)
    a = ap.parse_args()
    repo = Path(a.repo)
    cutoff = git(repo, "rev-list", "-1", "--before=2025-08-01", "origin/master").decode().strip()
    head = git(repo, "rev-parse", "origin/master").decode().strip()
    old, mid, new = tree_functions(repo, "OpenSSL_1_1_1"), tree_functions(repo, cutoff), tree_functions(repo, head)
    mid_names = {n for _, n in mid}
    members = [t for k, t in new.items() if old.get(k) == t]
    nonmembers = [t for (f, n), t in new.items() if n not in mid_names]
    random.Random(42).shuffle(members)
    members = members[:a.max_members]
    print(f"[positive_control] members={len(members)} non-members={len(nonmembers)} cutoff={cutoff[:10]} head={head[:10]}")

    tok = AutoTokenizer.from_pretrained(a.model)
    model = AutoModelForCausalLM.from_pretrained(a.model, dtype=torch.bfloat16, device_map="cuda").eval()
    recs = [{"member": 1, "n_lines": t.count("\n") + 1, **score(model, tok, t, 0.2, 4096)} for t in members] + \
           [{"member": 0, "n_lines": t.count("\n") + 1, **score(model, tok, t, 0.2, 4096)} for t in nonmembers]
    y = np.array([r["member"] for r in recs]); L = np.array([r["n_lines"] for r in recs])
    out = {"model": a.model, "n_members": int(y.sum()), "n_nonmembers": int((1 - y).sum()),
           "cutoff_commit": cutoff, "head_commit": head, "auc": {}, "auc_by_length_tertile": {}}
    edges = np.quantile(L, [0, 1 / 3, 2 / 3, 1])
    for m in ("mean_lp", "mink", "minkpp"):
        s = np.array([r[m] for r in recs])
        out["auc"][m] = float(roc_auc_score(y, s))
        per = []
        for lo, hi in zip(edges[:-1], edges[1:]):
            idx = (L >= lo) & (L <= hi)
            if len(set(y[idx])) == 2:
                per.append(float(roc_auc_score(y[idx], s[idx])))
        out["auc_by_length_tertile"][m] = per
    dst = ROOT / "results" / f"positive_control_{a.model.split('/')[-1]}.json"
    dst.write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
