"""minkprobe_lines.py — line-level membership contrast on the FIXED functions (GPU).

Designed after the first probe (minkprobe.py) showed that whole-function contrasts are confounded:
in the post-cutoff pairs only the fix is new; the vulnerable function usually predates training.
This probe isolates the new code.

For every fixed function, token log-probabilities under the model are split by source line into
  added     tokens on lines the official fix added (difflib, whitespace-insensitive), and
  unchanged tokens on lines shared with the vulnerable version.
Per function: score(added) - score(unchanged), for mean log-prob and mean Min-K%++ z.
  Big-Vul (pre-cutoff): both line types public since 2010-2019.
  Post-cutoff         : added lines written after the model's training; unchanged lines mostly older.
Memorisation predicts a more negative added-minus-unchanged difference for post-cutoff fixes
(difference-in-differences: controls project, style, and the generic 'added lines are unusual' effect).
Output: results/minkprobe_lines_<model>.jsonl
"""
import argparse
import difflib
import json
import time
from pathlib import Path

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

ROOT = Path(__file__).resolve().parent.parent


def added_lines(before: str, after: str) -> set[int]:
    a = [l.strip() for l in before.splitlines()]
    b = [l.strip() for l in after.splitlines()]
    out = set()
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag in ("replace", "insert"):
            out.update(j for j in range(j1, j2) if b[j])
    return out


@torch.no_grad()
def token_scores(model, tok, text, max_len):
    enc = tok(text, return_tensors="pt", truncation=True, max_length=max_len, return_offsets_mapping=True)
    ids = enc.input_ids.to(model.device)
    offs = enc.offset_mapping[0].tolist()
    logp_all = torch.log_softmax(model(ids).logits[0, :-1].float(), dim=-1)
    tgt = ids[0, 1:]
    lp = logp_all.gather(1, tgt[:, None])[:, 0]
    p_all = logp_all.exp()
    mu = (p_all * logp_all).sum(-1)
    sigma = ((p_all * logp_all.pow(2)).sum(-1) - mu.pow(2)).clamp_min(1e-12).sqrt()
    z = (lp - mu) / sigma
    line_starts = [0] + [i + 1 for i, ch in enumerate(text) if ch == "\n"]

    def line_of(pos):
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo
    lines = [line_of(offs[t + 1][0]) for t in range(len(tgt))]  # line of each predicted token
    return lp.tolist(), z.tolist(), lines


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="Qwen/Qwen2.5-Coder-7B")
    ap.add_argument("--max-len", type=int, default=4096)
    a = ap.parse_args()
    tok = AutoTokenizer.from_pretrained(a.model)
    model = AutoModelForCausalLM.from_pretrained(a.model, dtype=torch.bfloat16, device_map="cuda").eval()
    out = ROOT / "results" / f"minkprobe_lines_{a.model.split('/')[-1]}.jsonl"
    t0 = time.time()
    with open(out, "w") as fh:
        for name, prov in (("bigvul/bigvul_pairs.jsonl", "pre_cutoff"), ("postcutoff/postcutoff_pairs.jsonl", "post_cutoff")):
            for ln in (ROOT / "data" / name).read_text().splitlines():
                r = json.loads(ln)
                add = added_lines(r["func_before"], r["func_after"])
                lp, z, lines = token_scores(model, tok, r["func_after"], a.max_len)
                ia = [i for i, l in enumerate(lines) if l in add]
                iu = [i for i, l in enumerate(lines) if l not in add]
                if not ia or not iu:
                    continue
                m = lambda xs, idx: sum(xs[i] for i in idx) / len(idx)  # noqa: E731
                fh.write(json.dumps({"cve_id": r["cve_id"], "project": r.get("project", ""), "provenance": prov,
                                     "n_added_tokens": len(ia), "n_unchanged_tokens": len(iu),
                                     "lp_added": m(lp, ia), "lp_unchanged": m(lp, iu),
                                     "z_added": m(z, ia), "z_unchanged": m(z, iu)}) + "\n")
    print(f"[minkprobe_lines] wrote {out} in {time.time() - t0:.0f}s; model={a.model}")


if __name__ == "__main__":
    main()
