"""minkprobe.py — likelihood-based memorization probe on an open-weight code model (GPU).

Pre-registered design (written before any result was seen):
  Model      : an open base code LLM (default Qwen/Qwen2.5-Coder-7B, released 2024). Every
               post-cutoff fix in our data (CVE published >= 2025-08-01) postdates its training.
  Scores     : per function, token log-probabilities under the model, then
                 mean_lp   mean token log-probability (reference),
                 mink      Min-K% Prob, mean of the lowest k% token log-probs (Shi et al., ICLR'24),
                 minkpp    Min-K%++, mean of the lowest k% standardised token log-probs
                           z_t = (log p(x_t) - mu_t) / sigma_t, with mu_t, sigma_t the mean and std of
                           log p(.) under the model's next-token distribution at step t.
               k = 20. Higher scores = more 'familiar' to the model.
  Contrasts  : C1 verbatim vs. certified slice-preserving variant (renamed locals, reformatted,
                  dead code): drop = score(verbatim) - score(variant). Memorised code should lose
                  more than unseen code. Compared between Big-Vul (pre-cutoff) and post-cutoff.
               C2 within-pair: score(vulnerable) - score(fixed). For post-cutoff CVEs the fix was
                  written after training, so memorisation predicts a larger gap than for Big-Vul.
               C3 raw group means (confounded by project and length; reported as such).
Output: results/minkprobe_<model>.jsonl (one record per function) — analysed by analyze_minkprobe.py.
"""
import argparse
import json
import math
import os
import sys
import time
from pathlib import Path

import numpy as np
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
from data_prep import CVEItem  # noqa: E402
from variant_builder import build_variant  # noqa: E402


def load_pairs():
    rows = []
    for name, prov in (("bigvul/bigvul_pairs.jsonl", "pre_cutoff"), ("postcutoff/postcutoff_pairs.jsonl", "post_cutoff")):
        for ln in (ROOT / "data" / name).read_text().splitlines():
            r = json.loads(ln)
            rows.append({"cve_id": r["cve_id"], "cwe": r.get("cwe", ""), "project": r.get("project", ""),
                         "provenance": prov, "before": r["func_before"], "after": r["func_after"]})
    return rows


@torch.no_grad()
def score(model, tok, text: str, k: float, max_len: int) -> dict:
    ids = tok(text, return_tensors="pt", truncation=True, max_length=max_len).input_ids.to(model.device)
    if ids.shape[1] < 3:
        return {"n_tokens": int(ids.shape[1]), "mean_lp": float("nan"), "mink": float("nan"), "minkpp": float("nan")}
    logits = model(ids).logits[0, :-1].float()
    logp_all = torch.log_softmax(logits, dim=-1)
    tgt = ids[0, 1:]
    lp = logp_all.gather(1, tgt[:, None])[:, 0]
    p_all = logp_all.exp()
    mu = (p_all * logp_all).sum(-1)
    sigma = ((p_all * logp_all.pow(2)).sum(-1) - mu.pow(2)).clamp_min(1e-12).sqrt()
    z = (lp - mu) / sigma
    n = max(1, int(math.ceil(k * lp.numel())))
    return {"n_tokens": int(ids.shape[1]), "mean_lp": float(lp.mean()),
            "mink": float(torch.topk(lp, n, largest=False).values.mean()),
            "minkpp": float(torch.topk(z, n, largest=False).values.mean())}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="Qwen/Qwen2.5-Coder-7B")
    ap.add_argument("--k", type=float, default=0.2)
    ap.add_argument("--max-len", type=int, default=4096)
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    tok = AutoTokenizer.from_pretrained(a.model)
    model = AutoModelForCausalLM.from_pretrained(a.model, torch_dtype=torch.bfloat16, device_map="cuda")
    model.eval()
    out = ROOT / "results" / f"minkprobe_{a.model.split('/')[-1]}.jsonl"
    out.parent.mkdir(exist_ok=True)
    rows = load_pairs()
    t0 = time.time()
    with open(out, "w") as fh:
        for i, r in enumerate(rows):
            for side, label in (("before", 1), ("after", 0)):
                code = r[side]
                var = build_variant(CVEItem(cve_id=r["cve_id"], cwe=r["cwe"], code=code, label=label,
                                            provenance="seen" if r["provenance"] == "pre_cutoff" else "unseen"),
                                    seed=a.seed + i)
                rec = {"cve_id": r["cve_id"], "project": r["project"], "provenance": r["provenance"], "side": side,
                       "variant_certified": bool(var.certified), "n_lines": code.count("\n") + 1,
                       "verbatim": score(model, tok, code, a.k, a.max_len),
                       "variant": score(model, tok, var.code, a.k, a.max_len)}
                fh.write(json.dumps(rec) + "\n")
            if (i + 1) % 25 == 0:
                print(f"[minkprobe] {i + 1}/{len(rows)} pairs, {time.time() - t0:.0f}s", flush=True)
    print(f"[minkprobe] wrote {out} in {time.time() - t0:.0f}s; model={a.model}; "
          f"gpu={torch.cuda.get_device_name(0)}; torch={torch.__version__}")


if __name__ == "__main__":
    main()
