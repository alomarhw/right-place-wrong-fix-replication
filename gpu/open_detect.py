"""open_detect.py — RQ2 replication on open-weight instruct code models (GPU).

Same 150 vulnerable/fixed CVE pairs and the SAME prompts as the Claude experiments:
  abs_answer   one function, instruct audit prompt, one-word answer   (detectors._DETECT_SYSTEM)
  abs_reason   one function, reason then 'Answer: VULNERABLE|SAFE'      (e1_absolute_reason.SYSTEM)
  con_answer   both versions, one-letter answer, both orders            (e1_contrastive.SYSTEM)
  con_reason   both versions, reason then 'Answer: A|B', both orders    (e1_contrastive.SYSTEM_REASON)
Greedy decoding via the model's chat template. Reports pair-correctness (Wilson 95% CI), positive rate
(absolute modes), position bias (contrastive), and the 'longer version is the fix' rule for reference.
Writes results/open_detect_<model>.json (summary + per-pair predictions).
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from data_prep import build_corpus  # noqa: E402
from detectors import _DETECT_SYSTEM, _parse_verdict  # noqa: E402
import e1_absolute_reason as ear  # noqa: E402
import e1_contrastive as ec  # noqa: E402


def wilson(k, n, z=1.96):
    p = k / n; d = 1 + z * z / n; c = (p + z * z / (2 * n)) / d
    h = z * (p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5 / d
    return [p, max(0.0, c - h), min(1.0, c + h)]


@torch.no_grad()
def generate(model, tok, systems_users, max_new, bs):
    outs = []
    for i in range(0, len(systems_users), bs):
        chunk = systems_users[i:i + bs]
        texts = [tok.apply_chat_template([{"role": "system", "content": s}, {"role": "user", "content": u}],
                                         tokenize=False, add_generation_prompt=True) for s, u in chunk]
        enc = tok(texts, return_tensors="pt", padding=True).to(model.device)
        gen = model.generate(**enc, max_new_tokens=max_new, do_sample=False, pad_token_id=tok.pad_token_id)
        outs += tok.batch_decode(gen[:, enc.input_ids.shape[1]:], skip_special_tokens=True)
        print(f"  generated {min(i + bs, len(systems_users))}/{len(systems_users)}", flush=True)
    return outs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="Qwen/Qwen2.5-Coder-7B-Instruct")
    ap.add_argument("--bs", type=int, default=16)
    a = ap.parse_args()
    tok = AutoTokenizer.from_pretrained(a.model, padding_side="left")
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    model = AutoModelForCausalLM.from_pretrained(a.model, dtype=torch.bfloat16, device_map="cuda").eval()

    items, _ = build_corpus(n_cves=300, allow_synthetic=False, seed=42)
    by = {}
    for it in items:
        by.setdefault(it.cve_id, {})[it.label] = it
    pairs = [(c, d[1], d[0]) for c, d in by.items() if 1 in d and 0 in d]
    longer_fix = np.array([len(f.code) > len(v.code) for _, v, f in pairs])
    res = {"model": a.model, "n_pairs": len(pairs),
           "heuristic_longer_is_fix": wilson(int(longer_fix.sum()), len(pairs)), "modes": {}, "per_pair": {}}

    for mode, system, max_new in (("abs_answer", _DETECT_SYSTEM, 8), ("abs_reason", ear.SYSTEM, 700)):
        prompts = [(system, f"Function under review:\n```c\n{x.code}\n```") for _, v, f in pairs for x in (v, f)]
        outs = generate(model, tok, prompts, max_new, a.bs)
        parse = _parse_verdict if mode == "abs_answer" else ear.verdict
        pred = np.array([parse(o) for o in outs]).reshape(-1, 2)  # [vuln_pred, fixed_pred]
        ok = (pred[:, 0] == 1) & (pred[:, 1] == 0)
        res["modes"][mode] = {"pair_correct": wilson(int(ok.sum()), len(ok)), "positive_rate": float(pred.mean()),
                              "accuracy": float(((pred[:, 0] == 1).sum() + (pred[:, 1] == 0).sum()) / pred.size)}
        res["per_pair"][mode] = ok.astype(int).tolist()

    for mode, system, max_new in (("con_answer", ec.SYSTEM, 4), ("con_reason", ec.SYSTEM_REASON, 700)):
        prompts = []
        for _, v, f in pairs:
            prompts += [(system, ec.prompt(v.code, f.code)), (system, ec.prompt(f.code, v.code))]
        outs = generate(model, tok, prompts, max_new, a.bs)
        ans = np.array([ec.answer(o) for o in outs]).reshape(-1, 2)
        ok_vf, ok_fv = ans[:, 0] == "A", ans[:, 1] == "B"
        ok = ok_vf & ok_fv
        b10 = int((ok & ~longer_fix).sum()); b01 = int((~ok & longer_fix).sum())
        from scipy.stats import binomtest
        res["modes"][mode] = {"pair_correct": wilson(int(ok.sum()), len(ok)),
                              "acc_vulnerable_first": float(ok_vf.mean()), "acc_vulnerable_second": float(ok_fv.mean()),
                              "mcnemar_vs_heuristic": {"model_only": b10, "heuristic_only": b01,
                                                       "p": float(binomtest(b10, b10 + b01, 0.5).pvalue) if b10 + b01 else 1.0},
                              "acc_when_fix_shorter": float(ok[~longer_fix].mean()) if (~longer_fix).any() else None}
        res["per_pair"][mode] = ok.astype(int).tolist()
    res["per_pair"]["cve_id"] = [c for c, _, _ in pairs]
    res["per_pair"]["provenance"] = [v.provenance for _, v, _ in pairs]
    dst = ROOT / "results" / f"open_detect_{a.model.split('/')[-1]}.json"
    dst.write_text(json.dumps(res, indent=1))
    print(json.dumps({k: v for k, v in res.items() if k != "per_pair"}, indent=1))


if __name__ == "__main__":
    main()
