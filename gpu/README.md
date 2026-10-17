# Open-weight (GPU) experiments

These experiments use open-weight models because they need token probabilities or local inference, which the Claude API does not provide.

**Hardware and software**
- One NVIDIA RTX 6000 Ada (48 GB), on Windows 11 with WSL2 Ubuntu.
- Python 3.11, PyTorch 2.6.0 (CUDA 12.4), Transformers 5.19, bfloat16 weights.
- All runs together take about 70 minutes of GPU time, including model downloads.

```bash
conda create -n rpw python=3.11 && conda activate rpw
pip install torch --index-url https://download.pytorch.org/whl/cu124
pip install "transformers>=4.45" accelerate numpy scipy pandas scikit-learn tree-sitter tree-sitter-c
```

Run all commands from the replication root.

| Script | What it does | Output |
|---|---|---|
| `gpu/minkprobe.py` | Min-K% / Min-K%++ scores of all 412 functions and their certified variants under Qwen2.5-Coder-7B (base) | `results/minkprobe_*.jsonl` |
| `gpu/analyze_minkprobe.py` | Whole-function contrasts C1–C3 (reported as confounded) | `results/minkprobe_*_analysis.json` |
| `gpu/minkprobe_lines.py` | Line-level contrast: lines the fix added vs. unchanged lines, within each fixed function | `results/minkprobe_lines_*.jsonl` |
| `gpu/positive_control.py` | Membership positive control within OpenSSL: functions unchanged since `OpenSSL_1_1_1` vs. functions first written after 2025-08-01 (needs `git clone --filter=blob:none https://github.com/openssl/openssl`) | `results/positive_control_*.json` |
| `gpu/open_detect.py` | RQ2 replication with Qwen2.5-Coder-7B/14B-Instruct: the same four probes and prompts as the Claude runs | `results/open_detect_*.json` |

The line-level contrast was designed after the whole-function comparison proved confounded: in post-cutoff pairs only the fix is new, while the vulnerable code usually predates training.

## Sensitivity: interprocedural srcSlice slices in the RQ1 repair ladder (free, open model)

Tests whether a dependence-based slice changes RQ1, without paid API calls. Arms A3s/A4s replace the identifier
slice with an interprocedural srcSlice slice; A3c (identifier slice + the same called functions, unsliced) separates
slicing from extra context. Model: Qwen3-Coder-30B-A3B-Instruct-FP8 served with vLLM (`--enforce-eager`).

1. `gpu/fetch_archives.py CODELINKS.json` fetches, for each of the 150 RQ1 CVEs, the file containing the vulnerable
   function and every C/C++ file in its directory at the vulnerable commit (manifest with SHA-256 in
   `data/archives_manifest.json`; set `RP_ARCHIVE_DIR` to keep the sources outside the package).
2. `gpu/build_inter_slices.py` runs `srcml --position` over each archive and `srcslice` once, then builds each
   function's slice with `srcslice_inter.py` (def/use lines, closure over dvars and pointers, and each `cfuncs` entry
   followed into the callee's parameter, across files). Output: `data/srcslice_inter.json`.
3. `RP_LOCAL_LLM_BASE_URL=http://HOST:PORT/v1 RP_LLM_MODEL=Qwen/Qwen3-Coder-30B-A3B-Instruct-FP8 python gpu/run_open_ladder.py`
   runs A2, A3, A4, A3s, A4s, A3c (3 repeats, the ladder's seeds) and writes
   `results/open_ladder_Qwen3-Coder-30B-A3B-Instruct-FP8.json`. Responses are cached in `data/_llm_cache_open.sqlite`,
   so a re-run replays without a server; the frozen Claude cache is never used by this path.

Result: VPR A3 4.9% vs A3s 4.9% (Wilcoxon p = .88), A4 4.4% vs A4s 4.2% (p = 1.0), A3c 4.2%.
