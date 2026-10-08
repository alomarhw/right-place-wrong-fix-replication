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
