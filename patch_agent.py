"""patch_agent.py — RQ3-E2 detect-verify-patch agent + ablation ladder.

Each ladder arm asks a REAL LLM (detectors.LLMClient; RP_LLM_MODEL, default
claude-haiku-4-5) to return the complete patched function. Arms differ only in
the evidence placed in the prompt and in whether the agent may retry on its
own feedback:

  - no_grounding_no_feedback   : vulnerable function only; one attempt
                                 (ungrounded LLM patching, primary baseline)
  - compiler_test_feedback     : function only; up to k attempts with static
                                 feedback (no code block, unchanged function,
                                 unbalanced braces/parentheses, renamed function)
  - cve_text_rag               : + CVE id, CWE and the CVE record description;
                                 static feedback, up to k attempts
  - slice_grounded_no_feedback : + CVE text + the vulnerability slice; one attempt
  - slice_grounded_full        : + CVE text + slice; static feedback plus
                                 slice-severance feedback (is the vulnerable
                                 slice still intact?), up to k attempts

No arm ever sees the official fix: feedback is computed from the vulnerable
function and the candidate only. The agent decides when to stop (its own checks
pass, or the budget k is spent) and submits ONE final patch; the independent
oracle (oracle.independent_oracle, which compares against the official fix)
judges that submission once and is never used as a retry signal.

Sampling uses temperature RP_PATCH_TEMPERATURE (default 0.7) with the repeat
seed in the cache key, so repeats are independent samples and every response is
cached on disk for exact re-runs.
"""
from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import dataclass, field

import numpy as np

from data_prep import _pair_files, extract_slice
from detectors import LLMClient, llm_map
from oracle import LSH_THRESHOLD, independent_oracle, vsvector_similarity
from rq3_data import CVEPatchItem

RANDOM_SEED = int(os.environ.get("RP_RANDOM_SEED", 42))

RETRY_BUDGET = int(os.environ.get("RP_RETRY_BUDGET", 5))
PATCH_TEMPERATURE = float(os.environ.get("RP_PATCH_TEMPERATURE", 0.7))

# ladder conditions in increasing grounding order
LADDER = [
    "no_grounding_no_feedback",
    "compiler_test_feedback",
    "cve_text_rag",
    "slice_grounded_no_feedback",
    "slice_grounded_full",
]
_USES_CVE_TEXT = {"cve_text_rag", "slice_grounded_no_feedback", "slice_grounded_full"}
_USES_SLICE = {"slice_grounded_no_feedback", "slice_grounded_full"}
_USES_FEEDBACK = {"compiler_test_feedback", "cve_text_rag", "slice_grounded_full"}

_SYSTEM = (
    "You are a security engineer patching a vulnerable C function from an open-source "
    "project. Make the smallest change that removes the vulnerability while preserving "
    "the function's behaviour on valid inputs. Keep the function name and signature. "
    "Return ONLY the complete patched function in a single ```c code block.")


@dataclass
class AgentRun:
    cve_id: str
    condition: str
    validated: bool
    iterations: int
    final_patch: str
    reason: str
    severed_history: list = field(default_factory=list)


_CVE_TEXT: dict | None = None


_CVE_TEXT_LOCK = threading.Lock()


def _cve_text(cve_id: str) -> str:
    """CVE record description (cveawg.mitre.org), stored with the pair files.

    Built under a lock into a local dict and published only when complete: the agent runs in a thread
    pool, and an unlocked lazy fill let a thread read the half-built table and send a CVE-text arm a
    prompt WITHOUT the description (found in 2 of 168 post-cutoff first attempts)."""
    global _CVE_TEXT
    if _CVE_TEXT is None:
        with _CVE_TEXT_LOCK:
            if _CVE_TEXT is None:
                table: dict = {}
                for p in _pair_files():
                    for ln in p.read_text(errors="ignore").splitlines():
                        try:
                            r = json.loads(ln)
                        except Exception:  # noqa: BLE001
                            continue
                        if r.get("cve_id") and r.get("description"):
                            table.setdefault(r["cve_id"], r["description"])
                _CVE_TEXT = table
    return _CVE_TEXT.get(cve_id, "")


def _func_name(code: str) -> str:
    m = re.search(r"([A-Za-z_]\w*)\s*\([^;{]*\)\s*\{", code, flags=re.S)
    return m.group(1) if m else ""


def _extract_code(text: str) -> str:
    blocks = re.findall(r"```(?:c|C|cpp)?\s*\n(.*?)```", text, flags=re.S)
    return max(blocks, key=len).strip("\n") if blocks else ""


def _norm(code: str) -> str:
    code = re.sub(r"/\*.*?\*/|//[^\n]*", " ", code, flags=re.S)
    return re.sub(r"\s+", "", code)


def _static_feedback(cand: str, vulnerable: str) -> list[str]:
    """Compiler-style sanity checks that need neither headers nor the official fix."""
    if not cand:
        return ["No ```c code block with the complete function was found in your answer."]
    issues = []
    if _norm(cand) == _norm(vulnerable):
        issues.append("Your function is identical to the vulnerable one; nothing was patched.")
    if cand.count("{") != cand.count("}"):
        issues.append(f"Unbalanced braces ({cand.count('{')} '{{' vs {cand.count('}')} '}}').")
    if cand.count("(") != cand.count(")"):
        issues.append(f"Unbalanced parentheses ({cand.count('(')} '(' vs {cand.count(')')} ')').")
    want = _func_name(vulnerable)
    if want and _func_name(cand) != want:
        issues.append(f"The function must keep its name '{want}'.")
    return issues


def _severance_feedback(cand: str, vulnerable: str) -> tuple[bool, list[str]]:
    """Is the vulnerable slice still intact in the candidate? (vulnerable code only)"""
    sim = vsvector_similarity(cand, vulnerable)
    severed = sim < LSH_THRESHOLD
    if severed:
        return True, []
    cand_lines = {re.sub(r"\s+", " ", l.strip()) for l in cand.splitlines()}
    intact = [l for l in extract_slice(vulnerable) if re.sub(r"\s+", " ", l) in cand_lines][:12]
    msg = (f"The vulnerability slice is still intact (slice similarity {sim:.2f} >= "
           f"{LSH_THRESHOLD:.2f}): the data flow into the vulnerable operation is unchanged. "
           "These slice statements are unchanged:\n" + "\n".join(f"  {l}" for l in intact))
    return False, [msg]


def _prompt(item: CVEPatchItem, condition: str, previous: str, feedback: list[str]) -> str:
    parts = []
    if condition in _USES_CVE_TEXT:
        desc = _cve_text(item.cve_id)
        parts.append(f"Vulnerability: {item.cve_id} ({item.cwe}).")
        if desc:
            parts.append(f"CVE description: {desc}")
    parts.append(f"Vulnerable function:\n```c\n{item.vulnerable_code}\n```")
    if condition in _USES_SLICE:
        sl = "\n".join(item.vulnerable_slice or extract_slice(item.vulnerable_code))
        parts.append("Vulnerability slice (the statements that reach the vulnerable "
                     f"operation; your patch must cut or guard this flow):\n```c\n{sl}\n```")
    if feedback:
        parts.append(f"Your previous attempt:\n```c\n{previous}\n```\n"
                     "It was rejected by the checks below. Fix these problems and return the "
                     "complete patched function again.\n- " + "\n- ".join(feedback))
    return "\n\n".join(parts)


# ----------------------------------------------------------------------------
# The agent loop for one CVE under one condition
# ----------------------------------------------------------------------------
def run_agent_on_item(item: CVEPatchItem, condition: str, seed: int) -> AgentRun:
    client = LLMClient.get()
    budget = RETRY_BUDGET if condition in _USES_FEEDBACK else 1
    severed_history: list[bool] = []
    cand, feedback, iterations = "", [], 0
    for it_i in range(1, budget + 1):
        iterations = it_i
        text = client.complete(_SYSTEM, _prompt(item, condition, cand, feedback),
                               max_tokens=4096, temperature=PATCH_TEMPERATURE,
                               sample=seed * 10 + it_i)
        cand = _extract_code(text)
        severed, sev_fb = _severance_feedback(cand, item.vulnerable_code) if cand else (False, [])
        severed_history.append(bool(severed))
        feedback = _static_feedback(cand, item.vulnerable_code)
        if condition == "slice_grounded_full" and not feedback:
            feedback = sev_fb
        if not feedback or condition not in _USES_FEEDBACK:
            break
    final = cand or item.vulnerable_code
    verdict = independent_oracle(final, item.official_fixed_code, item.vulnerable_code)
    return AgentRun(cve_id=item.cve_id, condition=condition,
                    validated=bool(verdict.validated), iterations=iterations,
                    final_patch=final, reason=verdict.reason,
                    severed_history=severed_history)


def run_ladder(items: list[CVEPatchItem], seed: int = RANDOM_SEED) -> dict:
    """Run every ladder condition over all CVEs. Returns per-condition AgentRun lists."""
    jobs = [(i, item, cond) for i, item in enumerate(items) for cond in LADDER]
    runs = llm_map(lambda j: run_agent_on_item(j[1], j[2], seed=seed + j[0] * 101), jobs)
    results: dict[str, list[AgentRun]] = {c: [] for c in LADDER}
    for (_, _, cond), run in zip(jobs, runs):
        results[cond].append(run)
    print(f"[patch_agent] LLM usage so far: {LLMClient.get().stats()}")
    return results


def summarize_condition(runs: list[AgentRun]) -> dict:
    """VPR, mean iterations-to-accept, accept count for one condition."""
    n = len(runs)
    accepts = [r for r in runs if r.validated]
    vpr = len(accepts) / n if n else 0.0
    # iterations-to-accept averaged over ACCEPTED patches (finite convention if none)
    if accepts:
        iters = float(np.mean([r.iterations for r in accepts]))
    else:
        iters = float(RETRY_BUDGET)  # no accepts -> hit the budget
    return {
        "validated_patch_rate_vpr": vpr,
        "iterations_to_accept": iters,
        "n_accepted": len(accepts),
        "n_total": n,
        "validated_mask": [int(r.validated) for r in runs],
        "iterations": [r.iterations for r in runs],
    }


if __name__ == "__main__":
    from rq3_data import build_rq3_corpus
    items, tag = build_rq3_corpus(n_cves=15, allow_synthetic=False)
    res = run_ladder(items)
    for cond in LADDER:
        s = summarize_condition(res[cond])
        print(f"{cond:30s} VPR={s['validated_patch_rate_vpr']:.3f} "
              f"iters={s['iterations_to_accept']:.2f} ({s['n_accepted']}/{s['n_total']})")
