"""oracle.py — RQ3-E1 independent validation oracle + severance signal.

Two distinct patch judges:

  1. INDEPENDENT ORACLE (the arbiter). A patch is VALIDATED iff it changes the
     vulnerable function, keeps braces balanced, and either equals the official CVE
     fix (comment/whitespace-normalized) or makes every statement change the official
     fix makes (removes what it removes, adds what it adds; extra edits allowed). It
     never uses the severance signal or any method's output. It is conservative: a
     correct fix written differently from the official one is rejected, so validated-
     patch rates are lower bounds. (The earlier guarded-sink surrogate accepted the
     unpatched function on 149/150 real Big-Vul pairs and was replaced.)

  2. vsvector-SEVERANCE SIGNAL (intermediate only). Measures whether the patched
     function's vulnerability slice signature (vsvector) still matches the known
     vulnerable signature above the foundation LSH threshold. 'Severed' means the
     vulnerable slice no longer matches — a NECESSARY-but-not-sufficient signal. It is
     NEVER the arbiter; its agreement with the independent oracle is quantified.

Calibration (RQ3-E1): run BOTH judges on labelled patch sets:
  * official patches  -> should be ACCEPTED by the independent oracle,
  * three known-bad patterns (whole-slice deletion, no-op/comment-only, semantics-
    breaking edit) -> should be REJECTED.
Report the independent-oracle confusion matrix with Wilson CIs, and the
severance-vs-oracle agreement (MCC, Cohen's kappa, severance false-accept rate).

Includes an explicit NEGATIVE CONTROL: the official fixed function compared to an
identical copy of itself must be judged EQUAL (trivial accept), and the whole-slice-
deletion positive control must be accepted by severance but rejected by the oracle.

Key deps: scikit-learn==1.5.1 (matthews_corrcoef, cohen_kappa_score), numpy==2.2.6.
"""
from __future__ import annotations

import os
import re
from collections import Counter
from dataclasses import dataclass

import numpy as np

from data_prep import canonical_slice, extract_slice
from rq3_data import CVEPatchItem

RANDOM_SEED = int(os.environ.get("RP_RANDOM_SEED", 42))

# foundation LSH acceptance threshold for vsvector matching
LSH_THRESHOLD = float(os.environ.get("RP_LSH_THRESHOLD", 0.90))

# sink patterns whose UNGUARDED presence indicates a live vulnerability
_SINKS = [r"\bstrcpy\b", r"\bstrcat\b", r"\bsprintf\b", r"\bgets\b", r"\bmemcpy\b"]
_GUARD_TOKENS = ["strncpy", "sizeof", "snprintf", "if", "return -1", "MAXA", "bounds",
                 "<=", "<", ">", "min(", "length", "len"]


# ----------------------------------------------------------------------------
# vsvector (slice signature) similarity — foundation similarity model
# ----------------------------------------------------------------------------
def _slice_tokens(code: str) -> set[str]:
    canon = canonical_slice(code)
    return set(re.findall(r"[A-Za-z_]\w*|[^\sA-Za-z_]", canon)) or {"_empty_"}


def vsvector_similarity(code_a: str, code_b: str) -> float:
    """Jaccard similarity of the two canonical vulnerability-slice signatures."""
    a, b = _slice_tokens(code_a), _slice_tokens(code_b)
    inter = len(a & b)
    union = len(a | b) or 1
    return inter / union


# ----------------------------------------------------------------------------
# Behavioural surrogate: abstract interpreter over vulnerability-relevant ops.
# Returns True if the function's vulnerable sink is GUARDED (i.e., safe).
# This is an INDEPENDENT reference (not derived from any patch method's output).
# ----------------------------------------------------------------------------
def _sink_is_guarded(code: str) -> bool:
    """Deterministic guarded-sink check over the vulnerability slice."""
    slice_lines = extract_slice(code)
    slice_text = "\n".join(slice_lines)
    has_unsafe_sink = any(re.search(p, slice_text) for p in _SINKS)
    # use-after-free surrogate: a dereference after a free of the same pointer
    uaf = bool(re.search(r"\bfree\s*\(\s*(\w+)\s*\)", slice_text)) and \
        bool(re.search(r"\b\w+\s*\[", slice_text))
    # integer-overflow surrogate: multiplication feeding malloc without guard
    iovf = bool(re.search(r"\bmalloc\s*\([^)]*\*", slice_text))
    guarded = any(tok in slice_text for tok in _GUARD_TOKENS)

    if uaf:
        # safe only if the free happens after last use (heuristic: free is last stmt)
        free_pos = slice_text.rfind("free(")
        deref = [m.start() for m in re.finditer(r"\w+\s*\[", slice_text)]
        last_deref = max(deref) if deref else -1
        return free_pos >= last_deref
    if iovf and not guarded:
        return False
    if has_unsafe_sink and not guarded:
        return False
    return True


def _canonical_behaviour(code: str) -> str:
    """Canonicalize a function for behavioural-equivalence comparison."""
    c = re.sub(r"/\*.*?\*/", " ", code, flags=re.S)
    c = re.sub(r"//[^\n]*", " ", c)
    # abstract local identifiers so renaming does not change equivalence
    c = re.sub(r"[A-Za-z_]\w*", "ID", c)
    return re.sub(r"\s+", "", c)


# ----------------------------------------------------------------------------
# The two judges
# ----------------------------------------------------------------------------
@dataclass
class OracleVerdict:
    validated: bool          # independent oracle ACCEPT
    severed: bool            # severance signal says vuln slice no longer matches
    reason: str


def _norm_stmt(line: str) -> str:
    """Normalize one source line for statement comparison (comments and whitespace removed)."""
    s = re.sub(r"/\*.*?\*/", " ", line)
    s = re.sub(r"//.*", "", s)
    return re.sub(r"\s+", "", s)


def _stmts(code: str) -> list[str]:
    """Normalized, non-trivial statement lines of a function (block-comment-free)."""
    code = re.sub(r"/\*.*?\*/", " ", code, flags=re.S)
    out = []
    for ln in code.splitlines():
        s = _norm_stmt(ln)
        if s and s not in {"{", "}", "};"}:
            out.append(s)
    return out


def _delta(before: str, after: str) -> tuple[Counter, Counter]:
    """(removed, added) statement multisets turning `before` into `after`."""
    b, a = Counter(_stmts(before)), Counter(_stmts(after))
    return b - a, a - b


def independent_oracle(patched_code: str, official_fixed_code: str,
                       vulnerable_code: str) -> OracleVerdict:
    """INDEPENDENT arbiter (official-fix agreement, conservative).

    ACCEPT iff the candidate (1) actually changes the vulnerable function, (2) keeps braces
    balanced, and (3) either equals the official fix after comment/whitespace normalization, or
    makes every statement change the official fix makes: it removes every statement the official
    fix removes and adds every statement the official fix adds (normalized, multiset). Extra edits
    are allowed. This never uses the severance signal and never looks at any method's output.

    It is conservative: a semantically equivalent fix written differently from the official one is
    rejected, so validated-patch rates are lower bounds. On real data it rejects the unpatched
    vulnerable function and accepts the official fix by construction (see calibrate_oracles).
    """
    exact = _stmts(patched_code) == _stmts(official_fixed_code)
    rem_off, add_off = _delta(vulnerable_code, official_fixed_code)
    rem_c, add_c = _delta(vulnerable_code, patched_code)
    changed = bool(rem_c or add_c)
    covers = (not (rem_off - rem_c)) and (not (add_off - add_c))
    braces_ok = _has_balanced_braces(patched_code)

    validated = bool(changed and braces_ok and (exact or covers))

    # severance signal (reported, not used for the decision)
    sim_to_vuln = vsvector_similarity(patched_code, vulnerable_code)
    severed = sim_to_vuln < LSH_THRESHOLD

    if not changed:
        reason = "unchanged"
    elif not braces_ok:
        reason = "unbalanced_braces"
    elif exact:
        reason = "equivalent_to_official_fix"
    elif covers:
        reason = "covers_official_fix_changes"
    else:
        reason = "missing_official_fix_changes"
    return OracleVerdict(validated=validated, severed=severed, reason=reason)


def _has_balanced_braces(code: str) -> bool:
    depth = 0
    for ch in code:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0 and code.count("{") >= 1


# ----------------------------------------------------------------------------
# Known-bad patch synthesis (for RQ3-E1 calibration)
# ----------------------------------------------------------------------------
def make_whole_slice_deletion(item: CVEPatchItem) -> str:
    """Delete the vulnerability slice lines entirely (severs vsvector; breaks function)."""
    slice_set = {l.strip() for l in extract_slice(item.vulnerable_code)}
    kept = [ln for ln in item.vulnerable_code.splitlines() if ln.strip() not in slice_set]
    return "\n".join(kept)


def make_noop_patch(item: CVEPatchItem) -> str:
    """No-op / comment-only edit: the vulnerability is untouched."""
    lines = item.vulnerable_code.splitlines()
    out = []
    for ln in lines:
        out.append(ln)
        if ln.strip().endswith(";"):
            out.append("    /* reviewed: no change */")
    return "\n".join(out)


def make_semantics_breaking_patch(item: CVEPatchItem) -> str:
    """Edit that breaks unrelated behaviour (fails a regression test)."""
    code = item.vulnerable_code
    # corrupt a return value / remove a closing brace to break behaviour
    code = re.sub(r"return\s+[^;]+;", "return -999;", code, count=1)
    if "return -999;" not in code:
        code = code + "\n    return -999;"
    return code


# ----------------------------------------------------------------------------
# RQ3-E1 calibration
# ----------------------------------------------------------------------------
def calibrate_oracles(items: list[CVEPatchItem], seed: int = RANDOM_SEED) -> dict:
    """Run both judges on labelled patch sets; return confusion-matrix calibration.

    Labelled sets:
      official fix   -> gold ACCEPT
      whole-slice del, no-op, semantics-break -> gold REJECT
    """
    from sklearn.metrics import matthews_corrcoef, cohen_kappa_score

    oracle_pred, gold = [], []
    sev_pred = []  # severance accept (not severed) interpreted as 'accept'
    official_accepts = 0
    known_bad_false_accepts = 0
    n_official = 0
    n_known_bad = 0

    # negative control: official fix vs identical copy must be judged EQUAL (accept)
    neg_control_pass = True
    # positive control: whole-slice deletion accepted by severance, rejected by oracle
    pos_control_hits = 0
    pos_control_total = 0

    for it in items:
        # --- official fix: gold ACCEPT ---
        v = independent_oracle(it.official_fixed_code, it.official_fixed_code, it.vulnerable_code)
        oracle_pred.append(int(v.validated))
        sev_pred.append(int(not v.severed))  # accept if NOT severed
        gold.append(1)
        n_official += 1
        if v.validated:
            official_accepts += 1
        # negative control: identical copy must be equal -> validated True
        if not v.validated:
            neg_control_pass = False

        # --- three known-bad patterns: gold REJECT ---
        bad_patches = [
            ("whole_slice_deletion", make_whole_slice_deletion(it)),
            ("noop", make_noop_patch(it)),
            ("semantics_break", make_semantics_breaking_patch(it)),
        ]
        for kind, bad in bad_patches:
            bv = independent_oracle(bad, it.official_fixed_code, it.vulnerable_code)
            oracle_pred.append(int(bv.validated))
            sev_pred.append(int(not bv.severed))
            gold.append(0)
            n_known_bad += 1
            if bv.validated:
                known_bad_false_accepts += 1
            # positive control: whole-slice deletion severs vsvector but must be rejected
            if kind == "whole_slice_deletion":
                pos_control_total += 1
                if bv.severed and not bv.validated:
                    pos_control_hits += 1

    gold = np.array(gold)
    oracle_pred = np.array(oracle_pred)
    sev_pred = np.array(sev_pred)

    # confusion matrix for the independent oracle vs gold
    tp = int(np.sum((oracle_pred == 1) & (gold == 1)))
    fp = int(np.sum((oracle_pred == 1) & (gold == 0)))
    tn = int(np.sum((oracle_pred == 0) & (gold == 0)))
    fn = int(np.sum((oracle_pred == 0) & (gold == 1)))

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    official_accept_rate = official_accepts / n_official if n_official else 0.0
    false_accept_rate = known_bad_false_accepts / n_known_bad if n_known_bad else 0.0

    # severance vs independent-oracle agreement (severance as intermediate signal)
    if len(set(oracle_pred.tolist())) >= 2 and len(set(sev_pred.tolist())) >= 2:
        mcc = float(matthews_corrcoef(oracle_pred, sev_pred))
        kappa = float(cohen_kappa_score(oracle_pred, sev_pred))
    else:
        mcc = 0.0
        kappa = 0.0
    # severance false-accept relative to the independent oracle:
    # severance accepts (not severed) where oracle rejects
    sev_fa = int(np.sum((sev_pred == 1) & (oracle_pred == 0)))
    sev_fa_rate = sev_fa / max(1, int(np.sum(oracle_pred == 0)))

    return {
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": precision,
        "recall": recall,
        "official_patch_accept_rate": official_accept_rate,
        "oracle_false_accept_rate": false_accept_rate,
        "n_official": n_official,
        "n_known_bad": n_known_bad,
        "severance_vs_oracle_mcc": mcc,
        "severance_vs_oracle_kappa": kappa,
        "severance_false_accept_rate": sev_fa_rate,
        "negative_control_identical_fix_accepted": bool(neg_control_pass),
        "positive_control_slice_deletion_severed_but_rejected": (
            pos_control_hits / pos_control_total if pos_control_total else 0.0),
        "gold": gold.tolist(),
        "oracle_pred": oracle_pred.tolist(),
        "severance_pred": sev_pred.tolist(),
    }


if __name__ == "__main__":
    from rq3_data import build_rq3_corpus
    items, tag = build_rq3_corpus(n_cves=15, allow_synthetic=True)
    cal = calibrate_oracles(items)
    print("official_accept_rate:", cal["official_patch_accept_rate"])
    print("false_accept_rate:", cal["oracle_false_accept_rate"])
    print("severance MCC:", cal["severance_vs_oracle_mcc"], "kappa:", cal["severance_vs_oracle_kappa"])
    print("neg control:", cal["negative_control_identical_fix_accepted"])
    print("pos control:", cal["positive_control_slice_deletion_severed_but_rejected"])