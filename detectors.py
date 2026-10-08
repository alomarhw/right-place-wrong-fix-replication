"""detectors.py — CPU-runnable vulnerable-clone detectors.

Implements the contracted baseline family. All detectors are trained/calibrated
ONLY on the verbatim split (mirroring real-world training exposure to published
CVE code), then evaluated on both splits.

Detector types:
  - LexicalRecall:      char/token n-gram TF-IDF + MinHash kNN surface similarity
                        (memorization-sensitive control; should show LARGEST gap)
  - EncoderDetector:    small-encoder 'LLM detector' proxy — token TF-IDF +
                        LogisticRegression (stands in for frozen CodeBERT head on CPU)
  - SliceMatcher:       SRC VUL / VulSlicer slice-matching (semantics-aware;
                        should show SMALLEST gap)
  - VuddyHash:          VUDDY-style length-filtered normalized-hash matcher
  - VulPecker: char n-gram Jaccard similarity to known-vulnerable functions
  - LLMDetector: a real LLM (Anthropic API, RP_LLM_MODEL, default claude-haiku-4-5)
    under instruct / RAG / ungrounded prompting, temperature 0, disk-cached.

EncoderDetector is a TF-IDF + logistic-regression classifier; it stands in for a
fine-tuned CodeBERT/UniXcoder head and is NOT a neural encoder.

Key deps: scikit-learn==1.5.1, numpy==2.2.6, datasketch==1.6.5.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics.pairwise import cosine_similarity

from data_prep import canonical_slice, extract_slice

RANDOM_SEED = int(os.environ.get("RP_RANDOM_SEED", 42))

try:
    from datasketch import MinHash, MinHashLSHForest  # noqa: F401
    _HAVE_DATASKETCH = True
except Exception:  # noqa: BLE001
    _HAVE_DATASKETCH = False


def _tokens(code: str) -> list[str]:
    return re.findall(r"[A-Za-z_]\w*|[^\sA-Za-z_]", code)


def _char_ngrams(code: str, n: int = 4) -> set[str]:
    s = re.sub(r"\s+", "", code)
    return {s[i:i + n] for i in range(max(0, len(s) - n + 1))}


# ----------------------------------------------------------------------------
# Base interface
# ----------------------------------------------------------------------------
@dataclass
class _Example:
    code: str
    label: int


class BaseDetector:
    name = "base"

    def fit(self, train_codes: list[str], train_labels: list[int]) -> None:  # noqa: D401
        raise NotImplementedError

    def predict(self, codes: list[str]) -> np.ndarray:
        raise NotImplementedError

    def set_groups(self, groups: list[str] | None) -> None:
        """CVE id of each training row; queries passed to predict() are aligned to the
        same list. Only retrieval-based detectors use it (to exclude same-CVE examples)."""
        self.groups = list(groups) if groups is not None else None


# ----------------------------------------------------------------------------
# 1. Lexical-recall control: char/token n-gram TF-IDF + kNN surface similarity
# ----------------------------------------------------------------------------
class LexicalRecall(BaseDetector):
    name = "lexical_recall_control"

    def __init__(self, seed: int = RANDOM_SEED):
        self.vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1)
        self.clf = KNeighborsClassifier(n_neighbors=1, metric="cosine")
        self.seed = seed

    def fit(self, train_codes, train_labels):
        X = self.vec.fit_transform(train_codes)
        self.clf.fit(X, train_labels)

    def predict(self, codes):
        X = self.vec.transform(codes)
        return self.clf.predict(X)


# ----------------------------------------------------------------------------
# 2. Encoder 'LLM detector' proxy: token TF-IDF + logistic regression head
#    (stands in for a frozen CodeBERT/UniXcoder head; CPU-only, deterministic)
# ----------------------------------------------------------------------------
class EncoderDetector(BaseDetector):
    name = "finetuned_encoder_llm"

    def __init__(self, seed: int = RANDOM_SEED):
        self.vec = TfidfVectorizer(tokenizer=_tokens, token_pattern=None,
                                   ngram_range=(1, 2), min_df=1)
        self.clf = LogisticRegression(max_iter=1000, class_weight="balanced",
                                      random_state=seed)
        self.seed = seed

    def fit(self, train_codes, train_labels):
        X = self.vec.fit_transform(train_codes)
        if len(set(train_labels)) < 2:
            # degenerate: single class -> constant predictor
            self._const = int(train_labels[0]) if train_labels else 0
            self.clf = None
            return
        self._const = None
        self.clf.fit(X, train_labels)

    def predict(self, codes):
        if self.clf is None:
            return np.full(len(codes), getattr(self, "_const", 0), dtype=int)
        X = self.vec.transform(codes)
        return self.clf.predict(X)


# ----------------------------------------------------------------------------
# 3. SRC VUL / VulSlicer slice matcher: match canonical vulnerability slice
#    against known-vulnerable slice signatures (semantics-aware).
# ----------------------------------------------------------------------------
class SliceMatcher(BaseDetector):
    name = "slice_matcher"

    def __init__(self, threshold: float = 0.6, seed: int = RANDOM_SEED):
        self.threshold = threshold
        self.vec = TfidfVectorizer(tokenizer=_tokens, token_pattern=None, min_df=1)
        self._vuln_matrix = None

    def fit(self, train_codes, train_labels):
        slices = [canonical_slice(c) for c in train_codes]
        vuln_slices = [s for s, y in zip(slices, train_labels) if y == 1 and s]
        if not vuln_slices:
            vuln_slices = [s for s in slices if s][:1] or ["x"]
        self._all_slices = slices
        self.vec.fit([s if s else "x" for s in slices])
        self._vuln_matrix = self.vec.transform(vuln_slices)

    def predict(self, codes):
        qs = [canonical_slice(c) or "x" for c in codes]
        Q = self.vec.transform(qs)
        sims = cosine_similarity(Q, self._vuln_matrix)
        maxsim = sims.max(axis=1) if sims.shape[1] else np.zeros(len(codes))
        return (maxsim >= self.threshold).astype(int)


# ----------------------------------------------------------------------------
# 4. VUDDY-style length-filtered normalized-hash matcher.
# ----------------------------------------------------------------------------
class VuddyHash(BaseDetector):
    name = "vuddy_hash"

    def __init__(self, seed: int = RANDOM_SEED):
        self._vuln_hashes: set[str] = set()
        self._len_buckets: dict[int, set[str]] = {}

    @staticmethod
    def _normalize(code: str) -> str:
        code = re.sub(r"/\*.*?\*/", " ", code, flags=re.S)
        code = re.sub(r"//[^\n]*", " ", code)
        # abstract identifiers (VUDDY abstraction)
        code = re.sub(r"[A-Za-z_]\w*", "X", code)
        return re.sub(r"\s+", "", code)

    def _hash(self, code: str) -> tuple[int, str]:
        norm = self._normalize(code)
        return len(norm), hashlib.md5(norm.encode()).hexdigest()  # noqa: S324

    def fit(self, train_codes, train_labels):
        for c, y in zip(train_codes, train_labels):
            if y == 1:
                length, h = self._hash(c)
                self._vuln_hashes.add(h)
                self._len_buckets.setdefault(length, set()).add(h)

    def predict(self, codes):
        out = []
        for c in codes:
            length, h = self._hash(c)
            # exact normalized-hash match within same length bucket
            out.append(1 if h in self._len_buckets.get(length, set()) else 0)
        return np.array(out, dtype=int)


# ----------------------------------------------------------------------------
# 5. VulPecker code-similarity proxy: char-ngram Jaccard to vulnerable set.
# ----------------------------------------------------------------------------
class VulPecker(BaseDetector):
    name = "vulpecker"

    def __init__(self, threshold: float = 0.5, seed: int = RANDOM_SEED):
        self.threshold = threshold
        self._vuln_grams: list[set[str]] = []

    def fit(self, train_codes, train_labels):
        self._vuln_grams = [_char_ngrams(c) for c, y in zip(train_codes, train_labels) if y == 1]
        if not self._vuln_grams:
            self._vuln_grams = [_char_ngrams(train_codes[0])] if train_codes else [set()]

    def predict(self, codes):
        out = []
        for c in codes:
            g = _char_ngrams(c)
            best = 0.0
            for vg in self._vuln_grams:
                inter = len(g & vg)
                union = len(g | vg) or 1
                best = max(best, inter / union)
            out.append(1 if best >= self.threshold else 0)
        return np.array(out, dtype=int)


# ----------------------------------------------------------------------------
# 6/7/8. Real LLM detectors (Anthropic Messages API).
#   One model (RP_LLM_MODEL, default claude-haiku-4-5; training data through
#   Jul 2025, so post-cutoff CVEs published >= 2025-08-01 are 'unseen') under
#   three prompting regimes:
#     instruct_llm   : structured CWE-aware instruction prompt, function only
#     rag_llm        : same prompt + k nearest labelled training functions
#                      (TF-IDF cosine; near-duplicates of the query, cosine > 0.9
#                      on raw OR identifier-normalized code, are excluded so
#                      retrieval cannot return the item itself, a renamed copy
#                      of it, or its before/after partner); examples from the
#                      query's own CVE are always excluded (set_groups)
#     ungrounded_llm : minimal "is this vulnerable?" prompt, no guidance
#   Temperature 0; every response is cached on disk (sqlite) keyed by
#   (model, prompt, temperature, sample), so repeats and reruns are free and
#   results are reproducible from the cache. Without ANTHROPIC_API_KEY the run
#   fails loudly instead of falling back to a proxy.
# ----------------------------------------------------------------------------
LLM_MODEL = os.environ.get("RP_LLM_MODEL", "claude-haiku-4-5")
LLM_WORKERS = int(os.environ.get("RP_LLM_WORKERS", 8))


def _cache_path() -> Path:
    env = os.environ.get("RP_LLM_CACHE")
    for cand in ([Path(env)] if env else []) + [Path("data") / "_llm_cache.sqlite",
                                                  Path("results") / "_llm_cache.sqlite"]:
        try:
            cand.parent.mkdir(parents=True, exist_ok=True)
            sqlite3.connect(str(cand)).close()
            return cand
        except Exception:  # noqa: BLE001
            continue
    return Path("_llm_cache.sqlite")


class LLMClient:
    """Thread-safe cached wrapper around anthropic.Anthropic().messages.create."""
    _lock = threading.Lock()
    _instance = None

    def __init__(self):
        # Without a key the client still serves every cached response (offline replay of the
        # frozen cache); only a cache miss then fails, loudly, instead of falling back to a proxy.
        self.client = None
        if os.environ.get("ANTHROPIC_API_KEY"):
            import anthropic
            self.client = anthropic.Anthropic(max_retries=8)
        self.path = _cache_path()
        self.db = sqlite3.connect(str(self.path), check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS c (k TEXT PRIMARY KEY, v TEXT)")
        self.db.commit()
        self._key_locks: dict[str, threading.Lock] = {}
        self.calls = 0
        self.hits = 0
        self.in_tokens = 0
        self.out_tokens = 0
        print(f"[llm] model={LLM_MODEL} cache={self.path}")

    @classmethod
    def get(cls) -> "LLMClient":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def complete(self, system: str, user: str, max_tokens: int = 16,
                 temperature: float | None = 0.0, sample: int = 0, model: str | None = None) -> str:
        model = model or LLM_MODEL
        key = hashlib.sha256(json.dumps([model, system, user, max_tokens, temperature, sample])
                             .encode()).hexdigest()
        # One in-flight request per key: identical concurrent requests (e.g. ladder arms that
        # share their first attempt) wait for the first, and every caller returns the stored
        # value, so a re-run served from the cache reproduces the original run exactly.
        with self._lock:
            key_lock = self._key_locks.setdefault(key, threading.Lock())
        with key_lock:
            return self._complete_locked(key, model, system, user, max_tokens, temperature)

    def _complete_locked(self, key, model, system, user, max_tokens, temperature) -> str:
        with self._lock:
            row = self.db.execute("SELECT v FROM c WHERE k=?", (key,)).fetchone()
            if row is not None:
                self.hits += 1
                return row[0]
        if self.client is None:
            raise RuntimeError("Cache miss and ANTHROPIC_API_KEY is not set: this response is not in "
                               f"the frozen cache ({self.path}); set the key to query {model}.")
        for attempt in range(6):
            try:
                kwargs = {} if temperature is None else {"temperature": temperature}  # newer models reject it
                resp = self.client.messages.create(
                    model=model, max_tokens=max_tokens, **kwargs,
                    system=system, messages=[{"role": "user", "content": user}])
                break
            except Exception as exc:  # noqa: BLE001
                if attempt == 5:
                    raise
                print(f"[llm] retry after {type(exc).__name__}: {str(exc)[:120]}")
                time.sleep(5 * (attempt + 1))
        text = "".join(getattr(b, "text", "") for b in resp.content)
        with self._lock:
            self.calls += 1
            self.in_tokens += resp.usage.input_tokens
            self.out_tokens += resp.usage.output_tokens
            self.db.execute("INSERT OR IGNORE INTO c VALUES (?, ?)", (key, text))  # first write wins
            self.db.commit()
            return self.db.execute("SELECT v FROM c WHERE k=?", (key,)).fetchone()[0]

    def stats(self) -> dict:
        return {"model": LLM_MODEL, "api_calls": self.calls, "cache_hits": self.hits,
                "input_tokens": self.in_tokens, "output_tokens": self.out_tokens}


def llm_map(fn, xs: list) -> list:
    with ThreadPoolExecutor(max_workers=LLM_WORKERS) as ex:
        return list(ex.map(fn, xs))


_DETECT_SYSTEM = (
    "You are a security auditor reviewing C functions from open-source projects. "
    "Decide whether the function contains a memory-safety or input-validation "
    "vulnerability that an attacker could trigger (e.g. out-of-bounds read/write, "
    "integer overflow leading to a bad size, use-after-free, NULL dereference, "
    "missing length or state check). Code that already contains the necessary "
    "checks is SAFE. Answer with exactly one word: VULNERABLE or SAFE.")
_UNGROUNDED_SYSTEM = "Answer with exactly one word: VULNERABLE or SAFE."


def _id_normalize(code: str) -> str:
    """Comments/whitespace dropped and every non-keyword identifier mapped to ID, so a
    renamed or reformatted copy of a function stays near-identical to the original."""
    code = re.sub(r"/\*.*?\*/|//[^\n]*", " ", code, flags=re.S)
    kw = {"if", "else", "for", "while", "do", "return", "switch", "case", "break", "continue",
          "goto", "sizeof", "struct", "int", "char", "void", "unsigned", "const", "static"}
    return " ".join(t if (t in kw or not re.match(r"[A-Za-z_]", t)) else "ID"
                    for t in _tokens(code))


def _parse_verdict(text: str) -> int:
    t = text.strip().upper()
    if t.startswith("VULN") or ("VULNERABLE" in t and "SAFE" not in t):
        return 1
    return 0


class LLMDetector(BaseDetector):
    """Zero-shot / retrieval-augmented LLM vulnerable-function classifier."""

    def __init__(self, name: str, mode: str, k: int = 4, seed: int = RANDOM_SEED):
        self.name = name
        self.mode = mode  # 'instruct' | 'rag' | 'ungrounded'
        self.k = k
        self.seed = seed

    def fit(self, train_codes, train_labels):
        # Prompted LLMs are not trained; RAG indexes the labelled training functions.
        if self.mode == "rag":
            self._codes = list(train_codes)
            self._labels = [int(y) for y in train_labels]
            self._vec = TfidfVectorizer(tokenizer=_tokens, token_pattern=None, min_df=1)
            self._X = self._vec.fit_transform(self._codes)
            self._nvec = TfidfVectorizer(tokenizer=_tokens, token_pattern=None, min_df=1,
                                         ngram_range=(1, 3))
            self._NX = self._nvec.fit_transform([_id_normalize(c) for c in self._codes])

    def _prompt(self, code: str, qgroup: str | None = None) -> tuple[str, str]:
        groups = getattr(self, "groups", None) or [None] * len(getattr(self, "_codes", []))
        if self.mode == "ungrounded":
            return _UNGROUNDED_SYSTEM, f"Is this C function vulnerable?\n\n```c\n{code}\n```"
        user = f"Function under review:\n```c\n{code}\n```"
        if self.mode == "rag":
            sims = cosine_similarity(self._vec.transform([code]), self._X)[0]
            nsims = cosine_similarity(self._nvec.transform([_id_normalize(code)]), self._NX)[0]
            order = [i for i in np.argsort(-sims)
                     if sims[i] <= 0.9 and nsims[i] <= 0.9
                     and (qgroup is None or groups[i] != qgroup)][: self.k]
            shots = "\n\n".join(
                f"Reference example {j + 1} (labelled "
                f"{'VULNERABLE' if self._labels[i] else 'SAFE'}):\n```c\n{self._codes[i]}\n```"
                for j, i in enumerate(order))
            user = ("Labelled reference functions retrieved from a CVE database "
                    "(similar code, not the function under review):\n\n"
                    f"{shots}\n\n{user}")
        return _DETECT_SYSTEM, user

    def predict(self, codes):
        client = LLMClient.get()

        groups = getattr(self, "groups", None)
        qgroups = groups if groups is not None and len(groups) == len(codes) else [None] * len(codes)

        def one(pair):
            system, user = self._prompt(*pair)
            return _parse_verdict(client.complete(system, user, max_tokens=8))
        return np.array(llm_map(one, list(zip(codes, qgroups))), dtype=int)


def make_instruct_llm(seed=RANDOM_SEED):
    return LLMDetector("instruct_llm", "instruct", seed=seed)


def make_rag_llm(seed=RANDOM_SEED):
    return LLMDetector("rag_llm", "rag", seed=seed)


def make_ungrounded_llm(seed=RANDOM_SEED):
    return LLMDetector("ungrounded_llm", "ungrounded", seed=seed)


# ----------------------------------------------------------------------------
# Registry mapping contract baseline names -> detector factory
# ----------------------------------------------------------------------------
DETECTOR_REGISTRY = {
    "SRC VUL vsvector slice matching (foundation, \\cite{57b456a85303a715d9311a88cd3de662b631778c}) — deterministic detector baseline":
        lambda s=RANDOM_SEED: SliceMatcher(seed=s),
    "VUDDY hashing-based vulnerable clone detector (from VUDDY corpus / salimi2022vulslicer comparison)":
        lambda s=RANDOM_SEED: VuddyHash(seed=s),
    "VulPecker code-similarity vulnerability detector (li2016vulpecker)":
        lambda s=RANDOM_SEED: VulPecker(seed=s),
    "Fine-tuned CodeBERT/UniXcoder vulnerability classifier (LLM detector)":
        lambda s=RANDOM_SEED: EncoderDetector(seed=s),
    "Open-weight instruct LLM detector (e.g., StarCoder2/CodeLlama, elatoubi2025assessing-style prompting)":
        lambda s=RANDOM_SEED: make_instruct_llm(s),
    "RAG-based LLM vulnerability detector (antal2026evaluating / kaniewski2026revisiting style)":
        lambda s=RANDOM_SEED: make_rag_llm(s),
    "Ungrounded LLM patching (same LLM, no slice/CVE grounding) — primary RQ3 baseline":
        lambda s=RANDOM_SEED: make_ungrounded_llm(s),
    "VulSlicer slice-based detector (salimi2022vulslicer)":
        lambda s=RANDOM_SEED: SliceMatcher(threshold=0.55, seed=s),
}

# Core three detectors highlighted in the RQ1 decision rule (memorization->reasoning spectrum)
CORE_DETECTORS = {
    "lexical_recall_control": lambda s=RANDOM_SEED: LexicalRecall(seed=s),
    "finetuned_encoder_llm": lambda s=RANDOM_SEED: EncoderDetector(seed=s),
    "slice_matcher_src_vul": lambda s=RANDOM_SEED: SliceMatcher(seed=s),
}


def build_all_detectors(seed: int = RANDOM_SEED) -> dict[str, BaseDetector]:
    dets = {}
    for k, factory in CORE_DETECTORS.items():
        dets[k] = factory(seed)
    for name, factory in DETECTOR_REGISTRY.items():
        dets[name] = factory(seed)
    return dets


if __name__ == "__main__":
    from data_prep import build_corpus
    items, _ = build_corpus(n_cves=10, allow_synthetic=True)
    codes = [it.code for it in items]
    labels = [it.label for it in items]
    for name, det in build_all_detectors().items():
        det.fit(codes, labels)
        pred = det.predict(codes)
        acc = float((pred == np.array(labels)).mean())
        print(f"{name[:40]:40s} train_acc={acc:.3f}")