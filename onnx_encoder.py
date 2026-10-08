"""onnx_encoder.py — frozen code-encoder embeddings (CPU-only).

The RQ2 contract includes a FROZEN pre-trained code encoder (CodeBERT/UniXcoder)
detector. Running a real transformer on CPU is optional and slow; more importantly,
on this platform ``import torch`` (pulled in by transformers) raises a native
libc++ ``std::system_error`` and can terminate the whole process at interpreter
shutdown. So by DEFAULT this module NEVER imports torch/transformers: it uses a
deterministic, content-sensitive hashed-ngram embedding that behaves like a
lexical-recall-sensitive encoder.

torch/transformers are imported ONLY inside a function guarded by
RP_USE_REAL_ENCODER=1, so the default pipeline never touches them. Both paths are
deterministic given RP_RANDOM_SEED. The fallback is clearly a PROXY and is recorded
as such in provenance by callers.
"""
from __future__ import annotations

import os
import hashlib
import functools
from typing import Iterable

import numpy as np

RANDOM_SEED = int(os.environ.get("RP_RANDOM_SEED", 42))
_EMBED_DIM = 256


def _use_real_encoder() -> bool:
    return os.environ.get("RP_USE_REAL_ENCODER", "0") in ("1", "true", "True")


@functools.lru_cache(maxsize=1)
def _load_real_encoder():
    """Attempt to load a frozen CodeBERT encoder on CPU. Returns (tok, model) or None.

    torch/transformers are imported here, lazily, and ONLY when RP_USE_REAL_ENCODER=1,
    so a broken torch install cannot crash the default (proxy) pipeline.
    """
    if not _use_real_encoder():
        return None
    try:
        import torch  # noqa: F401 — imported lazily and only when explicitly enabled
        from transformers import AutoTokenizer, AutoModel

        name = os.environ.get("RP_ENCODER_NAME", "microsoft/codebert-base")
        tok = AutoTokenizer.from_pretrained(name)
        model = AutoModel.from_pretrained(name)
        model.eval()
        torch.manual_seed(RANDOM_SEED)
        return (tok, model)
    except Exception as exc:  # pragma: no cover - native/offline dependent
        print(f"[onnx_encoder] real encoder unavailable ({exc}); using hashed proxy.")
        return None


def _tokenize(text: str) -> list[str]:
    buf, toks = [], []
    for ch in text:
        if ch.isalnum() or ch == "_":
            buf.append(ch)
        else:
            if buf:
                toks.append("".join(buf))
                buf = []
    if buf:
        toks.append("".join(buf))
    return toks


def _hashed_ngram_embedding(text: str, dim: int = _EMBED_DIM) -> np.ndarray:
    """Deterministic hashed character+token n-gram embedding.

    Sensitive to surface form: verbatim text yields a near-identical vector,
    while renamed identifiers / reordered statements shift it — exactly the
    lexical-recall behaviour the frozen-encoder detector is meant to exhibit.
    """
    vec = np.zeros(dim, dtype=np.float64)
    toks = _tokenize(text.lower())
    grams = list(toks)
    grams += [f"{a}~{b}" for a, b in zip(toks, toks[1:])]
    clean = "".join(toks)
    grams += [clean[i:i + 4] for i in range(0, max(0, len(clean) - 3))]
    for g in grams:
        h = int(hashlib.md5((str(RANDOM_SEED) + g).encode()).hexdigest(), 16)
        idx = h % dim
        sign = 1.0 if (h >> 8) & 1 else -1.0
        vec[idx] += sign
    n = np.linalg.norm(vec)
    if n > 0:
        vec /= n
    return vec


def _real_embedding(text: str) -> np.ndarray:  # pragma: no cover
    loaded = _load_real_encoder()
    if loaded is None:
        return _hashed_ngram_embedding(text)
    import torch  # lazy

    tok, model = loaded
    with torch.no_grad():
        enc = tok(text, return_tensors="pt", truncation=True, max_length=256)
        out = model(**enc)
        emb = out.last_hidden_state.mean(dim=1).squeeze(0).cpu().numpy()
    n = np.linalg.norm(emb)
    if n > 0:
        emb = emb / n
    return emb.astype(np.float64)


def embed(text: str) -> np.ndarray:
    """Return a unit-norm embedding for one code string."""
    if _use_real_encoder():
        return _real_embedding(text)
    return _hashed_ngram_embedding(text)


def embed_many(texts: Iterable[str]) -> np.ndarray:
    return np.vstack([embed(t) for t in texts])


def cosine(a: np.ndarray, b: np.ndarray) -> float:
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    if na == 0 or nb == 0:
        return 0.0
    return float(np.dot(a, b) / (na * nb))


def encoder_kind() -> str:
    """Report which encoder path is active (for provenance)."""
    if _use_real_encoder() and _load_real_encoder() is not None:
        return "frozen_codebert_cpu"
    return "hashed_ngram_proxy"


if __name__ == "__main__":
    a = "int main() { char buf[8]; strcpy(buf, src); return 0; }"
    b = "int main() { char tmp[8]; strcpy(tmp, input); return 0; }"  # renamed
    print("encoder kind:", encoder_kind())
    print("verbatim self-sim:", cosine(embed(a), embed(a)))
    print("renamed-variant sim:", cosine(embed(a), embed(b)))