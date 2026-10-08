"""sitecustomize.py — block torch import in the default experiment process.

On this machine ``import torch`` (pulled in transitively by transformers/datasets)
raises a native libc++ ``std::system_error`` and can terminate the whole process at
interpreter shutdown. The default SliceGuard pipeline is CPU-only and does NOT need
torch: onnx_encoder.py uses a hashed-ngram proxy unless RP_USE_REAL_ENCODER=1.

Python imports ``sitecustomize`` automatically at startup (if importable on the
path). We install a lightweight import guard that makes ``import torch`` /
``import transformers`` fail with a clean ImportError in the default mode, so any
accidental/transitive import degrades gracefully to the proxy path instead of
crashing the interpreter. When RP_USE_REAL_ENCODER=1 the guard is disabled and the
real libraries may load.
"""
from __future__ import annotations

import os
import sys


def _install_guard() -> None:
    if os.environ.get("RP_USE_REAL_ENCODER", "0") in ("1", "true", "True"):
        return  # real encoder explicitly requested — allow torch/transformers.

    import importlib.abc
    import importlib.machinery

    blocked = {"torch", "transformers"}

    class _BlockFinder(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):  # noqa: D401
            root = fullname.split(".", 1)[0]
            if root in blocked:
                raise ImportError(
                    f"{fullname} import blocked in default CPU mode "
                    "(set RP_USE_REAL_ENCODER=1 to enable)."
                )
            return None

    # prepend so it intercepts before the normal finders
    sys.meta_path.insert(0, _BlockFinder())


try:
    _install_guard()
except Exception:  # pragma: no cover — never break startup
    pass