"""Pytest configuration: expose the project root on sys.path and fix the seed.

This lets `pytest` import the RQ1-ALT1 helper modules (detectors, variant_builder,
invariance_contrast, ...) without installation, and makes any randomness used in
tests deterministic.
"""
from __future__ import annotations

import os
import random
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

RANDOM_SEED = int(os.environ.get("RP_RANDOM_SEED", 42))
random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)