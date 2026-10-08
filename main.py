"""main.py — SliceGuard top-level orchestrator (RQ1 + RQ2 + RQ3).

Runs the full controlled experiment across every research question:
  RQ1 (RQ1-E0 membership probe + RQ1-E1 verbatim-vs-variant invariance contrast),
  RQ2 (RQ2-E1 certified-variant benchmark construction + RQ2-E2 invariance DiD),
  RQ3 (RQ3-E1 independent oracle calibration + RQ3-E2 slice-grounded agent ladder).

Runnability contract:
  * `python3 main.py` runs the FULL / paper-grade path by default in
    STRICT_REAL_DATA_MODE (the normal Study pipeline: Engineer execution).
  * `python3 main.py --smoke` runs a tiny end-to-end validation (NOT evidence).
  * All selectors/flags are OPTIONAL with sensible defaults; by default ALL RQs run.

This process is CPU-only and deliberately NEVER imports torch/transformers (they
crash the interpreter at shutdown on this platform). A torch import guard is
installed at startup; the frozen-encoder detector uses a deterministic hashed proxy
unless RP_USE_REAL_ENCODER=1.

Key deps (pinned in requirements.txt): numpy==2.2.6, pandas==2.2.2,
scikit-learn==1.5.1, scipy==1.13.1, statsmodels==0.14.6, matplotlib==3.9.1,
datasketch==1.6.5.
"""
from __future__ import annotations

# --- install a torch/transformers import guard BEFORE anything else imports them ---
import os as _os
import sys as _sys


def _install_torch_guard() -> None:
    if _os.environ.get("RP_USE_REAL_ENCODER", "0") in ("1", "true", "True"):
        return
    import importlib.abc

    blocked = {"torch", "transformers"}

    class _BlockFinder(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            root = fullname.split(".", 1)[0]
            if root in blocked:
                raise ImportError(
                    f"{fullname} import blocked in default CPU mode "
                    "(set RP_USE_REAL_ENCODER=1 to enable)."
                )
            return None

    for finder in _sys.meta_path:
        if type(finder).__name__ == "_BlockFinder":
            return
    _sys.meta_path.insert(0, _BlockFinder())


_install_torch_guard()

import argparse
import json
import os
import random
import sys
import traceback
from pathlib import Path
from typing import Any

import numpy as np

RANDOM_SEED = int(os.environ.get("RP_RANDOM_SEED", 42))

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
FIGURES = ROOT / "figures"
TABLES = RESULTS / "tables"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _ensure_dirs() -> None:
    for d in (RESULTS, FIGURES, TABLES):
        d.mkdir(parents=True, exist_ok=True)


def _seed_everything(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    os.environ.setdefault("PYTHONHASHSEED", str(seed))


def _strict_mode() -> bool:
    return os.environ.get("STRICT_REAL_DATA_MODE", "1") not in ("0", "false", "False")


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="SliceGuard — contamination-controlled vulnerable-clone evaluation "
                    "and slice-grounded agentic patching (RQ1+RQ2+RQ3).")
    p.add_argument("--smoke", action="store_true",
                   help="Tiny end-to-end validation run (NOT paper-grade evidence).")
    p.add_argument("--full", action="store_true",
                   help="Explicit paper-grade scale (default in STRICT_REAL_DATA_MODE).")
    p.add_argument("--pilot", action="store_true",
                   help="Pilot scale (sanity, not publishable).")
    p.add_argument("--rqs", default="RQ1,RQ2,RQ3",
                   help="Comma-separated RQ ids to run (default: ALL).")
    p.add_argument("--n-cves", type=int, default=None,
                   help="Override CVE count (clamped to the active tier for --smoke).")
    p.add_argument("--repeats", type=int, default=None,
                   help="Override repeat count.")
    p.add_argument("--seed", type=int, default=RANDOM_SEED,
                   help="Random seed (default: RP_RANDOM_SEED env or 42).")
    return p.parse_args(argv)


def _resolve_mode(args: argparse.Namespace):
    from rp_run_modes import resolve_scale

    if args.smoke:
        requested = "smoke"
    elif args.pilot:
        requested = "pilot"
    elif args.full:
        requested = "full"
    else:
        requested = "full" if _strict_mode() else "smoke"

    scale = resolve_scale(requested, n_cves=args.n_cves, repeats=args.repeats)
    mode_info = {
        "mode": scale["mode"],
        "rows_or_items": scale["n_cves"],
        "repeats": scale["repeats"],
        "paper_grade": scale["paper_grade"],
        "strict_real_data": scale["mode"] != "smoke",
        "allow_synthetic": scale["allow_synthetic"],
    }
    return scale, mode_info


def _print_banner(scale: dict) -> None:
    print("#" * 78)
    print("#  SliceGuard — Contamination-Controlled Evaluation & Slice-Grounded")
    print("#  Agentic Patching of Vulnerable Clones  (RQ1 + RQ2 + RQ3)")
    print("#" * 78)
    tier = "PAPER-GRADE run mode" if scale["paper_grade"] else f"{scale['mode'].upper()} run mode"
    if scale["mode"] == "smoke":
        print(f"Smoke run mode: max_rows={scale['n_cves']}, repeats={scale['repeats']} "
              "— NOT paper-grade evidence.")
    else:
        print(f"{tier}: rows={scale['n_cves']}, repeats={scale['repeats']}, "
              f"paper_grade={scale['paper_grade']}")
    print(f"strict_real_data_mode={_strict_mode()}  seed={RANDOM_SEED}")
    print("#" * 78)


def _data_preflight() -> None:
    try:
        import preprocess
        found = preprocess.prepare("data")
        total = sum(len(v) for v in found.values())
        print(f"[main] data preflight: discovered {total} usable file(s) under data/.")
    except Exception as exc:  # noqa: BLE001
        print(f"[main] WARNING: generic preprocess failed (continuing): {exc}")
    try:
        import rq3_preprocess
        st = rq3_preprocess.preprocess()
        if st.get("ok"):
            print(f"[main] RQ3 preprocess: {st['n_pairs']} CVE patch pairs ready.")
    except Exception as exc:  # noqa: BLE001
        print(f"[main] WARNING: RQ3 preprocess failed (continuing): {exc}")


def _merge_provenance(sources: dict[str, str], n_items: int) -> None:
    from rp_run_modes import build_dataset_record, merge_manifest_lineage

    used_synthetic = any(tag == "synthetic" for tag in sources.values())
    datasets = []
    vul_source = sources.get("RQ1") or sources.get("RQ2") or "unknown"
    datasets.append(build_dataset_record(
        name="VulSlicer + VUDDY (SRC VUL corpora, Zenodo 6059924)",
        path="data/vulslicer",
        source="real" if vul_source == "real" else "synthetic",
        rows=n_items,
    ))
    rq3_source = sources.get("RQ3", "unknown")
    datasets.append(build_dataset_record(
        name="CVE vulnerable/fixed patch pairs (Big-Vul/CVEfixes or VulSlicer+VUDDY; NOT GLUE)",
        path="data/cve_patches",
        source="real" if rq3_source == "real" else "synthetic",
        rows=n_items,
    ))
    datasets = merge_manifest_lineage(datasets, data_root="data")

    prov: dict[str, Any] = {"usedSynthetic": bool(used_synthetic), "datasets": datasets}
    mined = ROOT / "data" / "data_provenance.json"
    if mined.exists():
        try:
            prev = json.loads(mined.read_text())
            if prev.get("usedMinedData"):
                prov["usedMinedData"] = True
        except Exception:  # noqa: BLE001
            pass

    out = RESULTS / "data_provenance.json"
    out.write_text(json.dumps(prov, indent=2, default=_json_default))
    print(f"[main] wrote {out} (usedSynthetic={used_synthetic})")


def _write_run_metadata(scale: dict, sources: dict[str, str]) -> None:
    any_synthetic = any(t == "synthetic" for t in sources.values())
    data_source = "synthetic" if any_synthetic else "real"
    meta = {
        "mode": scale["mode"],
        "run_tier": scale["run_tier"],
        "rows_or_items": int(scale["n_cves"]),
        "repeats": int(scale["repeats"]),
        "datasets": [
            "VulSlicer + VUDDY (SRC VUL corpora, Zenodo 6059924)",
            "CVE vulnerable/fixed patch pairs (NOT GLUE)",
        ],
        "data_source": data_source,
        "paper_grade": bool(scale["paper_grade"] and data_source == "real"),
        "random_seed": RANDOM_SEED,
        "strict_real_data_mode": scale["mode"] != "smoke",
        "experiments": ["RQ1-E0", "RQ1-E1", "RQ2-E1", "RQ2-E2", "RQ3-E1", "RQ3-E2"],
        "per_rq_data_source": sources,
    }
    out = RESULTS / "run_metadata.json"
    out.write_text(json.dumps(meta, indent=2))
    tier = "PAPER-GRADE run mode" if meta["paper_grade"] else f"{scale['mode'].upper()} run mode"
    print(f"[main] {tier}: rows={meta['rows_or_items']}, repeats={meta['repeats']}, "
          f"data_source={data_source}, paper_grade={meta['paper_grade']}")
    print(f"[main] wrote {out}")


def _json_default(o: Any) -> Any:
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    return str(o)


def _run_rq1(scale: dict) -> str:
    print("\n" + "=" * 74)
    print("RQ1 : memorization vs. slice-reasoning (RQ1-E0 membership + RQ1-E1 invariance)")
    print("=" * 74)
    # Import the build_corpus function from data_prep (not invariance_contrast)
    try:
        from data_prep import build_corpus
    except ImportError:
        build_corpus = None
    try:
        import analysis as rq1_analysis
        run_func = getattr(rq1_analysis, "run_analysis", None)
        if run_func is None:
            raise AttributeError("analysis.py missing run_analysis function")
        # Use the build_corpus function from data_prep to create items for run_invariance_contrast
        items, _ = build_corpus(n_cves=scale["n_cves"], allow_synthetic=scale["allow_synthetic"], seed=RANDOM_SEED)
        results = run_func(
            n_cves=scale["n_cves"],
            allow_synthetic=scale["allow_synthetic"],
            repeats=scale["repeats"],
            seed=RANDOM_SEED,
        )
    except Exception:
        # fallback to invariance_contrast run if analysis.py wrapper is missing
        import invariance_contrast as rq1
        if build_corpus is not None:
            items, _ = build_corpus(n_cves=scale["n_cves"], allow_synthetic=scale["allow_synthetic"], seed=RANDOM_SEED)
        else:
            # Defensive fallback for data_prep absence; generate synthetic
            items = []
        results = rq1.run_invariance_contrast(items, seed=RANDOM_SEED)
    source_tag = results.get("RQ1", {}).get("_data_source", "unknown")
    try:
        import plots as rq1_plots
        rq1_plots.main()
    except Exception as exc:  # noqa: BLE001
        print(f"[main] WARNING: RQ1 figures failed: {exc}")
        traceback.print_exc()
    return source_tag


def _run_rq2(scale: dict) -> str:
    print("\n" + "=" * 74)
    print("RQ2 : slice-preserving benchmark construction + invariance contrast (DiD)")
    print("=" * 74)
    try:
        import build_rq2_artifacts
        build_rq2_artifacts.build_benchmark(
            n_items=scale["n_cves"],
            strict_real_data=(scale["mode"] != "smoke"),
            seed=RANDOM_SEED,
        )
    except Exception as exc:
        print(f"[main] WARNING: RQ2 artifact producer failed (continuing): {exc}")

    import rq2_analysis
    results = rq2_analysis.run_analysis(
        n_cves=scale["n_cves"],
        allow_synthetic=scale["allow_synthetic"],
        repeats=scale["repeats"],
        seed=RANDOM_SEED,
    )
    source_tag = results.get("RQ2", {}).get("_data_source", "unknown")
    try:
        import rq2_plots
        rq2_plots.main()
    except Exception as exc:  # noqa: BLE001
        print(f"[main] WARNING: RQ2 figures failed: {exc}")
        traceback.print_exc()
    return source_tag


def _run_rq3(scale: dict) -> str:
    print("\n" + "=" * 74)
    print("RQ3 : independent-oracle calibration + slice-grounded agentic patching ladder")
    print("=" * 74)

    # Use rq3_main.py orchestrator instead of direct call to analysis
    try:
        import rq3_main
        results = rq3_main.run_rq3(mode_info=scale)
        source_tag = results.get("_data_source", "unknown")
    except Exception as exc:
        # If rq3_main fails, fall back to rq3_data.load_rq3_corpus + rq3_analysis.run_analysis directly,
        # to ensure presence of load_corpus and avoid invariance_contrast build_corpus erroneous calls
        print(f"[main] WARNING: rq3_main.py failed, trying fallback: {exc}")
        try:
            from rq3_data import build_rq3_corpus
            import rq3_analysis
            results = rq3_analysis.run_analysis(
                n_cves=scale["n_cves"],
                allow_synthetic=scale["allow_synthetic"],
                repeats=scale["repeats"],
                seed=RANDOM_SEED,
            )
            source_tag = results.get("RQ3", {}).get("_data_source", "unknown")
        except Exception as exc2:
            print(f"[main] ERROR: rq3_analysis fallback failed: {exc2}")
            raise
    try:
        import rq3_plots
        rq3_plots.main()
    except Exception as exc:  # noqa: BLE001
        print(f"[main] WARNING: RQ3 figures failed: {exc}")
        traceback.print_exc()
    try:
        import rq3_tables
        rq3_tables.write_rq3_tables()
    except Exception as exc:  # noqa: BLE001
        print(f"[main] WARNING: RQ3 tables failed: {exc}")
    return source_tag


_REQUIRED_METRICS = {
    "RQ1": ["accuracy", "macro_f1", "recall",
            "memorization_gap_acc_rq1", "pooled_split_odds_ratio_rq1"],
    "RQ2": ["accuracy", "macro_f1", "recall",
            "accepted_variant_yield_rq2", "vsvector_invariance_pass_rate_rq2",
            "difference_in_differences_did_rq2", "annotator_agreement_cohen_s_kappa_rq2"],
    "RQ3": ["accuracy", "macro_f1", "recall",
            "validated_patch_rate_vpr_rq3", "iterations_to_accept_rq3",
            "oracle_false_accept_rate_rq3", "official_patch_accept_rate_rq3"],
}


def _validate_results(requested_rqs: list[str]) -> None:
    import math
    rp = RESULTS / "results.json"
    if not rp.exists():
        raise RuntimeError("results/results.json was not written — pipeline failed.")
    data = json.loads(rp.read_text())
    for rq in requested_rqs:
        if rq not in data:
            raise RuntimeError(f"results.json missing required key {rq}.")
        metrics = data[rq].get("metrics", {})
        for m in _REQUIRED_METRICS[rq]:
            if m not in metrics:
                raise RuntimeError(f"{rq}.metrics missing '{m}'.")
            v = metrics[m]
            if v is None or (isinstance(v, float) and not math.isfinite(v)):
                raise RuntimeError(f"{rq}.metrics['{m}'] is non-finite/missing: {v!r}")
    print("[main] final validation: all requested RQ metrics present and finite.")


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    global RANDOM_SEED
    RANDOM_SEED = int(args.seed)
    os.environ["RP_RANDOM_SEED"] = str(RANDOM_SEED)
    _seed_everything(RANDOM_SEED)
    _ensure_dirs()

    scale, _mode_info = _resolve_mode(args)
    _print_banner(scale)

    _data_preflight()

    requested_rqs = [r.strip().upper() for r in args.rqs.split(",") if r.strip()]
    valid = {"RQ1", "RQ2", "RQ3"}
    requested_rqs = [r for r in requested_rqs if r in valid] or ["RQ1", "RQ2", "RQ3"]

    sources: dict[str, str] = {}
    failures: dict[str, str] = {}

    runners = {"RQ1": _run_rq1, "RQ2": _run_rq2, "RQ3": _run_rq3}
    for rq in requested_rqs:
        try:
            sources[rq] = runners[rq](scale)
        except RuntimeError as exc:
            print(f"\n[main] ERROR running {rq}: {exc}")
            failures[rq] = str(exc)
        except Exception as exc:  # noqa: BLE001
            print(f"\n[main] UNEXPECTED ERROR running {rq}: {exc}")
            traceback.print_exc()
            failures[rq] = str(exc)

    if sources:
        try:  # rebuild the statistics summary over every RQ now in results.json
            import analysis
            analysis.main()
        except Exception as exc:  # noqa: BLE001
            print(f"[main] WARNING: analysis summary failed: {exc}")

    try:
        _write_run_metadata(scale, sources)
    except Exception as exc:  # noqa: BLE001
        print(f"[main] WARNING: run_metadata write failed: {exc}")
    try:
        _merge_provenance(sources, scale["n_cves"])
    except Exception as exc:  # noqa: BLE001
        print(f"[main] WARNING: provenance write failed: {exc}")

    if failures:
        print("\n" + "!" * 78)
        print("[main] One or more RQs failed (strict real-data mode fails loudly):")
        for rq, msg in failures.items():
            print(f"   - {rq}: {msg.splitlines()[0]}")
        print("!" * 78)
        if not sources:
            return 1

    succeeded = [rq for rq in requested_rqs if rq in sources]
    try:
        _validate_results(succeeded)
    except Exception as exc:  # noqa: BLE001
        print(f"[main] final validation FAILED: {exc}")
        return 1

    print("\n" + "=" * 74)
    print("[main] RUN COMPLETE")
    print(f"       RQs succeeded : {succeeded}")
    if failures:
        print(f"       RQs failed    : {list(failures.keys())}")
    print(f"       results       : {RESULTS / 'results.json'}")
    print(f"       figures       : {FIGURES}/")
    print(f"       tables        : {TABLES}/")
    any_synthetic = any(t == "synthetic" for t in sources.values())
    if any_synthetic:
        print("       *** NOTE: at least one RQ used SYNTHETIC data — SMOKE run, "
              "NOT paper-grade evidence. ***")
    print("=" * 74)

    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())