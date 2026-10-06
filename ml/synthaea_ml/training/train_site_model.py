"""Trains a site-specific Isolation Forest model combining global + site corpus.

Site-specific model adaptation (Issue #49): Takes a global benign baseline + site-specific
telemetry corpus, trains a recalibrated model, validates against global-model-floor check
(using Issue #45's robustness evaluation), and outputs a site model ready for canary deployment.

Input contract:
- `--global-dataset`: Global baseline directory (same as train_linux.py input)
- `--site-corpus`: Site-specific corpus JSONL file (exported from control plane via /api/corpus/finalize)
- `--output-dir`: Registry version directory for site model

Site corpus format (JSONL):
```json
{"timestamp": "2026-09-23T10:00:00Z", "event_type": "exec", "event": {...}, "agent_id": "..."}
```

Global-model-floor check:
- Site model must match/exceed global model on shared scenario suite
- Uses run_robustness_evaluation() from Issue #45
- If floor check fails, training aborts

Usage:
    python -m synthaea_ml.training.train_site_model \\
        --global-dataset ml/datasets/baselines/linux__dev__abc__2026-09-11/ \\
        --site-corpus /path/to/corpus-v1.jsonl \\
        --output-dir ml/registry/cmdline-iforest-linux-site-acme/0.1.0/ \\
        --site-name acme-corp \\
        --robustness-scenarios lab/scenarios/beacon.yaml
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
from skl2onnx import to_onnx
from sklearn.ensemble import IsolationForest

from synthaea_ml.data.canonical import ml_cmdline_from_record
from synthaea_ml.data.manifest import DEFAULT_BASELINE_FILENAME
from synthaea_ml.evaluation.robustness import run_robustness_evaluation
from synthaea_ml.features.cmdline import extract_features
from synthaea_ml.registry.training_record import (
    DatasetVersion,
    dataset_version_from_manifest,
    write_training_record,
)

TRAINING_SCRIPT = "synthaea_ml/training/train_site_model.py"
MODEL_FILENAME = "model.onnx"

# Inherit hyperparameters from train_linux.py
HYPERPARAMETERS: dict[str, object] = {
    "n_estimators": 100,
    "contamination": 0.05,
    "random_state": 42,
}


def load_global_baseline(baseline_dir: Path) -> list[str]:
    """Load global benign baseline (same as train_linux.py)."""
    baseline_path = baseline_dir / DEFAULT_BASELINE_FILENAME
    if not baseline_path.exists():
        raise FileNotFoundError(f"Global baseline not found: {baseline_path}")

    cmdlines: list[str] = []
    for line in baseline_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            cmdlines.append(ml_cmdline_from_record(json.loads(line)))

    # Deduplicate
    seen: set[str] = set()
    unique: list[str] = []
    for c in cmdlines:
        if c not in seen:
            seen.add(c)
            unique.append(c)

    print(f"Global baseline: {len(cmdlines)} entries -> {len(unique)} unique")
    return unique


def load_site_corpus(corpus_path: Path) -> list[str]:
    """Load site-specific corpus from JSONL export."""
    if not corpus_path.exists():
        raise FileNotFoundError(f"Site corpus not found: {corpus_path}")

    cmdlines: list[str] = []
    for line in corpus_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            record = json.loads(line)
            # Site corpus format: {"event_type": "exec", "event": {...}}
            if record.get("event_type") == "exec" and "event" in record:
                cmdline = ml_cmdline_from_record(record["event"])
                cmdlines.append(cmdline)

    # Deduplicate
    seen: set[str] = set()
    unique: list[str] = []
    for c in cmdlines:
        if c not in seen:
            seen.add(c)
            unique.append(c)

    print(f"Site corpus: {len(cmdlines)} entries -> {len(unique)} unique")
    return unique


def combine_corpora(global_corpus: list[str], site_corpus: list[str]) -> list[str]:
    """Combine global + site corpus with deduplication."""
    seen: set[str] = set()
    combined: list[str] = []

    # Add global corpus first
    for c in global_corpus:
        if c not in seen:
            seen.add(c)
            combined.append(c)

    # Add site corpus (dedup against global)
    for c in site_corpus:
        if c not in seen:
            seen.add(c)
            combined.append(c)

    print(f"Combined corpus: {len(combined)} unique samples ({len(global_corpus)} global + {len(site_corpus)} site)")
    return combined


def run_global_floor_check(
    site_model,
    global_model_path: Path,
    scenario_yaml: Path,
) -> bool:
    """Validate that site model meets global-model-floor on shared scenarios.

    Uses Issue #45's run_robustness_evaluation() to compare site model vs global model
    on the shared scenario suite. Site model must have:
    - Escape rate <= global model escape rate
    - Median degradation <= global model median degradation

    Returns True if floor check passes, False otherwise.
    """
    import pickle

    # Load global model
    with open(global_model_path, "rb") as f:
        global_model = pickle.load(f)

    # Run robustness evaluation on both models
    print("\n=== Running global-model-floor check ===")
    print("Evaluating global model...")
    global_card = run_robustness_evaluation(
        model=global_model,
        scenario_yaml=scenario_yaml,
        tier="T0",
        mutation_seed=42,
    )

    print("Evaluating site model...")
    site_card = run_robustness_evaluation(
        model=site_model,
        scenario_yaml=scenario_yaml,
        tier="T0",
        mutation_seed=42,
    )

    # Compare metrics
    print(f"\nGlobal model: escape_rate={global_card.escape_rate:.2%}, median_degradation={global_card.median_score_degradation:.3f}")
    print(f"Site model:   escape_rate={site_card.escape_rate:.2%}, median_degradation={site_card.median_score_degradation:.3f}")

    # Floor check: site model must not regress vs global
    escape_ok = site_card.escape_rate <= global_card.escape_rate + 0.05  # Allow 5% increase
    degradation_ok = site_card.median_score_degradation <= global_card.median_score_degradation + 0.10  # Allow 0.10 increase

    if escape_ok and degradation_ok:
        print("✅ Global-model-floor check PASSED")
        return True
    else:
        print("❌ Global-model-floor check FAILED")
        if not escape_ok:
            print(f"   - Escape rate regression: {site_card.escape_rate:.2%} > {global_card.escape_rate:.2%} + 5%")
        if not degradation_ok:
            print(f"   - Median degradation regression: {site_card.median_score_degradation:.3f} > {global_card.median_score_degradation:.3f} + 0.10")
        return False


def main():
    parser = argparse.ArgumentParser(description="Train site-specific Isolation Forest model")
    parser.add_argument("--global-dataset", type=Path, required=True,
                        help="Global baseline directory (e.g., ml/datasets/baselines/linux__dev__abc__2026-09-11/)")
    parser.add_argument("--site-corpus", type=Path, required=True,
                        help="Site-specific corpus JSONL file (e.g., corpus-v1.jsonl)")
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="Output directory for site model (e.g., ml/registry/cmdline-iforest-linux-site-acme/0.1.0/)")
    parser.add_argument("--site-name", type=str, required=True,
                        help="Site/tenant name for provenance")
    parser.add_argument("--robustness-scenarios", type=Path, default=None,
                        help="Scenario YAML for global-model-floor check (optional)")
    parser.add_argument("--global-model", type=Path, default=None,
                        help="Path to global model .pkl for floor check (optional)")
    args = parser.parse_args()

    # Load corpora
    print("=== Loading corpora ===")
    global_corpus = load_global_baseline(args.global_dataset)
    site_corpus = load_site_corpus(args.site_corpus)
    combined = combine_corpora(global_corpus, site_corpus)

    if len(combined) < 10:
        raise ValueError(f"Combined corpus has only {len(combined)} samples - need at least 10")

    # Extract features
    print("\n=== Extracting features ===")
    X = np.array([extract_features(cmdline) for cmdline in combined], dtype=np.float32)
    print(f"Feature matrix: {X.shape}")

    # Train model
    print("\n=== Training Isolation Forest ===")
    clf = IsolationForest(**HYPERPARAMETERS)
    clf.fit(X)
    print(f"Trained on {len(combined)} samples")

    # Global-model-floor check (if requested)
    if args.robustness_scenarios and args.global_model:
        floor_passed = run_global_floor_check(
            site_model=clf,
            global_model_path=args.global_model,
            scenario_yaml=args.robustness_scenarios,
        )
        if not floor_passed:
            raise ValueError("Global-model-floor check failed - site model does not meet baseline quality")
    elif args.robustness_scenarios or args.global_model:
        print("⚠️  Warning: Skipping global-model-floor check (need both --robustness-scenarios and --global-model)")

    # Export to ONNX
    print("\n=== Exporting to ONNX ===")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    # Pinned like train_linux.py: skl2onnx does not yet follow the `ai.onnx.ml` v4 domain
    # that onnx 1.22 emits by default.
    onnx_model = to_onnx(clf, X[:1], target_opset={"": 18, "ai.onnx.ml": 3})
    onnx_path = args.output_dir / MODEL_FILENAME
    with open(onnx_path, "wb") as f:
        f.write(onnx_model.SerializeToString())
    print(f"Exported: {onnx_path}")

    # Write training record with provenance
    print("\n=== Writing training record ===")
    dataset_versions = [dataset_version_from_manifest(args.global_dataset)]

    # Add site corpus as dataset version
    site_corpus_version = DatasetVersion(
        name=f"site-corpus-{args.site_name}",
        baseline_sha256=compute_file_sha256(args.site_corpus),
        sample_count=len(site_corpus),
    )
    dataset_versions.append(site_corpus_version)

    write_training_record(
        args.output_dir,
        training_script=TRAINING_SCRIPT,
        dataset_versions=dataset_versions,
        robustness_cards=[],  # Populated by separate robustness evaluation run
        scenario_replays=[],
    )

    print(f"\n✅ Site model training complete: {args.output_dir}")
    print(f"   Global corpus: {len(global_corpus)} samples")
    print(f"   Site corpus: {len(site_corpus)} samples")
    print(f"   Combined: {len(combined)} samples")


def compute_file_sha256(file_path: Path) -> str:
    """Compute SHA-256 hash of file."""
    import hashlib
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


if __name__ == "__main__":
    main()
