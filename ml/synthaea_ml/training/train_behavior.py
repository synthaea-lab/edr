"""Trains the T1 behavior Isolation Forest on the 23 lineage-aware features (issue #617).

T1 scores one process incarnation at a time on cmdline (9) + correlation (8) + lineage (6)
features (`synthaea_ml.features.t1`). Unlike the T0 trainers it cannot learn from a
`baseline.jsonl` of command lines: the correlation and lineage blocks need pids, process
generations and parents, so its input is a raw agent capture of normal activity.

Input contract: a dataset directory (`--dataset`) containing

- `events.jsonl`: the agent's own capture (`crates/schema::Event` JSON, identity nested
  under `meta`), recorded on a host doing normal work.
- `manifest.json`: written by `python -m synthaea_ml.data.manifest` with
  `--baseline-filename events.jsonl`; verified before training, as for the T0 trainers.

Output (`--output-dir`, a registry version directory): `model.onnx`,
`model_metadata.json` (conformal threshold + feature bounds) and `model_record.json`.

What this does **not** do: ship a model. The Rust combined scorer that builds the same 23
features on-device does not exist yet, and the benign corpus must be a real capture; the
existing `argv`-only baselines carry no lineage and cannot show a lineage gain. Run
`--robustness-scenarios` to record the T1 robustness card (lineage mutators included).

Usage:
    python -m synthaea_ml.training.train_behavior \\
        --dataset ml/datasets/baselines/linux__dev__abc__2026-10-02/ \\
        --output-dir ml/registry/behavior-iforest-linux/0.1.0/
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
from skl2onnx import to_onnx
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split

from synthaea_ml.calibration import calibrate_threshold, compute_feature_bounds
from synthaea_ml.data.behavior_dataset import load_records
from synthaea_ml.data.manifest import BEHAVIOR_CAPTURE_FILENAME
from synthaea_ml.evaluation.robustness import run_robustness_evaluation
from synthaea_ml.features import t1
from synthaea_ml.registry.training_record import (
    RobustnessCard,
    dataset_version_from_manifest,
    write_training_record,
)

TRAINING_SCRIPT = "synthaea_ml/training/train_behavior.py"
MODEL_FILENAME = "model.onnx"
METADATA_FILENAME = "model_metadata.json"

# Same calibration contract as the T0 trainers (issue #46).
FP_BUDGET_PER_ENDPOINT_DAY = 5.0
BENIGN_RATE_PER_DAY = 1000.0
FEATURE_BOUNDS_MARGIN = 0.05

# Provisional: the T0 value, to be settled on the first real capture (a process's
# behavior counts are tightly clustered, so a lower contamination may separate better,
# as `train_correlation.py` anticipates). Do not tune on the synthetic test corpus.
HYPERPARAMETERS: dict[str, object] = {
    "n_estimators": 100,
    "contamination": 0.05,
    "random_state": 42,
}

MIN_SAMPLES = 20
"""Fewer distinct incarnations than this cannot support a 70/30 split and a conformal
threshold; refuse rather than emit a model whose boundary is noise."""


def load_matrix(dataset_dirs: list[Path]) -> np.ndarray:
    """The deduplicated 23-feature matrix of every dataset's capture.

    Deduplicated by feature vector: an identical process behavior seen 10 000 times adds
    one sample, so the boundary is not dragged toward the most repeated activity.
    """
    rows: dict[tuple[float, ...], None] = {}
    total = 0
    for d in dataset_dirs:
        for record in load_records(d / BEHAVIOR_CAPTURE_FILENAME):
            total += 1
            rows[tuple(t1.extract_features(record))] = None
    print(f"Behavior capture: {total} process incarnations -> {len(rows)} distinct vectors")
    if len(rows) < MIN_SAMPLES:
        raise ValueError(
            f"only {len(rows)} distinct behavior vectors (need at least {MIN_SAMPLES}): "
            "capture a longer normal-activity session"
        )
    return np.array(list(rows), dtype=np.float32)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        type=Path,
        required=True,
        nargs="+",
        help="One or more directories, each with events.jsonl + manifest.json.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Registry version directory (model.onnx + model_record.json are written here).",
    )
    parser.add_argument(
        "--robustness-scenarios",
        type=Path,
        nargs="*",
        default=[],
        help="Scenario yamls for T1 adversarial robustness evaluation (issue #45/#617).",
    )
    parser.add_argument(
        "--robustness-events",
        type=Path,
        help=(
            "Capture of MALICIOUS activity matching the scenarios (events.jsonl, agent wire "
            "format). Without it the evaluation falls back to synthetic events."
        ),
    )
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    # Verify every manifest first: a mutated capture is rejected before any model exists.
    dataset_versions = [
        dataset_version_from_manifest(d, baseline_filename=BEHAVIOR_CAPTURE_FILENAME)
        for d in args.dataset
    ]

    X = load_matrix(args.dataset)
    X_train, X_cal = train_test_split(X, test_size=0.3, random_state=42)
    print(f"Split: {len(X_train)} training, {len(X_cal)} calibration")

    clf = IsolationForest(**HYPERPARAMETERS)
    clf.fit(X_train)

    conformal_cal = calibrate_threshold(
        clf,
        X_cal,
        fp_budget=FP_BUDGET_PER_ENDPOINT_DAY,
        benign_rate_per_day=BENIGN_RATE_PER_DAY,
    )
    print(
        f"Conformal calibration: threshold={conformal_cal.threshold:.4f} "
        f"for <={FP_BUDGET_PER_ENDPOINT_DAY} FP/endpoint/day"
    )
    bounds = compute_feature_bounds(X_train, list(t1.FEATURE_NAMES), margin=FEATURE_BOUNDS_MARGIN)

    onnx_model = to_onnx(clf, X_train[:1], target_opset={"": 18, "ai.onnx.ml": 3})
    (args.output_dir / MODEL_FILENAME).write_bytes(onnx_model.SerializeToString())
    metadata = {
        "threshold": conformal_cal.threshold,
        "feature_bounds": {
            "feature_names": bounds.feature_names,
            "min_values": bounds.min_values,
            "max_values": bounds.max_values,
        },
    }
    (args.output_dir / METADATA_FILENAME).write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
    )

    robustness_cards: list[RobustnessCard] = []
    for scenario_path in args.robustness_scenarios:
        card = run_robustness_evaluation(
            model=clf,
            scenario_yaml=scenario_path,
            tier="T1",
            mutation_seed=42,
            events_source=args.robustness_events,
        )
        robustness_cards.append(card)
        print(
            f"  {card.scenario_name}: escape_rate={card.escape_rate:.2%}, "
            f"median_degradation={card.median_score_degradation:+.3f}"
        )

    write_training_record(
        args.output_dir,
        training_script=TRAINING_SCRIPT,
        dataset_versions=dataset_versions,
        robustness_cards=robustness_cards,
        hyperparameters=HYPERPARAMETERS,
        conformal_calibration=conformal_cal,
        feature_bounds=bounds,
    )
    print(f"T1 model trained on {len(X)} distinct behavior vectors -> {args.output_dir}")


if __name__ == "__main__":
    main()
