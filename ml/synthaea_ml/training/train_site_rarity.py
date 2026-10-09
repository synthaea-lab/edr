"""Recalibrates a site model with the rarity feature and records its effect (issue #640).

Per-site adaptation (#49) rebuilds a T0 model from a site corpus. This entry point adds the
fleet-derived signal ADR-0020 describes: is the executed image on this fleet's common set
(seen on at least K hosts)? The model scores cmdline (9) + rarity (2) features, with the
rarity values taken **point in time** from the corpus itself (`synthaea_ml.data.common_set`),
never from today's counters.

It trains two models on the same time-ordered split, so the effect is measured, not assumed:

- the baseline on the 9 cmdline features;
- the candidate on cmdline + rarity;

each calibrated on the later calibration slice to the same FP budget, then scored on the
final, never-seen test slice. The test slice is benign site activity, so every flag there
is a false positive: `fp_rate_test_*` in the model record is the empirical FP rate of each
model at its own calibrated threshold. The split is by **time**, not random: a random split
would put an event's near-duplicates on both sides and flatter both models.

What this does not do: ship a model. The Rust half of the rarity feature is not written yet
(ADR-0020 is accepted), so the agent cannot load an 11-feature model yet; and the global-model-floor
check of `train_site_model.py` (a site model must not lose detections the global model has)
still has to pass before any site model leaves the lab. Detection quality is not measured
here: only the false-positive side, on benign corpora.

Input: a site corpus JSONL (`{timestamp, event_type, event, agent_id}` per line, as
`/api/corpus/finalize` exports it). Usage:

    python -m synthaea_ml.training.train_site_rarity \\
        --site-corpus corpus-v1.jsonl --site-name acme \\
        --output-dir ml/registry/cmdline-rarity-iforest-linux-site-acme/0.1.0/
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np
from skl2onnx import to_onnx
from sklearn.ensemble import IsolationForest

from synthaea_ml.calibration import calibrate_threshold, compute_feature_bounds
from synthaea_ml.data.canonical import ml_cmdline_from_record
from synthaea_ml.data.common_set import (
    DEFAULT_INTERVAL_NS,
    DEFAULT_K,
    _timestamp_ns,
    point_in_time_snapshots,
)
from synthaea_ml.features import cmdline, rarity
from synthaea_ml.registry.training_record import DatasetVersion, write_training_record

TRAINING_SCRIPT = "synthaea_ml/training/train_site_rarity.py"
MODEL_FILENAME = "model.onnx"
METADATA_FILENAME = "model_metadata.json"
FEATURE_NAMES = [*cmdline.FEATURE_NAMES, *rarity.FEATURE_NAMES]

DEFAULT_MIN_HOSTS = 5
"""Hosts a snapshot must cover before the rarity evidence counts (ADR-0020)."""
MIN_ROWS = 60
"""Fewer exec events cannot support a three-way time split and a conformal threshold."""
TRAIN_FRACTION = 0.7
CALIBRATION_FRACTION = 0.15

FP_BUDGET_PER_ENDPOINT_DAY = 5.0
BENIGN_RATE_PER_DAY = 1000.0
FEATURE_BOUNDS_MARGIN = 0.05

HYPERPARAMETERS: dict[str, object] = {
    "n_estimators": 100,
    "contamination": 0.05,
    "random_state": 42,
}


def load_corpus(path: Path) -> list[dict[str, Any]]:
    """Every record of a site corpus; unreadable lines are skipped, not fatal."""
    if not path.exists():
        raise FileNotFoundError(f"site corpus not found: {path}")
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and "timestamp" in record:
            records.append(record)
    return records


def build_matrices(
    records: list[dict[str, Any]], k: int, min_hosts: int, interval_ns: int
) -> tuple[np.ndarray, np.ndarray, float]:
    """Time-ordered `(X_cmdline, X_with_rarity, known_fraction)` over the exec records.

    The snapshots are computed over *all* records (a host that only ever ran non-exec events
    still counts as reporting), then the exec records are taken in time order.
    """
    snapshots = point_in_time_snapshots(records, k=k, interval_ns=interval_ns)
    rows = [
        (_timestamp_ns(r), i)
        for i, r in enumerate(records)
        if r.get("event_type") == "exec" and isinstance(r.get("event"), dict)
    ]
    rows.sort()
    base: list[list[float]] = []
    extra: list[list[float]] = []
    for _, i in rows:
        event = records[i]["event"]
        base.append(cmdline.extract_features(ml_cmdline_from_record(event)))
        extra.append(rarity.extract_features(event.get("sha256"), snapshots[i], min_hosts))
    x_base = np.array(base, dtype=np.float32)
    x_rare = np.array(extra, dtype=np.float32)
    known = float(x_rare[:, 0].mean()) if len(x_rare) else 0.0
    return x_base, np.hstack([x_base, x_rare]), known


def time_split(n: int) -> tuple[slice, slice, slice]:
    """Train, calibration and test slices of `n` time-ordered rows."""
    a = int(n * TRAIN_FRACTION)
    b = int(n * (TRAIN_FRACTION + CALIBRATION_FRACTION))
    return slice(0, a), slice(a, b), slice(b, n)


def fit_and_measure(
    x: np.ndarray, names: list[str]
) -> tuple[IsolationForest, Any, Any, float]:
    """Trains on the early slice, calibrates on the middle one, and returns
    `(model, conformal_calibration, feature_bounds, test_fp_rate)`."""
    train, calibration, test = time_split(len(x))
    clf = IsolationForest(**HYPERPARAMETERS)
    clf.fit(x[train])
    cal = calibrate_threshold(
        clf,
        x[calibration],
        fp_budget=FP_BUDGET_PER_ENDPOINT_DAY,
        benign_rate_per_day=BENIGN_RATE_PER_DAY,
    )
    bounds = compute_feature_bounds(x[train], names, margin=FEATURE_BOUNDS_MARGIN)
    scores = clf.decision_function(x[test])
    fp_rate = float((scores < cal.threshold).mean()) if len(scores) else 0.0
    return clf, cal, bounds, fp_rate


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site-corpus", type=Path, required=True)
    parser.add_argument("--site-name", required=True, help="Tenant name, for provenance.")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--k", type=int, default=DEFAULT_K, help="Hosts for the common set.")
    parser.add_argument("--min-hosts", type=int, default=DEFAULT_MIN_HOSTS)
    parser.add_argument(
        "--interval-hours",
        type=float,
        default=DEFAULT_INTERVAL_NS / 3_600_000_000_000,
        help="Cadence of published snapshots.",
    )
    args = parser.parse_args()

    records = load_corpus(args.site_corpus)
    interval_ns = int(args.interval_hours * 3_600_000_000_000)
    x_base, x_rare, known = build_matrices(records, args.k, args.min_hosts, interval_ns)
    if len(x_rare) < MIN_ROWS:
        raise ValueError(
            f"only {len(x_rare)} exec events in the corpus (need at least {MIN_ROWS})"
        )
    print(f"{len(x_rare)} exec events; rarity known for {known:.0%} of them")

    _, base_cal, _, base_fp = fit_and_measure(x_base, list(cmdline.FEATURE_NAMES))
    clf, cal, bounds, rare_fp = fit_and_measure(x_rare, FEATURE_NAMES)
    print(
        f"test-slice false-positive rate: cmdline only {base_fp:.2%}, "
        f"with rarity {rare_fp:.2%} (budget {FP_BUDGET_PER_ENDPOINT_DAY:g}/endpoint/day)"
    )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    onnx_model = to_onnx(clf, x_rare[:1], target_opset={"": 18, "ai.onnx.ml": 3})
    (args.output_dir / MODEL_FILENAME).write_bytes(onnx_model.SerializeToString())
    (args.output_dir / METADATA_FILENAME).write_text(
        json.dumps(
            {
                "threshold": cal.threshold,
                "feature_bounds": {
                    "feature_names": bounds.feature_names,
                    "min_values": bounds.min_values,
                    "max_values": bounds.max_values,
                },
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    corpus_sha = hashlib.sha256(args.site_corpus.read_bytes()).hexdigest()
    write_training_record(
        args.output_dir,
        training_script=TRAINING_SCRIPT,
        dataset_versions=[
            DatasetVersion(
                name=f"site-corpus-{args.site_name}",
                baseline_sha256=corpus_sha,
                sample_count=len(records),
            )
        ],
        hyperparameters=HYPERPARAMETERS,
        conformal_calibration=cal,
        feature_bounds=bounds,
        extra={
            "site": args.site_name,
            "rarity_k": str(args.k),
            "rarity_min_hosts": str(args.min_hosts),
            "snapshot_interval_hours": str(args.interval_hours),
            "exec_events": str(len(x_rare)),
            "rarity_known_fraction": f"{known:.4f}",
            "fp_rate_test_cmdline_only": f"{base_fp:.4f}",
            "fp_rate_test_with_rarity": f"{rare_fp:.4f}",
            "threshold_cmdline_only": f"{base_cal.threshold:.6f}",
            "global_model_floor": "NOT CHECKED: run it before this model leaves the lab",
        },
    )
    print(f"Site model with rarity -> {args.output_dir}")


if __name__ == "__main__":
    main()
