"""Measures what the lineage features add to the T1 behavior model (issue #617).

The question of #617 is whether the 23-feature T1 vector (cmdline 9 + correlation 8 +
lineage 6) detects more than the same vector without the lineage block, at the same
false-positive budget. This module answers it from two real captures, never from synthetic
events:

- a **benign** dataset directory, as `train_behavior.py` takes (`events.jsonl` +
  `manifest.json`), recorded on a host doing varied normal work;
- a **malicious** capture (`events.jsonl`, same wire format) of scenario runs, with the
  process tree of the scenario runner given as `--root-pid` and its time window, so that the
  host's background processes during the run are not counted as attacks.

For each of `--seeds` random splits of the distinct benign vectors (50% train, 25%
calibration, 25% held-out test) it fits the two variants with the trainer's own
hyperparameters, calibrates the threshold on the calibration part with the trainer's FP
budget, and reports, per variant: the detection rate on the malicious vectors at that
threshold, the false-positive rate on the held-out benign vectors, and the ROC AUC (which
does not depend on the threshold, so a small capture still says something). The gain is the
paired per-seed difference, 23 features minus 17, with its spread: one lucky split is not a
result.

What it does not do: write into `model_record.json` (no field for it in the registry
schema, a signed-envelope-adjacent change of its own) or train the shipped model
(`train_behavior.py` does). It writes a JSON report next to the model for a reviewer to read.

Usage:
    python -m synthaea_ml.evaluation.t1_lineage_gain \\
        --benign-dataset ml/datasets/captures/linux__lab__<date>/ \\
        --malicious-capture ml/datasets/labeled/linux__lab__<date>/events.jsonl \\
        --root-pid 4242 --start-ns 1790000000000000000 --end-ns 1790000900000000000 \\
        --output t1_lineage_gain.json
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score

from synthaea_ml.calibration import calibrate_threshold
from synthaea_ml.data.behavior_dataset import (
    DEFAULT_WINDOW_NS,
    load_events,
    records_from_events,
)
from synthaea_ml.data.manifest import BEHAVIOR_CAPTURE_FILENAME
from synthaea_ml.features import correlation, lineage, t1
from synthaea_ml.training.train_behavior import (
    BENIGN_RATE_PER_DAY,
    FP_BUDGET_PER_ENDPOINT_DAY,
    HYPERPARAMETERS,
    MIN_SAMPLES,
    load_matrix,
)

# The baseline is the T1 vector without its lineage block: the lineage features come last.
BASELINE_FEATURE_COUNT = t1.FEATURE_COUNT - len(lineage.FEATURE_NAMES)
VARIANTS = {"without_lineage": BASELINE_FEATURE_COUNT, "with_lineage": t1.FEATURE_COUNT}

TRAIN_FRACTION = 0.50
CALIBRATION_FRACTION = 0.25  # the rest is the held-out test


@dataclass(frozen=True)
class VariantResult:
    """One feature set over all seeds."""

    features: int
    detection_rate_mean: float
    detection_rate_std: float
    false_positive_rate_mean: float
    false_positive_rate_std: float
    auc_mean: float
    auc_std: float


@dataclass(frozen=True)
class GainReport:
    """What the lineage block adds, with the sizes that bound how far to trust it."""

    benign_distinct_vectors: int
    malicious_distinct_vectors: int
    seeds: int
    fp_budget_per_endpoint_day: float
    without_lineage: VariantResult
    with_lineage: VariantResult
    auc_gain_mean: float
    auc_gain_std: float
    detection_gain_mean: float
    detection_gain_std: float
    seeds_where_lineage_is_not_worse: int


def _distinct(matrix: np.ndarray) -> np.ndarray:
    return np.unique(matrix, axis=0)


def _split(benign: np.ndarray, seed: int) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    order = np.random.default_rng(seed).permutation(len(benign))
    n_train = int(len(benign) * TRAIN_FRACTION)
    n_cal = int(len(benign) * CALIBRATION_FRACTION)
    train = benign[order[:n_train]]
    cal = benign[order[n_train : n_train + n_cal]]
    test = benign[order[n_train + n_cal :]]
    return train, cal, test


def _one_split(
    benign: np.ndarray, malicious: np.ndarray, seed: int, columns: int
) -> tuple[float, float, float]:
    """Detection rate, false-positive rate and AUC of one variant on one split."""
    train, cal, test = _split(benign, seed)
    model = IsolationForest(**{**HYPERPARAMETERS, "random_state": seed})
    model.fit(train[:, :columns])
    threshold = calibrate_threshold(
        model,
        cal[:, :columns],
        fp_budget=FP_BUDGET_PER_ENDPOINT_DAY,
        benign_rate_per_day=BENIGN_RATE_PER_DAY,
    ).threshold
    benign_scores = model.decision_function(test[:, :columns])
    malicious_scores = model.decision_function(malicious[:, :columns])
    detection = float(np.mean(malicious_scores < threshold))
    false_positive = float(np.mean(benign_scores < threshold))
    labels = np.r_[np.zeros(len(benign_scores)), np.ones(len(malicious_scores))]
    # IsolationForest: lower decision_function = more anomalous, so negate for the AUC.
    auc = float(roc_auc_score(labels, -np.r_[benign_scores, malicious_scores]))
    return detection, false_positive, auc


def measure_gain(benign: np.ndarray, malicious: np.ndarray, seeds: int = 20) -> GainReport:
    """The report for two feature matrices of 23 columns each (benign, malicious).

    Raises:
        ValueError: A matrix has the wrong width, the benign set is too small to split three
            ways (`MIN_SAMPLES` distinct vectors, as the trainer requires) or the malicious
            set is empty.
    """
    for name, matrix in (("benign", benign), ("malicious", malicious)):
        if matrix.ndim != 2 or matrix.shape[1] != t1.FEATURE_COUNT:
            raise ValueError(f"{name} matrix must have {t1.FEATURE_COUNT} columns")
    benign, malicious = _distinct(benign), _distinct(malicious)
    if len(benign) < MIN_SAMPLES:
        raise ValueError(
            f"only {len(benign)} distinct benign vectors (need at least {MIN_SAMPLES}): "
            "capture a longer and more varied normal-activity session"
        )
    if len(malicious) == 0:
        raise ValueError("no malicious process incarnation: check --root-pid and the window")

    per_variant: dict[str, list[tuple[float, float, float]]] = {name: [] for name in VARIANTS}
    for seed in range(seeds):
        for name, columns in VARIANTS.items():
            per_variant[name].append(_one_split(benign, malicious, seed, columns))

    def summarize(name: str) -> VariantResult:
        rows = np.array(per_variant[name])
        return VariantResult(
            features=VARIANTS[name],
            detection_rate_mean=float(rows[:, 0].mean()),
            detection_rate_std=float(rows[:, 0].std()),
            false_positive_rate_mean=float(rows[:, 1].mean()),
            false_positive_rate_std=float(rows[:, 1].std()),
            auc_mean=float(rows[:, 2].mean()),
            auc_std=float(rows[:, 2].std()),
        )

    base, full = np.array(per_variant["without_lineage"]), np.array(per_variant["with_lineage"])
    auc_gain = full[:, 2] - base[:, 2]
    detection_gain = full[:, 0] - base[:, 0]
    return GainReport(
        benign_distinct_vectors=len(benign),
        malicious_distinct_vectors=len(malicious),
        seeds=seeds,
        fp_budget_per_endpoint_day=FP_BUDGET_PER_ENDPOINT_DAY,
        without_lineage=summarize("without_lineage"),
        with_lineage=summarize("with_lineage"),
        auc_gain_mean=float(auc_gain.mean()),
        auc_gain_std=float(auc_gain.std()),
        detection_gain_mean=float(detection_gain.mean()),
        detection_gain_std=float(detection_gain.std()),
        seeds_where_lineage_is_not_worse=int(np.sum(auc_gain >= 0)),
    )


def _process_edges(path: Path) -> dict[tuple[int, int | None], tuple[int, int | None, int]]:
    """`(pid, generation) -> (ppid, parent_generation, first_ts_ns)` from every wire event.

    Every event carries its identity and its parent's in `meta`, so a process that forked
    and never exec'd (a subshell) still links its children to the runner.
    """
    edges: dict[tuple[int, int | None], tuple[int, int | None, int]] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            meta = json.loads(line).get("meta")
        except (json.JSONDecodeError, AttributeError):
            continue
        if not isinstance(meta, dict) or "pid" not in meta or "ppid" not in meta:
            continue
        key = (meta["pid"], meta.get("process_generation"))
        ts = meta.get("timestamp_ns", 0)
        if key not in edges or ts < edges[key][2]:
            edges[key] = (meta["ppid"], meta.get("parent_process_generation"), ts)
    return edges


def descendants_of(
    path: Path, root_pid: int, start_ns: int, end_ns: int
) -> set[tuple[int, int | None]]:
    """The `(pid, generation)` of `root_pid`'s process tree seen inside `[start_ns, end_ns]`.

    The root is the incarnation of `root_pid` first seen inside the window (a pid recycled
    before or after it is another process); a descendant is a process first seen inside the
    window whose parent incarnation is already in the set.
    """
    edges = _process_edges(path)
    members: set[tuple[int, int | None]] = {
        key for key, (_, _, ts) in edges.items() if key[0] == root_pid and start_ns <= ts <= end_ns
    }
    changed = True
    while changed:
        changed = False
        for key, (ppid, parent_generation, ts) in edges.items():
            if key in members or not start_ns <= ts <= end_ns:
                continue
            if (ppid, parent_generation) in members:
                members.add(key)
                changed = True
    return members


def malicious_matrix(
    capture: Path,
    root_pid: int,
    start_ns: int,
    end_ns: int,
    window_ns: int = DEFAULT_WINDOW_NS,
) -> np.ndarray:
    """The 23-feature matrix of the scenario runner's process tree (excluding the runner)."""
    members = descendants_of(capture, root_pid, start_ns, end_ns)
    records = [
        r
        for r in records_from_events(load_events(capture), window_ns)
        if (r["pid"], r.get("process_generation")) in members and r["pid"] != root_pid
    ]
    return np.array([t1.extract_features(r) for r in records], dtype=np.float32).reshape(
        -1, t1.FEATURE_COUNT
    )


def _report_dict(report: GainReport, notes: dict[str, Any]) -> dict[str, Any]:
    return {**asdict(report), "notes": notes}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benign-dataset", type=Path, required=True, nargs="+")
    parser.add_argument("--malicious-capture", type=Path, required=True)
    parser.add_argument("--root-pid", type=int, required=True)
    parser.add_argument("--start-ns", type=int, required=True)
    parser.add_argument("--end-ns", type=int, required=True)
    parser.add_argument("--seeds", type=int, default=20)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    benign = load_matrix([d for d in args.benign_dataset])
    malicious = malicious_matrix(args.malicious_capture, args.root_pid, args.start_ns, args.end_ns)
    report = measure_gain(benign, malicious, seeds=args.seeds)
    notes = {
        "benign_datasets": [str(d / BEHAVIOR_CAPTURE_FILENAME) for d in args.benign_dataset],
        "malicious_capture": str(args.malicious_capture),
        "correlation_features": len(correlation.FEATURE_NAMES),
        "reading": (
            "Positive gain means the 23-feature model separates the malicious runs from "
            "held-out benign activity better than the 17-feature one. The malicious runs "
            "are lab scenarios (mostly spawned from a shell): a gain on lineage needs a "
            "scenario whose parent is anomalous."
        ),
    }
    args.output.write_text(
        json.dumps(_report_dict(report, notes), indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"AUC {report.without_lineage.auc_mean:.3f} -> {report.with_lineage.auc_mean:.3f} "
        f"(gain {report.auc_gain_mean:+.3f} +/- {report.auc_gain_std:.3f} over {report.seeds} "
        f"splits); detection {report.without_lineage.detection_rate_mean:.2%} -> "
        f"{report.with_lineage.detection_rate_mean:.2%}"
    )


if __name__ == "__main__":
    main()
