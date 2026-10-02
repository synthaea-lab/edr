"""Model record — the machine-parsable half of a model card.

Every registry entry has a human-readable ``card.md`` alongside its
``model.onnx`` (see ``ml/registry/README.md``). The card documents purpose,
metrics, FP rate, scenario-replay results and known limitations for a reader.

``model_record.json`` sits next to it, capturing exactly what a machine needs
to answer:

* "was this model trained on the datasets its card claims?" — the pre-existing
  binding, still enforced by hashing each baseline's content against
  ``sample_sha256``;
* "was this model replay-validated against the scenarios its card claims,
  and did those replays pass?" — the new binding introduced by ADR-0009,
  matched by hashing each scenario yaml against
  ``ScenarioReplayResult.scenario_yaml_sha256`` and by re-computing the
  ``passed`` field from the recorded counts.

Both are enforced at ``verify_training_record`` time and, through it, at
``verify_provenance`` time in the release gate.

Layout inside a version directory::

    ml/registry/<model>/<version>/
        model.onnx           # the artifact
        card.md              # for humans
        model_record.json    # for machines — this module writes/reads it

The record binds each ``DatasetVersion`` by its ``baseline_sha256`` (the
content hash the manifest already publishes), not by path — a dataset can move
on disk without invalidating the record, but a mutated baseline cannot pass
``verify_training_record`` even if it kept the same path. The same principle
applies to scenario yamls via ``scenario_yaml_sha256``.

Renamed from ``training.json`` in ADR-0009: the record now covers scenario
replay outcomes on top of dataset binding — no longer a "training" concept but
a full model-lifecycle record. Schema version bumped 1 → 2; readers reject v1
(matches the ``manifest.py`` pattern). No on-disk migration was required:
``training.json`` had never been materialised in the repo when this rename
landed (verified pre-ADR).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from synthaea_ml.data.manifest import (
    BEHAVIOR_CAPTURE_FILENAME,
    DEFAULT_BASELINE_FILENAME,
    load_manifest,
    verify_manifest,
)

SCHEMA_VERSION = 3
"""Bumped only when a field changes in a way that breaks readers.

Bumped 1 → 2 in ADR-0009 for the addition of ``scenario_replays`` on
``TrainingRecord`` and the rename of the on-disk file to
``model_record.json``.

Bumped 2 → 3 for issues #45 and #46: added ``robustness_cards`` (adversarial
evaluation results binding mutations to model versions for evasion cost
measurement), ``conformal_calibration``, and ``feature_bounds`` (FP-budget
thresholds and OOD guards). Backward compatible (optional fields with None
defaults).
"""

MODEL_RECORD_FILENAME = "model_record.json"


# ── Dataset binding (unchanged since schema v1) ─────────────────────────────


@dataclass(frozen=True)
class DatasetVersion:
    """One entry in ``TrainingRecord.dataset_versions``.

    ``baseline_sha256`` is the manifest's ``sample_sha256`` (locking the sample
    file content), and ``sample_count`` is the manifest's ``sample_count``
    (a cheap cross-check that catches a truncated baseline before the slower
    hash comparison does).
    """

    name: str
    baseline_sha256: str
    sample_count: int


# ── Conformal calibration binding (issue #46, schema v3) ────────────────────


@dataclass(frozen=True)
class ConformalCalibration:
    """Conformal prediction calibration metadata (issue #46).

    Records the threshold computed from a calibration set to meet a stated FP
    budget (e.g., ≤5 false positives per endpoint per day). See
    ``synthaea_ml.calibration.calibrate_conformal`` for the computation.
    """

    fp_budget_per_endpoint_day: float
    threshold: float
    calibration_set_size: int
    benign_baseline_rate: float
    calibrated_at: str  # ISO 8601 UTC


@dataclass(frozen=True)
class FeatureBounds:
    """Per-feature [min, max] bounds for out-of-distribution detection (issue #46).

    Computed from the training set with a margin to avoid false OOD rejections
    on legitimate edge cases. The Rust scorer validates feature vectors against
    these bounds before inference.
    """

    feature_names: list[str]
    min_values: list[float]
    max_values: list[float]


# ── Scenario replay binding (ADR-0009, schema v2) ───────────────────────────


@dataclass(frozen=True)
class Environment:
    """OS/kernel/arch on which a replay ran. Minimum for v1;
    libc (glibc/musl) and toolchain versions are v2 candidates
    (ADR-0009 § Deferred).

    ``kernel`` is ``platform.release()`` verbatim — cross-platform via the
    Python stdlib helper. On Linux/macOS the value equals ``uname -r``
    (e.g. ``"6.6.0-generic"``, ``"23.6.0"``); on Windows it is the major
    version only (e.g. ``"10"``), NOT the full Windows build. A full-build
    Windows field would need its own dataclass member and is deferred until
    a case requires the extra precision.
    """

    os: str
    kernel: str
    arch: str


@dataclass(frozen=True)
class ExpectedDetection:
    """One expected ``(technique, rule)`` tuple in a scenario. Mirror of the
    yaml sidecar schema (#44's decision 2 / ADR-0009 § Schema).

    ``technique`` is an opaque string as ``Alert.technique`` and
    ``CorrelationAlert.rule`` produce it — it may be a single ATT&CK id
    (``"T1071"``) or a combined form (``"T1105/T1059/T1071"``). The passing
    criterion matches by exact string equality, not by ATT&CK decomposition
    (see ``compute_passed``).
    """

    technique: str
    rule: str
    min_count: int
    tolerance: int


@dataclass(frozen=True)
class ObservedDetection:
    """What the replay actually observed for one ``(technique, rule)`` tuple.

    Emitted by the replay engine that reads a run's ``alerts.ndjson`` and
    tallies ``(technique, rule)`` counts. Zero counts are represented by the
    tuple being absent from the list rather than by ``count == 0``, matching
    how the alerts pipeline reports.
    """

    technique: str
    rule: str
    count: int


@dataclass(frozen=True)
class ScenarioReplayResult:
    """One replay run against one scenario, in one environment.

    Binds to the source ``lab/scenarios/<scenario_name>.yaml`` by content
    hash — mutating the yaml invalidates every record that references it, in
    the same way ``DatasetVersion.baseline_sha256`` binds datasets.

    ``passed`` is cached (writer computes it via ``compute_passed`` and stores
    it; ``verify_scenario_replay`` re-computes and rejects if the cached value
    disagrees, catching a mutated ``passed`` field).
    """

    scenario_name: str
    scenario_yaml_sha256: str
    run_at: str  # ISO 8601 UTC, e.g. "2026-09-17T10:15:00Z"
    environment: Environment
    expected_detections: list[ExpectedDetection]
    observed_detections: list[ObservedDetection]
    passed: bool


# ── Record ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TrainingRecord:
    """The ``model_record.json`` sidecar of a registry model version.

    Kept named ``TrainingRecord`` (rather than ``ModelRecord``) for continuity
    with existing callers; the on-disk filename and human semantics both moved
    to a model-lifecycle framing in ADR-0009 but the Python type keeps its
    historic name to minimise churn across the codebase.
    """

    schema_version: int
    trained_at: str
    training_script: str
    dataset_versions: list[DatasetVersion]
    scenario_replays: list[ScenarioReplayResult] = field(default_factory=list)
    robustness_cards: list[RobustnessCard] = field(default_factory=list)
    hyperparameters: dict[str, object] = field(default_factory=dict)
    extra: dict[str, str] = field(default_factory=dict)
    conformal_calibration: ConformalCalibration | None = None
    feature_bounds: FeatureBounds | None = None

    def to_dict(self) -> dict[str, object]:
        """Deterministic dict serialisation. Uses explicit per-field packing
        so a nested frozen dataclass with mutable-typed fields (list, dict)
        cannot leak a dataclass-internal representation into the JSON.
        """
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "trained_at": self.trained_at,
            "training_script": self.training_script,
            "dataset_versions": [asdict(v) for v in self.dataset_versions],
            "scenario_replays": [_scenario_replay_to_dict(r) for r in self.scenario_replays],
            "robustness_cards": [_robustness_card_to_dict(c) for c in self.robustness_cards],
            "hyperparameters": dict(self.hyperparameters),
            "extra": dict(self.extra),
        }
        if self.conformal_calibration is not None:
            result["conformal_calibration"] = asdict(self.conformal_calibration)
        if self.feature_bounds is not None:
            result["feature_bounds"] = asdict(self.feature_bounds)
        return result


def _scenario_replay_to_dict(r: ScenarioReplayResult) -> dict[str, object]:
    """Explicit serialisation for a ``ScenarioReplayResult`` so nested
    dataclasses (``Environment``, ``ExpectedDetection``, ``ObservedDetection``)
    round-trip as plain dicts."""
    return {
        "scenario_name": r.scenario_name,
        "scenario_yaml_sha256": r.scenario_yaml_sha256,
        "run_at": r.run_at,
        "environment": asdict(r.environment),
        "expected_detections": [asdict(e) for e in r.expected_detections],
        "observed_detections": [asdict(o) for o in r.observed_detections],
        "passed": r.passed,
    }


def _scenario_replay_from_dict(d: dict[str, object]) -> ScenarioReplayResult:
    """Inverse of ``_scenario_replay_to_dict`` — round-trips a JSON-decoded
    dict back into the nested-dataclass form."""
    env = Environment(**d["environment"])  # type: ignore[arg-type]
    return ScenarioReplayResult(
        scenario_name=d["scenario_name"],  # type: ignore[arg-type]
        scenario_yaml_sha256=d["scenario_yaml_sha256"],  # type: ignore[arg-type]
        run_at=d["run_at"],  # type: ignore[arg-type]
        environment=env,
        expected_detections=[ExpectedDetection(**e) for e in d["expected_detections"]],  # type: ignore[arg-type,union-attr]
        observed_detections=[ObservedDetection(**o) for o in d["observed_detections"]],  # type: ignore[arg-type,union-attr]
        passed=d["passed"],  # type: ignore[arg-type]
    )


def _robustness_card_to_dict(c: RobustnessCard) -> dict[str, object]:
    """Explicit serialisation for a ``RobustnessCard`` so nested
    ``MutationTestResult`` dataclasses round-trip as plain dicts."""
    return {
        "scenario_name": c.scenario_name,
        "scenario_yaml_sha256": c.scenario_yaml_sha256,
        "tested_at": c.tested_at,
        "mutation_results": [asdict(m) for m in c.mutation_results],
        "escape_rate": c.escape_rate,
        "median_score_degradation": c.median_score_degradation,
        "worst_case_degradation": c.worst_case_degradation,
    }


def _robustness_card_from_dict(d: dict[str, object]) -> RobustnessCard:
    """Inverse of ``_robustness_card_to_dict`` — round-trips a JSON-decoded
    dict back into the nested-dataclass form."""
    return RobustnessCard(
        scenario_name=d["scenario_name"],  # type: ignore[arg-type]
        scenario_yaml_sha256=d["scenario_yaml_sha256"],  # type: ignore[arg-type]
        tested_at=d["tested_at"],  # type: ignore[arg-type]
        mutation_results=[MutationTestResult(**m) for m in d["mutation_results"]],  # type: ignore[arg-type,union-attr]
        escape_rate=d["escape_rate"],  # type: ignore[arg-type]
        median_score_degradation=d["median_score_degradation"],  # type: ignore[arg-type]
        worst_case_degradation=d["worst_case_degradation"],  # type: ignore[arg-type]
    )


# ── Passing criterion (ADR-0009 § Passing criterion) ────────────────────────


@dataclass(frozen=True)
class MutationTestResult:
    """One mutation test outcome (original vs mutated score).

    Emitted by the robustness evaluation runner for each combination of
    (mutator class, intensity, sample). Tracks whether the mutation caused
    evasion (score drop below threshold).
    """

    mutation_class: str
    intensity: str
    original_score: float
    mutated_score: float
    score_delta: float
    threshold: float
    escaped: bool
    seed: int


@dataclass(frozen=True)
class RobustnessCard:
    """Adversarial evaluation results for one scenario against one model.

    Binds to the source ``lab/scenarios/<scenario_name>.yaml`` by content
    hash, parallel to ``ScenarioReplayResult``. Captures aggregate metrics
    (escape rate, degradation percentiles) alongside per-mutation details.

    Generated by ``synthaea_ml.evaluation.robustness.run_robustness_evaluation``.
    """

    scenario_name: str
    scenario_yaml_sha256: str
    tested_at: str  # ISO 8601 UTC, e.g. "2026-09-23T10:15:00Z"
    mutation_results: list[MutationTestResult]
    escape_rate: float
    median_score_degradation: float
    worst_case_degradation: float


# ── Passing criterion (ADR-0009 § Passing criterion) ────────────────────────


def compute_passed(
    expected: list[ExpectedDetection],
    observed: list[ObservedDetection],
) -> bool:
    """Compute a scenario replay's ``passed`` value from its expected and
    observed detections.

    Per ADR-0009: for each ``ExpectedDetection`` in the scenario, find the
    matching observation by exact ``(technique, rule)`` string equality.

    * Missing observation → fail.
    * ``observed_count < min_count`` → fail (under-detection).
    * ``observed_count > min_count + tolerance`` → fail (over-detection —
      noisy rule).
    * Otherwise → pass for that expected detection.

    ``passed`` is ``True`` iff every expected detection passes. AND across
    all expected — one failure is enough to fail the scenario.
    """
    obs_by_key: dict[tuple[str, str], int] = {(o.technique, o.rule): o.count for o in observed}
    for e in expected:
        key = (e.technique, e.rule)
        if key not in obs_by_key:
            return False
        count = obs_by_key[key]
        if count < e.min_count:
            return False
        if count > e.min_count + e.tolerance:
            return False
    return True


# ── File-content hash helper ───────────────────────────────────────────────


_HASH_CHUNK = 1 << 16  # 64 KiB, matches manifest.py's chunk size


def _sha256_file(path: Path) -> str:
    """Content hash of a file. Same shape as ``manifest._hash_file``, private
    here to avoid a cross-module import for a five-line helper. The chunk
    size matches so both scans read the same-sized pages when the OS is
    already caching."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(_HASH_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


# ── Naming (unchanged) ──────────────────────────────────────────────────────


def default_dataset_name(baseline_dir: Path) -> str:
    """Derive a human-legible dataset name from the manifest next to a
    baseline.

    Convention: ``<platform>__<workload_label>__<host_id>__<YYYY-MM-DD>``.
    Double underscores separate the four coordinates so a workload label
    containing a single hyphen (``desktop-user``) does not become ambiguous.
    The date is ``capture_start[:10]`` — day-level granularity is what we bin
    by; sub-day precision belongs in the manifest, not in the name.

    Raises:
        FileNotFoundError: If the manifest is missing.
    """
    manifest = load_manifest(baseline_dir)
    capture_day = manifest.capture_start[:10]  # "2026-09-11" from ISO string
    return (
        f"{manifest.platform}__{manifest.workload_label}__{manifest.host_id}__{capture_day}"
    )


def dataset_version_from_manifest(
    baseline_dir: Path,
    *,
    name: str | None = None,
    baseline_filename: str = DEFAULT_BASELINE_FILENAME,
) -> DatasetVersion:
    """Verify the baseline against its manifest and return a ``DatasetVersion``.

    A caller who reads this back — the release gate or a re-training tool —
    can trust ``baseline_sha256`` to point at unmutated content because we
    just re-hashed the file to check.

    Args:
        baseline_dir: Directory containing ``baseline.jsonl`` and
            ``manifest.json``.
        name: Optional override. Defaults to
            ``default_dataset_name(baseline_dir)``.
        baseline_filename: Name of the samples file the manifest was written
            for. A T1 behavior capture is ``events.jsonl``, not ``baseline.jsonl``.

    Raises:
        FileNotFoundError: If baseline or manifest is missing.
        ValueError: If the baseline hash or sample count no longer matches
            the manifest (see ``verify_manifest``).
    """
    verify_manifest(baseline_dir, baseline_filename=baseline_filename)
    manifest = load_manifest(baseline_dir)
    return DatasetVersion(
        name=name if name is not None else default_dataset_name(baseline_dir),
        baseline_sha256=manifest.sample_sha256,
        sample_count=manifest.sample_count,
    )


# ── Write / load ────────────────────────────────────────────────────────────


def write_training_record(
    model_dir: Path,
    *,
    training_script: str,
    dataset_versions: list[DatasetVersion],
    scenario_replays: list[ScenarioReplayResult] | None = None,
    robustness_cards: list[RobustnessCard] | None = None,
    hyperparameters: dict[str, object] | None = None,
    trained_at: datetime | None = None,
    extra: dict[str, str] | None = None,
    conformal_calibration: ConformalCalibration | None = None,
    feature_bounds: FeatureBounds | None = None,
) -> TrainingRecord:
    """Write ``model_dir/model_record.json``.

    Args:
        model_dir: The registry version directory, e.g.
            ``ml/registry/cmdline-iforest-linux/0.2.0/``. Must already exist.
        training_script: Path-like string identifying the entry point,
            e.g. ``"synthaea_ml/training/train_linux.py"``. Recorded for
            traceability, not resolved.
        dataset_versions: One entry per baseline the run consumed. Callers
            build these via ``dataset_version_from_manifest`` so each has a
            re-verifiable hash before it reaches this function.
        scenario_replays: Zero or more replay outcomes to bind to this model
            version. Each is expected to have been produced by the (upcoming)
            replay engine which fills the yaml hash and cached ``passed`` in
            one shot. Empty list is legal (a model without replay validation
            is a model that will not ship under the strict release gate — a
            fact captured by ``verify_provenance``, not here).
        robustness_cards: Zero or more adversarial evaluation outcomes to bind
            to this model version. Each is produced by the robustness evaluation
            runner which fills the yaml hash and aggregated metrics. Empty list
            is legal (a model without robustness testing may not ship under
            strict release gate).
        hyperparameters: The knobs the run was configured with. Not
            interpreted here — round-trip only.
        trained_at: Timezone-aware datetime, normalised to UTC. Defaults
            to ``datetime.now(UTC)``.
        extra: Optional ``str`` → ``str`` metadata, namespaced under ``extra``
            so a future typed field cannot collide.
        conformal_calibration: Optional conformal prediction calibration metadata
            (issue #46). See ``synthaea_ml.calibration.calibrate_conformal``.
        feature_bounds: Optional per-feature bounds for OOD detection (issue #46).
            See ``synthaea_ml.calibration.compute_feature_bounds``.

    Returns:
        The ``TrainingRecord`` that was just written.

    Raises:
        FileNotFoundError: If ``model_dir`` does not exist.
        ValueError: If ``trained_at`` is naive, or ``dataset_versions`` is
            empty (a training run with no dataset would not lock anything).
    """
    if not model_dir.is_dir():
        raise FileNotFoundError(f"model_dir does not exist: {model_dir}")
    if not dataset_versions:
        raise ValueError("dataset_versions must not be empty")
    if trained_at is None:
        trained_at = datetime.now(UTC)
    if trained_at.tzinfo is None:
        raise ValueError("trained_at must be timezone-aware")

    record = TrainingRecord(
        schema_version=SCHEMA_VERSION,
        trained_at=trained_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        training_script=training_script,
        dataset_versions=list(dataset_versions),
        scenario_replays=list(scenario_replays) if scenario_replays else [],
        robustness_cards=list(robustness_cards) if robustness_cards else [],
        hyperparameters=dict(hyperparameters) if hyperparameters else {},
        extra=dict(extra) if extra else {},
        conformal_calibration=conformal_calibration,
        feature_bounds=feature_bounds,
    )

    (model_dir / MODEL_RECORD_FILENAME).write_text(
        json.dumps(record.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return record


def load_training_record(model_dir: Path) -> TrainingRecord:
    """Read ``model_dir/model_record.json``.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the schema version is not one this reader knows.
    """
    path = model_dir / MODEL_RECORD_FILENAME
    if not path.exists():
        raise FileNotFoundError(f"model record not found: {path}")

    payload = json.loads(path.read_text(encoding="utf-8"))
    schema_version = payload.get("schema_version")
    # Accept v2 and v3: robustness_cards (v3) is additive with default=[],
    # so v2 records load cleanly (PR #405 review fix)
    if schema_version not in (2, SCHEMA_VERSION):
        raise ValueError(
            f"unsupported {MODEL_RECORD_FILENAME} schema_version: {schema_version!r} "
            f"(this reader knows 2 and {SCHEMA_VERSION})"
        )

    # Schema v3 fields (backward compatible: None if absent)
    conformal_cal = None
    if "conformal_calibration" in payload:
        conformal_cal = ConformalCalibration(**payload["conformal_calibration"])  # type: ignore[arg-type]

    feature_bounds = None
    if "feature_bounds" in payload:
        feature_bounds = FeatureBounds(**payload["feature_bounds"])  # type: ignore[arg-type]

    return TrainingRecord(
        schema_version=schema_version,
        trained_at=payload["trained_at"],
        training_script=payload["training_script"],
        dataset_versions=[DatasetVersion(**v) for v in payload["dataset_versions"]],
        scenario_replays=[
            _scenario_replay_from_dict(r) for r in payload.get("scenario_replays", [])
        ],
        robustness_cards=[
            _robustness_card_from_dict(c) for c in payload.get("robustness_cards", [])
        ],
        hyperparameters=dict(payload.get("hyperparameters", {})),
        extra=dict(payload.get("extra", {})),
        conformal_calibration=conformal_cal,
        feature_bounds=feature_bounds,
    )


# ── Verification (release gate insertion point) ─────────────────────────────


def verify_scenario_replay(
    replay: ScenarioReplayResult,
    scenarios_root: Path,
) -> None:
    """Re-verify one ``ScenarioReplayResult`` against on-disk state.

    Two checks (ADR-0009):

    * ``scenario_yaml_sha256`` matches the current content hash of
      ``scenarios_root/<scenario_name>.yaml``.
    * Re-computing the passing criterion from the recorded
      ``expected_detections`` and ``observed_detections`` agrees with the
      cached ``passed`` field (a mutated cache is caught).

    The gate does *not* re-run the scenario; it verifies the record's
    self-consistency and its binding to the source yaml.

    Raises:
        FileNotFoundError: If the source yaml is missing.
        ValueError: If the yaml hash or the re-computed ``passed`` disagrees
            with the recorded value.
    """
    yaml_path = scenarios_root / f"{replay.scenario_name}.yaml"
    if not yaml_path.exists():
        raise FileNotFoundError(
            f"scenario yaml {yaml_path} missing — cannot verify replay for "
            f"{replay.scenario_name!r}"
        )
    current_hash = _sha256_file(yaml_path)
    if current_hash != replay.scenario_yaml_sha256:
        raise ValueError(
            f"scenario {replay.scenario_name!r} yaml hash mismatch: "
            f"replay locked {replay.scenario_yaml_sha256}, "
            f"current yaml is {current_hash}"
        )
    recomputed = compute_passed(replay.expected_detections, replay.observed_detections)
    if recomputed != replay.passed:
        raise ValueError(
            f"scenario {replay.scenario_name!r} passed field mutated: "
            f"cached {replay.passed}, re-computed {recomputed}"
        )


def verify_training_record(
    model_dir: Path,
    baselines_root: Path,
    scenarios_root: Path,
) -> None:
    """Re-verify every ``DatasetVersion`` and every ``ScenarioReplayResult``
    in the model record against on-disk state.

    The release gate calls this before shipping a model. Two families of
    checks:

    * **Dataset provenance** (schema v1 semantics, unchanged): each dataset
      version's ``baseline_sha256`` and ``sample_count`` must still match the
      on-disk baseline's current manifest. Baseline moved → fail. Baseline
      mutated → fail.
    * **Scenario replay provenance** (schema v2, ADR-0009): each replay's
      ``scenario_yaml_sha256`` must still match ``scenarios_root/<name>.yaml``,
      and the recorded ``passed`` value must agree with a re-computation of
      the passing criterion (catches a mutated cache).

    Args:
        model_dir: The registry version directory.
        baselines_root: The parent directory holding baselines by name, e.g.
            ``ml/datasets/baselines/``. Each ``DatasetVersion.name`` is looked
            up as ``baselines_root/<name>/``.
        scenarios_root: The directory holding scenario yaml sidecars, e.g.
            ``lab/scenarios/``. Each ``ScenarioReplayResult.scenario_name`` is
            looked up as ``scenarios_root/<name>.yaml``.

    Raises:
        FileNotFoundError: If the model record itself, any referenced
            baseline directory or its manifest, or any referenced scenario
            yaml, is missing.
        ValueError: If a referenced baseline's current hash or sample count
            no longer matches what the record locked, or a referenced
            scenario yaml's current hash or a cached ``passed`` no longer
            matches.
    """
    record = load_training_record(model_dir)
    for dv in record.dataset_versions:
        baseline_dir = baselines_root / dv.name
        if not baseline_dir.is_dir():
            raise FileNotFoundError(
                f"dataset {dv.name!r} not found under {baselines_root}"
            )
        # A T1 behavior dataset is a raw agent capture named `events.jsonl` (#617);
        # every other dataset is `baseline.jsonl`.
        baseline_filename = next(
            (n for n in (DEFAULT_BASELINE_FILENAME, BEHAVIOR_CAPTURE_FILENAME)
             if (baseline_dir / n).exists()),
            DEFAULT_BASELINE_FILENAME,
        )
        baseline_path = baseline_dir / baseline_filename
        if not baseline_path.exists():
            raise FileNotFoundError(
                f"baseline missing inside {baseline_dir}: expected {DEFAULT_BASELINE_FILENAME} "
                f"or {BEHAVIOR_CAPTURE_FILENAME}"
            )
        verify_manifest(baseline_dir, baseline_filename=baseline_filename)
        current = load_manifest(baseline_dir)
        if current.sample_sha256 != dv.baseline_sha256:
            raise ValueError(
                f"dataset {dv.name!r} hash mismatch: "
                f"training record locked {dv.baseline_sha256}, "
                f"current baseline is {current.sample_sha256}"
            )
        if current.sample_count != dv.sample_count:
            raise ValueError(
                f"dataset {dv.name!r} sample_count mismatch: "
                f"training record locked {dv.sample_count}, "
                f"current baseline has {current.sample_count}"
            )
    for replay in record.scenario_replays:
        verify_scenario_replay(replay, scenarios_root)
