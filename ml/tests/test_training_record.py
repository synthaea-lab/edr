"""Tests for `synthaea_ml.registry.training_record` — the machine-parsable half
of a model card.

The properties that need to hold for the release gate to be trustworthy:

- Building a DatasetVersion from a manifest fails loudly if the baseline was
  edited without regenerating the manifest (that's the whole point).
- Writing a model record then loading it round-trips every field, including
  the scenario replays added in ADR-0009 (schema v2).
- `verify_training_record` catches all four failure modes it is meant to
  prevent: baseline moved, baseline mutated, scenario yaml mutated, cached
  `passed` field mutated.
- The passing criterion (ADR-0009) treats under-detection, over-detection
  and missing observations symmetrically as failures.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from synthaea_ml.data.manifest import write_manifest
from synthaea_ml.registry.training_record import (
    MODEL_RECORD_FILENAME,
    SCHEMA_VERSION,
    DatasetVersion,
    Environment,
    ExpectedDetection,
    ObservedDetection,
    ScenarioReplayResult,
    compute_passed,
    dataset_version_from_manifest,
    default_dataset_name,
    load_training_record,
    verify_scenario_replay,
    verify_training_record,
    write_training_record,
)

_START = datetime(2026, 9, 11, 10, 0, 0, tzinfo=UTC)
_END = datetime(2026, 9, 11, 11, 0, 0, tzinfo=UTC)
_TRAINED_AT = datetime(2026, 9, 11, 12, 0, 0, tzinfo=UTC)


def _make_baseline_with_manifest(
    dir_path: Path,
    *,
    lines: list[str],
    platform: str = "linux",
    workload: str = "dev",
    hostname: str = "solkapc",
) -> None:
    (dir_path / "baseline.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    write_manifest(
        dir_path,
        platform=platform,
        os_version="22.04",
        workload_label=workload,
        capture_start=_START,
        capture_end=_END,
        hostname=hostname,
    )


def _write_scenario_yaml(scenarios_root: Path, name: str, contents: str) -> tuple[Path, str]:
    """Write a scenario yaml sidecar and return its path + content hash.

    The tests do not need a schema-valid yaml since the record binds by
    content hash, not by parse — any deterministic bytes will do.
    """
    scenarios_root.mkdir(parents=True, exist_ok=True)
    path = scenarios_root / f"{name}.yaml"
    path.write_text(contents, encoding="utf-8")
    return path, hashlib.sha256(contents.encode("utf-8")).hexdigest()


def _env(kernel: str = "6.6.0-generic") -> Environment:
    return Environment(os="linux", kernel=kernel, arch="x86_64")


# --- default_dataset_name --------------------------------------------------


def test_default_dataset_name_from_manifest(tmp_path: Path) -> None:
    _make_baseline_with_manifest(
        tmp_path,
        lines=['{"argv": ["ls"]}'],
        platform="windows",
        workload="desktop-user",
        hostname="solkapc",
    )
    # Convention: <platform>__<workload>__<host_id>__<YYYY-MM-DD>.
    # Double-underscore separator survives a workload like "desktop-user".
    name = default_dataset_name(tmp_path)
    assert name.startswith("windows__desktop-user__")
    assert name.endswith("__2026-09-11")


def test_default_dataset_name_missing_manifest_raises(tmp_path: Path) -> None:
    (tmp_path / "baseline.jsonl").write_text('{"argv": ["ls"]}\n', encoding="utf-8")
    with pytest.raises(FileNotFoundError):
        default_dataset_name(tmp_path)


# --- dataset_version_from_manifest -----------------------------------------


def test_dataset_version_from_manifest_matches_manifest_hash(tmp_path: Path) -> None:
    _make_baseline_with_manifest(tmp_path, lines=['{"argv": ["ls"]}', '{"argv": ["id"]}'])
    dv = dataset_version_from_manifest(tmp_path)
    assert dv.sample_count == 2
    assert len(dv.baseline_sha256) == 64  # sha256 hex


def test_dataset_version_from_manifest_accepts_explicit_name(tmp_path: Path) -> None:
    _make_baseline_with_manifest(tmp_path, lines=['{"argv": ["ls"]}'])
    dv = dataset_version_from_manifest(tmp_path, name="custom-name-2026-09-11")
    assert dv.name == "custom-name-2026-09-11"


def test_dataset_version_from_manifest_rejects_edited_baseline(tmp_path: Path) -> None:
    """The property that makes this whole module worth writing: an edited
    baseline is rejected at dataset-version construction time, not silently
    baked into a model card."""
    _make_baseline_with_manifest(tmp_path, lines=['{"argv": ["ls"]}'])
    with (tmp_path / "baseline.jsonl").open("a", encoding="utf-8") as f:
        f.write('{"argv": ["id"]}\n')
    with pytest.raises(ValueError, match="baseline hash mismatch"):
        dataset_version_from_manifest(tmp_path)


# --- write_training_record / load_training_record --------------------------


def test_write_training_record_round_trip(tmp_path: Path) -> None:
    model_dir = tmp_path / "model_dir"
    model_dir.mkdir()

    baseline_dir = tmp_path / "baseline_dir"
    baseline_dir.mkdir()
    _make_baseline_with_manifest(baseline_dir, lines=['{"argv": ["ls"]}'])
    dv = dataset_version_from_manifest(baseline_dir, name="linux__dev__abc__2026-09-11")

    written = write_training_record(
        model_dir,
        training_script="synthaea_ml/training/train_linux.py",
        dataset_versions=[dv],
        hyperparameters={"n_estimators": 100, "contamination": 0.05},
        trained_at=_TRAINED_AT,
        extra={"commit_sha": "deadbeef"},
    )
    loaded = load_training_record(model_dir)

    assert loaded == written
    assert loaded.schema_version == SCHEMA_VERSION
    assert loaded.trained_at == "2026-09-11T12:00:00Z"
    assert loaded.training_script == "synthaea_ml/training/train_linux.py"
    assert loaded.dataset_versions == [dv]
    assert loaded.hyperparameters == {"n_estimators": 100, "contamination": 0.05}
    assert loaded.extra == {"commit_sha": "deadbeef"}
    # ADR-0009: scenario_replays defaults to empty list when not supplied.
    assert loaded.scenario_replays == []


def test_write_training_record_defaults_trained_at_to_now(tmp_path: Path) -> None:
    """When `trained_at` is not supplied, the written value is the current
    UTC instant. We only assert the format and the fact that it is timezone-
    aware, not the exact second — the real check is that the field is set."""
    baseline_dir = tmp_path / "b"
    baseline_dir.mkdir()
    _make_baseline_with_manifest(baseline_dir, lines=['{"argv": ["ls"]}'])
    dv = dataset_version_from_manifest(baseline_dir)
    model_dir = tmp_path / "m"
    model_dir.mkdir()

    record = write_training_record(
        model_dir,
        training_script="synthaea_ml/training/train_linux.py",
        dataset_versions=[dv],
    )
    # ISO Z-suffixed, 20 chars ("YYYY-MM-DDTHH:MM:SSZ").
    assert len(record.trained_at) == 20
    assert record.trained_at.endswith("Z")


def test_write_training_record_naive_datetime_raises(tmp_path: Path) -> None:
    baseline_dir = tmp_path / "b"
    baseline_dir.mkdir()
    _make_baseline_with_manifest(baseline_dir, lines=['{"argv": ["ls"]}'])
    dv = dataset_version_from_manifest(baseline_dir)
    model_dir = tmp_path / "m"
    model_dir.mkdir()

    naive = datetime(2026, 9, 11, 12, 0, 0)  # noqa: DTZ001 — must be rejected
    with pytest.raises(ValueError, match="trained_at must be timezone-aware"):
        write_training_record(
            model_dir,
            training_script="synthaea_ml/training/train_linux.py",
            dataset_versions=[dv],
            trained_at=naive,
        )


def test_write_training_record_empty_dataset_versions_raises(tmp_path: Path) -> None:
    model_dir = tmp_path / "m"
    model_dir.mkdir()
    with pytest.raises(ValueError, match="dataset_versions must not be empty"):
        write_training_record(
            model_dir,
            training_script="synthaea_ml/training/train_linux.py",
            dataset_versions=[],
            trained_at=_TRAINED_AT,
        )


def test_write_training_record_missing_model_dir_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        write_training_record(
            tmp_path / "does-not-exist",
            training_script="synthaea_ml/training/train_linux.py",
            dataset_versions=[DatasetVersion(name="x", baseline_sha256="0" * 64, sample_count=1)],
            trained_at=_TRAINED_AT,
        )


def test_training_record_json_is_sorted_and_indented(tmp_path: Path) -> None:
    model_dir = tmp_path / "m"
    model_dir.mkdir()
    write_training_record(
        model_dir,
        training_script="synthaea_ml/training/train_linux.py",
        dataset_versions=[DatasetVersion(name="x", baseline_sha256="0" * 64, sample_count=1)],
        trained_at=_TRAINED_AT,
    )
    raw = (model_dir / MODEL_RECORD_FILENAME).read_text(encoding="utf-8")
    parsed = json.loads(raw)
    assert list(parsed.keys()) == sorted(parsed.keys())
    assert "\n  " in raw  # indent=2


def test_write_training_record_converts_non_utc_to_utc(tmp_path: Path) -> None:
    model_dir = tmp_path / "m"
    model_dir.mkdir()
    paris_offset = timezone(timedelta(hours=2))
    paris_trained_at = datetime(2026, 9, 11, 14, 0, 0, tzinfo=paris_offset)
    record = write_training_record(
        model_dir,
        training_script="synthaea_ml/training/train_linux.py",
        dataset_versions=[DatasetVersion(name="x", baseline_sha256="0" * 64, sample_count=1)],
        trained_at=paris_trained_at,
    )
    assert record.trained_at == "2026-09-11T12:00:00Z"


def test_load_training_record_missing_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_training_record(tmp_path)


def test_load_training_record_unsupported_schema_version_raises(tmp_path: Path) -> None:
    (tmp_path / MODEL_RECORD_FILENAME).write_text(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION + 42,
                "trained_at": "2026-09-11T12:00:00Z",
                "training_script": "synthaea_ml/training/train_linux.py",
                "dataset_versions": [],
                "scenario_replays": [],
                "hyperparameters": {},
                "extra": {},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unsupported model_record.json schema_version"):
        load_training_record(tmp_path)


def test_load_training_record_rejects_v1_schema(tmp_path: Path) -> None:
    """ADR-0009: SCHEMA_VERSION bumped 1 → 2 with the scenario_replays
    addition. A v1 record must be rejected explicitly, matching the
    manifest.py rejection pattern — a reader that silently upgrades v1 to
    v2 would leave the scenario_replays list empty and let a model with no
    replay validation slip through the ship gate."""
    (tmp_path / MODEL_RECORD_FILENAME).write_text(
        json.dumps(
            {
                "schema_version": 1,
                "trained_at": "2026-09-11T12:00:00Z",
                "training_script": "synthaea_ml/training/train_linux.py",
                "dataset_versions": [],
                "hyperparameters": {},
                "extra": {},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unsupported model_record.json schema_version"):
        load_training_record(tmp_path)


# --- verify_training_record ------------------------------------------------


def test_verify_training_record_matches_after_write(tmp_path: Path) -> None:
    """End-to-end: build a dataset with a manifest, train (skipped), write the
    record, and verify. The whole point is that this passes as long as no one
    tampered with either half."""
    baselines_root = tmp_path / "baselines"
    baselines_root.mkdir()
    baseline_dir = baselines_root / "linux__dev__abc__2026-09-11"
    baseline_dir.mkdir()
    _make_baseline_with_manifest(baseline_dir, lines=['{"argv": ["ls"]}'])
    dv = dataset_version_from_manifest(
        baseline_dir, name="linux__dev__abc__2026-09-11"
    )

    model_dir = tmp_path / "model"
    model_dir.mkdir()
    write_training_record(
        model_dir,
        training_script="synthaea_ml/training/train_linux.py",
        dataset_versions=[dv],
        trained_at=_TRAINED_AT,
    )
    scenarios_root = tmp_path / "scenarios"
    scenarios_root.mkdir()
    verify_training_record(model_dir, baselines_root, scenarios_root)  # no exception


def test_verify_training_record_detects_edited_baseline(tmp_path: Path) -> None:
    baselines_root = tmp_path / "baselines"
    baselines_root.mkdir()
    baseline_dir = baselines_root / "linux__dev__abc__2026-09-11"
    baseline_dir.mkdir()
    _make_baseline_with_manifest(baseline_dir, lines=['{"argv": ["ls"]}'])
    dv = dataset_version_from_manifest(
        baseline_dir, name="linux__dev__abc__2026-09-11"
    )
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    write_training_record(
        model_dir,
        training_script="synthaea_ml/training/train_linux.py",
        dataset_versions=[dv],
        trained_at=_TRAINED_AT,
    )

    # Someone edits the baseline (and helpfully regenerates the manifest so
    # the manifest→baseline check passes) — but the training record still
    # locked the old hash, so we must catch it.
    (baseline_dir / "baseline.jsonl").write_text(
        '{"argv": ["ls"]}\n{"argv": ["id"]}\n', encoding="utf-8"
    )
    write_manifest(
        baseline_dir,
        platform="linux",
        os_version="22.04",
        workload_label="dev",
        capture_start=_START,
        capture_end=_END,
        hostname="solkapc",
    )

    scenarios_root = tmp_path / "scenarios"
    scenarios_root.mkdir()
    with pytest.raises(ValueError, match="hash mismatch"):
        verify_training_record(model_dir, baselines_root, scenarios_root)


def test_verify_training_record_detects_missing_baseline_dir(tmp_path: Path) -> None:
    """A moved / deleted dataset directory is a hard fail — the record names a
    baseline the release gate cannot re-verify."""
    baselines_root = tmp_path / "baselines"
    baselines_root.mkdir()
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    write_training_record(
        model_dir,
        training_script="synthaea_ml/training/train_linux.py",
        dataset_versions=[
            DatasetVersion(
                name="linux__dev__abc__2026-09-11",
                baseline_sha256="0" * 64,
                sample_count=1,
            )
        ],
        trained_at=_TRAINED_AT,
    )
    scenarios_root = tmp_path / "scenarios"
    scenarios_root.mkdir()
    with pytest.raises(FileNotFoundError, match="not found"):
        verify_training_record(model_dir, baselines_root, scenarios_root)


# --- Passing criterion (ADR-0009) ------------------------------------------


def test_compute_passed_all_expected_in_range() -> None:
    expected = [
        ExpectedDetection(technique="T1071", rule="check_beacon", min_count=3, tolerance=1),
        ExpectedDetection(technique="T1059.004", rule="check_base64_decode", min_count=1, tolerance=0),
    ]
    observed = [
        ObservedDetection(technique="T1071", rule="check_beacon", count=3),
        ObservedDetection(technique="T1059.004", rule="check_base64_decode", count=1),
    ]
    assert compute_passed(expected, observed) is True


def test_compute_passed_upper_bound_is_min_plus_tolerance() -> None:
    """`min_count + tolerance` is inclusive on the upper bound; one over is a fail."""
    expected = [ExpectedDetection(technique="T1071", rule="r", min_count=3, tolerance=2)]
    assert compute_passed(expected, [ObservedDetection(technique="T1071", rule="r", count=5)]) is True
    assert compute_passed(expected, [ObservedDetection(technique="T1071", rule="r", count=6)]) is False


def test_compute_passed_under_detection_fails() -> None:
    expected = [ExpectedDetection(technique="T1071", rule="r", min_count=3, tolerance=1)]
    observed = [ObservedDetection(technique="T1071", rule="r", count=2)]
    assert compute_passed(expected, observed) is False


def test_compute_passed_over_detection_fails() -> None:
    """Over-detection means the rule is noisier than the scenario budgeted for —
    an equal category of failure. This is what the tolerance ceiling exists to
    catch."""
    expected = [ExpectedDetection(technique="T1071", rule="r", min_count=3, tolerance=1)]
    observed = [ObservedDetection(technique="T1071", rule="r", count=5)]  # over min+tol=4
    assert compute_passed(expected, observed) is False


def test_compute_passed_missing_observation_fails() -> None:
    """A scenario that lists an expected detection with zero observations is a
    fail, regardless of what other detections did or did not fire."""
    expected = [
        ExpectedDetection(technique="T1071", rule="r", min_count=1, tolerance=0),
        ExpectedDetection(technique="T1059.004", rule="r2", min_count=1, tolerance=0),
    ]
    observed = [ObservedDetection(technique="T1071", rule="r", count=1)]  # T1059 missing
    assert compute_passed(expected, observed) is False


def test_compute_passed_zero_tolerance_exact_match() -> None:
    expected = [ExpectedDetection(technique="T1071", rule="r", min_count=3, tolerance=0)]
    assert compute_passed(expected, [ObservedDetection(technique="T1071", rule="r", count=3)]) is True
    assert compute_passed(expected, [ObservedDetection(technique="T1071", rule="r", count=4)]) is False


def test_compute_passed_composite_technique_string_exact_match() -> None:
    """`technique` may be a combined string like ``"T1105/T1059/T1071"`` — the
    passing criterion is exact string equality on both fields, no ATT&CK
    decomposition."""
    expected = [ExpectedDetection(technique="T1105/T1059/T1071", rule="r", min_count=1, tolerance=0)]
    matched = [ObservedDetection(technique="T1105/T1059/T1071", rule="r", count=1)]
    decomposed = [ObservedDetection(technique="T1105", rule="r", count=1)]  # partial → miss
    assert compute_passed(expected, matched) is True
    assert compute_passed(expected, decomposed) is False


# --- verify_scenario_replay ------------------------------------------------


def _make_replay(
    scenarios_root: Path,
    *,
    name: str = "beacon",
    contents: str = "kind: beacon\nexpected_detections: []\n",
    expected: list[ExpectedDetection] | None = None,
    observed: list[ObservedDetection] | None = None,
    passed: bool | None = None,
) -> ScenarioReplayResult:
    """Build a valid ``ScenarioReplayResult`` bound to a yaml just written on disk.
    ``passed`` defaults to the value ``compute_passed`` produces (i.e. an honest
    record); callers that want to test the mutation path pass ``passed=`` explicitly.
    """
    _, sha = _write_scenario_yaml(scenarios_root, name, contents)
    exp = expected if expected is not None else [
        ExpectedDetection(technique="T1071", rule="r", min_count=1, tolerance=0),
    ]
    obs = observed if observed is not None else [
        ObservedDetection(technique="T1071", rule="r", count=1),
    ]
    return ScenarioReplayResult(
        scenario_name=name,
        scenario_yaml_sha256=sha,
        run_at="2026-09-17T10:00:00Z",
        environment=_env(),
        expected_detections=exp,
        observed_detections=obs,
        passed=compute_passed(exp, obs) if passed is None else passed,
    )


def test_verify_scenario_replay_matches(tmp_path: Path) -> None:
    scenarios_root = tmp_path / "scenarios"
    replay = _make_replay(scenarios_root)
    verify_scenario_replay(replay, scenarios_root)  # no exception


def test_verify_scenario_replay_detects_missing_yaml(tmp_path: Path) -> None:
    scenarios_root = tmp_path / "scenarios"
    replay = _make_replay(scenarios_root, name="beacon")
    # Remove the yaml after the replay was recorded.
    (scenarios_root / "beacon.yaml").unlink()
    with pytest.raises(FileNotFoundError, match="scenario yaml"):
        verify_scenario_replay(replay, scenarios_root)


def test_verify_scenario_replay_detects_mutated_yaml(tmp_path: Path) -> None:
    """The scenario yaml is edited after the replay was recorded — the hash
    the record locked no longer matches on-disk content, so the release gate
    must refuse."""
    scenarios_root = tmp_path / "scenarios"
    replay = _make_replay(scenarios_root, name="beacon", contents="v1\n")
    # Mutate the yaml on disk. The replay's recorded hash is still that of "v1\n".
    (scenarios_root / "beacon.yaml").write_text("v2 different content\n", encoding="utf-8")
    with pytest.raises(ValueError, match="yaml hash mismatch"):
        verify_scenario_replay(replay, scenarios_root)


def test_verify_scenario_replay_detects_mutated_passed_field(tmp_path: Path) -> None:
    """Someone flipped `passed` from False to True in the record without
    re-running the scenario — the ship gate must catch it by re-computing the
    passing criterion from the stored counts."""
    scenarios_root = tmp_path / "scenarios"
    # Recorded counts say under-detection (fail), but `passed=True` was written.
    replay = _make_replay(
        scenarios_root,
        expected=[ExpectedDetection(technique="T1071", rule="r", min_count=3, tolerance=0)],
        observed=[ObservedDetection(technique="T1071", rule="r", count=1)],
        passed=True,  # honest re-compute would say False
    )
    with pytest.raises(ValueError, match="passed field mutated"):
        verify_scenario_replay(replay, scenarios_root)


def test_verify_training_record_verifies_scenario_replays(tmp_path: Path) -> None:
    """End-to-end: a model record with both dataset versions and scenario
    replays verifies both halves in one call."""
    baselines_root = tmp_path / "baselines"
    baselines_root.mkdir()
    baseline_dir = baselines_root / "linux__dev__abc__2026-09-11"
    baseline_dir.mkdir()
    _make_baseline_with_manifest(baseline_dir, lines=['{"argv": ["ls"]}'])
    dv = dataset_version_from_manifest(
        baseline_dir, name="linux__dev__abc__2026-09-11"
    )
    scenarios_root = tmp_path / "scenarios"
    replay = _make_replay(scenarios_root, name="beacon", contents="kind: beacon\n")

    model_dir = tmp_path / "model"
    model_dir.mkdir()
    write_training_record(
        model_dir,
        training_script="synthaea_ml/training/train_linux.py",
        dataset_versions=[dv],
        scenario_replays=[replay],
        trained_at=_TRAINED_AT,
    )

    loaded = load_training_record(model_dir)
    assert loaded.scenario_replays == [replay]  # round-trips through JSON

    verify_training_record(model_dir, baselines_root, scenarios_root)  # no exception


def test_verify_training_record_detects_mutated_scenario_yaml_end_to_end(tmp_path: Path) -> None:
    """The mutated-yaml failure mode surfaces through the release gate's
    single entry point, not just verify_scenario_replay in isolation."""
    baselines_root = tmp_path / "baselines"
    baselines_root.mkdir()
    baseline_dir = baselines_root / "linux__dev__abc__2026-09-11"
    baseline_dir.mkdir()
    _make_baseline_with_manifest(baseline_dir, lines=['{"argv": ["ls"]}'])
    dv = dataset_version_from_manifest(
        baseline_dir, name="linux__dev__abc__2026-09-11"
    )
    scenarios_root = tmp_path / "scenarios"
    replay = _make_replay(scenarios_root, name="beacon", contents="v1\n")

    model_dir = tmp_path / "model"
    model_dir.mkdir()
    write_training_record(
        model_dir,
        training_script="synthaea_ml/training/train_linux.py",
        dataset_versions=[dv],
        scenario_replays=[replay],
        trained_at=_TRAINED_AT,
    )

    (scenarios_root / "beacon.yaml").write_text("v2 mutated\n", encoding="utf-8")
    with pytest.raises(ValueError, match="yaml hash mismatch"):
        verify_training_record(model_dir, baselines_root, scenarios_root)
