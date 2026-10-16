"""Tests for the provenance half of `verify_onnx` — the release gate that binds a
shipped model to the baselines it was trained on and the scenario replays that
validated it.

The ONNX-runtime side of verify_onnx (input shape, deterministic inference,
score/label consistency) is validated implicitly by the real registry entries;
these tests focus on the provenance hook: legacy vs modern entries, strict vs
interactive mode, and the failure modes verify_training_record exists to catch.

Renamed from `training.json` to `model_record.json` in ADR-0009; the tests
below use the new name consistently.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest

from synthaea_ml.data.manifest import write_manifest
from synthaea_ml.export.verify_onnx import (
    VerificationError,
    _is_strict_provenance,
    verify_provenance,
)
from synthaea_ml.registry.training_record import (
    Environment,
    ExpectedDetection,
    ObservedDetection,
    ScenarioReplayResult,
    compute_passed,
    dataset_version_from_manifest,
    write_training_record,
)

_START = datetime(2026, 9, 14, 10, 0, 0, tzinfo=UTC)
_END = datetime(2026, 9, 14, 11, 0, 0, tzinfo=UTC)


def _make_baseline(dir_path: Path, *, name: str, samples: int = 3) -> Path:
    baseline_dir = dir_path / name
    baseline_dir.mkdir(parents=True, exist_ok=True)
    lines = [f'{{"argv": ["cmd-{i}"]}}' for i in range(samples)]
    (baseline_dir / "baseline.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    write_manifest(
        baseline_dir,
        platform="linux",
        os_version="test",
        workload_label="dev",
        capture_start=_START,
        capture_end=_END,
        hostname="testhost",
    )
    return baseline_dir


def _make_model_dir_with_record(
    tmp_path: Path, baselines_root: Path, dataset_name: str
) -> Path:
    """Create a fake model_dir with a valid model_record.json pointing at a baseline."""
    model_dir = tmp_path / "model_out"
    model_dir.mkdir()
    baseline_dir = baselines_root / dataset_name
    dv = dataset_version_from_manifest(baseline_dir, name=dataset_name)
    write_training_record(
        model_dir,
        training_script="synthaea_ml/training/train_linux.py",
        dataset_versions=[dv],
        trained_at=_START,
    )
    return model_dir


def _write_scenario_yaml(scenarios_root: Path, name: str, contents: str) -> str:
    scenarios_root.mkdir(parents=True, exist_ok=True)
    (scenarios_root / f"{name}.yaml").write_bytes(contents.encode("utf-8"))
    return hashlib.sha256(contents.encode("utf-8")).hexdigest()


# --- Legacy entry (no model_record.json) ----------------------------------


def test_legacy_entry_passes_with_warning_in_dev_mode(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Pre-#44 registry entries have no model_record.json. In dev mode we do not want
    to break every verify_onnx run just because the old cards are still there."""
    model_dir = tmp_path / "cmdline-iforest-linux-0.1.0"
    model_dir.mkdir()
    baselines_root = tmp_path / "baselines"
    baselines_root.mkdir()
    scenarios_root = tmp_path / "scenarios"
    scenarios_root.mkdir()

    verify_provenance(model_dir, baselines_root, scenarios_root, strict=False)  # no exception
    captured = capsys.readouterr()
    assert "WARN" in captured.err
    assert "pre-#44 legacy entry" in captured.err


def test_legacy_entry_fails_in_strict_mode(tmp_path: Path) -> None:
    """Release CI (SYNTHAEA_STRICT_PROVENANCE=1) refuses to let a legacy entry
    ship without a model record."""
    model_dir = tmp_path / "cmdline-iforest-linux-0.1.0"
    model_dir.mkdir()
    baselines_root = tmp_path / "baselines"
    baselines_root.mkdir()
    scenarios_root = tmp_path / "scenarios"
    scenarios_root.mkdir()

    with pytest.raises(VerificationError, match="pre-#44 legacy entry"):
        verify_provenance(model_dir, baselines_root, scenarios_root, strict=True)


# --- Modern entry with a valid model_record.json --------------------------


def test_modern_entry_matches(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    baselines_root = tmp_path / "baselines"
    baselines_root.mkdir()
    _make_baseline(baselines_root, name="linux__dev__abc__2026-09-14")
    model_dir = _make_model_dir_with_record(
        tmp_path, baselines_root, "linux__dev__abc__2026-09-14"
    )
    scenarios_root = tmp_path / "scenarios"
    scenarios_root.mkdir()

    verify_provenance(model_dir, baselines_root, scenarios_root, strict=True)  # no exception
    captured = capsys.readouterr()
    assert "provenance: ok" in captured.out


def test_modern_entry_detects_baseline_mutation(tmp_path: Path) -> None:
    """The whole point: a baseline edited (or truncated, or appended-to) after the
    model was trained no longer matches, and the release gate catches it."""
    baselines_root = tmp_path / "baselines"
    baselines_root.mkdir()
    baseline_dir = _make_baseline(
        baselines_root, name="linux__dev__abc__2026-09-14"
    )
    model_dir = _make_model_dir_with_record(
        tmp_path, baselines_root, "linux__dev__abc__2026-09-14"
    )
    scenarios_root = tmp_path / "scenarios"
    scenarios_root.mkdir()

    # Mutate the baseline after the model record was written; also regenerate the
    # manifest so verify_manifest passes — the mismatch we want to catch is
    # record vs current, not manifest vs baseline.
    with (baseline_dir / "baseline.jsonl").open("a", encoding="utf-8") as f:
        f.write('{"argv": ["injected"]}\n')
    write_manifest(
        baseline_dir,
        platform="linux",
        os_version="test",
        workload_label="dev",
        capture_start=_START,
        capture_end=_END,
        hostname="testhost",
    )

    with pytest.raises(VerificationError, match="provenance check failed"):
        verify_provenance(model_dir, baselines_root, scenarios_root, strict=False)


def test_modern_entry_detects_missing_baseline(tmp_path: Path) -> None:
    """A moved / deleted baseline directory is caught as well - the release gate
    cannot re-verify what it cannot find."""
    baselines_root = tmp_path / "baselines"
    baselines_root.mkdir()
    _make_baseline(baselines_root, name="linux__dev__abc__2026-09-14")
    model_dir = _make_model_dir_with_record(
        tmp_path, baselines_root, "linux__dev__abc__2026-09-14"
    )
    scenarios_root = tmp_path / "scenarios"
    scenarios_root.mkdir()

    # Delete the baseline directory after the record was written.
    import shutil
    shutil.rmtree(baselines_root / "linux__dev__abc__2026-09-14")

    with pytest.raises(VerificationError, match="provenance check failed"):
        verify_provenance(model_dir, baselines_root, scenarios_root, strict=False)


# --- Modern entry with scenario replays (ADR-0009) ------------------------


def _model_dir_with_dataset_and_replay(
    tmp_path: Path, baselines_root: Path, scenarios_root: Path, *, dataset_name: str
) -> Path:
    """Build a model_dir whose record binds one dataset and one scenario replay,
    both bound to on-disk content by hash."""
    baseline_dir = _make_baseline(baselines_root, name=dataset_name)
    dv = dataset_version_from_manifest(baseline_dir, name=dataset_name)

    yaml_sha = _write_scenario_yaml(scenarios_root, "beacon", "kind: beacon\n")
    expected = [ExpectedDetection(technique="T1071", rule="r", min_count=1, tolerance=0)]
    observed = [ObservedDetection(technique="T1071", rule="r", count=1)]
    replay = ScenarioReplayResult(
        scenario_name="beacon",
        scenario_yaml_sha256=yaml_sha,
        run_at="2026-09-17T10:00:00Z",
        environment=Environment(os="linux", kernel="6.6.0-generic", arch="x86_64"),
        expected_detections=expected,
        observed_detections=observed,
        passed=compute_passed(expected, observed),
    )

    model_dir = tmp_path / "model_out"
    model_dir.mkdir()
    write_training_record(
        model_dir,
        training_script="synthaea_ml/training/train_linux.py",
        dataset_versions=[dv],
        scenario_replays=[replay],
        trained_at=_START,
    )
    return model_dir


def test_modern_entry_with_replay_matches(tmp_path: Path) -> None:
    baselines_root = tmp_path / "baselines"
    baselines_root.mkdir()
    scenarios_root = tmp_path / "scenarios"
    scenarios_root.mkdir()
    model_dir = _model_dir_with_dataset_and_replay(
        tmp_path, baselines_root, scenarios_root, dataset_name="linux__dev__abc__2026-09-14"
    )

    verify_provenance(model_dir, baselines_root, scenarios_root, strict=True)  # no exception


def test_modern_entry_detects_mutated_scenario_yaml(tmp_path: Path) -> None:
    """A mutated scenario yaml on disk breaks the replay binding, and the
    release gate must refuse just as it refuses a mutated baseline."""
    baselines_root = tmp_path / "baselines"
    baselines_root.mkdir()
    scenarios_root = tmp_path / "scenarios"
    scenarios_root.mkdir()
    model_dir = _model_dir_with_dataset_and_replay(
        tmp_path, baselines_root, scenarios_root, dataset_name="linux__dev__abc__2026-09-14"
    )

    # Someone edits the scenario yaml after the replay was recorded.
    (scenarios_root / "beacon.yaml").write_text("kind: beacon-mutated\n", encoding="utf-8")

    with pytest.raises(VerificationError, match="yaml hash mismatch"):
        verify_provenance(model_dir, baselines_root, scenarios_root, strict=False)


# --- Strict-mode env-var parsing ------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("1", True),
        ("true", True),
        ("TRUE", True),
        ("yes", True),
        ("YES", True),
        ("0", False),
        ("false", False),
        ("no", False),
        ("", False),
        ("garbage", False),
    ],
)
def test_is_strict_provenance_env_parsing(
    monkeypatch: pytest.MonkeyPatch, value: str, expected: bool
) -> None:
    monkeypatch.setenv("SYNTHAEA_STRICT_PROVENANCE", value)
    assert _is_strict_provenance() is expected


def test_is_strict_provenance_defaults_to_false(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SYNTHAEA_STRICT_PROVENANCE", raising=False)
    assert _is_strict_provenance() is False
