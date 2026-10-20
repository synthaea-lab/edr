"""The comparison of a rarity site model with the global model (issue #640, last open floor).

`check_rarity_floor` compares the candidate with the same corpus's cmdline-only model. The
global model, the one trained on the lab baseline and shipped to every site, is the other
reference: a site model that does worse than it on the shared scenario suite, or flags a fleet
that has no snapshot yet more than it does, should not replace it. These tests pin the loader of
the global model (the shipped `model.onnx` and `model_metadata.json`), the floor, and the run.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest
from skl2onnx import to_onnx
from sklearn.ensemble import IsolationForest

from synthaea_ml.calibration import calibrate_threshold
from synthaea_ml.evaluation.onnx_model import load_shipped_model
from synthaea_ml.training import train_site_rarity as rare

BEACON = Path(__file__).resolve().parents[2] / "lab" / "scenarios" / "beacon.yaml"
ONNX_OPSET = {"": 18, "ai.onnx.ml": 3}


def _cmdline_rows(n: int, seed: int) -> np.ndarray:
    return np.random.default_rng(seed).normal(size=(n, 9)).astype(np.float32)


def _export(directory: Path, model: IsolationForest, threshold: float | None) -> Path:
    """What `train_linux` writes: `model.onnx`, and `model_metadata.json` when there is a threshold."""
    directory.mkdir(parents=True, exist_ok=True)
    sample = _cmdline_rows(1, seed=0)
    (directory / "model.onnx").write_bytes(
        to_onnx(model, sample, target_opset=ONNX_OPSET).SerializeToString()
    )
    if threshold is not None:
        (directory / "model_metadata.json").write_text(json.dumps({"threshold": threshold}))
    return directory


@pytest.fixture(scope="module")
def global_forest() -> IsolationForest:
    return IsolationForest(n_estimators=50, random_state=42).fit(_cmdline_rows(1000, seed=11))


# --- loading the shipped model ---------------------------------------------------------------


def test_the_loaded_model_scores_like_the_estimator_it_was_exported_from(
    tmp_path: Path, global_forest: IsolationForest
) -> None:
    loaded = load_shipped_model(_export(tmp_path / "g", global_forest, threshold=-0.07))
    x = _cmdline_rows(40, seed=5)

    assert np.allclose(loaded.decision_function(x), global_forest.decision_function(x), atol=1e-5)
    assert np.allclose(loaded.decision_function(x.tolist()), global_forest.decision_function(x), atol=1e-5)
    assert loaded.threshold == pytest.approx(-0.07)
    assert loaded.threshold_source == "model_metadata.json"
    assert loaded.n_features_in_ == 9


def test_without_metadata_the_threshold_is_zero_as_the_agents_scorer_does_and_it_is_said(
    tmp_path: Path, global_forest: IsolationForest
) -> None:
    loaded = load_shipped_model(_export(tmp_path / "g", global_forest, threshold=None))

    assert loaded.threshold == 0.0
    assert "no model_metadata.json" in loaded.threshold_source


def test_a_directory_without_a_model_is_refused(tmp_path: Path) -> None:
    (tmp_path / "empty").mkdir()
    with pytest.raises(FileNotFoundError, match="model.onnx"):
        load_shipped_model(tmp_path / "empty")


def test_metadata_without_a_threshold_is_refused_rather_than_read_as_zero(
    tmp_path: Path, global_forest: IsolationForest
) -> None:
    directory = _export(tmp_path / "g", global_forest, threshold=None)
    (directory / "model_metadata.json").write_text(json.dumps({"feature_bounds": {}}))

    with pytest.raises(ValueError, match="threshold"):
        load_shipped_model(directory)


def test_a_model_of_another_width_is_refused_on_scoring(tmp_path: Path) -> None:
    wide = IsolationForest(n_estimators=10, random_state=1).fit(np.zeros((50, 11), dtype=np.float32) + 1)
    directory = tmp_path / "wide"
    directory.mkdir()
    (directory / "model.onnx").write_bytes(
        to_onnx(wide, np.zeros((1, 11), dtype=np.float32), target_opset=ONNX_OPSET).SerializeToString()
    )

    loaded = load_shipped_model(directory)

    assert loaded.n_features_in_ == 11
    with pytest.raises(ValueError, match="11 features"):
        loaded.decision_function(_cmdline_rows(3, seed=1))


# --- the floor -------------------------------------------------------------------------------


def _candidate(withheld_fraction: float):
    """A rarity candidate and its calibration, plus the cmdline columns of a held-out test slice."""
    x_base = _cmdline_rows(2000, seed=1)
    rng = np.random.default_rng(2)
    known = rng.random(2000) >= withheld_fraction
    rarity_cols = np.stack([known, known & (rng.random(2000) < 0.8)], axis=1).astype(np.float32)
    x_rare = np.hstack([x_base, rarity_cols])
    forest = IsolationForest(n_estimators=100, random_state=42).fit(x_rare[:1400])
    cal = calibrate_threshold(
        forest, x_rare[1400:1700], fp_budget=rare.FP_BUDGET_PER_ENDPOINT_DAY,
        benign_rate_per_day=rare.BENIGN_RATE_PER_DAY,
    )
    return forest, cal, x_base[1700:]


def _global(tmp_path: Path, forest: IsolationForest, x_cal: np.ndarray):
    """The global model as shipped, its threshold calibrated on `x_cal` as `train_linux` does."""
    cal = calibrate_threshold(
        forest, x_cal, fp_budget=rare.FP_BUDGET_PER_ENDPOINT_DAY,
        benign_rate_per_day=rare.BENIGN_RATE_PER_DAY,
    )
    return load_shipped_model(_export(tmp_path / "g", forest, cal.threshold))


def test_a_candidate_that_flags_the_withheld_state_more_than_the_global_model_fails(
    tmp_path: Path, global_forest: IsolationForest
) -> None:
    cand, cand_cal, x_test = _candidate(withheld_fraction=0.01)
    reference = _global(tmp_path, global_forest, _cmdline_rows(300, seed=12))

    floor = rare.check_global_floor(cand, cand_cal, reference, x_test)

    assert floor.fp_withheld > floor.fp_global + rare.WITHHELD_FP_MARGIN
    assert not floor.passed
    assert any("global model" in failure and "withheld" in failure for failure in floor.failures)


def test_a_candidate_trained_with_plenty_of_withheld_rows_holds_the_global_floor(
    tmp_path: Path, global_forest: IsolationForest
) -> None:
    cand, cand_cal, x_test = _candidate(withheld_fraction=0.5)
    reference = _global(tmp_path, global_forest, _cmdline_rows(300, seed=12))

    floor = rare.check_global_floor(cand, cand_cal, reference, x_test)

    assert floor.fp_withheld <= floor.fp_global + rare.WITHHELD_FP_MARGIN
    assert floor.passed, floor.failures
    assert floor.scenario_lines == []


def _card(escape: float, degradation: float) -> SimpleNamespace:
    return SimpleNamespace(escape_rate=escape, median_score_degradation=degradation)


def _fake_robustness(monkeypatch: pytest.MonkeyPatch, candidate, reference) -> list[dict]:
    calls: list[dict] = []

    def fake(model, scenario_yaml, tier="T0", mutation_seed=42, threshold=None, events_source=None):
        calls.append({"model": model, "threshold": threshold, "tier": tier, "seed": mutation_seed})
        outcome = candidate if isinstance(model, rare.WithheldRarity) else reference
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(rare, "run_robustness_evaluation", fake)
    return calls


def test_the_scenarios_compare_the_candidate_with_the_global_model_at_each_models_own_threshold(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, global_forest: IsolationForest
) -> None:
    cand, cand_cal, x_test = _candidate(withheld_fraction=0.5)
    reference = _global(tmp_path, global_forest, _cmdline_rows(300, seed=12))
    calls = _fake_robustness(monkeypatch, _card(0.10, 0.02), _card(0.10, 0.02))

    floor = rare.check_global_floor(cand, cand_cal, reference, x_test, [BEACON])

    assert floor.passed, floor.failures
    by_kind = {isinstance(c["model"], rare.WithheldRarity): c for c in calls}
    assert by_kind[True]["threshold"] == cand_cal.threshold
    assert by_kind[False]["threshold"] == reference.threshold
    assert by_kind[False]["model"] is reference
    assert {c["tier"] for c in calls} == {"T0"} and {c["seed"] for c in calls} == {42}
    assert len(floor.scenario_lines) == 1 and "beacon" in floor.scenario_lines[0]
    assert "global" in floor.scenario_lines[0]


@pytest.mark.parametrize(
    ("candidate", "passes"),
    # The reference is (0.5, 0.5): the boundaries are exact in floating point, as in the
    # cmdline-only floor, so an exclusive comparison would fail the first and third.
    [
        (_card(0.55, 0.5), True),
        (_card(0.5501, 0.5), False),
        (_card(0.5, 0.6), True),
        (_card(0.5, 0.6001), False),
    ],
)
def test_the_tolerances_are_the_inclusive_ones_of_the_other_floors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, global_forest: IsolationForest,
    candidate: SimpleNamespace, passes: bool,
) -> None:
    cand, cand_cal, x_test = _candidate(withheld_fraction=0.5)
    reference = _global(tmp_path, global_forest, _cmdline_rows(300, seed=12))
    _fake_robustness(monkeypatch, candidate, _card(0.5, 0.5))

    floor = rare.check_global_floor(cand, cand_cal, reference, x_test, [BEACON])

    assert floor.passed is passes, floor.failures
    if not passes:
        assert all("global model" in failure for failure in floor.failures)


def test_a_candidate_that_detects_nothing_the_global_model_detects_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, global_forest: IsolationForest
) -> None:
    cand, cand_cal, x_test = _candidate(withheld_fraction=0.5)
    reference = _global(tmp_path, global_forest, _cmdline_rows(300, seed=12))
    _fake_robustness(monkeypatch, ValueError("no originally-detected samples"), _card(0.1, 0.0))

    floor = rare.check_global_floor(cand, cand_cal, reference, x_test, [BEACON])

    assert not floor.passed
    assert any("beacon" in failure and "global model" in failure for failure in floor.failures)


def test_a_scenario_the_global_model_cannot_evaluate_is_skipped_and_said_so(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, global_forest: IsolationForest
) -> None:
    cand, cand_cal, x_test = _candidate(withheld_fraction=0.5)
    reference = _global(tmp_path, global_forest, _cmdline_rows(300, seed=12))
    _fake_robustness(monkeypatch, _card(0.5, 0.5), ValueError("no originally-detected samples"))

    floor = rare.check_global_floor(cand, cand_cal, reference, x_test, [BEACON])

    assert floor.passed
    assert "skipped" in floor.scenario_lines[0] and "global model" in floor.scenario_lines[0]


# --- the run ---------------------------------------------------------------------------------


def _run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *extra: str) -> Path:
    from test_rarity import _corpus

    out = tmp_path / "site-model"
    monkeypatch.setattr(
        "sys.argv",
        [
            rare.TRAINING_SCRIPT, "--site-corpus", str(_corpus(tmp_path)), "--site-name", "acme",
            "--output-dir", str(out), "--min-hosts", "3", "--withhold-fraction", "0.3", *extra,
        ],
    )
    rare.main()
    return out


def test_the_run_records_the_global_comparison_and_no_longer_says_not_checked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, global_forest: IsolationForest
) -> None:
    from synthaea_ml.registry.training_record import load_training_record

    directory = _export(tmp_path / "global", global_forest, threshold=-0.2)
    extra = load_training_record(
        _run(monkeypatch, tmp_path, "--global-model-dir", str(directory))
    ).extra

    assert extra["global_model_floor"].startswith("PASSED"), extra["global_model_floor"]
    assert "threshold -0.2" in extra["global_model_floor"]
    assert "model_metadata.json" in extra["global_model_floor"]
    assert "NOT CHECKED" not in extra["global_model_floor"]
    assert 0.0 <= float(extra["fp_rate_test_global_model"]) <= 1.0


def test_the_record_says_which_scenarios_were_compared_with_the_global_model(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, global_forest: IsolationForest
) -> None:
    from synthaea_ml.registry.training_record import load_training_record

    # The synthetic corpus's beacon events look benign to the candidate, so the scores are stood in.
    _fake_robustness(monkeypatch, _card(0.1, 0.0), _card(0.1, 0.0))
    directory = _export(tmp_path / "global", global_forest, threshold=None)
    extra = load_training_record(
        _run(
            monkeypatch, tmp_path, "--global-model-dir", str(directory),
            "--robustness-scenarios", str(BEACON),
        )
    ).extra

    assert "beacon" in extra["global_model_floor"]
    assert "no model_metadata.json" in extra["global_model_floor"]


def test_without_a_global_model_the_record_still_says_it_was_not_checked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from synthaea_ml.registry.training_record import load_training_record

    extra = load_training_record(_run(monkeypatch, tmp_path)).extra

    assert "NOT CHECKED" in extra["global_model_floor"]
    assert "--global-model-dir" in extra["global_model_floor"]
    assert "fp_rate_test_global_model" not in extra


def test_a_failing_global_floor_stops_the_run_before_any_model_is_written(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, global_forest: IsolationForest
) -> None:
    failing = rare.GlobalFloor(
        passed=False, fp_global=0.0, fp_withheld=0.9, scenario_lines=[],
        failures=["with the rarity withheld the candidate flags 90.00% against the global model's 0.00%"],
        threshold=0.0, threshold_source="model_metadata.json",
    )
    monkeypatch.setattr(rare, "check_global_floor", lambda *a, **k: failing)
    directory = _export(tmp_path / "global", global_forest, threshold=0.0)

    with pytest.raises(ValueError, match="global model floor failed"):
        _run(monkeypatch, tmp_path, "--global-model-dir", str(directory))

    assert not (tmp_path / "site-model" / "model.onnx").exists()
