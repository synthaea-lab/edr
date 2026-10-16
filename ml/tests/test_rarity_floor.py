"""The floor a rarity site model must hold before it leaves the lab (issue #640).

The rarity features are withheld (0, 0) until a snapshot covers enough hosts, which is the
state of every freshly enrolled fleet. A model trained mostly on rows where rarity was known
can score that state as anomalous, and the training run's own false-positive figure (taken at
the natural mix of known and withheld rows) would not show it. These tests pin the two checks
`train_site_rarity` makes before it writes a model: the false-positive rate with the rarity
withheld, and the scenario suite against the same corpus's cmdline-only model.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest
from sklearn.ensemble import IsolationForest

from synthaea_ml.calibration import calibrate_threshold
from synthaea_ml.training import train_site_rarity as rare

BEACON = Path(__file__).resolve().parents[2] / "lab" / "scenarios" / "beacon.yaml"


def _cmdline_rows(n: int, seed: int) -> np.ndarray:
    return np.random.default_rng(seed).normal(size=(n, 9)).astype(np.float32)


def _rarity_columns(n: int, withheld_fraction: float, seed: int) -> np.ndarray:
    """`rarity_known` and `image_in_common_set`, with `withheld_fraction` of the rows (0, 0)."""
    rng = np.random.default_rng(seed)
    known = rng.random(n) >= withheld_fraction
    common = rng.random(n) < 0.8
    return np.stack([known, known & common], axis=1).astype(np.float32)


def _models(withheld_fraction: float):
    """A cmdline-only baseline and a rarity candidate, each calibrated on its own slice, plus
    the cmdline columns of a held-out test slice."""
    x_base = _cmdline_rows(2000, seed=1)
    x_rare = np.hstack([x_base, _rarity_columns(2000, withheld_fraction, seed=2)])
    train, cal_slice, test = slice(0, 1400), slice(1400, 1700), slice(1700, 2000)
    base = IsolationForest(n_estimators=100, random_state=42).fit(x_base[train])
    base_cal = calibrate_threshold(
        base, x_base[cal_slice], fp_budget=rare.FP_BUDGET_PER_ENDPOINT_DAY,
        benign_rate_per_day=rare.BENIGN_RATE_PER_DAY,
    )
    cand = IsolationForest(n_estimators=100, random_state=42).fit(x_rare[train])
    cand_cal = calibrate_threshold(
        cand, x_rare[cal_slice], fp_budget=rare.FP_BUDGET_PER_ENDPOINT_DAY,
        benign_rate_per_day=rare.BENIGN_RATE_PER_DAY,
    )
    return cand, cand_cal, base, base_cal, x_base[test]


def test_the_adapter_scores_the_candidate_with_the_rarity_columns_withheld() -> None:
    cand, *_ = _models(withheld_fraction=0.3)
    x = _cmdline_rows(50, seed=9)
    adapter = rare.WithheldRarity(cand)

    assert adapter.n_features_in_ == 9
    expected = cand.decision_function(np.hstack([x, np.zeros((50, 2), dtype=np.float32)]))
    assert np.allclose(adapter.decision_function(x), expected)
    assert np.allclose(adapter.decision_function(x.tolist()), expected), "lists are accepted too"


def test_a_candidate_that_flags_the_withheld_state_fails_the_floor() -> None:
    # 1% of the training rows were withheld: the state looks rare to the forest, and every
    # event on a fleet that has no snapshot yet would be scored as anomalous.
    cand, cand_cal, base, base_cal, x_test = _models(withheld_fraction=0.01)

    floor = rare.check_rarity_floor(cand, cand_cal, base, base_cal, x_test)

    assert floor.fp_withheld > floor.fp_cmdline_only + rare.WITHHELD_FP_MARGIN
    assert not floor.passed
    assert any("withheld" in failure for failure in floor.failures)


def test_a_candidate_trained_with_plenty_of_withheld_rows_holds_the_floor() -> None:
    cand, cand_cal, base, base_cal, x_test = _models(withheld_fraction=0.5)

    floor = rare.check_rarity_floor(cand, cand_cal, base, base_cal, x_test)

    assert floor.fp_withheld <= floor.fp_cmdline_only + rare.WITHHELD_FP_MARGIN
    assert floor.passed, floor.failures
    assert floor.scenario_lines == [], "no scenario was asked for, none is reported"


def _card(escape: float, degradation: float) -> SimpleNamespace:
    return SimpleNamespace(escape_rate=escape, median_score_degradation=degradation)


def _fake_robustness(monkeypatch: pytest.MonkeyPatch, candidate, baseline) -> list[dict]:
    """Replaces the robustness run: the first model asked about is the candidate's adapter,
    which is told apart from the baseline by its type. Returns the calls made."""
    calls: list[dict] = []

    def fake(model, scenario_yaml, tier="T0", mutation_seed=42, threshold=None, events_source=None):
        calls.append({"model": model, "threshold": threshold, "tier": tier, "seed": mutation_seed})
        outcome = candidate if isinstance(model, rare.WithheldRarity) else baseline
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(rare, "run_robustness_evaluation", fake)
    return calls


def test_the_scenarios_compare_the_candidate_with_the_baseline_at_each_models_own_threshold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cand, cand_cal, base, base_cal, x_test = _models(withheld_fraction=0.5)
    calls = _fake_robustness(monkeypatch, _card(0.10, 0.02), _card(0.10, 0.02))

    floor = rare.check_rarity_floor(cand, cand_cal, base, base_cal, x_test, [BEACON])

    assert floor.passed, floor.failures
    by_kind = {isinstance(c["model"], rare.WithheldRarity): c for c in calls}
    assert by_kind[True]["threshold"] == cand_cal.threshold
    assert by_kind[False]["threshold"] == base_cal.threshold
    assert {c["tier"] for c in calls} == {"T0"} and {c["seed"] for c in calls} == {42}
    assert len(floor.scenario_lines) == 1 and "beacon" in floor.scenario_lines[0]


@pytest.mark.parametrize(
    ("candidate", "passes"),
    # The baseline is (0.5, 0.5): 0.5 + 0.05 and 0.5 + 0.10 are exact in floating point, so the
    # boundary is really on the boundary and an exclusive comparison would fail the first and third.
    [
        (_card(0.55, 0.5), True),     # exactly the escape-rate tolerance: inclusive
        (_card(0.5501, 0.5), False),  # just past it
        (_card(0.5, 0.6), True),      # exactly the degradation tolerance: inclusive
        (_card(0.5, 0.6001), False),
    ],
)
def test_the_tolerances_are_inclusive_and_the_same_as_the_global_floor_check(
    monkeypatch: pytest.MonkeyPatch, candidate: SimpleNamespace, passes: bool
) -> None:
    cand, cand_cal, base, base_cal, x_test = _models(withheld_fraction=0.5)
    _fake_robustness(monkeypatch, candidate, _card(0.5, 0.5))

    floor = rare.check_rarity_floor(cand, cand_cal, base, base_cal, x_test, [BEACON])

    assert floor.passed is passes, floor.failures


def test_a_candidate_that_detects_nothing_the_baseline_detects_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cand, cand_cal, base, base_cal, x_test = _models(withheld_fraction=0.5)
    _fake_robustness(monkeypatch, ValueError("no originally-detected samples"), _card(0.1, 0.0))

    floor = rare.check_rarity_floor(cand, cand_cal, base, base_cal, x_test, [BEACON])

    assert not floor.passed
    assert any("beacon" in failure for failure in floor.failures)


def test_a_scenario_the_baseline_cannot_evaluate_is_skipped_and_said_so(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cand, cand_cal, base, base_cal, x_test = _models(withheld_fraction=0.5)
    _fake_robustness(monkeypatch, _card(0.5, 0.5), ValueError("no originally-detected samples"))

    floor = rare.check_rarity_floor(cand, cand_cal, base, base_cal, x_test, [BEACON])

    assert floor.passed, "there is nothing the baseline detects for the candidate to lose"
    assert "skipped" in floor.scenario_lines[0]


# --- the run -------------------------------------------------------------------------------


def _run(monkeypatch: pytest.MonkeyPatch, tmp_path, *extra: str) -> Path:
    from test_rarity import _corpus

    out = tmp_path / "site-model"
    monkeypatch.setattr(
        "sys.argv",
        [
            rare.TRAINING_SCRIPT, "--site-corpus", str(_corpus(tmp_path)), "--site-name", "acme",
            "--output-dir", str(out), "--min-hosts", "3", *extra,
        ],
    )
    rare.main()
    return out


def test_the_run_records_the_withheld_false_positive_rate_and_the_scenario_floor(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    from synthaea_ml.registry.training_record import load_training_record

    out = _run(monkeypatch, tmp_path, "--withhold-fraction", "0.3", "--robustness-scenarios", str(BEACON))

    extra = load_training_record(out).extra
    assert 0.0 <= float(extra["fp_rate_test_with_rarity_withheld"]) <= 1.0
    assert extra["rarity_floor"].startswith("PASSED"), extra["rarity_floor"]
    assert "beacon" in extra["rarity_floor"]
    assert "NOT CHECKED" in extra["global_model_floor"], "the global model was not compared"


def test_without_scenarios_the_withheld_check_still_runs_and_the_record_says_what_was_skipped(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    from synthaea_ml.registry.training_record import load_training_record

    extra = load_training_record(_run(monkeypatch, tmp_path, "--withhold-fraction", "0.3")).extra

    assert extra["withhold_fraction"] == "0.3000"
    assert extra["rarity_floor"].startswith("PASSED (withheld false-positive rate only")
    assert "scenarios" in extra["rarity_floor"]


def test_a_failing_floor_stops_the_run_before_any_model_is_written(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    failing = rare.RarityFloor(
        passed=False, fp_cmdline_only=0.0, fp_withheld=0.9, scenario_lines=[],
        failures=["withheld false-positive rate 90.00% is above 0.00% + 1.00%"],
    )
    monkeypatch.setattr(rare, "check_rarity_floor", lambda *a, **k: failing)

    with pytest.raises(ValueError, match="floor"):
        _run(monkeypatch, tmp_path)

    assert not (tmp_path / "site-model" / "model.onnx").exists()


def test_a_corpus_where_rarity_is_almost_always_known_is_refused_unless_rows_are_withheld(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    # The synthetic corpus has a known rarity for 95% of its rows, as a real one does after
    # the first snapshot boundary: trained as it is, the model flags every event of a fleet
    # that has no snapshot yet, while its false-positive rate at the natural mix reads 0%.
    with pytest.raises(ValueError, match="floor failed") as refused:
        _run(monkeypatch, tmp_path)
    assert "withheld" in str(refused.value)
    assert not (tmp_path / "site-model" / "model.onnx").exists()

    out = _run(monkeypatch, tmp_path, "--withhold-fraction", "0.3")
    assert (out / "model.onnx").exists()


# --- withhold_rows -------------------------------------------------------------------------


def _matrix(n: int = 1000) -> np.ndarray:
    return np.hstack([_cmdline_rows(n, seed=3), np.ones((n, 2), dtype=np.float32)])


def test_withholding_zeroes_only_the_rarity_columns_of_a_share_of_the_chosen_rows() -> None:
    x = _matrix()
    before = x.copy()

    out = rare.withhold_rows(x, 0.3, seed=42, rows=slice(0, 700))

    assert np.array_equal(x, before), "the input is not modified"
    assert np.array_equal(out[:, :9], x[:, :9]), "the cmdline columns never change"
    assert np.array_equal(out[700:], x[700:]), "rows outside the slice never change"
    withheld = (out[:700, 9:] == 0.0).all(axis=1)
    assert 0.25 < withheld.mean() < 0.35
    assert ((out[:700, 9:] == 1.0).all(axis=1) | withheld).all(), "a row is either kept or withheld whole"


def test_withholding_is_deterministic_and_a_fraction_of_zero_changes_nothing() -> None:
    x = _matrix()

    assert np.array_equal(
        rare.withhold_rows(x, 0.4, seed=7, rows=slice(0, 500)),
        rare.withhold_rows(x, 0.4, seed=7, rows=slice(0, 500)),
    )
    assert not np.array_equal(
        rare.withhold_rows(x, 0.4, seed=7, rows=slice(0, 500)),
        rare.withhold_rows(x, 0.4, seed=8, rows=slice(0, 500)),
    )
    zero = rare.withhold_rows(x, 0.0, seed=7, rows=slice(0, 500))
    assert np.array_equal(zero, x) and zero is not x


@pytest.mark.parametrize("fraction", [-0.1, 1.0, 2.0])
def test_a_fraction_outside_zero_to_one_is_refused(fraction: float) -> None:
    with pytest.raises(ValueError, match="withhold fraction"):
        rare.withhold_rows(_matrix(10), fraction, seed=1, rows=slice(0, 10))
